package cachex

import (
	"encoding/json"
	"fmt"
	"gnamed/ext/faketimer"
	"gnamed/ext/xgeoip2"
	"gnamed/ext/xlog"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type SklCacheConfig struct {
	MaxLevel    int     `json:"maxLevel"` // log(1/p)(n)
	Probability float64 `json:"probability"`
	MaxCount    int64   `json:"maxCount"`
	NoEviction  bool    `json:"noEviction"` // default remove the oldest two expired elements
}

func (c *SklCacheConfig) Parse() error {
	if c.MaxLevel < 0 || c.MaxLevel >= 128 {
		return fmt.Errorf("invalid MaxLevel not in [1, 128]: %d", c.MaxLevel)
	} else if c.MaxLevel == 0 {
		c.MaxLevel = 32
	}

	if c.Probability < 0 || c.Probability >= 1 {
		return fmt.Errorf("invalid Probability not in (0, 1): %f", c.Probability)
	} else if c.Probability == 0 {
		c.Probability = 0.5
	}

	return nil
}

func (c *SklCacheConfig) marshal() []byte {
	bs, err := json.Marshal(c)
	if err != nil {
		return []byte("{}")
	}
	return bs
}

func (c *SklCacheConfig) NewSklCache() *SklCache {
	return c.newSklCache()
}

// if *SklCacheConfig is nil, use default
func InitDefaultSklCache(c *SklCacheConfig) {
	if c == nil {
		c = &SklCacheConfig{
			MaxLevel:    32,
			Probability: 0.5,
		}
	}
	c.newSklCache()
}

type SklCache struct {
	maxCount   int64 // the limit count of stored elements, no limit if <= 0, delete oldest element when limit hit
	noEviction bool  // default remove the oldest two expired elements

	lock        *sync.Mutex   // lock for lazy init
	maxLevel    int           // skiplist maxlevel
	probability float64       // skiplist probability
	count       *atomic.Int64 // total count

	// qtype -> SklTable
	tables []*SklTable // 1<<16
	// qtype -> SkipList
	skls []*SkipList // 1<<16
}

type SklTable struct {
	table map[string]*TableNode
	lock  *sync.RWMutex
}

type TableNode struct {
	sklNode *SkipListNode // SkipListNode.vals and SkipListNode.value to evict expired keys
	//val     []byte        // dns.Msg
	val          *dns.Msg
	extraElement *extraElement  // extra element
	reads        *atomic.Uint64 // cache hit count
}

func (c *SklCacheConfig) newSklCache() *SklCache {

	xlog.Logger().Trace().Str("log_type", "cache").Str("op_type", "new").Str("cache_mode", CacheModeSkipList).RawJSON("options", c.marshal()).Msg("")

	size := 1 << 16
	tables := make([]*SklTable, size)
	skls := make([]*SkipList, size)

	sklCache := &SklCache{
		maxCount:    c.MaxCount,
		noEviction:  c.NoEviction,
		lock:        new(sync.Mutex),
		maxLevel:    c.MaxLevel,
		probability: c.Probability,
		count:       new(atomic.Int64),

		tables: tables,
		skls:   skls,
	}

	// init common qtype at startup
	for _, qtype := range []uint16{dns.TypeA} {
		sklCache.lazyInit(qtype)
	}

	// set public function
	Get = sklCache.Get
	Set = sklCache.Set
	Remove = sklCache.Remove
	Dump = sklCache.Dump
	Store = sklCache.Store

	return sklCache
}

// lazy init to save startup memory, but hit performance
// startup memory usage:
// 1. init all at startup: 500MB, at the end 50MB
// 2. lazy init: 10MB
func (sklc *SklCache) lazyInit(qtype uint16) {
	if sklc.tables[qtype] == nil {
		sklc.lock.Lock()

		// double check
		if sklc.tables[qtype] == nil {
			// need to init
			sklc.tables[qtype] = &SklTable{
				table: make(map[string]*TableNode),
				lock:  new(sync.RWMutex),
			}
			sklc.skls[qtype] = NewSkipList(sklc.maxLevel, sklc.probability)
		}

		sklc.lock.Unlock()

	}
}

// O(1)
func (sklc *SklCache) Get(key string, qtype uint16) (*dns.Msg, int64, bool) {
	// lazy init
	sklc.lazyInit(qtype)

	sklt := sklc.tables[qtype]
	sklt.lock.RLock()
	if tnode, found := sklt.table[key]; found {
		val := tnode.val
		expiredUTC := tnode.sklNode.value
		tnode.reads.Add(1)

		sklt.lock.RUnlock()

		// check ttl
		if faketimer.GetFakeTimerUnixSecond() > tnode.sklNode.value {
			// remove
			sklc.Remove(key, qtype)
			// steal cache, let caller determine using or not
			return val, expiredUTC, false
		}
		return val.Copy(), expiredUTC, true
	}

	sklt.lock.RUnlock()

	return nil, 0, false
}

// update: O(1)
// Insert: O(logN)
func (sklc *SklCache) Set(key string, qtype uint16, value *dns.Msg, ttl uint32) bool {
	// make sure deep-copy
	value = value.Copy()

	// lazy init
	sklc.lazyInit(qtype)

	expiredUTC := faketimer.GetFakeTimerUnixSecond() + int64(ttl)

	sklt := sklc.tables[qtype]
	sklt.lock.Lock()
	defer sklt.lock.Unlock()

	skll := sklc.skls[qtype]
	skll.lock.Lock()
	defer skll.lock.Unlock()

	count := sklc.count.Load()
	// try to remove expired elements of this qtype, up to two elements
	// O(1)
	if (len(sklt.table) > 0 && !sklc.noEviction) || (sklc.maxCount > 0 && sklc.maxCount <= count) {
		nowUTC := faketimer.GetFakeTimerUnixSecond()
		curr := skll.head
		if curr.forward[0] != nil && (curr.forward[0].value < nowUTC || (sklc.maxCount > 0 && sklc.maxCount <= count)) {

			expired := curr.forward[0].value < nowUTC
			hitCountLimit := sklc.maxCount > 0 && sklc.maxCount <= count
			qtypeS := dns.TypeToString[qtype]

			deletedCnt := 0
			for k := range curr.forward[0].vals {
				delete(sklt.table, k)
				delete(curr.forward[0].vals, k)
				sklc.count.Add(-1)
				xlog.Logger().Trace().Str("log_type", "cache").Str("op_type", "evict").Str("name", k).Str("qtype", qtypeS).Bool("expired", expired).Bool("hit_count_limit", hitCountLimit).Msg("")
				if deletedCnt == 1 {
					break
				}
				deletedCnt++
			}

			if len(curr.forward[0].vals) == 0 {
				skll.Erase(curr.forward[0].value)
			}
		}
	}

	var oldReads uint64 = 0
	// remove old
	if oldTNode, exist := sklt.table[key]; exist {
		oldReads = oldTNode.reads.Load()
		if oldTNode.sklNode.value == expiredUTC {
			// should not reach
			oldTNode.reads.Add(1)
			oldTNode.val = value
			return true
		}

		delete(oldTNode.sklNode.vals, key)
		if len(oldTNode.sklNode.vals) == 0 {
			skll.Erase(oldTNode.sklNode.value)
			sklc.count.Add(-1)
		}
	}

	sklc.count.Add(1)

	reads := &atomic.Uint64{}
	reads.Store(1 + oldReads)
	// check expireSecond match skipListNode exist or not
	if node, found := skll.Get(expiredUTC); found {
		// add new key
		node.vals[key] = struct{}{}
		// update
		sklt.table[key] = &TableNode{
			val:     value,
			sklNode: node,
			reads:   reads,
		}
		return true
	}

	node := skll.Insert(expiredUTC)
	node.vals[key] = struct{}{}
	sklt.table[key] = &TableNode{
		val:     value,
		sklNode: node,
		reads:   reads,
	}

	return true
}

// O(1) or O(logN)
// Optimizaion:
// 1. O(1): delay erase skipListNode until node.value < currentUTC
// 2. O(1): use double-linked list to contruct skiplist
func (sklc *SklCache) Remove(key string, qtype uint16) bool {
	// lazy init
	sklc.lazyInit(qtype)

	sklt := sklc.tables[qtype]
	sklt.lock.Lock()
	defer sklt.lock.Unlock()

	if tnode, found := sklt.table[key]; found {

		// remove entry in table
		delete(sklt.table, key)

		skll := sklc.skls[qtype]
		skll.lock.Lock()

		delete(tnode.sklNode.vals, key)

		if len(tnode.sklNode.vals) == 0 {
			// remove entry in list
			skll.Erase(tnode.sklNode.value)
		}

		sklc.count.Add(-1)
		skll.lock.Unlock()
		return true
	}
	return false
}

func (sklc *SklCache) Dump() map[string][]uint16 {
	res := make(map[string][]uint16)

	for qtype, table := range sklc.tables {
		if table == nil {
			continue
		}
		table.lock.RLock()
		for qname := range table.table {
			if res[qname] == nil {
				res[qname] = []uint16{}
			}
			res[qname] = append(res[qname], uint16(qtype))
		}
		table.lock.RUnlock()
	}
	return res
}

// 2500 ~ 25ms
// 2500 ~ 12ms (range cache)
// 2500 ~ 12ms (geo)
func (sklc *SklCache) Store() StoreElements {

	ses := make(StoreElements)

	for qtype, table := range sklc.tables {
		if table == nil {
			continue
		}
		table.lock.RLock()
		for qname, tnode := range table.table {

			if ses[qname] == nil {
				ses[qname] = make(map[uint16]*StoreElement, 2)
			}
			se := &StoreElement{
				Frequency: int(tnode.reads.Load()),
			}
			if tnode.extraElement == nil {
				tnode.extraElement = &extraElement{
					Country: xgeoip2.GetCountryIsoCodeFromMsg(tnode.val),
				}
			}
			se.Country = tnode.extraElement.Country
			se.Rcode = tnode.val.Rcode
			old := tnode.val.Compress
			tnode.val.Compress = false // it's ok
			se.MsgSize = tnode.val.Len()
			tnode.val.Compress = old
			se.MsgSections = len(tnode.val.Question) + len(tnode.val.Answer) + len(tnode.val.Ns) + len(tnode.val.Extra)
			ses[qname][uint16(qtype)] = se
		}
		table.lock.RUnlock()
	}
	return ses
}

// O(k)
// k: element's value less or equal target
func (sklc *SklCache) EraseBefore(qtype uint16, target int64) {

	// lazy init
	sklc.lazyInit(qtype)

	// O(k)
	// remove sklc.tables[int(qtype)].Table
	// remove sklc.tables[int(qtype)].EraseBefore(target)

	sklt := sklc.tables[qtype]
	sklt.lock.Lock()
	defer sklt.lock.Unlock()

	skll := sklc.skls[qtype]
	skll.lock.Lock()
	defer skll.lock.Unlock()

	curr := skll.head
	for curr != nil && curr.value <= target {
		for k := range curr.vals {
			delete(sklt.table, k)
		}
		curr = curr.forward[0]
	}
	skll.EraseBefore(target)
}

// Paper:
// 1. Skip Lists: A Probabilistic Alternative to Balanced Trees
//
// Performance:
// 1. convert into double-linklist, make delete node as O(1)
//
// in this use-case, for most case, delete node from head, which is O(1)
type SkipListNode struct {
	value   int64               // sorted element, expiredUTC = time.Now() + ttl (uint32)
	vals    map[string]struct{} // hashset
	forward []*SkipListNode
}

type SkipList struct {
	head  *SkipListNode
	level int
	rand  *rand.Rand
	lock  *sync.RWMutex

	MaxLevel    int
	Probability float64
}

func NewSkipList(maxLevel int, probability float64) *SkipList {
	if maxLevel <= 0 {
		panic(fmt.Sprintf("maxLevel %d not satisfied with (0, ~]", maxLevel))
	}

	if probability <= 0 || probability > 1 {
		panic(fmt.Sprintf("probability %f not satisfied with (0, 1.0]", probability))
	}

	skl := &SkipList{
		head:  NewSkipListNode(),
		level: 1,
		lock:  new(sync.RWMutex),

		MaxLevel:    maxLevel,
		Probability: probability,
	}

	skl.head.forward = make([]*SkipListNode, skl.MaxLevel)
	// use current timestamp as rand source
	skl.rand = rand.New(rand.NewSource(time.Now().UnixNano()))

	return skl
}

// FIXME
func NewSkipListNode() *SkipListNode {
	return &SkipListNode{
		vals: make(map[string]struct{}),
	}
}

func (skl *SkipList) Get(target int64) (*SkipListNode, bool) {
	curr := skl.head
	// from top-bottom search, each level SkipListNode is sorted
	for i := skl.level - 1; i >= 0; i-- {
		for curr.forward[i] != nil {
			if curr.forward[i].value == target {
				return curr.forward[i], true
			} else if curr.forward[i].value > target {
				break
			} else {
				curr = curr.forward[i]
			}
		}
	}
	return nil, false
}

func (skl *SkipList) Search(key string, target int64) (*SkipListNode, bool) {
	curr := skl.head
	// from top-bottom search, each level SkipListNode is sorted
	for i := skl.level - 1; i >= 0; i-- {
		for curr.forward[i] != nil {
			if curr.forward[i].value == target {
				if _, found := curr.forward[i].vals[key]; found {
					return curr.forward[i], true
				} else {
					return nil, false
				}
			} else if curr.forward[i].value > target {
				break
			} else {
				curr = curr.forward[i]
			}
		}
	}
	return nil, false
}

func (skl *SkipList) Insert(target int64) *SkipListNode {
	level := 1
	for skl.rand.Float64() < skl.Probability && level < skl.MaxLevel {
		level++
	}

	newLevel := level
	if newLevel < skl.level {
		newLevel = skl.level
	}
	update := make([]*SkipListNode, newLevel)
	curr := skl.head

	// all level node.Value less than target
	for i := skl.level - 1; i >= 0; i-- {
		for curr.forward[i] != nil && curr.forward[i].value < target {
			curr = curr.forward[i]
		}
		update[i] = curr
	}

	curr = curr.forward[0]

	// ignore duplicate
	if curr != nil && curr.value == target {
		return curr
	}

	// create new level, point to head
	if level > skl.level {
		for i := skl.level; i < level; i++ {
			update[i] = skl.head
		}
		skl.level = level
	}

	node := NewSkipListNode()
	node.value = target
	node.forward = make([]*SkipListNode, level)

	// insert new node
	for i := 0; i < level; i++ {
		node.forward[i] = update[i].forward[i]
		update[i].forward[i] = node
	}

	return node
}

// remove key in target SkipListNode
// if rest key (SkipListNode.vals) is empty, earse SkipListNode
func (skl *SkipList) Remove(target int64, key string) bool {

	if skl.head.forward[0] == nil {
		return false
	}

	update := make([]*SkipListNode, skl.MaxLevel)
	curr := skl.head
	for i := skl.level - 1; i >= 0; i-- {
		for curr.forward[i] != nil && curr.forward[i].value < target {
			curr = curr.forward[i]
		}
		update[i] = curr
	}

	curr = curr.forward[0]

	if curr == nil || curr.value != target {
		return false
	}

	delete(curr.vals, key)
	if len(curr.vals) > 0 {
		return true
	}

	// erease matching value
	for i := 0; i < skl.level; i++ {
		if update[i].forward[i] != nil && update[i].forward[i].value == target {
			update[i].forward[i] = curr.forward[i]
		}
	}
	// free
	curr = nil

	for skl.level > 1 && skl.head.forward[skl.level-1] == nil {
		skl.level--
	}

	return true
}

// earse all SkipListNodes (SkipListNode.Value <= target)
func (skl *SkipList) EraseBefore(target int64) bool {

	if skl.head.forward[0] == nil {
		return false
	}

	update := make([]*SkipListNode, skl.MaxLevel)
	curr := skl.head
	for i := skl.level - 1; i >= 0; i-- {
		for curr.forward[i] != nil && curr.forward[i].value < target {
			curr = curr.forward[i]
		}
		update[i] = curr
	}

	curr = curr.forward[0]

	if curr == nil || curr.forward[0] == nil {
		// remove all
		for i := 0; i < skl.level; i++ {
			skl.head.forward[i] = nil
		}
		skl.level = 0

		return true
	}

	for i := 0; i < skl.level; i++ {
		if update[i].forward[i] == nil {
			skl.head.forward[i] = nil
		} else if update[i].forward[i].value == target {
			// update[i].forward[0].formard[i]
			skl.head.forward[i] = curr.forward[i]
		} else {
			skl.head.forward[i] = update[i].forward[i]
		}
		// free
		update[i] = nil
	}

	// free
	curr = nil

	for skl.level > 1 && skl.head.forward[skl.level-1] == nil {
		skl.level--
	}

	return true
}

// earse SkipListNode (SkipListNode.Value == target)
func (skl *SkipList) Erase(target int64) bool {

	if skl.head.forward[0] == nil {
		return false
	}

	update := make([]*SkipListNode, skl.MaxLevel)
	curr := skl.head
	for i := skl.level - 1; i >= 0; i-- {
		for curr.forward[i] != nil && curr.forward[i].value < target {
			curr = curr.forward[i]
		}
		update[i] = curr
	}

	curr = curr.forward[0]

	if curr == nil || curr.value != target {
		return false
	}

	// erease matching value
	for i := 0; i < skl.level; i++ {
		if update[i].forward[i] != nil && update[i].forward[i].value == target {
			update[i].forward[i] = curr.forward[i]
		}
	}
	// free
	curr = nil

	for skl.level > 1 && skl.head.forward[skl.level-1] == nil {
		skl.level--
	}
	return true
}
