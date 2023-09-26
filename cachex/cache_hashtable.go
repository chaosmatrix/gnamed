package cachex

import (
	"gnamed/ext/faketimer"
	"gnamed/ext/xgeoip2"
	"gnamed/ext/xlog"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

type HashTableCacheConfig struct {
}

func (c *HashTableCacheConfig) Parse() error {

	return nil
}

type Element struct {
	key   string
	qtype uint16
	//value      []byte
	value        *dns.Msg
	extraElement *extraElement
	expiredUTC   int64
	reads        *atomic.Uint64 // cache hit count
}

type Elements struct {
	element map[string]*Element
	lock    *sync.RWMutex
}

type Cache struct {
	// qtype -> len(key) % mod -> {key: element}
	cache [][]*Elements
}

func InitDefaultHashCache() {
	newHashCache(256)
}

func NewHashCache(slots int) *Cache {
	if slots < 256 {
		slots = 256
	} else if slots > 65536 {
		slots = 65536
	}
	return newHashCache(slots)
}

func newHashCache(slots int) *Cache {

	xlog.Logger().Trace().Str("log_type", "cache").Str("op_type", "new").Str("cache_mode", CacheModeHashTable).Int("slots", slots).Msg("")

	cache := make([][]*Elements, slots)
	for _i := range cache {
		ems := make([]*Elements, 8)
		for _j := range ems {
			ems[_j] = &Elements{
				element: make(map[string]*Element),
				lock:    new(sync.RWMutex),
			}
		}
		cache[_i] = ems
	}
	c := &Cache{
		cache: cache,
	}

	// set public function
	Get = c.Get
	Set = c.Set
	Remove = c.Remove
	Dump = c.Dump
	Store = c.Store

	return c
}

func (c *Cache) Get(key string, qtype uint16) (*dns.Msg, int64, bool) {
	i := int(qtype) % len(c.cache)
	j := len(key) % len(c.cache[0])

	c.cache[i][j].lock.RLock()
	if e, _found := c.cache[i][j].element[key]; _found {

		val := e.value
		e.reads.Add(1)
		if faketimer.GetFakeTimerUnixSecond() > e.expiredUTC {
			c.cache[i][j].lock.RUnlock()
			c.Remove(key, qtype)
			return val.Copy(), e.expiredUTC, false
		}

		defer c.cache[i][j].lock.RUnlock()
		return val.Copy(), e.expiredUTC, true
	}
	c.cache[i][j].lock.RUnlock()
	return nil, 0, false
}

func (c *Cache) Remove(key string, qtype uint16) bool {
	i := int(qtype) % len(c.cache)
	j := len(key) % len(c.cache[0])

	c.cache[i][j].lock.Lock()
	delete(c.cache[i][j].element, key)
	c.cache[i][j].lock.Unlock()
	return true
}

func (c *Cache) Set(key string, qtype uint16, value *dns.Msg, ttl uint32) bool {

	value = value.Copy()

	i := int(qtype) % len(c.cache)
	j := len(key) % len(c.cache[0])

	reads := &atomic.Uint64{}
	reads.Store(1)
	element := &Element{
		key:        key,
		qtype:      qtype,
		value:      value,
		expiredUTC: faketimer.GetFakeTimerUnixSecond() + int64(ttl),
		reads:      reads,
	}
	c.cache[i][j].lock.Lock()
	c.cache[i][j].element[key] = element
	c.cache[i][j].lock.Unlock()
	return true
}

func (c *Cache) Dump() map[string][]uint16 {
	res := make(map[string][]uint16)

	for _, eless := range c.cache {
		if eless == nil {
			continue
		}
		for _, eles := range eless {
			eles.lock.RLock()
			for qname, ele := range eles.element {
				if res[qname] == nil {
					res[qname] = []uint16{}
				}
				res[qname] = append(res[qname], ele.qtype)

			}
			eles.lock.RUnlock()
		}
	}
	return res
}

func (c *Cache) Store() StoreElements {
	ses := make(StoreElements)

	for _, eless := range c.cache {
		if eless == nil {
			continue
		}
		for _, eles := range eless {
			eles.lock.RLock()
			for qname, ele := range eles.element {
				if ele.extraElement == nil {
					ele.extraElement = &extraElement{
						Country: xgeoip2.GetCountryIsoCodeFromMsg(ele.value),
					}
				}
				if ses[qname] == nil {
					ses[qname] = make(map[uint16]*StoreElement, 2)
				}
				se := &StoreElement{
					Frequency: int(ele.reads.Load()),
					Rcode:     ele.value.Rcode,
					Country:   ele.extraElement.Country,
				}
				ses[qname][ele.qtype] = se
			}
			eles.lock.RUnlock()
		}
	}
	return ses
}
