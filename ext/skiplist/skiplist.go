package skiplist

import (
	"math"
	"math/rand"
	"sync"
	"time"
)

type SkipNode struct {
	position int
	vals     map[string]interface{}
	next     []*SkipNode
	prev     []*SkipNode
}

type SkipList struct {
	head *SkipNode
	tail *SkipNode
	lock *sync.RWMutex

	nodeCount    int
	elementCount int
	rand         *rand.Rand

	level       int
	probability float64
}

func NewSkipList(level int, probability float64) *SkipList {

	nexts := make([]*SkipNode, level)

	head := &SkipNode{
		position: math.MinInt64,
		vals:     make(map[string]interface{}),
		next:     nexts,
	}

	tail := &SkipNode{
		position: math.MaxInt64,
		prev:     make([]*SkipNode, level),
		vals:     make(map[string]interface{}),
	}
	for i := 0; i < level; i++ {
		nexts[i] = tail
		nexts[i].prev[i] = head
	}

	skl := &SkipList{
		head:         head,
		tail:         tail,
		lock:         new(sync.RWMutex),
		rand:         rand.New(rand.NewSource(time.Now().UnixMicro())),
		elementCount: 0,
		nodeCount:    2,
		level:        level,
		probability:  probability,
	}

	return skl
}

func (skl *SkipList) getRandLevel() int {
	level := 1
	for skl.rand.Float64() < skl.probability && level < skl.level {
		level++
	}
	return level
}

func (skl *SkipList) Insert(position int, key string, val interface{}) *SkipNode {
	skl.lock.Lock()
	defer skl.lock.Unlock()

	curr := skl.head
	updates := make([]*SkipNode, skl.level)

	if curr.position == position {
		goto LabelFound
	}

	for i := skl.level - 1; i >= 0; i-- {
		for len(curr.next) > i && curr.next[i].position <= position {
			curr = curr.next[i]
		}
		if curr.position == position {
			goto LabelFound
		}
		updates[i] = curr
	}

LabelFound:
	if curr.position == position {
		if _, found := curr.vals[key]; !found {
			skl.elementCount++
		}
		curr.vals[key] = val

		return curr
	}

	level := skl.getRandLevel()

	for i := level - 1; i >= 0 && updates[i] == nil; i-- {
		updates[i] = skl.head
	}

	node := &SkipNode{
		position: position,
		vals:     make(map[string]interface{}),
		prev:     make([]*SkipNode, level),
		next:     make([]*SkipNode, level),
	}
	node.vals[key] = val
	for i := 0; i < level; i++ {

		node.next[i] = updates[i].next[i]
		node.prev[i] = updates[i]
		updates[i].next[i].prev[i] = node
		updates[i].next[i] = node
	}
	skl.nodeCount++
	skl.elementCount++

	return node
}

func (skl *SkipList) Search(position int, key string) (bool, interface{}) {
	skl.lock.Lock()
	defer skl.lock.Unlock()

	curr := skl.head
	if curr.position == position {
		goto LabelFound
	}

	for i := skl.level - 1; i >= 0; i-- {
		for len(curr.next) > i && curr.next[i].position <= position {
			curr = curr.next[i]
		}
		if curr.position == position {
			goto LabelFound
		}
	}

LabelFound:
	if curr == nil || curr.position != position {
		return false, nil
	}

	val, found := curr.vals[key]

	return found, val
}

func (skl *SkipList) Delete(position int, key string) interface{} {
	skl.lock.Lock()
	defer skl.lock.Unlock()

	curr := skl.head
	if curr.position == position {
		goto LabelFound
	}

	for i := skl.level - 1; i >= 0; i-- {
		for len(curr.next) > i && curr.next[i].position <= position {
			curr = curr.next[i]
		}
		if curr.position == position {
			goto LabelFound
		}
	}

LabelFound:
	if val, found := curr.vals[key]; found {
		skl.elementCount--

		if len(curr.vals) <= 1 {
			skl.removeWithoutLock(curr)
		} else {
			delete(curr.vals, key)
		}
		return val
	}

	return nil
}

func (skl *SkipList) Remove(skn *SkipNode) *SkipNode {
	skl.lock.Lock()
	defer skl.lock.Unlock()
	return skl.removeWithoutLock(skn)
}

// caller should lock
func (skl *SkipList) removeWithoutLock(skn *SkipNode) *SkipNode {

	if skn == nil {
		return nil
	}
	// prevent remove head and tail
	if skn.position == math.MinInt64 || skn.position == math.MaxInt64 {
		skn.vals = make(map[string]interface{})
		return nil
	}

	for i := 0; i < len(skn.prev); i++ {
		skn.prev[i].next[i] = skn.next[i]
		skn.next[i].prev[i] = skn.prev[i]
	}
	skn.prev = []*SkipNode{}
	skn.next = []*SkipNode{}

	skl.nodeCount--

	return skn
}

type TypeRemoveMask uint8

const (
	RemoveMaskSkip TypeRemoveMask = 1 << iota
	RemoveMaskStop
	RemoveMaskDelete
)

func (skl *SkipList) RemoveNodeFunc(f func(position int) TypeRemoveMask) (checkCnt int, delCnt int) {
	skl.lock.Lock()
	defer skl.lock.Unlock()

	curr := skl.head
	if len(curr.vals) > 0 {
		checkCnt++
		switch f(curr.position) {
		case RemoveMaskDelete:
			skl.elementCount -= len(curr.vals)
			curr.vals = make(map[string]interface{})
			delCnt++
		case RemoveMaskStop:
			return
		case RemoveMaskSkip:
			//
		default:
			return
		}
	}

	for len(curr.next) > 0 && len(curr.next[0].vals) > 0 {

		checkCnt++
		switch f(curr.next[0].position) {
		case RemoveMaskDelete:
			skl.elementCount -= len(curr.next[0].vals)
			delCnt++
		case RemoveMaskStop:
			return
		case RemoveMaskSkip:
			continue
		default:
			return
		}

		if node := skl.removeWithoutLock(curr.next[0]); node == nil {
			return
		}
	}
	return
}

func (skl *SkipList) RemoveFunc(f func(position int, key string) TypeRemoveMask) (checkCnt int, delCnt int) {
	skl.lock.Lock()
	defer skl.lock.Unlock()

	curr := skl.head
	for k := range curr.vals {
		checkCnt++
		switch f(curr.position, k) {
		case RemoveMaskDelete:
			delete(curr.vals, k)
			skl.elementCount--
			delCnt++
		case RemoveMaskStop:
			return
		case RemoveMaskSkip:
			//
		default:
			return
		}
	}

	for len(curr.next) > 0 && len(curr.next[0].vals) > 0 {

		for k := range curr.next[0].vals {
			checkCnt++
			switch f(curr.next[0].position, k) {
			case RemoveMaskDelete:
				delete(curr.next[0].vals, k)
				skl.elementCount--
				delCnt++
			case RemoveMaskStop:
				return
			case RemoveMaskSkip:
				//
			default:
				return
			}
		}

		if len(curr.next[0].vals) == 0 {
			if node := skl.removeWithoutLock(curr.next[0]); node == nil {
				return
			}
		} else {
			curr = curr.next[0]
		}
	}
	return
}

// remove at most N elements from head
// if more than N elements in same position, remove randomly
func (skl *SkipList) RemoveN(n int) (delCnt int) {
	return skl.RemoveNLessEqual(n, math.MaxInt64)
}

// remove at most N elements from head which less than position
// if more than N elements in same position, remove randomly
func (skl *SkipList) RemoveNLessEqual(n int, position int) (delCnt int) {
	skl.lock.Lock()
	defer skl.lock.Unlock()
	delCnt = 0

	curr := skl.head
	if curr.position <= position && len(curr.vals) > 0 {
		if len(curr.vals) <= n {
			delCnt += len(curr.vals)
			n -= len(curr.vals)

			skl.elementCount -= len(curr.vals)
			skl.nodeCount--

			curr.vals = make(map[string]interface{})
		} else {
			for k := range curr.vals {
				delete(curr.vals, k)
				delCnt++
				n--
				skl.elementCount--
				if n <= 0 {
					return delCnt
				}
			}
		}
	}

	for n > 0 && len(curr.next) > 0 && curr.next[0].position <= position && len(curr.next[0].vals) > 0 {
		if len(curr.next[0].vals) <= n {
			delCnt += len(curr.next[0].vals)
			n -= len(curr.next[0].vals)

			skl.elementCount -= len(curr.next[0].vals)
			if delNode := skl.removeWithoutLock(curr.next[0]); delNode == nil {
				return delCnt
			}
		} else {
			for k := range curr.next[0].vals {
				delete(curr.next[0].vals, k)
				delCnt++
				n--
				skl.elementCount--
				if n <= 0 {
					return delCnt
				}
			}
		}
	}

	return delCnt
}

// remove at most N Nodes from head
func (skl *SkipList) RemoveNNode(n int) (delCnt int) {
	return skl.RemoveNNodeLessEqual(n, math.MaxInt64)
}

// remove at most N Nodes from head which less equal with position
func (skl *SkipList) RemoveNNodeLessEqual(n int, position int) (delCnt int) {
	skl.lock.Lock()
	defer skl.lock.Unlock()

	curr := skl.head
	delCnt = 0

	if n > 0 && len(curr.vals) > 0 && curr.position <= position {
		n--
		delCnt++

		skl.elementCount -= len(curr.vals)
		skl.nodeCount--

		curr.vals = make(map[string]interface{})
	}

	for n > 0 && len(curr.next) > 0 && curr.next[0].position <= position && len(curr.next[0].vals) > 0 {
		n--
		delCnt++
		skl.elementCount -= len(curr.next[0].vals)
		if delNode := skl.removeWithoutLock(curr.next[0]); delNode == nil {
			return delCnt
		}
	}

	return delCnt
}

func (skl *SkipList) GetNode(position int) *SkipNode {
	skl.lock.Lock()
	defer skl.lock.Unlock()

	return skl.getNodeWithoutLock(position)
}

func (skl *SkipList) getNodeWithoutLock(position int) *SkipNode {
	curr := skl.head

	if curr.position == position {
		return curr
	}

	for i := skl.level - 1; i >= 0; i-- {
		for len(curr.next) > i && curr.next[i].position <= position {
			curr = curr.next[i]
		}
		if curr.position == position {
			return curr
		}
	}
	return nil
}

func (skl *SkipList) Walk(walkFunc func(position int, key string, val interface{})) {
	skl.lock.Lock()
	defer skl.lock.Unlock()

	curr := skl.head
	if len(curr.vals) > 0 {
		for k, v := range curr.vals {
			walkFunc(curr.position, k, v)
		}
	}

	for len(curr.next) > 0 && len(curr.next[0].vals) > 0 {
		for k, v := range curr.next[0].vals {
			walkFunc(curr.next[0].position, k, v)
		}
		curr = curr.next[0]
	}
}

func (skl *SkipList) collectLessEqualNodeFromHead(position int) (updates []*SkipNode) {
	updates = make([]*SkipNode, skl.level)

	curr := skl.head
	if curr.position == position {
		updates[0] = curr
		return
	}

	for i := skl.level - 1; i >= 0; i-- {
		for len(curr.next) > i && curr.next[i].position <= position {
			curr = curr.next[i]
		}
		if curr.position == position {
			updates[0] = curr
			return
		}
		updates[i] = curr
	}
	return
}

func (skl *SkipList) getLessEqualNodeFromTail(position int) *SkipNode {

	curr := skl.tail

	if curr.position == position {
		return curr
	}

	for i := skl.level - 1; i >= 0; i-- {
		for len(curr.prev) > i && curr.prev[i].position >= position {
			curr = curr.prev[i]
		}
		if curr.position == position {
			return curr
		}
	}

	if curr != nil && curr.position > position {
		return curr.prev[0]
	}
	return curr
}

func (skl *SkipList) getLessEqualNodeFromHead(position int) *SkipNode {

	curr := skl.head

	if curr.position == position {
		return curr
	}

	for i := skl.level - 1; i >= 0; i-- {
		for len(curr.next) > i && curr.next[i].position <= position {
			curr = curr.next[i]
		}
		if curr.position == position {
			return curr
		}
	}
	return curr
}
