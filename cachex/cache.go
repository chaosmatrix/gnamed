package cachex

import (
	"sync"
	"time"
)

type Cachexer interface {
	Get(key string, qtype uint16) ([]byte, bool)
	Set(key string, qtype uint16, value []byte) bool
	Remove(key string, qtype uint16) bool
}

type Element struct {
	key        string
	qtype      uint16
	value      []byte
	ttl        uint32
	createTime time.Time
}

type Elements struct {
	element map[string]Element
	lock    sync.RWMutex
}

type Cache struct {
	// qtype -> len(key) % mod -> {key: element}
	cache [][]Elements
}

var _Cache *Cache

func New(slot int) *Cache {
	_Cache = new(slot)
	return _Cache
}

func new(slot int) *Cache {
	cache := make([][]Elements, slot)
	for _i, _ := range cache {
		ems := make([]Elements, 8)
		for _j, _ := range ems {
			var lock sync.RWMutex
			ems[_j] = Elements{
				element: make(map[string]Element),
				lock:    lock,
			}
		}
		cache[_i] = ems
	}
	return &Cache{
		cache: cache,
	}
}

func Get(key string, qtype uint16) ([]byte, bool) {
	return _Cache.Get(key, qtype)
}

// TODO:
// 1. update ttl before reply
func (c *Cache) Get(key string, qtype uint16) ([]byte, bool) {
	i := int(qtype) % len(c.cache)
	j := len(key) % len(c.cache[0])

	now := time.Now()
	c.cache[i][j].lock.RLock()
	if _v, _found := c.cache[i][j].element[key]; _found {
		c.cache[i][j].lock.RUnlock()
		// bug: _v.ttl * uint32(time.Second)
		if now.Sub(_v.createTime) > time.Duration(time.Duration(_v.ttl)*time.Second) {
			c.Remove(key, qtype)
			return []byte{}, false
		}
		return _v.value, true
	}
	c.cache[i][j].lock.RUnlock()
	return []byte{}, false
}

func Remove(key string, qtype uint16) bool {
	return _Cache.Remove(key, qtype)
}

func (c *Cache) Remove(key string, qtype uint16) bool {
	i := int(qtype) % len(c.cache)
	j := len(key) % len(c.cache[0])

	c.cache[i][j].lock.Lock()
	delete(c.cache[i][j].element, key)
	c.cache[i][j].lock.Unlock()
	return true
}

func Set(key string, qtype uint16, value []byte, ttl uint32) bool {
	return _Cache.Set(key, qtype, value, ttl)
}

func (c *Cache) Set(key string, qtype uint16, value []byte, ttl uint32) bool {
	i := int(qtype) % len(c.cache)
	j := len(key) % len(c.cache[0])

	element := Element{
		key:        key,
		qtype:      qtype,
		value:      value,
		ttl:        ttl,
		createTime: time.Now(),
	}
	c.cache[i][j].lock.Lock()
	c.cache[i][j].element[key] = element
	c.cache[i][j].lock.Unlock()
	return true
}
