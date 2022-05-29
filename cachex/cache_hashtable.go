package cachex

import (
	"gnamed/configx"
	"gnamed/libnamed"
	"sync"
)

type Element struct {
	key        string
	qtype      uint16
	value      []byte
	expiredUTC int64
}

type Elements struct {
	element map[string]Element
	lock    *sync.RWMutex
}

type Cache struct {
	// qtype -> len(key) % mod -> {key: element}
	cache [][]Elements
}

func NewDefaultHashCache() {
	newHashCache(256)
}

func NewHashCache(slots int) *Cache {
	return newHashCache(slots)
}

func newHashCache(slots int) *Cache {

	libnamed.Logger.Trace().Str("log_type", "cache").Str("cache_mode", configx.CacheModeHashTable).Int("slots", slots).Msg("")

	cache := make([][]Elements, slots)
	for _i := range cache {
		ems := make([]Elements, 8)
		for _j := range ems {
			ems[_j] = Elements{
				element: make(map[string]Element),
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

	return c
}

func (c *Cache) Get(key string, qtype uint16) ([]byte, int64, bool) {
	i := int(qtype) % len(c.cache)
	j := len(key) % len(c.cache[0])

	c.cache[i][j].lock.RLock()
	if e, _found := c.cache[i][j].element[key]; _found {

		if libnamed.GetFakeTimerUnixSecond() > e.expiredUTC {
			c.cache[i][j].lock.RUnlock()
			c.Remove(key, qtype)
			return []byte{}, e.expiredUTC, false
		}

		defer c.cache[i][j].lock.RUnlock()
		return e.value, e.expiredUTC, true
	}
	c.cache[i][j].lock.RUnlock()
	return []byte{}, 0, false
}

func (c *Cache) Remove(key string, qtype uint16) bool {
	i := int(qtype) % len(c.cache)
	j := len(key) % len(c.cache[0])

	c.cache[i][j].lock.Lock()
	delete(c.cache[i][j].element, key)
	c.cache[i][j].lock.Unlock()
	return true
}

func (c *Cache) Set(key string, qtype uint16, value []byte, ttl uint32) bool {
	i := int(qtype) % len(c.cache)
	j := len(key) % len(c.cache[0])

	element := Element{
		key:        key,
		qtype:      qtype,
		value:      value,
		expiredUTC: libnamed.GetFakeTimerUnixSecond() + int64(ttl),
	}
	c.cache[i][j].lock.Lock()
	c.cache[i][j].element[key] = element
	c.cache[i][j].lock.Unlock()
	return true
}
