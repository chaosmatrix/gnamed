package cachex

type Cachexer interface {
	Get(key string, qtype uint16) (val []byte, expiredUTC int64, exist bool)
	Set(key string, qtype uint16, value []byte, ttl uint32) bool
	Remove(key string, qtype uint16) bool
}

// Expose Public Functions
var Get func(key string, qtype uint16) ([]byte, int64, bool)
var Set func(key string, qtype uint16, value []byte, ttl uint32) bool
var Remove func(key string, qtype uint16) bool
