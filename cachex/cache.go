package cachex

import (
	"gnamed/configx"

	"github.com/miekg/dns"
)

type Cachexer interface {
	Get(key string, qtype uint16) (val *dns.Msg, expiredUTC int64, exist bool)
	Set(key string, qtype uint16, value *dns.Msg, ttl uint32) bool
	Remove(key string, qtype uint16) bool
	Dump() map[string][]int16
	Store() *configx.WarmFormat
}

// Expose Public Functions
var Get func(key string, qtype uint16) (*dns.Msg, int64, bool)
var Set func(key string, qtype uint16, value *dns.Msg, ttl uint32) bool
var Remove func(key string, qtype uint16) bool
var Dump func() map[string][]uint16
var Store func() *configx.WarmFormat

func InitCache(cacheMode string) {
	// init cache
	switch cacheMode {
	case configx.CacheModeSkipList:
		NewDefaultSklCache()
	case configx.CacheModeHashTable:
		NewDefaultHashCache()
	default:
		panic("invalid cache mode")
	}
}
