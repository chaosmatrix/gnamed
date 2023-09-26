package cachex

import (
	"fmt"
	"gnamed/ext/faketimer"
	"gnamed/ext/xlog"
	"math"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

const (
	CacheModeSkipList  = "skiplist"
	CacheModeHashTable = "hashtable"
)

type Cachexer interface {
	// TODO: change xpiredUTC to passSec
	Get(key string, qtype uint16) (val *dns.Msg, expiredUTC int64, exist bool)
	Set(key string, qtype uint16, value *dns.Msg, ttl uint32) bool
	Remove(key string, qtype uint16) bool
	Dump() map[string][]int16
	Store() StoreElements
}

// Expose Public Functions
var Get func(key string, qtype uint16) (*dns.Msg, int64, bool)
var Set func(key string, qtype uint16, value *dns.Msg, ttl uint32) bool
var Remove func(key string, qtype uint16) bool
var Dump func() map[string][]uint16
var Store func() StoreElements

// RR Cache
type RrCache struct {
	MaxTTL                      uint32  `json:"maxTTL"`
	MinTTL                      uint32  `json:"minTTL"`
	NxMaxTTL                    uint32  `json:"nxMaxTTL"` // TTL for NXDOMAIN
	NxMinTTL                    uint32  `json:"nxMinTTL"`
	ErrTTL                      uint32  `json:"errTTL"` // TTL for not NXDomain ERROR
	Mode                        string  `json:"mode"`
	RefreshBeforeExpiredSec     uint32  `json:"refreshBeforeExpiredSec"`     // time.Now().Unix() >= expired - RefreshBeforeExpiredSec
	RefreshBeforeExpiredPercent float64 `json:"refreshBeforeExpiredPercent"` // time.Now().Unix() >= expired - ttl * RefreshBeforeExpiredPercent
	UseSteal                    bool    `json:"useSteal"`                    // use steal cache and do background update

	// options for different cache mode
	SkipListConfig  *SklCacheConfig       `json:"skiplist,omitempty"`
	HashTableConfig *HashTableCacheConfig `json:"hashtable,omitempty"`

	// internal use
	enableBackgroundUpdate bool      `json:"-"` // true if UseSteal || BeforeExpiredSecond != 0 || BeforeExpiredPercent != 0
	backgroundQueryMap     *sync.Map `json:"-"`
}

func (rc *RrCache) Parse() error {
	if err := rc.parse(); err != nil {
		return err
	}
	rc.initDefault()
	return nil
}

func (rc *RrCache) parse() error {

	if rc.MinTTL > rc.MaxTTL {
		err := fmt.Errorf("MinTTL: %d > MaxTTL: %d", rc.MinTTL, rc.MaxTTL)
		xlog.Logger().Error().Str("log_type", "cache").Str("log_type", "parse").Err(err).Msg("")
		return err
	}

	if rc.NxMinTTL > rc.NxMaxTTL {
		err := fmt.Errorf("MinTTL: %d > MaxTTL: %d", rc.NxMinTTL, rc.NxMaxTTL)
		xlog.Logger().Error().Str("log_type", "cache").Str("log_type", "parse").Err(err).Msg("")
		return err
	}

	if rc.ErrTTL == 0 {
		rc.ErrTTL = 60
	}

	rc.enableBackgroundUpdate = rc.UseSteal || rc.RefreshBeforeExpiredSec != 0 || rc.RefreshBeforeExpiredPercent != 0

	if rc.enableBackgroundUpdate {
		rc.backgroundQueryMap = new(sync.Map)
	}

	if rc.SkipListConfig == nil {
		rc.SkipListConfig = &SklCacheConfig{}
	} else {
		if err := rc.SkipListConfig.Parse(); err != nil {
			return err
		}
	}

	switch rc.Mode {
	case "", CacheModeSkipList:
		rc.Mode = CacheModeSkipList
		if rc.SkipListConfig == nil {
			rc.SkipListConfig = &SklCacheConfig{}
		}
		if err := rc.SkipListConfig.Parse(); err != nil {
			return err
		}
	case CacheModeHashTable:
		if rc.HashTableConfig == nil {
			rc.HashTableConfig = &HashTableCacheConfig{}
		}
		if err := rc.HashTableConfig.Parse(); err != nil {
			return err
		}
	default:
		err := fmt.Errorf("invalid cache mode '%s', allowed cache mode: %v", rc.Mode, []string{CacheModeSkipList, CacheModeHashTable})
		xlog.Logger().Error().Str("log_type", "cache").Str("log_type", "parse").Err(err).Msg("")
		return err
	}

	return nil
}

var defaultOnce *sync.Once = &sync.Once{}

// disable changing cache mode during running(reload)
func (rc *RrCache) initDefault() {
	defaultOnce.Do(func() {
		switch rc.Mode {
		case CacheModeSkipList:
			InitDefaultSklCache(rc.SkipListConfig)
		case CacheModeHashTable:
			InitDefaultHashCache()
		default:
			panic(fmt.Errorf("invalid cache mode: %s", rc.Mode))
		}
	})
}

// err: func execute status, nil means success or not execute
// ok: lock status, false if failed to lock
func (rc *RrCache) BackgroundUpdate(lockKey string, r *dns.Msg, f func(*dns.Msg) error) (err error, locked bool) {
	if !rc.BackgroundQueryTryLock(lockKey) {
		return nil, false
	}
	defer rc.BackgroundQueryUnlock(lockKey)
	err = f(r)
	return err, true
}

// try to get lock about key
// return false, if key already locked, else return true and lock the key
func (c *RrCache) BackgroundQueryTryLock(lockKey string) bool {
	_, loaded := c.backgroundQueryMap.LoadOrStore(lockKey, true)
	return !loaded
}

func (c *RrCache) BackgroundQueryUnlock(lockKey string) {
	c.backgroundQueryMap.Delete(lockKey)
}

func (rc *RrCache) IsNeedBackgroundUpdate(ttl uint32, passTTL uint32) bool {
	if !rc.enableBackgroundUpdate {
		return false
	}

	if ttl <= passTTL {
		return true
	}

	if rc.RefreshBeforeExpiredSec > 0 && ttl-passTTL <= rc.RefreshBeforeExpiredSec {
		return true
	}

	if rc.RefreshBeforeExpiredPercent > 0 && ttl-uint32(float64(ttl)*rc.RefreshBeforeExpiredPercent) <= passTTL {
		return true
	}

	return false
}

func (rc *RrCache) SetMsg(msg *dns.Msg) bool {
	qname := msg.Question[0].Name
	qtype := msg.Question[0].Qtype
	ttl := rc.GetMsgTTL(msg)
	if ttl <= 0 {
		// prevent dns-rebind, set to 60 to cache the resule in short time
		// some resolver's implementation will try to set ttl to 0 to disable client cache result
		xlog.Logger().Error().Str("log_type", "cache").Str("name", qname).Str("qtype", dns.TypeToString[qtype]).Uint32("ttl", ttl).Msg("cache result in 60s to prevent dns-rebind")
		ttl = 60
	}
	return Set(strings.ToLower(qname), qtype, msg, ttl)
}

func (rc *RrCache) GetMsg(r *dns.Msg, backgroundUpdateFunc func(*dns.Msg) error) (*dns.Msg, bool) {
	qname := strings.ToLower(r.Question[0].Name)
	qtype := r.Question[0].Qtype
	if resp, expiredUTC, found := Get(qname, qtype); found || (rc.UseSteal && resp != nil) {

		ttl := rc.getMsgTTL(resp)
		var passTTL uint32 = 0
		if d := faketimer.GetFakeTimerUnixSecond() - expiredUTC + int64(ttl); d >= 0 {
			passTTL = uint32(d)
		}
		if rc.enableBackgroundUpdate && backgroundUpdateFunc != nil {
			if !found || rc.IsNeedBackgroundUpdate(ttl, passTTL) {
				lockKey := qname + "_" + dns.ClassToString[r.Question[0].Qclass] + "_" + dns.TypeToString[qtype]
				go rc.BackgroundUpdate(lockKey, r.Copy(), backgroundUpdateFunc)
			}
		}
		updateMsgTTL(resp, passTTL)
		return resp, found
	}

	return nil, false
}

func (rc *RrCache) GetMsgTTL(msg *dns.Msg) uint32 {
	return rc.getMsgTTL(msg)
}

func (rc *RrCache) getMsgTTL(msg *dns.Msg) uint32 {
	var ttl uint32 = 0
	if msg == nil {
		return ttl
	}

	rcode := msg.Rcode
	if len(msg.Answer) > 0 {
		qtype := msg.Question[0].Qtype
		for _, ans := range msg.Answer {
			if ans.Header().Rrtype == qtype {
				ttl = ans.Header().Ttl
				break
			}
			ttl = ans.Header().Ttl
		}
	} else {
		for _, ans := range msg.Ns {

			// SOA Record
			// REFRESH: TTL for NXDomain
			// RETRY: TTL for not NXDomain and NOERROR
			// EXPIRE: upper TTL for NOERROR
			if ans.Header().Rrtype == dns.TypeSOA {
				if soa, ok := ans.(*dns.SOA); ok {
					if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
						ttl = soa.Refresh
					} else {
						ttl = soa.Retry
					}
				}
				break
			}
		}
	}
	switch rcode {
	case dns.RcodeSuccess:
		ttl = correctTTL(ttl, rc.MinTTL, rc.MaxTTL)
	case dns.RcodeNameError:
		ttl = correctTTL(ttl, rc.NxMinTTL, rc.NxMaxTTL)
	default:
		ttl = correctTTL(ttl, rc.ErrTTL, math.MaxUint32)
	}
	return ttl
}

func correctTTL(v uint32, minval uint32, maxval uint32) uint32 {
	if minval > 0 && v < minval {
		v = minval
	}
	if maxval >= minval && v > maxval {
		v = maxval
	}
	return v
}

func updateMsgTTL(msg *dns.Msg, passTTL uint32) {
	if len(msg.Answer) == 0 || passTTL == 0 {
		return
	}

	for i := range msg.Answer {
		msg.Answer[i].Header().Ttl = subTTL(msg.Answer[i].Header().Ttl, passTTL)
	}

	for i := range msg.Ns {
		msg.Ns[i].Header().Ttl = subTTL(msg.Ns[i].Header().Ttl, passTTL)
	}

	for i := range msg.Extra {
		msg.Extra[i].Header().Ttl = subTTL(msg.Extra[i].Header().Ttl, passTTL)
	}

}

func subTTL(ttl uint32, skip uint32) uint32 {
	// some program treat zero ttl as invalid answer, set as 1 increase compatibility
	// rfc1035#section-4.1.3:
	// Zero values are interpreted to mean that the RR can only be used for the
	// transaction in progress, and should not be cached.
	if ttl <= skip {
		return 23
	} else {
		return ttl - skip
	}
}
