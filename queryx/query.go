package queryx

import (
	"errors"
	"fmt"
	"gnamed/cachex"
	"gnamed/configx"
	"gnamed/libnamed"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

func Query(r *dns.Msg, config *configx.Config, logEvent *zerolog.Event) (*dns.Msg, error) {

	var err error

	// pre-check
	if r == nil {
		err = errors.New("invalid dns message")
		libnamed.Logger.Error().Err(err).Msg("")
		return nil, err
	}

	logEvent.Uint16("id", r.Id)
	if len(r.Question) == 0 {
		rmsg := new(dns.Msg)
		rmsg.SetReply(r)
		rmsg.Rcode = dns.RcodeFormatError
		return rmsg, fmt.Errorf("invalid dns query")
	}

	origName := r.Question[0].Name
	qtype := dns.TypeToString[r.Question[0].Qtype]
	qclass := dns.ClassToString[r.Question[0].Qclass]

	logEvent.Str("orig_name", origName).Str("qtype", qtype).Str("qclass", qclass)

	if qtype == "" || qclass == "" {
		rmsg := new(dns.Msg)
		rmsg.SetReply(r)
		rmsg.Rcode = dns.RcodeFormatError
		return rmsg, fmt.Errorf("invalid dns query")
	}

	// disable singleflight
	if !config.Server.Main.Singleflight {
		return query(r, config, logEvent, false)
	}

	// enable singleflight
	singleflightGroup := config.GetSingleFlightGroup(r.Question[0].Qclass, r.Question[0].Qtype)
	f := func() (*dns.Msg, error) {
		return query(r, config, logEvent, false)
	}

	rmsg, hit, err := singleflightGroup.Do(strings.ToLower(origName), f)
	logEvent.Bool("singleflight", hit)
	if err != nil {
		return rmsg, err
	}

	// NOTICE: two dns msg has same question not equal same dns msg, they might has different flags or some others.
	// singleflight already make sure do deep copy, return values are concurrency safe.
	if hit {
		// return from prev copy, need to make sure update name
		setReply(rmsg, r, origName)
		return rmsg, err
	}
	return rmsg, err
}

func query(r *dns.Msg, config *configx.Config, logEvent *zerolog.Event, byPassCache bool) (*dns.Msg, error) {
	var err error

	origName := r.Question[0].Name
	qname := origName
	qtype := dns.TypeToString[r.Question[0].Qtype]

	// Filter
	// 1. validate domain
	if !libnamed.ValidateDomain(origName) {
		r.SetReply(r)
		r.Rcode = dns.RcodeFormatError
		logEvent.Str("query_type", "query_fake").Str("rcode", dns.RcodeToString[r.Rcode])
		return r, fmt.Errorf("invalid domain base on RFC 1035 and RFC 3696")
	}

	// 2. whitelist/blacklist search
	if _r, _s, _forbidden := config.Query.QueryForbidden(origName, qtype); _forbidden {
		rmsg, err := queryFake(r, nil)
		logEvent.Str("query_type", "query_fake").Str("rcode", dns.RcodeToString[rmsg.Rcode]).Str("blacklist", _r+"_"+_s)
		return rmsg, err
	}

	cname, vname := config.Server.FindRealName(origName)
	logEvent.Str("view_name", vname)
	if cname != qname {
		qname = cname
		logEvent.Str("cname", cname)
		for i := range r.Question {
			r.Question[i].Name = cname
		}
	}

	logEvent.Str("qname", qname)

	// 3. cache search
	if !byPassCache {
		cacheCfg := config.Server.Cache
		if rmsg, expiredUTC, found := cacheGetDnsMsg(r, &cacheCfg); found || (cacheCfg.UseSteal && expiredUTC > 0) {
			if (cacheCfg.UseSteal || cacheCfg.BackgroundUpdate) && expiredUTC-libnamed.GetFakeTimerUnixSecond() <= cacheCfg.BeforeExpiredSecond {
				logEvent.Bool("background_update", true)
				// do background query
				go func(nr *dns.Msg) {
					_logEvent := libnamed.Logger.Trace().Str("log_type", "query_background").Uint16("id", nr.Id).Str("qtype", dns.TypeToString[nr.Question[0].Qtype])
					// bypass singflight & cache
					_, nerr := query(nr, config, _logEvent, true)
					_logEvent.Err(nerr).Msg("")
				}(r.Copy())
			}
			logEvent.Str("query_type", "").Str("rcode", dns.RcodeToString[rmsg.Rcode])
			if found {
				logEvent.Str("cache", "hit")
			} else {
				logEvent.Str("cache", "steal")
			}
			setReply(rmsg, r, origName)
			return rmsg, nil
		}
	} else {
		logEvent.Bool("by_pass_cache", byPassCache)
	}

	// 4. hosts lookup
	if record, found := config.Server.FindRecordFromHosts(qname, qtype); found {
		logEvent.Str("query_type", "hosts")
		rmsg := new(dns.Msg)
		rrs := strings.Join([]string{origName, "60", dns.ClassToString[r.Question[0].Qclass], qtype, record}, "    ")
		_rr, _err := dns.NewRR(rrs)
		if _err != nil {
			return nil, _err
		}
		rmsg.Answer = []dns.RR{_rr}
		setReply(rmsg, r, origName)
		return rmsg, nil
	}

	// 5. external query
	nameServerTag, nameserver := config.Server.FindViewNameServer(vname)
	logEvent.Str("nameserver_tag", nameServerTag)

	if nameserver == nil {
		// shouldn't reach here
		rmsg := new(dns.Msg)
		setReply(rmsg, r, origName)
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, fmt.Errorf("no avaliable view match name \"%s\"", origName)
	}

	var rmsg *dns.Msg

	queryStartTime := time.Now()
	switch nameserver.Protocol {
	case configx.ProtocolTypeDNS:
		logEvent.Str("query_type", "query_dns")
		rmsg, err = queryDoD(r, nameserver.Dns)
	case configx.ProtocolTypeDoH:
		logEvent.Str("query_type", "query_doh")
		rmsg, err = queryDoH(r, nameserver.DoH)
	case configx.ProtocolTypeDoT:
		logEvent.Str("query_type", "query_dot")
		rmsg, err = queryDoT(r, nameserver.DoT)
	case configx.ProtocolTypeDoQ:
		logEvent.Str("query_type", "query_doq")
		rmsg, err = queryDoQ(r, nameserver.DoQ)
	default:
		logEvent.Str("query_type", "query_dns")
		rmsg, err = queryDoD(r, nameserver.Dns)
	}
	logEvent.Dur("latency_query", time.Since(queryStartTime))
	// 4. cache response
	if err == nil {
		logEvent.Str("rcode", dns.RcodeToString[rmsg.Rcode])

		cacheTTL := getMsgTTL(rmsg, &config.Server.Cache)
		if cacheTTL == 0 {
			// rfc1035#section-4.1.3
			// zero ttl can be use for DNS rebinding attack, for the sake of security, should cache it short time
			// https://crypto.stanford.edu/dns/dns-rebinding.pdf
			logEvent.Str("cache", "skip_zero_ttl")
		} else {
			if ok := cacheSetDnsMsg(rmsg, cacheTTL); ok {
				logEvent.Str("cache", "update")
			} else {
				logEvent.Str("cache", "failed")
			}
		}
	} else {
		return nil, err
	}

	// 5. update reply msg
	setReply(rmsg, r, origName)
	return rmsg, err
}

// FIXME: public function should not here
func GetMsgTTL(r *dns.Msg, cacheCfg *configx.Cache) uint32 {
	return getMsgTTL(r, cacheCfg)
}

func getMsgTTL(r *dns.Msg, cacheCfg *configx.Cache) uint32 {

	var ttl uint32 = 0

	if r == nil {
		return ttl
	}

	if len(r.Answer) > 0 {
		qtype := r.Question[0].Qtype
		for _, rr := range r.Answer {
			if rr.Header().Rrtype != qtype {
				continue
			}
			ttl = rr.Header().Ttl
			break
		}
		if ttl == 0 {
			// only cname, but no qtype record
			ttl = r.Answer[0].Header().Ttl
		}

		if cacheCfg.MaxTTL > 0 && ttl > cacheCfg.MaxTTL {
			ttl = cacheCfg.MaxTTL
		}
	} else {
		for _, rr := range r.Ns {
			if rr.Header().Rrtype == dns.TypeSOA {
				_soa := rr.(*dns.SOA)
				ttl = _soa.Expire
				if cacheCfg.MaxTTL > 0 && ttl > cacheCfg.MaxTTL {
					ttl = cacheCfg.MaxTTL
				}
				break
			}
		}
	}

	if ttl < cacheCfg.MinTTL {
		ttl = cacheCfg.MinTTL
	}
	return ttl
}

func cacheSetDnsMsg(r *dns.Msg, cacheTTL uint32) bool {
	bmsg, err := r.Pack()
	if err != nil || cacheTTL <= 0 {
		qname := r.Question[0].Name
		qtype := r.Question[0].Qtype
		libnamed.Logger.Error().Str("op_type", "pack_msg").Str("qname", qname).Str("qtype", dns.TypeToString[qtype]).Err(err).Msg("")
		return false
	}
	return cachex.Set(strings.ToLower(r.Question[0].Name), r.Question[0].Qtype, bmsg, cacheTTL)
}

func cacheGetDnsMsg(r *dns.Msg, cacheCfg *configx.Cache) (*dns.Msg, int64, bool) {
	qname := r.Question[0].Name
	qtype := r.Question[0].Qtype
	if bmsg, expiredUTC, found := cachex.Get(strings.ToLower(qname), qtype); found || (cacheCfg.UseSteal && expiredUTC > 0) {
		resp := new(dns.Msg)
		if err := resp.Unpack(bmsg); err != nil {
			// 1. log error
			// 2. delete cache ?
			// 3. ignore
			libnamed.Logger.Error().Str("op_type", "unpack_cache_msg").Str("qname", qname).Str("qtype", dns.TypeToString[qtype]).Err(err).Msg("")
			return nil, expiredUTC, false
		}

		cacheTTL := getMsgTTL(resp, cacheCfg)
		replyUpdateTTL(resp, expiredUTC, cacheTTL)

		return resp, expiredUTC, found
	}

	return nil, 0, false
}

func replyUpdateTTL(r *dns.Msg, expiredUTC int64, ttl uint32) {
	if len(r.Answer) == 0 {
		return
	}

	nowUTC := libnamed.GetFakeTimerUnixSecond()

	// rfc1035#section-4.1.3:
	// Zero values are interpreted to mean that the RR can only be used for the
	// transaction in progress, and should not be cached.
	if nowUTC > expiredUTC {
		return
	}

	currTTL := uint32(expiredUTC - nowUTC)
	skipSec := ttl - currTTL

	for i := range r.Answer {
		r.Answer[i].Header().Ttl = subTTL(r.Answer[i].Header().Ttl, skipSec)
	}

	for i := range r.Ns {
		r.Ns[i].Header().Ttl = subTTL(r.Ns[i].Header().Ttl, skipSec)
	}

	for i := range r.Extra {
		r.Extra[i].Header().Ttl = subTTL(r.Extra[i].Header().Ttl, skipSec)
	}

}

func subTTL(ttl uint32, skip uint32) uint32 {
	if ttl <= skip {
		// some program treat zero ttl as invalid answer, set as 1 increase compatibility
		return 1
	} else {
		return ttl - skip
	}
}

func replyUpdateName(r *dns.Msg, oldname string) {

	if len(r.Question) == 0 {
		return
	}
	qname := r.Question[0].Name
	if qname != oldname {
		// Question SECTION
		for i := range r.Question {
			r.Question[i].Name = oldname
		}
		// ANSWER SECTION
		for i := range r.Answer {
			if r.Answer[i].Header().Name == qname {
				r.Answer[i].Header().Name = oldname
			}
		}
		// AUTHORITY SECTION
		for i := range r.Ns {
			if r.Ns[i].Header().Name == qname {
				r.Ns[i].Header().Name = oldname
			}
		}
		// ADDITIONAL SECTION
		for i := range r.Extra {
			if r.Extra[i].Header().Name == qname {
				r.Extra[i].Header().Name = oldname
			}
		}
	}
}

func setReply(resp *dns.Msg, r *dns.Msg, oldName string) {
	rcode := resp.Rcode
	resp.SetReply(r)
	resp.Rcode = rcode

	// rfc1035#section-4.1.1:
	// 1. act as forwarded/authoritative name server, didn't support recursive query
	// 2. RA: denotes whether recursive query support is avaliable in the name server (this)
	// 3. If RD is set, it directs the name server to pursue the query recursively. Recursive query support is optional
	if r.RecursionDesired {
		// fix dig output (while RD set) ";; WARNING: recursion requested but not available"
		resp.RecursionAvailable = true
	}

	// rfc7873#section-5.2
	// Fix OPT PSEUDOSECTION COOKIE
	if opt := r.IsEdns0(); opt != nil {
		if ropt := resp.IsEdns0(); ropt != nil {
			// echo cookie
			*ropt = *opt
		}
	}
	replyUpdateName(resp, oldName)
}
