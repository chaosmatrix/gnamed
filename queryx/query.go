package queryx

import (
	"errors"
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
	if len(r.Question) == 0 {
		err = errors.New("dns message hasn't valid question")
		libnamed.Logger.Error().Uint16("id", r.Id).Err(err).Msg("")
		r.SetReply(r)
		r.Rcode = dns.RcodeFormatError
		return r, err
	}
	origName := r.Question[0].Name
	qtype := dns.TypeToString[r.Question[0].Qtype]
	logEvent.Uint16("id", r.Id).Str("orig_name", origName).Str("qtype", qtype)
	// disable singleflight
	if !config.Server.Main.Singleflight {
		return query(r, config, logEvent)
	}

	// enable singleflight
	singleflightGroup := config.GetSingleFlightGroup(r.Question[0].Qtype)
	f := func() (*dns.Msg, error) {
		return query(r, config, logEvent)
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

func query(r *dns.Msg, config *configx.Config, logEvent *zerolog.Event) (*dns.Msg, error) {
	var err error

	origName := r.Question[0].Name
	qname := origName
	qtype := dns.TypeToString[r.Question[0].Qtype]

	// Filter
	// 1. validate domain
	if !libnamed.ValidateDomain(origName) {
		r.SetReply(r)
		r.Rcode = dns.RcodeFormatError
		logEvent.Str("query_type", "query_fake").Str("rcode", dns.RcodeToString[r.Rcode]).Err(errors.New("invalid domain base on RFC 1035 and RFC 3696"))
		return r, err
	}

	// Cache
	// 0. lock - ensure single flying query or internal search
	// 1. whitelist/blacklist search
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
		for i, _ := range r.Question {
			r.Question[i].Name = cname
		}
	}

	logEvent.Str("qname", qname)

	// 2. cache search
	if rmsg, found := cacheGetDnsMsg(r, &config.Server.Cache); found {
		logEvent.Str("query_type", "").Str("rcode", dns.RcodeToString[rmsg.Rcode]).Str("cache", "hit")
		setReply(rmsg, r, origName)
		return rmsg, nil
	}
	// 3. external query
	dnsTag, nameserver := config.Server.FindNameServer(qname)
	logEvent.Str("nameserver_tag", dnsTag)

	if nameserver == nil {
		// reply from hosts file
		_record, _ := config.Server.FindRecordFromHosts(qname, qtype)
		_msg := strings.Join([]string{origName, "60", "IN", qtype, _record}, "    ")

		logEvent.Str("query_type", "hosts")
		rmsg := new(dns.Msg)
		_rr, _err := dns.NewRR(_msg)
		if _err != nil {
			return nil, _err
		}
		rmsg.Answer = []dns.RR{_rr}
		setReply(rmsg, r, origName)
		return rmsg, nil
	}

	var rmsg *dns.Msg

	queryStartTime := time.Now()
	switch nameserver.Protocol {
	case configx.ProtocolTypeDNS:
		logEvent.Str("query_type", "query_dns")
		rmsg, err = queryDoD(r, &nameserver.Dns)
	case configx.ProtocolTypeDoH:
		logEvent.Str("query_type", "query_doh")
		rmsg, err = queryDoH(r, &nameserver.DoH)
	case configx.ProtocolTypeDoT:
		logEvent.Str("query_type", "query_dot")
		rmsg, err = queryDoT(r, &nameserver.DoT)
	default:
		logEvent.Str("query_type", "query_dns")
		rmsg, err = queryDoD(r, &nameserver.Dns)
	}
	logEvent.Dur("latency_query", time.Since(queryStartTime))
	// 4. cache response
	if err == nil {
		logEvent.Str("rcode", dns.RcodeToString[rmsg.Rcode])

		cacheTTL := getMsgTTL(rmsg, &config.Server.Cache)
		if cacheTTL == 0 {
			// rfc1035#section-4.1.3
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

func getMsgTTL(r *dns.Msg, cacheCfg *configx.Cache) uint32 {

	// FIXME: default ttl should be configurable
	var ttl uint32 = 0

	if len(r.Answer) > 0 {
		qtype := r.Question[0].Qtype
		for _, _rr := range r.Answer {
			if _rr.Header().Rrtype != qtype {
				continue
			}
			ttl = _rr.Header().Ttl
			break
		}
		if ttl == 0 {
			// only cname, but no qtype record
			ttl = r.Answer[0].Header().Ttl
		}
		if cacheCfg.MinTTL > 0 && ttl < cacheCfg.MinTTL {
			ttl = cacheCfg.MinTTL
		} else if cacheCfg.MaxTTL > 0 && ttl > cacheCfg.MaxTTL {
			ttl = cacheCfg.MaxTTL
		}
	} else {
		for _, _rr := range r.Ns {
			if _rr.Header().Rrtype == dns.TypeSOA {
				_soa := _rr.(*dns.SOA)
				ttl = _soa.Expire
				if cacheCfg.MaxTTL > 0 && ttl > cacheCfg.MaxTTL {
					ttl = cacheCfg.MaxTTL
				} else if cacheCfg.MinTTL > 0 && ttl < cacheCfg.MinTTL {
					ttl = cacheCfg.MinTTL
				}
				break
			}
		}
	}
	return ttl
}

func cacheSetDnsMsg(r *dns.Msg, cacheTTL uint32) bool {
	bmsg, err := r.Pack()
	if err != nil || cacheTTL <= 0 {
		qname := r.Question[0].Name
		qtype := r.Question[0].Qtype
		libnamed.Logger.Error().Str("op_type", "pack_msg").Str("qname", qname).Uint16("qtype", qtype).Err(err).Msg("")
		return false
	}
	return cachex.Set(strings.ToLower(r.Question[0].Name), r.Question[0].Qtype, bmsg, cacheTTL)
}

func cacheGetDnsMsg(r *dns.Msg, cacheCfg *configx.Cache) (*dns.Msg, bool) {
	qname := r.Question[0].Name
	qtype := r.Question[0].Qtype
	if bmsg, expiredUTC, found := cachex.Get(strings.ToLower(qname), qtype); found {
		resp := new(dns.Msg)
		if err := resp.Unpack(bmsg); err != nil {
			// 1. log error
			// 2. delete cache ?
			// 3. ignore
			libnamed.Logger.Error().Str("op_type", "unpack_cache_msg").Str("qname", qname).Uint16("qtype", qtype).Err(err).Msg("")
			return nil, false
		}

		cacheTTL := getMsgTTL(resp, cacheCfg)
		replyUpdateTTL(resp, expiredUTC, cacheTTL)

		return resp, true
	}

	return nil, false
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

	for i, _ := range r.Answer {
		r.Answer[i].Header().Ttl = subTTL(r.Answer[i].Header().Ttl, skipSec)
	}

	for i, _ := range r.Ns {
		r.Ns[i].Header().Ttl = subTTL(r.Ns[i].Header().Ttl, skipSec)
	}

	for i, _ := range r.Extra {
		r.Extra[i].Header().Ttl = subTTL(r.Extra[i].Header().Ttl, skipSec)
	}

}

func subTTL(ttl uint32, skip uint32) uint32 {
	if ttl < skip {
		return 0
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
		for i, _ := range r.Question {
			r.Question[i].Name = oldname
		}
		// ANSWER SECTION
		for i, _ := range r.Answer {
			if r.Answer[i].Header().Name == qname {
				r.Answer[i].Header().Name = oldname
			}
		}
		// AUTHORITY SECTION
		for i, _ := range r.Ns {
			if r.Ns[i].Header().Name == qname {
				r.Ns[i].Header().Name = oldname
			}
		}
		// ADDITIONAL SECTION
		for i, _ := range r.Extra {
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
