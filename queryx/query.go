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
		libnamed.Logger.Error().Err(err).Msgf("%v", r)
		return nil, err
	}
	if len(r.Question) == 0 {
		err = errors.New("dns message hasn't valid question")
		libnamed.Logger.Debug().Uint16("id", r.Id).Err(err).Msg("")
		r.SetReply(r)
		r.Rcode = dns.RcodeFormatError
		return r, err
	}
	origName := r.Question[0].Name
	qtype := dns.TypeToString[r.Question[0].Qtype]
	logEvent.Str("orig_name", origName).Str("qtype", qtype)
	// disable singleflight
	if !config.Server.Main.Singleflight {
		return query(r, config, logEvent)
	}

	// enable singleflight
	singleflightGroup := config.GetSingleFlightGroup(qtype)
	f := func() (*dns.Msg, error) {
		return query(r, config, logEvent)
	}

	key := strings.ToLower(origName)

	rmsg, hit, err := singleflightGroup.Do(key, f)
	logEvent.Str("key", key).Bool("singleflight", hit)
	if err != nil {
		return rmsg, err
	}

	// NOTICE: two dns msg has same question not equal same dns msg, they minght has different flags or some others.
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
	if rmsg, found := cacheGetDnsMsg(r); found {
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

		if ok := cacheSetDnsMsg(rmsg, &config.Server.Cache); ok {
			logEvent.Str("cache", "update")
		}
	} else {
		return nil, err
	}
	setReply(rmsg, r, origName)
	return rmsg, err
}

func cacheSetDnsMsg(r *dns.Msg, cacheCfg *configx.Cache) bool {
	bmsg, err := r.Pack()
	if err != nil {
		return false
	}
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
	return cachex.Set(strings.ToLower(r.Question[0].Name), r.Question[0].Qtype, bmsg, ttl)
}

func cacheGetDnsMsg(r *dns.Msg) (*dns.Msg, bool) {
	resp := new(dns.Msg)

	name := r.Question[0].Name
	qtype := r.Question[0].Qtype
	if bmsg, found := cachex.Get(strings.ToLower(name), qtype); found {
		if err := resp.Unpack(bmsg); err != nil {
			// 1. log error
			// 2. delete cache ?
			// 3. ignore
			libnamed.Logger.Error().Str("op_type", "unpack_cache_msg").Str("name", name).Uint16("qtype", qtype).Err(err).Msg("")
			return nil, false
		}
		return resp, true
	}

	return nil, false
}

func replyUpdateName(r *dns.Msg, oldname string) {

	if len(r.Question) == 0 {
		return
	}
	qname := r.Question[0].Name
	if qname != oldname {
		// Question SECTION
		for _idx, _ := range r.Question {
			r.Question[_idx].Name = oldname
		}
		// ANSWER SECTION
		for _idx, _ := range r.Answer {
			if r.Answer[_idx].Header().Name == qname {
				r.Answer[_idx].Header().Name = oldname
			}
		}
		// AUTHORITY SECTION
		for _idx, _ := range r.Ns {
			if r.Ns[_idx].Header().Name == qname {
				r.Ns[_idx].Header().Name = oldname
			}
		}
		// ADDITIONAL SECTION
		for _idx, _ := range r.Extra {
			if r.Extra[_idx].Header().Name == qname {
				r.Extra[_idx].Header().Name = oldname
			}
		}
	}
}

func setReply(resp *dns.Msg, r *dns.Msg, oldName string) {
	rcode := resp.Rcode
	resp.SetReply(r)
	resp.Rcode = rcode

	// Fix OPT PSEUDOSECTION COOKIE
	if opt := r.IsEdns0(); opt != nil {
		if ropt := resp.IsEdns0(); ropt != nil {
			// echo cookie
			*ropt = *opt
		}
	}
	replyUpdateName(resp, oldName)
}
