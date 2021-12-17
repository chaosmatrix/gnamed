package queryx

import (
	"errors"
	"gnamed/cachex"
	"gnamed/configx"
	"gnamed/libnamed"
	"strings"

	"github.com/miekg/dns"
)

func Query(r *dns.Msg, config *configx.Config) (*dns.Msg, error) {

	var err error

	// pre-check
	if r == nil {
		err = errors.New("invalid dns message")
		libnamed.Logger.Error().Err(err).Msgf("%v", r)
		return new(dns.Msg), err
	}
	if len(r.Question) == 0 {
		err = errors.New("dns message hasn't valid question")
		libnamed.Logger.Debug().Uint16("id", r.Id).Err(err).Msg("")
		r.SetReply(r)
		r.Rcode = dns.RcodeFormatError
		return r, err
	}

	// disable singleflight
	if !config.Server.Main.Singleflight {
		return query(r, config)
	}

	// enable singleflight
	singleflightGroup := config.GetSingleFlightGroup()
	f := func() (*dns.Msg, error) {
		return query(r, config)
	}

	origName := r.Question[0].Name
	key := strings.ToLower(origName) + "_" + dns.TypeToString[r.Question[0].Qtype]

	rmsg, hit, err := singleflightGroup.Do(key, f)

	// query() make sure rmsg not nil, and always a valid *dns.Msg
	replyUpdateName(rmsg, origName)

	libnamed.Logger.Trace().Str("log_type", "filter").Uint16("id", r.Id).Str("key", key).Bool("singleflight", hit).Msg("")
	// BUG: two dns msg has same question not equal same dns msg, they minght has different flags or some others.
	if hit {
		// return from prev copy
		rcode := rmsg.Rcode
		rmsg.SetReply(r)
		rmsg.Rcode = rcode
		// Fix OPT PSEUDOSECTION COOKIE
		if opt := r.IsEdns0(); opt != nil {
			if ropt := rmsg.IsEdns0(); ropt != nil {
				*ropt = *opt
			}
		}
		return rmsg, err
	}
	return rmsg, err
}

func query(r *dns.Msg, config *configx.Config) (*dns.Msg, error) {
	var err error

	_logEvent := libnamed.Logger.Debug().Str("log_type", "query").Uint16("id", r.Id)

	name := r.Question[0].Name
	qtype := dns.TypeToString[r.Question[0].Qtype]

	_logEvent.Str("name", name).Str("qtype", qtype)

	// Filter
	// 1. validate domain
	if !libnamed.ValidateDomain(name) {
		_logEvent.Str("query_type", "query_fake").Err(errors.New("invalid domain base on RFC 1035 and RFC 3696")).Msg("")
		return queryFake(r, nil)
	}

	// Cache
	// 0. lock - ensure single flying query or internal search
	// 1. whitelist/blacklist search
	if _r, _s, _forbidden := config.Query.QueryForbidden(name, qtype); _forbidden {
		_logEvent.Str("query_type", "query_fake").Str("blacklist", _r+"_"+_s).Msg("")
		return queryFake(r, nil)
	}

	// handle cname
	oldname := name
	oldMsg := new(dns.Msg)
	oldMsg.SetReply(r)

	cname, vname := config.Server.FindRealName(name)
	_logEvent.Str("view_name", vname)
	if len(cname) != 0 && cname != name {
		name = cname
		_logEvent.Str("cname", cname)
		for i, _ := range r.Question {
			r.Question[i].Name = cname
		}
	}

	// 2. cache search
	if rmsg, found := cacheGetDnsMsg(r); found {
		if oldname != name {
			replyUpdateName(rmsg, oldname)
		}
		_logEvent.Str("query_type", "").Str("cache", "hit").Msg("")
		// Fix OPT PSEUDOSECTION COOKIE
		if opt := r.IsEdns0(); opt != nil {
			if ropt := rmsg.IsEdns0(); ropt != nil {
				*ropt = *opt
			}
		}
		return rmsg, nil
	}
	// 3. external query
	dnsTag, nameserver := config.Server.FindNameServer(r.Question[0].Name)
	_logEvent.Str("nameserver_tag", dnsTag)

	if nameserver == nil {
		// FIXME: reply from hosts file
		_record, _ := config.Server.FindRecordFromHosts(r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype])
		_msg := strings.Join([]string{name, "60", "IN", qtype, _record}, "    ")

		_logEvent.Str("query_type", "hosts")
		_rr, _err := dns.NewRR(_msg)
		if _err != nil {
			_logEvent.Err(err).Msg("")
			// FIXME
			return oldMsg, _err
		}
		oldMsg.Answer = []dns.RR{_rr}
		_logEvent.Msg("")
		return oldMsg, nil
	}

	rmsg := new(dns.Msg)
	rmsg.SetReply(r)

	switch nameserver.Protocol {
	case configx.ProtocolTypeDNS:
		_logEvent.Str("query_type", "query_dns")
		rmsg, err = queryDoD(r, &nameserver.Dns)
	case configx.ProtocolTypeDoH:
		_logEvent.Str("query_type", "query_doh")
		rmsg, err = queryDoH(r, &nameserver.DoH)
	case configx.ProtocolTypeDoT:
		_logEvent.Str("query_type", "query_dot")
		rmsg, err = queryDoT(r, &nameserver.DoT)
	default:
		_logEvent.Str("query_type", "query_dns")
		rmsg, err = queryDoD(r, &nameserver.Dns)
	}
	// 4. cache response
	if err == nil {
		_logEvent.Str("rcode", dns.RcodeToString[r.Rcode])

		if ok := cacheSetDnsMsg(rmsg, &config.Server.Cache); ok {
			_logEvent.Str("cache", "update")
		}
	} else {
		_logEvent.Err(err)
		rmsg = new(dns.Msg)
		rmsg.SetReply(r)
		rmsg.Rcode = dns.RcodeServerFailure
	}
	replyUpdateName(rmsg, oldname)
	_logEvent.Msg("")
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
		/*
			resp.RecursionAvailable = r.RecursionDesired
			r.Answer = resp.Copy().Answer
			r.Ns = resp.Copy().Copy().Ns
			r.Extra = resp.Copy().Extra
			r.Rcode = resp.Copy().Rcode
			r.RecursionAvailable = r.RecursionDesired
		*/
		resp.SetReply(r)
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

func setReply(resp *dns.Msg, r *dns.Msg) {
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
}
