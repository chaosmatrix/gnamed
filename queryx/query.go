package queryx

import (
	"errors"
	"gnamed/cachex"
	"gnamed/configx"
	"gnamed/libnamed"
	"strings"

	"github.com/miekg/dns"
)

func Query(r *dns.Msg, config *configx.Config) error {
	return query(r, config)
}

func query(r *dns.Msg, config *configx.Config) error {
	var err error

	name := r.Question[0].Name
	qtype := dns.TypeToString[r.Question[0].Qtype]

	_logEvent := libnamed.Logger.Debug().Str("name", name).Str("qtype", qtype)

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
		_logEvent.Str("query_type", "query_fake").Str("blacklist", _r+"_"+_s)
		err = queryFake(r, nil)
		if err != nil {
			_logEvent.Err(err)
		}
		_logEvent.Msg("")
		return err
	}

	// handle cname
	oldname := name
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
	if cacheGetDnsMsg(r) {
		if oldname != name {
			replyUpdateName(r, oldname)
		}
		_logEvent.Str("query_type", "").Str("cache", "hit").Msg("")
		return nil
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
			return _err
		}
		r.Answer = []dns.RR{_rr}
		_logEvent.Msg("")
		return nil
	}
	switch nameserver.Protocol {
	case configx.ProtocolTypeDNS:
		_logEvent.Str("query_type", "query_dns")
		err = queryDoD(r, &nameserver.Dns)
	case configx.ProtocolTypeDoH:
		_logEvent.Str("query_type", "query_doh")
		err = queryDoH(r, &nameserver.DoH)
	case configx.ProtocolTypeDoT:
		_logEvent.Str("query_type", "query_dot")
		err = queryDoT(r, &nameserver.DoT)
	default:
		_logEvent.Str("query_type", "query_dns")
		err = queryDoD(r, &nameserver.Dns)
	}
	// 4. cache response
	if err == nil {
		_logEvent.Str("rcode", dns.RcodeToString[r.Rcode])

		if ok := cacheSetDnsMsg(r, &config.Server.Cache); ok {
			_logEvent.Str("cache", "update")
		}
	}
	if oldname != name {
		replyUpdateName(r, oldname)
	}
	_logEvent.Err(err).Msg("")
	return err
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
	return cachex.Set(r.Question[0].Name, r.Question[0].Qtype, bmsg, ttl)
}

func cacheGetDnsMsg(r *dns.Msg) bool {
	resp := new(dns.Msg)

	name := r.Question[0].Name
	qtype := r.Question[0].Qtype
	if bmsg, found := cachex.Get(name, qtype); found {
		if err := resp.Unpack(bmsg); err != nil {
			// 1. log error
			// 2. delete cache ?
			// 3. ignore
			libnamed.Logger.Error().Str("op_type", "unpack_cache_msg").Str("name", name).Uint16("qtype", qtype).Err(err).Msg("")
			return false
		}
		reply(r, resp)
		return true
	}

	return false
}

func reply(r *dns.Msg, resp *dns.Msg) {
	r.Answer = resp.Copy().Answer
	r.Ns = resp.Copy().Copy().Ns
	r.Extra = resp.Copy().Extra
	r.Rcode = resp.Copy().Rcode
	if r.Question[0].Name != resp.Question[0].Name {
		// ANSWER SECTION
		for _idx, _ := range r.Answer {
			if r.Answer[_idx].Header().Name == resp.Question[0].Name {
				r.Answer[_idx].Header().Name = r.Question[0].Name
			}
		}
		// AUTHORITY SECTION
		for _idx, _ := range r.Ns {
			if r.Ns[_idx].Header().Name == resp.Question[0].Name {
				r.Ns[_idx].Header().Name = r.Question[0].Name
			}
		}
		// ADDITIONAL SECTION
		for _idx, _ := range r.Extra {
			if r.Extra[_idx].Header().Name == resp.Question[0].Name {
				r.Extra[_idx].Header().Name = r.Question[0].Name
			}
		}
	}
}

func replyUpdateName(r *dns.Msg, oldname string) {

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
