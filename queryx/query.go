package queryx

import (
	"errors"
	"fmt"
	"gnamed/cachex"
	"gnamed/configx"
	"gnamed/libnamed"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func Query(dc *libnamed.DConnection, config *configx.Config) (*dns.Msg, error) {

	r := dc.IncomingMsg
	logEvent := dc.Log
	var err error

	// pre-check
	if r == nil {
		err = errors.New("invalid dns message")
		logEvent.Err(err)
		return nil, err
	}

	logEvent.Uint16("id", r.Id)
	if len(r.Question) == 0 {
		rmsg := new(dns.Msg)
		rmsg.SetReply(r)
		rmsg.Rcode = dns.RcodeFormatError
		return rmsg, fmt.Errorf("invalid dns query")
	}

	qname := r.Question[0].Name
	qtype := dns.TypeToString[r.Question[0].Qtype]
	qclass := dns.ClassToString[r.Question[0].Qclass]

	logEvent.Str("name", qname).Str("qtype", qtype).Str("qclass", qclass)

	if qtype == "" || qclass == "" {
		rmsg := new(dns.Msg)
		rmsg.SetReply(r)
		rmsg.Rcode = dns.RcodeFormatError
		return rmsg, fmt.Errorf("invalid dns query")
	}

	// disable singleflight
	if !config.Server.Main.Singleflight {
		return query(dc, config, false)
	}

	// enable singleflight
	singleflightGroup := config.GetSingleFlightGroup(r.Question[0].Qclass, r.Question[0].Qtype)
	f := func() (*dns.Msg, error) {
		return query(dc, config, false)
	}

	rmsg, hit, err := singleflightGroup.Do(strings.ToLower(qname), f)
	logEvent.Bool("singleflight", hit)
	if err != nil {
		return rmsg, err
	}

	// NOTICE: two dns msg has same question not equal same dns msg, they might has different flags or some others.
	// singleflight already make sure do deep copy, return values are concurrency safe.
	if hit {
		// return from prev copy, need to make sure update name
		setReply(rmsg, r, qname)
		return rmsg, err
	}
	return rmsg, err
}

func query(dc *libnamed.DConnection, cfg *configx.Config, byPassCache bool) (*dns.Msg, error) {

	r := dc.IncomingMsg
	logEvent := dc.Log

	var err error

	qname := r.Question[0].Name
	outgoingQname := qname
	qtype := dns.TypeToString[r.Question[0].Qtype]

	// Filter
	// 1. validate domain
	if !libnamed.ValidateDomain(qname) {
		rmsg := new(dns.Msg)
		rmsg.SetReply(r)
		rmsg.Rcode = dns.RcodeFormatError
		logEvent.Str("query_type", "query_fake").Str("rcode", dns.RcodeToString[r.Rcode])
		return r, fmt.Errorf("invalid domain base on RFC 1035 and RFC 3696")
	}

	// 2. whitelist/blacklist search
	if _r, _s, _forbidden := cfg.Query.QueryForbidden(qname, qtype); _forbidden {
		rmsg, err := queryFake(r, nil)
		logEvent.Str("query_type", "query_fake").Str("rcode", dns.RcodeToString[rmsg.Rcode]).Str("blacklist", _r+"_"+_s)
		return rmsg, err
	}

	cname, vname := cfg.Server.FindRealName(qname)
	logEvent.Str("view_name", vname)
	if cname != outgoingQname {
		outgoingQname = cname
		logEvent.Str("cname", cname)
		for i := range r.Question {
			r.Question[i].Name = cname
		}
	}

	// 3. cache search
	if !byPassCache {
		cacheCfg := cfg.Server.Cache
		if rmsg, expiredUTC, cacheTTL, found := cacheGetDnsMsg(r, &cacheCfg); found || (cacheCfg.UseSteal && rmsg != nil && expiredUTC > 0) {
			nowUTC := libnamed.GetFakeTimerUnixSecond()
			if (cacheCfg.UseSteal || cacheCfg.BackgroundUpdate) && ((cacheCfg.BeforeExpiredSecond > 0 && expiredUTC-cacheCfg.BeforeExpiredSecond <= nowUTC) || (cacheCfg.BeforeExpiredPercent > 0 && expiredUTC-int64((float64(cacheTTL)*cacheCfg.BeforeExpiredPercent)) <= nowUTC)) {

				lockKey := outgoingQname + "_" + dns.ClassToString[r.Question[0].Qclass] + "_" + qtype
				if cacheCfg.BackgroundQueryTryLock(lockKey) {
					// ensure only one outgoing same query (qname, qclass, qtype)
					logEvent.Bool("background_update", true)
					// do background query
					go func(nr *dns.Msg, lockKey string) {
						defer cacheCfg.BackgroundQueryUnlock(lockKey)
						_logEvent := libnamed.Logger.Trace().Str("log_type", "query_background").Uint16("id", nr.Id).Str("qtype", dns.TypeToString[nr.Question[0].Qtype]).Str("qclass", dns.ClassToString[nr.Question[0].Qclass])
						// bypass singleflight & cache
						// if not bypass singleflight, depend on schedule, background query might reply from cache itself:
						// background query execute before reply from cache
						// if curr query include all same querys blocking by singleflight have completed and background query hasn't completed,
						// might be more than one outgoing same query
						ndc := &libnamed.DConnection{
							IncomingMsg: nr,
							Log:         _logEvent,
						}
						_, nerr := query(ndc, cfg, true)
						_logEvent.Err(nerr).Msg("")
					}(r.Copy(), lockKey)
				}
			}

			logEvent.Str("query_type", "").Str("rcode", dns.RcodeToString[rmsg.Rcode])
			if found {
				logEvent.Str("cache", "hit")
			} else {
				logEvent.Str("cache", "steal")
			}
			setReply(rmsg, r, qname)
			return rmsg, nil
		}
	} else {
		logEvent.Bool("by_pass_cache", byPassCache)
	}

	// 4. hosts lookup
	if record, found := cfg.Server.FindRecordFromHosts(outgoingQname, qtype); found {
		logEvent.Str("query_type", "hosts")
		rmsg := new(dns.Msg)
		rrs := strings.Join([]string{qname, "60", dns.ClassToString[r.Question[0].Qclass], qtype, record}, "    ")
		_rr, _err := dns.NewRR(rrs)
		if _err != nil {
			return nil, _err
		}
		rmsg.Answer = []dns.RR{_rr}
		setReply(rmsg, r, qname)
		return rmsg, nil
	}

	// 5. external query
	nameServerTag, nameserver := cfg.Server.FindViewNameServer(vname)
	logEvent.Str("nameserver_tag", nameServerTag)

	if nameserver == nil {
		// shouldn't reach here
		rmsg := new(dns.Msg)
		setReply(rmsg, r, qname)
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, fmt.Errorf("no avaliable view match name \"%s\"", qname)
	}

	logEvent.Str("query_type", "external")
	var rmsg *dns.Msg

	oId := dc.IncomingMsg.Id
	if oId == 0 {
		dc.IncomingMsg.Id = dns.Id() // make sure incoming msg id not zero
	}

	// send dnssec query to server that don't support dnssec, might be response with FORMERR
	view, found := cfg.Server.View[vname]
	if found && (view.Dnssec || view.Subnet != "") {
		opt := &libnamed.OPTOption{
			EnableDNSSEC:  view.Dnssec,
			EnableECS:     view.Subnet != "",
			SourceIP:      view.EcsAddress,
			Family:        view.EcsFamily,
			SourceNetmask: view.EcsNetMask,
			SourceScope:   view.EcsNetMask,
			UDPSize:       1024,
		}
		libnamed.SetOpt(r, opt)
	}

	queryStartTime := time.Now()
	switch nameserver.Protocol {
	case configx.ProtocolTypeDNS:
		rmsg, err = queryDoD(dc, nameserver.Dns)
	case configx.ProtocolTypeDoH:
		rmsg, err = queryDoH(dc, nameserver.DoH)
	case configx.ProtocolTypeDoT:
		rmsg, err = queryDoT(dc, nameserver.DoT)
	case configx.ProtocolTypeDoQ:
		rmsg, err = queryDoQ(dc, nameserver.DoQ)
	default:
		rmsg, err = queryDoD(dc, nameserver.Dns)
	}
	logEvent.Dur("latency_query", time.Since(queryStartTime))

	dc.IncomingMsg.Id = oId
	if rmsg != nil {
		rmsg.Id = oId
	}

	if r.Question[0].Qtype == dns.TypeHTTPS && view.RrHTTPS != nil && (view.RrHTTPS.Replace || !rrExist(rmsg, r.Question[0].Qtype)) {
		logEvent.Bool("intercept_with_fake", true)
		ips := fetchIP(r, cfg)
		rmsg, err = queryInterceptHTTPS(r, ips, &view)
	}

	if view.Dnssec {
		// dnssec unsupported on upstream server
		logEvent.Bool("dnssec", rmsg.IsEdns0() == nil || rmsg.IsEdns0().Do())
		logEvent.Str("signature_verify", "TODO")
		// TODO: verify RRSIG, if rmsg.IsEdns0().Do() == true
		// 1. get domain's DNSKEY: query domain with TypeDNSKEY
		// 2. verify RRSIG with DNSKEY: func (rr *RRSIG) Verify(k *DNSKEY, rrset []RR) error
	}

	// 4. cache response
	if err == nil {
		logEvent.Str("rcode", dns.RcodeToString[rmsg.Rcode])

		cacheTTL := getMsgTTL(rmsg, &cfg.Server.Cache)
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
	setReply(rmsg, r, qname)

	return rmsg, err
}

func fetchIP(r *dns.Msg, cfg *configx.Config) []net.IP {

	res := make([][]net.IP, 2)
	var wg sync.WaitGroup

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		wg.Add(1)
		go func(qtype uint16) {
			m := r.Copy()
			m.Question[0].Qtype = qtype

			logEvent := libnamed.Logger.Trace().Str("op_type", "op_https_sub")
			dc := &libnamed.DConnection{
				IncomingMsg: m,
				Log:         logEvent,
			}
			resp, err := Query(dc, cfg)
			if err == nil {
				ans := rrFetchIP(resp)
				if qtype == dns.TypeA {
					res[0] = ans
				} else if qtype == dns.TypeAAAA {
					res[1] = ans
				}
			}
			logEvent.Err(err).Msg("")
			wg.Done()
		}(qtype)
	}

	wg.Wait()

	if len(res[0]) == 0 {
		return res[1]
	} else if len(res[1]) == 0 {
		return res[0]
	} else {
		res[0] = append(res[0], res[1]...)
		res[1] = []net.IP{}
		return res[0]
	}
}

func rrFetchIP(m *dns.Msg) []net.IP {
	res := []net.IP{}

	if m != nil && m.Answer != nil {
		for _, ans := range m.Answer {
			rtype := ans.Header().Rrtype
			if rtype == dns.TypeA {
				if a, ok := ans.(*dns.A); ok {
					res = append(res, a.A.To4())
				}
			} else if rtype == dns.TypeAAAA {
				if aaaa, ok := ans.(*dns.AAAA); ok {
					res = append(res, aaaa.AAAA.To16())
				}
			}
		}
	}

	return res
}
func rrExist(m *dns.Msg, qtype uint16) bool {
	if m == nil || m.Answer == nil || len(m.Answer) == 0 {
		return false
	}

	for _, ans := range m.Answer {
		if ans.Header().Rrtype == qtype {
			return true
		}
	}
	return false
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
		libnamed.Logger.Error().Str("log_type", "cache").Str("op_type", "pack_msg").Str("name", qname).Str("qtype", dns.TypeToString[qtype]).Err(err).Msg("")
		return false
	}
	return cachex.Set(strings.ToLower(r.Question[0].Name), r.Question[0].Qtype, bmsg, cacheTTL)
}

func cacheGetDnsMsg(r *dns.Msg, cacheCfg *configx.Cache) (*dns.Msg, int64, uint32, bool) {
	qname := r.Question[0].Name
	qtype := r.Question[0].Qtype
	if bmsg, expiredUTC, found := cachex.Get(strings.ToLower(qname), qtype); found || (cacheCfg.UseSteal && expiredUTC > 0) {
		resp := new(dns.Msg)
		if err := resp.Unpack(bmsg); err != nil {
			// 1. log error
			// 2. delete cache ?
			// 3. ignore
			libnamed.Logger.Error().Str("log_type", "cache").Str("op_type", "unpack_cache_msg").Str("name", qname).Str("qtype", dns.TypeToString[qtype]).Err(err).Msg("")
			return nil, 0, 0, false
		}

		cacheTTL := getMsgTTL(resp, cacheCfg)
		replyUpdateTTL(resp, expiredUTC, cacheTTL)

		return resp, expiredUTC, cacheTTL, found
	}

	return nil, 0, 0, false
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

	if len(r.Question) == 0 || oldname == "" {
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
	if resp != r {
		rcode := resp.Rcode
		// if resp refer to r, Questions will set as make([]Question, 1), no valid question
		resp.SetReply(r)
		resp.Rcode = rcode

		// rfc7873#section-5.2
		// Fix OPT PSEUDOSECTION COOKIE
		if opt := r.IsEdns0(); opt != nil {
			if ropt := resp.IsEdns0(); ropt != nil {
				// echo cookie
				*ropt = *opt
			}
		} else if len(r.Extra) == 0 && len(resp.Extra) != 0 {
			// clean response Extra
			resp.Extra = []dns.RR{}
		}
	} else if !resp.Response {
		resp.Response = true
	}

	// rfc1035#section-4.1.1:
	// 1. act as forwarded/authoritative name server, didn't support recursive query
	// 2. RA: denotes whether recursive query support is avaliable in the name server (this)
	// 3. If RD is set, it directs the name server to pursue the query recursively. Recursive query support is optional
	if r.RecursionDesired {
		// fix dig output (while RD set) ";; WARNING: recursion requested but not available"
		resp.RecursionAvailable = true
	}

	replyUpdateName(resp, oldName)
}
