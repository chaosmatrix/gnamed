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
	"github.com/rs/zerolog"
)

func Query(dc *libnamed.DConnection, config *configx.Config) (*dns.Msg, error) {

	r := dc.OutgoingMsg
	dc.SetIncomingMsg()

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
		err = errors.New("invalid dns query, question section is empty")
		logEvent.Err(err)
		return rmsg, err
	}

	qname := r.Question[0].Name
	qtype := dns.TypeToString[r.Question[0].Qtype]
	qclass := dns.ClassToString[r.Question[0].Qclass]

	logEvent.Str("name", qname).Str("qtype", qtype).Str("qclass", qclass)

	if qtype == "" || qclass == "" {
		rmsg := new(dns.Msg)
		rmsg.SetReply(r)
		rmsg.Rcode = dns.RcodeFormatError
		err = fmt.Errorf("invalid dns query, type or class is invalid, name: '%s', type: %d, class: %d", qname, r.Question[0].Qtype, r.Question[0].Qclass)
		logEvent.Err(err)
		return rmsg, err
	}
	//r.Compress = true // always compress

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
		setReply(rmsg, dc.GetIncomingMsg())
		return rmsg, err
	}
	return rmsg, err
}

func query(dc *libnamed.DConnection, cfg *configx.Config, byPassCache bool) (*dns.Msg, error) {

	r := dc.OutgoingMsg
	logEvent := dc.Log

	var err error

	qname := strings.ToLower(r.Question[0].Name)
	outgoingQname := qname
	qtype := dns.TypeToString[r.Question[0].Qtype]

	// Filter
	// 1. validate domain
	if !libnamed.ValidateDomain(qname) {
		rmsg := new(dns.Msg)
		rmsg.SetReply(r)
		rmsg.Rcode = dns.RcodeFormatError
		logEvent.Str("query_type", "query_fake").Str("rcode", dns.RcodeToString[r.Rcode])
		return rmsg, fmt.Errorf("invalid domain base on RFC 1035 and RFC 3696")
	}

	// 2. whitelist/blacklist search
	// 2.1 search malware
	if listName, found := cfg.Filter.MatchDomain(qname); found {
		rmsg, err := queryFake(r, nil)
		logEvent.Str("query_type", "query_fake").Str("rcode", dns.RcodeToString[rmsg.Rcode]).Str("blacklist", "filter_"+listName+"_"+qname)
		return rmsg, err
	}
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

	view, found := cfg.Server.View[vname]
	if !found {
		// must be an internal error
		rmsg := new(dns.Msg)
		rmsg.SetReply(r)
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, fmt.Errorf("server failure, no view match qname")
	}

	// hijack
	if r.Question[0].Qtype == dns.TypeHTTPS && view.RrHTTPS != nil && view.RrHTTPS.Hijack {
		rmsg, err := queryInterceptHTTPS(r, nil, &view)
		logEvent.Str("query_type", "query_fake").Str("rcode", dns.RcodeToString[rmsg.Rcode]).Bool("hijack", true)
		return rmsg, err
	}

	// 3. cache search
	if !byPassCache {
		cacheCfg := cfg.Server.RrCache

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
						_logEvent := libnamed.Logger.Info().Str("log_type", "query_background").Uint16("id", nr.Id).Str("qtype", dns.TypeToString[nr.Question[0].Qtype]).Str("qclass", dns.ClassToString[nr.Question[0].Qclass])
						// bypass singleflight & cache
						// if not bypass singleflight, depend on schedule, background query might reply from cache itself:
						// background query execute before reply from cache
						// if curr query include all same querys blocking by singleflight have completed and background query hasn't completed,
						// might be more than one outgoing same query
						ndc := &libnamed.DConnection{
							OutgoingMsg: nr,
							Log:         _logEvent,
						}
						ndc.SetIncomingMsg()
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
			setReply(rmsg, dc.GetIncomingMsg())
			return rmsg, nil
		}
	} else {
		logEvent.Bool("by_pass_cache", byPassCache)
	}

	// 4. hosts lookup
	if record, found := cfg.Server.FindRecordFromHosts(outgoingQname, qtype); found {
		logEvent.Str("query_type", "hosts")
		rmsg := new(dns.Msg)
		rmsg.SetReply(r)
		rrs := strings.Join([]string{qname, "60", dns.ClassToString[r.Question[0].Qclass], qtype, record}, "    ")
		_rr, _err := dns.NewRR(rrs)
		if _err != nil {
			return nil, _err
		}
		rmsg.Answer = []dns.RR{_rr}
		setReply(rmsg, dc.GetIncomingMsg())
		return rmsg, nil
	}

	// 5. external query
	//nameServerTag, nameserver := cfg.Server.FindViewNameServer(vname)
	//logEvent.Str("nameserver_tag", nameServerTag)
	nameservers := cfg.Server.FindViewNameServers(vname)

	if nameservers == nil {
		// shouldn't reach here
		rmsg := new(dns.Msg)
		rmsg.SetReply(r)
		setReply(rmsg, dc.GetIncomingMsg())
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, fmt.Errorf("no avaliable view match name \"%s\"", qname)
	}

	logEvent.Str("query_type", "external")

	oId := dc.OutgoingMsg.Id
	dc.OutgoingMsg.Id |= dns.Id()

	// send dnssec query to server that don't support dnssec, might be response with FORMERR
	//view, found := cfg.Server.View[vname]
	if found && (view.Dnssec || view.Subnet != "") {
		opt := &libnamed.OPTOption{
			EnableDNSSEC:  view.Dnssec,
			EnableECS:     view.Subnet != "",
			SourceIP:      view.EcsAddress,
			Family:        view.EcsFamily,
			SourceNetmask: view.EcsNetMask,
			SourceScope:   view.EcsNetMask,
			UDPSize:       1280,
		}
		libnamed.SetOpt(r, opt)
	}

	// randomw Upper/Lower domain's chars
	if view.RandomDomain {
		dc.OutgoingMsg.Question[0].Name = libnamed.RandomUpperDomain(dc.OutgoingMsg.Question[0].Name)
	}

	var rmsg *dns.Msg

	logQueries := zerolog.Arr()
	queryStartTime := time.Now()
	if len(nameservers) == 1 {
		for tag, nameserver := range nameservers {
			dc.SubLog = zerolog.Dict().Str("nameserver_tag", tag)

			rmsg, err = queryNs(dc, nameserver)

			if listName, malwareIP, found := filterCheckIP(rmsg, cfg.Filter.MatchIP); found {
				rmsg, _ = queryFake(dc.OutgoingMsg, nil)
				if err != nil {
					err = fmt.Errorf("rrs contain malware IP")
				}
				dc.SubLog.Str("blacklist", "filter_"+listName+"_"+malwareIP)
			}

			logQueries.Dict(dc.SubLog)
		}
	} else {
		// TODO:
		// 1. configurable query policy: serial or parallel
		// 2. configurable result choice policy: first (response) or merge
		completed := make(chan *queryResult, len(nameservers))
		for tag := range nameservers {
			go func(tag string) {
				// only copy IncommingMsg, share logEvent
				ndc := &libnamed.DConnection{
					OutgoingMsg: dc.OutgoingMsg.Copy(),
					Log:         nil, // set nil, panic is buggy
					SubLog:      zerolog.Dict().Str("nameserver_tag", tag),
				}
				tmsg, terr := queryNs(ndc, nameservers[tag])
				if listName, malwareIP, found := filterCheckIP(tmsg, cfg.Filter.MatchIP); found {
					tmsg, _ = queryFake(ndc.OutgoingMsg, nil)
					if terr != nil {
						terr = fmt.Errorf("rrs contain malware IP")
					}
					ndc.SubLog.Str("blacklist", "filter_"+listName+"_"+malwareIP)
				}

				completed <- &queryResult{
					msg:    tmsg,
					err:    terr,
					subLog: ndc.SubLog,
				}
			}(tag)
		}

		for i := 0; i < len(nameservers); i++ {
			qr := <-completed // prev function already set timeout
			logQueries.Dict(qr.subLog)
			rmsg, err = qr.msg, qr.err
			if err == nil && rmsg != nil && rmsg.Rcode == dns.RcodeSuccess {
				// using first one
				break
			}
		}
	}
	logEvent.Array("queries", logQueries)
	logEvent.Dur("latency_query", time.Since(queryStartTime))

	dc.OutgoingMsg.Id = oId
	if rmsg != nil {
		rmsg.Id = oId
	}

	if r.Question[0].Qtype == dns.TypeHTTPS && view.RrHTTPS != nil && !rrExist(rmsg, r.Question[0].Qtype) {
		logEvent.Bool("replace", true)
		ips := fetchIP(r, cfg)
		rmsg, err = queryInterceptHTTPS(r, ips, &view)
	}

	if rmsg != nil && view.Dnssec {
		// dnssec unsupported on upstream server
		logEvent.Bool("dnssec", rmsg.IsEdns0() == nil || rmsg.IsEdns0().Do())
		logEvent.Str("signature_verify", "TODO")
		// TODO: verify RRSIG, if rmsg.IsEdns0().Do() == true
		// 1. get domain's DNSKEY: query domain with TypeDNSKEY
		// 2. verify RRSIG with DNSKEY: func (rr *RRSIG) Verify(k *DNSKEY, rrset []RR) error
	}

	// 4. cache response
	if err == nil && rmsg != nil {

		logEvent.Str("rcode", dns.RcodeToString[rmsg.Rcode])
		if reOrder := rrPrivateFirst(rmsg); reOrder {
			logEvent.Bool("re_order", reOrder)
		}

		cacheTTL := getMsgTTL(rmsg, &cfg.Server.RrCache)
		if cacheTTL == 0 {
			// rfc1035#section-4.1.3
			// zero ttl can be use for DNS rebinding attack, for the sake of security, should cache it short time
			// https://crypto.stanford.edu/dns/dns-rebinding.pdf
			// https://github.com/Rhynorater/rebindMultiA
			// dns-rebinding way:
			// 1. only one record with small ttl (zero), trigger client redo dns lookup
			// 2. multi record and control the record's sequence, make first record unacceptable, trigger client connect the second record
			//
			// fix:
			// 1. server:
			// 	> E2E support, https
			// 2. client:
			// 	> always use E2E protocol
			// 	> if private and public address co-exist, always select the private address (linux/unix-like system)
			// 	> reject the response that contain private address from un-trust public dns server
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
	setReply(rmsg, dc.GetIncomingMsg())

	return rmsg, err
}

type queryResult struct {
	msg    *dns.Msg
	err    error
	subLog *zerolog.Event
}

func queryNs(dc *libnamed.DConnection, nameserver *configx.NameServer) (*dns.Msg, error) {
	var rmsg *dns.Msg
	var err error
	//queryStartTime := time.Now()
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
	//logEvent.Dur("latency_query", time.Since(queryStartTime))
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

			logEvent := libnamed.Logger.Info().Str("op_type", "op_https_sub")
			dc := &libnamed.DConnection{
				OutgoingMsg: m,
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
		if qtype := m.Question[0].Qtype; qtype != dns.TypeA && qtype != dns.TypeAAAA {
			return res
		}

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

func filterCheckIP(m *dns.Msg, f func(string) (string, bool)) (string, string, bool) {
	if m != nil && m.Answer != nil {

		if qtype := m.Question[0].Qtype; qtype != dns.TypeA && qtype != dns.TypeAAAA {
			return "", "", false
		}

		for _, ans := range m.Answer {
			rtype := ans.Header().Rrtype
			if rtype == dns.TypeA {
				if a, ok := ans.(*dns.A); ok {
					s := a.A.String()
					if listName, found := f(s); found {
						return listName, s, true
					}
				}
			} else if rtype == dns.TypeAAAA {
				if aaaa, ok := ans.(*dns.AAAA); ok {
					s := aaaa.AAAA.String()
					if listName, found := f(s); found {
						return listName, s, true
					}
				}
			}
		}
	}
	return "", "", false
}

// re-sort answer section
// rules:
// 1. private ip first
//
// return true if need to re-order rrset
// dns-rebind prevent:
// 1. https://crypto.stanford.edu/dns/dns-rebinding.pdf
// 2. https://github.com/Rhynorater/rebindMultiA
func rrPrivateFirst(m *dns.Msg) bool {

	if qtype := m.Question[0].Qtype; qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return false
	}

	j := 0
	for i, ans := range m.Answer {
		if a, ok := ans.(*dns.A); ok {
			if a.A.IsPrivate() {
				m.Answer[i], m.Answer[j] = m.Answer[j], m.Answer[i]
				j++
			}
		} else if aaaa, ok := ans.(*dns.AAAA); ok {
			if aaaa.AAAA.IsPrivate() {
				m.Answer[i], m.Answer[j] = m.Answer[j], m.Answer[i]
				j++
			}
		}
	}

	return j != 0
}

// FIXME: public function should not here
func GetMsgTTL(msg *dns.Msg, cacheCfg *configx.RrCache) uint32 {
	return getMsgTTL(msg, cacheCfg)
}

// Warning: this is a violation of the RFC
func getMsgTTL(msg *dns.Msg, cacheCfg *configx.RrCache) uint32 {

	var ttl uint32 = 0

	if msg == nil {
		return ttl
	}

	// fix upstream server temporary failure
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return cacheCfg.ErrTtl
	}

	if len(msg.Answer) > 0 {
		qtype := msg.Question[0].Qtype
		for _, rr := range msg.Answer {
			if rr.Header().Rrtype == qtype {
				ttl = rr.Header().Ttl
				break
			}
		}
		if ttl == 0 {
			// only cname, but no qtype record
			ttl = msg.Answer[0].Header().Ttl
		}
		if ttl < cacheCfg.MinTTL {
			ttl = cacheCfg.MinTTL
		} else if cacheCfg.MaxTTL > 0 && ttl > cacheCfg.MaxTTL {
			ttl = cacheCfg.MaxTTL
		}
	} else {
		for _, rr := range msg.Ns {
			if rr.Header().Rrtype == dns.TypeSOA {
				if soa, ok := rr.(*dns.SOA); ok {
					ttl = soa.Expire
				}
				break
			}
		}
	}

	return ttl
}

func cacheSetDnsMsg(r *dns.Msg, cacheTTL uint32) bool {
	if cacheTTL <= 0 {
		qname := r.Question[0].Name
		qtype := r.Question[0].Qtype
		libnamed.Logger.Error().Str("log_type", "cache").Str("name", qname).Str("qtype", dns.TypeToString[qtype]).Msg("cache ttl less or equal 0")
		return false
	}
	return cachex.Set(strings.ToLower(r.Question[0].Name), r.Question[0].Qtype, r, cacheTTL)
}

func cacheGetDnsMsg(r *dns.Msg, cacheCfg *configx.RrCache) (*dns.Msg, int64, uint32, bool) {
	qname := r.Question[0].Name
	qtype := r.Question[0].Qtype
	if resp, expiredUTC, found := cachex.Get(strings.ToLower(qname), qtype); found || (cacheCfg.UseSteal && expiredUTC > 0) {

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

func setReply(resp *dns.Msg, r *dns.Msg) {

	oldName := resp.Question[0].Name
	newName := r.Question[0].Name

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

	replyUpdateName(resp, oldName, newName)
}

// Case:
// 1. some upstream nameserver can't handle dns query which qname has uppercase letter, will reply message that qname not equal with the name in answer section
//
// for example:
/*
;; opcode: QUERY, status: NOERROR, id: 1
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;EXAMPLE.COM.     IN       A

;; ANSWER SECTION:
example.com.      60      IN      A       1.2.3.4
example.com.      60      IN      A       1.2.3.5
*/
func replyUpdateName(r *dns.Msg, oldName string, newName string) {

	if oldName == newName && oldName == strings.ToLower(oldName) {
		return
	}

	// Question SECTION
	for i := range r.Question {
		r.Question[i].Name = newName
	}
	// ANSWER SECTION
	for i := range r.Answer {
		if wrapStringsEqualFold(r.Answer[i].Header().Name, oldName) {
			r.Answer[i].Header().Name = newName
		}
	}
	// AUTHORITY SECTION
	for i := range r.Ns {
		if wrapStringsEqualFold(r.Ns[i].Header().Name, oldName) {
			r.Ns[i].Header().Name = newName
		}
	}
	// ADDITIONAL SECTION
	for i := range r.Extra {
		if wrapStringsEqualFold(r.Extra[i].Header().Name, oldName) {
			r.Extra[i].Header().Name = newName
		}
	}
}

// built-in function strings.EqualFold not compare the length of two strings at the beginning
// performance(5x slower than s == t):
// 1. strings.EqualFold(): 10ns/op
// 2. s == t: 2ns/op
// 3. wrapStringsEqualFold(): 2ns/op if len(s) != len(t), others 10ns/op
func wrapStringsEqualFold(s string, t string) bool {
	if len(s) != len(t) {
		return false
	}
	return strings.EqualFold(s, t)
}
