package queryx

import (
	"errors"
	"fmt"
	"gnamed/configx"
	"gnamed/ext/types"
	"gnamed/ext/xlog"
	"gnamed/libnamed"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

func Query(dc *types.DConnection, cfg *configx.Config) (*dns.Msg, error) {

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
	if !cfg.Global.Singleflight {
		return query(dc, cfg, false)
	}

	// enable singleflight
	singleflightGroup := cfg.GetSingleFlightGroup(r.Question[0].Qclass, r.Question[0].Qtype)
	f := func() (*dns.Msg, error) {
		return query(dc, cfg, false)
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

func query(dc *types.DConnection, cfg *configx.Config, byPassCache bool) (*dns.Msg, error) {

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
	if listName, found := cfg.Filter.IsDenyDomain(qname); found {
		rmsg, err := queryFakeWithRR(r, cfg.Filter.FakeRR(r))
		if len(rmsg.Answer) == 0 {
			rmsg.Rcode = dns.RcodeNameError
		}
		logEvent.Str("query_type", "query_fake").Str("rcode", dns.RcodeToString[rmsg.Rcode]).Bool("deny", found).Str("filter_type", "listset").Str("rule", listName+"_"+qname)
		return rmsg, err
	}

	if ruleStr, found := cfg.Filter.RuleSet.IsDeny(qname, qtype); found || ruleStr != "" {
		if found {
			rmsg, err := queryFakeWithRR(r, cfg.Filter.FakeRR(r))

			// NXDomain means all QType of this domain are not exist
			// response with NXDomain (dns.RcodeNameError) sometimes means that
			// telling client don't try to fallback into other kind of IP, this domain hasn't any valid IP Address (both IPv4 and IPv6)
			// https://datatracker.ietf.org/doc/html/rfc4074#section-4.2
			// https://datatracker.ietf.org/doc/html/rfc6147#section-5.1.2
			if len(rmsg.Answer) == 0 {
				if _, exist := cfg.Filter.RuleSet.IsDenyALL(qname); exist {
					rmsg.Rcode = dns.RcodeNameError
				}
			}
			logEvent.Str("query_type", "query_fake").Str("rcode", dns.RcodeToString[rmsg.Rcode]).Bool("deny", found).Str("filter_type", "ruleset").Str("rule", ruleStr)
			return rmsg, err
		}
		logEvent.Bool("deny", found).Str("filter_type", "ruleset").Str("rule", ruleStr)
	}

	cname, zone := cfg.Server.FindRealName(qname)
	logEvent.Str("view_name", zone)
	if cname != "" && cname != outgoingQname {
		outgoingQname = cname
		logEvent.Str("cname", cname)
		for i := range r.Question {
			r.Question[i].Name = cname
		}
	}

	view, found := cfg.Server.View[zone]
	if !found {
		// must be an internal error
		rmsg := new(dns.Msg)
		rmsg.SetReply(r)
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, fmt.Errorf("server failure, no view match qname")
	}

	// hijack
	if r.Question[0].Qtype == dns.TypeHTTPS && view.RrHTTPS != nil && view.RrHTTPS.Hijack {
		//rmsg, err := queryInterceptHTTPS(r, nil, view.RrHTTPS)
		rmsg, err := queryFakeWithRR(r, view.RrHTTPS.FakeRR(r, nil))
		logEvent.Str("query_type", "query_fake").Str("rcode", dns.RcodeToString[rmsg.Rcode]).Bool("hijack", true)
		return rmsg, err
	}

	// set msg OPT in view
	view.SetMsgOpt(r)

	// 3. cache search
	if !byPassCache {
		rc := cfg.Server.RrCache
		if rmsg, found := rc.GetMsg(r, backgroundQuery); found || rmsg != nil {
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
	nameservers := cfg.Server.FindViewNameServers(zone)

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

			if listName, malwareIP, found := filterCheckIP(rmsg, cfg.Filter.IsDenyIP); found {
				rmsg, _ = queryFakeWithRR(dc.OutgoingMsg, cfg.Filter.FakeRR(dc.OutgoingMsg))
				if err != nil {
					err = fmt.Errorf("rrs contain malware IP")
				}
				dc.SubLog.Bool("deny", found).Str("filter_type", "listset").Str("rule", listName+"_"+malwareIP)
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
				ndc := &types.DConnection{
					OutgoingMsg: dc.OutgoingMsg.Copy(),
					Log:         nil, // set nil, panic is buggy
					SubLog:      zerolog.Dict().Str("nameserver_tag", tag),
				}
				tmsg, terr := queryNs(ndc, nameservers[tag])
				if listName, malwareIP, found := filterCheckIP(tmsg, cfg.Filter.IsDenyIP); found {
					tmsg, _ = queryFakeWithRR(ndc.OutgoingMsg, cfg.Filter.FakeRR(ndc.OutgoingMsg))
					if terr != nil {
						terr = fmt.Errorf("rrs contain malware IP")
					}
					ndc.SubLog.Bool("deny", found).Str("filter_type", "listset").Str("rule", listName+"_"+malwareIP)
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
		rmsg, err = queryFakeWithRR(r, view.RrHTTPS.FakeRR(r, ips))
	}

	if rmsg != nil && view.Dnssec {
		// dnssec unsupported on upstream server
		logEvent.Bool("dnssec", rmsg.IsEdns0() != nil && rmsg.IsEdns0().Do())
		logEvent.Str("signature_verify", "TODO")
		// TODO: verify RRSIG, if rmsg.IsEdns0().Do() == true
		// 1. get domain's DNSKEY: query domain with TypeDNSKEY
		// 2. verify RRSIG with DNSKEY: func (rr *RRSIG) Verify(k *DNSKEY, rrset []RR) error
	}

	// 4. cache response
	if err == nil && rmsg != nil {
		logEvent.Str("rcode", dns.RcodeToString[rmsg.Rcode])
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
		if reOrder := rrPrivateFirst(rmsg); reOrder {
			logEvent.Bool("reorder", reOrder)
			logEvent.Str("reorder_desc", "private and public addresses co-exist, make private first")
		}

		rc := cfg.Server.RrCache
		if ok := rc.SetMsg(rmsg); ok {
			logEvent.Str("cache", "update")
		} else {
			logEvent.Str("cache", "failed")
		}
	} else if rmsg == nil {
		// fake response with empty RR to prevent client from hanging
		rmsg, _ = queryFakeWithRR(dc.OutgoingMsg, nil)
	}

	// 5. update reply msg
	setReply(rmsg, dc.GetIncomingMsg())

	return rmsg, err
}

func backgroundQuery(nr *dns.Msg) error {
	logEvent := xlog.Logger().Info().Str("log_type", "query_background").Uint16("id", nr.Id)
	logEvent.Str("name", nr.Question[0].Name).Str("qtype", dns.TypeToString[nr.Question[0].Qtype]).Str("qclass", dns.ClassToString[nr.Question[0].Qclass])
	// bypass singleflight & cache
	// if not bypass singleflight, depend on schedule, background query might reply from cache itself:
	// background query execute before reply from cache
	// if curr query include all same querys blocking by singleflight have completed and background query hasn't completed,
	// might be more than one outgoing same query
	ndc := &types.DConnection{
		OutgoingMsg: nr,
		Log:         logEvent,
	}
	ndc.SetIncomingMsg()
	cfg := configx.GetGlobalConfig()
	_, nerr := query(ndc, cfg, true)
	logEvent.Err(nerr).Msg("")
	return nerr
}

type queryResult struct {
	msg    *dns.Msg
	err    error
	subLog *zerolog.Event
}

func queryNs(dc *types.DConnection, nameserver *configx.NameServer) (*dns.Msg, error) {
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

			logEvent := xlog.Logger().Info().Str("op_type", "op_https_sub")
			dc := &types.DConnection{
				OutgoingMsg: m,
				Log:         logEvent,
			}
			resp, err := Query(dc, cfg)
			if err == nil {
				ans := rrFetchIP(resp)
				switch qtype {
				case dns.TypeA:
					res[0] = ans
				case dns.TypeAAAA:
					res[1] = ans
				}
			}
			logEvent.Err(err).Msg("")
			wg.Done()
		}(qtype)
	}

	wg.Wait()

	res[0] = append(res[0], res[1]...)
	res[1] = nil
	return res[0]
}

func rrFetchIP(m *dns.Msg) []net.IP {
	res := []net.IP{}

	if m == nil || len(m.Answer) == 0 {
		return res
	}

	if qtype := m.Question[0].Qtype; qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return res
	}

	for _, ans := range m.Answer {
		switch ans.Header().Rrtype {
		case dns.TypeA:
			if a, ok := ans.(*dns.A); ok {
				res = append(res, a.A.To4())
			}
		case dns.TypeAAAA:
			if aaaa, ok := ans.(*dns.AAAA); ok {
				res = append(res, aaaa.AAAA.To16())
			}
		}
	}

	return res
}

func rrExist(m *dns.Msg, qtype uint16) bool {
	if m == nil || m.Rcode != dns.RcodeSuccess {
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
			switch ans.Header().Rrtype {
			case dns.TypeA:
				if a, ok := ans.(*dns.A); ok {
					s := a.A.String()
					if listName, found := f(s); found {
						return listName, s, true
					}
				}
			case dns.TypeAAAA:
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

// when private and public addresses co-exist, private always order first
// rules:
// 1. private ip first
//
// return true if need to re-order rrset
// dns-rebind prevent:
// 1. https://crypto.stanford.edu/dns/dns-rebinding.pdf
// 2. https://github.com/Rhynorater/rebindMultiA
func rrPrivateFirst(m *dns.Msg) bool {

	if m == nil || len(m.Question) == 0 {
		return false
	}

	if qtype := m.Question[0].Qtype; qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return false
	}

	j := 0
	for i, ans := range m.Answer {
		switch ans.Header().Rrtype {
		case dns.TypeA:
			if a, ok := ans.(*dns.A); ok {
				if a.A.IsPrivate() {
					m.Answer[i], m.Answer[j] = m.Answer[j], m.Answer[i]
					j++
				}
			}
		case dns.TypeAAAA:
			if aaaa, ok := ans.(*dns.AAAA); ok {
				if aaaa.AAAA.IsPrivate() {
					m.Answer[i], m.Answer[j] = m.Answer[j], m.Answer[i]
					j++
				}
			}
		}
	}

	return j != 0 && j != len(m.Answer)
}

func setReply(resp *dns.Msg, r *dns.Msg) {
	if resp == nil || len(resp.Question) == 0 || r == nil || len(r.Question) == 0 {
		return
	}

	oldName := resp.Question[0].Name
	newName := r.Question[0].Name

	if resp != r {
		rcode := resp.Rcode
		// if resp refer to r, Questions will set as make([]Question, 1), no valid question
		resp.SetReply(r)
		resp.Rcode = rcode

		// dns.Pack() didn't set Compress flag
		//resp.Compress = r.Compress

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
