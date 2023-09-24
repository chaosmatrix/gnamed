package filter

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gnamed/ext/hyper"
	"gnamed/ext/runner"
	"gnamed/ext/trie"
	"gnamed/ext/xlog"
	"gnamed/libnamed"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/idna"

	"github.com/andybalholm/brotli"
	"github.com/miekg/dns"
)

// Data Sources:
// * https://gitlab.com/malware-filter/urlhaus-filter
// * https://filterlists.com/

// always keep the newest *Filter, even after reload
var _filterValue *atomic.Value = new(atomic.Value)

type Filter struct {
	// Filter
	Background    bool          `json:"background"`
	Global        FilterGlobal  `json:"global"`
	ListSet       ListSet       `json:"listset"`
	DisableStats  bool          `json:"disable_stats"` // stats domain hit count, which has performance hit
	Timer         string        `json:"timer"`
	timerDuration time.Duration `json:"-"`

	// RuleSet
	RuleSet RuleSet `json:"ruleset"`

	// internal
	filterStats  *filterStats `json:"-"`
	signalChan   chan string  `json:"-"`
	daemonEnable bool         `json:"-"`
}

type ListSet map[string]*FilterInfo

const (
	signalReload = "SIGHUP"
	signalStop   = "SIGQUIT"
)

type FilterGlobal struct {
	Path          string        `json:"path"`
	Concurrency   int           `json:"concurrency"`
	Delay         string        `json:"delay"` // delay before updating filters at startup
	DelayDuration time.Duration `json:"-"`

	// default block with NXDomain
	// priority: this > loopback
	// only work for A or AAAA record, others are block with NXDomain
	// https://www.rfc-editor.org/rfc/rfc5735#section-4
	// https://www.rfc-editor.org/rfc/rfc6890#section-2.2.2
	// https://www.rfc-editor.org/rfc/rfc6890#section-2.2.3
	BlockWithAddressThis     bool `json:"blockWithAddressThis"`     // 0.0.0.0 or [::]
	BlockWithAddressLoopback bool `json:"blockWithAddressLoopback"` // 127.0.0.1 or [::1]
}

var qtypeToAddrThis = map[uint16]string{
	dns.TypeA:    "0.0.0.0",
	dns.TypeAAAA: "::",
}

var qtypeToAddrLoopback = map[uint16]string{
	dns.TypeA:    "127.0.0.1",
	dns.TypeAAAA: "::1",
}

func (f *Filter) FakeRR(r *dns.Msg) dns.RR {
	return f.Global.fakeRR(r)
}

func (g FilterGlobal) fakeRR(r *dns.Msg) dns.RR {
	if r == nil || len(r.Question) == 0 {
		return nil
	}

	qtype := r.Question[0].Qtype
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return nil
	}

	addr := ""
	if g.BlockWithAddressLoopback {
		addr = qtypeToAddrLoopback[qtype]
	} else if g.BlockWithAddressThis {
		addr = qtypeToAddrThis[qtype]
	} else {
		return nil
	}

	if addr == "" {
		return nil
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		return nil
	}
	switch qtype {
	case dns.TypeA:
		return &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: r.Question[0].Qtype,
				Class:  r.Question[0].Qclass,
				Ttl:    60,
			},
			A: ip.To4(),
		}
	case dns.TypeAAAA:
		return &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: r.Question[0].Qtype,
				Class:  r.Question[0].Qclass,
				Ttl:    60,
			},
			AAAA: ip.To16(),
		}
	default:
		return nil
	}
}

type FilterInfo struct {
	Path                  string            `json:"path"`
	FileName              string            `json:"filename"`
	Url                   string            `json:"url"`
	Refresh               string            `json:"refresh"`
	RefreshDuration       time.Duration     `json:"-"`
	SyntaxRegex           string            `json:"syntax_regex"`
	syntaxRegex           *regexp.Regexp    `json:"-"`
	Syntax                string            `json:"syntax"`
	SyntaxCommentBytes    []string          `json:"syntax_comment_bytes"`
	syntaxCommentBytes    map[byte]struct{} `json:"-"`
	SyntaxDetectLine      int               `json:"syntax_detect_line"`
	SyntaxDetectLineValid int               `json:"syntax_detect_line_valid"`
	Timeout               string            `json:"timeout"`
	TimeoutDuration       time.Duration     `json:"-"`
	RefreshAtStartup      bool              `json:"refresh_at_startup"`

	// internal
	lock             *sync.Mutex             `json:"-"`
	filterTable      *atomic.Value           `json:"-"`
	syntaxParserFunc TypeSyntaxParserFunc    `json:"-"`
	updateTime       time.Time               `json:"-"`
	stats            *filterSyntaxParseStats `json:"-"`

	fpath string `json:"-"`
}

type filterTable struct {
	domains map[string]struct{}
	ips     map[string]struct{}
}

type filterStats struct {
	lock      *sync.Mutex
	HitMap    map[string]int // domain: hit_count
	hit       *atomic.Uint64
	ipHit     *atomic.Uint64
	domainHit *atomic.Uint64
}

func (fns *filterStats) update(rs string, rt uint8, disableStats bool) {

	if !disableStats {
		fns.lock.Lock()
		fns.HitMap[rs]++
		fns.lock.Unlock()
	}

	fns.hit.Add(1)
	switch rt {
	case filterRuleTypeIP:
		fns.ipHit.Add(1)
	case filterRuleTypeDomain:
		fns.domainHit.Add(1)
	}

}

type FilterHitStats struct {
	HitMap    map[string]int
	Total     int
	IPHit     int
	DomainHit int
}

func (f *Filter) GetStats() string {

	fns := f.filterStats
	m := make(map[string]int)
	if !f.DisableStats {
		fns.lock.Lock()
		m = fns.HitMap
		defer fns.lock.Unlock()
	}

	res := &FilterHitStats{
		HitMap:    m,
		Total:     int(fns.hit.Load()),
		IPHit:     int(fns.ipHit.Load()),
		DomainHit: int(fns.domainHit.Load()),
	}

	bs, err := json.MarshalIndent(res, "", "\t")
	if err != nil {
		return "{}"
	}
	return string(bs)
}

// Copy From golang souce code
var asciiSpace = [256]bool{'\t': true, '\n': true, '\v': true, '\f': true, '\r': true, ' ': true}

type TypeSyntaxParserFunc func(s string) (rule string, ruleType uint8)

const (
	filterRuleTypeComment uint8 = iota
	filterRuleTypeInvalid
	filterRuleTypeDomain
	filterRuleTypeIP

	filterSyntaxTypeAdblock string = "adblock"
	filterSyntaxTypeDomain  string = "domain"
	filterSyntaxTypeHosts   string = "hosts"
	filterSyntaxTypeDnsmasq string = "dnsmasq"
	filterSyntaxTypeRegexp  string = "regexp"

	syntaxDetectLine      int = 100
	syntaxDetectLineValid int = 23
)

var (
	syntaxCommentBytes = map[byte]struct{}{'#': {}, '!': {}, '[': {}, ' ': {}, '\t': {}, '\n': {}, '\v': {}, '\f': {}, '\r': {}}
)

var filterSyntaxParserMap = map[string]func(s string, commentBytes map[byte]struct{}) (rule string, ruleType uint8){
	filterSyntaxTypeAdblock: builtInFilterSyntaxAdblock,
	filterSyntaxTypeDomain:  builtInFilterSyntaxDomain,
	filterSyntaxTypeHosts:   builtInFilterSyntaxHosts,
	filterSyntaxTypeDnsmasq: builtInFilterSyntaxDnsmasq,
}

func (fi *FilterInfo) detectFilterSyntaxParser() error {

	if f, found := filterSyntaxParserMap[fi.Syntax]; found {
		fi.syntaxParserFunc = func(s string) (rule string, ruleType uint8) {
			return f(s, fi.syntaxCommentBytes)
		}
		return nil
	}

	if fi.syntaxRegex != nil {
		fi.Syntax = filterSyntaxTypeRegexp
		fi.syntaxParserFunc = func(s string) (string, uint8) {
			s = strings.TrimSpace(s)
			if filterSyntaxInCommentBytes(s, fi.syntaxCommentBytes) {
				return "", 0
			}
			s = fi.syntaxRegex.FindString(s)
			return filterSyntaxParse(s)
		}
		return nil
	}

	fr, err := os.Open(fi.fpath)
	if err != nil {
		return err
	}
	defer fr.Close()

	mc := make(map[string]int, len(filterSyntaxParserMap))

	sc := bufio.NewScanner(fr)
	for i := 0; i < fi.SyntaxDetectLine && sc.Scan(); i++ {
		s := strings.TrimSpace(sc.Text())
		if len(s) == 0 {
			continue
		}

		for bfn, bff := range filterSyntaxParserMap {
			if rs, _ := bff(s, fi.syntaxCommentBytes); len(rs) != 0 {
				mc[bfn]++
			}
		}
	}

	maxCnt := 0
	for bfn, cnt := range mc {
		if cnt > fi.SyntaxDetectLineValid && maxCnt < cnt {
			// must allocate new value "f"
			// if use range value "bfn" in func(), "bfn" will always equal the last value in range
			f := filterSyntaxParserMap[bfn]
			fi.syntaxParserFunc = func(s string) (rule string, ruleType uint8) {
				return f(s, fi.syntaxCommentBytes)
			}
			fi.Syntax = bfn
			maxCnt = cnt
		}
	}

	if fi.syntaxParserFunc != nil {
		return nil
	}

	return fmt.Errorf("no valid SyntaxParser detect and no regexp syntax configured")
}

func filterSyntaxInCommentBytes(s string, bm map[byte]struct{}) bool {
	if len(s) == 0 {
		return true
	}
	if bm == nil {
		return false
	}
	_, found := bm[s[0]]
	return found
}

func filterSyntaxParse(s string) (string, uint8) {
	if len(s) == 0 {
		return "", 0
	}

	if addr, err := netip.ParseAddr(s); err == nil {
		if addr.Is4() {
			return s, filterRuleTypeIP
		} else {
			return addr.String(), filterRuleTypeIP
		}
	}

	rs, err := idna.Punycode.ToASCII(dns.Fqdn(s))
	if err != nil || !libnamed.ValidateDomain(rs) {
		return "", filterRuleTypeInvalid
	}
	return rs, filterRuleTypeDomain
}

// Default Syntax (Domains)
// format:
/*
# Title: 1Hosts (Lite)

doubleclick.net
g.doubleclick.net
*/
//
func builtInFilterSyntaxDomain(s string, commentBytes map[byte]struct{}) (string, uint8) {
	s = strings.TrimSpace(s)
	if filterSyntaxInCommentBytes(s, commentBytes) {
		return "", 0
	}
	return filterSyntaxParse(s)
}

// Adblock Syntax (Adblock Plus)
// format:
/*
[Adblock Plus]
! Syntax: Adblock Plus Filter List

||0--foodwarez.da.ru^
*/
//
func builtInFilterSyntaxAdblock(s string, commentBytes map[byte]struct{}) (string, uint8) {
	s = strings.TrimSpace(s)
	if len(s) < 4 {
		return "", 0
	}

	if filterSyntaxInCommentBytes(s, commentBytes) {
		return "", 0
	}
	s = s[2 : len(s)-1]

	return filterSyntaxParse(s)
}

// Hosts Syntax (Hosts)
// format:
/*
127.0.0.1 ad.example.com
0.0.0.0 ad.example.com
0.0.0.0 ad.example.com # host example
*/
//
func builtInFilterSyntaxHosts(s string, commentBytes map[byte]struct{}) (string, uint8) {
	s = strings.TrimSpace(s)

	if filterSyntaxInCommentBytes(s, commentBytes) {
		return "", 0
	}
	i := 0
	for ; i < len(s) && !asciiSpace[s[i]]; i++ {
	}
	for ; i < len(s) && asciiSpace[s[i]]; i++ {
	}
	j := i + 1
	for ; j < len(s) && !asciiSpace[s[j]]; j++ {
	}

	if i > 0 && i < j && j <= len(s) {
		s = s[i:j]
	} else {
		return "", 0
	}

	return filterSyntaxParse(s)
}

// dnsmasq domains list (dnsmasq)
// format:
/*
server=/teams.events.data.microsoft.com/
server=/fp.measure.office.com/
server=/app-measurement.com/
*/
//
func builtInFilterSyntaxDnsmasq(s string, commentBytes map[byte]struct{}) (string, uint8) {
	s = strings.TrimSpace(s)

	if filterSyntaxInCommentBytes(s, commentBytes) {
		return "", 0
	}

	p := "server=/"
	if len(s) <= len(p)+1 || s[:len(p)] != p {
		return "", 0
	}

	return filterSyntaxParse(s[8 : len(s)-1])
}

func (f *Filter) init() error {
	var err error

	err = f.parse()
	if err != nil {
		return err
	}
	err = f.loadLocalFilterFiles()
	if err != nil {
		return err
	}
	err = f.updateLocalFilterFiles()
	if err != nil {
		return err
	}
	return err
}

func (f *Filter) Start() error {

	if f.Background {
		go func() {
			f.loadLocalFilterFiles()
			time.Sleep(1 * time.Minute)
			f.updateLocalFilterFiles()
			if f.daemonEnable {
				f.daemon()
			}
		}()
	} else {
		f.loadLocalFilterFiles()
		go func() {
			time.Sleep(1 * time.Minute)
			f.updateLocalFilterFiles()
			if f.daemonEnable {
				f.daemon()

			}
		}()
	}
	return nil
}

func (f *Filter) Stop() error {

	if f.daemonEnable {
		f.signalChan <- signalStop
	}
	return nil
}

func (f *Filter) UpdateLocalFilterFiles() error {
	return f.updateLocalFilterFiles()
}

func (f *Filter) LoadLocalFilterFiles() error {
	return f.loadLocalFilterFiles()
}

func (f *Filter) DaemonStart() {
	if f.daemonEnable {
		f.daemon()
	}
}

type filterContentMashal struct {
	Stats   map[string]int      `json:"stats"`
	Domains map[string]struct{} `json:"domains"`
	IPs     map[string]struct{} `json:"ips"`
}

// marshal filter lookup table into string
func (f *Filter) MarshalFilter(name string) string {
	fi := f.ListSet[name]
	if fi == nil {
		return "{\"message\": \"invalid filter name\"}"
	}

	fi.lock.Lock()

	ft, ok := fi.filterTable.Load().(*filterTable)
	if !ok {
		return "{\"message\": \"internal error\"}"
	}

	dm := ft.domains
	im := ft.ips

	fi.lock.Unlock()

	res := &filterContentMashal{
		Stats:   map[string]int{"domain": len(dm), "ips": len(im)},
		Domains: dm,
		IPs:     im,
	}

	bs, err := json.MarshalIndent(res, "", " ")
	if err != nil {
		return "{\"message\": \"failed to marshal filter content\"}"
	}
	return string(bs)
}

func (f *Filter) Parse() error {
	return f.parse()
}

func (f *Filter) parse() error {

	f.filterStats = &filterStats{
		lock:      new(sync.Mutex),
		HitMap:    make(map[string]int, 0),
		hit:       &atomic.Uint64{},
		ipHit:     &atomic.Uint64{},
		domainHit: &atomic.Uint64{},
	}

	f.signalChan = make(chan string)
	if f.Timer == "" {
		f.timerDuration = 23 * time.Minute
	} else {
		t, err := time.ParseDuration(f.Timer)
		if err != nil {
			f.timerDuration = 23 * time.Minute
		} else {
			if t < 1*time.Minute {
				f.timerDuration = 1 * time.Minute
			} else {
				f.timerDuration = t
			}
		}
	}

	if f.Global.Delay == "" {
		f.Global.DelayDuration = 5 * time.Second
	} else {
		if d, err := time.ParseDuration(f.Global.Delay); err == nil && d > 0 {
			f.Global.DelayDuration = d
		} else {
			if err != nil {
				return err
			}
			f.Global.DelayDuration = 5 * time.Second
		}
	}

	unixTime := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	for ln, l := range f.ListSet {
		l.lock = new(sync.Mutex)

		if l.Timeout != "" {
			t, err := time.ParseDuration(l.Timeout)
			if err != nil {
				return err
			}
			l.TimeoutDuration = t
		}
		if l.TimeoutDuration < 60*time.Second {
			l.TimeoutDuration = 60 * time.Second
		} else if l.TimeoutDuration > 180*time.Second {
			l.TimeoutDuration = 180 * time.Second
		}

		if l.Refresh != "" {
			t, err := time.ParseDuration(l.Refresh)
			if err != nil {
				return err
			}
			if t < 65*time.Second {
				l.RefreshDuration = 65 * time.Second
			} else {
				l.RefreshDuration = t
			}
			f.daemonEnable = true

			if l.RefreshDuration <= l.TimeoutDuration {
				return fmt.Errorf("filter's refresh duration shorter than download timeout, filter: %s, Refresh: %s, Timeout: %s", ln, l.Refresh, l.Timeout)
			}
		}

		if l.Url == "" && (l.RefreshDuration != 0 || l.RefreshAtStartup) {
			return fmt.Errorf("filter has refresh policy but url is empty, filter: %s, url: %s", ln, l.Url)
		}

		if l.SyntaxRegex != "" {
			xp, err := regexp.Compile(l.SyntaxRegex)
			if err != nil {
				return err
			}
			l.Syntax = filterSyntaxTypeRegexp
			l.syntaxRegex = xp
		}

		if f.Global.Concurrency <= 0 {
			f.Global.Concurrency = 8
		}
		if f.Global.Concurrency > len(f.ListSet) {
			f.Global.Concurrency = len(f.ListSet)
		}

		fpath := f.Global.Path
		if l.Path != "" {
			fpath = l.Path
		}

		l.fpath = path.Join(path.Clean(fpath), l.FileName)

		if st, err := os.Stat(l.fpath); err == nil {
			l.updateTime = st.ModTime()
		} else {
			if l.Url == "" || (!l.RefreshAtStartup && l.RefreshDuration == 0) {
				return fmt.Errorf("filter's local file not exist and no valid update policy, filter: %s, error: %v", ln, err)
			}
			l.updateTime = unixTime
		}

		if len(l.SyntaxCommentBytes) == 0 {
			l.syntaxCommentBytes = syntaxCommentBytes
		} else {
			bytesMap := make(map[byte]struct{}, len(l.SyntaxCommentBytes))
			for _, b := range l.SyntaxCommentBytes {
				if len(b) != 1 {
					return fmt.Errorf("invalid syntax comment byte (length != 1): %s", b)
				}
				bytesMap[b[0]] = struct{}{}
			}
			l.syntaxCommentBytes = bytesMap
		}

		if l.SyntaxDetectLine <= 0 {
			l.SyntaxDetectLine = syntaxDetectLine
		}

		if l.SyntaxDetectLineValid <= 0 {
			l.SyntaxDetectLineValid = syntaxDetectLineValid
		}

		ft := &filterTable{
			domains: make(map[string]struct{}),
			ips:     make(map[string]struct{}),
		}

		l.filterTable = new(atomic.Value)
		l.filterTable.Store(ft)

		if err := l.detectFilterSyntaxParser(); err != nil {
			xlog.Logger().Error().Str("log_type", "filter").Str("op_type", "detect").Str("filter_name", ln).Err(err).Msg("failed to detect syntax parser")
		}

		l.stats = new(filterSyntaxParseStats)
	}

	if err := f.RuleSet.parse(); err != nil {
		return err
	}

	if f.Background {
		go f.loadLocalFilterFiles()
	} else {
		if err := f.loadLocalFilterFiles(); err != nil {
			return err
		}
	}

	_filterValue.Store(f)

	runner.RegisterStartPost("filter_updateLocalFilterFiles", func() error {
		go func() {
			time.Sleep(f.Global.DelayDuration)
			f.updateLocalFilterFiles()
		}()
		return nil
	})

	runner.RegisterDaemon("filter_daemon_start", daemonStart, "filter_daemon_reload", daemonReload, "filter_daemon_stop", daemonStop)
	return nil
}

func (f *Filter) IsDenyDomain(domain string) (ruleStr string, found bool) {
	return f.MatchDomain(domain)
}

// return: (filter_name, found)
func (f *Filter) MatchDomain(domain string) (string, bool) {

	for ln, l := range f.ListSet {
		ft, ok := l.filterTable.Load().(*filterTable)
		if !ok {
			return "internal_error", true
		}

		if ft.matchDomain(domain) {
			f.filterStats.update(domain, filterRuleTypeDomain, f.DisableStats)
			return ln, true
		}
	}
	return "", false
}

func (f *Filter) IsDenyIP(addr string) (ruleStr string, found bool) {
	return f.MatchIP(addr)
}

func (f *Filter) MatchIP(addr string) (string, bool) {

	for ln, l := range f.ListSet {
		ft, ok := l.filterTable.Load().(*filterTable)
		if !ok {
			return "internal_error", true
		}
		if ft.matchIP(addr) {
			f.filterStats.update(addr, filterRuleTypeDomain, f.DisableStats)
			return ln, true
		}
	}
	return "", false
}

func (ft *filterTable) matchDomain(domain string) bool {
	_, found := ft.domains[domain]
	return found
}

func (ft *filterTable) matchIP(addr string) bool {
	_, found := ft.ips[addr]
	return found
}

type filterUpdateStats struct {
	Total   uint32         `json:"total"`
	Error   uint32         `json:"error"`
	errCnt  *atomic.Uint32 `json:"-"`
	Success uint32         `json:"success"`
	okCnt   *atomic.Uint32 `json:"-"`
	Skip    uint32         `json:"skip"`
}

func newFilterUpdateStats(total int) *filterUpdateStats {
	fus := &filterUpdateStats{
		Total:  uint32(total),
		errCnt: &atomic.Uint32{},
		okCnt:  &atomic.Uint32{},
	}
	return fus
}

func (fus *filterUpdateStats) update(err error) {
	if err == nil {
		fus.okCnt.Add(1)
	} else {
		fus.errCnt.Add(1)
	}
}

func (fus *filterUpdateStats) marshal() []byte {
	fus.Error = fus.errCnt.Load()
	fus.Success = fus.okCnt.Load()
	fus.Skip = fus.Total - fus.Success - fus.Error

	bs, err := json.Marshal(fus)
	if err != nil {
		return []byte("{}")
	}
	return bs
}

func daemonStart() error {
	f := _filterValue.Load().(*Filter)
	f.daemon()
	return nil
}

func daemonReload() error {
	return nil
}

func daemonStop() error {
	f := _filterValue.Load().(*Filter)
	f.signalChan <- signalStop
	return nil
}

func (f *Filter) daemon() {
	if !f.daemonEnable {
		xlog.Logger().Info().Str("log_type", "filter").Str("op_type", "update").Msg("daemon is disable")
		return
	}

	xlog.Logger().Info().Str("log_type", "filter").Str("op_type", "update").Dur("timer", f.timerDuration).Msg("start daemon to update filter in cycle")

	d := f.timerDuration
	t := time.NewTimer(d)
	for {
		logEvent := xlog.Logger().Info().Str("log_type", "filter").Str("op_type", "update")
		start := time.Now()
		stats := newFilterUpdateStats(len(f.ListSet))

		select {
		case <-t.C:
			var wg sync.WaitGroup
			flying := make(chan struct{}, f.Global.Concurrency)
			for ln, l := range f.ListSet {
				if l.RefreshDuration == 0 || time.Since(l.updateTime) < l.RefreshDuration {
					xlog.Logger().Info().Str("log_type", "filter").Str("op_type", "update").Str("filter_name", ln).Str("syntax", l.Syntax).RawJSON("stats", l.stats.marshal()).Bool("updated", false).Msg("skip update due to configured update policy")
					continue
				}
				wg.Add(1)
				flying <- struct{}{}
				go func(ln string, fi *FilterInfo) {
					var err error
					for i := 0; i < 3; i++ {
						start := time.Now()
						err := fi.download()
						xlog.Logger().Info().Str("log_type", "filter").Str("op_type", "update").Str("filter_name", ln).Str("syntax", fi.Syntax).RawJSON("stats", fi.stats.marshal()).Bool("updated", err == nil).Dur("elapsed_time", time.Since(start)).Err(err).Msg("")
						if err == nil {
							break
						}
						time.Sleep(500 * time.Millisecond)
					}
					stats.update(err)
					<-flying
					wg.Done()
				}(ln, f.ListSet[ln])
			}
			wg.Wait()
			logEvent.Dur("elapsed_time", time.Since(start)).RawJSON("stats", stats.marshal()).Msg("")
			t.Reset(d)
		case signalStr := <-f.signalChan:
			t.Stop()
			xlog.Logger().Info().Str("log_type", "filter").Str("op_type", "update").Str("signal", signalStr).Msg("daemon stop")
			return
		}
	}
}

func (f *Filter) updateLocalFilterFiles() error {

	logEvent := xlog.Logger().Info().Str("log_type", "filter").Str("op_type", "update")

	start := time.Now()

	stats := newFilterUpdateStats(len(f.ListSet))

	var wg sync.WaitGroup

	flying := make(chan struct{}, f.Global.Concurrency)
	for ln, l := range f.ListSet {
		if !l.RefreshAtStartup {
			xlog.Logger().Info().Str("log_type", "filter").Str("op_type", "update").Str("filter_name", ln).Str("syntax", l.Syntax).RawJSON("stats", l.stats.marshal()).Bool("updated", false).Msg("skip update due to configured update policy")
			continue
		}
		wg.Add(1)
		flying <- struct{}{}
		go func(ln string, fi *FilterInfo) {
			var err error
			for i := 0; i < 3; i++ {
				start := time.Now()
				err = fi.download()
				xlog.Logger().Info().Str("log_type", "filter").Str("op_type", "update").Str("filter_name", ln).Str("syntax", fi.Syntax).RawJSON("stats", fi.stats.marshal()).Bool("updated", err == nil).Dur("elapsed_time", time.Since(start)).Err(err).Msg("")
				if err == nil {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
			stats.update(err)
			<-flying
			wg.Done()
		}(ln, f.ListSet[ln])
	}
	wg.Wait()
	logEvent.Dur("elapsed_time", time.Since(start)).RawJSON("stats", stats.marshal()).Msg("")
	return nil
}

func (f *Filter) loadLocalFilterFiles() error {

	logEvent := xlog.Logger().Info().Str("log_type", "filter").Str("op_type", "load")

	start := time.Now()

	stats := newFilterUpdateStats(len(f.ListSet))

	var wg sync.WaitGroup
	for ln, l := range f.ListSet {
		wg.Add(1)
		go func(ln string, fi *FilterInfo) {
			start := time.Now()
			err := fi.parse()
			xlog.Logger().Info().Str("log_type", "filter").Str("op_type", "load").Str("filter_name", ln).Str("syntax", fi.Syntax).RawJSON("stats", fi.stats.marshal()).Dur("elapsed_time", time.Since(start)).Err(err).Msg("")
			stats.update(err)
			wg.Done()
		}(ln, l)
	}
	wg.Wait()
	logEvent.Dur("elapsed_time", time.Since(start)).RawJSON("stats", stats.marshal()).Msg("")
	return nil
}

type filterSyntaxParseStats struct {
	Total           int    `json:"total"`
	Valid           int    `json:"valid"`
	Invalid         int    `json:"invalid"`
	ElapsedDownload string `json:"elapsed_download"`
	ElapsedParse    string `json:"elapsed_parse"`
}

func (fsp *filterSyntaxParseStats) marshal() []byte {
	bs, err := json.Marshal(fsp)
	if err != nil {
		return []byte("{}")
	}

	return bs
}

// error condition:
// 1. filter filename not exist
// 2. no valid filter
func (fi *FilterInfo) parse() error {

	start := time.Now()

	fi.lock.Lock()
	defer fi.lock.Unlock()

	if fi.syntaxParserFunc == nil {
		err := fi.detectFilterSyntaxParser()
		if err != nil {
			return err
		}
	}

	fr, err := os.Open(fi.fpath)
	if err != nil {
		return err
	}
	defer fr.Close()

	ft, ok := fi.filterTable.Load().(*filterTable)
	if !ok {
		return errors.New("unable to convert value into filterTable type")
	}

	sc := bufio.NewScanner(fr)

	stats := &filterSyntaxParseStats{}

	domains := make(map[string]struct{}, len(ft.domains))
	ips := make(map[string]struct{}, len(ft.ips))
	for sc.Scan() {
		rs, rt := fi.syntaxParserFunc(sc.Text())
		if rt == 0 {
			continue
		}

		switch rt {
		case filterRuleTypeDomain:
			domains[rs] = struct{}{}
		case filterRuleTypeIP:
			ips[rs] = struct{}{}
		default:
			stats.Invalid++
			continue
		}

		stats.Valid++
	}
	if stats.Valid < fi.SyntaxDetectLineValid {
		return fmt.Errorf("file: %s hasn't any valid filter that can be parse by %v", fi.fpath, fi.Syntax)
	}

	fi.updateTime = time.Now()
	stats.Total = stats.Valid + stats.Invalid

	// update stats
	fi.stats.Total = stats.Total
	fi.stats.Invalid = stats.Invalid
	fi.stats.Valid = stats.Valid
	fi.stats.ElapsedParse = time.Since(start).String()

	nft := &filterTable{
		domains: domains,
		ips:     ips,
	}
	fi.filterTable.Store(nft)

	return nil
}

func (fi *FilterInfo) download() error {

	logEvent := xlog.Logger().Trace().Str("log_type", "filter").Str("op_type", "download").Str("url", fi.Url)
	start := time.Now()
	defer func() {
		logEvent.Dur("elapsed_time", time.Since(start)).Msg("")
	}()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(fi.TimeoutDuration))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fi.Url, nil)
	logEvent.Err(err)
	if err != nil {
		return err
	}
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Add("Accept-Encoding", "deflate")
	req.Header.Add("Accept-Encoding", "br")

	hc := &hyper.HyperClient{
		Timeout: fi.TimeoutDuration,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 1 {
				return errors.New("429 too many redirect")
			}
			if req.URL.Scheme != "http" {
				return errors.New("only https allowed")
			}
			return nil
		},
		DisableALPNCache: true,
	}
	resp, err := hc.Do(req)
	logEvent.Err(err)
	defer hc.CloseIdleConnections()
	if err != nil {
		return err
	}
	logEvent.Int("status_code", resp.StatusCode).Str("proto", resp.Proto)
	if resp.StatusCode != 200 || resp.Body == nil {
		return fmt.Errorf("invalid http response, status_code: %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	// persist as temp file
	oldfpath := fi.fpath
	tmpfpath := fi.fpath + ".tmp"

	fw, err := os.OpenFile(tmpfpath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}

	// make sure tmpfpath removed
	defer func() {
		fw.Close() // it's ok for double close fd
		if fi, err := os.Stat(tmpfpath); (err == nil || os.IsExist(err)) && fi.Mode().IsRegular() {
			err = os.Remove(tmpfpath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[+] failed to remove tmp file %s", tmpfpath)
			}
		}
		fi.fpath = oldfpath
	}()

	rd := resp.Body
	if !resp.Uncompressed && resp.Header.Get("Content-Encoding") != "" {
		ce := resp.Header.Get("Content-Encoding")
		switch ce {
		case "gzip":
			if gziprd, err := gzip.NewReader(resp.Body); err == nil {
				rd = gziprd
			} else {
				return err
			}
		case "br":
			rd = io.NopCloser(brotli.NewReader(resp.Body))
		case "deflate":
			rd = flate.NewReader(resp.Body)
		default:
			return fmt.Errorf("server sent http response wiht unknow compression algorithm %s", ce)
		}
	}
	if _, err := io.Copy(fw, rd); err != nil {
		logEvent.Err(err)
		fw.Close()
		return err
	}
	fw.Close()
	rd.Close() // compresser don't close the underlying io.Reader

	fi.stats.ElapsedDownload = time.Since(start).String()

	// parse filter
	fi.fpath = tmpfpath

	if err := fi.parse(); err != nil {
		logEvent.Err(err)
		return err
	}

	// update
	err = os.Rename(tmpfpath, oldfpath)
	logEvent.Err(err)
	return err
}

// mapping QType into Rules
type RuleSet struct {
	Allow map[string]*RuleInfo `json:"allow"` // QType mapping
	Deny  map[string]*RuleInfo `json:"deny"`
}

type RuleInfo struct {
	Equal      []string            `json:"equal"`
	equalMap   map[string]struct{} `json:"-"`
	Prefix     []string            `json:"prefix"`
	prefixTrie *trie.PrefixTrie    `json:"-"`
	Suffix     []string            `json:"suffix"`
	suffixTrie *trie.SuffixTrie    `json:"-"`
	Contain    []string            `json:"contain"`
	Regexp     []string            `json:"regexp"`
	regexp     []*regexp.Regexp    `json:"-"`
}

const (
	ruleTypeEqual   string = "equal"
	ruleTypePrefix  string = "prefix"
	ruleTypeSuffix  string = "suffix"
	ruleTypeContain string = "contain"
	ruleTypeRegexp  string = "regexp"

	ruleSetQtypeALL string = "ALL" // special qtype to identify all dns qtype
)

// parse RuleSet
func (rs *RuleSet) parse() error {

	if rs.Allow == nil {
		rs.Allow = make(map[string]*RuleInfo)
	}
	if rs.Deny == nil {
		rs.Deny = make(map[string]*RuleInfo)
	}

	rules := []map[string]*RuleInfo{rs.Deny, rs.Allow}

	for _, rs := range rules {
		for qt, ri := range rs {
			t := strings.ToUpper(qt)
			if _, found := dns.StringToType[t]; !found && t != ruleSetQtypeALL {
				xlog.Logger().Error().Str("log_type", "config").Str("op_type", "contruct_query_list").Msgf("invalid qtype %s", qt)
				return fmt.Errorf("skip invalid qtype %s", qt)
			}
			if err := ri.parse(); err != nil {
				return err
			}
			//rules[i][qt] = ri
		}
	}

	return nil
}

func (ri *RuleInfo) parse() error {
	var err error

	// pre process input
	for i, s := range ri.Equal {
		s, err = idna.ToASCII(ri.Equal[i])
		if err != nil || len(s) == 0 {
			xlog.Logger().Error().Str("log_type", "config").Str("op_type", "contruct_query_list").Err(err).Msgf("invalid equal rule '%s'", ri.Equal[i])
			if err == nil {
				return fmt.Errorf("invalid equal rule '%s'", ri.Equal[i])
			}
			return err
		}
		ri.Equal[i] = dns.Fqdn(s)
	}
	for i, s := range ri.Suffix {
		s, err = idna.ToASCII(ri.Suffix[i])
		if err != nil || len(s) == 0 {
			xlog.Logger().Error().Str("log_type", "config").Str("op_type", "contruct_query_list").Err(err).Msgf("invalid suffix rule '%s'", ri.Suffix[i])
			if err == nil {
				return fmt.Errorf("invalid suffix rule '%s'", ri.Equal[i])
			}
			return err
		}
		ri.Suffix[i] = dns.Fqdn(s)
	}
	for i, s := range ri.Prefix {
		s, err = idna.ToASCII(ri.Prefix[i])
		if err != nil || len(s) == 0 {
			xlog.Logger().Error().Str("log_type", "config").Str("op_type", "contruct_query_list").Err(err).Msgf("invalid prefix rule '%s'", ri.Prefix[i])
			if err == nil {
				return fmt.Errorf("invalid prefix rule '%s'", ri.Equal[i])
			}
			return err
		}
		ri.Prefix[i] = s
	}

	// build internal using data struct
	if len(ri.Equal) > 0 {
		ri.equalMap = make(map[string]struct{}, len(ri.Equal))
		for _, rl := range ri.Equal {
			ri.equalMap[rl] = struct{}{}
		}
	}

	if len(ri.Prefix) > 0 {
		ri.prefixTrie = trie.NewPrefixTrie(ri.Prefix)
	}
	if len(ri.Suffix) > 0 {
		ri.suffixTrie = trie.NewSuffixTrie(ri.Suffix)
	}

	if len(ri.Regexp) > 0 {
		// pre-compile regexp
		ri.regexp = make([]*regexp.Regexp, len(ri.Regexp))
		for i := range ri.Regexp {
			ri.regexp[i], err = regexp.Compile(ri.Regexp[i])
			if err != nil {
				xlog.Logger().Error().Str("log_type", "config").Str("op_type", "contruct_query_list").Err(err).Msgf("invalid regexp rule '%s'", ri.Regexp[i])
				return err
			}
		}
	}

	return err
}

// check the name's qtype allow or not
func (q *RuleSet) IsAllow(name string, qtype string) (string, bool) {
	if ruleType, ruleStr, found := q.allow(name, qtype); found {
		return ruleType + "_" + ruleStr, true
	}
	if ruleType, ruleStr, found := q.deny(name, qtype); found {
		return ruleType + "_" + ruleStr, false
	}
	return "", true
}

// check if all qtype of this name are allow or not
func (q *RuleSet) IsAllowALL(name string) (string, bool) {
	return q.IsAllow(name, ruleSetQtypeALL)
}

func (q *RuleSet) IsDeny(name string, qtype string) (string, bool) {
	if ruleType, ruleStr, found := q.allow(name, qtype); found {
		return ruleType + "_" + ruleStr, false
	}
	if ruleType, ruleStr, found := q.deny(name, qtype); found {
		return ruleType + "_" + ruleStr, true
	}
	return "", false
}

// check if all qtype of this name are deny or not
func (q *RuleSet) IsDenyALL(name string) (string, bool) {
	return q.IsDeny(name, ruleSetQtypeALL)
}

func (q *RuleSet) allow(name string, qtype string) (string, string, bool) {
	if ql, found := q.Allow[qtype]; found {
		if ruleType, ruleStr, found := ql.match(name); found {
			return ruleType, ruleStr, found
		}
	}
	if ql, found := q.Allow[ruleSetQtypeALL]; found {
		return ql.match(name)
	}
	return "", "", false
}

func (q *RuleSet) deny(name string, qtype string) (string, string, bool) {
	if ql, found := q.Deny[qtype]; found {
		if ruleType, ruleStr, found := ql.match(name); found {
			return ruleType, ruleStr, found
		}
	}
	if ql, found := q.Deny[ruleSetQtypeALL]; found {
		return ql.match(name)
	}
	return "", "", false
}

// return: ruleType, ruleName, exist
func (ql *RuleInfo) match(name string) (ruleType string, ruleStr string, found bool) {
	// O(1)
	if ql.equalMap != nil {
		if _, found := ql.equalMap[name]; found {
			return ruleTypeEqual, name, true
		}
	}
	// O(m)
	if ql.suffixTrie != nil {
		if rule, found := ql.suffixTrie.Query(name); found {
			return ruleTypeSuffix, rule, found
		}
	}
	// O(m)
	if ql.prefixTrie != nil {
		if rule, found := ql.prefixTrie.Query(name); found {
			return ruleTypePrefix, rule, found
		}
	}
	// len(ql.Contain) * O(avg(len(_contain)))
	// Optimization:
	// 1. algorithm: Aho-Corasick or flashtext
	//  1.1 flashtext https://arxiv.org/pdf/1711.00046.pdf
	for _, rule := range ql.Contain {
		if strings.Contains(name, rule) {
			return ruleTypeContain, rule, true
		}
	}
	// O(m) * O(len(_ql.regexp))
	for _, rule := range ql.regexp {
		if rule.MatchString(name) {
			return ruleTypeRegexp, rule.String(), true
		}
	}
	return "", "", false
}
