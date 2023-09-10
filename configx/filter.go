package configx

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gnamed/libnamed"
	"gnamed/runner"
	"io"
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

type Filter struct {
	Background    bool                   `json:"background"`
	Global        FilterGlobal           `json:"global"`
	Lists         map[string]*FilterInfo `json:"lists"`
	DisableStats  bool                   `json:"disable_stats"` // stats domain hit count, which has performance hit
	Timer         string                 `json:"timer"`
	timerDuration time.Duration          `json:"-"`

	// internal
	filterStats  *filterStats `json:"-"`
	signalChan   chan string  `json:"-"`
	daemonEnable bool         `json:"-"`
}

const (
	signalReload = "SIGHUP"
	signalStop   = "SIGQUIT"
)

type FilterGlobal struct {
	Path          string        `json:"path"`
	Concurrency   int           `json:"concurrency"`
	Delay         string        `json:"delay"` // delay before updating filters at startup
	DelayDuration time.Duration `json:"-"`
}

type FilterInfo struct {
	Path                  string         `json:"path"`
	FileName              string         `json:"filename"`
	Url                   string         `json:"url"`
	Refresh               string         `json:"refresh"`
	RefreshDuration       time.Duration  `json:"-"`
	SyntaxRegex           string         `json:"syntax_regex"`
	syntaxRegex           *regexp.Regexp `json:"-"`
	Syntax                string         `json:"syntax"`
	SyntaxCommentBytes    []byte         `json:"syntax_comment_bytes"`
	SyntaxDetectLine      int            `json:"syntax_detect_line"`
	SyntaxDetectLineValid int            `json:"syntax_detect_line_valid"`
	Timeout               string         `json:"timeout"`
	TimeoutDuration       time.Duration  `json:"-"`
	RefreshAtStartup      bool           `json:"refresh_at_startup"`

	// internal
	lock             *sync.Mutex             `json:"-"`
	filterTable      *filterTable            `json:"-"`
	syntaxParserFunc TypeSyntaxParserFunc    `json:"-"`
	updateTime       time.Time               `json:"-"`
	stats            *filterSyntaxParseStats `json:"-"`

	fpath string `json:"-"`
}

type filterTable struct {
	id      *atomic.Uint32
	domains []map[string]struct{}
	ips     []map[string]struct{}
}

type filterStats struct {
	lock      *sync.Mutex
	HitMap    map[string]int // domain: hit_count
	hit       *atomic.Uint64
	ipHit     *atomic.Uint64
	domainHit *atomic.Uint64
}

func (fns *filterStats) update(rs string, rt string, disableStats bool) {

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

type TypeSyntaxParserFunc func(string) (rule string, ruleType string)

const (
	filterRuleTypeDomain  string = "domain"
	filterRuleTypeIP      string = "ip"
	filterRuleTypeInvalid string = "invalid"

	filterSyntaxTypeAdblock string = "adblock"
	filterSyntaxTypeDomain  string = "domain"
	filterSyntaxTypeHosts   string = "hosts"
	filterSyntaxTypeDnsmasq string = "dnsmasq"
	filterSyntaxTypeRegexp  string = "regexp"

	syntaxDetectLine      int = 100
	syntaxDetectLineValid int = 23
)

var (
	syntaxCommentBytes []byte = []byte{'#', '!', '[', ' '}
)

var filterSyntaxParserMap = map[string]TypeSyntaxParserFunc{
	filterSyntaxTypeAdblock: builtInFilterSyntaxAdblock,
	filterSyntaxTypeDomain:  builtInFilterSyntaxDomain,
	filterSyntaxTypeHosts:   builtInFilterSyntaxHosts,
	filterSyntaxTypeDnsmasq: builtInFilterSyntaxDnsmasq,
}

func (fi *FilterInfo) detectFilterSyntaxParser() error {

	if f, found := filterSyntaxParserMap[fi.Syntax]; found {
		fi.syntaxParserFunc = f
		return nil
	}

	filterSyntaxRegexpFunc := func(s string) (string, string) {
		s = strings.TrimSpace(s)
		s = fi.syntaxRegex.FindString(s)
		return filterSyntaxParse(s)
	}

	if fi.syntaxRegex != nil {
		fi.Syntax = filterSyntaxTypeRegexp
		fi.syntaxParserFunc = filterSyntaxRegexpFunc
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
			if rs, _ := bff(s); len(rs) != 0 {
				mc[bfn]++
			}
		}
	}

	maxCnt := 0
	for bfn, cnt := range mc {
		if cnt > fi.SyntaxDetectLineValid && maxCnt < cnt {
			fi.syntaxParserFunc = filterSyntaxParserMap[bfn]
			fi.Syntax = bfn
			maxCnt = cnt
		}
	}

	if fi.syntaxParserFunc != nil {
		return nil
	}

	return fmt.Errorf("no valid SyntaxParser detect and no regexp syntax configured")
}

func filterSyntaxIsComment(s string) bool {
	return len(s) == 0 || s[0] == '#' || s[0] == '[' || s[0] == '!'
}

func filterSyntaxParse(s string) (string, string) {
	if len(s) == 0 {
		return "", ""
	}

	if _, err := netip.ParseAddr(s); err == nil {
		return s, filterRuleTypeIP
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
func builtInFilterSyntaxDomain(s string) (string, string) {
	s = strings.TrimSpace(s)
	if filterSyntaxIsComment(s) {
		return "", ""
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
func builtInFilterSyntaxAdblock(s string) (string, string) {
	s = strings.TrimSpace(s)
	if len(s) < 4 {
		return "", ""
	}

	if filterSyntaxIsComment(s) {
		return "", ""
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
func builtInFilterSyntaxHosts(s string) (string, string) {
	s = strings.TrimSpace(s)

	if filterSyntaxIsComment(s) {
		return "", ""
	}
	i := 0
	for ; i < len(s) && s[i] != ' '; i++ {
	}
	for ; i < len(s) && s[i] == ' '; i++ {
	}
	j := i + 1
	for ; j < len(s) && s[j] != ' '; j++ {
	}

	if i > 0 && i < j && j <= len(s) {
		s = s[i:j]
	} else {
		return "", ""
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
func builtInFilterSyntaxDnsmasq(s string) (string, string) {
	s = strings.TrimSpace(s)

	if filterSyntaxIsComment(s) {
		return "", ""
	}

	p := "server=/"
	if len(s) <= len(p) || s[:len(p)] != p {
		return "", ""
	}

	return filterSyntaxParse(s[8 : len(s)-1])
}

func InitFilter() error {
	return nil
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
	Ips     map[string]struct{} `json:"ips"`
}

// marshal filter lookup table into string
func (f *Filter) MarshalFilter(name string) string {
	fi := f.Lists[name]
	if fi == nil {
		return "{\"message\": \"invalid filter name\"}"
	}

	fi.lock.Lock()

	id := fi.filterTable.id.Load()
	dm := fi.filterTable.domains[id]
	im := fi.filterTable.ips[id]

	fi.lock.Unlock()

	res := &filterContentMashal{
		Stats:   map[string]int{"domain": len(dm), "ips": len(im)},
		Domains: dm,
		Ips:     im,
	}

	bs, err := json.MarshalIndent(res, "", " ")
	if err != nil {
		return "{\"message\": \"failed to marshal filter content\"}"
	}
	return string(bs)
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
	for ln, l := range f.Lists {
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
			if t < 60*time.Second {
				l.RefreshDuration = 60 * time.Second
			} else {
				l.RefreshDuration = t
			}
			f.daemonEnable = true
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
		if f.Global.Concurrency > len(f.Lists) {
			f.Global.Concurrency = len(f.Lists)
		}

		fpath := f.Global.Path
		if l.Path != "" {
			fpath = l.Path
		}

		l.fpath = path.Join(path.Clean(fpath), l.FileName)

		if st, err := os.Stat(l.fpath); err == nil {
			l.updateTime = st.ModTime()
		} else {
			l.updateTime = unixTime
		}

		l.filterTable = &filterTable{
			id:      &atomic.Uint32{},
			domains: make([]map[string]struct{}, 2),
			ips:     make([]map[string]struct{}, 2),
		}

		if len(l.SyntaxCommentBytes) == 0 {
			l.SyntaxCommentBytes = syntaxCommentBytes
		}

		if l.SyntaxDetectLine <= 0 {
			l.SyntaxDetectLine = syntaxDetectLine
		}

		if l.SyntaxDetectLineValid <= 0 {
			l.SyntaxDetectLineValid = syntaxDetectLineValid
		}

		for i := 0; i < 2; i++ {
			l.filterTable.domains[i] = make(map[string]struct{})
			l.filterTable.ips[i] = make(map[string]struct{})
		}

		if err := l.detectFilterSyntaxParser(); err != nil {
			libnamed.Logger.Error().Str("log_type", "filter").Str("op_type", "detect").Str("filter_name", ln).Err(err).Msg("failed to detect syntax parser")
		}
	}

	runner.RegisterStartPre("filter_LoadLocalFilterFiles", func() error {

		var err error
		if f.Background {
			go f.loadLocalFilterFiles()
		} else {
			err = f.loadLocalFilterFiles()
		}
		return err
	})

	runner.RegisterDaemon("filter_daemon_start", daemonStart, "filter_daemon_reload", daemonReload, "filter_daemon_stop", daemonStop)
	return nil
}

// return: (filter_name, found)
func (f *Filter) MatchDomain(domain string) (string, bool) {

	for ln, l := range f.Lists {
		if l.filterTable.matchDomain(domain) {
			f.filterStats.update(domain, filterRuleTypeDomain, f.DisableStats)
			return ln, true
		}
	}
	return "", false
}

func (f *Filter) MatchIP(addr string) (string, bool) {

	for ln, l := range f.Lists {
		if l.filterTable.matchIP(addr) {
			f.filterStats.update(addr, filterRuleTypeDomain, f.DisableStats)
			return ln, true
		}
	}
	return "", false
}

func (ft *filterTable) matchDomain(domain string) bool {
	m := ft.domains[ft.id.Load()]
	if len(m) == 0 {
		m = ft.domains[ft.id.Load()]
	}
	_, found := m[domain]
	return found
}

func (ft *filterTable) matchIP(addr string) bool {
	m := ft.ips[ft.id.Load()]
	if len(m) == 0 {
		m = ft.ips[ft.id.Load()]
	}
	_, found := m[addr]
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
	cfg := GetGlobalConfig()
	f := cfg.Filter
	f.daemon()
	return nil
}

func daemonReload() error {
	cfg := GetGlobalConfig()
	f := cfg.Filter
	f.signalChan <- signalReload
	return nil
}

func daemonStop() error {
	cfg := GetGlobalConfig()
	f := cfg.Filter
	f.signalChan <- signalStop
	return nil
}

func (f *Filter) daemon() {
LabelReload:
	if !f.daemonEnable {
		return
	}

	finishChan := make(chan struct{})
	go func() {
		time.Sleep(f.Global.DelayDuration)
		f.updateLocalFilterFiles()
		finishChan <- struct{}{}
	}()

	select {
	case signalStr := <-f.signalChan:
		if signalStr == signalReload {
			f = GetGlobalConfig().Filter
			goto LabelReload
		} else {
			return
		}
	case <-finishChan:
		//
	}

	libnamed.Logger.Info().Str("log_type", "filter").Str("op_type", "update").Dur("timer", f.timerDuration).Msg("start daemon to update filter in cycle")

	d := f.timerDuration
	t := time.NewTimer(d)
	for {
		logEvent := libnamed.Logger.Info().Str("log_type", "filter").Str("op_type", "update")
		start := time.Now()
		stats := newFilterUpdateStats(len(f.Lists))

		select {
		case <-t.C:
			var wg sync.WaitGroup
			flying := make(chan struct{}, f.Global.Concurrency)
			for ln, l := range f.Lists {
				if l.RefreshDuration == 0 || time.Since(l.updateTime) < l.RefreshDuration {
					libnamed.Logger.Info().Str("log_type", "filter").Str("op_type", "update").Str("filter_name", ln).Str("syntax", l.Syntax).RawJSON("stats", l.stats.marshal()).Bool("updated", false).Msg("skip update due to configured update policy")
					continue
				}
				wg.Add(1)
				flying <- struct{}{}
				go func(ln string, fi *FilterInfo) {
					var err error
					for i := 0; i < 3; i++ {
						start := time.Now()
						err := fi.download()
						libnamed.Logger.Info().Str("log_type", "filter").Str("op_type", "update").Str("filter_name", ln).Str("syntax", fi.Syntax).RawJSON("stats", fi.stats.marshal()).Bool("updated", err == nil).Dur("elapsed_time", time.Since(start)).Err(err).Msg("")
						if err == nil {
							break
						}
					}
					stats.update(err)
					<-flying
					wg.Done()
				}(ln, l)
			}
			wg.Wait()
			logEvent.Dur("elapsed_time", time.Since(start)).RawJSON("stats", stats.marshal()).Msg("")
			t.Reset(d)
		case signalStr := <-f.signalChan:
			if signalStr == signalReload {
				t.Stop()
				f = GetGlobalConfig().Filter
				goto LabelReload
			} else if signalStr == signalStop {
				libnamed.Logger.Info().Str("log_type", "filter").Str("op_type", "update").Msg("stop filter update daemon")
				goto LabelExit
			} else {
				libnamed.Logger.Error().Str("log_type", "filter").Str("op_type", "update").Err(fmt.Errorf("receive unknow signal '%s'", signalStr)).Msg("stop filter update daemon")
				goto LabelExit
			}
		}
	}
LabelExit:
	t.Stop()
}

func (f *Filter) updateLocalFilterFiles() error {

	logEvent := libnamed.Logger.Info().Str("log_type", "filter").Str("op_type", "update")

	start := time.Now()

	stats := newFilterUpdateStats(len(f.Lists))

	var wg sync.WaitGroup

	flying := make(chan struct{}, f.Global.Concurrency)
	for ln, l := range f.Lists {
		if !l.RefreshAtStartup && time.Since(l.updateTime) < l.RefreshDuration {
			libnamed.Logger.Info().Str("log_type", "filter").Str("op_type", "update").Str("filter_name", ln).Str("syntax", l.Syntax).RawJSON("stats", l.stats.marshal()).Bool("updated", false).Msg("skip update due to configured update policy")
			continue
		}
		wg.Add(1)
		flying <- struct{}{}
		go func(ln string, fi *FilterInfo) {
			var err error
			for i := 0; i < 3; i++ {
				start := time.Now()
				err = fi.download()
				libnamed.Logger.Info().Str("log_type", "filter").Str("op_type", "update").Str("filter_name", ln).Str("syntax", fi.Syntax).RawJSON("stats", fi.stats.marshal()).Bool("updated", err == nil).Dur("elapsed_time", time.Since(start)).Err(err).Msg("")
				if err == nil {
					break
				}
			}
			stats.update(err)
			<-flying
			wg.Done()
		}(ln, l)
	}
	wg.Wait()
	logEvent.Dur("elapsed_time", time.Since(start)).RawJSON("stats", stats.marshal()).Msg("")
	return nil
}

func (f *Filter) loadLocalFilterFiles() error {

	logEvent := libnamed.Logger.Info().Str("log_type", "filter").Str("op_type", "load")

	start := time.Now()

	stats := newFilterUpdateStats(len(f.Lists))

	var wg sync.WaitGroup
	for ln, l := range f.Lists {
		wg.Add(1)
		go func(ln string, fi *FilterInfo) {
			start := time.Now()
			err := fi.parse()
			libnamed.Logger.Info().Str("log_type", "filter").Str("op_type", "load").Str("filter_name", ln).Str("syntax", fi.Syntax).RawJSON("stats", fi.stats.marshal()).Dur("elapsed_time", time.Since(start)).Err(err).Msg("")
			stats.update(err)
			wg.Done()
		}(ln, l)
	}
	wg.Wait()
	logEvent.Dur("elapsed_time", time.Since(start)).RawJSON("stats", stats.marshal()).Msg("")
	return nil
}

type filterSyntaxParseStats struct {
	Total   int `json:"total"`
	Valid   int `json:"valid"`
	Invalid int `json:"invalid"`
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

	ft := fi.filterTable
	id := ft.id.Load()

	sc := bufio.NewScanner(fr)

	stats := &filterSyntaxParseStats{}

	domains := make(map[string]struct{}, len(ft.domains[id]))
	ips := make(map[string]struct{}, len(ft.ips[id]))
	for i := 1; sc.Scan(); i++ {
		rs, rt := fi.syntaxParserFunc(sc.Text())
		if rt == "" {
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

	oid := id
	id ^= 1
	ft.domains[id] = domains
	ft.ips[id] = ips
	ft.id.Store(id)

	// release old objects
	ft.domains[oid] = make(map[string]struct{})
	ft.ips[oid] = make(map[string]struct{})

	fi.updateTime = time.Now()
	stats.Total = stats.Valid + stats.Invalid
	fi.stats = stats

	return nil
}

func (fc *FilterInfo) download() error {

	logEvent := libnamed.Logger.Trace().Str("log_type", "filter").Str("op_type", "download").Str("url", fc.Url)
	start := time.Now()
	defer func() {
		logEvent.Dur("elapsed_time", time.Since(start)).Msg("")
	}()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(fc.TimeoutDuration))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fc.Url, nil)
	logEvent.Err(err)
	if err != nil {
		return err
	}
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Add("Accept-Encoding", "deflate")
	req.Header.Add("Accept-Encoding", "br")

	hc := &libnamed.HyperClient{
		Timeout: fc.TimeoutDuration,
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
	oldfpath := fc.fpath
	tmpfpath := fc.fpath + ".tmp"

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
		fc.fpath = oldfpath
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
	} else {
		fw.Close()
	}
	rd.Close() // compresser don't close the underlying io.Reader

	// parse filter
	fc.fpath = tmpfpath

	if err := fc.parse(); err != nil {
		logEvent.Err(err)
		return err
	}

	// update
	err = os.Rename(tmpfpath, oldfpath)
	logEvent.Err(err)
	return err
}
