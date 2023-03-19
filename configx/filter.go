package configx

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"gnamed/libnamed"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

// Data Sources:
// * https://gitlab.com/malware-filter/urlhaus-filter
// 	* https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh-online.txt
//  * https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt
// * https://filterlists.com/

// random String
var randStr = strconv.Itoa(int(rand.NewSource(time.Now().Unix()).Int63() % 100000))

type Filter struct {
	Background bool                     `json:"background"` // parsed filter Background
	Default    FilterConfig             `json:"default"`
	Lists      map[string]*FilterConfig `json:"lists"`

	// internal using
	tables        map[string]*lookupTable `json:"-"` // name -> filter
	stopChan      chan struct{}           `json:"-"` // signal deamon to exit
	daemonRunning bool                    `json:"-"` // tag daemon running or not
	stats         *filterStats            `json:"-"`
}

type FilterConfig struct {
	Path             string `json:"path"`
	Refresh          string `json:"refresh"`
	Parser           string `json:"parser"`
	Filename         string `json:"filename"`
	Url              string `json:"url"`
	RefreshAtStartup bool   `json:"refresh_at_startup"`

	// internal
	refreshDuration time.Duration `json:"-"` // internal use
	fpath           string        `json:"-"` // internal use, full path file name
	lookupTable     *lookupTable  `json:"-"` // refer Filter.tables[name]
}

type lookupTable struct {
	id      atomic.Uint32
	lock    *sync.RWMutex
	domains [2]map[string]bool
	ips     [2]map[string]bool
}

// internal use
type filterStats struct {
	total       atomic.Int64
	domainTotal atomic.Int64
	ipTotal     atomic.Int64
	domainHit   atomic.Int64
	ipHit       atomic.Int64
}

type ParserFuncNameType string
type ParserFuncType func(fname string) (domains map[string]bool, ips map[string]bool)

const (
	ParserFuncNameDefault = "default"
	ParserFuncNameAgh     = "agh" // AdGuard Home
)

var allowFilterParser = []string{ParserFuncNameDefault, ParserFuncNameAgh}

type ParserTypeInterface interface {
	setFileds(lt *lookupTable)
	parse(fname string) error
}

// mapping parser into struct
// struct info will be changed after every time used
var _pm = map[string]func() ParserTypeInterface{
	ParserFuncNameDefault: func() ParserTypeInterface { return &defaultParser{} },
	ParserFuncNameAgh:     func() ParserTypeInterface { return &aghParser{} },
}

type FilterStats struct {
	Total       int64
	DomainTotal int64
	IPTotal     int64
	DomainHit   int64
	IPHit       int64
}

func (f *Filter) GetStats() FilterStats {
	return FilterStats{
		Total:       f.stats.total.Load(),
		DomainTotal: f.stats.domainTotal.Load(),
		IPTotal:     f.stats.ipTotal.Load(),
		DomainHit:   f.stats.domainHit.Load(),
		IPHit:       f.stats.ipHit.Load(),
	}
}

func (f *Filter) StopDaemon() {
	if f.daemonRunning {
		f.stopChan <- struct{}{}
	}
}

// a deamon update filters in schedule
func (f *Filter) deamon() {
	interval, round := f.findRefreshSecond()

	f.daemonRunning = interval > 0

	if interval > 0 {
		libnamed.Logger.Debug().Str("log_type", "filter").Msg("update filter's rule in configured refresh interval")
	}

	curr := interval
	go func() {

		// check filters that need to refresh at startup
		k := 0
		var wg *sync.WaitGroup = new(sync.WaitGroup)
		for ln, lc := range f.Lists {
			if lc.RefreshAtStartup {
				k++
				wg.Add(1)
				go func(k int, ln string, lc *FilterConfig) {
					for i := 1; i <= 3; i++ {
						time.Sleep(time.Duration(k%10) + time.Duration(i)*30*time.Second)
						err := lc.UpdateFilter()
						libnamed.Logger.Debug().Str("log_type", "filter").Str("name", ln).Str("op_type", "update_filter").Str("filename", lc.fpath).Err(err).Msg("refresh filter at startup")
						if err == nil {
							break
						}
					}
					wg.Done()
				}(k, ln, f.Lists[ln])
			}
		}
		wg.Wait()

		if interval == 0 {
			return
		}

		t := time.NewTicker(time.Duration(interval) * time.Second)
		for {
			select {
			case <-t.C:
				//
			case <-f.stopChan:
				// receive exit signal
				libnamed.Logger.Debug().Str("log_type", "filter").Msg("receive signal, daemon exit")
				return
			}

			cnt := 0
			for ln, lc := range f.Lists {
				secs := int(lc.refreshDuration.Seconds())
				if secs > 0 && curr%secs == 0 {
					cnt++
					go func(cnt int, ln string, lc *FilterConfig) {
						// cause the lc.refreshDurations might be very large, so, need to retry if failed
						k := int(lc.refreshDuration.Seconds())/3600 - 1
						if k <= 0 {
							k = 1
						}
						for i := 0; i < k; i++ {
							time.Sleep(time.Duration(cnt % 10))
							err := lc.UpdateFilter()
							logEvent := libnamed.Logger.Debug().Str("log_type", "filter").Str("name", ln).Str("op_type", "update_filter").Str("filename", lc.fpath).Err(err)
							if i > 0 {
								logEvent.Int("retry", i)
							}
							logEvent.Msg("")

							if err == nil {
								break
							}
							time.Sleep(time.Duration(i) * 30)
						}
					}(cnt, ln, f.Lists[ln])
				}
			}
			if cnt > 0 {
				libnamed.Logger.Debug().Str("log_type", "filter").Msgf("in this cycle the number of filter need to update is %d", cnt)
			}
			curr %= round
			curr += interval
		}
	}()
}

// (refershInterval, refershRound)
func (f *Filter) findRefreshSecond() (int, int) {
	interval, round := 0, 0
	for _, fc := range f.Lists {
		if fc.refreshDuration == 0 {
			continue
		}
		secs := int(fc.refreshDuration.Seconds())
		if interval != 0 {
			interval = gcd(interval, secs)
			round = lcm(round, secs)
		} else {
			interval = secs
			round = secs
		}
	}
	return interval, round
}

func gcd(x, y int) int {
	if x == 0 || y == 0 {
		return 0
	}
	for x != 0 {
		x, y = y%x, x
	}

	return y
}

func lcm(x, y int) int {
	return x / gcd(x, y) * y
}

func (fc *FilterConfig) UpdateFilter() error {

	// fetch filter
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(60*time.Second))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fc.Url, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Accept-Encoding", "gzip")
	req.Header.Add("Accept-Encoding", "deflate")
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.Proto != "https" {
				return fmt.Errorf("only https allow")
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil || resp == nil || resp.StatusCode != 200 || resp.Body == nil {
		return fmt.Errorf("invalid http response, error: %v", err)
	}

	// persist as temp file
	tmpfpath := fc.fpath + "." + randStr + ".tmp"

	fw, err := os.OpenFile(tmpfpath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}

	// make sure tmpfpath removed
	defer func() {
		fw.Close() // it's ok for double close fd
		if fi, err := os.Stat(tmpfpath); os.IsExist(err) && fi.Mode().IsRegular() {
			err = os.Remove(tmpfpath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[+] failed to remove tmp file %s", tmpfpath)
			}
		}
	}()

	rd := resp.Body
	if !resp.Uncompressed {
		ce := resp.Header.Get("Content-Encoding")
		if strings.Contains(ce, "gzip") {
			if gziprd, err := gzip.NewReader(resp.Body); err == nil {
				rd = gziprd
			} else {
				return err
			}
		} else if strings.Contains(ce, "deflate") {
			rd = flate.NewReader(resp.Body)
		} else {
			// unknow compress algorithm
			return fmt.Errorf("server sent http response wiht unknow compression algorithm %s", ce)
		}
	}
	if _, err := io.Copy(fw, rd); err != nil {
		//
		fw.Close()
		return err
	} else {
		fw.Close()
	}
	rd.Close()

	// parse filter
	oldpath := fc.fpath
	fc.fpath = tmpfpath
	if err := fc.Parse(); err != nil {
		fc.fpath = oldpath
		return err
	}
	fc.fpath = oldpath

	// update
	if err := os.Rename(tmpfpath, oldpath); err != nil {
		return err
	}
	return nil
}

func (f *Filter) Parse() error {

	// check default
	if f.Default.Path == "" {
		wd, err := os.Getwd()

		if err != nil {
			return err
		}
		f.Default.Path = wd
	}
	if f.Default.Parser == "" {
		f.Default.Parser = ParserFuncNameDefault
	} else {
		good := false
		for _, p := range allowFilterParser {
			if p == f.Default.Parser {
				good = true
				break
			}
		}
		if !good {
			return fmt.Errorf("invalid filter parser, valid parsers are %v", allowFilterParser)
		}
	}

	if f.Default.Refresh != "" {
		d, err := time.ParseDuration(f.Default.Refresh)
		if err != nil {
			return err
		}
		f.Default.refreshDuration = d
	}

	// init internal using value
	f.tables = make(map[string]*lookupTable)

	// check lists
	for ln, lc := range f.Lists {
		if lc.Filename == "" {
			return fmt.Errorf("invalid filter list, name: %s", ln)
		}
		fpath := lc.Path
		if fpath == "" {
			fpath = f.Default.Path
		}

		fpath = path.Clean(path.Join(fpath, lc.Filename))
		// TODO: optional: for the sake of security, make sure under current working directory
		//
		if fi, err := os.Stat(fpath); err == nil {
			if !fi.Mode().IsRegular() {
				return fmt.Errorf("no such file: %s", fpath)
			}
			if fi.Mode().Perm()&0666 != 0666 {
				return fmt.Errorf("don't have read and write permission for file %s", fpath)
			}
		} else {
			return err
		}

		lc.fpath = fpath
		if lc.Parser == "" {
			lc.Parser = ParserFuncNameDefault
		} else {
			good := false
			for _, p := range allowFilterParser {
				if p == lc.Parser {
					good = true
					break
				}
			}
			if !good {
				return fmt.Errorf("invalid filter parser, valid parsers are %v", allowFilterParser)
			}
		}

		if lc.Refresh != "" {
			d, err := time.ParseDuration(lc.Refresh)
			if err != nil {
				return err
			}
			lc.refreshDuration = d
		}

		lt := &lookupTable{
			lock: new(sync.RWMutex),
		}
		f.tables[ln] = lt
		lc.lookupTable = lt
		f.Lists[ln] = lc
	}

	f.stats = new(filterStats)

	// parse filter list
	if err := f.ParseFilter(); err != nil {
		return err
	}

	f.stopChan = make(chan struct{})
	f.deamon()
	return nil
}

func (f *Filter) ParseFilter() error {

	var err error
	k := 0

	f.stats.total.Store(0)
	// if parse filter in background
	// some query will be bypassed during sartup/reload.
	var wg *sync.WaitGroup = new(sync.WaitGroup)
	for ln, _ := range f.Lists {
		k++
		wg.Add(1)
		go func(k int, lc *FilterConfig) {
			time.Sleep(time.Duration(k%10) * time.Second)
			if _err := lc.Parse(); _err != nil {
				err = _err
			}
			wg.Done()
			domainTotal := int64(len(lc.lookupTable.domains[int(lc.lookupTable.id.Load())]))
			ipTotal := int64(len(lc.lookupTable.ips[int(lc.lookupTable.id.Load())]))
			f.stats.domainTotal.Add(domainTotal)
			f.stats.ipTotal.Add(ipTotal)
			f.stats.total.Add(domainTotal + ipTotal)

		}(k, f.Lists[ln])
	}
	if !f.Background {
		wg.Wait()
	}

	return err
}

func (fc *FilterConfig) Parse() error {
	lt := fc.lookupTable

	var err error
	if pf, found := _pm[fc.Parser]; found {
		p := pf()
		p.setFileds(lt)
		err = p.parse(fc.fpath)
	} else {
		p := _pm["default"]()
		p.setFileds(lt)
		err = p.parse(fc.fpath)
	}

	return err
}

func (f *Filter) MatchDomain(domain string) (string, bool) {
	for listName, lt := range f.tables {
		id := lt.id.Load()
		if lt.domains[id][domain] {
			f.stats.domainHit.Add(1)
			return listName, true
		}
	}

	return "", false
}

func (f *Filter) MatchIP(ip string) (string, bool) {
	for listName, lt := range f.tables {
		id := lt.id.Load()
		if lt.ips[id][ip] {
			f.stats.ipHit.Add(1)
			return listName, true
		}
	}

	return "", false
}

/*
# Title: Online Malicious Domains Blocklist
# Updated: 2023-03-09T12:11:51Z
# Expires: 1 day (update frequency)
# Homepage: https://gitlab.com/malware-filter/urlhaus-filter
# License: https://gitlab.com/malware-filter/urlhaus-filter#license
# Source: https://urlhaus.abuse.ch/api/
1.2.3.4
malware-domain.com
*/
type defaultParser struct {
	lookupTable *lookupTable
}

func (dp *defaultParser) setFileds(lt *lookupTable) {
	dp.lookupTable = lt
}

func (dp *defaultParser) parse(fname string) error {
	dp.lookupTable.lock.Lock()
	defer dp.lookupTable.lock.Unlock()
	id := dp.lookupTable.id.Load() ^ 1

	// clean all
	dp.lookupTable.domains[id] = make(map[string]bool)
	dp.lookupTable.ips[id] = make(map[string]bool)

	domains, ips := dp.lookupTable.domains[id], dp.lookupTable.ips[id]

	fr, err := os.Open(fname)
	if err != nil {
		return err
	}
	defer fr.Close()

	errCnt := 0
	sc := bufio.NewScanner(fr)
	//sc.Split(bufio.ScanLines) // default
	for i := 1; sc.Scan(); i++ {
		line := strings.TrimSpace(sc.Text())
		if len(line) < 3 || strings.HasPrefix(line, "#") {
			continue
		}

		if sip := net.ParseIP(line); sip != nil && sip.String() == line {
			ips[sip.String()] = true
		} else if libnamed.ValidateDomain(line) {
			domains[dns.Fqdn(line)] = true
		} else {
			// invalid
			k := len(line)
			if k > 23 {
				k = 23
			}
			fmt.Fprintf(os.Stderr, "[+] invalid filter, filename: %s, line: %d, filter: %s\n", fname, i, line[:k])
			errCnt++
		}
	}

	// check
	if len(domains) != 0 || len(ips) != 0 {
		dp.lookupTable.id.Store(id)
	} else if errCnt > 0 {
		return fmt.Errorf("all filters are invalid")
	}
	return nil
}

/*
! Title: Online Malicious URL Blocklist (AdGuard Home)
! Updated: 2023-03-09T12:11:51Z
! Expires: 1 day (update frequency)
! Homepage: https://gitlab.com/malware-filter/urlhaus-filter
! License: https://gitlab.com/malware-filter/urlhaus-filter#license
! Source: https://urlhaus.abuse.ch/api/
||1.2.3.4^
||malware-domain.com^
*/
type aghParser struct {
	lookupTable *lookupTable
}

func (ap *aghParser) setFileds(lt *lookupTable) {
	ap.lookupTable = lt
}

func (ap *aghParser) parse(fname string) error {
	ap.lookupTable.lock.Lock()
	defer ap.lookupTable.lock.Unlock()
	id := ap.lookupTable.id.Load() ^ 1

	// always clean it
	ap.lookupTable.domains[id] = make(map[string]bool)
	ap.lookupTable.ips[id] = make(map[string]bool)

	domains, ips := ap.lookupTable.domains[id], ap.lookupTable.ips[id]

	fr, err := os.Open(fname)
	if err != nil {
		return err
	}

	defer fr.Close()

	sc := bufio.NewScanner(fr)
	//sc.Split(bufio.ScanLines) // default

	// line format: ||<content>^
	errCnt := 0
	for i := 1; sc.Scan(); i++ {
		line := strings.TrimSpace(sc.Text())
		if len(line) < 3 || strings.HasPrefix(line, "!") {
			continue
		}

		line = line[2 : len(line)-1]

		if sip := net.ParseIP(line); sip != nil && sip.String() == line {
			ips[sip.String()] = true
		} else if libnamed.ValidateDomain(line) {
			domains[dns.Fqdn(line)] = true
		} else {
			// invalid
			k := len(line)
			if k > 23 {
				k = 23
			}
			fmt.Fprintf(os.Stderr, "[+] invalid filter, filename: %s, line: %d, filter: %s\n", fname, i, line[:k])
			errCnt++
		}
	}

	if len(domains) != 0 || len(ips) != 0 {
		ap.lookupTable.id.Store(id)
	} else if errCnt > 0 {
		return fmt.Errorf("all filters are invalid")
	}
	return nil
}
