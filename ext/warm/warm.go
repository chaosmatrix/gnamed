package warm

import (
	"encoding/json"
	"errors"
	"fmt"
	"gnamed/cachex"
	"gnamed/ext/runner"
	"gnamed/ext/xgeoip2"
	"gnamed/ext/xlog"
	"math"
	"net"
	"os"
	"path"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type WarmFormat struct {
	Count                int
	Start                time.Time `json:"-"`
	ElapsedTime          string    // duration to persist warm cache
	ElapsedTimeDumpCache string    //
	ElapsedTimeUpdate    string
	Timestamp            int64
	MsgSizeStat          *MsgSizeStat
	Elements             map[string]map[uint16]*WarmElement // name -> qtype -> element
}

type WarmElement struct {
	Frequency         int    `json:"frequency"`
	Rcode             int    `json:"rcode"`
	Country           string `json:"country"`
	Type              uint16 `json:"type"`
	LastUsedTimestamp int64  `json:"last_used_timestamp"`
	MsgSize           int    `json:"msg_size,omitempty"`
	MsgSections       int    `json:"msg_sections,omitempty"`
}

type MsgSizeStat struct {
	Count      int         `json:"total"`
	Max        int         `json:"max"`
	Min        int         `json:"min"`
	Middle     int         `json:"middle"`
	Avg        int         `json:"avg"`
	CDFMapSize map[int]int `json:"cdf_map_size"` // CDF stat
}

// keep newest *WarmRunnerInfo
var _warmRunnerInfoValue = new(atomic.Value)

type WarmRunnerInfo struct {
	FileName            string        `json:"filename"`
	Delay               string        `json:"delay"`
	DelayDuration       time.Duration `json:"-"`
	Concurrency         int           `json:"concurrency"`
	FrequencyUpTo       int           `json:"frequencyUpTo"`
	UnUsedTime          string        `json:"unusedTime"` // case 0, use default, case positive, use it, case negative, skip check
	unUsedUnix          int64         `json:"-"`
	NameServerUDP       string        `json:"nameServerUDP"`
	Maxminddb           string        `json:"maxminddb"` // if empty, skip lookup the location of ip
	StoreNonWarmUpCache bool          `json:"storeNonWarmUpCache"`
	cacheWarmed         bool          `json:"-"`
	Limit               *WarmLimit    `json:"limit"`
}

// rate limit
type WarmLimit struct {
	Token            int    `json:"token"`
	Interval         string `json:"interval"`
	IntervalDuration time.Duration
}

const (
	defaultDelayDuration = 60 * time.Second
	defaultConcurrency   = 8
	defaultFrequencyUpTo = 1
	defaultUnUsedUnix    = 7 * 24 * 60 * 60 // 7 days in seconds
)

func (wri *WarmRunnerInfo) Run() error {
	return wri.run()
}

func (wri *WarmRunnerInfo) run() error {
	time.Sleep(wri.DelayDuration)
	start := time.Now()
	wstat, err := wri.sendQuery()
	if err != nil {
		xlog.Logger().Error().Str("log_type", "WarmRunner").Dur("Delay", wri.DelayDuration).Dur("elapsed_time", time.Since(start)).Err(err).Msg("failed to warm cache at startup")
	} else {
		xlog.Logger().Info().Str("log_type", "WarmRunner").Dur("Delay", wri.DelayDuration).Dur("elapsed_time", time.Since(start)).RawJSON("stats", wstat.marshal()).Msg("success warm cache at startup")
	}
	wri.cacheWarmed = true
	return err
}

func (wri *WarmRunnerInfo) Parse() error {
	return wri.parse()
}

func (wri *WarmRunnerInfo) parse() error {
	if wri.FileName == "" {
		return errors.New("empty filename")
	}
	if wri.Delay == "" {
		wri.DelayDuration = defaultDelayDuration
	} else {
		if d, err := time.ParseDuration(wri.Delay); err == nil && d >= 0 {
			wri.DelayDuration = d
		} else {
			if err == nil {
				err = fmt.Errorf("invlaid duration Delay: %s", wri.Delay)
			}
			return err
		}
	}

	if wri.Concurrency <= 0 {
		wri.Concurrency = defaultConcurrency
	}

	if wri.FrequencyUpTo < defaultFrequencyUpTo {
		wri.FrequencyUpTo = defaultFrequencyUpTo
	}

	if wri.UnUsedTime == "" {
		wri.unUsedUnix = defaultUnUsedUnix
	} else {
		if d, err := time.ParseDuration(wri.UnUsedTime); err == nil && d >= 0 {
			wri.unUsedUnix = int64(d.Seconds())
		} else {
			if err == nil {
				err = fmt.Errorf("invalid duration UnUsedTime: %s", wri.UnUsedTime)
			}
			return err
		}
	}

	if wri.NameServerUDP == "" {
		return fmt.Errorf("no valid nameserver")
	} else {
		_, _, err := net.SplitHostPort(wri.NameServerUDP)
		if err != nil {
			return fmt.Errorf("invalid nameserver '%s', error: %v", wri.NameServerUDP, err)
		}
	}

	if wri.Limit != nil {
		if d, err := time.ParseDuration(wri.Limit.Interval); err == nil && d > 0 {
			wri.Limit.IntervalDuration = d
		}
		if wri.Limit.Token <= 0 || wri.Limit.IntervalDuration <= 0 {
			return fmt.Errorf("invalid rate limit value")
		}
	}

	if wri.Maxminddb != "" {
		if err := xgeoip2.InitDefaultGeoReader(wri.Maxminddb); err != nil {
			return err
		}
	}

	_warmRunnerInfoValue.Store(wri)

	runner.RegisterStartPost("warm_cache", func() error {
		_wri := _warmRunnerInfoValue.Load().(*WarmRunnerInfo)
		go _wri.run()
		return nil
	})

	runner.RegisterShutdown("warm_cache_store", func() error {
		_wri := _warmRunnerInfoValue.Load().(*WarmRunnerInfo)
		err := _wri.Store()
		return err
	})
	return nil
}

type warmStats struct {
	Total   int          `json:"total"`
	Unique  int          `json:"unique"`
	Skip    int          `json:"skip"`
	skip    atomic.Int64 `json:"-"`
	Err     int          `json:"error"`
	err     atomic.Int64 `json:"-"`
	Success int          `json:"success"`
	success atomic.Int64 `json:"-"`
}

func (ws *warmStats) marshal() []byte {

	ws.Skip = int(ws.skip.Load())
	ws.Err = int(ws.err.Load())
	ws.Success = int(ws.success.Load())

	ws.Total = ws.Skip + ws.Err + ws.Success

	bs, err := json.Marshal(ws)
	if err == nil {
		return bs
	}
	return []byte("{}")
}

func (wri *WarmRunnerInfo) sendQuery() (*warmStats, error) {
	wstat := &warmStats{}
	fr, err := os.Open(wri.FileName)
	if err != nil {
		return wstat, err
	}
	defer fr.Close()
	wf := &WarmFormat{}
	err = json.NewDecoder(fr).Decode(wf)
	if err != nil || wf.Count <= 0 {
		return wstat, err
	}

	wstat.Unique = wf.Count

	concurrency := wri.Concurrency
	if concurrency > wf.Count {
		concurrency = wf.Count
	}
	var wg sync.WaitGroup

	qnameChan := make(chan string, concurrency)
	unUsedDuration := time.Duration(wri.unUsedUnix) * time.Second
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			m := new(dns.Msg)
			client := &dns.Client{
				UDPSize: 1280,
				Timeout: 5 * time.Second,
			}
			conn, err := client.Dial(wri.NameServerUDP)
			for {
				qname := <-qnameChan
				if qname == "" {
					// exit
					qnameChan <- ""
					break
				}
				for _, we := range wf.Elements[qname] {

					logEvent := xlog.Logger().Debug().Str("log_type", "WarmRunner").Str("op_type", "query").Str("name", qname).Str("type", dns.TypeToString[we.Type])
					if we.Frequency < wri.FrequencyUpTo {
						logEvent.Msg("skip due to low frequency")
						wstat.skip.Add(1)
						continue
					} else if we.Rcode != dns.RcodeSuccess {
						logEvent.Msg("skip due to not success rcode")
						wstat.skip.Add(1)
						continue
					} else if wri.unUsedUnix > 0 && we.LastUsedTimestamp > 0 && wf.Timestamp-we.LastUsedTimestamp > wri.unUsedUnix {
						logEvent.Dur("unused", unUsedDuration).Msg("skip due to long time unused by user")
						wstat.skip.Add(1)
						continue
					}

					m.SetQuestion(qname, we.Type)

					for j := 0; j < 3; j++ {
						if conn != nil {
							_, _, err = client.ExchangeWithConn(m, conn)
						} else {
							_, _, err = client.Exchange(m, wri.NameServerUDP)
						}
						if err != nil || conn == nil {
							if conn != nil {
								conn.Close()
							}
							conn, _ = client.Dial(wri.NameServerUDP)
						}
						if err == nil {
							break
						}
					}
					if err == nil {
						wstat.success.Add(1)
					} else {
						wstat.err.Add(1)
					}
					logEvent.Err(err).Msg("")
				}
			}
			if conn != nil {
				conn.Close()
			}
			wg.Done()
		}()
	}

	if wri.Limit == nil {
		for qname := range wf.Elements {
			qnameChan <- qname
		}
	} else {
		token := wri.Limit.Token
		timer := time.NewTimer(wri.Limit.IntervalDuration)
		for qname := range wf.Elements {
			qnameChan <- qname
			token--
			if token <= 0 {
				token = wri.Limit.Token
				<-timer.C
				timer.Reset(wri.Limit.IntervalDuration)
			}
		}
	}

	// stop
	qnameChan <- ""

	wg.Wait()
	qnameChan = nil

	return wstat, err
}

func (wri *WarmRunnerInfo) Store() error {
	start := time.Now()
	err := wri.store()
	elapsedTime := time.Since(start)
	if err != nil {
		xlog.Logger().Error().Str("log_type", "WarmRunner").Str("op_type", "Store").Dur("elapsed_time", elapsedTime).Err(err).Msg("failed to store cache as file")
	} else {
		xlog.Logger().Info().Str("log_type", "WarmRunner").Str("op_type", "Store").Dur("elapsed_time", elapsedTime).Msg("success to store cache as file")
	}
	return err
}

func (wri *WarmRunnerInfo) store() error {

	if !wri.cacheWarmed && !wri.StoreNonWarmUpCache {
		return fmt.Errorf("skip store cache as file, cause didn't warm up")
	}

	start := time.Now()
	ses := cachex.Store()
	elapsedTime := time.Since(start).String()
	if len(ses) == 0 {
		return fmt.Errorf("cache size is zero, skip truncate old warm file")
	}

	wf := new(WarmFormat)

	wf.ElapsedTimeDumpCache = elapsedTime

	wf.Count = len(ses)

	fpath := path.Dir(wri.FileName)
	if _, err := os.Stat(fpath); err != nil && !os.IsExist(err) {
		if err = os.MkdirAll(fpath, 0755); err != nil {
			return err
		}
	}

	tmpfn := wri.FileName + ".tmp"
	fw, err := os.OpenFile(tmpfn, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}

	wri.update(wf, ses)

	wf.ElapsedTime = time.Since(start).String()

	je := json.NewEncoder(fw)
	je.SetIndent("", "\t")
	err = je.Encode(wf)
	if err != nil {
		fw.Close()
		os.Remove(tmpfn)
		return err
	}
	fw.Close()
	err = os.Rename(tmpfn, wri.FileName)
	return err
}

func (wri *WarmRunnerInfo) update(wf *WarmFormat, ses cachex.StoreElements) error {

	start := time.Now()
	defer func() {
		wf.ElapsedTimeUpdate = time.Since(start).String()
	}()

	owf := new(WarmFormat)
	fr, err := os.Open(wri.FileName)
	if err != nil {
		owf = nil
	} else {
		defer fr.Close()
		if err := json.NewDecoder(fr).Decode(owf); err != nil {
			owf = nil
		}
	}

	wf.Count = len(ses)

	nowUnix := time.Now().Unix()
	wf.Timestamp = nowUnix

	if wf.Elements == nil {
		wf.Elements = make(map[string]map[uint16]*WarmElement)
	}

	msss := make([]int, 0, len(ses)*2)
	sumMsgSize := 0
	for qname, sem := range ses {
		if wf.Elements[qname] == nil {
			wf.Elements[qname] = make(map[uint16]*WarmElement, len(sem))
		}
		for qtype, se := range sem {
			nwe := &WarmElement{
				Frequency:         se.Frequency,
				Rcode:             se.Rcode,
				Country:           se.Country,
				Type:              qtype,
				MsgSize:           se.MsgSize,
				MsgSections:       se.MsgSections,
				LastUsedTimestamp: nowUnix,
			}
			sumMsgSize += se.MsgSize
			msss = append(msss, se.MsgSize)
			if se.Frequency == 1 && owf != nil && owf.Elements != nil {
				if owes, found := owf.Elements[qname]; found {
					if owe, found1 := owes[qtype]; found1 {
						nwe.LastUsedTimestamp = owe.LastUsedTimestamp
					}
				}
			}
			wf.Elements[qname][qtype] = nwe
		}
	}

	mss := &MsgSizeStat{}
	if len(msss) > 0 {
		sort.Ints(msss)
		cdfmap := map[int]int{
			10: 0, 20: 0, 30: 0, 40: 0, 50: 0, 60: 0, 65: 0,
			70: 0, 75: 0, 80: 0, 85: 0, 90: 0, 95: 0, 99: 0,
		}
		p := 0.01
		for f := range cdfmap {
			i := int(math.Ceil(float64(len(msss)*f) * p))
			if i >= len(msss) {
				i = len(msss) - 1
			}
			cdfmap[f] = msss[i]
		}

		middle := 0
		if len(msss)%2 == 0 {
			middle = (msss[len(msss)/2-1] + msss[len(msss)/2]) / 2
		} else {
			middle = msss[len(msss)/2]
		}
		mss = &MsgSizeStat{
			Count:      len(msss),
			Min:        msss[0],
			Max:        msss[len(msss)-1],
			Middle:     middle,
			Avg:        sumMsgSize / len(msss),
			CDFMapSize: cdfmap,
		}
	}
	wf.MsgSizeStat = mss
	return err
}
