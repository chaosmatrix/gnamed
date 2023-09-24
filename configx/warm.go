package configx

import (
	"encoding/json"
	"fmt"
	"gnamed/libnamed"
	"gnamed/runner"
	"io"
	"net"
	"os"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type WarmFormat struct {
	Count                         int
	Start                         time.Time `json:"-"`
	ElapsedTime                   string    // duration to persist warm cache
	ElapsedTimeDumpCache          string    //
	ElapsedTimeUpdateLastUsedTime string
	Timestamp                     int64
	Elements                      map[string]map[uint16]*WarmElement // name -> qtype -> element
}

type WarmElement struct {
	//Name      string `json:"name"`
	Frequency         int    `json:"frequency"`
	Rcode             int    `json:"rcode"`
	Country           string `json:"country"`
	Type              uint16 `json:"type"`
	LastUsedTimestamp int64  `json:"last_used_timestamp"`
}

type WarmRunnerInfo struct {
	FileName            string        `json:"filename"`
	Delay               string        `json:"delay"`
	DelayDuration       time.Duration `json:"-"`
	Interval            string        `json:"interval"`
	IntervalDuration    time.Duration `json:"-"`
	Concurrency         int           `json:"concurrency"`
	FrequencyUpTo       int           `json:"frequencyUpTo"`
	UnUsedTime          string        `json:"unused_time"` // case 0, use default, case positive, use it, case negative, skip check
	unUsedUnix          int64         `json:"-"`
	NameServerUDP       string        `json:"nameServerUDP"`
	Maxminddb           string        `json:"maxminddb"` // if empty, skip lookup the location of ip
	StoreNonWarmUpCache bool          `json:"storeNonWarmUpCache"`
	cacheWarmed         bool          `json:"-"`
}

type WarmLimiter struct {
	Token            int
	Interval         string
	IntervalDuration time.Duration
}

const (
	defaultDelayDuration    = 60 * time.Second
	defaultIntervalDuration = 5 * time.Millisecond
	defaultConcurrency      = 8
	defaultFrequencyUpTo    = 1
	defaultUnUsedUnix       = 7 * 24 * 60 * 60 // 7 days in seconds
)

func (wri *WarmRunnerInfo) Run() error {
	return wri.run()
}

func (wri *WarmRunnerInfo) run() error {
	time.Sleep(wri.DelayDuration)
	start := time.Now()
	wstat, err := wri.sendQuery()
	if err != nil {
		libnamed.Logger.Error().Str("log_type", "WarmRunner").Dur("Delay", wri.DelayDuration).Dur("elapsed_time", time.Since(start)).Err(err).Msg("failed to warm cache at startup")
	} else {
		libnamed.Logger.Info().Str("log_type", "WarmRunner").Dur("Delay", wri.DelayDuration).Dur("elapsed_time", time.Since(start)).RawJSON("stats", wstat.marshal()).Msg("success warm cache at startup")
	}
	wri.cacheWarmed = true
	return err
}

func (wri *WarmRunnerInfo) parse() error {
	if d, err := time.ParseDuration(wri.Delay); err == nil && d >= 0 {
		wri.DelayDuration = d
	} else {
		wri.DelayDuration = defaultDelayDuration
	}

	if d, err := time.ParseDuration(wri.Interval); err == nil && d >= 0 {
		wri.IntervalDuration = d
	} else {
		wri.IntervalDuration = defaultIntervalDuration
	}

	if wri.Concurrency > defaultConcurrency || wri.Concurrency <= 0 {
		wri.Concurrency = defaultConcurrency
	}

	if wri.FrequencyUpTo < defaultFrequencyUpTo {
		wri.FrequencyUpTo = defaultFrequencyUpTo
	}

	if d, err := time.ParseDuration(wri.UnUsedTime); err == nil && d != 0 {
		wri.unUsedUnix = int64(d.Seconds())
	} else {
		wri.unUsedUnix = defaultUnUsedUnix
	}

	if wri.NameServerUDP == "" {
		return fmt.Errorf("no valid nameserver")
	} else {
		_, _, err := net.SplitHostPort(wri.NameServerUDP)
		if err != nil {
			return fmt.Errorf("invalid nameserver '%s', error: %v", wri.NameServerUDP, err)
		}
	}

	runner.RegisterStartPost("warm_cache", func() error {
		go wri.run()
		return nil
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

					logEvent := libnamed.Logger.Debug().Str("log_type", "WarmRunner").Str("op_type", "query").Str("name", qname).Str("type", dns.TypeToString[we.Type])
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

	for qname := range wf.Elements {
		qnameChan <- qname
	}

	// stop
	qnameChan <- ""

	wg.Wait()
	qnameChan = nil

	return wstat, err
}

func (wri *WarmRunnerInfo) Store(wf *WarmFormat) error {
	err := wri.store(wf)
	if err != nil {
		libnamed.Logger.Error().Str("log_type", "WarmRunner").Str("op_type", "Store").Err(err).Msg("failed to store cache as file")
	} else {
		libnamed.Logger.Info().Str("log_type", "WarmRunner").Str("op_type", "Store").Msg("success to store cache as file")
	}
	return err
}

func (wri *WarmRunnerInfo) store(wf *WarmFormat) error {

	if !wri.cacheWarmed && !wri.StoreNonWarmUpCache {
		return fmt.Errorf("skip store cache as file, cause didn't warm up")
	}
	if len(wf.Elements) == 0 {
		return fmt.Errorf("cache size is zero, skip truncate old warm file")
	}

	wf.ElapsedTimeDumpCache = time.Since(wf.Start).String()

	wf.Count = len(wf.Elements)

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

	wri.updateLastUsedTime(wf)

	wf.ElapsedTime = time.Since(wf.Start).String()

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

func (wri *WarmRunnerInfo) updateLastUsedTime(wf *WarmFormat) error {

	start := time.Now()
	defer func() {
		wf.ElapsedTimeUpdateLastUsedTime = time.Since(start).String()
	}()

	fr, err := os.Open(wri.FileName)
	if err != nil {
		return err
	}
	defer fr.Close()

	bs, err := io.ReadAll(fr)
	if err != nil {
		return err
	}

	owf := new(WarmFormat)
	err = json.Unmarshal(bs, owf)
	if err != nil {
		return err
	}

	nowUnix := time.Now().Unix()
	wf.Timestamp = nowUnix
	for qname, owes := range owf.Elements {
		if wes, found := wf.Elements[qname]; found {
			for qtype, we := range wes {
				wes[qtype].LastUsedTimestamp = nowUnix
				if we.Rcode != dns.RcodeSuccess || we.Frequency > 1 {
					continue
				}

				if owe, exist := owes[qtype]; exist && owe.LastUsedTimestamp != 0 {
					wes[qtype].LastUsedTimestamp = owe.LastUsedTimestamp
				}
			}
		}
	}

	return nil
}
