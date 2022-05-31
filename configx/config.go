package configx

import (
	"encoding/json"
	"errors"
	"fmt"
	"gnamed/libnamed"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

type CachePolicyType string

var (

	// QueryList Type
	QueryListTypeEqual   = "Equal"
	QueryListTypePrefix  = "Prefix"
	QueryListTypeSuffix  = "Suffix"
	QueryListTypeContain = "Contain"
	QueryListTypeRegexp  = "Regexp"
)

type Config struct {
	filename           string            `json:"-"` // current using configuration file name
	timestamp          time.Time         `json:"-"` // configuration file parse timestamp
	lock               *sync.Mutex       `json:"-"` // internal use, lazy init some values
	singleflightGroups []*libnamed.Group `json:"-"` // max size 1<<16
	Server             Server            `json:"server"`
	Query              Query             `json:"query"`
	Admin              Admin             `json:"admin"`
	Files              Files             `json:"files"`
}

type Server struct {
	Main       Main                  `json:"main"`
	Listen     []Listen              `json:"listen"`
	NameServer map[string]NameServer `json:"nameserver"`
	View       map[string]View       `json:"view"`
	Hosts      []Host                `json:"hosts"`
	Cache      Cache                 `json:"cache"`
}

type Main struct {
	// console://
	// file:/path/log
	// tcp:127.0.0.1:12345
	// udp:127.0.0.1:12345
	// unix:/path/syslog.socket
	LogFile  string `json:"logFile"`
	LogLevel string `json:"logLevel"`

	Singleflight bool `json:"singleflight"`
}

// Server -> Listen
type Listen struct {
	Addr      string    `json:"addr"`
	Network   string    `json:"network"`
	Protocol  string    `json:"protocol"`
	DohPath   string    `json:"doh_path"` // doh path, default "/dns-query"
	TlsConfig TlsConfig `json:"tls_config"`
	Timeout   Timeout   `json:"timeout"`
}

type TlsConfig struct {
	ServerName string `json:"serverName"`

	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// Server -> NameServer
type NameServer struct {
	Protocol string    `json:"protocol"`
	Dns      DODServer `json:"dns,omitempty"`
	DoT      DOTServer `json:"dot,omitempty"`
	DoH      DOHServer `json:"doh,omitempty"`
}

type DODServer struct {
	Server  string  `json:"server"`
	Timeout Timeout `json:"timeout"`
	DnsOpt  DnsOpt  `json:"dns_opt"`
}

type DOHMsgType string

const (
	DOHMsgTypeRFC8484          DOHMsgType = "RFC8484"
	DOHMsgTypeJSON             DOHMsgType = "JSON"
	DOHAccetpHeaderTypeRFC8484            = "application/dns-message"
	DOHAcceptHeaderTypeJSON               = "application/dns-json"
)

type DOHServer struct {
	Url     string              `json:"url"`
	Method  string              `json:"method"`
	Headers map[string][]string `json:"headers"`
	Format  DOHMsgType          `json:"format"`

	// if "Server" not a ip address, use this nameservers to resolve domain
	ExternalNameServers []string `json:"externalNameServers"`

	TlsConfig TlsConfig `json:"tls_config"`
	Timeout   Timeout   `json:"timeout"`
	DnsOpt    DnsOpt    `json:"dns_opt"`
}

type DOTServer struct {
	Server string `json:"server"`
	Sni    string `json:"sni"`

	// if "Server" not a ip address, use this nameservers to resolve domain
	ExternalNameServers []string `json:"externalNameServers"`

	TlsConfig TlsConfig `json:"tls_config"`
	Timeout   Timeout   `json:"timeout"`
	DnsOpt    DnsOpt    `json:"dns_opt"`
}

type Timeout struct {
	Idle            string        `json:"idle"`
	IdleDuration    time.Duration `json:"-"`
	Connect         string        `json:"connect"`
	ConnectDuration time.Duration `json:"-"` // hidden field, ignore encode/decode
	Read            string        `json:"read"`
	ReadDuration    time.Duration `json:"-"`
	Write           string        `json:"write"`
	WriteDuration   time.Duration `json:"-"`
}

type DnsOpt struct {
	Dnssec       bool `json:"dnssec"`
	Ecs          bool `json:"ecs"`
	RandomDomain bool `json:"randomDomain"`
}

// Server -> View
type View struct {
	ResolveType   string `json:"resolve_type"`
	NameServerTag string `json:"nameserver_tag"`
	Cname         string `json:"cname"`
}

// Server -> Hosts
type Host struct {
	Name   string `json:"name"`
	Record string `json:"record"`
	Qtype  string `json:"qtype"`
}

// Server -> Cache
type Cache struct {
	Policy       string `json:"policy"`
	MaxTTL       uint32 `json:"maxTTL"`
	MinTTL       uint32 `json:"minTTL"`
	ScanInterval string `json:"scanInterval"`
	Mode         string `json:"mode"`
}

// Query
type Query struct {
	// qtype -> QueryList
	WhiteList map[string]QueryList `json:"whitelist"`
	BlackList map[string]QueryList `json:"blacklist"`
}

type QueryList struct {
	Equal      []string             `json:"equal"`
	equalMap   map[string]bool      `json:"-"`
	Prefix     []string             `json:"prefix"`
	prefixTrie *libnamed.PrefixTrie `json:"-"`
	Suffix     []string             `json:"suffix"`
	suffixTrie *libnamed.SuffixTrie `json:"-"`
	Contain    []string             `json:"contain"`
	Regexp     []string             `json:"regexp"`
	regexp     []*regexp.Regexp     `json:"-"`
}

// Admin
type Admin struct {
	Listen []Listen `json:"listen"`
	Auth   Auth     `json:"auth"`
}

type Auth struct {
	Cidr  []string          `json:"cidr"`
	Token map[string]string `json:"token"` // user:token
}

// Files
type Files struct {
	EcsIpList string
}

func ParseConfig(fname string) (Config, error) {
	return parseConfig(fname)
}
func parseConfig(fname string) (Config, error) {
	var cfg Config
	fbs, err := ioutil.ReadFile(fname)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(fbs, &cfg)
	if err != nil {
		return cfg, err
	}

	cfg.filename = fname
	cfg.timestamp = time.Now()

	for i := 0; i < len(cfg.Server.Listen); i++ {
		cfg.Server.Listen[i].parseListen()
	}
	// TODO: additional check
	if !verifyViewNameServerTag(&cfg.Server) {
		return cfg, errors.New("some View's has invalid nameserver_tag")
	}

	// view -> FQDN
	for vk, vv := range cfg.Server.View {
		if vv.Cname != "" {
			vv.Cname = dns.Fqdn(vv.Cname)
		}
		vkFqdn := dns.Fqdn(vk)
		if vkFqdn != vk {
			delete(cfg.Server.View, vk)
		}
		cfg.Server.View[vkFqdn] = vv
	}
	for i := 0; i < len(cfg.Server.Hosts); i++ {
		cfg.Server.Hosts[i].Name = dns.Fqdn(cfg.Server.Hosts[i].Name)
	}

	cfg.Server.Main.verify()
	if cfg.Server.Main.Singleflight {
		cfg.singleflightGroups = make([]*libnamed.Group, 1<<16)
		cfg.lock = new(sync.Mutex) // initialize global lock
	}

	// verify and defaulting cache configuration options

	verifyDefaultingCache(&cfg.Server.Cache)

	fqdnQueryList(cfg.Query.BlackList)
	fqdnQueryList(cfg.Query.WhiteList)

	compileQueryRegexp(cfg.Query.BlackList)
	compileQueryRegexp(cfg.Query.WhiteList)

	contructQueryList(cfg.Query.BlackList)
	contructQueryList(cfg.Query.WhiteList)

	// admin cidr
	for i := 0; i < len(cfg.Admin.Auth.Cidr); i++ {
		if j := strings.LastIndex(cfg.Admin.Auth.Cidr[i], "/"); j < 0 {
			cfg.Admin.Auth.Cidr[i] += "/32"
		}

		if _, _cidr, _err := net.ParseCIDR(cfg.Admin.Auth.Cidr[i]); _err == nil {
			cfg.Admin.Auth.Cidr[i] = _cidr.String()
		} else {
			fmt.Fprintf(os.Stderr, "[+] invalid cidr %s\n", cfg.Admin.Auth.Cidr[i])
			err = _err
		}
	}

	return cfg, err
}

func (cfg *Config) DumpJson() (string, error) {
	bs, err := json.MarshalIndent(cfg, "", "    ")
	return string(bs), err
}

func (cfg *Config) GetFileName() string {
	return cfg.filename
}

func (cfg *Config) GetTimestamp() time.Time {
	return cfg.timestamp
}

func verifyDefaultingCache(c *Cache) {
	if c.Mode == "" {
		c.Mode = CacheModeSkipList
	} else if c.Mode != CacheModeSkipList && c.Mode != CacheModeHashTable {
		fmt.Fprintf(os.Stderr, "[+] invalid cache mode '%s' not in %v\n", c.Mode, []string{CacheModeSkipList, CacheModeHashTable})
		panic(errors.New("invalid cache mode"))
	}
}

func (l *Listen) parseListen() {

	ip, port, err := net.SplitHostPort(l.Addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[+] listen addr '%s' invalid, error: '%s'\n", l.Addr, err)
		panic(err)
	}
	portInt, err := strconv.Atoi(port)
	if err != nil || portInt > 65536 || portInt <= 0 {
		panic(fmt.Errorf("listen addr '%s' has invalid port, error: '%s'", l.Addr, err))
	}
	if _ip := net.ParseIP(ip); _ip == nil {
		err := fmt.Errorf("listen addr '%s' invalid", l.Addr)
		panic(err)
	}
	switch l.Protocol {
	case ProtocolTypeDNS:
		switch l.Network {
		case NetworkTypeTcp, NetworkTypeUdp:
			//
		default:
			err := fmt.Errorf("listen addr '%s' protocol '%s' not compatible with '%s'", l.Addr, l.Protocol, l.Network)
			panic(err)
		}
	case ProtocolTypeDoH, ProtocolTypeDoT:
		switch l.Network {
		case NetworkTypeTcp:
			//
		default:
			err := fmt.Errorf("listen addr '%s' protocol '%s' not compatible with '%s'", l.Addr, l.Protocol, l.Network)
			panic(err)
		}
	default:
		err := fmt.Errorf("listen addr '%s' protocol '%s' not support", l.Addr, l.Protocol)
		panic(err)
	}
	l.Timeout.parseTimeout()
}

func (cfg *Config) GetSingleFlightGroup(qtype uint16) *libnamed.Group {
	if cfg.singleflightGroups[qtype] == nil {
		// need to make sure len(cfg.singleflightGroups) different values need to init once, so sync.Once not a good choice.
		// make sure value only inittialize once
		// make sure waiting concurrency caller get valid and correct value
		cfg.lock.Lock()
		if cfg.singleflightGroups[qtype] == nil {
			// double check
			cfg.singleflightGroups[qtype] = new(libnamed.Group)
		}
		cfg.lock.Unlock()
	}

	return cfg.singleflightGroups[qtype]
}

func (mf *Main) verify() bool {
	if mf.LogLevel == "" {
		mf.LogLevel = zerolog.DebugLevel.String()
	}
	return true
}

func (t *Timeout) parseTimeout() {
	_logFunc := func(s string, err error) {
		if s != "" && err != nil {
			fmt.Fprintf(os.Stderr, "[+] invalid timeout: '%s', error: '%v', set as default\n", s, err)
		}
	}

	setDuration := func(durationField *time.Duration, durationString string, defaultDuration time.Duration) {
		if d, err := time.ParseDuration(durationString); err == nil {
			*durationField = d
		} else {
			_logFunc(durationString, err)
			*durationField = defaultDuration
		}
	}

	setDuration(&t.IdleDuration, t.Idle, DefaultTimeoutDurationIdle)
	setDuration(&t.ConnectDuration, t.Connect, DefaultTimeoutDurationConnect)
	setDuration(&t.ReadDuration, t.Read, DefaultTimeoutDurationRead)
	setDuration(&t.WriteDuration, t.Write, DefaultTimeoutDurationWrite)
}

func verifyViewNameServerTag(srv *Server) bool {
	res := true
	for _zone, _vi := range srv.View {
		if _ns, _found := srv.NameServer[_vi.NameServerTag]; !_found {
			fmt.Fprintf(os.Stderr, "[+] View: '%s', nameserver_tag: '%s' not found.\n", _zone, _vi.NameServerTag)
			res = false
		} else {
			switch _ns.Protocol {
			case ProtocolTypeDNS:
				_ns.Dns.Timeout.parseTimeout()
			case ProtocolTypeDoH:
				_ns.DoH.Timeout.parseTimeout()
			case ProtocolTypeDoT:
				_ns.DoT.Timeout.parseTimeout()
			default:
				fmt.Fprintf(os.Stderr, "[+] Nameserver: '%s' use unsupport protocol '%s'\n", _vi.NameServerTag, _ns.Protocol)
			}
		}
	}
	return res
}

func contructQueryList(qm map[string]QueryList) {
	for _k, _v := range qm {
		for _, _rule := range _v.Equal {
			_v.equalMap[_rule] = true
		}
		_v.prefixTrie = libnamed.NewPrefixTrie(_v.Prefix)
		_v.suffixTrie = libnamed.NewSuffixTrie(_v.Suffix)
		qm[_k] = _v
	}
}

func fqdnQueryList(qm map[string]QueryList) {
	for _k, _v := range qm {
		for _i, _ := range _v.Equal {
			_v.Equal[_i] = dns.Fqdn(_v.Equal[_i])
		}
		for _i, _ := range _v.Suffix {
			_v.Suffix[_i] = dns.Fqdn(_v.Suffix[_i])
		}
		qm[_k] = _v
	}
}

func compileQueryRegexp(qm map[string]QueryList) {
	for _key, _ql := range qm {
		if len(_ql.Regexp) == 0 {
			continue
		}
		_ql.regexp = make([]*regexp.Regexp, len(_ql.Regexp))
		for _i, _regexp := range _ql.Regexp {
			_ql.regexp[_i] = regexp.MustCompile(_regexp)
		}
		qm[_key] = _ql
	}
}

// return (cname, vname), if cname exist, else name
func (srv *Server) FindRealName(name string) (string, string) {
	idx := 0
	for i := 0; i < MaxCnameCounts; i++ {
		if _vi, _found := srv.View[name[idx:]]; _found {
			if len(_vi.Cname) != 0 && name != _vi.Cname {
				name = _vi.Cname
				idx = 0
				continue
			} else {
				return name, name[idx:]
			}
		}

		idx = strings.Index(name[idx:], ".") + idx
		if idx != len(name)-1 {
			idx++
		}
	}
	return name, "."
}

// request domain should first call `FindRealName` to get vname (after cname loop if exist)
// vname was the last viewName, ignore rest cname event exist (alreay reach MaxCnameCounts)
func (srv *Server) FindViewNameServer(vname string) (string, *NameServer) {
	if vi, found := srv.View[vname]; found && vi.ResolveType != ResolveTypeLocal {
		if ns, exist := srv.NameServer[vi.NameServerTag]; exist {
			return vi.NameServerTag, &ns
		}
	}
	return "", nil
}

// input original name, not vname
func (srv *Server) FindNameServer(name string) (string, *NameServer) {
	_, vname := srv.FindRealName(name)
	return srv.FindViewNameServer(vname)
}

func (srv *Server) FindRecordFromHosts(name string, qtype string) (string, bool) {
	for _, _host := range srv.Hosts {
		if qtype == _host.Qtype && name == _host.Name {
			return _host.Record, true
		}
	}
	return "", false
}

// QueryList Match
func (q *Query) QueryForbidden(name string, qtype string) (string, string, bool) {
	if _r, _s, _found := q.MatchWhitlist(name, qtype); _found {
		return _r, _s, false
	}
	if _r, _s, _found := q.MatchBlacklist(name, qtype); _found {
		return _r, _s, true
	}
	return "", "", false
}

func (q *Query) MatchWhitlist(name string, qtype string) (string, string, bool) {
	if _ql, _found := q.WhiteList[qtype]; _found {
		return _ql.Match(name)
	}
	return "", "", false
}

func (q *Query) MatchBlacklist(name string, qtype string) (string, string, bool) {
	if _ql, _found := q.BlackList[qtype]; _found {
		return _ql.Match(name)
	}
	return "", "", false
}

func (ql *QueryList) Match(name string) (string, string, bool) {
	// O(1)
	if _, found := ql.equalMap[name]; found {
		return QueryListTypeEqual, name, true
	}
	// O(m)
	if rule, found := ql.suffixTrie.Query(name); found {
		return QueryListTypeSuffix, rule, found
	}
	// O(m)
	if rule, found := ql.prefixTrie.Query(name); found {
		return QueryListTypePrefix, rule, found
	}
	// len(ql.Contain) * O(avg(len(_contain)))
	// Optimization: Aho-Corasick or flashtext
	// flashtext https://arxiv.org/pdf/1711.00046.pdf
	for _, _contain := range ql.Contain {
		if strings.Contains(name, _contain) {
			return QueryListTypeContain, _contain, true
		}
	}
	// O(m) * O(len(_ql.regexp))
	for _, _regexp := range ql.regexp {
		if _regexp.MatchString(name) {
			return QueryListTypeRegexp, _regexp.String(), true
		}
	}
	return "", "", false
}
