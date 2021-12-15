package configx

import (
	"encoding/json"
	"errors"
	"fmt"
	"gnamed/libnamed"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

type CachePolicyType string

var (
	// cache.policy
	CachePolicyRepectTtl = "respectTtl" // respect dns protocol's ttl
	CachePolicyStableTtl = "stableTtl"  // stable ttl in configuration file
	defaultCachePolity   = CachePolicyRepectTtl

	// QueryList Type
	QueryListTypeEqual  = "Equal"
	QueryListTypePrefix = "Prefix"
	QueryListTypeSuffix = "Suffix"
	QueryListTypeRegexp = "Regexp"
)

type Config struct {
	singleflightGroup *libnamed.Group `json:"-"`
	Server            Server          `json:"server"`
	Query             Query           `json:"query"`
	Admin             Admin           `json:"admin"`
	Files             Files           `json:"files"`
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
	TlsConfig TlsConfig `json:"tls_config"`
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

const DOHMsgTypeRFC8484 DOHMsgType = "RFC8484"
const DOHMsgTypeJSON DOHMsgType = "JSON"

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
	// TODO: additional check
	if !verifyViewNameServerTag(&cfg.Server) {
		return cfg, errors.New("some View's has invalid nameserver_tag")
	}

	// view -> FQDN
	for _vk, _vv := range cfg.Server.View {
		if _vv.Cname != "" {
			_vv.Cname = dns.Fqdn(_vv.Cname)
		}
		_vkFqdn := dns.Fqdn(_vk)
		if _vkFqdn != _vk {
			delete(cfg.Server.View, _vk)
		}
		cfg.Server.View[_vkFqdn] = _vv
	}
	for _i, _ := range cfg.Server.Hosts {
		cfg.Server.Hosts[_i].Name = dns.Fqdn(cfg.Server.Hosts[_i].Name)
	}

	cfg.Server.Main.verify()
	if cfg.Server.Main.Singleflight {
		cfg.singleflightGroup = new(libnamed.Group)
	}

	fqdnQueryList(cfg.Query.BlackList)
	fqdnQueryList(cfg.Query.WhiteList)

	compileQueryRegexp(cfg.Query.BlackList)
	compileQueryRegexp(cfg.Query.WhiteList)

	contructQueryList(cfg.Query.BlackList)
	contructQueryList(cfg.Query.WhiteList)

	return cfg, err
}

func (cfg *Config) GetSingleFlightGroup() *libnamed.Group {
	return cfg.singleflightGroup
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
			fmt.Fprintf(os.Stderr, "[+] invalid timeout: '%s', error: '%v'\n", s, err)
		}
	}
	if d, err := time.ParseDuration(t.Connect); err == nil {
		t.ConnectDuration = d
	} else {
		_logFunc(t.Connect, err)
		t.ConnectDuration = DefaultQueryTimeoutDurationConnect
	}
	if d, err := time.ParseDuration(t.Read); err == nil {
		t.ReadDuration = d
	} else {
		_logFunc(t.Read, err)
		t.ReadDuration = DefaultQueryTimeoutDurationRead
	}
	if d, err := time.ParseDuration(t.Write); err == nil {
		t.WriteDuration = d
	} else {
		_logFunc(t.Write, err)
		t.WriteDuration = DefaultQueryTimeoutDurationWrite
	}
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

func (srv *Server) FindNameServer(name string) (string, *NameServer) {
	idx := 0
	cnames := 0
	for {
		if _vi, _found := srv.View[name[idx:]]; _found {
			if cnames < MaxCnameCounts && _vi.Cname != "" && name != _vi.Cname {
				cnames++
				name = _vi.Cname
				idx = 0
				continue
			}
			if _vi.ResolveType == ResolveTypeLocal {
				return "", nil
			}
			if _dns, _found := srv.NameServer[_vi.NameServerTag]; _found {
				return _vi.NameServerTag, &_dns
			}
			return "", nil
		} else if len(name[idx:]) == 1 {
			break
		}
		idx1 := strings.Index(name[idx:], ".")
		if idx < 0 {
			break
		}
		idx += idx1
		if len(name[idx:]) != 1 {
			idx++
		}
	}
	return "", nil
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
		return QueryListTypePrefix, rule, found
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
			return "Contain", _contain, true
		}
	}
	for _, _regexp := range ql.regexp {
		if _regexp.MatchString(name) {
			return "Regexp", _regexp.String(), true
		}
	}
	return "", "", false
}

// Deprecated
func (ql *QueryList) MatchDeprecated(name string) (string, string, bool) {
	for _, _equal := range ql.Equal {
		if name == _equal {
			return "Equal", _equal, true
		}
	}
	for _, _prefix := range ql.Prefix {
		if strings.HasPrefix(name, _prefix) {
			return "Prefix", _prefix, true
		}
	}
	for _, _suffix := range ql.Suffix {
		if strings.HasSuffix(name, _suffix) {
			return "Suffix", _suffix, true
		}
	}
	for _, _contain := range ql.Contain {
		if strings.Contains(name, _contain) {
			return "Contain", _contain, true
		}
	}
	for _, _regexp := range ql.regexp {
		if _regexp.MatchString(name) {
			return "Regexp", _regexp.String(), true
		}
	}
	return "", "", false
}
