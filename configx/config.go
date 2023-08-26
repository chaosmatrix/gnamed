package configx

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"gnamed/libnamed"
	"gnamed/runner"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"golang.org/x/net/idna"
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

type globalConfig struct {
	cfg  *Config
	lock *sync.Mutex
}

var _globalConfig = &globalConfig{}

func InitGlobalConfig(cfg *Config) {
	_globalConfig = &globalConfig{
		cfg:  cfg,
		lock: new(sync.Mutex),
	}
}

func UpdateGlobalConfig() error {

	// prevent update frequency
	if time.Since(_globalConfig.cfg.GetTimestamp()) < 10*time.Second {
		time.Sleep(10 * time.Second)
	}

	_globalConfig.lock.Lock()
	defer _globalConfig.lock.Unlock()

	fname := _globalConfig.cfg.GetFileName()
	cfg, err := ParseConfig(fname)
	if err != nil {
		return err
	}

	// update pointer rather than update pointer's value, to achive lock-free
	_globalConfig.cfg = cfg

	return err
}

func GetGlobalConfig() *Config {
	return _globalConfig.cfg
}

type Config struct {
	filename           string               `json:"-"` // current using configuration file name
	timestamp          time.Time            `json:"-"` // configuration file parse timestamp
	lock               sync.Mutex           `json:"-"` // internal use, lazy init some values
	singleflightGroups [][]*libnamed.Group  `json:"-"` // [QCLASS][QTYPE]*libnamed.Group max size 1<<16 * 1<<16
	Server             Server               `json:"server"`
	Query              Query                `json:"query"`
	Admin              Admin                `json:"admin"`
	Filter             *Filter              `json:"filter"` // filter
	FallBack           FallBack             `json:"fallback"`
	WarmRunnerInfo     *WarmRunnerInfo      `json:"warm"`
	RunnerOption       *runner.RunnerOption `json:"runner"`
}

type Server struct {
	Main       Main                  `json:"main"`
	Listen     []Listen              `json:"listen"`
	NameServer map[string]NameServer `json:"nameserver"`
	View       map[string]View       `json:"view"`
	Hosts      []Host                `json:"hosts"`
	RrCache    RrCache               `json:"cache"`
}

type Main struct {
	// console://
	// file:/path/log
	// tcp:127.0.0.1:12345
	// udp:127.0.0.1:12345
	// unix:/path/syslog.socket
	LogFile          string        `json:"logFile"`
	LogLevel         string        `json:"logLevel"`
	ShutdownTimeout  string        `json:"shutdown_timeout"`
	ShutdownDuration time.Duration `json:"-"`

	Singleflight bool `json:"singleflight"`
}

// Server -> Listen
type Listen struct {
	Addr           string    `json:"addr"`
	Network        string    `json:"network"`
	Protocol       string    `json:"protocol"`
	DohPath        string    `json:"doh_path"` // doh path, default "/dns-query"
	TlsConfig      TlsConfig `json:"tls_config"`
	Timeout        Timeout   `json:"timeout"`
	QueriesPerConn int       `json:"queriesPerConn"`
}

type SocketAttr struct {
	KeepAliveNum      int  `json:"keepaliveNum"` // golang not support ?
	KeepAliveInterval int  `json:"keepAliveInterval"`
	DisableNoDelay    bool `json:"disableNoDelay"` // default enable no delay (seed data immedialy)

	// because of Delay ACK (RFC1122, < 500ms, implementation < 200ms), server might not receive ack about dns respose,
	// (close) reset connection before Delay ACK send, might trigger some security rule cause client blocked by server
	CloseWithRst bool `json:"CloseWithRst"` // TCP-only, reset connection to prevent TIME_WAIT (may has previous instantiation problem)
}

type TlsConfig struct {
	ServerName         string `json:"serverName"`
	InsecureSkipVerify bool   `json:"insecure"`
	CertFile           string `json:"certFile"`
	KeyFile            string `json:"keyFile"`

	// KeyLogWriter - should not used in production
	// if not empty, all tls master secrets will be writen into this file,
	// which can be used to decrypt tls traffic with wireshark
	KeyLogFile string `json:"keyLogFile"`
}

// Server -> NameServer
type NameServer struct {
	Protocol string     `json:"protocol"`
	Dns      *DODServer `json:"dns,omitempty"`
	DoT      *DOTServer `json:"dot,omitempty"`
	DoH      *DOHServer `json:"doh,omitempty"`
	DoQ      *DOQServer `json:"doq,omitempty"`
}

type DODServer struct {
	Server  string `json:"server"`
	Network string `json:"network"`

	Timeout    Timeout         `json:"timeout"`
	Pool       *ConnectionPool `json:"pool"`
	SocketAttr *SocketAttr     `json:"socketAttr,omitempty"`

	// use internal
	ClientUDP         *dns.Client                     `json:"-"`
	ClientTCP         *dns.Client                     `json:"-"`
	ConnectionPoolTCP *libnamed.ConnectionPool        `json:"-"`
	NewConn           func(string) (*dns.Conn, error) `json:"-"`
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
	HTTP3   bool                `json:"http3"`

	// if "Server" not a ip address, use this nameservers to resolve domain
	ExternalNameServers []string `json:"externalNameServers"`

	TlsConfig  TlsConfig   `json:"tls_config"`
	Timeout    Timeout     `json:"timeout"`
	SocketAttr *SocketAttr `json:"socketAttr,omitempty"`

	// use internal
	client     *http.Client `json:"-"`
	altSvcOnce *sync.Once   `json:"-"`
}

type DOTServer struct {
	Server string          `json:"server"`
	Pool   *ConnectionPool `json:"pool"`

	// if "Server" not a ip address, use this nameservers to resolve domain
	ExternalNameServers []string `json:"externalNameServers"`

	TlsConfig  TlsConfig   `json:"tls_config"`
	Timeout    Timeout     `json:"timeout"`
	SocketAttr *SocketAttr `json:"socketAttr,omitempty"`

	// use internal
	Client         *dns.Client                     `json:"-"`
	ConnectionPool *libnamed.ConnectionPool        `json:"-"`
	NewConn        func(string) (*dns.Conn, error) `json:"-"`
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

type ConnectionPool struct {
	IdleTimeout         string        `json:"idleTimeout"`
	idleTimeoutDuration time.Duration `json:"-"`
	Size                int           `json:"size"`
	QueriesPerConn      int           `json:"queriesPerConn"`
}

// Server -> View
type View struct {
	ResolveType    string   `json:"resolve_type"`
	NameServerTag  string   `json:"nameserver_tag"` // deprecated
	NameServerTags []string `json:"nameserver_tags"`
	FallBackTags   []string `json:"FallBack_tags"`
	Cname          string   `json:"cname"`
	Dnssec         bool     `json:"dnssec"`
	Subnet         string   `json:"subnet"`

	// TODO: avaliable for more than one avaliable nameservers
	//QuerySerial bool `json:"query_parallel"` // parallel query all nameservers, default true
	//MergeResult bool `json:"merge_result"` // wait all queries return then merge result or return first valid response, default false

	// sometimes can be used to prevent dns hijacking when using dns-over-plain-udp protocol
	RandomDomain bool `json:"random_domain"` // random Upper/Lower domain's chars

	// rfc: https://www.ietf.org/archive/id/draft-ietf-dnsop-svcb-https-10.html
	// WARNING: browser makes A/AAAA and HTTPS record concurrency, only work when HTTPS responsed before A/AAAA
	RrHTTPS *RrHTTPS `json:"rr_https"`

	// cache
	//RrCache *RrCache `json:"rr_cache"` // view's cache

	// internal: edns-client-subnet, parse from Subnet
	EcsFamily  uint16 `json:"-"` // 1: ipv4, 2: ipv6
	EcsAddress net.IP `json:"-"`
	EcsNetMask uint8  `json:"-"`
}

// HTTPS RRSet setting
type RrHTTPS struct {
	Priority uint16   `json:"priority"`
	Target   string   `json:"target"`
	Alpn     []string `json:"alpn"`
	Hijack   bool     `json:"hijack"` // QType HTTPS will be hijacked with configured
}

// RR Cache
type RrCache struct {
	MaxTTL               uint32  `json:"maxTTL"`
	MinTTL               uint32  `json:"minTTL"`
	NxMaxTtl             uint32  `json:"nxMaxTtl"` // TTL for NXDOMAIN
	NxMinTtl             uint32  `json:"nxMinTtl"`
	ErrTtl               uint32  `json:"errTTL"` // TTL for not NXDomain ERROR
	Mode                 string  `json:"mode"`
	UseSteal             bool    `json:"useSteal"`             // use steal cache, when element expired, return and trigger background query
	BackgroundUpdate     bool    `json:"backGroundUpdate"`     // true if BackgroundUpdate || UseSteal || BeforeExpiredSecond != 0 || BeforeExpiredPercent != 0
	BeforeExpiredSecond  int64   `json:"beforeExpiredSecond"`  // time.Now().Unix() >= expired - BeforeExpiredSecond, enable background query
	BeforeExpiredPercent float64 `json:"beforeExpiredPercent"` // time.Now().Unix() >= expired - ttl * BeforeExpiredPercent, enable background query

	// internal use
	backgroundQueryMap *sync.Map `json:"-"`
}

// Server -> Hosts
type Host struct {
	Name   string `json:"name"`
	Record string `json:"record"`
	Qtype  string `json:"qtype"`
}

// Query
type Query struct {
	// qtype -> QueryList
	WhiteList map[string]QueryList `json:"whitelist"`
	BlackList map[string]QueryList `json:"blacklist"`
}

type QueryList struct {
	Equal      []string             `json:"equal"`
	equalMap   map[string]struct{}  `json:"-"`
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

func (c *TlsConfig) parse() (*tls.Config, error) {
	tlsc := &tls.Config{
		InsecureSkipVerify: c.InsecureSkipVerify,
		ServerName:         c.ServerName,
	}
	if c.CertFile != "" && c.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return tlsc, err
		}
		tlsc.Certificates = []tls.Certificate{cert}
	}

	if c.KeyLogFile != "" {
		fw, err := os.OpenFile(c.KeyLogFile, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
		if err != nil {
			return tlsc, err
		}
		tlsc.KeyLogWriter = fw
	}

	scs := tls.CipherSuites()
	cs := make([]uint16, len(scs))
	for i, sc := range scs {
		cs[i] = sc.ID
	}

	// default include Two InsecureCipherSuites:
	// 1. TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)
	// 2. TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)
	//
	// limitation of built-in "tls" setting CipherSuites:
	// 1. unable to change the order of CipherSuites for outgoing packet (there is a sorted rule)
	// 2. tls1.3 only CipherSuites always included for tls1.3
	// 3. able to select part of CipherSuites and InsecureCipherSuites
	// 4. unable to change the CipherSuites of quic-tls1.3, it's tls1.3 only CipherSuites
	//
	// buiilt-in "tls" didn't support change the order of CipherSuites, the order can be used as a fingerprint
	// if want to change the order, use the 3rd-party lib "uTLS" instead
	tlsc.CipherSuites = cs

	return tlsc, nil
}

func ParseConfig(fname string) (*Config, error) {
	return parseConfig(fname)
}

func parseConfig(fname string) (*Config, error) {
	cfg := new(Config)
	fbs, err := os.ReadFile(fname)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(fbs, cfg)
	if err != nil {
		return cfg, err
	}

	cfg.filename = fname
	cfg.timestamp = time.Now()

	for i := 0; i < len(cfg.Server.Listen); i++ {
		if err = cfg.Server.Listen[i].parse(); err != nil {
			return cfg, err
		}
	}

	if err = cfg.Server.parse(); err != nil {
		return cfg, err
	}

	// view -> FQDN
	// default view "." must exist
	if _, found := cfg.Server.View["."]; !found {
		return cfg, fmt.Errorf("default view \".\" not exist")
	}
	for vk, vv := range cfg.Server.View {
		if err = (&vv).parse(); err != nil {
			return cfg, err
		}

		vkp := ""
		vkp, err = idna.ToASCII(vk)
		if err != nil || len(vk) == 0 {
			fmt.Fprintf(os.Stderr, "[+] can't convert view name %s into punnycode\n", vk)
			continue
		}

		vkFqdn := dns.Fqdn(vkp)
		if vkFqdn != vk {
			delete(cfg.Server.View, vk)
		}
		cfg.Server.View[vkFqdn] = vv
	}

	for i := 0; i < len(cfg.Server.Hosts); i++ {
		hpny := ""
		hpny, err = idna.ToASCII(cfg.Server.Hosts[i].Name)
		if err != nil || len(hpny) == 0 {
			continue
		}
		cfg.Server.Hosts[i].Name = dns.Fqdn(hpny)
	}

	if err = cfg.Server.Main.parse(); err != nil {
		return cfg, err
	}

	if cfg.Server.Main.Singleflight {
		// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
		// [1<<16][1<<16]*libnamed.Group
		// empty singleflightGroups memory usage: 65536 * sizeof(uintptr) = 65536 * 8 byte = 0.5MB
		cfg.singleflightGroups = make([][]*libnamed.Group, math.MaxUint16+1)
	}

	// verify and defaulting cache configuration options
	if err = cfg.Server.RrCache.parse(); err != nil {
		return cfg, err
	}

	if err = cfg.Query.parse(); err != nil {
		return cfg, err
	}

	// admin cidr
	for i := 0; i < len(cfg.Admin.Auth.Cidr); i++ {
		if j := strings.LastIndex(cfg.Admin.Auth.Cidr[i], "/"); j < 0 {
			cfg.Admin.Auth.Cidr[i] += "/32"
		}

		var cidr *net.IPNet
		if _, cidr, err = net.ParseCIDR(cfg.Admin.Auth.Cidr[i]); err == nil {
			cfg.Admin.Auth.Cidr[i] = cidr.String()
		} else {
			fmt.Fprintf(os.Stderr, "[+] invalid cidr %s\n", cfg.Admin.Auth.Cidr[i])
		}
	}

	// filter
	if cfg.Filter == nil {
		cfg.Filter = new(Filter)
	}
	if err = cfg.Filter.parse(); err != nil {
		return cfg, err
	}

	// warm runner
	if cfg.WarmRunnerInfo == nil {
		cfg.WarmRunnerInfo = new(WarmRunnerInfo)
	}
	if err = cfg.WarmRunnerInfo.parse(); err != nil {
		return cfg, err
	}
	if cfg.WarmRunnerInfo.NameServerUDP == "" {
		for _, ln := range cfg.Server.Listen {
			if ln.Protocol == ProtocolTypeDNS && (ln.Network == "udp" || ln.Network == "udp6") {
				cfg.WarmRunnerInfo.NameServerUDP = ln.Addr
				break
			}
		}
	}

	// runner
	if cfg.RunnerOption == nil {
		cfg.RunnerOption = new(runner.RunnerOption)
	}
	if err = cfg.RunnerOption.Parse(); err != nil {
		return cfg, err
	}

	if err == nil {
		InitGlobalConfig(cfg)
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

func (v *View) parse() error {

	if v.Cname != "" {
		v.Cname = dns.Fqdn(v.Cname)
	}

	if v.Subnet != "" {
		subnet := v.Subnet

		if !strings.Contains(subnet, "/") {
			if strings.Contains(subnet, ":") {
				subnet += "/128"
			} else {
				subnet += "/32"
			}
		}

		_, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			return fmt.Errorf("invalid subNet \"%s\"", v.Subnet)
		}

		ones, bits := ipNet.Mask.Size()
		if bits == net.IPv4len*8 {
			v.EcsAddress = ipNet.IP.To4()
			v.EcsFamily = defaultEcsFamilyIPv4
		} else {
			v.EcsAddress = ipNet.IP.To16()
			v.EcsFamily = defaultEcsFamilyIPv6
		}
		v.EcsNetMask = uint8(ones)
	}

	// RrHTTPS
	if v.RrHTTPS != nil {
		// rules:
		// 1. priority == 0 is AliasMode, and must has Target set
		// 2. if alpn not empty, priority isn't AliasMode, and vice verse
		if (len(v.RrHTTPS.Target) == 0 || len(v.RrHTTPS.Alpn) > 0) && v.RrHTTPS.Priority <= 0 {
			v.RrHTTPS.Priority = 1
		}

		if v.RrHTTPS.Priority > 0 && len(v.RrHTTPS.Alpn) == 0 {
			v.RrHTTPS.Alpn = defaultRrHTTPSAlpn
		}

		v.RrHTTPS.Target = dns.Fqdn(v.RrHTTPS.Target)
	}

	return nil
}

func (c *RrCache) parse() error {
	if c.Mode == "" {
		c.Mode = CacheModeSkipList
	} else if c.Mode != CacheModeSkipList && c.Mode != CacheModeHashTable {
		fmt.Fprintf(os.Stderr, "[+] invalid cache mode '%s' not in %v\n", c.Mode, []string{CacheModeSkipList, CacheModeHashTable})
		return fmt.Errorf("invalid cache mode '%s'", c.Mode)
	}

	if c.MinTTL > c.MaxTTL {
		fmt.Fprintf(os.Stderr, "[+] invalid MinTTL %d and MaxTTL %d\n", c.MinTTL, c.MaxTTL)
		return fmt.Errorf("invalid MinTTL %d and MaxTTL %d", c.MinTTL, c.MaxTTL)
	}

	if c.NxMinTtl > c.NxMaxTtl {
		fmt.Fprintf(os.Stderr, "[+] invalid NxMinTtl %d and NxMaxTtl %d\n", c.NxMinTtl, c.NxMaxTtl)
		return fmt.Errorf("invalid NxMinTtl %d and NxMaxTtl %d", c.NxMinTtl, c.NxMaxTtl)
	}

	if c.ErrTtl == 0 {
		c.ErrTtl = 60
	}

	if c.BeforeExpiredSecond >= int64(c.MaxTTL) {
		fmt.Fprintf(os.Stderr, "[+] beforeExpiredSecond %d >= MaxTTL %d, do background query every time when cache hit\n", c.BeforeExpiredSecond, c.MaxTTL)
	}

	if c.BeforeExpiredSecond < 0 {
		return fmt.Errorf("invalid beforeExpiredSecond %d < 0", c.BeforeExpiredSecond)
	}

	if c.BeforeExpiredPercent == 1 {
		fmt.Fprintf(os.Stderr, "[+] beforeExpiredPercent %f, do background query every time when cache hit\n", c.BeforeExpiredPercent)
	}

	if c.BeforeExpiredPercent > 1 || c.BeforeExpiredPercent < 0 {
		return fmt.Errorf("invalid beforeExpiredSecond %f, not between [0, 1.0]", c.BeforeExpiredPercent)
	}

	c.BackgroundUpdate = c.BackgroundUpdate || c.UseSteal || (c.BeforeExpiredSecond > 0) || (c.BeforeExpiredPercent > 0 || c.BeforeExpiredPercent <= 1)

	if c.BackgroundUpdate {
		c.backgroundQueryMap = new(sync.Map)
	}

	return nil
}

// try to get lock about key
// return false, if key already locked, else return true and lock the key
func (c *RrCache) BackgroundQueryTryLock(key string) bool {
	_, loaded := c.backgroundQueryMap.LoadOrStore(key, true)
	return !loaded
}

func (c *RrCache) BackgroundQueryUnlock(key string) {
	c.backgroundQueryMap.Delete(key)
}

func (l *Listen) parse() error {

	ip, port, err := net.SplitHostPort(l.Addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[+] listen addr '%s' invalid, error: '%s'\n", l.Addr, err)
		return err
	}
	portInt, err := strconv.Atoi(port)
	if err != nil || portInt > 65536 || portInt <= 0 {
		return fmt.Errorf("listen addr '%s' has invalid port, error: '%s'", l.Addr, err)
	}
	if _ip := net.ParseIP(ip); _ip == nil {
		return fmt.Errorf("listen addr '%s' invalid", l.Addr)
	}

	if l.QueriesPerConn < 0 {
		return fmt.Errorf("queriesPerConn %d < 0", l.QueriesPerConn)
	} else if l.QueriesPerConn == 0 {
		l.QueriesPerConn = 1
	}

	return l.Timeout.parse()
}

func (cfg *Config) GetSingleFlightGroup(qclass uint16, qtype uint16) *libnamed.Group {
	// lazy initialize
	if len(cfg.singleflightGroups[qclass]) == 0 {
		cfg.lock.Lock()
		if len(cfg.singleflightGroups[qclass]) == 0 {
			cfg.singleflightGroups[qclass] = make([]*libnamed.Group, math.MaxUint16+1)
			cfg.singleflightGroups[qclass][qtype] = new(libnamed.Group)
		}
		cfg.lock.Unlock()
	}

	// if more than two caller with same qclass, but different qtype, only one qclass&qtype will be initialize,
	// so, need to check again to make sure all qclass&qtype has been initiallized.
	if cfg.singleflightGroups[qclass][qtype] == nil {
		// need to make sure len(cfg.singleflightGroups) different values need to init once, so sync.Once not a good choice.
		// make sure value only inittialize once
		// make sure waiting concurrency caller get valid and correct value
		cfg.lock.Lock()
		if cfg.singleflightGroups[qclass][qtype] == nil {
			// double check
			cfg.singleflightGroups[qclass][qtype] = new(libnamed.Group)
		}
		cfg.lock.Unlock()
	}

	return cfg.singleflightGroups[qclass][qtype]
}

func (mf *Main) parse() error {
	if mf.LogLevel == "" {
		mf.LogLevel = zerolog.DebugLevel.String()
	}
	if mf.ShutdownTimeout == "" {
		mf.ShutdownDuration = 60 * time.Second
	} else {
		if t, err := time.ParseDuration(mf.ShutdownTimeout); err == nil {
			mf.ShutdownDuration = t
		} else {
			return err
		}
	}
	return nil
}

func (t *Timeout) parse() error {
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

	setDuration(&t.IdleDuration, t.Idle, defaultTimeoutDurationIdle)
	setDuration(&t.ConnectDuration, t.Connect, defaultTimeoutDurationConnect)
	setDuration(&t.ReadDuration, t.Read, defaultTimeoutDurationRead)
	setDuration(&t.WriteDuration, t.Write, defaultTimeoutDurationWrite)

	return nil
}

func setTCPSocketOpt(conn *net.Conn, socketAttr *SocketAttr) error {
	if socketAttr == nil {
		return nil
	}

	tcpConn, ok := (*conn).(*net.TCPConn)
	if !ok {
		return errors.New("invalid TCP socket")
	}
	var err error
	if socketAttr.CloseWithRst {
		err = tcpConn.SetLinger(0)
		if err != nil {
			return err
		}
	}

	// default golang enable TCP-KeepAlive and use system's parameter
	if socketAttr.KeepAliveInterval > 0 {
		err = tcpConn.SetKeepAlive(true)
		if err != nil {
			return err
		}
		err = tcpConn.SetKeepAlivePeriod(time.Duration(socketAttr.KeepAliveInterval) * time.Second)
		if err != nil {
			return err
		}
	} else if socketAttr.KeepAliveInterval < 0 || socketAttr.KeepAliveNum < 0 {
		err = tcpConn.SetKeepAlive(false)
		if err != nil {
			return err
		}
	}

	if socketAttr.DisableNoDelay {
		err = tcpConn.SetNoDelay(false)
		if err != nil {
			return err
		}
	}
	return err
}

func newDnsConnection(client *dns.Client, socketAttr *SocketAttr, addr string, network string) (*dns.Conn, error) {
	if network == "udp" || socketAttr == nil {
		return client.Dial(addr)
	}
	// tcp or tcp-tls
	conn, err := client.Dial(addr)
	if err != nil {
		return nil, err
	}
	err = setTCPSocketOpt(&conn.Conn, socketAttr)
	if err != nil {
		return conn, err
	}

	return conn, err
}

func (cp *ConnectionPool) parse() error {
	if cp == nil {
		return errors.New("invalid connection pool config")
	}

	if cp.Size == 0 {
		cp.Size = defaultPoolSize
	}

	if cp.QueriesPerConn == 0 {
		cp.QueriesPerConn = defaultPoolQueriesPerConn
	}

	if cp.IdleTimeout == "" {
		cp.idleTimeoutDuration = defaultPoolIdleTimeoutDuration
	} else {
		if d, err := time.ParseDuration(cp.IdleTimeout); err != nil {
			return err
		} else {
			cp.idleTimeoutDuration = d
		}
	}

	return nil
}

func (srv *Server) parse() error {
	res := true

	// verify using nameserverTag valid
	for zone, vi := range srv.View {

		// compitable with old configuration
		if len(vi.NameServerTags) == 0 && len(vi.NameServerTag) != 0 {
			vi.NameServerTags = []string{vi.NameServerTag}
			srv.View[zone] = vi
		}

		for _, nameserverTag := range vi.NameServerTags {
			if ns, found := srv.NameServer[nameserverTag]; !found {
				fmt.Fprintf(os.Stderr, "[+] View: '%s', nameserver_tag: '%s' not found.\n", zone, nameserverTag)
				res = false
			} else {
				var err error

				switch ns.Protocol {
				case ProtocolTypeDNS:
					err = ns.Dns.parse()
				case ProtocolTypeDoH:
					err = ns.DoH.parse()
				case ProtocolTypeDoT:
					err = ns.DoT.parse()
				case ProtocolTypeDoQ:
					err = ns.DoQ.parse()
				default:
					fmt.Fprintf(os.Stderr, "[+] Nameserver: '%s' use unsupport protocol '%s'\n", nameserverTag, ns.Protocol)
					res = false
				}

				if err != nil {
					fmt.Fprintf(os.Stderr, "[+] Nameserver: '%s', parse failed, error: %v\n", nameserverTag, err)
					res = false
				}
				srv.NameServer[nameserverTag] = ns
			}
		}
	}
	if res {
		return nil
	}
	return errors.New("some View's has invalid nameserver_tag")
}

func (dod *DODServer) parse() error {

	errInvalidServer := fmt.Errorf("invalid dns server address '%s'", dod.Server)
	host, portStr, err := net.SplitHostPort(dod.Server)
	if err != nil {
		host = dod.Server
		dod.Server = net.JoinHostPort(dod.Server, strconv.Itoa(defaultPortDns))
	} else {
		if port, err := strconv.Atoi(portStr); err != nil || port < 0 || port > 65535 {
			return errInvalidServer
		}
	}

	if net.ParseIP(host) == nil {
		return errInvalidServer
	}

	dod.Timeout.parse()

	if dod.Network == "" {
		dod.Network = "udp" // default
	}

	if dod.Network != "udp" && dod.Network != "tcp" {
		return fmt.Errorf("invalid dns network '%s', only 'udp' or 'tcp' allow", dod.Network)
	}

	if dod.Network == "udp" {
		dod.ClientUDP = &dns.Client{
			// Default buffer size to use to read incoming UDP message
			// default 512 B
			// must increase if edns-client-sub enable
			UDPSize:      1280,
			Net:          "udp",
			DialTimeout:  dod.Timeout.ConnectDuration,
			ReadTimeout:  dod.Timeout.ReadDuration,
			WriteTimeout: dod.Timeout.WriteDuration,
			//SingleInflight: true,
		}
	}

	dod.ClientTCP = &dns.Client{
		// Default buffer size to use to read incoming UDP message
		// default 512 B
		// must increase if edns-client-sub enable
		UDPSize:      1280,
		Net:          "tcp",
		DialTimeout:  dod.Timeout.ConnectDuration,
		ReadTimeout:  dod.Timeout.ReadDuration,
		WriteTimeout: dod.Timeout.WriteDuration,
		//SingleInflight: true,
	}

	dod.NewConn = func(network string) (*dns.Conn, error) {
		if network == "udp" {
			return newDnsConnection(dod.ClientUDP, dod.SocketAttr, dod.Server, network)
		} else {
			return newDnsConnection(dod.ClientTCP, dod.SocketAttr, dod.Server, network)
		}
	}

	if dod.Network == "tcp" && dod.Pool != nil {
		if err := dod.Pool.parse(); err != nil {
			return err
		}
		// only tcp enable connection pool
		cpf := &libnamed.ConnectionPool{
			MaxConn: dod.Pool.Size,
			MaxReqs: dod.Pool.QueriesPerConn,
			NewConn: func() (*dns.Conn, error) {
				return dod.NewConn("tcp")
			},
			CloseConn: func(conn *dns.Conn) error {
				if conn == nil {
					return nil
				}
				return conn.Close()
			},
			IdleTimeout: dod.Pool.idleTimeoutDuration,
		}
		cpt, err := libnamed.NewConnectionPool(cpf)
		if err != nil {
			return err
		}
		dod.ConnectionPoolTCP = cpt
	}
	return nil
}

func (doh *DOHServer) parse() error {
	errInvalidServer := fmt.Errorf("invalid dns-over-https server address '%s'", doh.Url)

	// process header
	for hk, hm := range doh.Headers {
		hkc := http.CanonicalHeaderKey(hk)
		if hkc != hk {
			delete(doh.Headers, hk)
			doh.Headers[hkc] = hm
		}
	}

	urlStruct, err := url.Parse(doh.Url)
	if err != nil || (urlStruct.Scheme != "http" && urlStruct.Scheme != "https") {
		return errInvalidServer
	}

	host, portStr := urlStruct.Hostname(), urlStruct.Port()
	if portStr != "" {
		if port, err := strconv.Atoi(portStr); err != nil || port < 0 || port > 65535 {
			return errInvalidServer
		}
	}

	if doh.TlsConfig.ServerName == "" {
		doh.TlsConfig.ServerName = strings.ToLower(strings.TrimSuffix(host, "."))
	}

	if net.ParseIP(host) == nil {
		if _, found := doh.Headers["Host"]; !found {
			doh.Headers["Host"] = []string{host}
		}

		qname := dns.Fqdn(host)
		addr := ""
		if libnamed.ValidateDomain(qname) {
			addr = lookupIP(qname, doh.ExternalNameServers)
		}

		if addr == "" {
			return fmt.Errorf("server '%s' no valid ip address found", doh.Url)
		}

		if portStr != "" {
			urlStruct.Host = net.JoinHostPort(addr, portStr)
		} else {
			urlStruct.Host = addr
		}

		doh.Url = urlStruct.String()
	}

	doh.Timeout.parse()

	doh.altSvcOnce = &sync.Once{}

	doh.initDoHClient()
	return nil
}

// FIXME: dot.Server was a config file, should not be change.
func (dot *DOTServer) parse() error {
	server, host, err := parseServer(dot.Server, dot.ExternalNameServers, defaultPortDoT)
	if err != nil {
		return err
	}
	dot.Server = server

	tlsc, err := dot.TlsConfig.parse()
	if err != nil {
		return err
	}
	if tlsc.ServerName == "" {
		tlsc.ServerName = strings.ToLower(host)
	}

	dot.Timeout.parse()

	dot.Client = &dns.Client{
		Net:          "tcp-tls",
		UDPSize:      1280,
		TLSConfig:    tlsc,
		DialTimeout:  dot.Timeout.ConnectDuration,
		ReadTimeout:  dot.Timeout.ReadDuration,
		WriteTimeout: dot.Timeout.WriteDuration,
		//SingleInflight: true,
	}

	dot.NewConn = func(network string) (*dns.Conn, error) {
		return newDnsConnection(dot.Client, dot.SocketAttr, dot.Server, dot.Client.Net)
	}

	if dot.Pool != nil {
		if err := dot.Pool.parse(); err != nil {
			return err
		}
		cpf := &libnamed.ConnectionPool{
			MaxConn: dot.Pool.Size,
			MaxReqs: dot.Pool.QueriesPerConn,
			NewConn: func() (*dns.Conn, error) {
				return dot.NewConn("tcp-tls")
			},
			CloseConn: func(conn *dns.Conn) error {
				if conn == nil {
					return nil
				}
				return conn.Close()
			},
			IdleTimeout: dot.Pool.idleTimeoutDuration,
		}
		cpt, err := libnamed.NewConnectionPool(cpf)
		if err != nil {
			return err
		}
		dot.ConnectionPool = cpt
	}
	return nil
}

func parseServer(server string, nameservers []string, defaultPort int) (string, string, error) {

	host, port, err := net.SplitHostPort(server)
	if err != nil {
		host = server
		port = strconv.Itoa(defaultPort)
		server = net.JoinHostPort(server, port)
	}

	if net.ParseIP(host) == nil {
		if libnamed.ValidateDomain(host) {
			addr := lookupIP(dns.Fqdn(host), nameservers)
			if len(addr) == 0 {
				return server, host, fmt.Errorf("server '%s' no valid ip address found", server)
			}
			server = net.JoinHostPort(addr, port)
		}
	}

	return server, host, err
}

func lookupIP(name string, nameservers []string) string {
	nss := nameservers
	if len(nss) == 0 {
		nss = defaultExternalNameServers
	}
	for _, ns := range nss {
		for _, network := range []string{"udp", "tcp"} {
			r := new(dns.Msg)
			r.SetQuestion(dns.Fqdn(name), dns.TypeA)
			client := dns.Client{
				Timeout: 5 * time.Second,
				UDPSize: 1280,
				Net:     network,
			}
			if resp, _, err := client.Exchange(r, ns); err == nil {
				for _, ans := range resp.Answer {
					if a, ok := ans.(*dns.A); ok {
						return a.A.String()
					}
				}
				break
			} else {
				fmt.Fprintf(os.Stderr, "[+] resolve domain '%s' from '%s' via '%s' failed, error: '%s'\n", name, ns, network, err)
			}
		}
	}

	return ""
}

const constQueryQtypeALL string = "ALL" // special qtype to identify all dns qtype

// parse contruct QueryList
func (q *Query) parse() error {

	err := contructQueryList(q.BlackList)
	if err != nil {
		return err
	}
	err = contructQueryList(q.WhiteList)

	return err
}

// TODO: should not skip invalid rule
func contructQueryList(qm map[string]QueryList) error {
	var err error

	for qt, ql := range qm {
		t := strings.ToUpper(qt)
		if _, found := dns.StringToType[t]; !found && t != constQueryQtypeALL {
			libnamed.Logger.Error().Str("log_type", "config").Str("op_type", "contruct_query_list").Msgf("invalid qtype %s", qt)
			return fmt.Errorf("skip invalid qtype %s", qt)
		}

		// pre process input
		for i, s := range ql.Equal {
			s, err = idna.ToASCII(ql.Equal[i])
			if err != nil || len(s) == 0 {
				libnamed.Logger.Error().Str("log_type", "config").Str("op_type", "contruct_query_list").Err(err).Msgf("invalid equal rule '%s'", ql.Equal[i])
				if err == nil {
					return fmt.Errorf("invalid equal rule '%s'", ql.Equal[i])
				}
				return err
			}
			ql.Equal[i] = dns.Fqdn(s)
		}
		for i, s := range ql.Suffix {
			s, err = idna.ToASCII(ql.Suffix[i])
			if err != nil || len(s) == 0 {
				libnamed.Logger.Error().Str("log_type", "config").Str("op_type", "contruct_query_list").Err(err).Msgf("invalid suffix rule '%s'", ql.Suffix[i])
				if err == nil {
					return fmt.Errorf("invalid suffix rule '%s'", ql.Equal[i])
				}
				return err
			}
			ql.Suffix[i] = dns.Fqdn(s)
		}
		for i, s := range ql.Prefix {
			s, err = idna.ToASCII(ql.Prefix[i])
			if err != nil || len(s) == 0 {
				libnamed.Logger.Error().Str("log_type", "config").Str("op_type", "contruct_query_list").Err(err).Msgf("invalid prefix rule '%s'", ql.Prefix[i])
				if err == nil {
					return fmt.Errorf("invalid prefix rule '%s'", ql.Equal[i])
				}
				return err
			}
			ql.Prefix[i] = s
		}

		// build internal using data struct
		ql.equalMap = make(map[string]struct{}, len(ql.Equal))
		for _, rl := range ql.Equal {
			ql.equalMap[rl] = struct{}{}
		}
		ql.prefixTrie = libnamed.NewPrefixTrie(ql.Prefix)
		ql.suffixTrie = libnamed.NewSuffixTrie(ql.Suffix)

		if len(ql.Regexp) > 0 {
			// pre-compile regexp
			ql.regexp = make([]*regexp.Regexp, len(ql.Regexp))
			for i := range ql.Regexp {
				ql.regexp[i], err = regexp.Compile(ql.Regexp[i])
				if err != nil {
					libnamed.Logger.Error().Str("log_type", "config").Str("op_type", "contruct_query_list").Err(err).Msgf("invalid regexp rule '%s'", ql.Regexp[i])
					return err
				}
			}
		}

		qm[t] = ql
	}
	return err
}

// return (cname, vname), if cname exist, else name
func (srv *Server) FindRealName(name string) (string, string) {
	idx := 0

	cnameCount := 0
	for i := 0; i < 255; i++ {
		if vi, found := srv.View[name[idx:]]; found {
			if len(vi.Cname) != 0 && name != vi.Cname && cnameCount < maxCnameCounts {
				name = vi.Cname
				idx = 0
				cnameCount++
				continue
			} else {
				return name, name[idx:]
			}
		}

		idx = strings.Index(name[idx:], ".") + idx
		if idx < len(name)-1 {
			idx++
		} else {
			break
		}
	}
	return name, "."
}

// {nameserver_tag: nameserver}
func (srv *Server) FindViewNameServers(vname string) map[string]*NameServer {
	if vi, found := srv.View[vname]; found && vi.ResolveType != ResolveTypeLocal {

		nss := make(map[string]*NameServer)
		for _, tag := range vi.NameServerTags {
			if ns, exist := srv.NameServer[tag]; exist {
				nss[tag] = &ns
			}
		}
		return nss
	}
	return nil
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
	for _, h := range srv.Hosts {
		if qtype == h.Qtype && name == h.Name {
			return h.Record, true
		}
	}
	return "", false
}

// QueryList Match
func (q *Query) QueryForbidden(name string, qtype string) (string, string, bool) {
	if ruleType, ruleStr, found := q.MatchWhitlist(name, qtype); found {
		return ruleType, ruleStr, false
	}
	if ruleType, ruleStr, found := q.MatchBlacklist(name, qtype); found {
		return ruleType, ruleStr, true
	}
	return "", "", false
}

func (q *Query) MatchWhitlist(name string, qtype string) (string, string, bool) {
	if ql, found := q.WhiteList[qtype]; found {
		return ql.Match(name)
	}
	if ql, found := q.WhiteList[constQueryQtypeALL]; found {
		return ql.Match(name)
	}
	return "", "", false
}

func (q *Query) MatchBlacklist(name string, qtype string) (string, string, bool) {
	if ql, found := q.BlackList[qtype]; found {
		return ql.Match(name)
	}
	if ql, found := q.BlackList[constQueryQtypeALL]; found {
		return ql.Match(name)
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
	for _, rule := range ql.Contain {
		if strings.Contains(name, rule) {
			return QueryListTypeContain, rule, true
		}
	}
	// O(m) * O(len(_ql.regexp))
	for _, rule := range ql.regexp {
		if rule.MatchString(name) {
			return QueryListTypeRegexp, rule.String(), true
		}
	}
	return "", "", false
}
