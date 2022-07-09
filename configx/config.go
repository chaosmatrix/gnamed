package configx

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"gnamed/libnamed"
	"io/ioutil"
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

	"github.com/lucas-clemente/quic-go"
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
	filename           string              `json:"-"` // current using configuration file name
	timestamp          time.Time           `json:"-"` // configuration file parse timestamp
	lock               sync.Mutex          `json:"-"` // internal use, lazy init some values
	singleflightGroups [][]*libnamed.Group `json:"-"` // [QCLASS][QTYPE]*libnamed.Group max size 1<<16 * 1<<16
	Server             Server              `json:"server"`
	Query              Query               `json:"query"`
	Admin              Admin               `json:"admin"`
	Files              Files               `json:"files"`
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
	Addr          string    `json:"addr"`
	Network       string    `json:"network"`
	Protocol      string    `json:"protocol"`
	DohPath       string    `json:"doh_path"` // doh path, default "/dns-query"
	TlsConfig     TlsConfig `json:"tls_config"`
	Timeout       Timeout   `json:"timeout"`
	QuerysPerConn int       `json:"querysPerConn"`
}

// TODO
type SocketAttr struct {
	KeepAliveNum      int
	KeepAliveInterval int
}

type TlsConfig struct {
	ServerName         string `json:"serverName"`
	InsecureSkipVerify bool   `json:"insecure"`
	CertFile           string `json:"certFile"`
	KeyFile            string `json:"keyFile"`
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

	Timeout Timeout         `json:"timeout"`
	DnsOpt  *DnsOpt         `json:"dns_opt"`
	Pool    *ConnectionPool `json:"pool"`

	// use internal
	ClientUDP         *dns.Client              `json:"-"`
	ClientTCP         *dns.Client              `json:"-"`
	ConnectionPoolTCP *libnamed.ConnectionPool `json:"-"`
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
	DnsOpt    *DnsOpt   `json:"dns_opt"`

	// use internal
	Client *http.Client `json:"-"`
}

type DOTServer struct {
	Server string          `json:"server"`
	Pool   *ConnectionPool `json:"pool"`

	// if "Server" not a ip address, use this nameservers to resolve domain
	ExternalNameServers []string `json:"externalNameServers"`

	TlsConfig TlsConfig `json:"tls_config"`
	Timeout   Timeout   `json:"timeout"`
	DnsOpt    *DnsOpt   `json:"dns_opt"`

	// use internal
	Client         *dns.Client              `json:"-"`
	ConnectionPool *libnamed.ConnectionPool `json:"-"`
}

// DNS-over-QUIC
type DOQServer struct {
	Server string          `json:"server"`
	Draft  bool            `json:"draft"` // send message content to server in draft format, rather than rfc9250
	Pool   *ConnectionPool `json:"pool"`

	// if "Server" not a ip address, use this nameservers to resolve domain
	ExternalNameServers []string `json:"externalNameServers"`

	TlsConfig TlsConfig `json:"tls_config"`
	Timeout   Timeout   `json:"timeout"`
	DnsOpt    *DnsOpt   `json:"dns_opt"`

	// use internal
	TlsConf  *tls.Config  `json:"-"`
	QuicConf *quic.Config `json:"-"`
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
	IdleTimeout         string        `json:"idle"`
	idleTimeoutDuration time.Duration `json:"-"`
	WaitTimeout         string        `json:"waitTimeout"`
	waitTimeoutDuration time.Duration `json:"-"`
	Size                int           `json:"size"`
}

type DnsOpt struct {
	Dnssec       bool `json:"dnssec"`       // enable dnssec
	Ecs          bool `json:"ecs"`          // enable edns-client-subnet
	RandomDomain bool `json:"randomDomain"` // randomw Upper/Lower domain's chars
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
	MaxTTL               uint32  `json:"maxTTL"`
	MinTTL               uint32  `json:"minTTL"`
	Mode                 string  `json:"mode"`
	UseSteal             bool    `json:"useSteal"`             // use steal cache, when element expired, return and trigger background query
	BackgroundUpdate     bool    `json:"backGroundUpdate"`     // true if BackgroundUpdate || UseSteal || BeforeExpiredSecond != 0 || BeforeExpiredPercent != 0
	BeforeExpiredSecond  int64   `json:"beforeExpiredSecond"`  // time.Now().Unix() >= expired - BeforeExpiredSecond, enable background query
	BeforeExpiredPercent float64 `json:"beforeExpiredPercent"` // time.Now().Unix() >= expired - ttl * BeforeExpiredPercent, enable background query

	// internal use
	backgroundQueryMap *sync.Map `json:"-"`
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

func ParseConfig(fname string) (*Config, error) {
	return parseConfig(fname)
}
func parseConfig(fname string) (*Config, error) {
	cfg := new(Config)
	fbs, err := ioutil.ReadFile(fname)
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
	if err = cfg.Server.Cache.parse(); err != nil {
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

func (c *Cache) parse() error {
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
func (c *Cache) BackgroundQueryTryLock(key string) bool {
	_, loaded := c.backgroundQueryMap.LoadOrStore(key, true)
	return !loaded
}

func (c *Cache) BackgroundQueryUnlock(key string) {
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

	if l.QuerysPerConn < 0 {
		return fmt.Errorf("querysPerConn %d < 0", l.QuerysPerConn)
	} else if l.QuerysPerConn == 0 {
		l.QuerysPerConn = 1
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
	} else {
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
	}
	return cfg.singleflightGroups[qclass][qtype]
}

func (mf *Main) parse() error {
	if mf.LogLevel == "" {
		mf.LogLevel = zerolog.DebugLevel.String()
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

	setDuration(&t.IdleDuration, t.Idle, DefaultTimeoutDurationIdle)
	setDuration(&t.ConnectDuration, t.Connect, DefaultTimeoutDurationConnect)
	setDuration(&t.ReadDuration, t.Read, DefaultTimeoutDurationRead)
	setDuration(&t.WriteDuration, t.Write, DefaultTimeoutDurationWrite)

	return nil
}

func (cp *ConnectionPool) parse() error {
	if cp == nil {
		return nil
	}

	if cp.Size == 0 {
		cp.Size = DefaultPoolSize
	}

	if cp.IdleTimeout == "" {
		cp.idleTimeoutDuration = DefaultPoolIdleTimeoutDuration
	} else {
		if d, err := time.ParseDuration(cp.IdleTimeout); err != nil {
			return err
		} else {
			cp.idleTimeoutDuration = d
		}
	}

	if cp.WaitTimeout == "" {
		cp.waitTimeoutDuration = DefaultPoolWaitTimeoutDuration
	} else {
		if d, err := time.ParseDuration(cp.WaitTimeout); err != nil {
			return err
		} else {
			cp.waitTimeoutDuration = d
		}
	}

	return nil
}

func (srv *Server) parse() error {
	res := true

	// verify using nameserverTag valid
	for zone, vi := range srv.View {
		if ns, found := srv.NameServer[vi.NameServerTag]; !found {
			fmt.Fprintf(os.Stderr, "[+] View: '%s', nameserver_tag: '%s' not found.\n", zone, vi.NameServerTag)
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
				fmt.Fprintf(os.Stderr, "[+] Nameserver: '%s' use unsupport protocol '%s'\n", vi.NameServerTag, ns.Protocol)
				res = false
			}

			if err != nil {
				fmt.Fprintf(os.Stderr, "[+] Nameserver: '%s', parse failed, error: %v\n", vi.NameServerTag, err)
				res = false
			}
			srv.NameServer[vi.NameServerTag] = ns
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
		dod.Server = net.JoinHostPort(dod.Server, strconv.Itoa(DefaultPortDns))
	} else {
		if port, err := strconv.Atoi(portStr); err != nil || port < 0 || port > 65535 {
			return errInvalidServer
		}
	}

	if net.ParseIP(host) == nil {
		return errInvalidServer
	}

	dod.Timeout.parse()

	if dod.Network != "tcp" {
		dod.ClientUDP = &dns.Client{
			// Default buffer size to use to read incoming UDP message
			// default 512 B
			// must increase if edns-client-sub enable
			UDPSize:      1024,
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
		UDPSize:      1024,
		Net:          "tcp",
		DialTimeout:  dod.Timeout.ConnectDuration,
		ReadTimeout:  dod.Timeout.ReadDuration,
		WriteTimeout: dod.Timeout.WriteDuration,
		//SingleInflight: true,
	}

	if dod.Network == "tcp" {
		if err := dod.Pool.parse(); err != nil {
			return err
		}
		// only tcp enable connection pool
		dod.ConnectionPoolTCP = libnamed.NewConnectionPool(dod.Pool.Size, dod.Pool.idleTimeoutDuration, dod.Pool.waitTimeoutDuration, func() (interface{}, error) {
			return dod.ClientTCP.Dial(dod.Server)
		})
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

	if net.ParseIP(host) == nil {
		if _, found := doh.Headers["Host"]; !found {
			doh.Headers["Host"] = []string{host}
		}

		if doh.TlsConfig.ServerName == "" {
			doh.TlsConfig.ServerName = host
		}

		qname := dns.Fqdn(host)
		host = ""
		if libnamed.ValidateDomain(qname) {
			host = lookupIP(qname, doh.ExternalNameServers)
		}

		if host == "" {
			return fmt.Errorf("server '%s' no valid ip address found", doh.Url)
		}

		if host != "" && portStr != "" {
			host = net.JoinHostPort(host, portStr)
		}

		urlStruct.Host = host

		doh.Url = urlStruct.String()
	}

	doh.Timeout.parse()

	client := &http.Client{
		Timeout: doh.Timeout.ConnectDuration + doh.Timeout.ReadDuration + doh.Timeout.WriteDuration,
	}

	if doh.TlsConfig.ServerName != "" {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         doh.TlsConfig.ServerName,
				InsecureSkipVerify: doh.TlsConfig.InsecureSkipVerify,
			},
			ForceAttemptHTTP2: true,
			Proxy:             http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   doh.Timeout.ConnectDuration + doh.Timeout.ReadDuration + doh.Timeout.WriteDuration,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
		client.Transport = tr
	}
	doh.Client = client
	return nil
}

// FIXME: dot.Server was a config file, should not be change.
func (dot *DOTServer) parse() error {
	server, host, err := parseServer(dot.Server, dot.ExternalNameServers, DefaultPortDoT)
	if err != nil {
		return err
	}
	dot.Server = server

	sni := dot.TlsConfig.ServerName
	if sni == "" {
		sni = strings.ToLower(strings.TrimRight(host, "."))
	}

	dot.Timeout.parse()

	dot.Client = &dns.Client{
		Net: "tcp-tls",
		TLSConfig: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: dot.TlsConfig.InsecureSkipVerify,
		},

		DialTimeout:  dot.Timeout.ConnectDuration,
		ReadTimeout:  dot.Timeout.ReadDuration,
		WriteTimeout: dot.Timeout.WriteDuration,
		//SingleInflight: true,
	}

	if dot.Pool != nil {
		if err := dot.Pool.parse(); err != nil {
			return err
		}

		dot.ConnectionPool = libnamed.NewConnectionPool(dot.Pool.Size, dot.Pool.idleTimeoutDuration, dot.Pool.waitTimeoutDuration, func() (interface{}, error) {
			return dot.Client.Dial(dot.Server)
		})
	}
	return nil
}

// FIXME: dot.Server was a config file, should not be change.
func (doq *DOQServer) parse() error {
	server, host, err := parseServer(doq.Server, doq.ExternalNameServers, DefaultPortDoQ)
	if err != nil {
		return err
	}
	doq.Server = server

	sni := doq.TlsConfig.ServerName
	if sni == "" {
		sni = strings.ToLower(strings.TrimRight(host, "."))
	}

	doq.Timeout.parse()

	// internal
	doq.TlsConf = &tls.Config{
		ServerName:         sni,
		NextProtos:         []string{"doq-i02", "doq-i00", "dq", "doq"},
		InsecureSkipVerify: doq.TlsConfig.InsecureSkipVerify,
	}
	doq.QuicConf = &quic.Config{
		HandshakeIdleTimeout: doq.Timeout.IdleDuration,
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
		r := new(dns.Msg)
		r.SetQuestion(dns.Fqdn(name), dns.TypeA)
		client := dns.Client{
			Timeout: 5 * time.Second,
		}
		if resp, _, err := client.Exchange(r, ns); err == nil {
			for _, ans := range resp.Answer {
				if a, ok := ans.(*dns.A); ok {
					return a.A.String()
				}
			}
		} else {
			fmt.Fprintf(os.Stderr, "[+] resolve domain '%s' failed, error: '%s'\n", name, err)
		}
	}

	return ""
}

// parse contruct QueryList
func (q *Query) parse() error {

	contructQueryList(q.BlackList)
	contructQueryList(q.WhiteList)

	return nil
}

func contructQueryList(qm map[string]QueryList) {
	for t, ql := range qm {

		// pre process input
		for i := range ql.Equal {
			ql.Equal[i] = dns.Fqdn(ql.Equal[i])
		}
		for i := range ql.Suffix {
			ql.Suffix[i] = dns.Fqdn(ql.Suffix[i])
		}

		// build internal using data struct
		for _, rl := range ql.Equal {
			ql.equalMap[rl] = true
		}
		ql.prefixTrie = libnamed.NewPrefixTrie(ql.Prefix)
		ql.suffixTrie = libnamed.NewSuffixTrie(ql.Suffix)

		if len(ql.Regexp) > 0 {
			// pre-compile regexp
			ql.regexp = make([]*regexp.Regexp, len(ql.Regexp))
			for i := range ql.Regexp {
				ql.regexp[i] = regexp.MustCompile(ql.Regexp[i])
			}
		}

		qm[t] = ql
	}
}

// return (cname, vname), if cname exist, else name
func (srv *Server) FindRealName(name string) (string, string) {
	idx := 0
	for i := 0; i < MaxCnameCounts; i++ {
		if vi, found := srv.View[name[idx:]]; found {
			if len(vi.Cname) != 0 && name != vi.Cname {
				name = vi.Cname
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
	return "", "", false
}

func (q *Query) MatchBlacklist(name string, qtype string) (string, string, bool) {
	if ql, found := q.BlackList[qtype]; found {
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
