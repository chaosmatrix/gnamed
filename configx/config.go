package configx

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"gnamed/cachex"
	"gnamed/ext/faketimer"
	"gnamed/ext/filter"
	"gnamed/ext/iptree"
	"gnamed/ext/pool"
	"gnamed/ext/runner"
	"gnamed/ext/warm"
	"gnamed/ext/xlog"
	"gnamed/ext/xsingleflight"
	"gnamed/libnamed"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

type globalConfig struct {
	value *atomic.Value
	lock  *sync.Mutex
}

var _globalConfig = &globalConfig{}

func InitGlobalConfig(cfg *Config) {
	v := new(atomic.Value)
	v.Store(cfg)
	_globalConfig = &globalConfig{
		value: v,
		lock:  new(sync.Mutex),
	}
}

func UpdateGlobalConfig() error {

	// prevent update frequency
	cfg := _globalConfig.value.Load().(*Config)
	if time.Since(cfg.GetTimestamp()) < 10*time.Second {
		time.Sleep(10 * time.Second)
	}

	_globalConfig.lock.Lock()
	defer _globalConfig.lock.Unlock()

	fname := cfg.GetFileName()
	cfg, err := ParseConfig(fname)
	if err != nil {
		return err
	}

	_globalConfig.value.Store(cfg)

	return err
}

func GetGlobalConfig() *Config {
	return _globalConfig.value.Load().(*Config)
}

type Config struct {
	filename           string                   `json:"-"` // current using configuration file name
	timestamp          time.Time                `json:"-"` // configuration file parse timestamp
	lock               sync.Mutex               `json:"-"` // internal use, lazy init some values
	singleflightGroups [][]*xsingleflight.Group `json:"-"` // [QCLASS][QTYPE]*xsingleflight.Group max size 1<<16 * 1<<16
	Global             Global                   `json:"global"`
	Server             Server                   `json:"server"`
	Admin              Admin                    `json:"admin"`
	Filter             *filter.Filter           `json:"filter"` // filter
	WarmRunnerInfo     *warm.WarmRunnerInfo     `json:"warm"`
	RunnerOption       *runner.RunnerOption     `json:"runner"`
}

type Server struct {
	Listen     []Listen               `json:"listen"`
	NameServer map[string]*NameServer `json:"nameserver"`
	View       map[string]*View       `json:"view"`
	Hosts      []Host                 `json:"hosts"`
	RrCache    *cachex.RrCache        `json:"cache"`
}

type Global struct {
	ShutdownTimeout  string                   `json:"shutdownTimeout"`
	ShutdownDuration time.Duration            `json:"-"`
	Log              *xlog.LogConfig          `json:"log"`
	FakeTimer        *faketimer.FakeTimerInfo `json:"fakeTimer"`
	DisableFakeTimer bool                     `json:"disableFakeTimer"` // default enable FakeTimer and use default options

	Singleflight bool `json:"singleflight"`
}

// Server -> Listen
type Listen struct {
	Addr               string      `json:"addr"`
	Network            string      `json:"network"`
	Protocol           string      `json:"protocol"`
	URLPath            string      `json:"urlPath"` // url path, for dns-over-https default to "/dns-query"
	TlsConfig          *TlsConfig  `json:"tls_config"`
	TLSConfig          *tls.Config `json:"-"`
	Timeout            Timeout     `json:"timeout"`
	QueriesPerConn     int         `json:"queriesPerConn"`
	DisableCompressMsg bool        `json:"disableCompressMsg"` // server, default enable compress, else depend on protocol and message size (udp <512, quic/tcp < 1024)
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
	ServerName         string   `json:"serverName"`
	InsecureSkipVerify bool     `json:"insecure"`
	CertFile           string   `json:"certFile"`
	KeyFile            string   `json:"keyFile"`
	ALPNS              []string `json:"alpns"`
	RequireClientAuth  bool     `json:"requireClientAuth"`
	MinVersion         float32  `json:"minVersion"`
	MaxVersion         float32  `json:"maxVersion"`

	// KeyLogWriter - should not used in production
	// if not empty, all tls master secrets will be writen into this file,
	// which can be used to decrypt tls traffic with wireshark
	KeyLogFile string `json:"keyLogFile"`
}

// Server -> NameServer
type NameServer struct {
	NameServerInfo

	Protocol string     `json:"-"`
	Dns      *DODServer `json:"-"`
	DoT      *DOTServer `json:"-"`
	DoH      *DOHServer `json:"-"`
	DoQ      *DOQServer `json:"-"`
	/*
		Protocol string     `json:"protocol"`
		Dns      *DODServer `json:"dns,omitempty"`
		DoT      *DOTServer `json:"dot,omitempty"`
		DoH      *DOHServer `json:"doh,omitempty"`
		DoQ      *DOQServer `json:"doq,omitempty"`
	*/
}

type NameServerInfo struct {
	URI                 string     `json:"uri"`
	addrs               []string   `json:"-"`
	Timeout             Timeout    `json:"timeout"`
	ExternalNameServers []string   `json:"externalNameServers"`
	Extra               *ExtraInfo `json:"extra"`
}

type ExtraInfo struct {
	// default:
	// 1. dns: udp4 (ipv4-only), will fallback to tcp when necessary
	// 2. others: ipv4 (ipv4-only)
	//
	// dns: to identify using tcp-only or not
	Network string `json:"network"`

	// tcp-only
	SocketAttr            *SocketAttr `json:"socketAttr,omitempty"`
	Pool                  *pool.Pool  `json:"pool"`                  // if nil, use default
	DisableConnectionPool bool        `json:"disableConnectionPool"` // tcp network will always enable connection pool

	// tls
	TLSConfig *TlsConfig `json:"tls_config"`

	// quic

	// http
	HTTP3               bool                `json:"http3"`
	DisableAttemptHTTP3 bool                `json:"disableAttemptHTTP3"`
	Method              string              `json:"method"`
	Headers             map[string][]string `json:"headers"`
	Format              DOHMsgType          `json:"format"`
}

func (ns *NameServer) parse() error {
	network := ""
	if ns.Extra != nil {
		network = ns.Extra.Network
	}
	addrs, host, err := parseURI(network, ns.URI, ns.ExternalNameServers)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return fmt.Errorf("invalid uri: %s, no valid addresses", ns.URI)
	}
	ns.addrs = addrs

	if ns.Extra == nil {
		ns.Extra = &ExtraInfo{}
	}

	if ns.Extra.TLSConfig != nil {
		if ns.Extra.TLSConfig.ServerName == "" {
			ns.Extra.TLSConfig.ServerName = host
		}
	} else {
		ns.Extra.TLSConfig = &TlsConfig{
			ServerName: host,
		}
	}
	tlsConf, err := ns.Extra.TLSConfig.parse()
	if err != nil {
		return err
	}
	if tlsConf.ServerName == "" {
		tlsConf.ServerName = host
	}

	colIdx := strings.Index(ns.URI, ":")
	if colIdx < 0 {
		colIdx = 0
	}

	scheme := strings.ToLower(ns.URI[:colIdx])
	switch scheme {
	case "https", "http":
		ns.Protocol = ProtocolTypeDoH
		ns.DoH = &DOHServer{}
		ns.DoH.init(ns)
		err = ns.DoH.parse()
	case "quic":
		ns.Protocol = ProtocolTypeDoQ
		ns.DoQ = &DOQServer{}
		ns.DoQ.init(ns)
		err = ns.DoQ.parse()
	case "tls":
		ns.Protocol = ProtocolTypeDoT
		ns.DoT = &DOTServer{}
		ns.DoT.init(ns)
		err = ns.DoT.parse()
	case "dns", "tcp", "udp":
		ns.Protocol = ProtocolTypeDNS
		if scheme != "dns" {
			ns.Extra.Network = scheme
		}
		ns.Dns = &DODServer{}
		ns.Dns.init(ns)
		err = ns.Dns.parse()
	default:
		return fmt.Errorf("invalid uri: %s", ns.URI)
	}

	return err
}

func (doh *DOHServer) init(nsi *NameServer) {
	*doh = DOHServer{
		Url:                 nsi.addrs[0],
		Method:              nsi.Extra.Method,
		Headers:             nsi.Extra.Headers,
		Format:              nsi.Extra.Format,
		HTTP3:               nsi.Extra.HTTP3,
		ExternalNameServers: nsi.ExternalNameServers,
		TlsConfig:           *nsi.Extra.TLSConfig,
		Timeout:             nsi.Timeout,
		SocketAttr:          nsi.Extra.SocketAttr,
	}
}

func (dot *DOTServer) init(nsi *NameServer) {
	*dot = DOTServer{
		Server:              nsi.addrs[0],
		Pool:                nsi.Extra.Pool,
		ExternalNameServers: nsi.ExternalNameServers,
		TlsConfig:           *nsi.Extra.TLSConfig,
		Timeout:             nsi.Timeout,
		SocketAttr:          nsi.Extra.SocketAttr,
	}
}

func (dod *DODServer) init(nsi *NameServer) {
	*dod = DODServer{
		Server:     nsi.addrs[0],
		Network:    nsi.Extra.Network,
		Timeout:    nsi.Timeout,
		Pool:       nsi.Extra.Pool,
		SocketAttr: nsi.Extra.SocketAttr,
	}
}

type NameServerTyper interface {
	*DODServer | *DOTServer | *DOHServer | *DOQServer
	parse() error
}

type DODServer struct {
	Server  string `json:"server"`
	Network string `json:"network"`

	Timeout               Timeout     `json:"timeout"`
	Pool                  *pool.Pool  `json:"pool"`
	DisableConnectionPool bool        `json:"disableConnectionPool"` // tcp network will always enable connection pool
	SocketAttr            *SocketAttr `json:"socketAttr,omitempty"`

	// use internal
	ClientUDP         *dns.Client                     `json:"-"`
	ClientTCP         *dns.Client                     `json:"-"`
	ConnectionPoolTCP *pool.ConnectionPool            `json:"-"`
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
	Server                string     `json:"server"`
	Pool                  *pool.Pool `json:"pool"`
	DisableConnectionPool bool       `json:"disableConnectionPool"` // tcp network will always enable connection pool

	// if "Server" not a ip address, use this nameservers to resolve domain
	ExternalNameServers []string `json:"externalNameServers"`

	TlsConfig  TlsConfig   `json:"tls_config"`
	Timeout    Timeout     `json:"timeout"`
	SocketAttr *SocketAttr `json:"socketAttr,omitempty"`

	// use internal
	Client         *dns.Client                     `json:"-"`
	ConnectionPool *pool.ConnectionPool            `json:"-"`
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

// Server -> View
type View struct {
	NameServerTags []string `json:"nameserver_tags"`
	Cname          string   `json:"cname"`
	Dnssec         bool     `json:"dnssec"`
	Subnet         string   `json:"subnet"`

	// TODO: avaliable for more than one avaliable nameservers
	//QuerySerial bool `json:"query_parallel"` // parallel query all nameservers, default true
	//MergeResult bool `json:"merge_result"` // wait all queries return then merge result or return first valid response, default false

	// sometimes can be used to prevent dns hijacking when using dns-over-plain-udp protocol
	RandomDomain bool `json:"random_domain"` // random Upper/Lower domain's chars

	Compress bool `json:"compress"` // disable compress msg

	// rfc: https://www.ietf.org/archive/id/draft-ietf-dnsop-svcb-https-10.html
	// WARNING: browser makes A/AAAA and HTTPS record concurrency, only work when HTTPS responsed before A/AAAA
	RrHTTPS *RrHTTPS `json:"rr_https"`

	// cache
	//RrCache *RrCache `json:"rr_cache"` // view's cache

	// internal: edns-client-subnet, parse from Subnet
	ecsFamily  uint16 `json:"-"` // 1: ipv4, 2: ipv6
	ecsAddress net.IP `json:"-"`
	ecsNetMask uint8  `json:"-"`
}

// HTTPS RRSet setting
type RrHTTPS struct {
	Priority uint16   `json:"priority"`
	Target   string   `json:"target"`
	Alpn     []string `json:"alpn"`
	Hijack   bool     `json:"hijack"` // QType HTTPS will be hijacked with configured
}

// rfc: https://www.ietf.org/archive/id/draft-ietf-dnsop-svcb-https-10.html
// fake dns HTTPS RR
func (h *RrHTTPS) FakeRR(r *dns.Msg, hints []net.IP) dns.RR {
	if r == nil || len(r.Question) == 0 || r.Question[0].Qtype != dns.TypeHTTPS {
		return nil
	}

	rr := new(dns.HTTPS)
	rr.Priority = h.Priority
	rr.Target = h.Target
	rr.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: r.Question[0].Qclass, Ttl: 300}

	if h.Priority > 0 {
		if len(h.Alpn) > 0 {
			e := new(dns.SVCBAlpn)
			e.Alpn = h.Alpn
			rr.Value = append(rr.Value, e)
		}

		ipv4hint := new(dns.SVCBIPv4Hint)
		ipv6hint := new(dns.SVCBIPv6Hint)
		for _, ip := range hints {
			ipv4 := ip.To4()
			if ipv4 != nil {
				ipv4hint.Hint = append(ipv4hint.Hint, ipv4)
			} else {
				ipv6hint.Hint = append(ipv6hint.Hint, ip)
			}
		}

		if len(ipv4hint.Hint) > 0 {
			rr.Value = append(rr.Value, ipv4hint)
		}
		if len(ipv6hint.Hint) > 0 {
			rr.Value = append(rr.Value, ipv6hint)
		}

	}
	return rr
}

// Server -> Hosts
type Host struct {
	Name   string `json:"name"`
	Record string `json:"record"`
	Qtype  string `json:"qtype"`
}

// Admin
type Admin struct {
	Listen        []Listen `json:"listen"`
	Auth          Auth     `json:"auth"`
	EnableProfile bool     `json:"enableProfile"`
}

type Auth struct {
	Cidr   []string          `json:"cidr"`
	iptree *iptree.IPTree    `json:"-"`
	Token  map[string]string `json:"token"` // user:token
}

func (a *Admin) parse() error {
	for i := range a.Listen {
		if err := a.Listen[i].parse(); err != nil {
			return err
		}
		if a.EnableProfile {
			t := a.Listen[i].Timeout
			logEvent := xlog.Logger().Warn().Str("log_type", "admin").Str("op_type", "parse")

			needLog := false
			if a.Listen[i].Timeout.WriteDuration < 30*time.Second {
				a.Listen[i].Timeout.WriteDuration = 30 * time.Second
				logEvent.Dur("write_timeout", t.WriteDuration)
				needLog = true
			}
			if a.Listen[i].Timeout.IdleDuration < 30*time.Second {
				a.Listen[i].Timeout.IdleDuration = 30 * time.Second
				logEvent.Dur("idle_timeout", t.IdleDuration)
				needLog = true
			}

			if needLog {
				logEvent.Msg("enable profile, slice change timeout greater than 30 sec")
			} else {
				logEvent.Discard()
			}
		}
	}
	return a.Auth.parse()
}

func (a *Auth) parse() error {

	if len(a.Cidr) == 0 {
		return nil
	}

	a.iptree = iptree.NewIPTree()
	for _, v := range a.Cidr {
		if i := strings.LastIndex(v, "/"); i < 0 {
			if strings.Contains(v, ":") {
				v += "/128"
			} else {
				v += "/32"
			}
		}

		if err := a.iptree.InsertCIDR(v); err != nil {
			return err
		}
	}
	return nil
}

func (a *Auth) CheckAllow(user string, token string, clientIP string) error {

	if !(len(a.Token) == 0 || (token != "" && a.Token[user] == token)) {
		return errors.New("client user and password not allow")
	}

	if a.iptree == nil {
		return nil
	}

	if a.iptree.SearchShortestCIDR(clientIP) != "" {
		return nil
	}

	return errors.New("client ip not allow")
}

func (c *TlsConfig) parse() (*tls.Config, error) {
	tlsc := &tls.Config{
		InsecureSkipVerify: c.InsecureSkipVerify,
		ServerName:         c.ServerName,
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

	if len(c.ALPNS) != 0 {
		tlsc.NextProtos = append([]string{}, c.ALPNS...)
	}

	if c.MinVersion != 0 && c.MaxVersion != 0 && c.MinVersion > c.MaxVersion {
		return tlsc, fmt.Errorf("tls minVersion %f greater than maxVersion %f", c.MinVersion, c.MaxVersion)
	}

	if c.MinVersion != 0 {
		if version, err := getTLSVersion(c.MinVersion); err == nil {
			tlsc.MinVersion = version
		} else {
			return tlsc, err
		}
	}

	if c.MaxVersion != 0 {
		if version, err := getTLSVersion(c.MaxVersion); err == nil {
			tlsc.MaxVersion = version
		} else {
			return tlsc, err
		}
	}

	// server side only and must
	if c.CertFile != "" && c.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return tlsc, err
		}
		tlsc.Certificates = []tls.Certificate{cert}
	}

	if c.RequireClientAuth {
		tlsc.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsc, nil
}

func getTLSVersion(vf float32) (uint16, error) {
	switch vf {
	case 0:
		return 0, nil
	case 1.0:
		return tls.VersionTLS10, nil
	case 1.1:
		return tls.VersionTLS11, nil
	case 1.2:
		return tls.VersionTLS12, nil
	case 1.3:
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("invaid tls version %f", vf)
	}
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

	if err = cfg.Global.parse(); err != nil {
		return cfg, err
	}

	if cfg.Global.Singleflight {
		// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
		// [1<<16][1<<16]*xsingleflight.Group
		// empty singleflightGroups memory usage: 65536 * sizeof(uintptr) = 65536 * 8 byte = 0.5MB
		cfg.singleflightGroups = make([][]*xsingleflight.Group, math.MaxUint16+1)
	}

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
		if err = vv.parse(); err != nil {
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

	// verify and defaulting cache configuration options
	if cfg.Server.RrCache == nil {
		cfg.Server.RrCache = new(cachex.RrCache)
	}
	if err = cfg.Server.RrCache.Parse(); err != nil {
		return cfg, err
	}

	// admin
	if err = cfg.Admin.parse(); err != nil {
		return cfg, err
	}

	// filter
	if cfg.Filter == nil {
		cfg.Filter = new(filter.Filter)
	}
	if err = cfg.Filter.Parse(); err != nil {
		return cfg, err
	}

	// warm runner
	if cfg.WarmRunnerInfo == nil {
		cfg.WarmRunnerInfo = new(warm.WarmRunnerInfo)
	}
	if err = cfg.WarmRunnerInfo.Parse(); err != nil {
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

	if len(v.NameServerTags) == 0 {
		return fmt.Errorf("no nameserver_tags configuring in view")
	}

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
			v.ecsAddress = ipNet.IP.To4()
			v.ecsFamily = defaultEcsFamilyIPv4
		} else {
			v.ecsAddress = ipNet.IP.To16()
			v.ecsFamily = defaultEcsFamilyIPv6
		}
		v.ecsNetMask = uint8(ones)
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

func (v *View) SetMsgOpt(msg *dns.Msg) {

	if msg == nil {
		return
	}
	msg.Compress = v.Compress

	if v.RandomDomain && len(msg.Question) > 0 {
		msg.Question[0].Name = libnamed.RandomUpperDomain(msg.Question[0].Name)
	}

	if v.Subnet != "" || v.Dnssec {
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(1280)

		if v.Subnet != "" {
			ecs := new(dns.EDNS0_SUBNET)

			ecs.Address = v.ecsAddress

			ecs.Family = v.ecsFamily
			ecs.Code = dns.EDNS0SUBNET

			ecs.SourceNetmask = v.ecsNetMask

			// https://datatracker.ietf.org/doc/html/rfc7871#section-6
			// SCOPE PREFIX-LENGTH
			// an unsigned octet representing the leftmost
			// number of significant bits of ADDRESS that the response covers.
			// In queries, it MUST be set to 0.
			ecs.SourceScope = 0

			opt.Option = append(opt.Option, ecs)
		}

		// send dnssec query to server that don't support dnssec, might be response with FORMERR
		if v.Dnssec {
			opt.SetDo()
		}
		msg.Extra = append(msg.Extra, opt)
	}
}

func (l *Listen) parse() error {

	host, port, err := net.SplitHostPort(l.Addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[+] listen addr '%s' invalid, error: '%s'\n", l.Addr, err)
		return err
	}
	portInt, err := strconv.Atoi(port)
	if err != nil || portInt > 65536 || portInt <= 0 {
		return fmt.Errorf("listen addr '%s' has invalid port, error: '%s'", l.Addr, err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("listen addr '%s' invalid", l.Addr)
	} else if ip.IsUnspecified() && (strings.HasPrefix(l.Network, "udp") || l.Protocol == "quic") {
		err1 := errors.New("listen on unspecified address, packet receive and send address might be different")
		xlog.Logger().Warn().Str("log_type", "server").Str("protocol", l.Protocol).Str("network", l.Network).Str("addr", l.Addr).Err(err1).Msg("")
	}

	if l.QueriesPerConn < 0 {
		return fmt.Errorf("queriesPerConn %d < 0", l.QueriesPerConn)
	} else if l.QueriesPerConn == 0 {
		l.QueriesPerConn = 1
	}

	if l.TlsConfig != nil {
		l.TLSConfig, err = l.TlsConfig.parse()
		if err != nil {
			return err
		}
	}
	// must valid tls
	switch l.Protocol {
	case "https", "tls", "tcp-tls", "quic":
		if l.TLSConfig == nil || len(l.TLSConfig.Certificates) == 0 || l.TLSConfig.ServerName != "" || l.TLSConfig.InsecureSkipVerify {
			return errors.New("listener enable TLS, but no valid TLS Config")
		}
	}

	return l.Timeout.parse()
}

func (cfg *Config) GetSingleFlightGroup(qclass uint16, qtype uint16) *xsingleflight.Group {
	// lazy initialize
	if len(cfg.singleflightGroups[qclass]) == 0 {
		cfg.lock.Lock()
		if len(cfg.singleflightGroups[qclass]) == 0 {
			cfg.singleflightGroups[qclass] = make([]*xsingleflight.Group, math.MaxUint16+1)
			cfg.singleflightGroups[qclass][qtype] = new(xsingleflight.Group)
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
			cfg.singleflightGroups[qclass][qtype] = new(xsingleflight.Group)
		}
		cfg.lock.Unlock()
	}

	return cfg.singleflightGroups[qclass][qtype]
}

func (g *Global) parse() error {
	if g.Log == nil {
		g.Log = new(xlog.LogConfig)
	}
	if err := g.Log.Parse(); err != nil {
		return err
	}
	if g.ShutdownTimeout == "" {
		g.ShutdownDuration = 60 * time.Second
	} else {
		if t, err := time.ParseDuration(g.ShutdownTimeout); err == nil {
			g.ShutdownDuration = t
		} else {
			return err
		}
	}
	if !g.DisableFakeTimer {
		if g.FakeTimer == nil {
			g.FakeTimer = &faketimer.FakeTimerInfo{}
		}
		if err := g.FakeTimer.Parse(); err != nil {
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

func (srv *Server) parse() error {

	if srv.View == nil {
		return errors.New("no valid view")
	}

	if _, found := srv.View["."]; !found {
		return errors.New("default view '.' not exist")
	}

	if loops, found := hasCnameLoop(srv.View); found {
		return fmt.Errorf("cname loop exist in view: %s", loops)
	}

	hasInvalid := false
	// verify using nameserverTag valid
	for zone, vi := range srv.View {

		if len(vi.NameServerTags) == 0 {
			hasInvalid = true
			fmt.Fprintf(os.Stderr, "[+] View: '%s', hasn't any valid nameserver_tags.\n", zone)
		}

		for _, nameserverTag := range vi.NameServerTags {
			if ns, found := srv.NameServer[nameserverTag]; !found {
				fmt.Fprintf(os.Stderr, "[+] View: '%s', nameserver_tag: '%s' not found.\n", zone, nameserverTag)
				hasInvalid = true
			} else {
				err := ns.parse()
				if err != nil {
					fmt.Fprintf(os.Stderr, "[+] Nameserver: '%s', parse failed, error: %v\n", nameserverTag, err)
					hasInvalid = true
				}
				srv.NameServer[nameserverTag] = ns
			}
		}
	}
	if hasInvalid {
		return errors.New("some View's has invalid nameserver_tag")
	}
	return nil
}

// detect cname loop in view, for example:
// A -> B -> C -> B
func hasCnameLoop(views map[string]*View) (string, bool) {
	for _, view := range views {
		if view.Cname == "" {
			continue
		}

		cname := view.Cname
		m := make(map[string]bool)
		m[cname] = true

		loops := cname
		for cname != "" && len(m) <= 5 {
			nextCname := findNextCname(cname, views)
			if cname == nextCname {
				break
			}
			loops += " -> " + nextCname
			if m[nextCname] {
				return loops, true
			}
			m[nextCname] = true

			cname = nextCname
		}

		if len(m) >= 5 {
			return loops + " reach cname loop limit >= 5", false
		}
	}
	return "", false
}

// find the name's next cname in view
func findNextCname(name string, views map[string]*View) string {

	i := 0
	for i < len(name) {
		if view, found := views[name[i:]]; found {
			return view.Cname
		}
		for ; i < len(name) && name[i] != '.'; i++ {
		}
		i++
	}
	return ""
}

// caller must ensure that there is no cname-loop in view
func (srv *Server) Find(name string) (cname string, zone string, view *View, nameservers map[string]*NameServer) {

	if len(name) == 0 {
		return
	}

	cname = ""
	zone = "."

	currName := name
	i := 0
	for {
		if i >= len(currName) {
			// should not here
			break
		}
		if v, found := srv.View[currName[i:]]; found {
			if v.Cname != "" && v.Cname != currName {
				cname = v.Cname
				currName = cname
				i = 0
				continue
			} else {
				zone = currName[i:]
				view = v
				break
			}
		}
		for ; i < len(currName)-2 && currName[i] != '.'; i++ {
		}
		i++
	}

	if view == nil {
		return
	}

	nameservers = make(map[string]*NameServer)
	for _, tag := range view.NameServerTags {
		if ns, found := srv.NameServer[tag]; found {
			nameservers[tag] = ns
		}
	}
	return cname, zone, view, nameservers
}

// return cname, name's longest equal view's name
func (srv *Server) FindRealName(name string) (cname string, zone string) {

	cname = ""
	zone = "."
	currName := name
	i := 0
	for {
		if i >= len(currName) {
			// should not here
			break
		}
		if v, found := srv.View[currName[i:]]; found {
			if v.Cname != "" && v.Cname != currName {
				cname = v.Cname
				currName = cname
				i = 0
				continue
			} else {
				zone = currName[i:]
				break
			}
		}
		for ; i < len(currName)-2 && currName[i] != '.'; i++ {
		}
		i++
	}

	return cname, zone
}

func (srv *Server) FindViewWithZone(zone string) *View {
	if v, found := srv.View[zone]; found {
		return v
	}
	return nil
}

// {nameserver_tag: nameserver}
func (srv *Server) FindViewNameServers(zone string) map[string]*NameServer {
	if vi, found := srv.View[zone]; found {
		nss := make(map[string]*NameServer)
		for _, tag := range vi.NameServerTags {
			if ns, exist := srv.NameServer[tag]; exist {
				nss[tag] = ns
			}
		}
		return nss
	}
	return nil
}

func (srv *Server) FindRecordFromHosts(name string, qtype string) (string, bool) {
	for _, h := range srv.Hosts {
		if qtype == h.Qtype && name == h.Name {
			return h.Record, true
		}
	}
	return "", false
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

	if dod.Network == "tcp" && (!dod.DisableConnectionPool || dod.Pool != nil) {
		if dod.Pool == nil {
			dod.Pool = &pool.Pool{}
		}

		if err := dod.Pool.Parse(); err != nil {
			return err
		}
		// only tcp enable connection pool
		newConn := func() (*dns.Conn, error) {
			return dod.NewConn("tcp")
		}
		closeConn := func(conn *dns.Conn) error {
			if conn == nil {
				return nil
			}
			return conn.Close()
		}

		cpt, err := dod.Pool.NewConnectionPool(newConn, closeConn)
		if err != nil {
			return err
		}
		xlog.Logger().Info().Str("log_type", "connection_pool").Str("op_type", "new").Str("protocol", "tcp").Str("server", dod.Server).Int("size", dod.Pool.Size).Int("requests", dod.Pool.Requests).Msg("")
		dod.ConnectionPoolTCP = cpt
	}
	return nil
}

func (doh *DOHServer) parse() error {
	errInvalidServer := fmt.Errorf("invalid dns-over-https server address '%s'", doh.Url)

	// process header
	for hk, hm := range doh.Headers {
		hkc := http.CanonicalHeaderKey(hk)
		switch hkc {
		case "Host", "User-Agent":
			if len(hm) > 1 {
				return fmt.Errorf("http header '%s' has more than one values: %s", hkc, hm)
			}
		default:
		}
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
			addrs := lookupIPs("ipv4", qname, doh.ExternalNameServers)
			if len(addrs) > 0 {
				addr = addrs[0]
			}
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

	if doh.Format == "" && len(doh.Headers["content-type"]) == 0 {
		cts := doh.Headers["content-type"]
		if len(cts) != 0 {
			switch cts[0] {
			case DOHAccetpHeaderTypeRFC8484:
				doh.Format = DOHMsgTypeRFC8484
			case DOHAcceptHeaderTypeJSON:
				doh.Format = DOHMsgTypeJSON
			default:
				doh.Format = DOHMsgTypeRFC8484
			}
		} else {
			doh.Format = DOHMsgTypeRFC8484
		}
	}

	if doh.Method == "" {
		doh.Method = http.MethodPost
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

	if !dot.DisableConnectionPool || dot.Pool != nil {
		if dot.Pool == nil {
			dot.Pool = &pool.Pool{}
		}
		if err := dot.Pool.Parse(); err != nil {
			return err
		}

		newConn := func() (*dns.Conn, error) {
			return dot.NewConn("tcp-tls")
		}
		closeConn := func(conn *dns.Conn) error {
			if conn == nil {
				return nil
			}
			return conn.Close()
		}

		cpt, err := dot.Pool.NewConnectionPool(newConn, closeConn)
		if err != nil {
			return err
		}
		xlog.Logger().Info().Str("log_type", "connection_pool").Str("op_type", "new").Str("protocol", "tcp").Str("server", dot.Server).Int("size", dot.Pool.Size).Int("requests", dot.Pool.Requests).Msg("")
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
			addrs := lookupIPs("ipv4", dns.Fqdn(host), nameservers)
			if len(addrs) == 0 {
				return server, host, fmt.Errorf("server '%s' no valid ip address found", server)
			}
			server = net.JoinHostPort(addrs[0], port)
		}
	}

	return server, host, err
}

// return: addrs, host, error
func parseURI(network string, uri string, nameservers []string) ([]string, string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return []string{}, "", err
	}

	var addrs []string
	hostname := u.Hostname()
	if ip := net.ParseIP(hostname); ip != nil {
		addrs = append(addrs, hostname)
	} else {
		addrs = lookupIPs(network, hostname, nameservers)
	}
	port := u.Port()
	if port != "" {
		for i := range addrs {
			addrs[i] = net.JoinHostPort(addrs[i], port)
		}
	}

	switch strings.ToLower(u.Scheme) {
	case "https", "http":
		for i := range addrs {
			u.Host = addrs[i]
			addrs[i] = u.String()
		}
	case "quic":
		if port == "" {
			for i := range addrs {
				addrs[i] = net.JoinHostPort(addrs[i], strconv.Itoa(defaultPortDoQ))
			}
		}
	case "dns":
		if port == "" {
			for i := range addrs {
				addrs[i] = net.JoinHostPort(addrs[i], strconv.Itoa(defaultPortDns))
			}
		}
	case "tls":
		if port == "" {
			for i := range addrs {
				addrs[i] = net.JoinHostPort(addrs[i], strconv.Itoa(defaultPortDoT))
			}
		}
	default:
		err = fmt.Errorf("invalid uri: %s, unsupport scheme", uri)
	}

	return addrs, hostname, err
}

func lookupIPs(network string, name string, nameservers []string) []string {
	if network == "" {
		network = "ipv4"
	}

	res := []string{}
	switch network[0] {
	case '4':
		res = lookupWithQtype(name, dns.TypeA, nameservers)
	case '6':
		res = lookupWithQtype(name, dns.TypeAAAA, nameservers)
	default:
		lock := new(sync.Mutex)
		qtypes := []uint16{dns.TypeA, dns.TypeAAAA}
		var wg sync.WaitGroup
		for i := range qtypes {
			wg.Add(1)
			go func(qtype uint16) {
				ips := lookupWithQtype(name, qtype, nameservers)
				lock.Lock()
				// make sure ipv4 first
				if qtype == dns.TypeA && len(res) > 0 {
					res = append(ips, res...)
				} else {
					res = append(res, ips...)
				}
				lock.Unlock()
				wg.Done()
			}(qtypes[i])
		}
		wg.Wait()
	}

	if len(res) == 0 {
		err := fmt.Errorf("domain %s hasn't any valid addresses", name)
		xlog.Logger().Error().Str("log_type", "main").Str("op_type", "lookupIP").Str("name", name).Strs("nameservers", nameservers).Str("network", network).Err(err).Msg("")
	}

	return res
}

func lookupWithQtype(name string, qtype uint16, nameservers []string) []string {
	nss := nameservers
	if len(nss) == 0 {
		nss = defaultExternalNameServers
	}

	ch := make(chan []string, len(nss))

	for i := range nss {
		go func(addr string) {
			for _, network := range []string{"udp", "tcp"} {
				client := &dns.Client{
					Net:     network,
					UDPSize: 1280,
					Timeout: 5 * time.Second,
				}
				r := new(dns.Msg)
				r.SetQuestion(dns.Fqdn(name), qtype)
				r, _, err := client.Exchange(r, addr)
				if err != nil {
					xlog.Logger().Error().Str("log_type", "init").Str("op_type", "lookupIP").Str("name", name).Uint16("qtype", qtype).Str("nameserver", addr).Err(err).Msg("")
					ch <- []string{}
					return
				}
				if r != nil && r.Truncated {
					continue
				}
				res := []string{}
				for _, ans := range r.Answer {
					rrType := ans.Header().Rrtype
					if rrType == dns.TypeA {
						if a, ok := ans.(*dns.A); ok {
							res = append(res, a.A.String())
						}
					} else if rrType == dns.TypeAAAA {
						if aaaa, ok := ans.(*dns.AAAA); ok {
							res = append(res, aaaa.String())
						}
					}
				}
				ch <- res

				break
			}
		}(nss[i])
	}

	res := []string{}
	for i := 0; i < cap(ch); i++ {
		addrs := <-ch
		res = append(res, addrs...)
	}
	return res
}
