//go:build !noquic

package hyper

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/sync/singleflight"
)

// hyper - httper
// 1. detect and auto select newest http protocol
// 2. against http or tls fingerprint

type HyperTransport struct {
	//client     *http.Client
	//onceAltSvc *sync.Once
}

const (
	// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
	AlpnHTTP11 = "http/1.1"
	AlpnHTTP2  = "h2"
	AlpnHTTP3  = "h3"
)

var _DefaultTLSCipherSuites = []uint16{}

func init() {
	_DefaultTLSCipherSuites = getCipherSuites()
}

var alpnToIndex = map[string]int{
	"h3":       3,
	"h2":       2,
	"http/1.1": 1,
}

// wrap http.Client support h3, h2, http/1.1 auto detect, and always choice the newest
type HyperClient struct {
	CheckRedirect func(req *http.Request, via []*http.Request) error
	Jar           http.CookieJar
	Timeout       time.Duration

	TLSConf  *tls.Config
	QUICConf *quic.Config // http3 only

	// disable cache req associated alpn
	// if true, every req need to detect ALPN
	DisableALPNCache bool

	// disable ALPN detect, every time send h3,h2,http/1.1 querys to server in paralle, then stop and use the first response
	// WARN: this use more resource
	DisableALPNDetect bool
	ParalleALPNs      []string // TODO

	// if zero, default to 300ms
	// if negative then wait until all detect connection timeout
	DetectWaitDelay time.Duration

	once         sync.Once
	altLock      sync.Mutex
	alts         sync.Map            // mapping host to alpn
	clients      []*http.Client      // alpn index *http.client
	singleflight *singleflight.Group // prevent paralle ALPN Detecte for same host
}

func (hc *HyperClient) Do(req *http.Request) (*http.Response, error) {

	hc.once.Do(func() {
		if len(hc.clients) == 0 {
			hc.clients = make([]*http.Client, 4)
		}
		if hc.singleflight == nil {
			hc.singleflight = &singleflight.Group{}
		}
	})

	addr := parseURLAddr(req.URL)

	if !hc.DisableALPNCache {
		if v, ok := hc.alts.Load(addr); ok {
			idx := v.(int)
			client := hc.clients[idx]
			return client.Do(req)
		}
	}

	v, err, _ := hc.singleflight.Do(addr, func() (interface{}, error) {
		ap := &ALPHDetecter{
			WaitDelay: 300 * time.Millisecond,
		}

		alpn, _ := ap.detectALPN(addr)
		if alpn == "" {
			alpn = AlpnHTTP11
		}
		return alpn, nil
	})

	alpn := AlpnHTTP11
	if err == nil {
		alpn = v.(string)
	}

	idx := alpnToIndex[alpn]

	hc.altLock.Lock()
	if client := hc.clients[idx]; client != nil {
		hc.altLock.Unlock()
		return client.Do(req)
	}

	client := &http.Client{
		CheckRedirect: hc.CheckRedirect,
		Jar:           hc.Jar,
		Timeout:       hc.Timeout,
	}
	client.Transport = newRoundTripper(alpn, hc.TLSConf, hc.QUICConf)

	hc.clients[idx] = client
	if !hc.DisableALPNCache {
		hc.alts.Store(addr, idx)
	}

	hc.altLock.Unlock()

	return client.Do(req)
}

// set alpn default http.Client
// alpn: h3, h2, http/1.1
func (hc *HyperClient) SetALPNClient(alpn string, client *http.Client) bool {
	idx, found := alpnToIndex[alpn]
	if !found {
		return false
	}
	hc.altLock.Lock()
	defer hc.altLock.Unlock()
	hc.clients[idx] = client
	return true
}

func (hc *HyperClient) DeleteALPNCahe(u *url.URL) bool {
	addr := parseURLAddr(u)
	_, ok := hc.alts.LoadAndDelete(addr)
	return ok
}

func (hc *HyperClient) CloseIdleConnections() {
	hc.altLock.Lock()
	defer hc.altLock.Unlock()
	for i := range hc.clients {
		if hc.clients[i] != nil {
			go hc.clients[i].CloseIdleConnections()
		}
	}
}

func NewClient(alpn string, tlsConf *tls.Config, quicConf *quic.Config) *http.Client {
	return newClient(alpn, tlsConf, quicConf)
}

func newClient(alpn string, tlsConf *tls.Config, quicConf *quic.Config) *http.Client {

	client := &http.Client{
		Transport: newRoundTripper(alpn, tlsConf, quicConf),
		Timeout:   60 * time.Second,
	}
	return client
}

func newRoundTripper(alpn string, tlsConf *tls.Config, quicConf *quic.Config) http.RoundTripper {

	switch alpn {
	case AlpnHTTP3:
		// HTTP/3
		tr := &http3.RoundTripper{
			//DisableCompression: true,
			//EnableDatagrams:    true,
			QuicConfig:      quicConf,
			TLSClientConfig: tlsConf,
		}

		if tr.QuicConfig == nil {
			tr.QuicConfig = &quic.Config{
				DisablePathMTUDiscovery: true,
				//EnableDatagrams:         true,
				MaxIncomingStreams:             100,
				MaxIncomingUniStreams:          100,
				InitialStreamReceiveWindow:     512 * 1024,
				InitialConnectionReceiveWindow: 512 * 1024,
			}
		}

		// Though REQ-5 in recommends a 2-minute timeout interval,
		// experience shows that sending packets every 30 seconds is necessary to
		// prevent the majority of middleboxes from losing state for UDP flows .
		if tr.QuicConfig.KeepAlivePeriod > 30*time.Second {
			tr.QuicConfig.KeepAlivePeriod = 30 * time.Second
		}
		return tr
	case AlpnHTTP2:
		// HTTP/2
		return &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				d := &net.Dialer{
					KeepAlive:     65 * time.Second,
					FallbackDelay: -1, // disable DualStack test
				}
				td := tls.Dialer{
					NetDialer: d,
					Config:    cfg,
				}
				conn, err := td.DialContext(ctx, network, addr)
				return conn, err
			},
			TLSClientConfig: tlsConf,
			//DisableCompression:        true,
			AllowHTTP:                 false,
			MaxDecoderHeaderTableSize: 4096,
			MaxEncoderHeaderTableSize: 4096,
			MaxHeaderListSize:         10 << 20, // 10MB
			PingTimeout:               10 * time.Second,
		}
	default:
		// HTTP/1.1 HTTP/1.0 HTTP/0.x
		return &http.Transport{
			//DisableCompression: true,
			//DisableKeepAlives: true,
			ForceAttemptHTTP2: false,
			Proxy:             http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := &net.Dialer{
					KeepAlive:     65 * time.Second,
					FallbackDelay: -1, // disable DualStack test
				}
				conn, err := d.DialContext(ctx, network, addr)
				return conn, err
			},
			MaxIdleConns:          10,
			IdleConnTimeout:       65 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       tlsConf,
		}
	}
}

var schemeToPort = map[string]string{
	"http":  "80",
	"https": "443",
}

func parseURLAddr(u *url.URL) string {
	if u == nil {
		return ""
	}

	if schemeToPort[u.Scheme] == "" {
		return u.Host
	}

	host := u.Host
	if host == "" {
		return ""
	} else if host[len(host)-1] == ']' {
		return host + ":" + schemeToPort[u.Scheme]
	} else if strings.LastIndex(host, ":") > 0 {
		return host
	} else {
		return host + ":" + schemeToPort[u.Scheme]
	}
}

func getCipherSuites() []uint16 {
	css := tls.CipherSuites()

	csID := make([]uint16, len(css))
	for i, cs := range css {
		csID[i] = cs.ID
	}

	return csID
}

type ALPHDetecter struct {
	TLSConf   *tls.Config
	QUICConf  *quic.Config
	WaitDelay time.Duration // zero or negative: wait all completed, positive: wait duration after first responsed
	Timeout   time.Duration // timeout for both TLS-TCP and QUIC-TLS, default 5s

	// default false
	// only work for domain not ip
	// WARNING:
	// 1. when using insecure dns protocol which is not tls, this Record Type might be hijack by ISP, then response incorrect value
	// 2. dns system isn't real-time, there might be a situation that server disable some ALPN, but some dns server cache incorrect value
	UseHTTPRr  bool
	Nameserver string // when UseHTTPRr, must set nameserver
}

func (ap *ALPHDetecter) CloneTLSConf() *tls.Config {
	if ap.TLSConf == nil {
		return nil
	}
	return ap.TLSConf.Clone()
}

func (ap *ALPHDetecter) CloneQUICConf() *quic.Config {
	if ap.QUICConf == nil {
		return nil
	}
	return ap.QUICConf.Clone()
}

func (ap *ALPHDetecter) DetectALPNFromURL(u *url.URL) (string, error) {
	return ap.detectALPNFromURL(u)
}

func (ap *ALPHDetecter) detectALPNFromURL(u *url.URL) (string, error) {
	if u == nil {
		return "", errors.New("invalid value: nil")
	}
	addr := parseURLAddr(u)
	return ap.detectALPN(addr)
}

// Try to detect the newest HTTP VERSION supported
func (ap *ALPHDetecter) DetectALPN(addr string) (string, error) {
	return ap.detectALPN(addr)
}

var (
	errWaitDelayTimeout = errors.New("timeout to wait another response")
)

// Try to detect the newest HTTP VERSION supported
func (ap *ALPHDetecter) detectALPN(addr string) (string, error) {

	type alpnResp struct {
		alpn string
		err  error
	}

	ch := make(chan *alpnResp, 2)

	go func() {
		alpn, err := detectALPNH3(ap.Timeout, addr, ap.CloneTLSConf(), ap.CloneQUICConf())
		ch <- &alpnResp{alpn: alpn, err: err}
	}()
	go func() {

		alpn, err := detectALPNH21(ap.Timeout, addr, ap.CloneTLSConf())
		ch <- &alpnResp{alpn: alpn, err: err}
	}()
	alpn := ""
	var err error

	var timer *time.Timer = nil
	var v *alpnResp
	for i := 0; i < cap(ch); i++ {
		if timer == nil {
			v = <-ch
		} else {
			select {
			case <-timer.C:
				return alpn, errWaitDelayTimeout
			case v = <-ch:
				//
			}
		}
		switch v.alpn {
		case AlpnHTTP3:
			return v.alpn, v.err
		case "":
			//
		default:
			alpn = v.alpn
			err = v.err
		}
		if ap.WaitDelay > 0 {
			timer = time.NewTimer(ap.WaitDelay)
		}
	}
	return alpn, err
}

var (
	errIPNotValidDomain = errors.New("unable to parse valid domain from ip address")
)

// TODO:
// 1. support much more ways to do dns query
// 2. support detect system default nameserver and use it
func detectALPNWithHTTPRr(timeout time.Duration, addr string, nameserver string) (string, error) {
	if len(addr) == 0 || addr[0] == '[' {
		return "", errIPNotValidDomain
	}
	qname := addr
	i := strings.LastIndex(addr, ":")
	if i > 0 {
		qname = addr[:i]
	}
	if _, err := netip.ParseAddr(qname); err == nil {
		return "", errIPNotValidDomain
	}

	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	r, err := hyperDnsLookup(timeout, qname, dns.TypeHTTPS, nameserver)
	if err != nil {
		return "", err
	}

	alpn := ""
	for _, ans := range r.Answer {
		if ans.Header().Rrtype == dns.TypeHTTPS {
			if h, ok := ans.(*dns.HTTPS); ok {
				for _, v := range h.Value {
					if v.Key() == dns.SVCB_ALPN {
						alpns := v.String()
						// return the first in order
						if i := strings.Index(alpns, ","); i > 0 {
							return alpns[:i], nil
						}
						return alpns, nil
					}
				}
			}
		}
	}

	return alpn, nil
}

func detectALPNH21(timeout time.Duration, addr string, tlsConf *tls.Config) (string, error) {
	// can only detect h2 or http/1.1
	// unable detect h3, cause it use udp, quic
	alpn := ""

	if tlsConf == nil {
		tlsConf = &tls.Config{
			CipherSuites: _DefaultTLSCipherSuites,
			NextProtos:   []string{AlpnHTTP2, AlpnHTTP11},
		}
	} else {
		if len(tlsConf.NextProtos) == 0 {
			tlsConf.NextProtos = []string{AlpnHTTP2, AlpnHTTP11}
		}
		if len(tlsConf.CipherSuites) == 0 {
			tlsConf.CipherSuites = _DefaultTLSCipherSuites
		}
	}

	if tlsConf.ServerName == "" {
		i := strings.LastIndex(addr, ":")
		if addr[0] == '[' {
			tlsConf.ServerName = addr[1 : i-1]
		} else {
			tlsConf.ServerName = addr[:i]
		}
	}

	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	d := &net.Dialer{
		Timeout:       timeout,
		FallbackDelay: -1,
		KeepAlive:     -1,
	}

	conn, err := tls.DialWithDialer(d, "tcp", addr, tlsConf)
	if err != nil {
		return alpn, err
	}
	defer conn.Close()

	err = conn.Handshake()
	if err != nil {
		return alpn, err
	}

	alpn = conn.ConnectionState().NegotiatedProtocol
	return alpn, nil
}

func detectALPNH3(timeout time.Duration, addr string, tlsConf *tls.Config, quicConf *quic.Config) (string, error) {
	if quicConf == nil {
		quicConf = &quic.Config{
			HandshakeIdleTimeout:    5 * time.Second,
			DisablePathMTUDiscovery: true,
		}
	}

	if tlsConf == nil {
		tlsConf = &tls.Config{
			NextProtos: []string{AlpnHTTP3},
		}
	} else {
		if len(tlsConf.NextProtos) == 0 {
			tlsConf.NextProtos = []string{AlpnHTTP3}
		}
	}

	if tlsConf.ServerName == "" {
		i := strings.LastIndex(addr, ":")
		if addr[0] == '[' {
			tlsConf.ServerName = addr[1 : i-1]
		} else {
			tlsConf.ServerName = addr[:i]
		}
	}

	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	alpn := ""
	errChan := make(chan error)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	go func() {
		conn, err := quic.DialAddr(ctx, addr, tlsConf, quicConf)
		if err != nil {
			errChan <- err
			return
		}
		defer conn.CloseWithError(0, "")

		state := conn.ConnectionState()

		if state.TLS.HandshakeComplete {
			alpn = state.TLS.NegotiatedProtocol
		}
		errChan <- nil
	}()

	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-errChan:
	}

	return alpn, err
}

// nameserver format: <scheme>://<addr>
// for example:
// 1. https://dns.example/dns-query
// 2. udp://1.2.3.4:53 or tcp://1.2.3.4:53 or tcp-tls://1.2.3.4:853
func hyperDnsLookup(timeout time.Duration, name string, qtype uint16, nameserver string) (*dns.Msg, error) {

	u, err := url.Parse(nameserver)
	if err != nil {
		return nil, fmt.Errorf("invalid nameserver format, %s", nameserver)
	}

	network := strings.ToLower(u.Scheme)
	addr := u.Host

	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	r := new(dns.Msg)
	r.SetQuestion(dns.Fqdn(name), qtype)

	switch network {
	case "https":
		r.Id = 0
		hc := &HyperClient{
			DisableALPNCache: true,
			Timeout:          timeout,
		}
		bs, err := r.Pack()
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest(http.MethodPost, nameserver, bytes.NewReader(bs))
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		//defer resp.Body.Close()
		//defer hc.CloseIdleConnections()

		rbs := make([]byte, 512)
		n, err := resp.Body.Read(rbs)
		if err != nil {
			return nil, err
		}

		rmsg := new(dns.Msg)
		err = rmsg.Unpack(rbs[:n])

		return rmsg, err

	case "quic":
		r.Id = 0
		buf := make([]byte, 514)
		bs, err := r.PackBuffer(buf[2:])
		if err != nil {
			return nil, err
		}
		if len(bs) > len(buf)-2 {
			buf = append(make([]byte, 2), bs...)
		} else {
			buf = buf[:len(bs)+2]
		}
		binary.BigEndian.PutUint16(buf, uint16(len(bs)))

		quicConf := &quic.Config{
			DisablePathMTUDiscovery: true,
			HandshakeIdleTimeout:    timeout,
		}

		tlsConf := &tls.Config{
			ServerName: strings.Split(addr, ":")[0],
			NextProtos: []string{"doq"},
		}
		conn, err := quic.DialAddr(context.Background(), addr, tlsConf, quicConf)
		if err != nil {
			return nil, err
		}
		defer conn.CloseWithError(0, "")
		qs, err := conn.OpenStreamSync(context.TODO())
		if err != nil {
			return nil, err
		}
		defer qs.Close()
		qs.SetDeadline(time.Now().Add(timeout))
		n, err := qs.Write(buf)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, errors.New("unable to send data to peer")
		}

		rbs, err := io.ReadAll(qs)
		//n, err = qs.Read(bs)
		if err != nil {
			return nil, err
		}
		rmsg := new(dns.Msg)
		err = rmsg.Unpack(rbs[2:])
		return r, err
	default:
		client := dns.Client{
			Net:     network,
			Timeout: timeout,
		}
		r, _, err := client.Exchange(r, addr)
		return r, err
	}

}
