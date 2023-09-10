//go:build !noquic

package configx

import (
	"context"
	"crypto/tls"
	"errors"
	"gnamed/libnamed"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// DNS-over-QUIC
type DOQServer struct {
	Server string          `json:"server"`
	Draft  bool            `json:"draft"` // send message content to server in draft format, rather than rfc9250
	Pool   *ConnectionPool `json:"pool"`

	// if "Server" not a ip address, use this nameservers to resolve domain
	ExternalNameServers []string `json:"externalNameServers"`

	TlsConfig TlsConfig `json:"tls_config"`
	Timeout   Timeout   `json:"timeout"`

	// use internal
	TlsConf  *tls.Config  `json:"-"`
	QuicConf *quic.Config `json:"-"`
}

// FIXME: dot.Server was a config file, should not be change.
func (doq *DOQServer) parse() error {
	server, host, err := parseServer(doq.Server, doq.ExternalNameServers, defaultPortDoQ)
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

func (doh *DOHServer) initDoHClient() {
	if doh.HTTP3 {
		doh.client = doh.newClient("h3")
	} else {
		doh.client = doh.newClient("http/1.1")
	}
}

// Only detect once, and it base on the response latency
// if h3 server unable to response before timeout, or because some networking issue
// it will think that the server not support h3
func (doh *DOHServer) onceDetectALPN() {
	doh.altSvcOnce.Do(func() {
		start := time.Now()
		tlsc, err := doh.TlsConfig.parse()
		if err != nil {
			panic(err)
		}

		u, err := url.ParseRequestURI(doh.Url)
		if err != nil {
			panic(err)
		}
		ap := &libnamed.ALPHDetecter{
			TLSConf:   tlsc,
			WaitDelay: 1 * time.Second,
		}
		alpn, err := ap.DetectALPNFromURL(u)

		msg := ""
		if alpn == "" {
			msg = "unable detect ALPN, used http/1.1"
		}
		doh.client = doh.newClient(alpn)
		libnamed.Logger.Trace().Str("log_type", "query").Str("op_type", "detect_alpn").Str("url", doh.Url).Str("alpn", alpn).Dur("elapsed_time", time.Since(start)).Err(err).Msg(msg)
	})
}

func (doh *DOHServer) GetClient() *http.Client {
	if doh.HTTP3 && doh.client != nil {
		return doh.client
	}
	doh.onceDetectALPN()
	return doh.client
}

func (doh *DOHServer) newClient(alpn string) *http.Client {

	tlsc, err := doh.TlsConfig.parse()
	if err != nil {
		panic(err)
	}

	client := &http.Client{
		Timeout: doh.Timeout.ConnectDuration + doh.Timeout.ReadDuration + doh.Timeout.WriteDuration,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 2 {
				return errors.New("429 Too many redirect")
			}
			return nil
		},
	}

	// rand value to against fingerprints
	rn := rand.Int()&1 + 1
	tn := time.Duration(rand.Int()&1) * 5 * time.Second

	switch alpn {
	case "h3":
		// HTTP/3
		tr := &http3.RoundTripper{
			DisableCompression: true,
			//EnableDatagrams:    true,
			QuicConfig: &quic.Config{
				HandshakeIdleTimeout:    doh.Timeout.ConnectDuration + tn,
				MaxIdleTimeout:          doh.Timeout.IdleDuration + tn,
				KeepAlivePeriod:         (doh.Timeout.IdleDuration + tn) / 2,
				DisablePathMTUDiscovery: true,
				//EnableDatagrams:         true,
				MaxIncomingStreams:             100 * int64(rn),
				MaxIncomingUniStreams:          100 * int64(rn),
				InitialStreamReceiveWindow:     512 * 1024 * uint64(rn),
				InitialConnectionReceiveWindow: 512 * 1024 * uint64(rn),
			},
			TLSClientConfig: tlsc,
		}

		// Though REQ-5 in recommends a 2-minute timeout interval,
		// experience shows that sending packets every 30 seconds is necessary to
		// prevent the majority of middleboxes from losing state for UDP flows .
		if tr.QuicConfig.KeepAlivePeriod > 30*time.Second {
			tr.QuicConfig.KeepAlivePeriod = 30 * time.Second
		}

		client.Transport = tr
	case "h2":
		// HTTP/2
		tr := &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				d := &net.Dialer{
					Timeout:       doh.Timeout.ConnectDuration, // connect timeout
					KeepAlive:     65 * time.Second,
					FallbackDelay: -1, // disable DualStack test
				}
				td := tls.Dialer{
					NetDialer: d,
					Config:    cfg,
				}
				conn, err := td.DialContext(ctx, network, addr)
				if err == nil {
					err = setTCPSocketOpt(&conn, doh.SocketAttr)
					if err != nil {
						return conn, err
					}
				}
				return conn, err
			},
			TLSClientConfig:           tlsc,
			DisableCompression:        true, // dns message already compress
			AllowHTTP:                 false,
			MaxDecoderHeaderTableSize: 4096,
			MaxEncoderHeaderTableSize: 4096,
			MaxHeaderListSize:         10 << 20, // 10MB
			//MaxReadFrameSize: ,
			ReadIdleTimeout:  doh.Timeout.IdleDuration,
			WriteByteTimeout: doh.Timeout.WriteDuration,
			PingTimeout:      10 * time.Second,
		}
		client.Transport = tr
	default:
		// HTTP/1.1 HTTP/1.0 HTTP/0.x
		tr := &http.Transport{
			DisableCompression: true, // dns message already compress
			ForceAttemptHTTP2:  false,
			Proxy:              http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := &net.Dialer{
					Timeout:       doh.Timeout.ConnectDuration, // connect timeout
					KeepAlive:     65 * time.Second,
					FallbackDelay: -1, // disable DualStack test
				}
				conn, err := d.DialContext(ctx, network, addr)
				if err == nil {
					err = setTCPSocketOpt(&conn, doh.SocketAttr)
					if err != nil {
						return conn, err
					}
				}
				return conn, err
			},
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       tlsc,
			//MaxResponseHeaderBytes: 10 << 20, // 10KB
		}
		client.Transport = tr

	}
	return client
}
