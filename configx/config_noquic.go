//go:build noquic

package configx

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// DNS-over-QUIC
type DOQServer struct {
}

// FIXME: dot.Server was a config file, should not be change.
func (doq *DOQServer) parse() error {
	return nil
}

func (doh *DOHServer) initDoHClient() {
	doh.client = doh.newClient("h2")
}

func (doh *DOHServer) OnceDetectALPN() {
	doh.altSvcOnce.Do(func() {
		return
	})
}

func (doh *DOHServer) GetClient() *http.Client {
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

	tr := &http.Transport{
		DisableCompression: true, // dns message already compress
		ForceAttemptHTTP2:  true,
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
	}
	switch alpn {
	case "h2":
		tr.ForceAttemptHTTP2 = true
		client.Transport = tr
	default:
		tr.ForceAttemptHTTP2 = false
		client.Transport = tr
	}
	return client
}
