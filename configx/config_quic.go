//go:build !noquic

package configx

import (
	"crypto/tls"
	"strings"

	"github.com/lucas-clemente/quic-go"
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
