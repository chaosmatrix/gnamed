package queryx

import (
	"crypto/tls"
	"gnamed/configx"

	"github.com/miekg/dns"
)

func queryDoT(r *dns.Msg, dot *configx.DOTServer) (*dns.Msg, error) {
	tlsConfig := &tls.Config{
		ServerName: dot.TlsConfig.ServerName,
	}
	client := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,

		DialTimeout:    dot.Timeout.ConnectDuration,
		ReadTimeout:    dot.Timeout.ReadDuration,
		WriteTimeout:   dot.Timeout.WriteDuration,
		SingleInflight: true,
	}
	resp, _, err := client.Exchange(r, dot.Server)
	if err != nil {
		rmsg := new(dns.Msg)
		rmsg.SetReply(r)
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, err
	}
	return resp, nil
}
