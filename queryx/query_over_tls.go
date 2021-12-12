package queryx

import (
	"crypto/tls"
	"gnamed/configx"

	"github.com/miekg/dns"
)

func queryDoT(r *dns.Msg, dot *configx.DOTServer) error {
	var err error
	rmsg := r.Copy()
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
	resp, _, err := client.Exchange(rmsg, dot.Server)
	if err != nil {
		return err
	}

	reply(r, resp)
	return nil
}
