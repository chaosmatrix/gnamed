package queryx

import (
	"gnamed/configx"

	"github.com/miekg/dns"
)

func queryDoD(r *dns.Msg, dod *configx.DODServer) error {
	resp := new(dns.Msg)
	var err error
	rmsg := r.Copy()
	for _, _net := range []string{configx.NetworkTypeUdp, configx.NetworkTypeTcp} {
		client := &dns.Client{
			// Default buffer size to use to read incoming UDP message
			// default 512 B
			UDPSize:        1024,
			Net:            _net,
			DialTimeout:    dod.Timeout.ConnectDuration,
			ReadTimeout:    dod.Timeout.ReadDuration,
			WriteTimeout:   dod.Timeout.WriteDuration,
			SingleInflight: true,
		}
		resp, _, err = client.Exchange(rmsg, dod.Server)
		if err != nil {
			return err
		}
		if resp.Truncated {
			// re-send via tcp
			continue
		}
		break
	}

	reply(r, resp)
	return nil
}
