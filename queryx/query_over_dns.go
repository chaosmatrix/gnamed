package queryx

import (
	"gnamed/configx"
	"gnamed/libnamed"
	"time"

	"github.com/miekg/dns"
)

func queryDoD(r *dns.Msg, dod *configx.DODServer) (*dns.Msg, error) {
	resp := new(dns.Msg)
	var err error
	var rtt time.Duration = 0
	for _, client := range []*dns.Client{dod.ClientUDP, dod.ClientTCP} {
		logEvent := libnamed.Logger.Trace().Str("log_type", "query").Str("protocol", configx.ProtocolTypeDNS)
		logEvent.Uint16("id", r.Id).Str("name", r.Question[0].Name).Str("type", dns.TypeToString[r.Question[0].Qtype]).Str("network", client.Net)

		resp, rtt, err = client.Exchange(r, dod.Server)
		logEvent.Dur("latency", rtt)
		if err != nil {
			logEvent.Err(err).Msg("")
			return resp, err
		}
		if resp.Truncated {
			// re-send via tcp
			logEvent.Bool("truncated", true).Msg("")
			continue
		}
		logEvent.Msg("")
		break
	}

	return resp, nil
}
