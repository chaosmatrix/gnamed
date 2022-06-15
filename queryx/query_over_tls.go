package queryx

import (
	"gnamed/configx"
	"gnamed/libnamed"

	"github.com/miekg/dns"
)

func queryDoT(r *dns.Msg, dot *configx.DOTServer) (*dns.Msg, error) {
	logEvent := libnamed.Logger.Trace().Str("log_type", "query").Str("protocol", configx.ProtocolTypeDoT)
	logEvent.Uint16("id", r.Id).Str("name", r.Question[0].Name).Str("type", dns.TypeToString[r.Question[0].Qtype]).Str("network", "tcp-tls")

	resp, rtt, err := dot.Client.Exchange(r, dot.Server)
	logEvent.Dur("latency", rtt)
	if err != nil {
		logEvent.Err(err).Msg("")
		rmsg := new(dns.Msg)
		rmsg.SetReply(r)
		rmsg.Rcode = dns.RcodeServerFailure
		return rmsg, err
	}
	logEvent.Msg("")
	return resp, nil
}
