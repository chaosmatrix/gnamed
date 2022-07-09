package queryx

import (
	"fmt"
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
		if client == nil {
			continue
		}

		logEvent := libnamed.Logger.Trace().Str("log_type", "query").Str("protocol", configx.ProtocolTypeDNS)
		logEvent.Uint16("id", r.Id).Str("name", r.Question[0].Name).Str("type", dns.TypeToString[r.Question[0].Qtype]).Str("network", client.Net)

		if dod.ConnectionPoolTCP != nil {
			vconn, _rtt, cached, _err := dod.ConnectionPoolTCP.Get()
			conn, _ := vconn.(*dns.Conn)
			logEvent.Dur("connection_pool_latency", _rtt).Bool("connection_pool_hit", cached).Err(_err)
			if _err == nil {
				logEvent.Str("connection_pointer", fmt.Sprintf("%p", conn))
				resp, rtt, err = client.ExchangeWithConn(r, conn)
			}
			if _err != nil || err != nil {
				if conn != nil {
					// other side close connection
					conn.Close() // ignore error
				}
				resp, rtt, err = client.Exchange(r, dod.Server)
			} else {
				dod.ConnectionPoolTCP.Put(conn)
			}
		} else {
			resp, rtt, err = client.Exchange(r, dod.Server)
		}
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
