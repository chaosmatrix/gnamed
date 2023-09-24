package queryx

import (
	"gnamed/configx"
	"gnamed/ext/types"
	"time"
	"unsafe"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

func queryDoD(dc *types.DConnection, dod *configx.DODServer) (*dns.Msg, error) {

	r := dc.OutgoingMsg
	//logEvent := dc.Log

	r.Compress = r.Compress || r.Len() >= 510

	var resp *dns.Msg
	var err error
	var rtt time.Duration = 0

	subEvent := dc.SubLog
	subEvent.Str("protocol", configx.ProtocolTypeDNS).Str("server", dod.Server).Str("network", dod.Network).
		Uint16("id", r.Id).Str("name", r.Question[0].Name)

	start := time.Now()
	for _, client := range []*dns.Client{dod.ClientUDP, dod.ClientTCP} {
		if client == nil {
			continue
		}

		if client.Net == "tcp" && dod.ConnectionPoolTCP != nil {
			ce, _rtt, cached, _err := dod.ConnectionPoolTCP.Get()

			poolLog := zerolog.Dict().Dur("latency", _rtt).Bool("hit", cached).Err(_err)
			if ce != nil {
				poolLog.Uint64("pointer", uint64(uintptr(unsafe.Pointer(&ce))))
			}
			subEvent.Dict("pool", poolLog)

			if _err == nil && ce.Conn != nil {
				resp, rtt, err = client.ExchangeWithConn(r, ce.Conn)
				if err != nil {
					ce.Conn.Close()
					ce.Conn = nil
				}
				dod.ConnectionPoolTCP.Put(ce)
			} else {
				var conn *dns.Conn
				conn, err = dod.NewConn(client.Net)
				if err == nil {
					resp, rtt, err = client.ExchangeWithConn(r, conn)
					conn.Close()
				} else {
					subEvent.Err(err)
				}
			}
		} else {
			var conn *dns.Conn
			conn, err = dod.NewConn(client.Net)
			if err == nil {
				resp, rtt, err = client.ExchangeWithConn(r, conn)
				conn.Close()
			}
		}

		if client.Net == "udp" {
			subEvent.Dur("udp_latency", rtt)
		} else {
			subEvent.Dur("tcp_latency", rtt)
		}
		if err != nil {
			break
		}
		if resp.Truncated {
			// re-send via tcp, should we let client do this ?
			subEvent.Bool("truncated", true).Err(err)
			continue
		}
		break
	}

	subEvent.Dur("latency", time.Since(start))
	subEvent.Err(err)

	return resp, err
}
