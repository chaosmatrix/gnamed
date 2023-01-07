package queryx

import (
	"gnamed/configx"
	"gnamed/libnamed"
	"time"
	"unsafe"

	"github.com/miekg/dns"
)

func queryDoD(dc *libnamed.DConnection, dod *configx.DODServer) (*dns.Msg, error) {

	r := dc.IncomingMsg
	//logEvent := dc.Log

	resp := new(dns.Msg)
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
			// no way to detect vconn already close
			// write data to "CLOSE_WAIT" is permited, error until read timeout
			ce, _rtt, cached, _err := dod.ConnectionPoolTCP.Get()
			//conn := ce.Conn

			subEvent.Dur("connection_pool_latency", _rtt).Bool("connection_pool_hit", cached).AnErr("connection_pool_error", _err)
			if _err == nil {
				subEvent.Uint64("connection_pointer", *(*uint64)(unsafe.Pointer(&ce.Conn)))
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
