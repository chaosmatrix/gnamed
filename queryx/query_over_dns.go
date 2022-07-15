package queryx

import (
	"gnamed/configx"
	"gnamed/libnamed"
	"time"
	"unsafe"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

func queryDoD(dc *libnamed.DConnection, dod *configx.DODServer) (*dns.Msg, error) {

	r := dc.IncomingMsg
	logEvent := dc.Log

	resp := new(dns.Msg)
	var err error
	var rtt time.Duration = 0

	eventArr := zerolog.Arr()
	subEvent := zerolog.Dict()
	for _, client := range []*dns.Client{dod.ClientUDP, dod.ClientTCP} {
		if client == nil {
			continue
		}

		subEvent.Str("protocol", configx.ProtocolTypeDNS).Str("server", dod.Server).Str("network", dod.Network).
			Uint16("id", r.Id).Str("name", r.Question[0].Name)

		if dod.ConnectionPoolTCP != nil {
			vconn, _rtt, cached, _err := dod.ConnectionPoolTCP.Get()
			conn, _ := vconn.(*dns.Conn)
			subEvent.Dur("connection_pool_latency", _rtt).Bool("connection_pool_hit", cached).Err(_err)
			if _err == nil {

				subEvent.Uint64("connection_pointer", *(*uint64)(unsafe.Pointer(&conn)))
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
		subEvent.Dur("latency", rtt)
		if err != nil {
			break
		}
		if resp.Truncated {
			// re-send via tcp
			subEvent.Bool("truncated", true).Err(err)
			eventArr.Dict(subEvent)
			subEvent = zerolog.Dict()
			continue
		}
		break
	}

	subEvent.Err(err)
	eventArr.Dict(subEvent)
	logEvent.Array("queries", eventArr)

	return resp, err
}
