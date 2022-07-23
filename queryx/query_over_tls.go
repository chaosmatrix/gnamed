package queryx

import (
	"gnamed/configx"
	"gnamed/libnamed"
	"time"
	"unsafe"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

func queryDoT(dc *libnamed.DConnection, dot *configx.DOTServer) (*dns.Msg, error) {

	r := dc.IncomingMsg

	subEvent := zerolog.Dict()

	subEvent.Str("protocol", configx.ProtocolTypeDoT).Str("network", "tcp-tls")
	subEvent.Uint16("id", r.Id).Str("name", r.Question[0].Name)

	var resp *dns.Msg
	var err error
	var rtt time.Duration

	if dot.ConnectionPool != nil {
		conn, _rtt, cached, _err := dot.ConnectionPool.Get()
		subEvent.Dur("connection_pool_latency", _rtt).Bool("connection_pool_hit", cached).AnErr("connection_pool_error", _err)
		if _err == nil {
			subEvent.Uint64("connection_pointer", *(*uint64)(unsafe.Pointer(&conn)))
			resp, rtt, err = dot.Client.ExchangeWithConn(r, conn)
		} else {
			conn, err = dot.NewConn(dot.Client.Net)
			if err == nil {
				resp, rtt, err = dot.Client.ExchangeWithConn(r, conn)
			} else {
				subEvent.Err(err)
			}
		}
		if err == nil {
			dot.ConnectionPool.Put(conn)
		} else if conn != nil {
			conn.Close()
		}
	} else {
		var conn *dns.Conn
		conn, err = dot.NewConn(dot.Client.Net)
		if err == nil {
			resp, rtt, err = dot.Client.ExchangeWithConn(r, conn)
			conn.Close()
		}
	}
	subEvent.Dur("latency", rtt)

	subEvent.Err(err)

	dc.Log.Array("quries", zerolog.Arr().Dict(subEvent))

	return resp, err
}
