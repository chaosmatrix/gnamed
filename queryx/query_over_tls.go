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
		vconn, _rtt, cached, _err := dot.ConnectionPool.Get()
		conn, _ := vconn.(*dns.Conn)
		subEvent.Dur("connection_pool_latency", _rtt).Bool("connection_pool_hit", cached).Err(_err)
		if _err == nil {
			subEvent.Uint64("connection_pointer", *(*uint64)(unsafe.Pointer(&conn)))
			resp, rtt, err = dot.Client.ExchangeWithConn(r, conn)
		}
		if _err != nil || err != nil {
			if conn != nil {
				// other side close connection
				conn.Close() // ignore error
			}
			// failed to get connection from pool or conn from pool invalid
			// retry with new conn
			conn, err = dot.NewConn(dot.Client.Net)
			if err == nil {
				resp, rtt, err = dot.Client.ExchangeWithConn(r, conn)
				conn.Close()
			}
		} else {
			dot.ConnectionPool.Put(conn)
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
