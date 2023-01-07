package queryx

import (
	"gnamed/configx"
	"gnamed/libnamed"
	"time"
	"unsafe"

	"github.com/miekg/dns"
)

func queryDoT(dc *libnamed.DConnection, dot *configx.DOTServer) (*dns.Msg, error) {

	r := dc.IncomingMsg

	subEvent := dc.SubLog

	subEvent.Str("protocol", configx.ProtocolTypeDoT).Str("network", "tcp-tls")
	subEvent.Uint16("id", r.Id).Str("name", r.Question[0].Name)

	var resp *dns.Msg
	var err error
	var rtt time.Duration

	if dot.ConnectionPool != nil {
		ce, _rtt, cached, _err := dot.ConnectionPool.Get()

		subEvent.Dur("connection_pool_latency", _rtt).Bool("connection_pool_hit", cached).AnErr("connection_pool_error", _err)
		if _err == nil {
			subEvent.Uint64("connection_pointer", *(*uint64)(unsafe.Pointer(&ce.Conn)))
			resp, rtt, err = dot.Client.ExchangeWithConn(r, ce.Conn)
			if err != nil {
				ce.Conn.Close()
				ce.Conn = nil
			}
			dot.ConnectionPool.Put(ce)
		} else {
			var conn *dns.Conn
			conn, err = dot.NewConn(dot.Client.Net)
			if err == nil {
				resp, rtt, err = dot.Client.ExchangeWithConn(r, conn)
				conn.Close()
			} else {
				subEvent.Err(err)
			}
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

	return resp, err
}
