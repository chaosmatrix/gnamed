package queryx

import (
	"gnamed/configx"
	"gnamed/ext/types"
	"time"
	"unsafe"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

func queryDoT(dc *types.DConnection, dot *configx.DOTServer) (*dns.Msg, error) {

	r := dc.OutgoingMsg

	subEvent := dc.SubLog

	subEvent.Str("protocol", configx.ProtocolTypeDoT).Str("network", "tcp-tls")
	subEvent.Uint16("id", r.Id).Str("name", r.Question[0].Name)

	var resp *dns.Msg
	var err error
	var rtt time.Duration

	if dot.ConnectionPool != nil {
		ce, _rtt, cached, _err := dot.ConnectionPool.Get()

		poolLog := zerolog.Dict().Dur("latency", _rtt).Bool("hit", cached).Err(_err)
		if ce != nil {
			poolLog.Uint64("pointer", uint64(uintptr(unsafe.Pointer(&ce))))
		}
		subEvent.Dict("pool", poolLog)

		if _err == nil {
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
