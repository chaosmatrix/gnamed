package queryx

import (
	"fmt"
	"gnamed/configx"
	"gnamed/libnamed"
	"time"

	"github.com/miekg/dns"
)

func queryDoT(r *dns.Msg, dot *configx.DOTServer) (*dns.Msg, error) {
	logEvent := libnamed.Logger.Trace().Str("log_type", "query").Str("protocol", configx.ProtocolTypeDoT)
	logEvent.Uint16("id", r.Id).Str("name", r.Question[0].Name).Str("type", dns.TypeToString[r.Question[0].Qtype]).Str("network", "tcp-tls")

	var resp *dns.Msg
	var err error
	var rtt time.Duration

	if dot.ConnectionPool != nil {
		conn, _rtt, cached, _err := dot.ConnectionPool.Get()
		logEvent.Dur("connection_pool_latency", _rtt).Bool("connection_pool_hit", cached).Err(_err)
		if _err == nil {
			logEvent.Str("connection_pointer", fmt.Sprintf("%p", conn))
			resp, rtt, err = dot.Client.ExchangeWithConn(r, conn)
		}
		if _err != nil || err != nil {
			if conn != nil {
				// other side close connection
				conn.Close() // ignore error
			}
			// failed to get connection from pool or conn from pool invalid
			// retry with new conn
			resp, rtt, err = dot.Client.Exchange(r, dot.Server)
		} else {
			dot.ConnectionPool.Put(conn)
		}
	} else {
		resp, rtt, err = dot.Client.Exchange(r, dot.Server)
	}
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
