package queryx

import (
	"context"
	"gnamed/configx"
	"gnamed/libnamed"
	"io"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
)

func queryDoQ(r *dns.Msg, doq *configx.DOQServer) (*dns.Msg, error) {
	logEvent := libnamed.Logger.Trace().Str("log_type", "query").Str("protocol", configx.ProtocolTypeDoQ)
	logEvent.Uint16("id", r.Id).Str("name", r.Question[0].Name).Str("type", dns.TypeToString[r.Question[0].Qtype]).Str("network", "udp")
	start := time.Now()
	defer func() {
		logEvent.Dur("lantancy", time.Since(start)).Msg("")
	}()

	qconn, err := quic.DialAddr(doq.Server, doq.TlsConf, doq.QuicConf)
	if err != nil {
		logEvent.Err(err)
		return nil, err
	}
	stream, err := qconn.OpenStreamSync(context.Background())
	if err != nil {
		logEvent.Err(err)
		return nil, err
	}
	defer stream.Close()

	bmsg, err := r.Pack()
	if err != nil {
		logEvent.Err(err)
		return nil, err
	}

	_, err = stream.Write(bmsg)
	if err != nil {
		logEvent.Err(err)
		return nil, err
	}

	var bs []byte
	if bs, err = io.ReadAll(stream); err == nil {
		err = r.Unpack(bs)
	}
	logEvent.Err(err)
	return r, err
}
