//go:build !noquic

package queryx

import (
	"context"
	"encoding/binary"
	"fmt"
	"gnamed/configx"
	"gnamed/libnamed"
	"io"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
)

// TODO:
// 1. reuse connection
// 2. group more querys into one connection, use different stream
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
	defer qconn.CloseWithError(0, "")

	ctx, cancel := context.WithTimeout(context.Background(), doq.Timeout.ConnectDuration)
	stream, err := qconn.OpenStreamSync(ctx)
	cancel()
	if err != nil {
		logEvent.Err(err)
		return nil, err
	}
	defer stream.Close()
	logEvent.Int64("stream_id", int64(stream.StreamID()))

	bmsg, err := r.Pack()
	if err != nil {
		logEvent.Err(err)
		return nil, err
	}

	if !doq.Draft {
		// https://www.rfc-editor.org/rfc/rfc9250.html#section-4.2
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(len(bmsg)))
		buf = append(buf, bmsg...)
		bmsg = buf
		logEvent.Str("doq_version", "rfc9250")
	} else {
		logEvent.Str("doq_version", "draft")
	}

	_, err = stream.Write(bmsg)
	if err != nil {
		logEvent.Err(err)
		return nil, err
	}

	// if resp refer to r, call (*dns.Msg)SetReply(*dns.Msg), will clean Questions Section
	// for example, response message Questions become (qtype and qclass show incorrect):
	// example.com.     CLASS0   None
	resp := new(dns.Msg)
	resp.SetReply(r)
	var bs []byte
	if bs, err = io.ReadAll(stream); err != nil {
		logEvent.Err(err)
		return resp, err
	}

	if doq.Draft {
		err = resp.Unpack(bs)
	} else if len(bs) < 2 {
		err = fmt.Errorf("message size %d < 2", len(bs))
	} else {
		err = resp.Unpack(bs[2:])
	}
	logEvent.Err(err)
	return resp, err
}
