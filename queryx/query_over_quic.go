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
func queryDoQ(dc *libnamed.DConnection, doq *configx.DOQServer) (*dns.Msg, error) {
	r := dc.IncomingMsg

	oId := r.Id
	r.Id = 0

	subEvent := dc.SubLog

	subEvent.Str("protocol", configx.ProtocolTypeDoQ).Str("network", "udp").
		Uint16("id", r.Id).Str("name", r.Question[0].Name)

	start := time.Now()

	defer func() {
		r.Id = oId
		subEvent.Dur("lantancy", time.Since(start))
	}()

	qconn, err := quic.DialAddr(doq.Server, doq.TlsConf, doq.QuicConf)
	if err != nil {
		subEvent.Err(err)
		return nil, err
	}
	defer qconn.CloseWithError(0, "")

	ctx, cancel := context.WithTimeout(context.Background(), doq.Timeout.ConnectDuration)
	stream, err := qconn.OpenStreamSync(ctx)
	cancel()
	if err != nil {
		subEvent.Err(err)
		return nil, err
	}
	defer stream.Close()
	subEvent.Int64("stream_id", int64(stream.StreamID()))

	bmsg, err := r.Pack()
	if err != nil {
		subEvent.Err(err)
		return nil, err
	}

	if !doq.Draft {
		// https://www.rfc-editor.org/rfc/rfc9250.html#section-4.2
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(len(bmsg)))
		buf = append(buf, bmsg...)
		bmsg = buf
		subEvent.Str("doq_version", "rfc9250")
	} else {
		subEvent.Str("doq_version", "draft")
	}

	_, err = stream.Write(bmsg)
	if err != nil {
		subEvent.Err(err)
		return nil, err
	}

	var bs []byte
	if bs, err = io.ReadAll(stream); err != nil {
		subEvent.Err(err)
		return nil, err
	}

	resp := new(dns.Msg)
	if doq.Draft {
		err = resp.Unpack(bs)
	} else if len(bs) < 2 {
		err = fmt.Errorf("message size %d < 2", len(bs))
	} else {
		err = resp.Unpack(bs[2:])
	}
	subEvent.Err(err)

	if err == nil {
		resp.Id = oId
	}
	return resp, err
}
