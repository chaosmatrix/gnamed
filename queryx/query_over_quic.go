//go:build !noquic

package queryx

import (
	"context"
	"gnamed/configx"
	"gnamed/ext/bytespool"
	"gnamed/ext/types"
	"time"

	"github.com/miekg/dns"
)

// TODO:
// 1. reuse connection
// 2. group more querys into one connection, use different stream
func queryDoQ(dc *types.DConnection, doq *configx.DOQServer) (*dns.Msg, error) {
	r := dc.OutgoingMsg

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

	qconn, err := doq.GetConnection()
	if err != nil {
		return nil, err
	}

	buf, off, reuse, err := bytespool.PackMsgWitBufSize(r, 0, bytespool.MaskEncodeWithLength)
	if err != nil {
		subEvent.Err(err)
		return nil, err
	}

	if reuse {
		defer func() { bytespool.Put(buf) }()
	}
	bmsg := buf[:off]

	if doq.Draft {
		bmsg = bmsg[2:]
		subEvent.Str("doq_version", "draft")
	} else {
		// https://www.rfc-editor.org/rfc/rfc9250.html#section-4.2
		subEvent.Str("doq_version", "rfc9250")
	}

	ctx, cancel := context.WithTimeout(context.Background(), doq.Timeout.ConnectDuration)
	stream, err := qconn.OpenStreamSync(ctx)
	defer cancel()
	if err != nil {
		subEvent.Err(err)
		return nil, err
	}
	defer stream.Close()
	subEvent.Int64("stream_id", int64(stream.StreamID()))

	stream.SetWriteDeadline(time.Now().Add(doq.Timeout.WriteDuration))
	_, err = stream.Write(bmsg)
	if err != nil {
		subEvent.Err(err)
		return nil, err
	}

	if reuse {
		bytespool.Put(buf)
		buf = nil
	}

	stream.SetReadDeadline(time.Now().Add(doq.Timeout.ReadDuration))
	rmsg, _, err := bytespool.UnpackMsgWitBufSize(stream, 512, bytespool.MaskEncodeWithLength)
	if err != nil {
		subEvent.Err(err)
		return nil, err
	}

	if rmsg != nil {
		rmsg.Id = oId
	}
	return rmsg, err
}
