package serverx

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"gnamed/configx"
	"gnamed/libnamed"
	"gnamed/queryx"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

const (
	// https://www.rfc-editor.org/rfc/rfc9250.html#section-4.2
	// doq max dns message size 65535 + 2 was the most safe size but increase memory usage
	// in most implementation and use case, 4096 + 2 should be enough
	// but in most real network, 1500 is the max MTU, dns query should not large than it
	// first 2-octet length field indicate the dns msg size in wire format
	// in draft version, unable to know reading dns message size
	// in rfc9250, able to use 2-octet field to get dns msg size
	maxDnsQueryMsgSize = dns.MaxMsgSize + 2
)

type quicServerOption struct {
	streamWriteTimeout time.Duration
	streamReadTimeout  time.Duration
	bytesPool          *sync.Pool
	maxAcceptedStream  int           // limit one connection accepted stream
	connIdleTimeout    time.Duration // connection idle timeout, if no new stream accept, close conn actively
}

func (qs *quicServerOption) handleConnection(conn quic.Connection) {
	defer conn.CloseWithError(0, "")
	var wg sync.WaitGroup

	for c := 0; c < qs.maxAcceptedStream; c++ {
		ctx, cancel := context.WithTimeout(conn.Context(), qs.connIdleTimeout)
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			// client close connection or idle timeout
			libnamed.Logger.Trace().Str("log_type", "server").Str("protocol", configx.ProtocolTypeDoQ).Str("connection", fmt.Sprintf("%p", conn)).Err(err).Msg("no more stream avaliable, connection idleTimeout or peer close it")
			cancel()
			break
		} else {
			cancel()
		}
		wg.Add(1)

		logEvent := libnamed.Logger.Debug().Str("log_type", "server").Str("protocol", configx.ProtocolTypeDoQ).Str("network", conn.RemoteAddr().Network()).Str("clientip", conn.RemoteAddr().String())

		go func(logEvent *zerolog.Event) {
			//logEvent.Str("stream_id", fmt.Sprintf("%d", stream.StreamID()))
			logEvent.Int64("stream_id", int64(stream.StreamID()))
			start := time.Now()

			qs.handleStream(stream, logEvent)

			logEvent.Dur("latency", time.Since(start)).Err(stream.Close()).Msg("")
			wg.Done()
		}(logEvent)
	}
	wg.Wait()
}

func (qs *quicServerOption) handleStream(stream quic.Stream, logEvent *zerolog.Event) error {
	buf := qs.bytesPool.Get().([]byte)
	defer qs.bytesPool.Put(buf)

	if err := stream.SetWriteDeadline(time.Now().Add(qs.streamReadTimeout)); err != nil {
		logEvent.Err(err)
		return err
	}
	n, err := stream.Read(buf)
	if err != nil {
		logEvent.Err(err)
		return err
	}

	draft := false
	pktLen := binary.BigEndian.Uint16(buf[:2])
	if pktLen == uint16(n-2) {
		logEvent.Str("doq_version", "rfc9250")
	} else {
		draft = true
		logEvent.Str("doq_version", "draft")
	}

	r := new(dns.Msg)
	if draft {
		if err = r.Unpack(buf[:n]); err != nil {
			logEvent.Err(err)
			stream.Write(replyServerFailure(r))
			return err
		}
	} else {
		if len(buf) < 2 {
			logEvent.Err(fmt.Errorf("message size %d < 2", len(buf)))
			return err
		}
		if err = r.Unpack(buf[2:n]); err != nil {
			logEvent.Err(err)
			stream.Write(replyServerFailure(r))
			return err
		}
	}

	cfg := getGlobalConfig()
	resp, err := queryx.Query(r, cfg, logEvent)
	if err != nil {
		logEvent.Err(err)
		return err
	}
	bmsg, err := resp.Pack()
	if err != nil {
		logEvent.Err(err)
		return err
	}

	if !draft {
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(len(bmsg)))
		buf = append(buf, bmsg...)
		bmsg = buf
	}

	if err := stream.SetWriteDeadline(time.Now().Add(qs.streamWriteTimeout)); err != nil {
		logEvent.Err(err)
		return err
	}
	stream.Write(bmsg)
	return nil
}

func serveDoQ(listen configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func(addr string, network string) {
		cert, err := tls.LoadX509KeyPair(listen.TlsConfig.CertFile, listen.TlsConfig.KeyFile)
		if err != nil {
			panic(err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"doq-i02", "doq-i00", "dq", "doq"},
		}
		qlisten, err := quic.ListenAddr(addr, tlsConfig, nil)
		if err != nil {
			panic(err)
		}

		// https://tools.ietf.org/id/draft-madi-dnsop-udp4dns-00.html
		// 1232 recommended for dual-stack
		// 1500 should be enough
		bytesPool := &sync.Pool{
			New: func() interface{} {
				return make([]byte, maxDnsQueryMsgSize)
			},
		}

		qs := quicServerOption{
			streamWriteTimeout: listen.Timeout.WriteDuration,
			streamReadTimeout:  listen.Timeout.ReadDuration,
			bytesPool:          bytesPool,
			maxAcceptedStream:  listen.QuerysPerConn,
			connIdleTimeout:    listen.Timeout.IdleDuration,
		}
		for {
			qconn, err := qlisten.Accept(context.Background())
			if err != nil {
				libnamed.Logger.Error().Str("log_type", "server").Str("protocol", configx.ProtocolTypeDoQ).Err(err).Msg("")
				continue
			}

			go qs.handleConnection(qconn)
		}
		wg.Done()
	}(listen.Addr, listen.Network)
}

func replyServerFailure(r *dns.Msg) []byte {
	if r == nil || len(r.Question) == 0 {
		return []byte{}
	}
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Opcode = dns.RcodeServerFailure

	bmsg, err := resp.Pack()
	if err != nil {
		return []byte{}
	}

	return bmsg
}
