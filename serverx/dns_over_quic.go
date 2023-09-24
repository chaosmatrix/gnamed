//go:build !noquic

package serverx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"gnamed/configx"
	"gnamed/ext/bytespool"
	"gnamed/ext/types"
	"gnamed/ext/xlog"
	"gnamed/queryx"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

type quicServerOption struct {
	streamWriteTimeout time.Duration
	streamReadTimeout  time.Duration
	maxAcceptedStream  int           // limit one connection accepted stream
	connIdleTimeout    time.Duration // connection idle timeout, if no new stream accept, close conn actively
	compressMsg        bool          // compress response dns message
}

func (qs *quicServerOption) handleConnection(cid int64, conn quic.Connection) {
	defer conn.CloseWithError(0, "")
	var streamWaitGroup sync.WaitGroup

	network := conn.RemoteAddr().Network()
	clientip := conn.RemoteAddr().String()
	localip := conn.LocalAddr().String()

	for c := 0; c < qs.maxAcceptedStream; c++ {

		ctx, cancel := context.WithTimeout(conn.Context(), qs.connIdleTimeout)
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			// client close connection or idle timeout
			xlog.Logger().Debug().Str("log_type", "server").Str("protocol", configx.ProtocolTypeDoQ).Str("network", network).Int64("connection_id", cid).Str("localip", localip).Str("clientip", clientip).Err(err).Msg("close connection")
			cancel()
			return
		} else {
			cancel()
		}

		streamWaitGroup.Add(1)
		go func(stream quic.Stream) {
			dc := &types.DConnection{
				OutgoingMsg: nil,
				Log:         xlog.Logger().Info(),
			}
			dc.Log.Str("log_type", "server").Str("protocol", configx.ProtocolTypeDoQ).Str("network", network).Int64("connection_id", cid).Str("localip", localip).Str("clientip", clientip).Int64("stream_id", int64(stream.StreamID()))
			start := time.Now()

			qs.handleStream(stream, dc)

			dc.Log.Dur("latency", time.Since(start)).Msg("")
			streamWaitGroup.Done()
		}(stream)
	}
	streamWaitGroup.Wait()
}

func (qs *quicServerOption) handleStream(stream quic.Stream, dc *types.DConnection) error {
	logEvent := dc.Log
	defer func() {
		logEvent.Err(stream.Close())
	}()

	if err := stream.SetReadDeadline(time.Now().Add(qs.streamReadTimeout)); err != nil {
		logEvent.Err(err)
		return err
	}

	r, lfmask, err := bytespool.UnpackMsgWitBufSize(stream, 128, bytespool.MaskEncodeWithOptionalLength)
	if err != nil {
		logEvent.Err(err)
		return err
	}

	// TODO:
	// 1. alpn in draft version must containt "-"
	// 2. alpn in RFC9250 must bet "doq"
	switch lfmask {
	case bytespool.MaskEncodeWithoutLength:
		logEvent.Str("receive_doq_version", "draft")
	case bytespool.MaskEncodeWithLength:
		logEvent.Str("receive_doq_version", "RFC9250")
	default:
		err := fmt.Errorf("invalid LengthFieldMask: %d", lfmask)
		logEvent.Str("receive_doq_version", "unknow").Err(err)
		return err
	}

	dc.OutgoingMsg = r

	cfg := configx.GetGlobalConfig()
	resp, err := queryx.Query(dc, cfg)
	if err != nil {
		logEvent.Err(err)
		return err
	}

	resp.Compress = qs.compressMsg

	buf, off, reuse, err := bytespool.PackMsgWitBufSize(resp, 0, lfmask)
	if err != nil {
		logEvent.Err(err)
		return err
	}
	if reuse {
		defer func() { bytespool.Put(buf) }()
	}
	bmsg := buf[:off]

	if err := stream.SetWriteDeadline(time.Now().Add(qs.streamWriteTimeout)); err != nil {
		logEvent.Err(err)
		return err
	}
	stream.Write(bmsg)
	return nil
}

func (srv *ServerMux) serveDoQ(listen *configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		if host, _, err := net.SplitHostPort(listen.Addr); err == nil {
			_ip := net.ParseIP(host)
			if _ip != nil && _ip.IsUnspecified() {
				err := errors.New("listen on unspecified address, packet receive and send address might be different")
				xlog.Logger().Warn().Str("log_type", "server").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Err(err).Msg("")
			}
		}

		if tlsc := listen.TLSConfig; tlsc != nil {
			if len(tlsc.NextProtos) == 0 {
				tlsc.NextProtos = []string{"doq-i02", "doq-i00", "dq", "doq"}
			}
			if tlsc.MinVersion < tls.VersionTLS13 {
				tlsc.MinVersion = tls.VersionTLS13
				if tlsc.MaxVersion < tlsc.MinVersion {
					tlsc.MaxVersion = tlsc.MinVersion
				}
			}
		}

		concurrencyStreams := int64(listen.QueriesPerConn) / 2
		if concurrencyStreams <= 0 {
			concurrencyStreams = int64(listen.QueriesPerConn)
		}
		keepAlivePeriod := listen.Timeout.IdleDuration / 2
		if keepAlivePeriod > 15*time.Second {
			keepAlivePeriod = 15 * time.Second
		}

		qConfig := &quic.Config{
			HandshakeIdleTimeout:             listen.Timeout.ConnectDuration,
			MaxIdleTimeout:                   listen.Timeout.IdleDuration,
			MaxIncomingStreams:               concurrencyStreams, // limit accepted streams, when reached, Accept call will block until idleTimeout
			MaxIncomingUniStreams:            -1,                 // disallow
			MaxStreamReceiveWindow:           dns.MaxMsgSize,
			MaxConnectionReceiveWindow:       uint64(dns.MaxMsgSize * listen.QueriesPerConn),
			MaxTokenAge:                      listen.Timeout.IdleDuration * 5,
			KeepAlivePeriod:                  keepAlivePeriod,
			DisablePathMTUDiscovery:          true,
			DisableVersionNegotiationPackets: true,
			Allow0RTT:                        true,
			EnableDatagrams:                  true,
		}

		qlisten, err := quic.ListenAddr(listen.Addr, listen.TLSConfig, qConfig)
		if err != nil {
			panic(err)
		}

		qs := &quicServerOption{
			streamWriteTimeout: listen.Timeout.WriteDuration,
			streamReadTimeout:  listen.Timeout.ReadDuration,
			maxAcceptedStream:  listen.QueriesPerConn,
			connIdleTimeout:    listen.Timeout.IdleDuration,
			compressMsg:        !listen.DisableCompressMsg,
		}

		srv.registerOnShutdown(func() {
			xlog.Logger().Info().Str("log_type", "server").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Msg("signal to shutdown server")
			err := qlisten.Close()
			logEvent := xlog.Logger().Info().Str("log_type", "server").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Err(err)

			wg.Done()
			logEvent.Msg("server has been shutdown")
		})

		var connWaitGroup sync.WaitGroup

		var connectionID int64 = 0
		for {
			//ctx, cancel := context.WithTimeout(context.Background(), qs.connIdleTimeout)
			ctx, cancel := context.WithCancel(context.Background())
			qconn, err := qlisten.Accept(ctx)
			if err != nil {
				xlog.Logger().Error().Str("log_type", "server").Str("protocol", configx.ProtocolTypeDoQ).Err(err).Msg("")
				if err == quic.ErrServerClosed {
					// active close listener
					cancel()
					break
				}
				// TODO, should always continue ?
				continue
			}
			connectionID++

			connWaitGroup.Add(1)
			go func(cid int64, conn quic.Connection) {
				qs.handleConnection(cid, conn)
				connWaitGroup.Done()
			}(connectionID, qconn)
		}
		connWaitGroup.Wait()

	}()
}
