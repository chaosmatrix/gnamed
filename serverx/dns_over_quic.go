package serverx

import (
	"context"
	"crypto/tls"
	"gnamed/configx"
	"gnamed/libnamed"
	"gnamed/queryx"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
)

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
				return make([]byte, 1500)
			},
		}

		for {
			qconn, err := qlisten.Accept(context.Background())
			if err != nil {
				libnamed.Logger.Error().Str("log_type", "server").Str("protocol", configx.ProtocolTypeDoQ).Err(err).Msg("")
				continue
			}

			go func(conn quic.Connection) {
				logEvent := libnamed.Logger.Debug().Str("log_type", "server").Str("protocol", configx.ProtocolTypeDoQ).Str("network", conn.RemoteAddr().Network()).Str("clientip", conn.RemoteAddr().String())
				start := time.Now()
				// BUG: latency incorrect, will always zero
				//defer logEvent.Dur("latency", time.Since(start)).Msg("")
				defer func() {
					logEvent.Dur("latency", time.Since(start)).Msg("")
				}()
				stream, err := conn.AcceptStream(qconn.Context())
				if err != nil {
					return
				}
				defer stream.Close()

				bs := bytesPool.Get().([]byte)

				// FIXME: handle size > len(bs)
				n, err := stream.Read(bs)
				if err != nil {
					logEvent.Err(err)
					return
				}
				r := new(dns.Msg)
				if err = r.Unpack(bs[:n]); err != nil {
					logEvent.Err(err)
					return
				}
				bytesPool.Put(bs)

				cfg := getGlobalConfig()
				resp, err := queryx.Query(r, cfg, logEvent)
				if err != nil {
					logEvent.Err(err)
					return
				}
				bmsg, err := resp.Pack()
				if err != nil {
					logEvent.Err(err)
					return
				}

				stream.Write(bmsg)
			}(qconn)
		}
		wg.Done()
	}(listen.Addr, listen.Network)
}
