package serverx

import (
	"gnamed/configx"
	"gnamed/ext/bytespool"
	"gnamed/ext/types"
	"gnamed/ext/xlog"
	"sync"
	"time"

	"gnamed/queryx"

	"github.com/miekg/dns"
)

type dnsServerOpt struct {
	compress bool
}

func (ds *dnsServerOpt) handleDoDRequest(w dns.ResponseWriter, r *dns.Msg) {
	dc := &types.DConnection{
		OutgoingMsg: r,
		Log:         xlog.Logger().Info(),
	}

	clientip := getAddrIP(w.RemoteAddr())
	network := w.RemoteAddr().Network()
	logEvent := dc.Log.Str("log_type", "server").Str("protocol", configx.ProtocolTypeDNS).Str("network", network).Str("clientip", clientip)
	start := time.Now()

	cfg := configx.GetGlobalConfig()
	rmsg, err := queryx.Query(dc, cfg)
	if err != nil {
		logEvent.Err(err)
	}
	if rmsg != nil {
		rmsg.Compress = ds.compress
		if network == "udp" && rmsg.IsTsig() == nil {
			buf, off, reuse, err1 := bytespool.PackMsgWitBufSize(rmsg, 0, bytespool.MaskEncodeWithoutLength)
			if err1 != nil {
				logEvent.AnErr("pack_msg_error", err1)
			} else {
				// auto add length field in tcp
				_, err = w.Write(buf[:off])
				if reuse {
					bytespool.Put(buf)
				}
			}
		} else {
			if !rmsg.Compress {
				rmsg.Compress = rmsg.Len() >= 510
			}
			err = w.WriteMsg(rmsg)
		}
		logEvent.AnErr("write_error", err)
	}
	logEvent.Dur("latency", time.Since(start)).AnErr("server_error", w.Close()).Msg("")
}

func (srv *ServerMux) serveDoD(listen *configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		ds := dnsServerOpt{
			compress: !listen.DisableCompressMsg,
		}

		dos := &dns.Server{
			Addr:          listen.Addr,
			Net:           listen.Network,
			MaxTCPQueries: listen.QueriesPerConn,
			UDPSize:       1280,
			IdleTimeout:   func() time.Duration { return listen.Timeout.IdleDuration },
			ReadTimeout:   listen.Timeout.ConnectDuration,
			WriteTimeout:  listen.Timeout.WriteDuration,
		}
		mux := dns.NewServeMux()
		mux.HandleFunc(".", ds.handleDoDRequest)
		dos.Handler = mux

		srv.registerOnShutdown(func() {
			xlog.Logger().Info().Str("log_type", "server").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Msg("signal to shutdown server")
			err := dos.Shutdown()
			logEvent := xlog.Logger().Info().Str("log_type", "server").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Err(err)

			wg.Done()
			logEvent.Msg("server has been shutdown")
		})

		err := dos.ListenAndServe()
		if err != nil {
			panic(err)
		}

	}()
}
