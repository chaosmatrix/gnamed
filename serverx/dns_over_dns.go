package serverx

import (
	"errors"
	"gnamed/configx"
	"gnamed/libnamed"
	"net"
	"strings"
	"sync"
	"time"

	"gnamed/queryx"

	"github.com/miekg/dns"
)

func handleDoDRequest(w dns.ResponseWriter, r *dns.Msg) {
	dc := &libnamed.DConnection{
		OutgoingMsg: r,
		Log:         libnamed.Logger.Info(),
	}

	clientip, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	logEvent := dc.Log.Str("log_type", "server").Str("protocol", configx.ProtocolTypeDNS).Str("network", w.RemoteAddr().Network()).Str("clientip", clientip)
	start := time.Now()

	cfg := configx.GetGlobalConfig()
	rmsg, err := queryx.Query(dc, cfg)
	if err != nil {
		logEvent.Err(err)
	}
	if rmsg != nil {
		err = w.WriteMsg(rmsg)
		logEvent.AnErr("write_error", err)
	}
	logEvent.Dur("latency", time.Since(start)).AnErr("server_error", w.Close()).Msg("")
}

func (srv *ServerMux) serveDoD(listen configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func(addr string, network string) {
		if strings.HasPrefix(network, "udp") {
			if host, _, err := net.SplitHostPort(listen.Addr); err == nil {
				_ip := net.ParseIP(host)
				if _ip != nil && _ip.IsUnspecified() {
					err := errors.New("listen on unspecified address, packet receive and send address might be different")
					libnamed.Logger.Warn().Str("log_type", "server").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Err(err).Msg("")
				}
			}
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
		mux.HandleFunc(".", handleDoDRequest)
		dos.Handler = mux
		//dns.HandleFunc(".", handleFunc)

		srv.registerOnShutdown(func() {
			libnamed.Logger.Info().Str("log_type", "server").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Msg("signal to shutdown server")
			err := dos.Shutdown()
			logEvent := libnamed.Logger.Info().Str("log_type", "server").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Err(err)

			wg.Done()
			logEvent.Msg("server has been shutdown")
		})

		err := dos.ListenAndServe()
		if err != nil {
			panic(err)
		}

	}(listen.Addr, listen.Network)
}
