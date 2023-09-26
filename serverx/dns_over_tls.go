package serverx

import (
	"gnamed/configx"
	"gnamed/ext/xlog"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func (srv *ServerMux) serveDoT(listen *configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {

		ds := dnsServerOpt{
			compress: !listen.DisableCompressMsg,
		}

		dos := &dns.Server{
			Addr:          listen.Addr,
			Net:           listen.Network,
			TLSConfig:     listen.TLSConfig,
			MaxTCPQueries: listen.QueriesPerConn,
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

			logEvent.Msg("server has been shutdown")
			wg.Done()
		})

		err := dos.ListenAndServe()
		if err != nil {
			panic(err)
		}
	}()
}
