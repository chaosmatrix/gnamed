//go:build noquic

package serverx

import (
	"context"
	"gnamed/configx"
	"gnamed/ext/xlog"
	"net/http"
	"sync"
)

func (srv *ServerMux) serveDoH(listen *configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		r := getHTTPHandler(listen)

		httpSrv := &http.Server{
			Addr:         listen.Addr,
			Handler:      r,
			IdleTimeout:  listen.Timeout.IdleDuration,
			ReadTimeout:  listen.Timeout.ReadDuration,
			WriteTimeout: listen.Timeout.WriteDuration,
		}

		srv.registerOnShutdown(func() {
			xlog.Logger().Info().Str("log_type", "server").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Msg("signal to shutdown server")
			err := httpSrv.Shutdown(context.Background())
			logEvent := xlog.Logger().Info().Str("log_type", "server").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Err(err)

			wg.Done()
			logEvent.Msg("server has been shutdown")
		})

		if listen.TlsConfig.CertFile == "" {
			err := httpSrv.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				panic(err)
			}
		} else {
			err := httpSrv.ListenAndServeTLS(listen.TlsConfig.CertFile, listen.TlsConfig.KeyFile)
			if err != nil && err != http.ErrServerClosed {
				panic(err)
			}
		}
	}()
}
