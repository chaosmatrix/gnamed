//go:build !noquic

package serverx

import (
	"context"
	"gnamed/configx"
	"gnamed/ext/xlog"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func (srv *ServerMux) serveDoH(listen *configx.Listen, wg *sync.WaitGroup) {
	switch listen.Network {
	case "udp", "udpv4", "udpv6":
		srv.serveDoHHTTP3(listen, wg)
	default:
		srv.serveDoHHTTP12(listen, wg)
	}
}

func (srv *ServerMux) serveDoHHTTP12(listen *configx.Listen, wg *sync.WaitGroup) {
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

func (srv *ServerMux) serveDoHHTTP3(listen *configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		r := getHTTPHandler(listen)

		httpSrv := &http3.Server{
			Addr:      listen.Addr,
			Handler:   r,
			TLSConfig: listen.TLSConfig,
			QuicConfig: &quic.Config{
				DisablePathMTUDiscovery: true,
				HandshakeIdleTimeout:    listen.Timeout.ConnectDuration,
				MaxIdleTimeout:          listen.Timeout.IdleDuration,
			},
		}

		srv.registerOnShutdown(func() {
			xlog.Logger().Info().Str("log_type", "server").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Msg("signal to shutdown server")
			err := httpSrv.Close()
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
