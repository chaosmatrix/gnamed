package serverx

import (
	"crypto/tls"
	"gnamed/configx"
	"gnamed/libnamed"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func (srv *ServerMux) serveDoT(listen configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func(addr string, network string) {
		cert, err := tls.LoadX509KeyPair(listen.TlsConfig.CertFile, listen.TlsConfig.KeyFile)
		if err != nil {
			panic(err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		dos := &dns.Server{
			Addr:          listen.Addr,
			Net:           listen.Network,
			TLSConfig:     tlsConfig,
			MaxTCPQueries: listen.QueriesPerConn,
			IdleTimeout:   func() time.Duration { return listen.Timeout.IdleDuration },
			ReadTimeout:   listen.Timeout.ConnectDuration,
			WriteTimeout:  listen.Timeout.WriteDuration,
		}

		mux := dns.NewServeMux()
		mux.HandleFunc(".", handleDoDRequest)
		dos.Handler = mux

		var dnsSrvWaitGroup sync.WaitGroup
		dnsSrvWaitGroup.Add(1)
		go func() {
			defer dnsSrvWaitGroup.Done()
			err := dos.ListenAndServe()
			if err != nil {
				panic(err)
			}
		}()

		// shutdown listener
		srv.waitShutdownSignal()

		libnamed.Logger.Debug().Str("log_type", "server").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Msg("signal to shutdown server")
		err = dos.Shutdown()
		logEvent := libnamed.Logger.Debug().Str("log_type", "server").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Err(err)

		dnsSrvWaitGroup.Wait()
		wg.Done()
		logEvent.Msg("server has been shutdown")
	}(listen.Addr, listen.Network)
}
