package serverx

import (
	"gnamed/configx"
	"gnamed/libnamed"
	"net"
	"sync"
	"time"

	"gnamed/queryx"

	"github.com/miekg/dns"
)

func handleDoDRequest(w dns.ResponseWriter, r *dns.Msg) {
	clientip, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	logEvent := libnamed.Logger.Debug().Str("log_type", "server").Str("protocol", configx.ProtocolTypeDNS).Str("client_network", w.RemoteAddr().Network()).Str("clientip", clientip)
	start := time.Now()
	defer func() {
		logEvent.Dur("latency", time.Since(start)).AnErr("server_error", w.Close()).Msg("")
	}()

	cfg := getGlobalConfig()
	rmsg, err := queryx.Query(r, cfg, logEvent)
	if err != nil {
		logEvent.AnErr("query_error", err)
	}
	if rmsg != nil {
		err = w.WriteMsg(rmsg)
		logEvent.AnErr("write_error", err)
	}
}

func (srv *ServerMux) serveDoD(listen configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func(addr string, network string) {
		// TODO: handle error
		//err := serveDoDFunc(&listen, handleDoDRequest)

		dos := &dns.Server{
			Addr:          listen.Addr,
			Net:           listen.Network,
			MaxTCPQueries: listen.QueriesPerConn,
			IdleTimeout:   func() time.Duration { return listen.Timeout.IdleDuration },
			ReadTimeout:   listen.Timeout.ConnectDuration,
			WriteTimeout:  listen.Timeout.WriteDuration,
		}
		mux := dns.NewServeMux()
		mux.HandleFunc(".", handleDoDRequest)
		dos.Handler = mux
		//dns.HandleFunc(".", handleFunc)

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
		err := dos.Shutdown()
		logEvent := libnamed.Logger.Debug().Str("log_type", "server").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Err(err)

		dnsSrvWaitGroup.Wait()
		wg.Done()
		logEvent.Msg("server has been shutdown")
	}(listen.Addr, listen.Network)
}
