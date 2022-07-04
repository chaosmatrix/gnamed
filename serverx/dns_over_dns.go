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

func serveDoD(listen configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func(addr string, network string) {
		// TODO: handle error
		err := serveDoDFunc(&listen, handleDoDRequest)
		if err != nil {
			panic(err)
		}
		wg.Done()
	}(listen.Addr, listen.Network)
}

func serveDoDFunc(listen *configx.Listen, handleFunc func(dns.ResponseWriter, *dns.Msg)) error {

	dos := &dns.Server{
		Addr:         listen.Addr,
		Net:          listen.Network,
		IdleTimeout:  getIdleTimeout,
		ReadTimeout:  listen.Timeout.ConnectDuration,
		WriteTimeout: listen.Timeout.WriteDuration,
	}
	dns.HandleFunc(".", handleFunc)
	return dos.ListenAndServe()
}

func getIdleTimeout() time.Duration {
	return 10 * time.Second
}
