package serverx

import (
	"gnamed/configx"
	"gnamed/libnamed"
	"sync"
	"time"

	"gnamed/queryx"

	"github.com/miekg/dns"
)

func handleDoDRequest(w dns.ResponseWriter, r *dns.Msg) {
	_logEvent := libnamed.Logger.Trace().Str("log_type", "server").Str("protocol", configx.ProtocolTypeDNS)
	rmsg, err := queryx.Query(r, cfg)
	_logEvent.Uint16("id", rmsg.Id).Str("name", rmsg.Question[0].Name).Str("type", dns.TypeToString[rmsg.Question[0].Qtype])
	_logEvent.Err(err).Msg("")
	w.WriteMsg(rmsg)
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
