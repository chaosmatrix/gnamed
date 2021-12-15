package serverx

import (
	"gnamed/configx"
	"sync"
	"time"

	"gnamed/queryx"

	"github.com/miekg/dns"
)

func handleDoDRequest(w dns.ResponseWriter, r *dns.Msg) {
	rmsg, _ := queryx.Query(r, cfg)
	w.WriteMsg(rmsg)
}

func serveDoD(listen configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func(addr string, network string) {
		// TODO: handle error
		serveDoDFunc(addr, network, handleDoDRequest)
	}(listen.Addr, listen.Network)
}

func serveDoDFunc(addr string, network string, handleFunc func(dns.ResponseWriter, *dns.Msg)) error {

	dos := &dns.Server{
		Addr:         addr,
		Net:          network,
		IdleTimeout:  getIdleTimeout,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	dns.HandleFunc(".", handleFunc)
	return dos.ListenAndServe()
}

func getIdleTimeout() time.Duration {
	return 10 * time.Second
}
