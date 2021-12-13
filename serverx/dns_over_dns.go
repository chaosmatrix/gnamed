package serverx

import (
	"gnamed/configx"
	"sync"
	"time"

	"gnamed/queryx"

	"github.com/miekg/dns"
)

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	rmsg, _ := queryx.Query(r, cfg)
	w.WriteMsg(rmsg)
}

func serveDoD(listen configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func(addr string, network string) {
		// TODO: handle error
		serveDoDFunc(addr, network, handleRequest)
	}(listen.Addr, listen.Network)
}

func serveDoDFunc(addr string, network string, handleFunc func(dns.ResponseWriter, *dns.Msg)) error {

	dos := &dns.Server{
		Addr:        addr,
		Net:         network,
		IdleTimeout: getIdleTimeout,
	}

	dns.HandleFunc(".", handleFunc)
	return dos.ListenAndServe()
}

func getIdleTimeout() time.Duration {
	return 5 * time.Second
}
