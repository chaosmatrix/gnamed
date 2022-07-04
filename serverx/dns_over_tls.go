package serverx

import (
	"crypto/tls"
	"gnamed/configx"
	"sync"

	"github.com/miekg/dns"
)

func serveDoT(listen configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func(addr string, network string) {
		// TODO: handle error
		err := serveDoTFunc(&listen, handleDoDRequest)
		if err != nil {
			panic(err)
		}
		wg.Done()
	}(listen.Addr, listen.Network)
}

func serveDoTFunc(listen *configx.Listen, handleFunc func(dns.ResponseWriter, *dns.Msg)) error {
	cert, err := tls.LoadX509KeyPair(listen.TlsConfig.CertFile, listen.TlsConfig.KeyFile)
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	dos := &dns.Server{
		Addr:         listen.Addr,
		Net:          "tcp-tls",
		TLSConfig:    tlsConfig,
		IdleTimeout:  getIdleTimeout,
		ReadTimeout:  listen.Timeout.ConnectDuration,
		WriteTimeout: listen.Timeout.WriteDuration,
	}

	dns.HandleFunc(".", handleFunc)
	return dos.ListenAndServe()
}
