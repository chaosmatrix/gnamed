package serverx

import (
	"context"
	"gnamed/configx"
	"net/http"
	_ "net/http/pprof"
	"sync"
)

func (srv *ServerMux) serveProf(listen configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		httpSrv := &http.Server{
			Addr:         "127.0.0.1:36060",
			Handler:      nil,
			IdleTimeout:  listen.Timeout.IdleDuration,
			ReadTimeout:  listen.Timeout.ReadDuration,
			WriteTimeout: listen.Timeout.WriteDuration,
		}

		srv.registerOnShutdown(func() {
			httpSrv.Shutdown(context.Background())
		})

		err := httpSrv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			panic(err)
		}
		wg.Done()
	}()
}
