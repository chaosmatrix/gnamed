package serverx

import (
	"context"
	"errors"
	"sync"

	"gnamed/configx"
	"gnamed/libnamed"
)

var (
	errServerProtocolUnsupport = errors.New("protocol not implemented")
)

const (
	envGinDisableLog = "GIN_DISABLELOG"
)

type ServerMux struct {
	lock         sync.Mutex
	shutdownChan chan struct{}
	shutdowns    []func()
	reloadFunc   func() error
}

func NewServerMux() *ServerMux {
	return &ServerMux{
		shutdownChan: make(chan struct{}, 1),
		shutdowns:    []func(){},
	}
}

// register funcs that will execute on shutdown
func (srv *ServerMux) RegisterOnShutdown(f func()) {
	srv.registerOnShutdown(f)
}

func (srv *ServerMux) registerOnShutdown(f func()) {
	srv.lock.Lock()
	srv.shutdowns = append(srv.shutdowns, f)
	srv.lock.Unlock()
}

func (srv *ServerMux) RegisterOnReload(f func() error) {
	srv.lock.Lock()
	srv.reloadFunc = f
	srv.lock.Unlock()
}

func (srv *ServerMux) Reload() error {
	if srv.reloadFunc != nil {
		return srv.reloadFunc()
	}
	return errors.New("reload function didn't register")
}

func (srv *ServerMux) Shutdown(ctx context.Context) error {
	srv.shutdownChan <- struct{}{}

	finishCh := make(chan struct{})
	go func() {
		srv.lock.Lock()
		for i := range srv.shutdowns {
			srv.shutdowns[i]()
		}
		srv.lock.Unlock()
		finishCh <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-finishCh:
		return nil
	}
}

// block until receive shutdown signal
func (srv *ServerMux) waitShutdownSignal() {
	<-srv.shutdownChan
	// refill to support call multi times
	srv.shutdownChan <- struct{}{}
}

func (srv *ServerMux) Serve(config *configx.Config, wg *sync.WaitGroup) {

	cfg := configx.GetGlobalConfig()

	sls := cfg.Server.Listen

	for i := 0; i < len(sls); i++ {
		logEvent := libnamed.Logger.Info().Str("log_type", "server").Str("address", sls[i].Addr).Str("network", sls[i].Network).Str("protocol", sls[i].Protocol)
		switch sls[i].Protocol {
		case configx.ProtocolTypeDNS:
			srv.serveDoD(sls[i], wg)
		case configx.ProtocolTypeDoH:
			srv.serveDoH(sls[i], wg)
		case configx.ProtocolTypeDoT:
			srv.serveDoT(sls[i], wg)
		case configx.ProtocolTypeDoQ:
			srv.serveDoQ(sls[i], wg)
		default:
			logEvent.Err(errServerProtocolUnsupport)
		}
		logEvent.Msg("")
	}

	als := cfg.Admin.Listen
	for i := 0; i < len(als); i++ {
		srv.serveAdmin(als[i], wg)
		libnamed.Logger.Info().Str("log_type", "admin").Str("address", als[i].Addr).Str("network", als[i].Network).Str("protocol", als[i].Protocol).Msg("")
	}

	// prof
	//srv.serveProf(config.Server.Listen[0], wg)
}
