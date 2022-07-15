package serverx

import (
	"errors"
	"gnamed/configx"
	"gnamed/libnamed"
	"sync"
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
}

func NewServerMux() *ServerMux {
	return &ServerMux{
		shutdownChan: make(chan struct{}, 1),
		shutdowns:    []func(){},
	}
}

// register funcs that will execute on shutdown
func (srv *ServerMux) registerOnShutdown(f func()) {
	srv.lock.Lock()
	srv.shutdowns = append(srv.shutdowns, f)
	srv.lock.Unlock()
}

func (srv *ServerMux) Reload() error {
	logEvent := libnamed.Logger.Debug().Str("log_type", "server")
	_, err := updateGlobalConfig()
	logEvent.Err(err).Msg("reload config")
	return err
}

func (srv *ServerMux) Shutdown() error {
	srv.shutdownChan <- struct{}{}

	srv.lock.Lock()
	for i := range srv.shutdowns {
		srv.shutdowns[i]()
	}
	srv.lock.Unlock()
	return nil
}

// block until receive shutdown signal
func (srv *ServerMux) waitShutdownSignal() {
	<-srv.shutdownChan
	// refill to support call multi times
	srv.shutdownChan <- struct{}{}
}

func (srv *ServerMux) Serve(config *configx.Config, wg *sync.WaitGroup) {
	sc := &serverConfig{
		configs: make([]*configx.Config, 2),
		currId:  0,
		lock:    sync.Mutex{},
	}
	sc.configs[sc.currId] = config

	globalServerConfig = sc

	// init golbal
	cfg := config

	sls := cfg.Server.Listen

	for i := 0; i < len(sls); i++ {
		logEvent := libnamed.Logger.Trace().Str("log_type", "server").Str("address", sls[i].Addr).Str("network", sls[i].Network).Str("protocol", sls[i].Protocol)
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
		libnamed.Logger.Trace().Str("log_type", "admin").Str("address", als[i].Addr).Str("network", als[i].Network).Str("protocol", als[i].Protocol).Msg("")
	}
}
