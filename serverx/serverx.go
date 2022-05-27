package serverx

import (
	"errors"
	"gnamed/configx"
	"gnamed/libnamed"
	"sync"
)

var cfg *configx.Config

var (
	ErrServerProtocolUnsupport = errors.New("protocol not implemented")
)

func Serve(config *configx.Config, wg *sync.WaitGroup) {
	// init golbal
	cfg = config

	sls := cfg.Server.Listen

	for i := 0; i < len(sls); i++ {
		logEvent := libnamed.Logger.Trace().Str("log_type", "server").Str("address", sls[i].Addr).Str("network", sls[i].Network).Str("protocol", sls[i].Protocol)
		switch sls[i].Protocol {
		case configx.ProtocolTypeDNS:
			serveDoD(sls[i], wg)
		case configx.ProtocolTypeDoH:
			serveDoH(sls[i], wg)
		default:
			logEvent.Err(ErrServerProtocolUnsupport)
		}
		logEvent.Msg("")
	}

	als := cfg.Admin.Listen
	for i := 0; i < len(als); i++ {
		serveAdmin(als[i], wg)
		libnamed.Logger.Trace().Str("log_type", "admin").Str("address", als[i].Addr).Str("network", als[i].Network).Str("protocol", als[i].Protocol).Msg("")
	}
}
