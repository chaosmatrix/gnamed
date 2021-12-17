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
	cfg = config

	for _, _listen := range config.Server.Listen {
		_logger := libnamed.Logger.Trace().Str("log_type", "server").Str("address", _listen.Addr).Str("network", _listen.Network).Str("protocol", _listen.Protocol)
		switch _listen.Protocol {
		case configx.ProtocolTypeDNS:
			serveDoD(_listen, wg)
		case configx.ProtocolTypeDoH:
			serveDoH(_listen, wg)
		default:
			_logger.Err(ErrServerProtocolUnsupport)
		}
		_logger.Msg("")
	}
}
