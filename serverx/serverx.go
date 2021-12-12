package serverx

import (
	"errors"
	"gnamed/configx"
	"gnamed/libnamed"
	"sync"
)

var cfg *configx.Config

func Serve(config *configx.Config, wg *sync.WaitGroup) {
	cfg = config

	for _, _listen := range config.Server.Listen {
		_logger := libnamed.Logger.Debug().Str("address", _listen.Addr).Str("network", _listen.Network).Str("protocol", _listen.Protocol)
		switch _listen.Protocol {
		case configx.ProtocolTypeDNS:
			_logger.Str("server_type", "dns")
			serveDoD(_listen, wg)
		default:
			_logger.Err(errors.New("Protocol Unsupport"))
		}
		_logger.Msg("")
	}
}
