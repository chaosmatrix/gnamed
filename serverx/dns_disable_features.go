//go:build noquic

package serverx

import (
	"gnamed/configx"
	"gnamed/ext/xerrs"
	"sync"
)

// Dns-Over-Quic
func (srv *ServerMux) serveDoQ(listen *configx.Listen, wg *sync.WaitGroup) {
	panic(xerrs.ErrDisableQuic)
}
