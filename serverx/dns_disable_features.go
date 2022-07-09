//go:build noquic

package serverx

import (
	"gnamed/configx"
	"gnamed/libnamed"
	"sync"
)

// Dns-Over-Quic
func serveDoQ(listen configx.Listen, wg *sync.WaitGroup) {
	panic(libnamed.ErrDisableQuic)
}
