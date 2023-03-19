//go:build noquic

package configx

// DNS-over-QUIC
type DOQServer struct {
}

// FIXME: dot.Server was a config file, should not be change.
func (doq *DOQServer) parse() error {
	return nil
}
