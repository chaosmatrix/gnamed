//go:build noquic

package queryx

import (
	"gnamed/configx"
	"gnamed/libnamed"

	"github.com/miekg/dns"
)

func queryDoQ(r *dns.Msg, doq *configx.DOQServer) (*dns.Msg, error) {
	return nil, libnamed.ErrDisableQuic
}
