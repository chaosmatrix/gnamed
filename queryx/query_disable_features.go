//go:build noquic

package queryx

import (
	"gnamed/configx"
	"gnamed/ext/types"
	"gnamed/ext/xerrs"

	"github.com/miekg/dns"
)

func queryDoQ(dc *types.DConnection, doq *configx.DOQServer) (*dns.Msg, error) {
	return nil, xerrs.ErrDisableQuic
}
