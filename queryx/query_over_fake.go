package queryx

import (
	"gnamed/configx"

	"github.com/miekg/dns"
)

func queryFake(r *dns.Msg, nameserver *configx.NameServer) error {
	var err error
	r.Answer = []dns.RR{}
	r.Extra = []dns.RR{}
	r.Ns = []dns.RR{}
	return err
}
