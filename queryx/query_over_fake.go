package queryx

import (
	"gnamed/configx"

	"github.com/miekg/dns"
)

func queryFake(r *dns.Msg, nameserver *configx.NameServer) (*dns.Msg, error) {
	var err error
	rmsg := new(dns.Msg)
	rmsg.SetReply(r)
	rmsg.Answer = []dns.RR{}
	rmsg.Extra = []dns.RR{}
	rmsg.Ns = []dns.RR{}
	rmsg.Rcode = dns.RcodeNameError // NXDomain
	return rmsg, err
}
