package queryx

import (
	"github.com/miekg/dns"
)

func queryFakeWithRR(r *dns.Msg, rr dns.RR) (*dns.Msg, error) {
	var err error
	rmsg := new(dns.Msg)
	rmsg.SetReply(r)

	if rr == nil {
		rmsg.Answer = []dns.RR{}
	} else {
		rmsg.Answer = []dns.RR{rr}
	}
	rmsg.Extra = []dns.RR{}
	rmsg.Ns = []dns.RR{}
	return rmsg, err
}
