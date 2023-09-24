package libnamed

import (
	"net"

	"github.com/miekg/dns"
)

type OPTOption struct {
	UDPSize       uint16
	EnableDNSSEC  bool   // Support DNEESE
	EnableECS     bool   // Support edns-client-subnet
	SourceIP      net.IP // Source IP Address
	Family        uint16
	SourceNetmask uint8 // Source Netmask 8 ~ 32
}

func SetOpt(r *dns.Msg, o *OPTOption) {
	if o == nil {
		return
	}

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT

	opt.SetUDPSize(o.UDPSize)

	if o.EnableECS {
		ecs := new(dns.EDNS0_SUBNET)

		ecs.Address = o.SourceIP
		ecs.Family = o.Family
		ecs.Code = dns.EDNS0SUBNET

		ecs.SourceNetmask = o.SourceNetmask

		opt.Option = append(opt.Option, ecs)
	}
	if o.EnableDNSSEC {
		opt.SetDo()
	}
	r.Extra = append(r.Extra, opt)
}
