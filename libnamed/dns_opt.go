package libnamed

import (
	"net"

	"github.com/miekg/dns"
)

const (
	// default 512 too small to transfer dns package with opt(ecs) in one
	// package
	defaultUDPSize = 1024
	minUDPSize     = 512
	maxUDPSize     = 4096

	defaultSNetmask = 24
	maxSNetmask     = 24 // for privacy
	minSNetmask     = 8
	defaultSScope   = 24
	maxSScope       = 24 // for privacy
	minSScope       = 8
)

type OPTOption struct {
	UDPSize       uint16
	EnableDNSSEC  bool   // Support DNEESE
	EnableECS     bool   // Support edns-client-subnet
	SourceIP      string // Source IP Address
	SourceNetmask uint8  // Source Netmask 8 ~ 32
	SourceScope   uint8  // Desire return netmask

}

func NewOPT(o *OPTOption) (opt *dns.OPT) {
	opt = new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	// default limit 512
	// when return msg large than 512,
	// will cause ErrTruncated(dns: failed to unpack truncated message)
	// recv msg buffer size, default 512 B
	udpSize := opt.UDPSize()
	if udpSize > maxUDPSize || udpSize < minUDPSize {
		opt.SetUDPSize(defaultUDPSize)
	} else {
		opt.SetUDPSize(o.UDPSize)
	}
	if o.EnableECS {
		opt = o.setECS(opt)
	}
	if o.EnableDNSSEC {
		opt.SetDo()
	}
	return
}

func (o *OPTOption) setECS(opt *dns.OPT) *dns.OPT {

	ecs := new(dns.EDNS0_SUBNET)

	ip := net.ParseIP(o.SourceIP)
	if len(ip) == net.IPv4len {
		// ipv4
		ecs.Family = 1
		ecs.Address = ip.To4()
	} else if len(ip) == net.IPv6len {
		// ipv6
		ecs.Family = 2
		ecs.Address = ip.To16()
	}
	ecs.Code = dns.EDNS0SUBNET
	if o.SourceNetmask < minSNetmask || o.SourceNetmask > maxSNetmask {
		ecs.SourceNetmask = defaultSNetmask
	} else {
		ecs.SourceNetmask = o.SourceNetmask
	}
	if o.SourceScope < minSScope || o.SourceScope > maxSScope {
		ecs.SourceScope = defaultSScope
	} else {
		ecs.SourceScope = o.SourceScope
	}
	opt.Option = append(opt.Option, ecs)
	return opt
}
