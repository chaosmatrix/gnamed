package queryx

import (
	"gnamed/configx"
	"net"

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

// rfc: https://www.ietf.org/archive/id/draft-ietf-dnsop-svcb-https-10.html
func queryInterceptHTTPS(r *dns.Msg, hints []net.IP, view *configx.View) (*dns.Msg, error) {
	var err error
	rmsg := new(dns.Msg)
	rmsg.SetReply(r)

	h := new(dns.HTTPS)
	h.Priority = view.RrHTTPS.Priority
	h.Target = view.RrHTTPS.Target
	h.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: r.Question[0].Qclass, Ttl: 300}

	if view.RrHTTPS.Priority > 0 {
		if len(view.RrHTTPS.Alpn) > 0 {
			e := new(dns.SVCBAlpn)
			e.Alpn = view.RrHTTPS.Alpn
			h.Value = append(h.Value, e)
		}

		for _, ip := range hints {
			ipv4 := ip.To4()
			if ipv4 != nil {
				ipv4hint := new(dns.SVCBIPv4Hint)
				ipv4hint.Hint = []net.IP{ipv4}
				h.Value = append(h.Value, ipv4hint)
			} else {
				ipv6hint := new(dns.SVCBIPv6Hint)
				ipv6hint.Hint = []net.IP{ip}
				h.Value = append(h.Value, ipv6hint)
			}
		}
	}

	rmsg.Answer = []dns.RR{h}

	return rmsg, err
}
