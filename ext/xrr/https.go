package xrr

import (
	"net"

	"github.com/miekg/dns"
)

// HTTPS RRSet setting
type RrHTTPS struct {
	Priority uint16   `json:"priority"`
	Target   string   `json:"target"`
	Alpn     []string `json:"alpn"`
	Hijack   bool     `json:"hijack"` // QType HTTPS will be hijacked with configured
}

var (
	// RrHTTPS
	// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
	defaultRrHTTPSAlpn = []string{"h3", "h2", "http/1.1"}
)

func (h *RrHTTPS) Parse() error {
	return h.parse()
}

func (h *RrHTTPS) parse() error {
	// rules:
	// 1. priority == 0 is AliasMode, and must has Target set
	// 2. if alpn not empty, priority isn't AliasMode, and vice verse
	if (len(h.Target) == 0 || len(h.Alpn) > 0) && h.Priority <= 0 {
		h.Priority = 1
	}

	if h.Priority > 0 && len(h.Alpn) == 0 {
		h.Alpn = defaultRrHTTPSAlpn
	}

	h.Target = dns.Fqdn(h.Target)

	return nil
}

// rfc: https://www.ietf.org/archive/id/draft-ietf-dnsop-svcb-https-10.html
// fake dns HTTPS RR
func (h *RrHTTPS) FakeRR(r *dns.Msg, hints []net.IP) dns.RR {
	if r == nil || len(r.Question) == 0 || r.Question[0].Qtype != dns.TypeHTTPS {
		return nil
	}

	rr := new(dns.HTTPS)
	rr.Priority = h.Priority
	rr.Target = h.Target
	rr.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: r.Question[0].Qclass, Ttl: 300}

	if h.Priority > 0 {
		if len(h.Alpn) > 0 {
			e := new(dns.SVCBAlpn)
			e.Alpn = h.Alpn
			rr.Value = append(rr.Value, e)
		}

		ipv4hint := new(dns.SVCBIPv4Hint)
		ipv6hint := new(dns.SVCBIPv6Hint)
		for _, ip := range hints {
			ipv4 := ip.To4()
			if ipv4 != nil {
				ipv4hint.Hint = append(ipv4hint.Hint, ipv4)
			} else {
				ipv6hint.Hint = append(ipv6hint.Hint, ip)
			}
		}

		if len(ipv4hint.Hint) > 0 {
			rr.Value = append(rr.Value, ipv4hint)
		}
		if len(ipv6hint.Hint) > 0 {
			rr.Value = append(rr.Value, ipv6hint)
		}

	}
	return rr
}
