package xhosts

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

type Record struct {
	Name string `json:"name"` // example, example.com
	Type string `json:"type"` // example, A
	TTL  int    `json:"ttl"`  // example, 60
	Data string `json:"data"` // example, 123.123.123.123
}

func (r *Record) parse() (dns.RR, error) {
	if r.TTL == 0 {
		r.TTL = 60
	} else if r.TTL < 0 {
		return nil, errors.New("invalid Record ttl")
	}
	s := fmt.Sprintf("%s\t%d\t%s\t%s\t%s", dns.Fqdn(r.Name), r.TTL, "IN", r.Type, r.Data)
	rr, err := dns.NewRR(s)
	return rr, err
}

type Hosts struct {
	RRs     []string                     `json:"rrs"`     // rr's  string format, example: "example.com.      60     IN      A       123.123.123.123"
	Records []*Record                    `json:"records"` // record
	table   map[string]map[uint16]dns.RR `json:"-"`
}

func (h *Hosts) Parse() error {
	return h.parse()
}

func (h *Hosts) parse() error {

	if len(h.RRs) > 0 || len(h.Records) > 0 {
		h.table = make(map[string]map[uint16]dns.RR)
	}
	for _, s := range h.RRs {
		if rr, err := dns.NewRR(s); err != nil {
			return err
		} else {
			h.addRRs([]dns.RR{rr})
		}
	}

	for _, r := range h.Records {
		if rr, err := r.parse(); err != nil {
			return err
		} else {
			h.addRRs([]dns.RR{rr})
		}
	}

	return nil
}

func (h *Hosts) addRRs(rrs []dns.RR) {
	for _, rr := range rrs {
		qname := rr.Header().Name
		qtype := rr.Header().Rrtype
		if h.table[qname] == nil {
			h.table[qname] = make(map[uint16]dns.RR)
		}
		h.table[qname][qtype] = rr
	}
}

func (h *Hosts) FakeMsg(r *dns.Msg) *dns.Msg {
	if len(h.table) == 0 || r == nil || len(r.Question) == 0 {
		return nil
	}

	qname := strings.ToLower(r.Question[0].Name)
	qtype := r.Question[0].Qtype

	if qr, found := h.table[qname]; found {
		if rr, found := qr[qtype]; found {
			rmsg := new(dns.Msg)
			rmsg.SetReply(r)
			rmsg.Answer = []dns.RR{rr}
			return rmsg
		}
	}
	return nil
}
