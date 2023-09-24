package configx

import (
	"github.com/miekg/dns"
)

// fallback:
// 1. define the rule that a query need to go into fallback
//

type FallBack struct {
	FileName string   `json:"filename"`
	Rrs      []string `json:"rrs"`
	Rcodes   []int    `json:"rcodes"`

	// internal use
	rrs    map[string]bool `json:"-"`
	rcodes map[int]bool    `json:"-"`
}

func (fb *FallBack) Match(msg *dns.Msg) (string, bool) {

	if msg == nil {
		return "", false
	}

	if _, found := fb.rcodes[msg.Rcode]; found {
		return "rcode_" + dns.RcodeToString[msg.Rcode], true
	}

	for _, ans := range msg.Answer {
		if a, ok := ans.(*dns.A); ok {
			as := a.A.String()
			if _, found := fb.rrs[as]; found {
				return "rr_" + as, found
			}
		} else if aaaa, ok := ans.(*dns.AAAA); ok {
			aaaas := aaaa.AAAA.String()
			if _, found := fb.rrs[aaaas]; found {
				return "rr_" + aaaas, true
			}
		}
	}

	return "", false
}
