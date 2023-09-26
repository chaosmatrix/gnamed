package xhosts

import (
	"fmt"
	"testing"
)

func TestHosts(t *testing.T) {
	rrs := []string{
		"www.example.com. 60 IN A 123.123.123.123",
		"example.com.      300     IN      HTTPS   1 . alpn=\"h3,h2,http/1.1\"",
	}
	records := []*Record{
		{Name: "example.com", Type: "A", TTL: 60, Data: "123.123.123.123"},
	}
	h := &Hosts{
		RRs:     rrs,
		Records: records,
	}

	if err := h.Parse(); err != nil {
		panic(err)
	}

	for name, vs := range h.table {
		for qtype, rr := range vs {
			fmt.Printf("name: %s qtype: %d\n", name, qtype)
			fmt.Printf("%s\n", rr)
			fmt.Printf("\n")
		}
	}
}
