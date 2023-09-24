package hyper

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDetectAlpn(t *testing.T) {
	tss := [][]string{
		{"tcp", "quic.nginx.org:443"},
		{"tcp", "www.bing.com:443"},
	}

	ap := &ALPHDetecter{
		WaitDelay: 300 * time.Millisecond,
	}
	for _, ts := range tss {
		alpn, err := ap.detectALPN(ts[1])
		fmt.Printf("%s => %s => %v\n", ts[1], alpn, err)
	}
}

func TestHyperClientDo(t *testing.T) {
	tss := [][]string{
		{"https://quic.nginx.org/", "h3"},
		{"https://www.bing.com/", "h2"},
		{"https://pkg.go.dev/", "h2"},
		{"https://o0.pages.dev/Lite/domains.txt", "h3"},
		{"https://phishing.army/download/phishing_army_blocklist_extended.txt", "h3"},
	}

	h := &HyperClient{
		Timeout: 10 * time.Second,
	}
	var wg sync.WaitGroup
	wg.Add(len(tss))
	for i := range tss {
		go func(i int) {
			ts := tss[i]
			req, _ := http.NewRequest(http.MethodGet, ts[0], nil)
			req.Header.Set("Accept-Encoding", "gzip")
			resp, err := h.Do(req)
			if err != nil {
				fmt.Printf("[+] url: %s, error: %s\n", ts, err)
			} else {
				io.Copy(io.Discard, resp.Body)
				fmt.Printf("[+] url: %s, status_code: %d, proto: %s\n", ts, resp.StatusCode, resp.Proto)
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
}

func TestQUICTLS(t *testing.T) {

	tlsConf := &tls.Config{
		ServerName: "1.0.0.1",
	}
	conn, err := tls.Dial("tcp", "1.0.0.1:443", tlsConf)
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()

	hosts := []string{
		"2606:4700:4700::1111",
		"[2606:4700:4700::1111]",
		"1.0.0.1",
		"one.one.one.one",
	}
	for _, host := range hosts {
		err = conn.VerifyHostname(host)
		if err != nil {
			fmt.Printf("%s - %v\n", host, err)
		} else {
			fmt.Printf("%s verifye pass\n", host)
		}
	}

	hps := []string{
		"2606:4700:4700::1111:443",
		"[2606:4700:4700::1111]:443",
		"1.0.0.1:443",
		"one.one.one.one:443",
	}
	for _, hp := range hps {
		h, p, err := net.SplitHostPort(hp)
		fmt.Printf("%s %s %v\n", h, p, err)
	}
}

func BenchmarkHostSplit(b *testing.B) {
	for i := 0; i < b.N; i++ {
		net.SplitHostPort("[2606:4700:4700::1111]:443")
	}
}

func BenchmarkHostIndex(b *testing.B) {
	host := "[2606:4700:4700::1111]:443"
	for i := 0; i < b.N; i++ {
		j := strings.LastIndex(host, ":")
		if j > 0 {
			host = host[:j]
		}
	}
}

func TestDetectALPNWithHTTPRr(t *testing.T) {
	alpn, err := detectALPNWithHTTPRr(5*time.Second, "v2ex.com:443", "udp://127.0.0.1:53")
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("%s %v\n", alpn, err)
}

func TestHyperDnsLookup(t *testing.T) {

	type Ts struct {
		name       string
		qtype      uint16
		nameserver string
	}

	tss := []*Ts{
		{name: "go.dev", qtype: dns.TypeA, nameserver: "udp://127.0.0.1:53"},
		{name: "go.dev", qtype: dns.TypeA, nameserver: "tcp://127.0.0.1:53"},
		{name: "go.dev", qtype: dns.TypeA, nameserver: "https://1.0.0.1/dns-query"},
		{name: "go.dev", qtype: dns.TypeA, nameserver: "quic://94.140.14.140:784"},
	}
	for _, ts := range tss {
		_, err := hyperDnsLookup(5*time.Second, ts.name, ts.qtype, ts.nameserver)
		if err != nil {
			t.Errorf("%s -> %v", ts.nameserver, err)
		}
	}
}
