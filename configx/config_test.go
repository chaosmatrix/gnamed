package configx

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestFindNameServer(t *testing.T) {
	cfg, err := ParseConfig("./config.json")
	if err != nil {
		panic(err)
	}

	zones := []string{}
	for k := range cfg.Server.View {
		zones = append(zones, k)
	}

	sort.Slice(zones, func(i, j int) bool {
		return len(zones[i]) > len(zones[j])
	})

	// invalid domain prefix do search

	for i := 0; i < len(zones); i++ {
		domain := "a--b--c." + zones[i]
		_, vn := cfg.Server.FindRealName(domain)
		if vn != zones[i] {
			t.Errorf("[+] bug: domain '%s' should match view '%s', but not view '%s'\n", domain, zones[i], vn)
		}
		//fmt.Printf("[+] domain: '%s' view '%s' nameserver '%s\n", domain, vn, cfg.Server.View[vn].NameServerTag)
	}

}

func TestQuicHttp3(t *testing.T) {

	fw, err := os.OpenFile("../data/ssl_session_test.log", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
	if err != nil {
		t.Error(err)
	}

	// same RoundTripper using same udp port
	tr := &http3.RoundTripper{
		DisableCompression: true,
		//EnableDatagrams:    true,
		QuicConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       60 * time.Second,
			//KeepAlivePeriod:      30 * time.Second / 2,
			//EnableDatagrams:         true,
			MaxIncomingStreams:      8,
			MaxIncomingUniStreams:   8,
			DisablePathMTUDiscovery: true,
			//RequireAddressValidation: func(net.Addr) bool { return false },
		},
		TLSClientConfig: &tls.Config{
			ServerName:         "1.0.0.1",
			InsecureSkipVerify: false,
			KeyLogWriter:       fw,
		},
	}
	client := &http.Client{
		//Timeout:   60 * time.Second,
		Transport: tr,
	}

	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("GET", "https://1.0.0.1", nil)
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("[+] %d error: %v\n", i, err)
		} else {
			fmt.Printf("[+] %d status: %v\n", i, resp.Status)
		}

		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		time.Sleep(200 * time.Second)
	}
	tr.Close()

}

func TestXxx(t *testing.T) {
	ms := make([]map[string]bool, 2)
	ms[0] = make(map[string]bool)
	ms[1] = make(map[string]bool)

	ms[0]["0a"] = true
	ms[0]["0b"] = true

	m := ms[0]
	ms[0] = make(map[string]bool)
	fmt.Printf("%v\n", m)
	fmt.Printf("%v\n", ms[0])
}

// 10ns/op
func BenchmarkStringsEqualFold(b *testing.B) {
	s := "example.com.a"
	t := "Example.COM."
	for i := 0; i < b.N; i++ {
		strings.EqualFold(s, t)
	}
}

// 2.5ns/op
func BenchmarkStringsEqual(b *testing.B) {
	s := "example.com.a"
	t := "example.coM.a"
	for i := 0; i < b.N; i++ {
		_ = s == t
	}
}

// 9ns/op
func BenchmarkStringsIgnoreCase(b *testing.B) {
	s := "example.com.a"
	t := "Example.COM.a"
	for i := 0; i < b.N; i++ {
		stringIgnoreCase(s, t)
	}
}

func stringIgnoreCase(s string, t string) bool {
	if len(s) != len(t) {
		return false
	}

	for i := 0; i < len(s); i++ {
		if d := s[i] - t[i]; d == 0 || d == 32 {
			continue
		} else {
			return false
		}
	}
	return true
}
