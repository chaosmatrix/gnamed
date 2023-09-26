package configx

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
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

func TestServer(t *testing.T) {
	views := map[string]*View{
		".":                {Cname: "", NameServerTags: []string{"tag_default", "tag_default_1"}},
		"v.":               {Cname: "", NameServerTags: []string{"tag_com", "tag_com_1"}},
		"com.":             {Cname: "", NameServerTags: []string{"tag_com", "tag_com_1"}},
		"example.com.":     {Cname: "", NameServerTags: []string{"tag_com", "tag_com_1"}},
		"www.example.com.": {Cname: "", NameServerTags: []string{"tag_com", "tag_com_1"}},
		"cname.com.":       {Cname: "cname.com.", NameServerTags: []string{"tag_com", "tag_com_1"}},
		"www.cname.com.":   {Cname: "cname.com.", NameServerTags: []string{"tag_com", "tag_com_1"}},
		"net.":             {Cname: "", NameServerTags: []string{"tag_net", "tag_net_1"}},
	}
	nss := map[string]*NameServer{
		"tag_default":   {},
		"tag_default_1": {},
		"tag_com":       {},
		"tag_com_1":     {},
		"tag_net":       {},
		"tag_net_1":     {},
	}
	srv := &Server{
		View:       views,
		NameServer: nss,
	}

	type R struct {
		cname       string
		zone        string
		view        *View
		nameservers map[string]*NameServer
	}
	tss := map[string]R{
		".":                  {cname: "", zone: ".", view: views["."]},
		"v.":                 {cname: "", zone: "v.", view: views["."]},
		"m.":                 {cname: "", zone: ".", view: views["."]},
		"go.dev.":            {cname: "", zone: ".", view: views["."]},
		"pkg.go.dev.":        {cname: "", zone: ".", view: views["."]},
		"example-1.com.":     {cname: "", zone: "com.", view: views["com."]},
		"1-example.com.":     {cname: "", zone: "com.", view: views["com."]},
		"wwwexample.com.":    {cname: "", zone: "com.", view: views["com."]},
		"example.com.":       {cname: "", zone: "example.com.", view: views["example.com."]},
		"www1.example.com.":  {cname: "", zone: "example.com.", view: views["example.com."]},
		"www.example.com.":   {cname: "", zone: "www.example.com.", view: views["www.example.com."]},
		"1.www.example.com.": {cname: "", zone: "www.example.com.", view: views["www.example.com."]},
		"example.net.":       {cname: "", zone: "net.", view: views["net."]},
		"www.cname.com.":     {cname: "cname.com.", zone: "cname.com.", view: views["cname.com."]},
		"1.www.cname.com.":   {cname: "cname.com.", zone: "cname.com.", view: views["cname.com."]},
		"www2.cname.com.":    {cname: "cname.com.", zone: "cname.com.", view: views["cname.com."]},
		"cname.com.":         {cname: "", zone: "cname.com.", view: views["cname.com."]},
	}

	for name, ts := range tss {
		cname, zone, view, nameservers := srv.Find(name)
		if ts.cname != cname || ts.zone != zone {
			t.Errorf("[+] bug: name: %s match zone %s, not match zone: %s\n", name, zone, ts.zone)
		}

		equalNS := true
		for _, tag := range views[zone].NameServerTags {
			if nameservers[tag] != nss[tag] {
				equalNS = false
				break
			}
		}

		if len(views[zone].NameServerTags) != len(nameservers) || !equalNS {
			t.Errorf("[+] bug: name: %s match nameservers: %s, not match: %s\n", name, view.NameServerTags, views[zone].NameServerTags)
		}

		cname, vname := srv.FindRealName(name)
		if cname == name {
			cname = ""
		}
		if ts.cname != cname || ts.zone != vname {
			t.Errorf("[+] bug: name: %s match zone %s, not match zone: %s\n", name, vname, ts.zone)
		}

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

type Age struct {
	Age int
}
type Name struct {
	Name string
}
type Ev interface {
	Age | Name
}
type S[T Ev] struct {
	Value string `json:"value"`
	Ev    T      `json:"-"`
}

func TestJsonParse(t *testing.T) {

	sj := `{
		"value": "str",
		"ev": {"age": 1}
	}`

	s := &S[Age]{}

	json.Unmarshal([]byte(sj), s)
	fmt.Printf("%v\n", s.Ev)
}

func TestNetInterface(t *testing.T) {
	ifss, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	for _, ifs := range ifss {
		fmt.Printf("%#v\n", ifs)
		addrs, err := ifs.Addrs()
		if err != nil {
			t.Error(err)
		}
		for _, addr := range addrs {
			fmt.Printf("%s\n", addr)
		}
	}
}
