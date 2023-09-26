package iptree

import (
	"net"
	"testing"
)

func TestIPTree(t *testing.T) {
	tree := NewIPTree()
	ipnetS := []string{
		"127.0.0.1/8", "10.0.0.0/8", "10.129.0.0/9",
		"11.129.0.0/9", "11.129.0.0/10",
		"192.168.16.1/24", "192.168.16.232/30",
		"123.123.123.123/24",
		"123.123.123.123/32",
		"2001:df5:a980::/48",
		"2400:3f20::/32",
		"2400:45c0::/32",
		"2401:51a0::/32",
		"2401:51a0::/16",
		"1010:51a0::/16",
		//"10.10.0.0/16",
		//"0.0.0.0/0",
	}
	for i := 0; i < len(ipnetS); i++ {
		_, ipnet, err := net.ParseCIDR(ipnetS[i])
		if err == nil {
			tree.Insert(ipnet)
		}
		tree.InsertCIDR(ipnetS[i]) // double insert to test function
	}

	ts := map[string]string{
		"127.0.0.1":            "127.0.0.1/8",
		"127.0.0.2":            "127.0.0.1/8",
		"10.0.0.1":             "10.0.0.0/8",
		"10.10.0.1":            "10.0.0.0/8",
		"10.129.0.0":           "10.129.0.0/9",
		"11.129.0.0":           "11.129.0.0/10",
		"192.168.16.1":         "192.168.16.1/24",
		"192.168.16.232":       "192.168.16.232/30",
		"123.123.123.123":      "123.123.123.123/32",
		"123.123.123.120":      "123.123.123.123/24",
		"2001:df5:a980:1230::": "2001:df5:a980::/48",
		"2400:3f20:1230::":     "2400:3f20::/32",
		"2400:45c0:1230::":     "2400:45c0::/32",
		"2401:51a0:1230::":     "2401:51a0::/32",
		"2401:1230:1230::":     "2401:51a0::/16",
		"1010:1230:1230::":     "1010:51a0::/16",
	}

	for k, v := range ts {
		vip := net.ParseIP(k)
		if vip == nil {
			t.Errorf("[+] bug %s not valid ip\n", k)
		}
		_, vipnet, err := net.ParseCIDR(v)
		if err != nil {
			t.Errorf("[+] bug %s not valid cidr\n", v)
		}
		if rs := tree.SearchLongest(vip); rs.String() != vipnet.String() {
			t.Errorf("[+] bug ip %s should match %s, but %s found\n", k, vipnet, rs)
		}
		if s := tree.SearchLongestCIDR(k); s != vipnet.String() {
			t.Errorf("[+] bug ip %s should match %s, but %s found\n", k, vipnet, s)
		}
	}

	sts := map[string]string{
		"127.0.0.1":            "127.0.0.1/8",
		"127.0.0.2":            "127.0.0.1/8",
		"10.0.0.1":             "10.0.0.0/8",
		"10.129.0.0":           "10.0.0.0/8",
		"11.129.0.0":           "11.129.0.0/9",
		"192.168.16.1":         "192.168.16.1/24",
		"192.168.16.232":       "192.168.16.232/24",
		"123.123.123.123":      "123.123.123.123/24",
		"123.123.123.120":      "123.123.123.123/24",
		"2001:df5:a980:1230::": "2001:df5:a980::/48",
		"2400:3f20:1230::":     "2400:3f20::/32",
		"2400:45c0:1230::":     "2400:45c0::/32",
		"2401:51a0:1230::":     "2401:51a0::/16",
		"2401:1230:1230::":     "2401:51a0::/16",
	}

	for k, v := range sts {
		vip := net.ParseIP(k)
		if vip == nil {
			t.Errorf("[+] bug %s not valid ip\n", k)
		}
		_, vipnet, err := net.ParseCIDR(v)
		if err != nil {
			t.Errorf("[+] bug %s not valid cidr\n", v)
		}
		if rs := tree.SearchShortest(vip); rs.String() != vipnet.String() {
			t.Errorf("[+] bug ip %s should match %s, but %s found\n", k, vipnet, rs)
		}

		if s := tree.SearchShortestCIDR(k); s != vipnet.String() {
			t.Errorf("[+] bug ip %s should match %s, but %s found\n", k, vipnet, s)
		}
	}
}

func BenchmarkIPTree(b *testing.B) {
	s := "123.123.123.123/30"

	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	tree := NewIPTree()
	tree.Insert(ipnet)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.SearchLongest(ip)
		//tree.SearchLongestCIDR("123.123.123.123")
	}
}
