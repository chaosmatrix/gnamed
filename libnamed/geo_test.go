package libnamed

import (
	"net"
	"testing"
)

func TestGetCountryIsoCode(t *testing.T) {
	InitGeoReader("../data/maxminddb/GeoLite2-Country.mmdb")

	ip2country := map[string]string{
		"8.8.8.8":        "US", // google dns
		"223.5.5.5":      "CN", // alidns
		"10.0.0.1":       "",   // private address
		"127.0.0.1":      "",
		"1.1.1.1":        "", // anycast
		"1.0.0.1":        "AU",
		"204.79.197.200": "US", // google.com
		"142.251.32.46":  "US", // bing.net
		"39.156.66.10":   "CN", // baidu.com
	}

	for ip, country := range ip2country {
		if code := GetCountryIsoCode(net.ParseIP(ip)); code != country {
			t.Errorf("ip: %s, country: %s != %s\n", ip, code, country)
		}
	}
}

// about 4410 ns/op
// 1000 ~ 4ms
// 2000 ~ 8ms
func BenchmarkGetCountryIsoCode(b *testing.B) {
	initGeoReader("../data/maxminddb/GeoLite2-Country.mmdb")

	ipAddress := net.ParseIP("204.79.197.200")
	for i := 0; i < b.N; i++ {
		GetCountryIsoCode(ipAddress)
	}
}
