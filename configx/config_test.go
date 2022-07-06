package configx

import (
	"sort"
	"testing"
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
