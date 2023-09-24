package libnamed

import (
	"net"
	"sync"

	"github.com/miekg/dns"
	"github.com/oschwald/geoip2-golang"
)

var geoCountryReader *geoip2.Reader = nil
var geoOnce *sync.Once
var geoFileName string = ""

func InitGeoReader(filename string) error {
	geoFileName = filename
	geoOnce = &sync.Once{}
	return nil
}

// geoip2.Reader need to close when not used anymore
func initGeoReader(filename string) error {
	rd, err := geoip2.Open(filename)
	if err != nil {
		return err
	}
	geoCountryReader = rd
	return nil
}

func GetCountryIsoCode(ipAddress net.IP) string {
	return getCountryIsoCode(ipAddress)
}

func getCountryIsoCode(ipAddress net.IP) string {

	geoOnce.Do(func() {
		initGeoReader(geoFileName)
	})

	if geoCountryReader == nil {
		return ""
	}
	country, err := geoCountryReader.Country(ipAddress)
	if err != nil {
		return ""
	}

	return country.Country.IsoCode
}

func GetCountryIsoCodeFromMsg(msg *dns.Msg) string {
	if msg == nil || msg.Rcode != dns.RcodeSuccess || len(msg.Question) == 0 {
		return ""
	}

	if qtype := msg.Question[0].Qtype; qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return ""
	}

	country := ""
	for _, ans := range msg.Answer {
		if a, ok := ans.(*dns.A); ok {
			country = getCountryIsoCode(a.A)
			if country != "" {
				break
			}
		}
		if aaaa, ok := ans.(*dns.AAAA); ok {
			country = getCountryIsoCode(aaaa.AAAA)
			if country != "" {
				break
			}
		}
	}
	return country
}
