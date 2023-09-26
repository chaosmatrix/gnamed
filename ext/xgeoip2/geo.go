package xgeoip2

import (
	"gnamed/ext/xlog"
	"net"
	"sync"

	"github.com/miekg/dns"
	"github.com/oschwald/geoip2-golang"
)

type xgeoip2 struct {
	filename string
	once     *sync.Once
	reader   *geoip2.Reader
}

var _xgeoip2 *xgeoip2 = new(xgeoip2)

func InitDefaultGeoReader(filename string) error {
	_xgeoip2.filename = filename
	_xgeoip2.once = &sync.Once{}
	return nil
}

func initDefaultGeoReader(filename string) error {
	_xgeoip2.filename = filename
	_xgeoip2.once = &sync.Once{}
	return nil
}

func GetCountryIsoCode(ipAddress net.IP) string {
	return getCountryIsoCode(ipAddress)
}

func getCountryIsoCode(ipAddress net.IP) string {

	_xgeoip2.once.Do(func() {
		if _xgeoip2 == nil || _xgeoip2.filename == "" {
			xlog.Logger().Error().Str("log_type", "geoip").Str("op_type", "init").Msg("no valid maxminddb file")
			return
		}
		rd, err := geoip2.Open(_xgeoip2.filename)
		_xgeoip2.reader = rd
		if err != nil {
			xlog.Logger().Error().Str("log_type", "geoip").Str("op_type", "init").Err(err).Msg("failed to init geoip reader")
		} else {
			xlog.Logger().Info().Str("log_type", "geoip").Str("op_type", "init").Msg("success init geoip reader")
		}
	})

	if _xgeoip2.reader == nil {
		return ""
	}
	country, err := _xgeoip2.reader.Country(ipAddress)
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
		switch ans.Header().Rrtype {
		case dns.TypeA:
			if a, ok := ans.(*dns.A); ok {
				country = getCountryIsoCode(a.A)
			}
		case dns.TypeAAAA:
			if aaaa, ok := ans.(*dns.AAAA); ok {
				country = getCountryIsoCode(aaaa.AAAA)
			}
		default:
			continue
		}
		if country != "" {
			break
		}
	}
	return country
}
