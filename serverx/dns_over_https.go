package serverx

import (
	"encoding/json"
	"errors"
	"gnamed/configx"
	"gnamed/libnamed"
	"gnamed/queryx"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
)

func handleDoHRequest(c *gin.Context) {
	switch c.Request.Method {
	case "GET", "POST":
		//
	default:
		c.String(http.StatusMethodNotAllowed, "method not allowed\r\n")
		return
	}

	switch c.GetHeader("Accept") {
	case configx.DOHAcceptHeaderTypeJSON:
		//
		handleDoHRequestJSON(c)
	case configx.DOHAccetpHeaderTypeRFC8484:
		//
		handleDoHRequestRFC8484(c)
	default:
		//
		handleDoHRequestJSON(c)
	}
}

func handleDoHRequestBadRequest(c *gin.Context) {
	c.String(http.StatusBadRequest, "invalid message type\r\n")
}

/*
// Google Json
curl --location --request GET "https://dns.google.com/resolve?name=www.google.com&type=a" \
 --header "Accept: application/dns-json"
*/
func handleDoHRequestJSON(c *gin.Context) {
	_logEvent := libnamed.Logger.Trace().Str("log_type", "server").Str("protocol", configx.ProtocolTypeDoH).Str("doh_msg_type", string(configx.DOHMsgTypeJSON))

	_logEvent.Str("clientip", c.ClientIP()).Str("method", c.Request.Method).Str("accept", c.GetHeader("Accept"))
	qname, found := c.GetQuery("name")
	if !found {
		_logEvent.Err(errors.New("bad request")).Msg("")
		handleDoHRequestBadRequest(c)
		return
	}
	_logEvent.Str("name", qname)
	fqname := dns.Fqdn(qname)
	qtype, found := c.GetQuery("type")
	if !found {
		_logEvent.Err(errors.New("bad request")).Msg("")
		handleDoHRequestBadRequest(c)
		return
	}
	_logEvent.Str("type", qtype)
	qtype = strings.ToUpper(qtype)
	qtypeInt := dns.StringToType[qtype]

	r := new(dns.Msg)
	q := dns.Question{
		Name:   fqname,
		Qtype:  qtypeInt,
		Qclass: dns.ClassINET,
	}
	r.Id = dns.Id()
	r.RecursionDesired = true
	r.Question = []dns.Question{q}

	_logEvent.Uint16("id", r.Id)

	rmsg, err := queryx.Query(r, cfg)
	if err != nil {
		_logEvent.Err(err).Msg("")
		handleDoHRequestBadRequest(c)
		return
	}

	resp := queryx.GResJson{
		Status: rmsg.Rcode,
		TC:     rmsg.Truncated,
		RD:     rmsg.RecursionDesired,
		RA:     rmsg.RecursionAvailable,
		AD:     rmsg.AuthenticatedData,
		CD:     rmsg.CheckingDisabled,
		Question: []queryx.GQuestion{{
			Name: qname,
			Type: qtypeInt,
		}},
	}

	if len(rmsg.Answer) > 0 {
		for _, ans := range rmsg.Answer {
			jans := queryx.GAnswer{
				Name: ans.Header().Name,
				Type: ans.Header().Rrtype,
				TTL:  int64(ans.Header().Ttl),
				Data: ans.String()[len(ans.Header().String()):],
			}
			resp.Answer = append(resp.Answer, jans)
		}
	}

	if len(rmsg.Ns) > 0 {
		for _, ans := range rmsg.Ns {
			jans := queryx.GAnswer{
				Name: ans.Header().Name,
				Type: ans.Header().Rrtype,
				TTL:  int64(ans.Header().Ttl),
				Data: ans.String()[len(ans.Header().String()):],
			}
			resp.Authority = append(resp.Authority, jans)
		}
	}

	bs, err := json.Marshal(resp)
	if err != nil {
		_logEvent.Err(err).Msg("")
		c.String(http.StatusInternalServerError, "internal server error\r\n")
		return
	}

	if c.GetHeader("Accept") == configx.DOHAcceptHeaderTypeJSON {
		c.Header("Content-Type", configx.DOHAcceptHeaderTypeJSON)
	} else {
		// Debug
		c.Header("Content-Type", "application/json")
	}
	_logEvent.Msg("")
	c.String(http.StatusOK, string(bs))
}

func handleDoHRequestRFC8484(c *gin.Context) {
	_logEvent := libnamed.Logger.Trace().Str("log_type", "server").Str("protocol", configx.ProtocolTypeDoH).Str("doh_msg_type", string(configx.DOHMsgTypeRFC8484))
	_logEvent.Str("clientip", c.ClientIP()).Str("method", c.Request.Method).Str("accept", c.GetHeader("Accept"))

	bs, err := c.GetRawData()
	if err != nil {
		_logEvent.Err(err).Msg("")
		handleDoHRequestBadRequest(c)
		return
	}
	r := new(dns.Msg)
	err = r.Unpack(bs)
	if err != nil {
		_logEvent.Err(err).Msg("")

		handleDoHRequestBadRequest(c)
		return
	}
	rmsg, err := queryx.Query(r, cfg)
	if err != nil {
		_logEvent.Err(err).Msg("")

		handleDoHRequestBadRequest(c)
		return
	}

	_logEvent.Uint16("id", rmsg.Id).Str("name", rmsg.Question[0].Name).Str("type", dns.TypeToString[rmsg.Question[0].Qtype])
	bmsg, err := rmsg.Pack()
	if err != nil {
		_logEvent.Err(err).Msg("")

		c.String(http.StatusInternalServerError, "internal server error\r\n")
		return
	}
	_logEvent.Msg("")
	c.Header("Content-Type", c.GetHeader("Accept"))
	c.String(http.StatusOK, string(bmsg))
}

func serveDoHFunc(listen configx.Listen) {
	r := gin.Default()
	if listen.DohPath == "" {
		r.GET("/dns-query", handleDoHRequest)
		r.POST("/dns-query", handleDoHRequest)
	} else {
		r.GET(listen.DohPath, handleDoHRequest)
		r.POST(listen.DohPath, handleDoHRequest)
	}
	if listen.TlsConfig.CertFile == "" {
		err := r.Run(listen.Addr)
		panic(err)
	} else {
		err := r.RunTLS(listen.Addr, listen.TlsConfig.CertFile, listen.TlsConfig.KeyFile)
		panic(err)
	}
}

func serveDoH(listen configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go serveDoHFunc(listen)
}
