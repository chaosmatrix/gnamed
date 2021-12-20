package serverx

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"gnamed/configx"
	"gnamed/libnamed"
	"gnamed/queryx"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

func handleDoHRequest(c *gin.Context) {
	logEvent := libnamed.Logger.Debug().Str("log_type", "server").Str("protocol", configx.ProtocolTypeDoH)

	logEvent.Str("clientip", c.ClientIP()).Str("method", c.Request.Method).Str("accept", c.GetHeader("Accept"))

	start := time.Now()
	switch c.Request.Method {
	case "GET", "POST":
		//
	default:
		c.String(http.StatusMethodNotAllowed, "method not allowed\r\n")
		logEvent.Dur("latency", time.Since(start)).Msg("")
		return
	}

	switch c.GetHeader("Accept") {
	case configx.DOHAcceptHeaderTypeJSON:
		//
		logEvent.Str("doh_msg_type", string(configx.DOHMsgTypeJSON))
		handleDoHRequestJSON(c, logEvent)
	case configx.DOHAccetpHeaderTypeRFC8484:
		//
		logEvent.Str("doh_msg_type", string(configx.DOHMsgTypeRFC8484))
		handleDoHRequestRFC8484(c, logEvent)
	default:
		//
		logEvent.Str("doh_msg_type", string(configx.DOHMsgTypeJSON))
		handleDoHRequestJSON(c, logEvent)
	}
	logEvent.Dur("latency", time.Since(start)).Msg("")
}

func handleDoHRequestBadRequest(c *gin.Context) {
	c.String(http.StatusBadRequest, "invalid message type\r\n")
}

// No RFC
//
// difference provider has difference implementation
//
// Some common requirement:
//
// request:
// 1. header: "Accept: application/dns-json" or "Accept: application/json" or no require
// 2. query params: "?name=example.com&type=a&do=true&cd=false&random=xxx&xxx", ignore additional fields
//     * required: "name", "type"
//     * optional: "do", "cd"
//     * ignored: all others
// 3. path: "resolv" or "dns-query" or others
//
// response:
// 1. header: "Content-Type: application/dns-json" or "Accept: application/json"
//
// reference:
// 1. google
// 2. 1.1.1.1 https://developers.cloudflare.com/1.1.1.1/encrypted-dns/dns-over-https/make-api-requests/dns-json
// 3. nextdns
//
func handleDoHRequestJSON(c *gin.Context, logEvent *zerolog.Event) {

	qname, found := c.GetQuery("name")
	if !found {
		logEvent.Err(errors.New("bad request"))
		handleDoHRequestBadRequest(c)
		return
	}
	fqname := dns.Fqdn(qname)
	qtype, found := c.GetQuery("type")
	if !found {
		logEvent.Err(errors.New("bad request"))
		handleDoHRequestBadRequest(c)
		return
	}
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

	rmsg, err := queryx.Query(r, cfg, logEvent)
	if err != nil {
		logEvent.Err(err)
		handleDoHRequestBadRequest(c)
		return
	}

	resp := libnamed.DOHJson{
		Status: rmsg.Rcode,
		TC:     rmsg.Truncated,
		RD:     rmsg.RecursionDesired,
		RA:     rmsg.RecursionAvailable,
		AD:     rmsg.AuthenticatedData,
		CD:     rmsg.CheckingDisabled,
		Question: []libnamed.DOHJsonQuestion{{
			Name: qname,
			Type: qtypeInt,
		}},
	}

	if len(rmsg.Answer) > 0 {
		for _, ans := range rmsg.Answer {
			jans := libnamed.DOHJsonAnswer{
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
			jans := libnamed.DOHJsonAnswer{
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
		logEvent.Err(err)
		c.String(http.StatusInternalServerError, "internal server error\r\n")
		return
	}

	if c.GetHeader("Accept") == configx.DOHAcceptHeaderTypeJSON {
		c.Header("Content-Type", configx.DOHAcceptHeaderTypeJSON)
	} else {
		// Debug
		c.Header("Content-Type", "application/json")
	}
	c.String(http.StatusOK, string(bs))
}

// RFC:
// 1. DOH https://datatracker.ietf.org/doc/html/rfc8484
// 2. DNS wireformat https://datatracker.ietf.org/doc/html/rfc1035
//
// request:
// 1. method: "GET" or "POST"
// 2. if method "GET" query param "dns", DNS wireformat with hex encoding
// 3. header: "accept: dns-message"
//
// response:
// 1. header: "Content-Type: dns-message"
// 2. body: DNS wireformat
//
func handleDoHRequestRFC8484(c *gin.Context, logEvent *zerolog.Event) {

	var bs []byte
	var err error
	switch c.Request.Method {
	case "GET":
		hexStr, found := c.GetQuery("dns")
		if !found {
			handleDoHRequestBadRequest(c)
			return
		}
		bs, err = hex.DecodeString(hexStr)
	case "POST":
		bs, err = c.GetRawData()
	default:
		c.String(http.StatusMethodNotAllowed, "method not allowed\r\n")
		return
	}

	if err != nil {
		logEvent.Err(err)
		handleDoHRequestBadRequest(c)
		return
	}

	r := new(dns.Msg)
	err = r.Unpack(bs)
	if err != nil {
		logEvent.Err(err)

		handleDoHRequestBadRequest(c)
		return
	}
	rmsg, err := queryx.Query(r, cfg, logEvent)
	if err != nil {
		logEvent.Err(err)

		handleDoHRequestBadRequest(c)
		return
	}

	bmsg, err := rmsg.Pack()
	if err != nil {
		logEvent.Err(err)

		c.String(http.StatusInternalServerError, "internal server error\r\n")
		return
	}
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
		if err != nil {
			panic(err)
		}
	} else {
		err := r.RunTLS(listen.Addr, listen.TlsConfig.CertFile, listen.TlsConfig.KeyFile)
		if err != nil {
			panic(err)
		}
	}
}

func serveDoH(listen configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		serveDoHFunc(listen)
		wg.Done()
	}()
}