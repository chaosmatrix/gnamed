package serverx

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"gnamed/configx"
	"gnamed/libnamed"
	"gnamed/queryx"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

func handleDoHRequest(c *gin.Context) {
	start := time.Now()

	logEvent := libnamed.Logger.Debug().Str("log_type", "server").Str("protocol", configx.ProtocolTypeDoH)

	logEvent.Str("clientip", c.ClientIP()).Str("method", c.Request.Method).Str("accept", c.GetHeader("Accept")).Str("uri", c.Request.URL.RequestURI())

	if c.Request.Method != "GET" && c.Request.Method != "POST" {
		logEvent.Int("status_code", http.StatusMethodNotAllowed)
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

func handleDoHRequestBadRequest(c *gin.Context, logEvent *zerolog.Event) {
	logEvent.Int("status_code", http.StatusBadRequest)
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
		logEvent.Err(errors.New("bad request, query_name name not found"))
		handleDoHRequestBadRequest(c, logEvent)
		return
	}
	fqname := dns.Fqdn(qname)
	if !libnamed.ValidateDomain(fqname) {
		logEvent.Err(errors.New("bad request, invalid domain"))
		handleDoHRequestBadRequest(c, logEvent)
		return
	}
	qtype, found := c.GetQuery("type")
	if !found {
		logEvent.Err(errors.New("bad request, query_name type not found"))
		handleDoHRequestBadRequest(c, logEvent)
		return
	}
	qtype = strings.ToUpper(qtype)
	qtypeNum, found := dns.StringToType[qtype]
	if !found {
		logEvent.Err(errors.New("bad request, invalid dns type"))
		handleDoHRequestBadRequest(c, logEvent)
		return
	}

	r := new(dns.Msg)
	q := dns.Question{
		Name:   fqname,
		Qtype:  qtypeNum,
		Qclass: dns.ClassINET,
	}
	r.Id = dns.Id()
	r.RecursionDesired = true
	r.Question = []dns.Question{q}

	cfg := getGlobalConfig()
	rmsg, err := queryx.Query(r, cfg, logEvent)
	if err != nil {
		logEvent.Err(err)
		handleDoHRequestBadRequest(c, logEvent)
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
			Type: qtypeNum,
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
		logEvent.Int("status_code", http.StatusInternalServerError)
		c.String(http.StatusInternalServerError, "internal server error\r\n")
		return
	}

	if c.GetHeader("Accept") == configx.DOHAcceptHeaderTypeJSON {
		c.Header("Content-Type", configx.DOHAcceptHeaderTypeJSON)
	} else {
		// Debug
		c.Header("Content-Type", "application/json")
	}
	logEvent.Int("status_code", http.StatusOK)
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
	case http.MethodGet:
		hexStr, found := c.GetQuery("dns")
		if !found {
			logEvent.Err(errors.New("bad request, query_name dns not found"))
			handleDoHRequestBadRequest(c, logEvent)
			return
		}
		bs, err = hex.DecodeString(hexStr)
	case http.MethodPost:
		if c.GetHeader("Content-Type") == string(configx.DOHAccetpHeaderTypeRFC8484) {
			logEvent.Int("status_code", http.StatusMethodNotAllowed)
			c.String(http.StatusMethodNotAllowed, "method not allowed\r\n")
			return
		}
		bs, err = c.GetRawData()
	default:
		logEvent.Int("status_code", http.StatusMethodNotAllowed)
		c.String(http.StatusMethodNotAllowed, "method not allowed\r\n")
		return
	}

	if err != nil {
		logEvent.Err(err)
		handleDoHRequestBadRequest(c, logEvent)
		return
	}

	r := new(dns.Msg)
	err = r.Unpack(bs)
	if err != nil {
		logEvent.Err(err)
		handleDoHRequestBadRequest(c, logEvent)
		return
	}

	cfg := getGlobalConfig()
	rmsg, err := queryx.Query(r, cfg, logEvent)
	if err != nil {
		logEvent.Err(err)
		handleDoHRequestBadRequest(c, logEvent)
		return
	}

	bmsg, err := rmsg.Pack()
	if err != nil {
		logEvent.Err(err).Int("status_code", http.StatusInternalServerError)
		c.String(http.StatusInternalServerError, "internal server error\r\n")
		return
	}
	c.Header("Content-Type", c.GetHeader("Accept"))
	logEvent.Int("status_code", http.StatusOK)
	c.String(http.StatusOK, string(bmsg))
}

func serveDoHFunc(listen configx.Listen) {
	r := gin.New()
	if os.Getenv(envGinDisableLog) == "" {
		r.Use(gin.Logger(), gin.Recovery())
	} else {
		r.Use(gin.Recovery())
		gin.DefaultWriter = ioutil.Discard
		//gin.DefaultErrorWriter = ioutil.Discard
	}
	//gin.SetMode(gin.ReleaseMode)

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
