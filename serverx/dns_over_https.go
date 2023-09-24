package serverx

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"gnamed/configx"
	"gnamed/ext/bytespool"
	"gnamed/ext/types"
	"gnamed/ext/xlog"
	"gnamed/libnamed"
	"gnamed/queryx"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

type dohServerOpt struct {
	compress bool
}

// https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
// https://github.com/gin-contrib/cors
func corsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		enableCors(c)
	}
}

func enableCors(c *gin.Context) {
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "GET, POST")
	c.Header("Access-Control-Allow-Headers", "Content-Type")
	c.Header("Access-Control-Allow-Credentials", "true")
}

func (ds *dohServerOpt) handleCorsPreflight(c *gin.Context) {
	if c.Request.Method == http.MethodOptions {
		c.String(http.StatusNoContent, "")
		return
	}

	c.String(http.StatusMethodNotAllowed, "")
}

func (ds *dohServerOpt) handleDoHRequest(c *gin.Context) {

	dc := &types.DConnection{
		OutgoingMsg: nil,
		Log:         xlog.Logger().Info(),
	}
	start := time.Now()
	logEvent := dc.Log.Str("log_type", "server").Str("protocol", configx.ProtocolTypeDoH)

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
		ds.handleDoHRequestJSON(c, dc)
	case configx.DOHAccetpHeaderTypeRFC8484:
		//
		logEvent.Str("doh_msg_type", string(configx.DOHMsgTypeRFC8484))
		ds.handleDoHRequestRFC8484(c, dc)
	default:
		//
		logEvent.Str("doh_msg_type", string(configx.DOHMsgTypeJSON))
		ds.handleDoHRequestJSON(c, dc)
	}
	logEvent.Dur("latency", time.Since(start)).Msg("")
}

func handleDoHRequestBadRequest(c *gin.Context, logEvent *zerolog.Event) {
	logEvent.Int("status_code", http.StatusBadRequest)
	c.String(http.StatusBadRequest, "invalid message type\r\n")
}

func handleDoHRequestBadGateway(c *gin.Context, logEvent *zerolog.Event) {
	logEvent.Int("status_code", http.StatusBadGateway)
	c.String(http.StatusBadGateway, "502 Bad Gateway\r\n")
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
//   - required: "name", "type"
//   - optional: "do", "cd"
//   - ignored: all others
//
// 3. path: "resolv" or "dns-query" or others
//
// response:
// 1. header: "Content-Type: application/dns-json" or "Accept: application/json"
//
// reference:
// 1. google
// 2. 1.1.1.1 https://developers.cloudflare.com/1.1.1.1/encrypted-dns/dns-over-https/make-api-requests/dns-json
// 3. nextdns
func (ds *dohServerOpt) handleDoHRequestJSON(c *gin.Context, dc *types.DConnection) {

	logEvent := dc.Log
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

	dc.OutgoingMsg = r
	cfg := configx.GetGlobalConfig()
	rmsg, err := queryx.Query(dc, cfg)
	if err != nil {
		logEvent.Err(err)
		handleDoHRequestBadRequest(c, logEvent)
		return
	}

	resp := types.DOHJson{
		Status: rmsg.Rcode,
		TC:     rmsg.Truncated,
		RD:     rmsg.RecursionDesired,
		RA:     rmsg.RecursionAvailable,
		AD:     rmsg.AuthenticatedData,
		CD:     rmsg.CheckingDisabled,
		Question: []types.DOHJsonQuestion{{
			Name: qname,
			Type: qtypeNum,
		}},
	}

	if len(rmsg.Answer) > 0 {
		for _, ans := range rmsg.Answer {
			jans := types.DOHJsonAnswer{
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
			jans := types.DOHJsonAnswer{
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
func (ds *dohServerOpt) handleDoHRequestRFC8484(c *gin.Context, dc *types.DConnection) {

	logEvent := dc.Log

	var r *dns.Msg
	var err error

	switch c.Request.Method {
	case http.MethodGet:
		hexStr, found := c.GetQuery("dns")
		if !found {
			logEvent.Err(errors.New("bad request, query_name dns not found"))
			handleDoHRequestBadRequest(c, logEvent)
			return
		}
		decLen := base64.RawURLEncoding.DecodedLen(len(hexStr))
		buf := bytespool.Get(decLen)
		var off int
		off, err = base64.RawURLEncoding.Decode(buf, []byte(hexStr))
		if err != nil {
			logEvent.Err(err)
			handleDoHRequestBadRequest(c, logEvent)
			return
		}
		r = new(dns.Msg)
		err = r.Unpack(buf[:off])
		bytespool.Put(buf)
		buf = nil
	case http.MethodPost:
		if c.GetHeader("Content-Type") != string(configx.DOHAccetpHeaderTypeRFC8484) {
			logEvent.Int("status_code", http.StatusMethodNotAllowed)
			c.String(http.StatusMethodNotAllowed, "method not allowed\r\n")
			return
		}
		bodyLen := c.Request.ContentLength + 2
		if bodyLen <= 0 {
			bodyLen = 128
		}
		r, _, err = bytespool.UnpackMsgWitBufSize(c.Request.Body, int(bodyLen), bytespool.MaskEncodeWithoutLength)
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

	dc.OutgoingMsg = r
	cfg := configx.GetGlobalConfig()
	rmsg, err := queryx.Query(dc, cfg)
	if err != nil {
		logEvent.Err(err)
		handleDoHRequestBadGateway(c, logEvent)
		return
	}

	rmsg.Compress = ds.compress
	buf, off, reuse, err := bytespool.PackMsgWitBufSize(rmsg, 0, bytespool.MaskEncodeWithoutLength)
	if reuse {
		defer func() { bytespool.Put(buf) }()
	}
	if err != nil {
		logEvent.Err(err).Int("status_code", http.StatusInternalServerError)
		c.String(http.StatusInternalServerError, "internal server error\r\n")
		return
	}
	bmsg := buf[:off]

	c.Header("Content-Type", c.GetHeader("Accept"))
	logEvent.Int("status_code", http.StatusOK)

	c.String(http.StatusOK, string(bmsg))
}

func getHTTPHandler(listen *configx.Listen) *gin.Engine {

	gin.SetMode(gin.ReleaseMode)

	v := os.Getenv(envGinEnableLog)
	if v == "" {
		gin.DefaultWriter = io.Discard
	}
	r := gin.New()
	if v != "" {
		r.Use(gin.Logger(), gin.Recovery())
	} else {
		r.Use(gin.Recovery())
	}
	r.Use(corsHandler())

	ds := dohServerOpt{
		compress: !listen.DisableCompressMsg,
	}
	if listen.URLPath == "" {
		r.GET("/dns-query", ds.handleDoHRequest)
		r.POST("/dns-query", ds.handleDoHRequest)
		r.OPTIONS("/dns-query", ds.handleCorsPreflight)
	} else {
		r.GET(listen.URLPath, ds.handleDoHRequest)
		r.POST(listen.URLPath, ds.handleDoHRequest)
		r.OPTIONS(listen.URLPath, ds.handleCorsPreflight)
	}

	return r
}
