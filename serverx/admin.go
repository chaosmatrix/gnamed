package serverx

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"gnamed/cachex"
	"gnamed/configx"
	"gnamed/libnamed"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

type AdminResponse struct {
	Status int // 0 OK, others Failed
	Desc   string
	Msg    string
}

// admin api special for browser, not compitable with restful api
// /cache/<action>?name=<domain>&type=<type_str>
func handleRequestAdminCache(c *gin.Context) {
	start := time.Now()

	logEvent := libnamed.Logger.Debug().Str("log_type", "admin")

	clientIP := c.ClientIP()
	logEvent.Str("clientip", clientIP).Str("method", c.Request.Method).Str("uri", c.Request.URL.RequestURI())

	if c.Request.Method != "GET" && c.Request.Method != "POST" {
		logEvent.Int("status_code", http.StatusMethodNotAllowed)
		c.String(http.StatusMethodNotAllowed, "method not allowed\r\n")
		logEvent.Dur("latency", time.Since(start)).Msg("")
		return
	}

	// Auth
	cidrAllow := len(cfg.Admin.Auth.Cidr) == 0

	if !cidrAllow {
		for _, cidr := range cfg.Admin.Auth.Cidr {
			subNet := "/32"
			if i := strings.Index(cidr, "/"); i > 0 {
				subNet = cidr[i:]
			} else {
				cidr += "/32"
			}

			if _, clientCidr, err := net.ParseCIDR(clientIP + subNet); err == nil && clientCidr.String() == cidr {
				cidrAllow = true
				break
			}
		}
	}

	// token check
	userAllow := false

	user, password := c.Query("user"), c.Query("password")
	if len(cfg.Admin.Auth.Token) == 0 || (user != "" && password != "" && hmac.Equal([]byte(cfg.Admin.Auth.Token[user]), []byte(password))) {
		userAllow = true
	}

	if !cidrAllow || !userAllow {
		c.JSON(http.StatusForbidden, AdminResponse{
			Status: 1,
			Desc:   "auth require",
			Msg:    "",
		})
	} else {
		action := c.Params.ByName("action")
		name := dns.Fqdn(strings.ToLower(c.Query("name")))
		qtype := strings.ToUpper(c.Query("type"))
		logEvent.Str("action", action).Str("name", name).Str("type", qtype)

		switch action {
		case "delete":
			handleRequestAdminCacheDelete(c, logEvent, name, qtype)
		case "show":
			handleRequestAdminCacheShow(c, logEvent, name, qtype)
		default:
			logEvent.Err(errors.New("action not allow"))
		}
	}

	logEvent.Dur("latency", time.Since(start)).Msg("")
}

// GET /cache/show?name=<domain>&type=<type_str>
func handleRequestAdminCacheShow(c *gin.Context, logEvent *zerolog.Event, name string, qtype string) {

	if bmsg, _, found := cachex.Get(name, dns.StringToType[qtype]); found {
		rmsg := new(dns.Msg)
		if err := rmsg.Unpack(bmsg); err != nil {
			logEvent.Int("status", 1).Int("status_code", http.StatusInternalServerError)
			c.JSON(http.StatusInternalServerError, AdminResponse{
				Status: 1,
				Desc:   "cache founded, but msg unpack failed",
				Msg:    "",
			})
			return
		}
		logEvent.Int("status", 0).Int("status_code", http.StatusOK)
		c.String(http.StatusOK, rmsg.String())
	} else {
		logEvent.Int("status", 1).Int("status_code", http.StatusNotFound)
		c.JSON(http.StatusNotFound, AdminResponse{
			Status: 1,
			Desc:   fmt.Sprintf("name '%s' type '%s' not found", name, qtype),
			Msg:    "",
		})
	}
}

// GET /cache/delete?name=<domain>&type=<type_str>
func handleRequestAdminCacheDelete(c *gin.Context, logEvent *zerolog.Event, name string, qtype string) {

	if cachex.Remove(strings.ToLower(name), dns.StringToType[qtype]) {
		logEvent.Int("status", 0).Int("status_code", http.StatusOK)
		c.JSON(http.StatusOK, AdminResponse{
			Status: 0,
			Desc:   "OK",
			Msg:    "",
		})
	} else {
		logEvent.Int("status", 1).Int("status_code", http.StatusNotFound)
		c.JSON(http.StatusNotFound, AdminResponse{
			Status: 0,
			Desc:   "OK",
			Msg:    fmt.Sprintf("name '%s' type '%s' not found", name, qtype),
		})
	}
}

func serveAdminFunc(listen configx.Listen) {
	// r = gin.Default()
	// fix "Creating an Engine instance with the Logger and Recovery middleware already attached."
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	cachePath := path.Join(listen.DohPath, "/cache/:action")
	r.GET(cachePath, handleRequestAdminCache)
	r.POST(cachePath, handleRequestAdminCache)

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

func serveAdmin(listen configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		serveAdminFunc(listen)
		wg.Done()
	}()
}
