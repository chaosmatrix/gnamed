package serverx

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"gnamed/cachex"
	"gnamed/configx"
	"gnamed/libnamed"
	"gnamed/queryx"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
)

type AdminResponse struct {
	Status int // 0 OK, others Failed
	Desc   string
	Msg    string
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg := configx.GetGlobalConfig()

		if len(cfg.Admin.Auth.Cidr) == 0 && len(cfg.Admin.Auth.Token) == 0 {
			return
		}

		clientIP := c.ClientIP()

		cidrAllow := len(cfg.Admin.Auth.Cidr) == 0
		if len(cfg.Admin.Auth.Cidr) != 0 {

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
		if cidrAllow {
			user, password := c.Query("user"), c.Query("password")
			if len(cfg.Admin.Auth.Token) == 0 || (user != "" && password != "" && hmac.Equal([]byte(cfg.Admin.Auth.Token[user]), []byte(password))) {
				return
			}
		}

		//c.AbortWithStatus(http.StatusUnauthorized)
		c.JSON(http.StatusUnauthorized, AdminResponse{
			Status: 1,
			Desc:   "auth require",
			Msg:    "",
		})
		c.Abort()

		if !cidrAllow {
			c.Keys["log_message"] = "client ip not allow"
		} else {
			c.Keys["log_message"] = "user or password wrong"
		}
	}
}

// must put before all other middleware, to prevent abort in any other middleware
func LoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		// make sure init
		if c.Keys == nil {
			c.Keys = make(map[string]any)
		}

		start := time.Now()

		logEvent := libnamed.Logger.Info().Str("log_type", "admin")

		clientIP := c.ClientIP()
		logEvent.Str("clientip", clientIP).Str("method", c.Request.Method).Str("uri", c.Request.URL.RequestURI())

		// call all rest handler
		c.Next()

		// special handle, for output log fields sequence
		logMessage := c.Keys["log_message"]
		message := ""
		if logMessage != nil {
			message = logMessage.(string)
			delete(c.Keys, "log_message")
		}

		for logName, logValue := range c.Keys {
			idx := strings.Index(logName, "_")
			logEvent.Any(logName[idx+1:], logValue)
		}

		logEvent.Int("status_code", c.Writer.Status()).Dur("latency", time.Since(start)).Msg(message)

	}
}

// /stats/filter
func handleRequestAdminStats(c *gin.Context) {
	cfg := configx.GetGlobalConfig()
	c.String(http.StatusOK, cfg.Filter.GetStats())
}

// /filter/show/?name=<filter_name>
func handleRequestAdminFilterShow(c *gin.Context) {
	name := c.Query("name")
	if len(name) == 0 {
		c.String(http.StatusBadRequest, "{\"message\": \"no valid filter name\"}")
		return
	}

	cfg := configx.GetGlobalConfig()
	c.String(http.StatusOK, cfg.Filter.MarshalFilter(name))
}

// /config/reload
// need rate limit
func (srv *ServerMux) handleRequestAdminConfig(c *gin.Context) {

	if c.Request.Method != "GET" && c.Request.Method != "POST" {
		c.String(http.StatusMethodNotAllowed, "method not allowed\r\n")
		return
	}

	action := c.Params.ByName("action")
	//fname := c.Query("filename")

	c.Keys["log_action"] = action

	switch action {
	case "reload":
		cfg := configx.GetGlobalConfig()
		lastTimestamp := cfg.GetTimestamp()

		// rate limit
		if time.Since(lastTimestamp) < 5*time.Second {
			c.Keys["log_rate_limit"] = true

			c.Header("Retry-After", "5")
			c.JSON(http.StatusTooManyRequests, AdminResponse{
				Status: 1,
				Desc:   "reload config in high frequency, retry after 5 seconds",
				Msg:    "",
			})
		} else {
			err := srv.Reload()
			c.Keys["log_error"] = err
			if err != nil {
				c.JSON(http.StatusInternalServerError, AdminResponse{
					Status: 1,
					Desc:   fmt.Sprintf("failed to update configuration, please make sure the configuration file correct, error: '%v'", err),
					Msg:    "",
				})
			} else {
				cfg = configx.GetGlobalConfig()
				currTimestamp := cfg.GetTimestamp()
				c.JSON(http.StatusOK, AdminResponse{
					Status: 0,
					Desc:   "success update configuration.",
					Msg:    "lastTimestamp: " + lastTimestamp.String() + " currTimestamp: " + currTimestamp.String(),
				})
			}
		}
	default:
		c.JSON(http.StatusBadRequest, AdminResponse{
			Status: 1,
			Desc:   "invalid request",
			Msg:    "",
		})
	}

}

// admin api special for browser, not compitable with restful api
// /cache/<action>?name=<domain>&type=<type_str>
func handleRequestAdminCache(c *gin.Context) {

	if c.Request.Method != "GET" && c.Request.Method != "POST" {
		c.String(http.StatusMethodNotAllowed, "method not allowed\r\n")
		return
	}

	action := c.Params.ByName("action")
	name := dns.Fqdn(strings.ToLower(c.Query("name")))
	qtype := strings.ToUpper(c.Query("type"))

	c.Keys["log_action"] = action
	c.Keys["log_name"] = name
	c.Keys["log_qtype"] = qtype

	switch action {
	case "delete":
		handleRequestAdminCacheDelete(c, name, qtype)
	case "show":
		handleRequestAdminCacheShow(c, name, qtype)
	case "dump":
		handleRequestAdminCacheDump(c)
	case "store":
		handleRequestAdminCacheStore(c)
	default:
		c.JSON(http.StatusBadRequest, AdminResponse{
			Status: 1,
			Desc:   "invalid request",
			Msg:    "",
		})
		c.Keys["log_error"] = errors.New("action not allow")
	}
}

// GET /cache/show?name=<domain>&type=<type_str>
func handleRequestAdminCacheShow(c *gin.Context, name string, qtype string) {

	if rmsg, expiredUTC, found := cachex.Get(name, dns.StringToType[qtype]); found {

		cacheTtl := queryx.GetMsgTTL(rmsg, &configx.GetGlobalConfig().Server.RrCache)
		expiredTime := time.Unix(expiredUTC, 0).String()
		addTime := time.Unix(expiredUTC-int64(cacheTtl), 0)

		headStr := fmt.Sprintf("\n;;\n;;\n;; add at:     %s\n;; expired at: %s\n;;\n", addTime, expiredTime)
		c.String(http.StatusOK, headStr+rmsg.String())
	} else {
		c.JSON(http.StatusNotFound, AdminResponse{
			Status: 1,
			Desc:   fmt.Sprintf("name '%s' type '%s' not found", name, qtype),
			Msg:    "",
		})
	}
}

// GET /cache/delete?name=<domain>&type=<type_str>
func handleRequestAdminCacheDelete(c *gin.Context, name string, qtype string) {

	if cachex.Remove(strings.ToLower(name), dns.StringToType[qtype]) {
		c.JSON(http.StatusOK, AdminResponse{
			Status: 0,
			Desc:   "OK",
			Msg:    "",
		})
	} else {
		c.JSON(http.StatusNotFound, AdminResponse{
			Status: 0,
			Desc:   "OK",
			Msg:    fmt.Sprintf("name '%s' type '%s' not found", name, qtype),
		})
	}
}

// GET /cache/dump
func handleRequestAdminCacheDump(c *gin.Context) {

	format := c.Query("format")
	c.Keys["log_format"] = format

	res := cachex.Dump()
	switch format {
	case "txt":
		arr := make([]string, len(res))
		i := 0
		for qname, qtypes := range res {
			tmp := qname
			for _, qtype := range qtypes {
				tmp += "," + dns.TypeToString[qtype]
			}
			arr[i] = tmp
			i++
		}
		//sort.Strings(arr)
		sort.Slice(arr, func(i, j int) bool {
			sizei, sizej := strings.Index(arr[i], ","), strings.Index(arr[j], ",")

			for ir, jr := sizei-1, sizej-1; ir >= 0 && jr >= 0; ir, jr = ir-1, jr-1 {
				if arr[i][ir] < arr[j][jr] {
					return true
				} else if arr[i][ir] > arr[j][jr] {
					return false
				}
			}
			return sizei < sizej
		})
		c.String(http.StatusOK, "%s", strings.Join(arr, "\n"))
	default:
		c.JSON(http.StatusOK, res)
	}
}

// GET /cache/store
func handleRequestAdminCacheStore(c *gin.Context) {
	wf := cachex.Store()
	wri := configx.GetGlobalConfig().WarmRunnerInfo
	err := wri.Store(wf)
	if err != nil {
		c.String(http.StatusInternalServerError, fmt.Sprintf("error: %v\n", err))
	} else {
		c.String(http.StatusOK, "success store cache as file\n")
	}
}

func (srv *ServerMux) serveAdmin(listen configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		//serveAdminFunc(listen)
		// r = gin.Default()
		// fix "Creating an Engine instance with the Logger and Recovery middleware already attached."
		gin.SetMode(gin.ReleaseMode)

		v := os.Getenv(envGinDisableLog)
		if v != "" {
			gin.DefaultWriter = io.Discard
			//gin.DefaultErrorWriter = ioutil.Discard
		}
		r := gin.New()
		if v == "" {
			r.Use(gin.Logger(), gin.Recovery())
		} else {
			r.Use(gin.Recovery())
		}

		r.Use(LoggerMiddleware())
		r.Use(AuthMiddleware())

		cachePath := path.Join(listen.DohPath, "/cache/:action")
		r.GET(cachePath, handleRequestAdminCache)
		r.POST(cachePath, handleRequestAdminCache)

		configPath := path.Join(listen.DohPath, "/config/:action")
		r.GET(configPath, srv.handleRequestAdminConfig)
		r.POST(configPath, srv.handleRequestAdminConfig)

		statsFilterPath := path.Join(listen.DohPath, "/stats/filter")
		r.GET(statsFilterPath, handleRequestAdminStats)
		r.POST(statsFilterPath, handleRequestAdminStats)

		filterShowPath := path.Join(listen.DohPath, "/filter/show")
		r.GET(filterShowPath, handleRequestAdminFilterShow)
		r.POST(filterShowPath, handleRequestAdminFilterShow)

		httpSrv := &http.Server{
			Addr:         listen.Addr,
			Handler:      r,
			IdleTimeout:  listen.Timeout.IdleDuration,
			ReadTimeout:  listen.Timeout.ReadDuration,
			WriteTimeout: listen.Timeout.WriteDuration,
		}

		srv.registerOnShutdown(func() {
			libnamed.Logger.Info().Str("log_type", "admin").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Msg("signal to shutdown server")
			err := httpSrv.Shutdown(context.Background()) // block all in-processing and idle connection closed
			logEvent := libnamed.Logger.Info().Str("log_type", "admin").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Err(err)

			wg.Done()
			logEvent.Msg("server has been shutdown")
		})

		if listen.TlsConfig.CertFile == "" {
			//err := r.Run(listen.Addr)
			err := httpSrv.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				panic(err)
			}
		} else {
			//err := r.RunTLS(listen.Addr, listen.TlsConfig.CertFile, listen.TlsConfig.KeyFile)
			err := httpSrv.ListenAndServeTLS(listen.TlsConfig.CertFile, listen.TlsConfig.KeyFile)
			if err != nil && err != http.ErrServerClosed {
				panic(err)
			}
		}
	}()
}
