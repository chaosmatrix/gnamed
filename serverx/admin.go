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
	"io/ioutil"
	"net"
	"net/http"
	"os"
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

func adminAuthUser(clientIP string, user string, password string) bool {
	cfg := getGlobalConfig()
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

	if len(cfg.Admin.Auth.Token) == 0 || (user != "" && password != "" && hmac.Equal([]byte(cfg.Admin.Auth.Token[user]), []byte(password))) {
		userAllow = true
	}

	return cidrAllow && userAllow
}

// /config/reload
// need rate limit
func handleRequestAdminConfig(c *gin.Context) {
	start := time.Now()

	logEvent := libnamed.Logger.Debug().Str("log_type", "admin")
	defer func() {
		logEvent.Dur("latency", time.Since(start)).Msg("")
	}()

	clientIP := c.ClientIP()
	logEvent.Str("clientip", clientIP).Str("method", c.Request.Method).Str("uri", c.Request.URL.RequestURI())

	if c.Request.Method != "GET" && c.Request.Method != "POST" {
		logEvent.Int("status_code", http.StatusMethodNotAllowed)
		c.String(http.StatusMethodNotAllowed, "method not allowed\r\n")
		return
	}

	if adminAuthUser(clientIP, c.Query("user"), c.Query("password")) {
		action := c.Params.ByName("action")
		//fname := c.Query("filename")
		logEvent.Str("action", action)

		switch action {
		case "reload":
			cfg := getGlobalConfig()
			lastTimestamp := cfg.GetTimestamp()

			// rate limit
			if time.Since(lastTimestamp) < 5*time.Second {
				logEvent.Bool("rate_limit", true).Int("status_code", http.StatusTooManyRequests)
				c.Header("Retry-After", "5")
				c.JSON(http.StatusTooManyRequests, AdminResponse{
					Status: 1,
					Desc:   "reload config in high frequency, retry after 5 seconds",
					Msg:    "",
				})
			} else {
				_, err := updateGlobalConfig()
				logEvent.Err(err)
				if err != nil {
					logEvent.Int("status_code", http.StatusInternalServerError)
					c.JSON(http.StatusInternalServerError, AdminResponse{
						Status: 1,
						Desc:   fmt.Sprintf("failed to update configuration, please make sure the configuration file correct, error: '%v'", err),
						Msg:    "",
					})
				} else {
					logEvent.Int("status_code", http.StatusOK)
					cfg = getGlobalConfig()
					currTimestamp := cfg.GetTimestamp()
					c.JSON(http.StatusOK, AdminResponse{
						Status: 0,
						Desc:   "success update configuration.",
						Msg:    "lastTimestamp: " + lastTimestamp.String() + " currTimestamp: " + currTimestamp.String(),
					})
				}
			}
		default:
			logEvent.Int("status_code", http.StatusBadRequest)
			c.JSON(http.StatusBadRequest, AdminResponse{
				Status: 1,
				Desc:   "invalid request",
				Msg:    "",
			})
			logEvent.Err(errors.New("action not allow"))
		}
	} else {
		logEvent.Int("status_code", http.StatusForbidden)
		c.JSON(http.StatusForbidden, AdminResponse{
			Status: 1,
			Desc:   "auth require",
			Msg:    "",
		})
	}
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

	if adminAuthUser(clientIP, c.Query("user"), c.Query("password")) {
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
			c.JSON(http.StatusBadRequest, AdminResponse{
				Status: 1,
				Desc:   "invalid request",
				Msg:    "",
			})
			logEvent.Err(errors.New("action not allow"))
		}
	} else {
		c.JSON(http.StatusForbidden, AdminResponse{
			Status: 1,
			Desc:   "auth require",
			Msg:    "",
		})
	}

	logEvent.Dur("latency", time.Since(start)).Msg("")
}

// GET /cache/show?name=<domain>&type=<type_str>
func handleRequestAdminCacheShow(c *gin.Context, logEvent *zerolog.Event, name string, qtype string) {

	if bmsg, expiredUTC, found := cachex.Get(name, dns.StringToType[qtype]); found {
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
		cacheTtl := queryx.GetMsgTTL(rmsg, &getGlobalConfig().Server.Cache)
		expiredTime := time.Unix(expiredUTC, 0).String()
		addTime := time.Unix(expiredUTC-int64(cacheTtl), 0)

		headStr := fmt.Sprintf("\n;;\n;;\n;; add at:     %s\n;; expired at: %s\n;;\n", addTime, expiredTime)
		logEvent.Int("status", 0).Int("status_code", http.StatusOK)
		c.String(http.StatusOK, headStr+rmsg.String())
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

func (srv *ServerMux) serveAdmin(listen configx.Listen, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		//serveAdminFunc(listen)
		// r = gin.Default()
		// fix "Creating an Engine instance with the Logger and Recovery middleware already attached."
		r := gin.New()
		if os.Getenv(envGinDisableLog) == "" {
			r.Use(gin.Logger(), gin.Recovery())
		} else {
			r.Use(gin.Recovery())
			gin.DefaultWriter = ioutil.Discard
			//gin.DefaultErrorWriter = ioutil.Discard
		}
		//gin.SetMode(gin.ReleaseMode)

		cachePath := path.Join(listen.DohPath, "/cache/:action")
		r.GET(cachePath, handleRequestAdminCache)
		r.POST(cachePath, handleRequestAdminCache)

		configPath := path.Join(listen.DohPath, "/config/:action")
		r.GET(configPath, handleRequestAdminConfig)
		r.POST(configPath, handleRequestAdminConfig)

		httpSrv := &http.Server{
			Addr:         listen.Addr,
			Handler:      r,
			IdleTimeout:  listen.Timeout.IdleDuration,
			ReadTimeout:  listen.Timeout.ReadDuration,
			WriteTimeout: listen.Timeout.WriteDuration,
		}

		var httpSrvWaitGroup sync.WaitGroup
		httpSrvWaitGroup.Add(1)
		go func() {
			defer httpSrvWaitGroup.Done()
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

		// shutdown listener
		srv.waitShutdownSignal()

		libnamed.Logger.Debug().Str("log_type", "admin").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Msg("signal to shutdown server")
		err := httpSrv.Shutdown(context.Background()) // block all in-processing and idle connection closed
		logEvent := libnamed.Logger.Debug().Str("log_type", "admin").Str("protocol", listen.Protocol).Str("network", listen.Network).Str("addr", listen.Addr).Err(err)

		httpSrvWaitGroup.Wait()

		wg.Done()
		logEvent.Msg("server has been shutdown")
	}()
}
