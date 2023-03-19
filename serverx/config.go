package serverx

import (
	"gnamed/configx"
	"sync"
	"time"
)

var defaultServerConfig *serverConfig

type serverConfig struct {
	cfg  *configx.Config
	lock sync.Mutex // protect concurrency update
}

func initDefaultServerConfig(cfg *configx.Config) {
	defaultServerConfig = &serverConfig{
		cfg: cfg,
	}
}
func getGlobalConfig() *configx.Config {
	return defaultServerConfig.cfg
}

func updateGlobalConfig() (*configx.Config, error) {

	// limit config update frequence
	if time.Since(getGlobalConfig().GetTimestamp()) < 3*time.Second {
		time.Sleep(3 * time.Second)
	}

	defaultServerConfig.lock.Lock()
	defer defaultServerConfig.lock.Unlock()

	defaultServerConfig.cfg.StopDaemon()

	fname := defaultServerConfig.cfg.GetFileName()
	cfg, err := configx.ParseConfig(fname)
	if err != nil {
		return cfg, err
	}

	// update pointer rather than update pointer's value, to achive lock-free
	defaultServerConfig.cfg = cfg

	return cfg, err
}
