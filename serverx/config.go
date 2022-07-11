package serverx

import (
	"gnamed/configx"
	"sync"
	"time"
)

var globalServerConfig *serverConfig

type serverConfig struct {
	configs []*configx.Config
	currId  int
	lock    sync.Mutex // protect concurrency update
}

func getGlobalConfig() *configx.Config {
	return globalServerConfig.configs[globalServerConfig.currId]
}

func updateGlobalConfig() (*configx.Config, error) {

	// limit config update frequence
	if time.Since(getGlobalConfig().GetTimestamp()) < 3*time.Second {
		time.Sleep(3 * time.Second)
	}

	globalServerConfig.lock.Lock()
	defer globalServerConfig.lock.Unlock()
	idx := globalServerConfig.currId ^ 1
	fname := globalServerConfig.configs[globalServerConfig.currId].GetFileName()
	cfg, err := configx.ParseConfig(fname)
	if err != nil {
		return cfg, err
	}

	// create new pointer point to new value
	// rather than update original pointer's value
	// not affect exist value
	globalServerConfig.configs[idx] = cfg

	// make sure currId updated after configuration updated, so that lock-free for read
	globalServerConfig.currId = idx

	return cfg, err
}
