package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"gnamed/cachex"
	"gnamed/libnamed"
	"gnamed/serverx"
	"strings"
	"sync"
	"time"

	"gnamed/configx"
)

var (
	configFile = "./configx/config.json"
	dumpJson   = false
	verbose    = false
)

func parseArgs() {
	flag.StringVar(&configFile, "config-file", configFile, "config file")
	flag.BoolVar(&dumpJson, "dump-json", dumpJson, "dump configuration with json format, then exit")
	flag.BoolVar(&verbose, "verbose", verbose, "verbose")

	flag.Parse()
}

func main() {
	parseArgs()
	cfg, err := configx.ParseConfig(configFile)
	if err != nil {
		panic(err)
	}

	if dumpJson {
		if bs, err := json.MarshalIndent(cfg, "", "    "); err == nil {
			fmt.Printf("%s\n", bs)
		} else {
			panic(err)
		}
		return
	}
	if verbose {
		fmt.Printf("%#v\n", cfg)
	}

	fakeTimer := libnamed.NewFakeTimer(1 * time.Second)
	fakeTimer.Run()

	var logType libnamed.LogType = libnamed.LogTypeConsole
	logPath := ""
	if logCfgs := strings.Split(cfg.Server.Main.LogFile, ":"); len(logCfgs) == 2 {
		logType = libnamed.LogType(logCfgs[0])
		logPath = logCfgs[1]
	} else if len(logCfgs) == 1 {
		logType = libnamed.LogType(logCfgs[0])
	}
	_, err = libnamed.NewLogger(string(logType), logPath, cfg.Server.Main.LogLevel)
	if err != nil {
		panic(err)
	}

	// init cache
	switch cfg.Server.Cache.Mode {
	case configx.CacheModeSkipList:
		cachex.NewDefaultSklCache()
	case configx.CacheModeHashTable:
		cachex.NewDefaultHashCache()
	default:
		panic("invalid cache mode")
	}

	var wg sync.WaitGroup
	serverx.Serve(&cfg, &wg)
	wg.Wait()

	fakeTimer.Stop()
}
