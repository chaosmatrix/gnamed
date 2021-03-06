package main

import (
	"flag"
	"fmt"
	"gnamed/cachex"
	"gnamed/libnamed"
	"gnamed/serverx"
	"os"
	"os/signal"
	"sync"
	"syscall"
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
		jsonStr, err := cfg.DumpJson()
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", jsonStr)
		return
	}
	if verbose {
		fmt.Printf("%#v\n", cfg)
	}

	fakeTimer := libnamed.NewFakeTimer(1 * time.Second)
	fakeTimer.Run()

	err = libnamed.InitDefaultLogger(cfg.Server.Main.LogFile, cfg.Server.Main.LogLevel)
	if err != nil {
		fmt.Printf("[+] failed to init default logger\n")
		panic(err)
	}

	// init cache
	cachex.InitCache(cfg.Server.Cache.Mode)

	var wg sync.WaitGroup

	srv := serverx.NewServerMux()
	srv.Serve(cfg, &wg)

	signalChan := make(chan os.Signal, 1)
	signals := []os.Signal{syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP}
	signal.Notify(signalChan, signals...)
	for {
		sg := <-signalChan
		logEvent := libnamed.Logger.Debug().Str("log_type", "main").Str("signal", sg.String())
		if sg == syscall.SIGHUP {
			logEvent.Msg("server start reload configuration")
			srv.Reload()
		} else {
			logEvent.Msg("server start shutdown")
			srv.Shutdown()
			break
		}
	}

	wg.Wait()

	fakeTimer.Stop()
}
