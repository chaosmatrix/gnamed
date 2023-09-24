package main

import (
	"context"
	"flag"
	"fmt"
	"gnamed/ext/runner"
	"gnamed/ext/xlog"
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

	xlog.Logger().Debug().Str("log_type", "main").Str("op_type", "start").Msg("")

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
		return
	}

	err = runner.ExecStartPre(cfg.RunnerOption.StartPreTimeoutDuration)
	if err != nil {
		xlog.Logger().Error().Str("log_type", "main").Str("op_type", "runner").Err(err).Msg("exec startPre funcs")
		panic(err)
	}

	var wg sync.WaitGroup

	srv := serverx.NewServerMux()
	srv.Serve(cfg, &wg)

	srv.RegisterOnReload(func() error {
		logEvent := xlog.Logger().Info().Str("log_type", "main").Str("op_type", "reload")
		start := time.Now()
		cfg := configx.GetGlobalConfig()
		err := runner.ExecDaemonStop(cfg.RunnerOption.DaemonStopTimeoutDuration)
		logEvent.AnErr("err_daemon_stop", err)

		runner.NewAndKeepDefaultRunner()

		err = configx.UpdateGlobalConfig()
		if err != nil {
			logEvent.AnErr("err_update_config", err)
			runner.RestoreDefaultRunner()
		}
		runner.ExecDaemonStart(&wg)
		logEvent.Dur("elapsed_time", time.Since(start)).Msg("")
		return err
	})

	// exec runner at startup
	// ignore warmRunner error
	//go cfg.WarmRunnerInfo.Run()

	err = runner.ExecStartPost(cfg.RunnerOption.StartPostTimeoutDuration)
	if err != nil {
		xlog.Logger().Error().Str("log_type", "main").Str("op_type", "runner").Err(err).Msg("exec startPost funcs")
		panic(err)
	}

	err = runner.ExecDaemonStart(&wg)
	if err != nil {
		xlog.Logger().Error().Str("log_type", "main").Str("op_type", "runner").Err(err).Msg("exec daemon start funcs")
		panic(err)
	}

	signalChan := make(chan os.Signal, 1)
	signals := []os.Signal{syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP}
	signal.Notify(signalChan, signals...)
	for {
		sg := <-signalChan
		logEvent := xlog.Logger().Info().Str("log_type", "main").Str("signal", sg.String())
		if sg == syscall.SIGHUP {
			logEvent.Str("op_type", "reload")
			err = srv.Reload()
			logEvent.AnErr("err_update_configuration", err)
			msg := "server reload configuration, success"
			if err != nil {
				msg = "server reload configuration, failed"
			}

			//err = runner.ExecDaemonReload(cfg.RunnerOption.DaemonReloadTimeoutDuration)
			//logEvent.AnErr("err_runner_daemon_reload", err)
			logEvent.Msg(msg)
		} else {
			logEvent.Str("op_type", "shutdown")

			// shutdown process:
			// 1. stop all daemons
			err = runner.ExecDaemonStop(cfg.RunnerOption.DaemonStopTimeoutDuration)
			logEvent.AnErr("err_runner_stop", err)

			// 2. shutdown server
			ctx, cancel := context.WithTimeout(context.TODO(), cfg.Global.ShutdownDuration)
			serr := srv.Shutdown(ctx)
			cancel()
			logEvent.AnErr("err_server_shutdown", serr)
			msg := "server shutdown completely"
			if err != nil {
				msg = "server shutdown timeout, force quit"
			}

			// 3. shutdown others after server shutdown
			err = runner.ExecShutdown(cfg.RunnerOption.ShutdownTimeoutDuration)
			logEvent.AnErr("error_runner_shutdown", err)

			logEvent.Msg(msg)
			if serr != nil {
				os.Exit(1)
			}
			break
		}
	}

	wg.Wait()

}
