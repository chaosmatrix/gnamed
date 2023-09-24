package runner

import (
	"context"
	"fmt"
	"gnamed/libnamed"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type RunnerOption struct {
	StartPreTimeout     string `json:"startPreTimeout"`
	StartPostTimeout    string `json:"startPostTimeout"`
	DaemonStopTimeout   string `json:"daemonStopTimeout"`
	DaemonReloadTimeout string `json:"daemonReloadTimeout"`
	ShutdownTimeout     string `json:"shutdownTimeout"`

	StartPreTimeoutDuration     time.Duration `json:"-"`
	StartPostTimeoutDuration    time.Duration `json:"-"`
	DaemonStopTimeoutDuration   time.Duration `json:"-"`
	DaemonReloadTimeoutDuration time.Duration `json:"-"`
	ShutdownTimeoutDuration     time.Duration `json:"-"`
}

type Runner struct {
	startPre  []*onceFunc   // before server start
	startPost []*onceFunc   // after server started
	daemon    []*daemonFunc // daemon function run with timer
	shutdown  []*onceFunc   // after server shutdown
}

type onceFunc struct {
	funcName string
	f        func() error
}

type daemonFunc struct {
	startFuncName  string
	startFunc      func() error
	stopFuncName   string
	stopFunc       func() error
	reloadFuncName string
	reloadFunc     func() error
}

var _runner *Runner

func init() {
	_runner = InitRunner()
}

var _oldRunner *Runner

func KeepDefaultRunner() {
	_oldRunner = _runner
}

func NewAndKeepDefaultRunner() {
	_runner, _oldRunner = InitRunner(), _runner
}

func RestoreDefaultRunner() {
	_runner, _oldRunner = _oldRunner, _runner
	_oldRunner = nil
}

func NewDefaultRunner() {
	_runner = InitRunner()
}

func InitRunner() *Runner {
	return &Runner{
		startPre:  []*onceFunc{},
		startPost: []*onceFunc{},
		daemon:    []*daemonFunc{},
	}
}

func (ropt *RunnerOption) Parse() error {
	return ropt.parse()
}

func (ropt *RunnerOption) parse() error {
	ropt.StartPreTimeoutDuration = parseDefaultDuration(ropt.StartPreTimeout, 30*time.Second)

	ropt.StartPostTimeoutDuration = parseDefaultDuration(ropt.StartPostTimeout, 30*time.Second)

	ropt.DaemonStopTimeoutDuration = parseDefaultDuration(ropt.DaemonStopTimeout, 30*time.Second)

	ropt.DaemonReloadTimeoutDuration = parseDefaultDuration(ropt.DaemonReloadTimeout, 30*time.Second)

	ropt.ShutdownTimeoutDuration = parseDefaultDuration(ropt.ShutdownTimeout, 30*time.Second)

	return nil
}

func parseDefaultDuration(s string, d time.Duration) time.Duration {
	if len(s) == 0 {
		return d
	} else if t, err := time.ParseDuration(s); err == nil && t > 0 {
		return t
	}
	return d
}

func runOnceFuncs(ctx context.Context, ofs []*onceFunc, s string) error {
	errCnt := &atomic.Uint32{}

	var wg sync.WaitGroup
	for i := range ofs {
		wg.Add(1)
		go func(of *onceFunc) {
			start := time.Now()
			logEvent := libnamed.Logger.Debug().Str("log_type", "runner").Str("op_type", s).Str("func", of.funcName)
			err := of.f()
			if err != nil {
				errCnt.Add(1)
			}
			logEvent.Dur("elapsed_time", time.Since(start)).Err(err).Msg("")
			wg.Done()
		}(ofs[i])
	}

	finishChan := make(chan struct{})
	go func() {
		wg.Wait()
		finishChan <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-finishChan:
		//
	}
	if cnt := errCnt.Load(); cnt > 0 {
		return fmt.Errorf("more than one func return error, total: %d, err: %d", len(ofs), cnt)
	}
	return nil
}

func ExecStartPre(timeout time.Duration) error {
	return _runner.ExecStartPre(timeout)
}

func (r *Runner) ExecStartPre(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return runOnceFuncs(ctx, r.startPre, "startPre")
}

func ExecStartPost(timeout time.Duration) error {
	return _runner.ExecStartPost(timeout)
}

func (r *Runner) ExecStartPost(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return runOnceFuncs(ctx, r.startPost, "startPost")
}

func ExecShutdown(timeout time.Duration) error {
	return _runner.ExecShutdown(timeout)
}

func (r *Runner) ExecShutdown(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return runOnceFuncs(ctx, r.shutdown, "shutdown")
}

func ExecDaemonStart(wg *sync.WaitGroup) error {
	return _runner.ExecDaemonStart(wg)
}

func (r *Runner) ExecDaemonStart(wg *sync.WaitGroup) error {

	for i := range r.daemon {
		wg.Add(1)
		go func(df *daemonFunc) {
			libnamed.Logger.Debug().Str("log_type", "runner").Str("op_type", "daemon").Str("func", df.startFuncName).Msg("start ...")
			err := df.startFunc()
			libnamed.Logger.Debug().Str("log_type", "runner").Str("op_type", "daemon").Str("func", df.startFuncName).Err(err).Msg("stoped")
			wg.Done()
		}(r.daemon[i])
	}
	return nil
}

func ExecDaemonReload(timeout time.Duration) error {
	return _runner.ExecDaemonReload(timeout)
}

func (r *Runner) ExecDaemonReload(timeout time.Duration) error {

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var wg sync.WaitGroup
	for i := range r.daemon {
		wg.Add(1)
		go func(df *daemonFunc) {
			libnamed.Logger.Debug().Str("log_type", "runner").Str("op_type", "daemon").Str("func", df.reloadFuncName).Msg("sending reload signal ...")
			err := df.reloadFunc()
			libnamed.Logger.Debug().Str("log_type", "runner").Str("op_type", "daemon").Str("func", df.reloadFuncName).Err(err).Msg("sended reload signal")
			wg.Done()
		}(r.daemon[i])
	}
	finishChan := make(chan struct{})
	go func() {
		wg.Wait()
		finishChan <- struct{}{}
	}()

	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-finishChan:
		//
	}
	return err
}

func ExecDaemonStop(timeout time.Duration) error {
	return _runner.ExecDaemonStop(timeout)
}

func (r *Runner) ExecDaemonStop(timeout time.Duration) error {

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var swg sync.WaitGroup
	for i := range r.daemon {
		swg.Add(1)
		go func(df *daemonFunc) {
			libnamed.Logger.Debug().Str("log_type", "runner").Str("op_type", "daemon").Str("func", df.stopFuncName).Msg("sending stop signal ...")
			err := df.stopFunc()
			libnamed.Logger.Debug().Str("log_type", "runner").Str("op_type", "daemon").Str("func", df.stopFuncName).Err(err).Msg("sended stop signal")
			swg.Done()
		}(r.daemon[i])
	}

	finishChan := make(chan struct{})

	go func() {
		swg.Wait()
		finishChan <- struct{}{}
	}()

	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-finishChan:
		//
	}
	return err
}

func RegisterStartPre(funcName string, f func() error) {
	_runner.RegisterStartPre(funcName, f)
}

func (r *Runner) RegisterStartPre(funcName string, f func() error) {
	of := &onceFunc{funcName: funcName, f: f}
	r.startPre = append(r.startPre, of)
}

func RegisterStartPost(funcName string, f func() error) {
	_runner.RegisterStartPost(funcName, f)
}

func (r *Runner) RegisterStartPost(funcName string, f func() error) {
	of := &onceFunc{funcName: funcName, f: f}
	r.startPost = append(r.startPost, of)
}

func RegisterShutdown(funcName string, f func() error) {
	_runner.RegisterShutdown(funcName, f)
}

func (r *Runner) RegisterShutdown(funcName string, f func() error) {
	of := &onceFunc{funcName: funcName, f: f}
	r.shutdown = append(r.shutdown, of)
}

func RegisterDaemon(startFuncName string, startFunc func() error, reloadFuncName string, reloadFunc func() error, stopFuncName string, stopFunc func() error) {
	_runner.RegisterDaemon(startFuncName, startFunc, reloadFuncName, reloadFunc, stopFuncName, stopFunc)
}

func (r *Runner) RegisterDaemon(startFuncName string, startFunc func() error, reloadFuncName string, reloadFunc func() error, stopFuncName string, stopFunc func() error) {
	df := &daemonFunc{
		startFuncName:  startFuncName,
		startFunc:      startFunc,
		reloadFuncName: reloadFuncName,
		reloadFunc:     reloadFunc,
		stopFuncName:   stopFuncName,
		stopFunc:       stopFunc,
	}
	r.daemon = append(r.daemon, df)
}

func getFuncName(v interface{}) string {
	f := runtime.FuncForPC(reflect.ValueOf(v).Pointer())
	if f == nil {
		return ""
	}
	return f.Name()
}
