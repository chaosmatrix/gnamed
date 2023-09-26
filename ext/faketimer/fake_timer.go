package faketimer

import (
	"errors"
	"fmt"
	"gnamed/ext/runner"
	"gnamed/ext/xlog"
	"sync/atomic"
	"time"
)

// use FakeTimer to minimize timer.Now() function call, but decrease precision

var (
	// init as 0 not time.Now().Unix(), make sure caller call Run() function
	nowUnixSecond int64 = 0
)

type FakeTimerInfo struct {
	Precision string `json:"precision"`
	precision time.Duration
}

func (fti *FakeTimerInfo) Parse() error {
	return fti.parse()
}

func (fti *FakeTimerInfo) parse() error {
	if fti.Precision == "" {
		// DNS TTL's precision is 1 sec
		fti.precision = 1 * time.Second
	} else {
		if d, err := time.ParseDuration(fti.Precision); err != nil {
			return err
		} else if d <= 0 {
			return fmt.Errorf("invalid precision: %s, <= 0", fti.Precision)
		} else {
			fti.precision = d
		}
	}

	fakeTimer := newFakeTimer(fti.precision)
	fakeTimerValue.Store(fakeTimer)
	fakeTimer.run()

	runner.RegisterShutdown("StopFakeTimer", func() error {
		if fakeTimerValue != nil {
			fakeTimer, ok := fakeTimerValue.Load().(*FakeTimer)
			if !ok {
				return errors.New("invalid fakeTimer type")
			}
			fakeTimer.stop()
			return nil
		} else {
			return errors.New("no valid fakeTimer to stop")
		}
	})
	xlog.Logger().Info().Str("log_type", "fakeTimer").Str("op_type", "init").Str("precision", fti.precision.String()).Msg("")
	return nil
}

type FakeTimer struct {
	done      chan struct{}
	precision time.Duration
	t         *time.Ticker
}

var fakeTimerValue *atomic.Value = new(atomic.Value)

func newFakeTimer(precision time.Duration) *FakeTimer {
	fakeTimer := &FakeTimer{
		precision: precision,
		t:         time.NewTicker(precision),
		done:      make(chan struct{}, 1),
	}

	return fakeTimer
}

func (ft *FakeTimer) run() {
	// init value before go into ticker cycle
	atomic.StoreInt64(&nowUnixSecond, time.Now().Unix())
	go func() {
		for {
			select {
			case <-ft.t.C:
				atomic.StoreInt64(&nowUnixSecond, time.Now().Unix())
			case <-ft.done:
				return
			}
		}
	}()
}

func (ft *FakeTimer) stop() {
	ft.done <- struct{}{}
}

// Global
func GetUnixSecond() int64 {
	return atomic.LoadInt64(&nowUnixSecond)
}

func GetFakeTimerUnixSecond() int64 {
	return atomic.LoadInt64(&nowUnixSecond)
}
