package libnamed

import (
	"sync/atomic"
	"time"
)

// use FakeTimer to minimize timer.Now() function call, but decrease precision

var (
	// init as 0 not time.Now().Unix(), make sure caller call Run() function
	nowUnixSecond int64 = 0
)

type FakeTimer struct {
	done      chan struct{}
	precision time.Duration
	t         *time.Ticker
}

var fakeTimer *FakeTimer

func NewFakeTimer(precision time.Duration) *FakeTimer {
	fakeTimer = &FakeTimer{
		precision: precision,
		t:         time.NewTicker(precision),
		done:      make(chan struct{}, 1),
	}

	return fakeTimer
}

func (ft *FakeTimer) Run() {
	// init value before go into ticker cycle
	atomic.StoreInt64(&nowUnixSecond, time.Now().Unix())
	go func() {
		for {
			select {
			case <-ft.t.C:
				now := time.Now().Unix()
				atomic.StoreInt64(&nowUnixSecond, now)
			case <-ft.done:
				return
			}
		}
	}()
}

func (ft *FakeTimer) Stop() {
	ft.done <- struct{}{}
}

func (ft *FakeTimer) GetUnixSecond() int64 {
	return atomic.LoadInt64(&nowUnixSecond)
}

// Global
func GetUnixSecond() int64 {
	return fakeTimer.GetUnixSecond()
}

func GetFakeTimerUnixSecond() int64 {
	return fakeTimer.GetUnixSecond()
}
