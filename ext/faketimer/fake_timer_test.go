package faketimer

import (
	"fmt"
	"gnamed/ext/runner"
	"testing"
	"time"
)

func TestFakeTimer(t *testing.T) {
	fti := FakeTimerInfo{
		Precision: "1s",
	}
	fti.parse()
	precision := int64(fti.precision.Seconds())

	for i := 0; i < 10; i++ {
		now := time.Now().Unix()
		ts := GetUnixSecond()

		diff := now - ts
		if diff > precision || diff < 0 {
			t.Errorf("[+] bug: time %d(builtin) - %d(fake) = %d, precision %d\n", now, ts, diff, precision)
		} else {
			fmt.Printf("[+] time %d(builtin) - %d(fake) = %d, precision %d\n", now, ts, diff, precision)
		}
		time.Sleep(time.Duration(i%3) * time.Second)
	}

	runner.ExecShutdown(30 * time.Second)
}

// ~ 0.2 ns/op
func BenchmarkFakeTimer(b *testing.B) {
	ft := newFakeTimer(1 * time.Second)
	ft.run()

	for i := 0; i < b.N; i++ {
		GetUnixSecond()
	}
	ft.stop()
}

// ~ 4 ns/op
func BenchmarkBuiltinTime(b *testing.B) {

	for i := 0; i < b.N; i++ {
		time.Now().Unix()
	}
}
