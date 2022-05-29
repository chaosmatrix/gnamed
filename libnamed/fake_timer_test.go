package libnamed

import (
	"fmt"
	"testing"
	"time"
)

func TestFakeTimer(t *testing.T) {
	var precision int64 = 1
	ft := NewFakeTimer(time.Duration(precision) * time.Second)

	// start timer
	ft.Run()

	for i := 0; i < 10; i++ {
		now := time.Now().Unix()
		ts := ft.GetUnixSecond()

		diff := now - ts
		if diff > precision || diff < 0 {
			t.Errorf("Timer precision %d unfix %d\n", diff, precision)
		} else {
			fmt.Printf("Precission %d - %d = %d, fix %d\n", now, ts, diff, precision)
		}
		time.Sleep(time.Duration(i%3) * time.Second)
	}

	// stop timer
	ft.Stop()
}
