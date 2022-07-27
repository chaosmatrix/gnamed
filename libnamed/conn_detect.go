//go:build !linux || detect_common

package libnamed

import (
	"errors"
	"io"
	"net"
	"time"
)

var (
	oneByteBuf = make([]byte, 1)
)

type EConn struct {
	conn    net.Conn
	timeout time.Duration
	err     error
}

func SetupConn(conn net.Conn, timeout time.Duration) (*EConn, error) {
	// preemptive scheduling, goroutines (Psyscall) schedule interval 20000 ns
	// Psyscall >= 20us
	// Prunning >= 10ms
	//
	// if Read() execute after ReadDeadline, Read() will return immedialy with error "i/o timeout",
	// and no way to make sure Read() will exec immedialy after SetReadDeadline()
	// chain:
	// src/net/net.go/SetDeadline() -> ... -> src/internal/poll/fd_poll_runtime.go/runtime_pollSetDeadline

	// extream case: cpu resource almost exhaust or cpu resource oversold (increase delay)
	// extreme case, safe timeout can make sure the Read() will be called instead timeout immedialy: > max(cpu.cfs_period_us - cpu.cfs_quota_us, 10ms)
	// normally, 50us ~ 1ms would be a suitable value, (use `perf trace -p $PID  -s` to get the reference of your machine and system)

	if timeout < 50*time.Microsecond {
		timeout = 50 * time.Microsecond
	}

	ec := &EConn{
		conn:    conn,
		timeout: timeout,
		err:     nil,
	}

	return ec, nil
}

func (ec *EConn) CheckConn() error {
	// read 0-byte from conn always return nil https://github.com/golang/go/issues/10940#issuecomment-245773886
	//buf := make([]byte, 1)

	err := ec.conn.SetReadDeadline(time.Now().Add(ec.timeout))
	if err != nil {
		return err
	}

	n, err := ec.conn.Read(oneByteBuf)
	if err == io.EOF {
		return err
	}

	if n != 0 {
		return errors.New("connection has unread data, can't be reuse")
	}

	// don't reset into no deadline
	// set deadline before read/write is good practice
	// conn.SetReadDeadline(time.Time{})
	return nil
}
