package libnamed

import (
	"container/list"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

/*
 * Simple ConnectionPool - FIFO with global lock
 */

var (
	defaultMaxReqs = 32
)

type ConnectionPool struct {
	MaxConn     int
	MaxReqs     int
	NewConn     func() (*dns.Conn, error)  // create new connection
	IsValidConn func(conn *dns.Conn) bool  // check connection, closed by peer or not
	CloseConn   func(conn *dns.Conn) error // close connection, release resource
	lock        sync.Mutex
	IdleTimeout time.Duration
	free        *list.List
	busy        *list.List
}

type Entry struct {
	conn      *dns.Conn // use (value).(type) failed to convert interface to given struct, aka. *dns.Conn
	reqs      int
	expiredAt int64
}

type Conn struct {
	Conn *dns.Conn
	e    *list.Element // refer into Connection
}

func NewConnectionPool(cp *ConnectionPool) (*ConnectionPool, error) {
	if cp.NewConn == nil || cp.IsValidConn == nil || cp.CloseConn == nil {
		return nil, errors.New("connection pool no valid function 'NewConn' || 'IsValidConn' || 'CloseConn'")
	}
	maxReqs := cp.MaxReqs
	if maxReqs <= 0 {
		maxReqs = defaultMaxReqs
	}
	return &ConnectionPool{
		MaxConn:     cp.MaxConn,
		MaxReqs:     maxReqs,
		NewConn:     cp.NewConn,
		IsValidConn: cp.IsValidConn,
		CloseConn:   cp.CloseConn,
		lock:        sync.Mutex{},
		IdleTimeout: cp.IdleTimeout,
		free:        list.New(),
		busy:        list.New(),
	}, nil
}

// FIFO
// connection, latency, cached, error
// Warning: unable to ensure conn is valid (didn't close by other side), caller should create new conn if conn invalid
func (cp *ConnectionPool) Get() (*Conn, time.Duration, bool, error) {
	cp.lock.Lock()
	start := time.Now()
	nowUnix := start.Unix()

	var entry *Entry
	var err error

	for cp.free.Len() != 0 {
		e := cp.free.Back()
		entry = e.Value.(*Entry)
		cp.free.Remove(e)
		if entry.expiredAt > nowUnix && entry.reqs < cp.MaxReqs {
			if !cp.IsValidConn(entry.conn) {
				// connection closed by peer
				// FIXME: close connection would be block in some situation
				cp.CloseConn(entry.conn)
			} else {
				break
			}
		} else {
			cp.CloseConn(entry.conn)
		}
		entry = nil
	}

	hit := true
	if entry == nil {
		entry = &Entry{}
		entry.conn, err = cp.NewConn()
		hit = false
	}

	entry.expiredAt = time.Now().Add(cp.IdleTimeout).Unix()
	entry.reqs++

	var e *list.Element = nil
	if err == nil {
		e = cp.busy.PushFront(entry)
	}

	c := &Conn{
		Conn: entry.conn,
		e:    e,
	}
	cp.lock.Unlock()
	return c, time.Since(start), hit, err
}

func (cp *ConnectionPool) Put(c *Conn) {
	if c == nil || c.e == nil {
		return
	}
	cp.lock.Lock()
	cp.busy.Remove(c.e)
	if c.Conn != nil && cp.free.Len() < cp.MaxConn {
		entry := c.e.Value.(*Entry)
		if entry.reqs < cp.MaxReqs {
			entry.expiredAt = time.Now().Add(cp.IdleTimeout).Unix()
			cp.free.PushFront(entry)
		}
	}
	cp.lock.Unlock()
}

func ConnClosedByPeer(conn net.Conn, timeout time.Duration) bool {
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

	// read 0-byte from conn always return nil https://github.com/golang/go/issues/10940#issuecomment-245773886
	buf := make([]byte, 1)

	err := conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return true
	}

	n, err := conn.Read(buf)
	if err == io.EOF || n != 0 {
		return true
	}

	// don't reset into no deadline
	// set deadline before read/write is good practice
	// conn.SetReadDeadline(time.Time{})
	return false
}
