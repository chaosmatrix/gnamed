package libnamed

import (
	"container/list"
	"errors"
	"sync"
	"time"

	"github.com/miekg/dns"
)

/*
 * Simple ConnectionPool - FIFO with global lock
 *
 * Design Goal: maximize the rate of reusable connection
 *
 */

type ConnectionPool struct {
	MaxConn     int
	MaxReqs     int
	NewConn     func() (*dns.Conn, error)  // create new connection
	CloseConn   func(conn *dns.Conn) error // close connection, release resource
	lock        sync.Mutex
	IdleTimeout time.Duration
	free        *list.List
	busy        *list.List
}

type Entry struct {
	conn      *dns.Conn // use (value).(type) failed to convert interface to given struct, aka. *dns.Conn
	econn     *EConn
	reqs      int
	expiredAt int64
}

type Conn struct {
	Conn *dns.Conn
	e    *list.Element // refer into Entry
}

func NewConnectionPool(cp *ConnectionPool) (*ConnectionPool, error) {
	if cp.NewConn == nil || cp.CloseConn == nil {
		return nil, errors.New("connection pool no valid function 'NewConn' || 'CloseConn'")
	}

	if cp.MaxConn <= 0 || cp.MaxReqs <= 0 {
		return nil, nil
	}

	return &ConnectionPool{
		MaxConn:     cp.MaxConn,
		MaxReqs:     cp.MaxReqs,
		NewConn:     cp.NewConn,
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
		cp.free.Remove(e)
		var ok bool
		entry, ok = e.Value.(*Entry)
		if !ok {
			continue
		}
		if entry.expiredAt > nowUnix && entry.reqs < cp.MaxReqs {
			if _err := entry.econn.CheckConn(); _err != nil || entry.econn.err != nil {
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
		hit = false

		entry = &Entry{}
		entry.conn, err = cp.NewConn()
		if err == nil {
			var econn *EConn
			econn, err = SetupConn(entry.conn.Conn, 1*time.Millisecond)
			entry.econn = econn
		}
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
		} else {
			cp.CloseConn(entry.conn)
			entry = nil
		}
	} else if c.Conn != nil {
		cp.CloseConn(c.Conn)
	}
	cp.lock.Unlock()
}
