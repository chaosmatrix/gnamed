package libnamed

import (
	"errors"
	"fmt"
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
	errClosedByPeer = errors.New("cache connection closed by peer")
)

type ConnectionPool struct {
	MaxConn     int
	NewConn     func() (*dns.Conn, error)  // create new connection
	IsValidConn func(conn *dns.Conn) bool  // check connection, closed by peer or not
	CloseConn   func(conn *dns.Conn) error // close connection, release resource
	lock        sync.Mutex
	IdleTimeout time.Duration
	WaitTimeout time.Duration
	queue       chan *Connection
}

type Connection struct {
	conn      *dns.Conn // use (value).(type) failed to convert interface to given struct, aka. *dns.Conn
	expiredAt int64
}

var errTimeout error

func NewConnectionPool(cp *ConnectionPool) (*ConnectionPool, error) {
	errTimeout = fmt.Errorf("wait avaliable connection in connection pool, timeout after %s", cp.WaitTimeout)
	if cp.NewConn == nil || cp.IsValidConn == nil || cp.CloseConn == nil {
		return nil, errors.New("connection pool no valid function 'NewConn' || 'IsValidConn' || 'CloseConn'")
	}
	return &ConnectionPool{
		MaxConn:     cp.MaxConn,
		NewConn:     cp.NewConn,
		IsValidConn: cp.IsValidConn,
		CloseConn:   cp.CloseConn,
		lock:        sync.Mutex{},
		IdleTimeout: cp.IdleTimeout,
		WaitTimeout: cp.WaitTimeout,
		queue:       make(chan *Connection, cp.MaxConn),
	}, nil
}

// FIFO
// connection, latency, cached, error
// Warning: unable to ensure conn is valid (didn't close by other side), caller should create new conn if conn invalid
func (cp *ConnectionPool) Get() (*dns.Conn, time.Duration, bool, error) {
	cp.lock.Lock()
	start := time.Now()
	nowUnix := start.Unix()
	var conn *Connection

	freeCnt := len(cp.queue)
	for i := 0; i < freeCnt; i++ {
		conn = <-cp.queue
		if conn.expiredAt > nowUnix {
			cp.lock.Unlock()
			// valid connection
			// TODO: golang hasn't valid way to test connection has been closed by other side
			// read 0-byte from conn always return nil https://github.com/golang/go/issues/10940#issuecomment-245773886
			goto checkConn
		} else {
			cp.CloseConn(conn.conn)
		}
	}

	// create new connection or wait
	if freeCnt < cp.MaxConn {
		cp.lock.Unlock()
		// create new connection
		c, err := cp.NewConn()
		if err != nil {
			return nil, time.Since(start), false, err
		}
		return c, time.Since(start), false, nil
	} else {
		cp.lock.Unlock()
		// wait
		select {
		case conn = <-cp.queue:
			// no need to check expired or not
			// might be closed by peer cause max requests limit
			goto checkConn
		case <-time.After(cp.WaitTimeout):
			return nil, time.Since(start), false, errTimeout
		}
	}

checkConn:
	if conn == nil {
		return nil, time.Since(start), false, errors.New("conn: nil pointer")
	}
	if !cp.IsValidConn(conn.conn) {
		cp.CloseConn(conn.conn)
		return nil, time.Since(start), false, errClosedByPeer
	}
	return conn.conn, time.Since(start), true, nil
}

func (cp *ConnectionPool) Put(conn *dns.Conn) {
	cp.lock.Lock()
	defer cp.lock.Unlock()
	if len(cp.queue) >= cp.MaxConn {
		return
	}
	cp.queue <- &Connection{
		conn:      conn,
		expiredAt: time.Now().Add(cp.IdleTimeout).Unix(),
	}
}

func ConnClosedByPeer(conn net.Conn, timeout time.Duration) bool {
	err := conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return true
	}

	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err == io.EOF || n != 0 {
		return true
	}

	//conn.SetReadDeadline(time.Time{})
	return false
}
