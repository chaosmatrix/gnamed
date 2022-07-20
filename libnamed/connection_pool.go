package libnamed

import (
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

/*
 * Simple ConnectionPool - FIFO with global lock
 */

type ConnectionPool struct {
	size        int
	newConn     func() (interface{}, error)
	lock        sync.Mutex
	idleTimeout time.Duration
	waitTimeout time.Duration
	queue       chan *Connection
}

type Connection struct {
	conn      interface{}
	expiredAt int64
}

var errTimeout error

func NewConnectionPool(size int, idleTimeout time.Duration, waitTimeout time.Duration, f func() (interface{}, error)) *ConnectionPool {
	errTimeout = fmt.Errorf("wait avaliable connection in connection pool, timeout after %s", waitTimeout)
	return &ConnectionPool{
		size:        size,
		newConn:     f,
		idleTimeout: idleTimeout,
		waitTimeout: waitTimeout,
		queue:       make(chan *Connection, size),
	}
}

// FIFO
// connection, latency, cached, error
// Warning: unable to ensure conn is valid (didn't close by other side), caller should create new conn if conn invalid
func (cp *ConnectionPool) Get() (interface{}, time.Duration, bool, error) {
	cp.lock.Lock()
	start := time.Now()
	nowUnix := start.Unix()

	freeCnt := len(cp.queue)
	for i := 0; i < freeCnt; i++ {
		conn := <-cp.queue
		if conn.expiredAt > nowUnix && conn.conn != nil {
			cp.lock.Unlock()
			// valid connection
			// TODO: golang hasn't valid way to test connection has been closed by other side
			// read 0-byte from conn always return nil https://github.com/golang/go/issues/10940#issuecomment-245773886
			return conn.conn, time.Since(start), true, nil
		} else if conn.conn != nil {
			dnsConn, ok := conn.conn.(*dns.Conn)
			if ok && dnsConn != nil {
				dnsConn.Close()
			}
		}
	}

	// create new connection or wait
	if freeCnt < cp.size {
		cp.lock.Unlock()
		// create new connection
		c, err := cp.newConn()
		if err != nil {
			return nil, time.Since(start), false, err
		}
		return c, time.Since(start), false, nil
	} else {
		cp.lock.Unlock()
		// wait
		select {
		case conn := <-cp.queue:
			// no need to check expired or not
			return conn.conn, time.Since(start), true, nil
		case <-time.After(cp.waitTimeout):
			return nil, time.Since(start), false, errTimeout
		}
	}
}

func (cp *ConnectionPool) Put(conn interface{}) {
	cp.lock.Lock()
	defer cp.lock.Unlock()
	cp.queue <- &Connection{
		conn:      conn,
		expiredAt: time.Now().Add(cp.idleTimeout).Unix(),
	}
}
