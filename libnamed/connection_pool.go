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

type DnsConnectionPool struct {
	size        int
	newConn     func() (*dns.Conn, error)
	lock        sync.Mutex
	idleTimeout time.Duration
	waitTimeout time.Duration
	queue       chan *Connection
}

type Connection struct {
	conn      *dns.Conn
	expiredAt int64
}

var errTimeout error

func NewDnsConnectionPool(size int, idleTimeout time.Duration, waitTimeout time.Duration, f func() (*dns.Conn, error)) *DnsConnectionPool {
	errTimeout = fmt.Errorf("wait avaliable connection in connection pool, timeout after %s", waitTimeout)
	return &DnsConnectionPool{
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
func (cp *DnsConnectionPool) Get() (*dns.Conn, time.Duration, bool, error) {
	cp.lock.Lock()
	defer cp.lock.Unlock()
	start := time.Now()
	nowUnix := start.Unix()

	freeCnt := len(cp.queue)
	for i := 0; i < freeCnt; i++ {
		conn := <-cp.queue
		if conn.expiredAt > nowUnix {
			// valid connection
			// TODO: golang hasn't valid way to test connection has been closed by other side
			// read 0-byte from conn always return nil https://github.com/golang/go/issues/10940#issuecomment-245773886
			return conn.conn, time.Since(start), true, nil
		}
	}

	// create new connection or wait
	if freeCnt < cp.size {
		// create new connection
		c, err := cp.newConn()
		if err != nil {
			return nil, time.Since(start), false, err
		}
		return c, time.Since(start), false, nil
	} else {
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

func (cp *DnsConnectionPool) Put(conn *dns.Conn) {
	cp.lock.Lock()
	defer cp.lock.Unlock()
	cp.queue <- &Connection{
		conn:      conn,
		expiredAt: time.Now().Add(cp.idleTimeout).Unix(),
	}
}
