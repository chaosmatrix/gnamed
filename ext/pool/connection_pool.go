package pool

import (
	"container/list"
	"errors"
	"fmt"
	"gnamed/ext/xlog"
	"sync"
	"time"
	"unsafe"

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
	MaxRequests int
	NewConn     func() (*dns.Conn, error)  // create new connection
	CloseConn   func(conn *dns.Conn) error // close connection, release resource
	lock        *sync.Mutex
	IdleTimeout time.Duration
	free        *list.List // connection in idle
	busy        uint64
}

type Entry struct {
	Conn      *dns.Conn // use (value).(type) failed to convert interface to given struct, aka. *dns.Conn
	econn     *EConn
	requests  int
	expiredAt int64
}

type Pool struct {
	IdleTimeout         string        `json:"idleTimeout"`
	idleTimeoutDuration time.Duration `json:"-"`
	Size                int           `json:"size"`
	Requests            int           `json:"requests"`
}

func (p *Pool) Parse() error {
	return p.parse()
}

func (p *Pool) parse() error {
	if p.Size < 0 {
		err := fmt.Errorf("invalid pool size: %d", p.Size)
		return err
	} else if p.Size == 0 {
		p.Size = 5
	}
	if p.Requests < 0 {
		err := fmt.Errorf("invalid pool per connection request limit: %d", p.Requests)
		return err
	} else if p.Requests == 0 {
		p.Requests = 32
	}
	if p.IdleTimeout != "" {
		if d, err := time.ParseDuration(p.IdleTimeout); err == nil && d > 0 {
			p.idleTimeoutDuration = d
		} else {
			if err == nil {
				err = fmt.Errorf("invalid pool idleTimeout: %s", p.IdleTimeout)
			}
			return err
		}
	} else {
		p.idleTimeoutDuration = 65 * time.Second
	}
	return nil
}

func (p *Pool) NewConnectionPool(newConn func() (*dns.Conn, error), closeConn func(conn *dns.Conn) error) (*ConnectionPool, error) {
	if newConn == nil || closeConn == nil {
		return nil, fmt.Errorf("func newConn and closeConn must not nil")
	}
	if p.Size <= 0 || p.Requests <= 0 || p.idleTimeoutDuration <= 0 {
		return nil, fmt.Errorf("invalid pool options")
	}
	return &ConnectionPool{
		MaxConn:     p.Size,
		MaxRequests: p.Requests,
		NewConn:     newConn,
		CloseConn:   closeConn,
		lock:        &sync.Mutex{},
		IdleTimeout: p.idleTimeoutDuration,
		free:        list.New(),
	}, nil
}

func NewConnectionPool(cp *ConnectionPool) (*ConnectionPool, error) {
	if cp.NewConn == nil || cp.CloseConn == nil {
		return nil, errors.New("connection pool no valid function 'NewConn' || 'CloseConn'")
	}

	if cp.MaxConn <= 0 || cp.MaxRequests <= 0 {
		return nil, nil
	}

	return &ConnectionPool{
		MaxConn:     cp.MaxConn,
		MaxRequests: cp.MaxRequests,
		NewConn:     cp.NewConn,
		CloseConn:   cp.CloseConn,
		lock:        &sync.Mutex{},
		IdleTimeout: cp.IdleTimeout,
		free:        list.New(),
	}, nil
}

// FIFO
// connection, latency, cached, error
// Warning: unable to ensure conn is valid (didn't close by other side), caller should create new conn if conn invalid
func (cp *ConnectionPool) Get() (*Entry, time.Duration, bool, error) {
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
		if entry.expiredAt > nowUnix && entry.requests < cp.MaxRequests {
			if _err := entry.econn.CheckConn(); _err != nil || entry.econn.err != nil {
				// connection closed by peer
				// FIXME: close connection would be block in some situation
				go cp.CloseConn(entry.Conn)
			} else {
				break
			}
		} else {
			go cp.CloseConn(entry.Conn)
		}
		entry = nil
	}

	hit := true
	if entry == nil {
		hit = false

		entry = &Entry{}
		entry.Conn, err = cp.NewConn()
		if err == nil {
			var econn *EConn
			econn, err = SetupConn(entry.Conn.Conn, 1*time.Millisecond)
			entry.econn = econn
		}
	}

	cp.busy++

	entry.expiredAt = time.Now().Add(cp.IdleTimeout).Unix()
	entry.requests++
	xlog.Logger().Trace().Str("log_type", "connection_pool").Str("op_type", "get").Uint64("pointer", uint64(uintptr(unsafe.Pointer(entry)))).Int("requests", entry.requests).Int("free_size", cp.free.Len()).Uint64("busy", cp.busy).Msg("")
	cp.lock.Unlock()
	return entry, time.Since(start), hit, err
}

func (cp *ConnectionPool) Put(ce *Entry) {
	if ce == nil || ce.Conn == nil {
		return
	}
	cp.lock.Lock()
	defer cp.lock.Unlock()
	cp.busy--

	logEvent := xlog.Logger().Trace().Str("log_type", "connection_pool").Str("op_type", "put").Uint64("pointer", uint64(uintptr(unsafe.Pointer(ce)))).Int("requests", ce.requests)
	if ce.Conn != nil && cp.free.Len() < cp.MaxConn && ce.requests < cp.MaxRequests {
		ce.expiredAt = time.Now().Add(cp.IdleTimeout).Unix()
		cp.free.PushFront(ce)
		logEvent.Int("free_size", cp.free.Len()).Uint64("busy", cp.busy).Bool("reuse", true).Msg("")
		return
	} else if ce.Conn != nil {
		go func() {
			cp.CloseConn(ce.Conn)
			ce = nil
		}()
	}
	logEvent.Int("free_size", cp.free.Len()).Uint64("busy", cp.busy).Bool("reuse", false).Msg("")
}
