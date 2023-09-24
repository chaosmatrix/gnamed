//go:build !detect_common

package pool

import (
	"errors"
	"net"
	"syscall"
	"time"
)

var (
	errInvalidConn    = errors.New("invalid conn, nil pointer")
	errConnPeerClosed = errors.New("connection has been closed by peer")
)

// syscall.EPOLLRDHUP: connection has been closed by peer, or shutdown_w
// syscall.EPOLLHUP : connection has been closed by peer, but there might some unread data
// syscall.EPOLLERR : error occure with connection associated fd
const watchEpollEvents uint32 = syscall.EPOLLRDHUP | syscall.EPOLLHUP | syscall.EPOLLERR

//var _ syscall.RawConn = &EConn{}

type EConn struct {
	rawConn syscall.RawConn
	efd     int
	err     error
}

func (ec *EConn) Control(f func(fd uintptr)) error {
	return ec.rawConn.Control(f)
}

/*
func (ec *EConn) Read(f func(fd uintptr) (done bool)) error {
	return ec.rawConn.Read(f)
}

func (ec *EConn) Write(f func(fd uintptr) (done bool)) error {
	return ec.rawConn.Write(f)
}
*/

func SetupConn(conn net.Conn, readTimeout time.Duration) (*EConn, error) {
	if conn == nil {
		return nil, errInvalidConn
	}

	rawConn, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		return nil, err
	}

	efd, err := syscall.EpollCreate1(0)
	if err != nil {
		return nil, err
	}

	ec := &EConn{
		rawConn: rawConn,
		efd:     efd,
		err:     nil,
	}

	err = ec.Control(func(fd uintptr) {
		err = syscall.EpollCtl(ec.efd, syscall.EPOLL_CTL_ADD, int(fd), &syscall.EpollEvent{Events: watchEpollEvents, Fd: int32(fd)})
		if err != nil {
			ec.err = err
			return
		}
	})

	if err != nil {
		return ec, err
	}

	return ec, ec.err
}

// < 10us
func (ec *EConn) CheckConn() error {

	err := ec.Control(func(fd uintptr) {
		events := make([]syscall.EpollEvent, 1)
		_, err := syscall.EpollWait(ec.efd, events, 0)
		if err != nil {
			ec.err = err
			return
		}
		if events[0].Events&watchEpollEvents != 0 {
			ec.err = errConnPeerClosed
		}
	})

	return err
}
