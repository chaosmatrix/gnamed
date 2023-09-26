package xlog

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sync/atomic"

	"github.com/rs/zerolog"
)

var _logger *atomic.Value = new(atomic.Value)

// stderr
// stdout
// file:///path/log
// tcp://127.0.0.1:12345
// udp://127.0.0.1:12345
// unix:///path/syslog.socket
type LogConfig struct {
	Level string // default debug
	Fd    string // default stderr

	// internal
	level zerolog.Level
	fw    io.Writer
}

func init() {
	l := &LogConfig{}
	err := l.parse()
	if err != nil {
		panic(err)
	}

	logger, err := l.new()
	if err != nil {
		panic(err)
	}
	_logger.Store(logger)
}

// return default logger
func Logger() *zerolog.Logger {
	return _logger.Load().(*zerolog.Logger)
}

func (l *LogConfig) Parse() error {
	if err := l.parse(); err != nil {
		return err
	}
	return initDefaultLogger(l)
}

func (l *LogConfig) parse() error {

	if l.Level == "" {
		l.Level = "debug"
	}

	level, err := zerolog.ParseLevel(l.Level)
	if err != nil {
		return err
	}
	l.level = level

	if l.Fd == "" {
		l.fw = os.Stderr
	} else {
		switch l.Fd {
		case "stderr":
			l.fw = os.Stderr
		case "stdout":
			l.fw = os.Stdout
		default:
			u, err := url.Parse(l.Fd)
			if err != nil {
				return fmt.Errorf("invalid Log File Path: %s, error: %v", l.Fd, err)
			}
			switch u.Scheme {
			case "tcp", "udp", "unix":
				c, err := net.Dial(u.Scheme, u.Host)
				if err != nil {
					return fmt.Errorf("invalid Log File Path: %s, error: %v", l.Fd, err)
				}
				l.fw = c
			case "file":
				i := len(u.Scheme) + len("://")
				if i <= len(l.Fd) {
					return fmt.Errorf("invalid Log Path: %s", l.Fd)
				}
				fw, err := os.OpenFile(l.Fd[i:], os.O_RDWR|os.O_APPEND, 0666)
				if err != nil {
					return fmt.Errorf("invalid Log Path: %s, error: %v", l.Fd, err)
				}
				l.fw = fw
			default:
				return fmt.Errorf("invalid Log File Path: %s, error: log protocol not implement", l.Fd)
			}
		}
	}

	return nil
}

func (l *LogConfig) new() (*zerolog.Logger, error) {
	logger := zerolog.New(l.fw).With().Timestamp().Stack().Logger().Level(l.level)
	//zerolog.SetGlobalLevel(l.level)
	return &logger, nil
}

func NewLogger(l *LogConfig) (*zerolog.Logger, error) {
	if err := l.parse(); err != nil {
		return nil, err
	}
	logger, err := l.new()
	return logger, err
}

func initDefaultLogger(l *LogConfig) error {
	logger, err := l.new()
	if err != nil {
		return err
	}
	_logger.Store(logger)
	return nil
}
