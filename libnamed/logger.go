package libnamed

import (
	"os"
	"strings"

	"github.com/rs/zerolog"
)

// TODO: should not public
var Logger zerolog.Logger

type LogType string

const (
	LogTypeConsole = "console"
	LogTypeFile    = "file"
	LogTypeUdp     = "udp"
	LogTypeTcp     = "tcp"
	LogTypeSyslog  = "syslog"

	DefaultLogType = LogTypeConsole
)

func InitDefaultLogger(logFile string, logLevel string) error {
	var logType LogType = DefaultLogType
	logPath := ""
	if logCfgs := strings.Split(logFile, ":"); len(logCfgs) == 2 {
		logType = LogType(logCfgs[0])
		logPath = logCfgs[1]
	} else if len(logCfgs) == 1 {
		logType = LogType(logCfgs[0])
	}
	return NewDefaultLogger(string(logType), logPath, logLevel)
}

func NewLogger(ftype string, fname string, level string) (zerolog.Logger, error) {
	return newLogger(ftype, fname, level)
}

func NewDefaultLogger(ftype string, fname string, level string) error {
	var err error

	Logger, err = newLogger(ftype, fname, level)

	return err
}

func newLogger(ftype string, fname string, level string) (zerolog.Logger, error) {
	var err error
	var logger zerolog.Logger

	switch ftype {
	case LogTypeConsole:
		logger = zerolog.New(os.Stderr).With().Timestamp().Stack().Logger()
	case LogTypeFile:
		var fd *os.File
		fd, err = os.Open(fname)
		if err == nil {
			logger = zerolog.New(fd).With().Timestamp().Stack().Logger()
		}
	default:
		logger = zerolog.New(os.Stderr).With().Timestamp().Stack().Logger()
	}
	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		return logger, err
	}
	zerolog.SetGlobalLevel(logLevel)
	return logger, err
}
