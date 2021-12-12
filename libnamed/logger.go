package libnamed

import (
	"os"

	"github.com/rs/zerolog"
)

var Logger zerolog.Logger

type LogType string

const (
	LogTypeConsole = "console"
	LogTypeFile    = "file"
	LogTypeUdp     = "udp"
	LogTypeTcp     = "tcp"
	LogTypeSyslog  = "syslog"
)

func NewLogger(ftype string, fname string, level string) (zerolog.Logger, error) {
	return newLogger(ftype, fname, level)
}
func newLogger(ftype string, fname string, level string) (zerolog.Logger, error) {
	var err error

	switch ftype {
	case LogTypeConsole:
		Logger = zerolog.New(os.Stderr).With().Timestamp().Stack().Logger()
	case LogTypeFile:
		var fd *os.File
		fd, err = os.Open(fname)
		if err == nil {
			Logger = zerolog.New(fd).With().Timestamp().Stack().Logger()
		}
	default:
		Logger = zerolog.New(os.Stderr).With().Timestamp().Stack().Logger()
	}
	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		return Logger, err
	}
	zerolog.SetGlobalLevel(logLevel)
	return Logger, err
}
