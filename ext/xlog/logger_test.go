package xlog

import "testing"

func TestLogger(t *testing.T) {
	Logger().Info().Str("log_type", "test").Str("op_type", "test_logger").Msg("")
	Logger().Trace().Str("log_type", "test").Str("op_type", "test_logger").Msg("")

	levels := []string{"info", "trace", "debug", "error"}
	for _, ls := range levels {
		lc := &LogConfig{Level: ls}
		if err := lc.Parse(); err != nil {
			t.Error(err)
		}
		if level := Logger().GetLevel(); level != lc.level {
			t.Errorf("[+] bug: incorrect log level: %s != %s\n", level, lc.level)
		}
		Logger().Trace().Str("log_type", "test").Str("op_type", "test_logger").Msg("")
	}
}
