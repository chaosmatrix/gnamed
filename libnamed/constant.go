package libnamed

import "errors"

var (
	ErrDisableQuic = errors.New("quic feature has been disable, binary was build with '-tags=\"noquic\"'")
)
