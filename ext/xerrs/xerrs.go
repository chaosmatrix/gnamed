package xerrs

import "errors"

var ErrDisableQuic = errors.New("disable quic support, build with tags 'noquic'")
