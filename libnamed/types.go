package libnamed

import (
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

type DConnection struct {
	IncomingMsg *dns.Msg       // incoming dns message
	Log         *zerolog.Event // connection log
}
