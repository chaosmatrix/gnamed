package libnamed

import (
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

type DConnection struct {
	IncomingMsg *dns.Msg       // incoming dns message
	Log         *zerolog.Event // connection log
	SubLog      *zerolog.Event // log about outgoing queries
}

func (dc *DConnection) Copy() *DConnection {
	return &DConnection{
		IncomingMsg: dc.IncomingMsg.Copy(),
		Log:         dc.Log,
		SubLog:      zerolog.Dict(),
	}
}
