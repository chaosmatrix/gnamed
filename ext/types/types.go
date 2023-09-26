package types

import (
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

type DConnection struct {
	OutgoingMsg *dns.Msg       // outgoing dns message, use to send outgoing query
	incomingMsg *dns.Msg       // keep origin incoming dns message
	Log         *zerolog.Event // connection log
	SubLog      *zerolog.Event // log about outgoing queries
}

func (dc *DConnection) Copy() *DConnection {
	return &DConnection{
		OutgoingMsg: dc.OutgoingMsg.Copy(),
		Log:         dc.Log,
		SubLog:      zerolog.Dict(),
	}
}

func (dc *DConnection) GetIncomingMsg() *dns.Msg {
	if dc.incomingMsg == nil {
		return dc.OutgoingMsg
	}
	return dc.incomingMsg
}

func (dc *DConnection) SetIncomingMsg() {
	dc.incomingMsg = dc.OutgoingMsg.Copy()
}
