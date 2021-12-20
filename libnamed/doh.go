package libnamed

// reference: https://developers.cloudflare.com/1.1.1.1/encrypted-dns/dns-over-https/make-api-requests/dns-json
//
// header:
//  Accept: application/dns-json or Accept: application/json
//
type DOHJsonQuestion struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

type DOHJsonAnswer struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  int64  `json:"TTL"`
	Data string `json:"data"`
}

// rfc: https://datatracker.ietf.org/doc/html/rfc1035
// some flags associate with rfc1035
//
type DOHJson struct {
	Status    int               `json:"Status"`              // require, dns.MsgHdr.Rcode
	TC        bool              `json:"TC"`                  // required, dns.MsgHdr.Truncated
	RD        bool              `json:"RD"`                  // required, dns.MsgHdr.RecursionDesired
	RA        bool              `json:"RA"`                  // required, dns.MsgHdr.RecursionAvailable
	AD        bool              `json:"AD"`                  // required, dns.MsgHdr.AuthenticatedData
	CD        bool              `json:"CD"`                  // required, dns.MsgHdr.CheckingDisabled
	Question  []DOHJsonQuestion `json:"Question"`            // required, dns.Msg.Question
	Answer    []DOHJsonAnswer   `json:"Answer"`              // require, dns.Msg.Answer
	Authority []DOHJsonAnswer   `json:"Authority,omitempty"` // optional, dns.Msg.Ns
	//Aditional []string          `json:"Aditional,omitempty"`          // optional, dns.Msg.Extra
	//ECS       string            `json:"edns_client_subnet,omitempty"` // optional
	//Comment   string            `json:"Comment,omitempty"`            // optional
}
