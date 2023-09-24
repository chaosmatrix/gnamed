package cachex

// cache extra elements
type extraElement struct {
	Country string
}

// {"name": {qtype: ...}}
type StoreElements map[string]map[uint16]*StoreElement

type StoreElement struct {
	//Type      uint16
	Rcode       int
	Frequency   int
	Country     string
	MsgSize     int // byte
	MsgSections int
}
