package libnamed

// Google JSON Format
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

type DOHJson struct {
	Status    int               `json:"Status"`
	TC        bool              `json:"TC"`
	RD        bool              `json:"RD"`
	RA        bool              `json:"RA"`
	AD        bool              `json:"AD"`
	CD        bool              `json:"CD"`
	Question  []DOHJsonQuestion `json:"Question"`
	Answer    []DOHJsonAnswer   `json:"Answer"`
	Authority []DOHJsonAnswer   `json:"Authority"`
	Aditional []string          `json:"Aditional"` // ?
	ECS       string            `json:"edns_client_subnet"`
	Comment   string            `json:"Comment"`
}
