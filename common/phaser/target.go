package phaser

const (
	TargetTypeDomain = "domain"
	TargetTypeIP     = "ip"
	TargetIPV4       = 4
	TargetIPV6       = 6
)

type IPVersion int
type TargetType string

type TargetError struct {
	Module string `json:"module,omitempty"`
	Error  string `json:"error"`
}

type Target struct {
	Host      string        `json:"host"`
	Type      TargetType    `json:"type"` // "domain" or "ip"
	IPVersion IPVersion     `json:"ip_version,omitempty"`
	Findings  Findings      `json:"findings"`
	Errors    []TargetError `json:"errors"`
}
