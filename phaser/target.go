package phaser

const (
	TargetTypeDomain = "domain"
	TargetTypeIP     = "ip"
	TargetIPV4       = 4
	TargetIPV6       = 6
)

type IPVersion int
type TargetType string

type Target struct {
	Host      string     `json:"host"`
	Type      TargetType `json:"type"` // "domain" or "ip"
	IPVersion IPVersion  `json:"ip_version,omitempty"`
	Findings  Findings   `json:"findings"`
	Errors    []string   `json:"errors"`
}
