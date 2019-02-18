package findings

type Port struct {
	ID       uint16 `json:"id"`
	State    string `json:"state"`
	Protocol string `json:"protocol"`
}
