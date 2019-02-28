package phaser

//
type Port struct {
	ID       uint16 `json:"id"`
	State    string `json:"state"`
	Protocol string `json:"protocol"`
	HTTP     bool   `json:"-"`
	HTTPS    bool   `json:"-"`
}
