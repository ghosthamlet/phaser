package findings

type DMARC struct {
	Domain   string   `json:"domain"`
	Resolves bool     `json:"resolves"`
	Records  []string `json:"records"`
}
