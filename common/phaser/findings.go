package phaser

// type Findings struct {
// 	Ports []findings.Port `json:"ports"`
// 	CNAME *string         `json:"cname"`
// }

type Finding struct {
	Module  string      `json:"module"`
	Version string      `json:"version"`
	Data    interface{} `json:"data"`
}

type Findings []Finding
