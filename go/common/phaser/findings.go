package phaser

// Finding wraps a module result. Data is the result of a module and MUST be a type found in
// phaser/findings
type Finding struct {
	Module  string      `json:"module"`
	Version string      `json:"version"`
	Data    interface{} `json:"data"`
}

// Findings is a collection of Finding
type Findings []Finding
