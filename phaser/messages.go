package phaser

import (
	"time"
)

type ScanCompletedMessage struct {
	ReportID string `json:"report_id"`
	File     File   `json:"file"`
}

type File struct {
	Path   string
	MD5    string
	SHA1   string
	SHA256 string
	SHA512 string
}

type ScanQueuedMessage struct {
	ScanID   string   `json:"scan_id"`
	Targets  []string `json:"targets"`
	Profile  string   `json:"profile"`
	ReportID string   `json:"report_id"`
}

type ScanStartedMessage struct {
	ReportID  string    `json:"report_id"`
	StartedAt time.Time `json:"started_at"`
}
