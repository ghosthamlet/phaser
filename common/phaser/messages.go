package phaser

import (
	"time"
)

type ScanCompletedMessage struct {
	ReportID string `json:"report_id"`
	File     File   `json:"file"`
}

type File struct {
	Path   string `json:"path"`
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	SHA512 string `json:"sha512,omitempty"`
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
