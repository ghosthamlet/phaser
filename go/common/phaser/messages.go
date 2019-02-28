package phaser

import (
	"time"
)

// ScanCompletedMessage notifies kernel that a scan has completed and results are available to be
// retrieved
// phaser_worker -> kernel
type ScanCompletedMessage struct {
	ReportID string `json:"report_id"`
	File     File   `json:"file"`
}

// File is a file, with hashs to ensure integrity
type File struct {
	Path   string `json:"path"`
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	SHA512 string `json:"sha512,omitempty"`
}

// ScanQueuedMessage notifies phaser workers that a scan has been requested
// kernel -> phaser_worker
type ScanQueuedMessage struct {
	ScanID   string   `json:"scan_id"`
	Targets  []string `json:"targets"`
	Profile  string   `json:"profile"`
	ReportID string   `json:"report_id"`
}

// ScanStartedMessage notifies kernel that a specific scan has started
// phaser_worker -> kernel
type ScanStartedMessage struct {
	ReportID  string    `json:"report_id"`
	StartedAt time.Time `json:"started_at"`
}
