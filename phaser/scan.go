package phaser

import (
	"time"
)

type Scan struct {
	ID             *string   `json:"id"`
	ReportID       *string   `json:"report_id"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at"`
	Duration       uint64    `json:"duration"`
	Targets        []Target  `json:"targets"`
	Profile        Profile   `json:"profile"`
	ScannerVersion string    `json:"scanner_version"`
	Config         Config    `json:"-"`
	ResultFile     File      `json:"-"`
}

type Profile struct {
	Name       string `json:"name" sane:"name"`
	UserAgent  string `json:"user_agent" sane:"user_agent"` // default useragent to use
	Subdomains bool   `json:"subdomains" sane:"subdomains"` // enable subdomains scan
	Checks     Checks `json:"checks" sane:"checks"`
}

type Checks struct {
	Ports bool `json:"ports" sane:"ports"`
	CNAME bool `json:"cname" sane:"cname"`
}

type Config struct {
	Profile     Profile
	Targets     []string
	Assets      string
	ID          *string
	ReportID    *string
	AWSS3Bucket *string
	Folder      *string
}
