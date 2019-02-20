package phaser

import (
	"context"
	"net/http"
	"time"
)

type Scan struct {
	ID             *string         `json:"id"`
	ReportID       *string         `json:"report_id"`
	StartedAt      time.Time       `json:"started_at"`
	CompletedAt    time.Time       `json:"completed_at"`
	Duration       uint64          `json:"duration"`
	Targets        []Target        `json:"targets"`
	Profile        Profile         `json:"profile"`
	ScannerVersion string          `json:"scanner_version"`
	Config         Config          `json:"-"`
	ResultFile     File            `json:"-"`
	HTTPClient     *http.Client    `json:"-"`
	Ctx            context.Context `json:"-"`
}

type Checks struct {
	Ports bool `json:"ports" sane:"ports"`
	CNAME bool `json:"cname" sane:"cname"`
}

type Config struct {
	Profile     Profile
	Targets     []string
	AssetsFolder  string
	ID          *string
	ReportID    *string
	AWSS3Bucket *string
	DataFolder  string
}
