package scanner

import (
	"encoding/json"
	"time"

	"github.com/bloom42/astro-go/log"
	"gitlab.com/bloom42/phaser/version"
	"gitlab.com/bloom42/shared/phaser"
)

const (
	ScanResultFile = "scan.json"
)

func NewScan(config phaser.Config) *phaser.Scan {
	log.With("scan_id", config.ID, "report_id", config.ReportID).Info("scan created")
	targets := parseTargets(config.Targets)
	scan := phaser.Scan{
		ID:             config.ID,
		ReportID:       config.ReportID,
		Profile:        config.Profile,
		Targets:        targets,
		StartedAt:      time.Now().UTC(),
		ScannerVersion: version.Version,
		Config:         config,
	}
	return &scan
}

// Run a complete scan
func Run(config phaser.Config) *phaser.Scan {
	scan := NewScan(config)
	RunScan(scan)
	return scan
}

func RunScan(scan *phaser.Scan) {
	for i, target := range scan.Targets {
		if len(target.Errors) != 0 { // error during initialisation
			continue
		}
		scanTarget(scan, &scan.Targets[i])
	}

	err := end(scan)
	if err != nil {
		log.With("err", err.Error()).Error("saving scan")
	} else {
		log.With("scan_id", scan.ID, "report_id", scan.ReportID, "file", scan.ResultFile.Path, "sha256", scan.ResultFile.SHA256).
			Info("scan successfully completed")
	}
}

func end(scan *phaser.Scan) error {
	completedAt := time.Now().UTC()
	scan.CompletedAt = completedAt
	scan.Duration = uint64(completedAt.Sub(scan.StartedAt) / 1000000) // convert to ms

	// save scan result
	data, err := json.MarshalIndent(scan, "", "  ")
	if err != nil {
		log.With("err", err.Error()).Error("saving")
		return err
	}
	resultFile, err := saveFile(scan, ScanResultFile, data)
	scan.ResultFile = resultFile
	return err
}

func scanTarget(scan *phaser.Scan, target *phaser.Target) {
	errs := []error{}

	/////////////////////////////////////////////////////////////////////////////
	// per host
	/////////////////////////////////////////////////////////////////////////////
	if scan.Profile.Checks.Ports {
		scanErrs := Ports(scan, target)
		errs = append(errs, scanErrs...)
	}

	if scan.Profile.Checks.CNAME && target.Type == phaser.TargetTypeDomain {
		scanErrs := CNAME(scan, target)
		errs = append(errs, scanErrs...)
	}

	target.Errors = append(target.Errors, errorsToStr(errs)...)
}
