package scanner

import (
	"encoding/json"
	"time"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/scanner/module/ports"
	"github.com/bloom42/phaser/version"
	"github.com/bloom42/rz-go/v2"
	"github.com/bloom42/rz-go/v2/log"
)

const (
	ScanResultFile = "scan.json"
)

func NewScan(config phaser.Config) *phaser.Scan {
	log.Info("scan created", rz.Any("scan_id", config.ID), rz.Any("report_id", config.ReportID))
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
		log.Error("saving scan", rz.Err(err))
	} else {
		log.Info("scan successfully completed",
			rz.Any("scan_id", scan.ID), rz.Any("report_id", scan.ReportID),
			rz.String("file", scan.ResultFile.Path), rz.String("sha256", scan.ResultFile.SHA256),
			rz.String("directory", scan.Config.DataFolder),
		)
	}
}

func end(scan *phaser.Scan) error {
	completedAt := time.Now().UTC()
	scan.CompletedAt = completedAt
	scan.Duration = uint64(completedAt.Sub(scan.StartedAt) / 1000000) // convert to ms

	// save scan result
	data, err := json.MarshalIndent(scan, "", "  ")
	if err != nil {
		log.Error("saving", rz.Err(err))
		return err
	}
	resultFile, err := saveFile(scan, ScanResultFile, data)
	scan.ResultFile = resultFile
	return err
}

func scanTarget(scan *phaser.Scan, target *phaser.Target) {

	// start by scanning ports
	log.Info("starting ports scan")
	portsModule := ports.Ports{}
	portsData, errs := portsModule.Run(scan, target)
	log.Info("ports scan ended")
	portsFinding := phaser.Finding{
		Module:  portsModule.Name(),
		Version: portsModule.Version(),
		Data:    portsData,
	}
	target.Findings = append(target.Findings, portsFinding)
	target.Errors = append(target.Errors, errorsToStr(errs)...)
	if len(target.Errors) != 0 {
		return
	}

	/////////////////////////////////////////////////////////////////////////////
	// host modules
	/////////////////////////////////////////////////////////////////////////////
	for _, module := range AllHostModules {
		moduleName := module.Name()
		moduleVersion := module.Version()
		logger := log.With(rz.Fields(rz.Dict("module", log.NewDict(rz.String("module", moduleName), rz.String("version", moduleVersion)))))
		logger.Info("starting host module")
		result, errs := module.Run(scan, target)
		logger.Info("host module ended")
		if result != nil {
			logger.Info("found something")
			finding := phaser.Finding{
				Module:  moduleName,
				Version: moduleVersion,
				Data:    result,
			}
			target.Findings = append(target.Findings, finding)
		}
		if len(errs) != 0 {
			logger.Error("", rz.Errors("errors", errs))
			target.Errors = append(target.Errors, errorsToStr(errs)...)
		}
	}

	/////////////////////////////////////////////////////////////////////////////
	// port modules
	/////////////////////////////////////////////////////////////////////////////
	scannedPorts := portsData.([]phaser.Port)
	for _, port := range scannedPorts {
		for _, module := range AllPortModules {
			moduleName := module.Name()
			moduleVersion := module.Version()
			logger := log.With(rz.Fields(
				rz.Dict("module", log.NewDict(rz.String("module", moduleName), rz.String("version", moduleVersion))),
				rz.Uint16("port", port.ID),
			))
			logger.Info("starting port module")
			result, errs := module.Run(scan, target, port)
			logger.Info("port module ended")
			if result != nil {
				logger.Info("found something", rz.String("target", target.Host))
				finding := phaser.Finding{
					Module:  moduleName,
					Version: moduleVersion,
					Data:    result,
				}
				target.Findings = append(target.Findings, finding)
			}
			if len(errs) != 0 {
				logger.Error("", rz.Errors("errors", errs))
				target.Errors = append(target.Errors, errorsToStr(errs)...)
			}
		}
	}

	// if scan.Profile.Checks.Ports {
	// 	scanErrs := Ports(scan, target)
	// 	errs = append(errs, scanErrs...)
	// }

	// if scan.Profile.Checks.CNAME && target.Type == phaser.TargetTypeDomain {
	// 	scanErrs := CNAME(scan, target)
	// 	errs = append(errs, scanErrs...)
	// }

	// target.Errors = append(target.Errors, errorsToStr(errs)...)
}
