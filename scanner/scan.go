package scanner

import (
	"context"
	"encoding/json"
	"time"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/scanner/module/ports"
	"github.com/bloom42/phaser/version"
	"github.com/bloom42/rz-go/v2"
)

const (
	ScanResultFile = "scan.json"
)

func NewScan(ctx context.Context, config phaser.Config) *phaser.Scan {
	logger := rz.FromCtx(ctx)
	logger.Info("scan created", rz.Any("report_id", config.ReportID))

	targets := parseTargets(config.Targets)
	scan := phaser.Scan{
		ID:             config.ID,
		ReportID:       config.ReportID,
		Profile:        config.Profile,
		Targets:        targets,
		StartedAt:      time.Now().UTC(),
		ScannerVersion: version.Version,
		Config:         config,
		HTTPClient:     createHTTPClient(),
		Ctx:            ctx,
	}
	return &scan
}

// Run a complete scan
func Run(ctx context.Context, config phaser.Config) *phaser.Scan {
	scan := NewScan(ctx, config)
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

	logger := rz.FromCtx(scan.Ctx)

	err := end(scan)
	if err != nil {
		logger.Error("saving scan", rz.Err(err))
	} else {
		logger.Info("scan successfully completed",
			rz.Any("report_id", scan.ReportID),
			rz.String("file", scan.ResultFile.Path), rz.String("sha256", scan.ResultFile.SHA256),
			rz.String("directory", scan.Config.DataFolder),
		)
	}
}

func end(scan *phaser.Scan) error {
	completedAt := time.Now().UTC()
	scan.CompletedAt = completedAt
	scan.Duration = uint64(completedAt.Sub(scan.StartedAt) / 1000000) // convert to ms
	logger := rz.FromCtx(scan.Ctx)

	// save scan result
	data, err := json.MarshalIndent(scan, "", "  ")
	if err != nil {
		logger.Error("saving", rz.Err(err))
		return err
	}
	resultFile, err := saveFile(scan, ScanResultFile, data)
	scan.ResultFile = resultFile
	return err
}

func scanTarget(scan *phaser.Scan, target *phaser.Target) {
	logger := rz.FromCtx(scan.Ctx)
	hostModules, portModules, err := getEnbaledModules(&scan.Profile)
	if err != nil {
		logger.Fatal(err.Error())
	}

	// start by scanning ports
	logger.Info("starting ports scan")
	portsModule := ports.Ports{}
	portsData, errs := portsModule.Run(scan, target)
	logger.Info("ports scan ended")
	portsFinding := phaser.Finding{
		Module:  portsModule.Name(),
		Version: portsModule.Version(),
		Data:    portsData,
	}
	target.Findings = append(target.Findings, portsFinding)
	if len(target.Errors) != 0 {
		logger.Error("", rz.Errors("errors", errs))
		target.Errors = append(target.Errors, toTargetErrors(portsModule, errs)...)
		return
	}

	/////////////////////////////////////////////////////////////////////////////
	// host modules
	/////////////////////////////////////////////////////////////////////////////
	for _, module := range hostModules {
		moduleName := module.Name()
		moduleVersion := module.Version()
		logger := logger.With(rz.Fields(
			rz.Dict("module", logger.NewDict(rz.String("module", moduleName), rz.String("version", moduleVersion))),
			rz.String("target", target.Host),
		))
		logger.Info("starting host module")
		result, errs := module.Run(scan, target)
		logger.Info("host module ended")
		if result != nil {
			logger.Warn("found something")
			finding := phaser.Finding{
				Module:  moduleName,
				Version: moduleVersion,
				Data:    result,
			}
			target.Findings = append(target.Findings, finding)
		}
		if len(errs) != 0 {
			logger.Error("", rz.Errors("errors", errs))
			target.Errors = append(target.Errors, toTargetErrors(module, errs)...)
		}
	}

	/////////////////////////////////////////////////////////////////////////////
	// port modules
	/////////////////////////////////////////////////////////////////////////////
	scannedPorts := portsData.([]phaser.Port)
	for _, port := range scannedPorts {
		for _, module := range portModules {
			moduleName := module.Name()
			moduleVersion := module.Version()
			logger := logger.With(rz.Fields(
				rz.String("target", target.Host),
				rz.Dict("module", logger.NewDict(rz.String("module", moduleName), rz.String("version", moduleVersion))),
				rz.Uint16("port", port.ID),
			))
			logger.Info("starting port module")
			result, errs := module.Run(scan, target, port)
			logger.Info("port module ended")
			if result != nil {
				logger.Warn("found something")
				finding := phaser.Finding{
					Module:  moduleName,
					Version: moduleVersion,
					Data:    result,
				}
				target.Findings = append(target.Findings, finding)
			}
			if len(errs) != 0 {
				logger.Error("", rz.Errors("errors", errs))
				target.Errors = append(target.Errors, toTargetErrors(module, errs)...)
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
