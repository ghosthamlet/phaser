package dns

import (
	"net"
	"strings"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/scanner/module"
)

type MissingOrInsufficientSPFRecord struct{}

func (MissingOrInsufficientSPFRecord) Name() string {
	return "dns/missing_or_insufficient_spf_record"
}

func (MissingOrInsufficientSPFRecord) Description() string {
	return "check if SPF record is insufficeient or missing"
}

func (MissingOrInsufficientSPFRecord) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (MissingOrInsufficientSPFRecord) Version() string {
	return "0.1.0"
}

type spfData struct {
	Domain    string   `json:"domain"`
	IsMissing bool     `json:"is_missing"`
	Records   []string `json:"records"`
}

func (MissingOrInsufficientSPFRecord) Run(scan *phaser.Scan, target *phaser.Target) (module.Result, []error) {
	errs := []error{}

	isSPFRecordMissing := true
	var ret module.Result
	records, err := net.LookupTXT(target.Host)

	if err != nil {
		errStr := err.Error()
		if strings.Contains(strings.ToLower(errStr), "no such host") == false {
			errs = append(errs, err)
			return ret, errs
		}
	}

	for _, record := range records {
		recordLower := strings.ToLower(record)
		if strings.Contains(recordLower, "v=spf1") {
			isSPFRecordMissing = false
			break
		}
	}

	// if "no such host"
	if records == nil {
		records = []string{}
	}

	if isSPFRecordMissing {
		data := spfData{
			Domain:    target.Host,
			Records:   records,
			IsMissing: isSPFRecordMissing,
		}
		ret = data
	}
	// if present, we found nothing so ret = nil
	return ret, errs
}
