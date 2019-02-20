package dns

import (
	"fmt"
	"net"
	"strings"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/scanner/module"
)

type MissingOrInsufficientDMARCRecord struct{}

func (MissingOrInsufficientDMARCRecord) Name() string {
	return "dns/missing_or_insufficient_dmarc_record"
}

func (MissingOrInsufficientDMARCRecord) Description() string {
	return "check if dmarc record is insufficeient or missing"
}

func (MissingOrInsufficientDMARCRecord) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (MissingOrInsufficientDMARCRecord) Version() string {
	return "0.1.0"
}

type Data struct {
	Domain  string   `json:"domain"`
	Records []string `json:"records"`
}

func (MissingOrInsufficientDMARCRecord) Run(scan *phaser.Scan, target *phaser.Target) (module.Result, []error) {
	errs := []error{}

	isDMARCRecordPresent := false
	var ret module.Result
	location := fmt.Sprintf("_dmarc.%s", target.Host)
	records, err := net.LookupTXT(location)

	if err != nil {
		errs = append(errs, err)
		return ret, errs
	}

	for _, record := range records {
		recordLower := strings.ToLower(record)
		if strings.Contains(recordLower, "v=dmarc1") {
			isDMARCRecordPresent = true
			break
		}
	}

	if !isDMARCRecordPresent {
		data := Data{
			Domain:  location,
			Records: records,
		}
		ret = data
	}
	return ret, errs
}
