package dns

import (
	"fmt"
	"net"
	"strings"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/common/phaser/findings"
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

func (MissingOrInsufficientDMARCRecord) Run(scan *phaser.Scan, target *phaser.Target) (module.Result, []error) {
	errs := []error{}

	isDMARCRecordMissing := true
	var ret module.Result
	location := fmt.Sprintf("_dmarc.%s", target.Host)
	records, err := net.LookupTXT(location)

	if err != nil {
		errStr := err.Error()
		if strings.Contains(strings.ToLower(errStr), "no such host") == false {
			errs = append(errs, err)
			return ret, errs
		}
	}

	for _, record := range records {
		recordLower := strings.ToLower(record)
		if strings.Contains(recordLower, "v=dmarc1") {
			isDMARCRecordMissing = false
			break
		}
	}

	// if "no such host"
	if records == nil {
		records = []string{}
	}

	if isDMARCRecordMissing {
		data := findings.DMARC{
			Domain:   location,
			Records:  records,
			Resolves: !isDMARCRecordMissing,
		}
		ret = data
	}
	// if present, we found nothing so ret = nil
	return ret, errs
}
