package dns

import (
	"net"
	"os/exec"
	"strings"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/common/phaser/findings"
	"github.com/bloom42/phaser/scanner/module"
)

type ZoneTransferInformationDisclosure struct{}

func (ZoneTransferInformationDisclosure) Name() string {
	return "dns/zone_trasnfer_information_disclosure"
}

func (ZoneTransferInformationDisclosure) Description() string {
	return "check if AXFR queries are enabled for each name server"
}

func (ZoneTransferInformationDisclosure) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (ZoneTransferInformationDisclosure) Version() string {
	return "0.1.0"
}

func (ZoneTransferInformationDisclosure) Run(scan *phaser.Scan, target *phaser.Target) (module.Result, []error) {
	errs := []error{}
	badServers := []findings.AXFR{}
	var ret module.Result

	nservers, err := net.LookupNS(target.Host)
	if err != nil {
		errs = append(errs, err)
		return ret, errs
	}

	for _, ns := range nservers {
		command := "dig"
		commandArgs := []string{"AXFR", target.Host, "@" + ns.Host}

		out, err := exec.Command(command, commandArgs...).Output()
		if err != nil {
			errs = append(errs, err)
			// var errr string
			// if eerr, ok := err.(*exec.ExitError); ok {
			// 	errr = string(eerr.Stderr)
			// } else {
			// 	errr = err.Error()
			// }
			// ret.Errors = append(ret.Errors, formatError(errr, target.Host, target.Type, nil))
			continue
		}

		outStr := string(out)
		outStrLower := strings.ToLower(outStr)
		if strings.Contains(outStr, "XFR") && strings.Contains(outStrLower, "transfer failed") == false {
			badServer := findings.AXFR{
				Domain:   ns.Host,
				Response: outStr,
			}
			badServers = append(badServers, badServer)
		}
	}

	if len(badServers) != 0 {
		ret = badServers
	}
	return ret, errs
}
