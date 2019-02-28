package ssltls

import (
	"fmt"
	"os/exec"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/common/phaser/findings"
	"github.com/bloom42/phaser/scanner/module"
	"github.com/bloom42/phaser/scanner/module/ssltls/sslyze"
)

type CVE_2014_0160 struct{}

func (CVE_2014_0160) Name() string {
	return "ssltls/cve_2014_0160"
}

func (CVE_2014_0160) Description() string {
	return "Check for CVE-2014-0160 (a.k.a. heartbleed). See  http://heartbleed.com"
}

func (CVE_2014_0160) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (CVE_2014_0160) Version() string {
	return "0.1.0"
}

// TODO: better sslyze target handling
func (CVE_2014_0160) Run(scan *phaser.Scan, target *phaser.Target, port phaser.Port) (module.Result, []error) {
	errs := []error{}
	var ret module.Result

	if port.HTTP || !port.HTTPS {
		return ret, errs
	}

	host := fmt.Sprintf("%s:%d", target.Host, port.ID)
	command := "sslyze"
	commandArgs := []string{"--heartbleed", "--json_out=-", host}

	out, err := exec.Command(command, commandArgs...).Output()
	if err != nil {
		errs = append(errs, err)
		return ret, errs
	}

	sslyzeResult, err := sslyze.Parse(out)
	if err != nil {
		errs = append(errs, err)
		return ret, errs
	}

	if len(sslyzeResult.AcceptedTargets) < 1 {
		return ret, errs
	}

	if sslyzeResult.AcceptedTargets[0].CommandsResults.Heartbleed.IsVulnerableToHeartbleed {
		ret = findings.URL{URL: "https://" + host}
	}

	return ret, errs
}
