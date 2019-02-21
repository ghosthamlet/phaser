package ssltls

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/scanner/module"
	"github.com/bloom42/phaser/scanner/module/ssltls/sslyze"
)

type ROBOT struct{}

func (ROBOT) Name() string {
	return "ssltls/robot"
}

func (ROBOT) Description() string {
	return "Check for the ROBOT attck. See https://robotattack.org"
}

func (ROBOT) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (ROBOT) Version() string {
	return "0.1.0"
}

type ROBOTData struct {
	Host string `json:"host"`
}

// TODO: better sslyze target handling
func (ROBOT) Run(scan *phaser.Scan, target *phaser.Target, port phaser.Port) (module.Result, []error) {
	errs := []error{}
	var ret module.Result

	if port.HTTP || !port.HTTPS {
		return ret, errs
	}

	host := fmt.Sprintf("%s:%d", target.Host, port.ID)
	command := "sslyze"
	commandArgs := []string{"--robot", "--json_out=-", host}

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

	if !strings.Contains(sslyzeResult.AcceptedTargets[0].CommandsResults.Robot.RobotResultEnum, "NOT_VULNERABLE") {
		ret = ROBOTData{host}
	}

	return ret, errs
}
