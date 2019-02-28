package whois

import (
	"io/ioutil"
	"os/exec"
	"path/filepath"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/common/phaser/findings"
	"github.com/bloom42/phaser/scanner/module"
)

type Whois struct{}

func (Whois) Name() string {
	return "domain/whois"
}

func (Whois) Description() string {
	return "get Whois data"
}

func (Whois) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (Whois) Version() string {
	return "0.1.0"
}

func (Whois) Run(scan *phaser.Scan, target *phaser.Target) (module.Result, []error) {
	errs := []error{}
	var ret interface{}
	var err error

	command := "whois"
	commandArgs := []string{target.Host}
	out, err := exec.Command(command, commandArgs...).Output()
	if err != nil {
		errs = append(errs, err)
		if err2, ok := err.(*exec.ExitError); ok {
			errs = append(errs, err2)
			return ret, errs
		}
		return ret, errs
	}

	fileName := "whois.txt"
	filePath := filepath.Join(scan.Config.DataFolder, fileName)
	err = ioutil.WriteFile(filePath, out, 0600)
	if err != nil {
		errs = append(errs, err)
		return ret, errs
	}
	ret = findings.File{
		Path: fileName,
	}
	return ret, errs
}
