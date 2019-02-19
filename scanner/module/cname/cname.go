package cname

import (
	"net"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/scanner/module"
)

type CName struct{}

func (CName) Name() string {
	return "cname"
}

func (CName) Description() string {
	return "get CName data"
}

func (CName) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (CName) Version() string {
	return "0.1.0"
}

func (CName) Run(scan *phaser.Scan, target *phaser.Target) (module.Result, []error) {
	errs := []error{}

	cname, err := net.LookupCNAME(target.Host)
	if err != nil {
		errs = append(errs, err)
	}
	return cname, errs
}
