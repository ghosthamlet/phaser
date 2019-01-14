package profile

import (
	"gitlab.com/bloom42/shared/phaser"
)

const (
	ApplicationName = "application"
)

var Application = phaser.Profile{
	Name:       ApplicationName,
	UserAgent:  DefaultUserAgent,
	Subdomains: false,
	Checks: phaser.Checks{
		Ports: true,
		CNAME: true,
	},
}
