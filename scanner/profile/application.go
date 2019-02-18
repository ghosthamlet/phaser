package profile

import (
	"github.com/bloom42/phaser/phaser"
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
