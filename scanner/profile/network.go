package profile

import (
	"gitlab.com/bloom42/shared/phaser"
)

const (
	NetworkName = "network"
)

var Network = phaser.Profile{
	Name:       NetworkName,
	UserAgent:  DefaultUserAgent,
	Subdomains: true,
	Checks: phaser.Checks{
		Ports: true,
		CNAME: true,
	},
}
