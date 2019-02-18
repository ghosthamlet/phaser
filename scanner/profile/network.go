package profile

import (
	"github.com/bloom42/phaser/common/phaser"
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
