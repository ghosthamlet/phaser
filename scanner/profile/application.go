package profile

import (
	"github.com/bloom42/phaser/common/phaser"
)

var Application = phaser.Profile{
	UserAgent:  DefaultUserAgent,
	Subdomains: false,
	Checks: phaser.Checks{
		Ports: true,
		CNAME: true,
	},
}
