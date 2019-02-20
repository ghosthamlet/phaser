package profile

import (
	"github.com/bloom42/phaser/common/phaser"
)

var Network = phaser.Profile{
	HTTP: phaser.ProfileHTTPConfig{
		UserAgent: DefaultUserAgent,
	},
	ScanSubdomains: true,
	Modules: phaser.ProfileModules{
		"http/gitlab/open_registration": phaser.ProfileModuleOptions{},
		"cname":                         phaser.ProfileModuleOptions{},
		"whois":                         phaser.ProfileModuleOptions{},
	},
}
