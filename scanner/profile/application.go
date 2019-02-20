package profile

import (
	"github.com/bloom42/phaser/common/phaser"
)

var Application = phaser.Profile{
	HTTP: phaser.ProfileHTTPConfig{
		UserAgent: DefaultUserAgent,
	},
	ScanSubdomains: false,
	Modules: phaser.ProfileModules{
		"gitlab/open_registration": phaser.ProfileModuleOptions{},
		"cname":                    phaser.ProfileModuleOptions{},
		"whois":                    phaser.ProfileModuleOptions{},
		"dns/missing_or_insufficient_dmarc_record": phaser.ProfileModuleOptions{},
	},
}
