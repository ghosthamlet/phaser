package scanner

import (
	"github.com/bloom42/phaser/scanner/module"
	"github.com/bloom42/phaser/scanner/module/cname"
	"github.com/bloom42/phaser/scanner/module/http/gitlab"
	"github.com/bloom42/phaser/scanner/module/whois"
	"github.com/bloom42/phaser/scanner/module/dns"
)

// AllHostModules contains all phaser's modules which will be run for each host.
// You must register you module here in order to be able to use it.
var AllHostModules = []module.HostModule{
	// ports.Ports{}, ports is enabled by default
	cname.CName{},
	whois.Whois{},
	dns.MissingOrInsufficientDMARCRecord{},
}

// AllPortModules contains all phaser's modules which will be run for each port for each host.
// You must register you module here in order to be able to use it.
var AllPortModules = []module.PortModule{
	gitlab.OpenRegistration{},
}
