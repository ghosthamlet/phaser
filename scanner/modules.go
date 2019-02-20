package scanner

import (
	"fmt"

	"github.com/bloom42/rz-go/v2/log"
	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/scanner/module"
	"github.com/bloom42/phaser/scanner/module/cname"
	"github.com/bloom42/phaser/scanner/module/http/gitlab"
	"github.com/bloom42/phaser/scanner/module/http/atlassian"
	"github.com/bloom42/phaser/scanner/module/http/elasticsearch"
	"github.com/bloom42/phaser/scanner/module/http/traefik"
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
	dns.MissingOrInsufficientSPFRecord{},
	dns.ZoneTransferInformationDisclosure{},
}

// AllPortModules contains all phaser's modules which will be run for each port for each host.
// You must register you module here in order to be able to use it.
var AllPortModules = []module.PortModule{
	gitlab.OpenRegistration{},
	atlassian.CVE_2017_9506{},
	elasticsearch.UnauthenticatedAccess{},
	traefik.UnauthenticatedAccess{},
}


func getEnbaledModules(profile *phaser.Profile) ([]module.HostModule, []module.PortModule) {
	hostModules := []module.HostModule{}
	portModules := []module.PortModule{}

	hostModulesMap := map[string]module.HostModule{}
	for _, mod := range AllHostModules {
		name := mod.Name()
		if _, ok := hostModulesMap[name]; ok {
			log.Fatal(fmt.Sprintf("host module %s declared multiple times", name))
		}
		hostModulesMap[name] = mod
	}

	portModulesMap := map[string]module.PortModule{}
	for _, mod := range AllPortModules {
		name := mod.Name()
		if _, ok := portModulesMap[name]; ok {
			log.Fatal(fmt.Sprintf("port module %s declared multiple times", name))
		}
		if _, ok := hostModulesMap[name]; ok {
			log.Fatal(fmt.Sprintf("module %s declared both as host module and port module ", name))
		}
		portModulesMap[name] = mod
	}

	for name := range profile.Modules {
		if module, isHostModule := hostModulesMap[name]; isHostModule {
			hostModules = append(hostModules, module)
		} else if module, isPortModule := portModulesMap[name]; isPortModule {
			portModules = append(portModules, module)
		} else {
			log.Fatal(fmt.Sprintf("cannot find module: %s", name))
		}
	}

	return hostModules, portModules
}
