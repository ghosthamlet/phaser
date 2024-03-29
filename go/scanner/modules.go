package scanner

import (
	"fmt"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/scanner/module"
	"github.com/bloom42/phaser/scanner/module/domain/cname"
	"github.com/bloom42/phaser/scanner/module/http/gitlab"
	"github.com/bloom42/phaser/scanner/module/http/atlassian"
	"github.com/bloom42/phaser/scanner/module/http/elasticsearch"
	"github.com/bloom42/phaser/scanner/module/http/traefik"
	"github.com/bloom42/phaser/scanner/module/http/cadvisor"
	"github.com/bloom42/phaser/scanner/module/http/git"
	"github.com/bloom42/phaser/scanner/module/http/prometheus"
	"github.com/bloom42/phaser/scanner/module/http/etcd"
	"github.com/bloom42/phaser/scanner/module/http/drupal"
	"github.com/bloom42/phaser/scanner/module/http/kibana"
	"github.com/bloom42/phaser/scanner/module/http/consul"
	"github.com/bloom42/phaser/scanner/module/domain/whois"
	"github.com/bloom42/phaser/scanner/module/http"
	"github.com/bloom42/phaser/scanner/module/ssltls"
	"github.com/bloom42/phaser/scanner/module/mysql"
	"github.com/bloom42/phaser/scanner/module/postgresql"
	"github.com/bloom42/phaser/scanner/module/http/yaheiphp"
	"github.com/bloom42/phaser/scanner/module/http/jetty"
	"github.com/bloom42/phaser/scanner/module/domain/takeover"
	"github.com/bloom42/phaser/scanner/module/dns"
)


func toTargetErrors(module module.BaseModule, errs []error) []phaser.TargetError {
	ret := make([]phaser.TargetError, len(errs))
	moduleName := module.Name()

	for i, err := range errs {
		ret[i] = phaser.TargetError{
			Module: moduleName,
			Error: err.Error(),
		}
	}
	return ret
}

// AllHostModules contains all phaser's modules which will be run for each host.
// You must register you module here in order to be able to use it.
var AllHostModules = []module.HostModule{
	// ports.Ports{}, ports is enabled by default
	cname.CName{},
	whois.Whois{},
	dns.MissingOrInsufficientDMARCRecord{},
	dns.MissingOrInsufficientSPFRecord{},
	dns.ZoneTransferInformationDisclosure{},
	takeover.Takeover{},
}

// AllPortModules contains all phaser's modules which will be run for each port for each host.
// You must register you module here in order to be able to use it.
var AllPortModules = []module.PortModule{
	gitlab.OpenRegistration{},
	atlassian.CVE_2017_9506{},
	elasticsearch.UnauthenticatedAccess{},
	traefik.UnauthenticatedAccess{},
	consul.UnauthenticatedAccess{},
	cadvisor.UnauthenticatedAccess{},
	etcd.UnauthenticatedAccess{},
	kibana.UnauthenticatedAccess{},
	git.HeadFileDisclosure{},
	git.DirectoryDisclosure{},
	git.ConfigFileDisclosure{},
	prometheus.DashboardUnauthenticatedAccess{},
	drupal.CVE_2018_7600{},
	http.DSStoreFileDisclosure{},
	http.DirectoryListingInformationDisclosure{},
	http.EnvFileDisclosure{},
	yaheiphp.InformationDisclosure{},
	jetty.CVE_2015_2080{},
	mysql.UnauthenticatedAccess{},
	postgresql.UnauthenticatedAccess{},
	ssltls.CVE_2014_0160{},
	ssltls.ROBOT{},
	ssltls.CVE_2014_0224{},
}

// loadModules load all modules to unique maps
func loadModules() (map[string]module.HostModule, map[string]module.PortModule, error) {
	hostModulesMap := map[string]module.HostModule{}
	portModulesMap := map[string]module.PortModule{}
	var err error

	for _, mod := range AllHostModules {
		name := mod.Name()
		if _, ok := hostModulesMap[name]; ok {
			err = fmt.Errorf("host module %s declared multiple times", name)
			return hostModulesMap, portModulesMap, err
		}
		hostModulesMap[name] = mod
	}


	for _, mod := range AllPortModules {
		name := mod.Name()
		if _, ok := portModulesMap[name]; ok {
			err = fmt.Errorf("port module %s declared multiple times", name)
			return hostModulesMap, portModulesMap, err
		}
		if _, ok := hostModulesMap[name]; ok {
			err = fmt.Errorf("module %s declared both as host module and port module ", name)
			return hostModulesMap, portModulesMap, err
		}
		portModulesMap[name] = mod
	}

	return hostModulesMap, portModulesMap, err
}


func getEnbaledModules(profile *phaser.Profile) ([]module.HostModule, []module.PortModule, error) {
	hostModules := []module.HostModule{}
	portModules := []module.PortModule{}
	var err error

	hostModulesMap, portModulesMap, err := loadModules();
	if err != nil {
		return hostModules, portModules, err
	}

	for name := range profile.Modules {
		if module, isHostModule := hostModulesMap[name]; isHostModule {
			hostModules = append(hostModules, module)
		} else if module, isPortModule := portModulesMap[name]; isPortModule {
			portModules = append(portModules, module)
		} else {
			err = fmt.Errorf("cannot find module: %s", name)
			return hostModules, portModules, err
		}
	}

	return hostModules, portModules, err
}
