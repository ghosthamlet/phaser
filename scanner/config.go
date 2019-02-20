package scanner

import (
	"fmt"
	"log"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/scanner/module"
)

func getEnbaledModules(profile *phaser.Profile) ([]module.HostModule, []module.PortModule) {
	hostModules := []module.HostModule{}
	portModules := []module.PortModule{}

	hostModulesMap := map[string]module.HostModule{}
	for _, mod := range AllHostModules {
		name := mod.Name()
		if _, ok := hostModulesMap[name]; ok {
			log.Fatal(fmt.Sprintf("module %s declared multiple times", name))
		}
		hostModulesMap[name] = mod
	}

	portModulesMap := map[string]module.PortModule{}
	for _, mod := range AllPortModules {
		name := mod.Name()
		if _, ok := portModulesMap[name]; ok {
			log.Fatal(fmt.Sprintf("module %s declared multiple times", name))
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
