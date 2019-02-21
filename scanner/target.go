package scanner

import (
	"fmt"
	"strings"

	"github.com/astrolib/govalidator"
	"github.com/bloom42/phaser/common/phaser"
)

func parseTargets(targets []string) []phaser.Target {
	ret := make([]phaser.Target, len(targets))

	for i, t := range targets {
		ret[i] = parseTarget(t)
	}

	return ret
}

func parseTarget(target string) phaser.Target {
	ret := phaser.Target{
		Host:       target,
		Errors:     []phaser.TargetError{},
		Findings:   phaser.Findings{},
		Subdomains: []phaser.Target{},
	}

	if govalidator.IsDNSName(target) == true && strings.Contains(target, ".") {
		ret.Type = phaser.TargetTypeDomain
	} else if govalidator.IsIPv4(target) == true {
		ret.Type = phaser.TargetTypeIP
		ret.IPVersion = phaser.TargetIPV4
	} else if govalidator.IsIPv6(target) == true {
		ret.Type = phaser.TargetTypeIP
		ret.IPVersion = phaser.TargetIPV6
	} else {
		err := phaser.TargetError{
			Error: fmt.Sprintf("%s is neither a domain nor an IP address", target),
		}
		ret.Errors = append(ret.Errors, err)
	}

	return ret
}
