package scanner

import (
	"fmt"
	"strings"

	"github.com/astrolib/govalidator"
	"gitlab.com/bloom42/shared/phaser"
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
		Host:     target,
		Errors:   []string{},
		Findings: phaser.Findings{},
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
		ret.Errors = append(ret.Errors, fmt.Sprintf("%s is neither a domain nor an IP address", target))
	}

	return ret
}
