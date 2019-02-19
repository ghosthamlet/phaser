package module

import (
	"github.com/bloom42/phaser/common/phaser"
)

// Result is the result of a `module.Run`
type Result interface{}

// HostModule must be implemented by all modules to be used by the phaser scan engine.
// They will be run at most once per host.
type HostModule interface {
	Name() string
	Description() string
	Author() string
	Version() string
	Run(*phaser.Scan, *phaser.Target) (Result, []error)
}

// PortModule must be implemented by all modules to be used by the phaser scan engine.
// They will be run at most once per port per host.
type PortModule interface {
	Name() string
	Description() string
	Author() string
	Version() string
	Run(*phaser.Scan, uint16 /*host*/) Result
}
