package module

import (
	"github.com/bloom42/phaser/common/phaser"
)

// Result is the result of a `module.Run`
type Result interface{}

// BaseModule must be implemented by all modules, whether by HostModules or by PortModule
type BaseModule interface {
	Name() string
	Description() string
	Author() string
	Version() string
}

// HostModule must be implemented by all modules to be used by the phaser scan engine.
// They will be run at most once per host.
type HostModule interface {
	BaseModule
	Run(*phaser.Scan, *phaser.Target) (Result, []error)
}

// PortModule must be implemented by all modules to be used by the phaser scan engine.
// They will be run at most once per port per host.
type PortModule interface {
	BaseModule
	Run(*phaser.Scan, *phaser.Target, phaser.Port) (Result, []error)
}
