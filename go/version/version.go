package version

import (
	"runtime"
)

// const set at build time
const (
	UTCBuildTime = "undefined"
	GitCommit    = "undefined"
	OS           = runtime.GOOS
	Arch         = runtime.GOARCH
	GoVersion    = "undefined"
	Name         = "phaser"
)

const (
	Version = "0.4.4"
)
