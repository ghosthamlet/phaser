package profile

import (
	"fmt"

	"github.com/bloom42/phaser/version"
)

var (
	DefaultUserAgent = fmt.Sprintf("Bloom (https://bloom.sh) phaser/%s", version.Version)
)
