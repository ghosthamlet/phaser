package scanner

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/version"
	"github.com/bloom42/sane-go"
)

var (
	DefaultUserAgent = fmt.Sprintf("Bloom (https://bloom.sh) phaser/%s", version.Version)
)

func exists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func applyProfileDefaults(profile *phaser.Profile) {
	if profile.HTTP.UserAgent == "" {
		profile.HTTP.UserAgent = DefaultUserAgent
	}
}

func GetProfile(assetsFolder, profile string) (phaser.Profile, error) {
	var ret phaser.Profile
	var err error

	proFilePath := filepath.Join(assetsFolder, "profiles", fmt.Sprintf("%s.sane", profile))
	if exists(proFilePath) {
		err = sane.Load(proFilePath, &ret)
		applyProfileDefaults(&ret)
		return ret, err
	}

	if exists(profile) {
		err = sane.Load(profile, &ret)
		applyProfileDefaults(&ret)
		return ret, err
	}

	err = fmt.Errorf("profile not found: %s", profile)
	return ret, err
}
