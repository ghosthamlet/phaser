package whois

import (
	"testing"

	"github.com/bloom42/phaser/util/test"
)

func TestWhois(t *testing.T) {
	test.TestModule(t, Whois{}, "domain/whois")
}
