package takeover

import (
	"testing"

	"github.com/bloom42/phaser/util/test"
)

func TestTakeover(t *testing.T) {
	test.TestModule(t, Takeover{}, "domain/takeover")
}
