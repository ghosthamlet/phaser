package ports

import (
	"testing"

	"github.com/bloom42/phaser/util/test"
)

func TestPorts(t *testing.T) {
	test.TestModule(t, Ports{}, "ports")
}
