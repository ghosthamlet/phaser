package ports

import (
	"testing"

	"github.com/bloom42/phaser/common/test"
)

func TestPorts(t *testing.T) {
	test.TestModule(t, Ports{}, "ports")
}
