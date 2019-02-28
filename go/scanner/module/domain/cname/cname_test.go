package cname

import (
	"testing"

	"github.com/bloom42/phaser/util/test"
)

func TestCName(t *testing.T) {
	test.TestModule(t, CName{}, "domain/cname")
}
