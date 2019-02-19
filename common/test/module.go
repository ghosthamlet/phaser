package test

import (
	"testing"

	"github.com/bloom42/phaser/scanner/module"
)

func TestModule(t *testing.T, module module.BaseModule, name string) {
	if name != module.Name() {
		t.Fatalf("Invalid module.Name. Expected: %s\nGot: %s\n", name, module.Name())
	}
}
