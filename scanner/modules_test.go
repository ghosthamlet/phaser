package scanner

import (
	"testing"
)

func TestLoadModules(t *testing.T) {
	if _, _, err := loadModules(); err != nil {
		t.Fatal(err)
	}
}
