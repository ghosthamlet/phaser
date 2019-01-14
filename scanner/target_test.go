package scanner

import (
	"testing"

	"gitlab.com/bloom42/shared/phaser"
)

func checkTarget(t *testing.T, target string, expected phaser.Target) {
	result := parseTarget(target)
	same := expected.Host == result.Host && expected.Type == result.Type && expected.IPVersion == result.IPVersion
	if same != true {
		t.Fatalf("unexpected result: %#v\nExpected: %#v\n", result, expected)
	}
}

func TestParseTarget(t *testing.T) {
	host := "kerkour.com"
	expected := phaser.Target{
		Host:      host,
		Type:      phaser.TargetTypeDomain,
		IPVersion: 0,
	}
	checkTarget(t, host, expected)

	host = "192.30.253.113"
	expected = phaser.Target{
		Host:      host,
		Type:      phaser.TargetTypeIP,
		IPVersion: phaser.TargetIPV4,
	}
	checkTarget(t, host, expected)
}
