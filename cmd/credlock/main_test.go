package main

import "testing"

func TestTheBuildsVersionWins(t *testing.T) {
	defer func(v string) { version = v }(version)
	version = "1.2.3+abc1234"
	if got := currentVersion(); got != "1.2.3+abc1234" {
		t.Fatalf("got %q", got)
	}
	// A test binary has no module version, so an unset version reads "dev".
	version = ""
	if got := currentVersion(); got != "dev" {
		t.Fatalf("got %q", got)
	}
}
