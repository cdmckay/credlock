//go:build linux && gtk

package approve

import (
	"strings"
	"testing"
	"time"
)

func TestTheLinuxWindowRefusesWhatOnlyAHubSends(t *testing.T) {
	remote := sample
	remote.Origin, remote.User = "papaya", "alice"
	pairing := remote
	pairing.Pairing, pairing.Code, pairing.Secrets = "new", "4821", nil
	for name, r := range map[string]Request{"remote": remote, "pairing": pairing} {
		if err := showable(NewView(r, time.Minute)); err == nil {
			t.Errorf("%s: shown", name)
		}
	}
	if err := showable(NewView(sample, time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestTheLinuxWindowNeedsWayland(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "")
	in := `{"question":"x","secrets":[{"name":"A","ref":"op://v/i/f"}],"timeout":5}`
	if code := WindowMain(strings.NewReader(in), &strings.Builder{}); code != 2 {
		t.Fatalf("got status %d", code)
	}
}
