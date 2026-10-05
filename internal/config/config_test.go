package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDLOCK_CONFIG", p)
}

func TestPinnedHubsAreRead(t *testing.T) {
	write(t, "[client]\nhubs = [\"potato\", \"tomato:9000\"]\n")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.Client.Hubs, ",") != "potato,tomato:9000" {
		t.Fatalf("%+v", c)
	}
}

func TestNoFileIsNoSettings(t *testing.T) {
	t.Setenv("CREDLOCK_CONFIG", filepath.Join(t.TempDir(), "absent.toml"))
	c, err := Load()
	if err != nil || len(c.Client.Hubs) != 0 {
		t.Fatalf("%+v, %v", c, err)
	}
}

func TestATypoIsAnError(t *testing.T) {
	write(t, "[client]\nhub = [\"potato\"]\n")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "client.hub") {
		t.Fatalf("got %v", err)
	}
}

func TestHubAddresses(t *testing.T) {
	for in, want := range map[string]string{
		"potato":      "potato:7177",
		"potato:9000": "potato:9000",
		"[fd7a::1]:1": "[fd7a::1]:1",
	} {
		if got := Addr(in); got != want {
			t.Errorf("Addr(%q) = %q, want %q", in, got, want)
		}
	}
}
