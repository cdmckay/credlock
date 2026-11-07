//go:build linux

package client

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cdmckay/credlock/internal/proto"
)

// fakeSystemdRun puts a systemd-run on PATH that records its arguments, one
// per line, in the file it returns, then prints out and exits with status.
func fakeSystemdRun(t *testing.T, out string, status int) string {
	t.Helper()
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + argsFile +
		"\nprintf '%s' '" + out + "'\nexit " + strconv.Itoa(status) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "systemd-run"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return argsFile
}

func TestTheHelperStartsAsASystemdUserService(t *testing.T) {
	argsFile := fakeSystemdRun(t, "", 0)
	t.Setenv("CREDLOCK_STATE", "/tmp/trial-state")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/4242")
	t.Setenv("WAYLAND_DISPLAY", "wayland-evil")
	if err := launchHelper("/opt/credlock"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, want := range []string{"--user", "--collect", "--unit=" + helperUnit,
		"--setenv=CREDLOCK_STATE=/tmp/trial-state", "--setenv=XDG_RUNTIME_DIR=/run/user/4242"} {
		if !slices.Contains(args, want) {
			t.Errorf("no %s in %q", want, args)
		}
	}
	if tail := args[len(args)-3:]; strings.Join(tail, " ") != "-- /opt/credlock "+proto.HelperCommand {
		t.Errorf("runs %q", tail)
	}
	// The display and PATH are the user manager's, never the caller's.
	for _, a := range args {
		if strings.Contains(a, "WAYLAND_DISPLAY") || strings.Contains(a, "PATH=") {
			t.Errorf("passed on %s", a)
		}
	}
}

func TestAHelperUnitAlreadyStartingIsNoFailure(t *testing.T) {
	fakeSystemdRun(t, "Failed to start transient service unit: Unit credlock-helper.service already exists.", 1)
	if err := launchHelper("/opt/credlock"); err != nil {
		t.Fatal(err)
	}
}

func TestASystemdThatWontStartTheHelperIsAFailure(t *testing.T) {
	fakeSystemdRun(t, "Failed to connect to bus: No medium found", 1)
	err := launchHelper("/opt/credlock")
	if err == nil || !strings.Contains(err.Error(), "No medium found") || !strings.Contains(err.Error(), "systemctl --user status") {
		t.Fatalf("got %v", err)
	}
}
