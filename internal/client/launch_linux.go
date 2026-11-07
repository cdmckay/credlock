//go:build linux

package client

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cdmckay/credlock/internal/proto"
)

// helperUnit is the transient systemd user service the helper runs as.
const helperUnit = "credlock-helper"

// launchHelper starts the helper as a transient systemd user service, where
// systemd runs one for the user. That keeps the helper out of the caller's
// process tree, so the command credlock run becomes isn't its parent, and out
// of any sandbox or login session the caller is in, which can end before the
// helper should. It also gets the user manager's environment, not the
// caller's: the display its dialog shows on, and the PATH it finds that dialog
// on, are the session's, not something a caller chose. Without systemd it is
// started as on macOS. A systemd that is there but won't start it is a
// failure, not a reason to fall back.
func launchHelper(exe string) error {
	systemdRun, err := exec.LookPath("systemd-run")
	if err != nil {
		return launchDetached(exe)
	}
	args := []string{"--user", "--quiet", "--collect", "--unit=" + helperUnit}
	// credlock's own overrides, for trial builds and tests, and the runtime
	// directory, so the helper's socket is where this client looks for it.
	for _, name := range []string{"CREDLOCK_STATE", "CREDLOCK_CONFIG", "XDG_RUNTIME_DIR"} {
		if v := os.Getenv(name); v != "" {
			args = append(args, "--setenv="+name+"="+v)
		}
	}
	args = append(args, "--", exe, proto.HelperCommand)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, systemdRun, args...).CombinedOutput()
	switch {
	case err == nil:
		return nil
	case strings.Contains(string(out), "already exists"):
		// Another client started it a moment ago, and its socket is coming.
		return nil
	default:
		return fmt.Errorf("starting the helper with systemd-run: %v: %s. Check that the systemd user manager is running: systemctl --user status",
			err, strings.TrimSpace(string(out)))
	}
}
