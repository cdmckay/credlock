package client

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cdmckay/credlock/internal/proto"
)

// loginItem is the launchd agent that starts the helper at login while hub
// mode is on, so other machines can ask after a restart.
const loginItem = "io.github.cdmckay.credlock"

func loginItemPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", loginItem+".plist"), nil
}

// stableCredlock is credlock's path as the shell finds it, such as a Nix
// profile or Homebrew link, which survives upgrades; a store path wouldn't.
func stableCredlock() (string, error) {
	if p, err := exec.LookPath("credlock"); err == nil {
		if abs, err := filepath.Abs(p); err == nil && !strings.HasPrefix(abs, "/nix/store/") {
			return abs, nil
		}
	}
	return os.Executable()
}

func installLoginItem() error {
	if os.Getenv("CREDLOCK_NO_LOGIN_ITEM") != "" { // for tests and trial builds
		return nil
	}
	exe, err := stableCredlock()
	if err != nil {
		return err
	}
	path, err := loginItemPath()
	if err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	esc := func(s string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	// PATH as it is now, so the helper finds op and tailscale when launchd
	// starts it, with launchd's own bare PATH.
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>%s</string>
	<key>ProgramArguments</key><array><string>%s</string><string>%s</string></array>
	<key>EnvironmentVariables</key><dict><key>PATH</key><string>%s</string></dict>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
	<key>ProcessType</key><string>Background</string>
	<key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, loginItem, esc(exe), proto.HelperCommand, esc(os.Getenv("PATH")), esc(filepath.Join(home, "Library", "Logs", "credlock.log")))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		return err
	}
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	_ = exec.Command("launchctl", "bootout", domain, path).Run()
	// The helper already running holds the lock, so the one launchd starts
	// now exits at once, successfully, and isn't restarted. At the next login
	// launchd's is the one.
	if out, err := exec.Command("launchctl", "bootstrap", domain, path).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func removeLoginItem() error {
	if os.Getenv("CREDLOCK_NO_LOGIN_ITEM") != "" {
		return nil
	}
	path, err := loginItemPath()
	if err != nil {
		return err
	}
	_ = exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d", os.Getuid()), path).Run()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
