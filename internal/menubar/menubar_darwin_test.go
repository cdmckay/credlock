package menubar

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain renders the icon to PNGs when CREDLOCK_SNAPSHOT_DIR is set, for
// checking it by eye:
//
//	CREDLOCK_SNAPSHOT_DIR=/tmp/shots go test ./internal/menubar
//
// It happens here because AppKit needs the main thread, and only TestMain runs
// on it.
func TestMain(m *testing.M) {
	if dir := os.Getenv("CREDLOCK_SNAPSHOT_DIR"); dir != "" && os.Getenv("CREDLOCK_FAKE_BAR") == "" {
		for _, mode := range []string{"light", "dark"} {
			path := filepath.Join(dir, fmt.Sprintf("icon-%s.png", mode))
			if err := iconSnapshot(path, mode == "dark"); err != nil {
				fmt.Fprintln(os.Stderr, "snapshot:", path, err)
				os.Exit(1)
			}
		}
	}
	os.Exit(m.Run())
}
