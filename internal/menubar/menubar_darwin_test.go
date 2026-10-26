package menubar

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain renders the icon and the access log to PNGs when
// CREDLOCK_SNAPSHOT_DIR is set, for checking them by eye:
//
//	CREDLOCK_SNAPSHOT_DIR=/tmp/shots go test ./internal/menubar
//
// It happens here because AppKit needs the main thread, and only TestMain runs
// on it.
func TestMain(m *testing.M) {
	if dir := os.Getenv("CREDLOCK_SNAPSHOT_DIR"); dir != "" && os.Getenv("CREDLOCK_FAKE_BAR") == "" {
		for _, mode := range []string{"light", "dark"} {
			dark := mode == "dark"
			for name, render := range map[string]func(string) error{
				"icon": func(path string) error { return iconSnapshot(path, dark) },
				"log":  func(path string) error { return logSnapshot(sampleLog, path, dark) },
			} {
				path := filepath.Join(dir, fmt.Sprintf("%s-%s.png", name, mode))
				if err := render(path); err != nil {
					fmt.Fprintln(os.Stderr, "snapshot:", path, err)
					os.Exit(1)
				}
			}
		}
	}
	os.Exit(m.Run())
}

// sampleLog has one of each kind of use, and more than the menu shows.
var sampleLog = Snapshot{Uses: []Use{
	{At: "16:00", Command: "bash /private/tmp/agent/e972b79f-1d2c-4f7e-9a0b-3c5d6e7f8a9b/command.sh", Reason: "Find the OAuth requests in prod APM for TICKET-123", Names: []string{"NEW_RELIC_API_KEY"}, Cached: true},
	{At: "15:50", Command: "newrelic nrql query --query 'SELECT count(*) FROM Transaction'", Reason: "Count yesterday's transactions", Names: []string{"NEW_RELIC_API_KEY"}},
	{At: "14:31", Origin: "papaya", Command: "in-api.sh --sync", Reason: "Sync the invoice API", Names: []string{"IN_TOKEN", "IN_SECRET"}, Cached: true},
	{At: "13:12", Search: "cloudflare", Reason: "Find a Cloudflare API token to read, then edit, staging's api, sso and auth DNS…", Summary: "2 items",
		Told: []string{`op://Private/Cloudflare DNS: "credential" (Concealed)`, `op://Private/Cloudflare R2: "access key" (Concealed), "secret" (Concealed)`}},
	{At: "12:52", Command: "curl -s https://circleci.com/api/v2/me", Reason: "Read the failed deploy's log", Names: []string{"CIRCLECI_TOKEN"}, Failed: true, Summary: "failed",
		Told: []string{`fieldNotFound: op://Private/CircleCI has no field "token"; its fields are "credential" (Concealed)`}},
	{At: "12:40", Origin: "devbox", Command: "paired with this Mac", Reason: "Pair for the build scripts"},
}}
