package approve

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdmckay/credlock/internal/proto"
)

// TestMain renders the window to PNGs when CREDLOCK_SNAPSHOT_DIR is set, for
// checking the layout by eye:
//
//	CREDLOCK_SNAPSHOT_DIR=/tmp/shots go test ./internal/approve
//
// It happens here because AppKit needs the main thread, and only TestMain runs
// on it.
func TestMain(m *testing.M) {
	if dir := os.Getenv("CREDLOCK_SNAPSHOT_DIR"); dir != "" && os.Getenv("CREDLOCK_FAKE_WINDOW") == "" {
		if err := snapshots(dir); err != nil {
			fmt.Fprintln(os.Stderr, "snapshots:", err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

func snapshots(dir string) error {
	one := sample
	one.Secrets = []proto.Secret{{Name: "IN_TOKEN", Ref: "op://Personal/Invoice Ninja/credential"}}
	one.Approved = 0
	one.Account = "my.1password.com (me@example.com)"

	long := sample
	long.Reason = "Plan the production Terraform change for the metrics collector, after the merge, to check nothing else moves"
	long.Command = []string{"terraform", "-chdir=infra/terraform/gcp/production", "plan", "-out=/tmp/metrics-collector-deploy-main.tfplan"}
	long.Cwd = "/Users/someone/src/a/rather/deeply/nested/project/directory"
	long.Secrets = nil
	for i := range 9 {
		long.Secrets = append(long.Secrets, proto.Secret{
			Name: fmt.Sprintf("METRICS_COLLECTOR_DEPLOY_KEY_%d", i),
			Ref:  fmt.Sprintf("op://Private/Metrics Collector Deploy Key %d/private key", i),
		})
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	remote := sample
	remote.Origin = "papaya"
	remote.Requester = "papaya, over Tailscale"
	remote.Cwd = "/srv/invoiceninja"
	pairing := remote
	pairing.Requester = "me on papaya, over Tailscale"
	pairing.Pairing, pairing.Code = "new", "4821"
	pairOnly := pairing
	pairOnly.Secrets, pairOnly.Approved = nil, 0
	pairOnly.Reason = "pair me on papaya with potato"
	pairOnly.Command = []string{"credlock", "pair", "potato"}
	for name, r := range map[string]Request{"one": one, "two": sample, "many": long, "remote": remote, "pairing": pairing, "pair-only": pairOnly} {
		for _, dark := range []bool{false, true} {
			mode := "light"
			if dark {
				mode = "dark"
			}
			path := filepath.Join(dir, strings.Join([]string{name, mode}, "-")+".png")
			if err := snapshot(NewView(r, 2*time.Minute), path, dark); err != nil {
				return err
			}
		}
	}
	return nil
}

func TestWindowMainRefusesEmptyContent(t *testing.T) {
	if code := WindowMain(strings.NewReader(`{"question":"x"}`), os.Stdout); code != 2 {
		t.Fatalf("got status %d", code)
	}
	if code := WindowMain(strings.NewReader(`not json`), os.Stdout); code != 2 {
		t.Fatalf("got status %d", code)
	}
}
