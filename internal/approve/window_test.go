package approve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cdmckay/credlock/internal/proto"
)

var sample = Request{
	Reason:    "Open the release PR",
	Command:   []string{"gh", "pr", "create", "--title", "Release 0.2.0"},
	Cwd:       "/work/credlock",
	Requester: "credlock (pid 4242)",
	Account:   "acme.1password.com (me@acme.example)",
	Secrets: []proto.Secret{
		{Name: "GITHUB_TOKEN", Ref: "op://Private/GitHub/token"},
		{Name: "NPM_TOKEN", Ref: "op://Private/npm/credential"},
	},
	Approved: 1,
	Window:   time.Hour,
	Cap:      24 * time.Hour,
}

func TestTheViewShowsWhoWhatAndWhy(t *testing.T) {
	v := NewView(sample, 2*time.Minute)
	for got, want := range map[string]string{
		v.Question:     "Allow this command to use 2 secrets?",
		v.Reason:       "Open the release PR",
		v.Command:      "gh pr create --title 'Release 0.2.0'",
		v.Directory:    "/work/credlock",
		v.Requester:    "credlock (pid 4242)",
		v.Account:      "acme.1password.com (me@acme.example)",
		v.Lifetime:     "1 hour after last use, 24 hours at most",
		v.SecretsTitle: "Requested secrets (2)",
		v.Approved:     "Plus 1 already approved.",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if len(v.Secrets) != 2 || v.Secrets[1] != sample.Secrets[1] || v.Timeout != 120 {
		t.Errorf("secrets %v, timeout %d", v.Secrets, v.Timeout)
	}
}

func TestARemoteRequestSaysSoFirst(t *testing.T) {
	r := sample
	r.Origin = "papaya"
	v := NewView(r, time.Minute)
	if v.Origin != "papaya" || v.Title != "Secret request from papaya" || !strings.Contains(v.OriginTitle, "another machine") ||
		!strings.Contains(v.OriginNote, "sent to papaya") || v.Question != "Allow papaya's command to use 2 secrets?" {
		t.Fatalf("%+v", v)
	}
	if local := NewView(sample, time.Minute); local.Origin != "" || local.OriginTitle != "" {
		t.Fatalf("a local request got a remote card: %+v", local)
	}
}

func TestAPairingSaysSoAndShowsItsCode(t *testing.T) {
	r := sample
	r.Origin, r.Requester, r.Pairing, r.Code = "papaya", "me on papaya, over Tailscale", "new", "4821"
	v := NewView(r, time.Minute)
	if v.OriginTone != "pair" || v.OriginTitle != "me on papaya wants to pair with this Mac" || v.Code != "4821" ||
		!strings.Contains(v.CodeNote, "papaya's terminal") || !strings.Contains(v.OriginNote, "sends the values") {
		t.Fatalf("%+v", v)
	}
	r.Secrets, r.Approved = nil, 0
	only := NewView(r, time.Minute)
	if only.Title != "Pairing request from papaya" || only.Question != "Pair me on papaya with this Mac?" ||
		strings.Contains(only.OriginNote, "values") || !strings.Contains(only.Footer, "sends no secrets") {
		t.Fatalf("pairing alone: %+v", only)
	}
}

func TestTheViewCountsOneSecret(t *testing.T) {
	r := sample
	r.Secrets = r.Secrets[:1]
	r.Approved = 0
	v := NewView(r, time.Minute)
	if v.Question != "Allow this command to use 1 secret?" || v.SecretsTitle != "Requested secret (1)" || v.Approved != "" {
		t.Fatalf("%q, %q, %q", v.Question, v.SecretsTitle, v.Approved)
	}
}

func TestTheViewFlattensClientText(t *testing.T) {
	v := NewView(Request{
		Reason:  "routine\nAll secrets already approved\x1b[2J",
		Command: []string{"sh", "-c", "evil\nfake line"},
		Secrets: []proto.Secret{{Name: "A\nB", Ref: "op://v/i/f\n"}},
	}, time.Minute)
	for _, s := range []string{v.Reason, v.Command, v.Secrets[0].Name, v.Secrets[0].Ref} {
		if strings.ContainsAny(s, "\n\x1b") {
			t.Errorf("control characters survived: %q", s)
		}
	}
	if v.Account != "(not given)" {
		t.Errorf("account %q", v.Account)
	}
	if v := NewView(Request{Secrets: sample.Secrets}, time.Minute); v.Reason != "(none given)" {
		t.Errorf("reason %q", v.Reason)
	}
}

// fakeWindow runs this test binary as the window process, behaving as mode.
func fakeWindow(mode string) func(ctx context.Context) (*exec.Cmd, error) {
	return func(ctx context.Context) (*exec.Cmd, error) {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFakeWindowProcess$")
		cmd.Env = append(os.Environ(), "CREDLOCK_FAKE_WINDOW="+mode)
		return cmd, nil
	}
}

// TestFakeWindowProcess is the fake window, not a test: it only acts when
// fakeWindow starts it.
func TestFakeWindowProcess(t *testing.T) {
	mode := os.Getenv("CREDLOCK_FAKE_WINDOW")
	if mode == "" {
		return
	}
	var v View
	data, _ := io.ReadAll(os.Stdin)
	if err := json.Unmarshal(data, &v); err != nil || v.Question == "" || v.Timeout <= 0 {
		fmt.Fprintln(os.Stderr, "bad view:", string(data))
		os.Exit(5)
	}
	switch mode {
	case "allow":
		fmt.Println("allow")
		os.Exit(0)
	case "deny":
		os.Exit(windowDenied)
	case "timeout":
		os.Exit(windowTimedOut)
	case "silent":
		os.Exit(0) // status 0 without saying "allow"
	case "hang":
		time.Sleep(time.Minute)
	case "crash":
		fmt.Fprintln(os.Stderr, "boom")
		os.Exit(2)
	}
	os.Exit(6)
}

func TestTheHelperReadsTheWindowsAnswer(t *testing.T) {
	for _, tc := range []struct {
		mode    string
		ok      bool
		timeout bool
		failure string // part of the error, when the window failed
	}{
		{mode: "allow", ok: true},
		{mode: "deny"},
		{mode: "timeout", timeout: true},
		{mode: "hang", timeout: true},
		{mode: "silent", failure: "without an answer"},
		{mode: "crash", failure: "boom"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			w := Window{Timeout: time.Second, grace: 500 * time.Millisecond, command: fakeWindow(tc.mode)}
			ok, err := w.Approve(context.Background(), sample)
			switch {
			case ok != tc.ok:
				t.Fatalf("ok = %v, err = %v", ok, err)
			case tc.timeout && !errors.Is(err, ErrTimedOut):
				t.Fatalf("want ErrTimedOut, got %v", err)
			case tc.failure != "" && (err == nil || !strings.Contains(err.Error(), tc.failure)):
				t.Fatalf("want an error mentioning %q, got %v", tc.failure, err)
			case !tc.timeout && tc.failure == "" && err != nil:
				t.Fatalf("unexpected error %v", err)
			}
		})
	}
}
