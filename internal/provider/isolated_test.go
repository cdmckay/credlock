package provider

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// echoProvider answers each reference with "ACCOUNT:REF", so a test can tell
// which account answered.
type echoProvider struct{ fail string }

func (p echoProvider) ResolveAll(_ context.Context, account string, refs []string) (map[string]string, error) {
	if p.fail != "" {
		return nil, errors.New(p.fail)
	}
	out := map[string]string{}
	for _, r := range refs {
		out[r] = account + ":" + r
	}
	return out, nil
}

// TestFakeResolverProcess is the fake resolver, not a test: it only acts when
// fakeResolvers starts it.
func TestFakeResolverProcess(t *testing.T) {
	mode := os.Getenv("CREDLOCK_FAKE_RESOLVER")
	if mode == "" {
		return
	}
	account := os.Getenv("CREDLOCK_FAKE_ACCOUNT")
	switch mode {
	case "echo":
		os.Exit(3 + serveResolver(echoProvider{}, account, os.Stdin, os.Stdout))
	case "fail":
		os.Exit(3 + serveResolver(echoProvider{fail: "itemNotFound: no such item in that vault"}, account, os.Stdin, os.Stdout))
	case "crash":
		os.Exit(3) // before answering anything
	case "hang":
		time.Sleep(time.Minute)
	}
	os.Exit(9)
}

type starts struct {
	mu       sync.Mutex
	accounts []string
}

func (s *starts) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.accounts...)
}

// fakeResolvers is an Isolated whose resolvers are this test binary, each
// behaving as mode(account) says.
func fakeResolvers(mode func(account string) string) (*Isolated, *starts) {
	s := &starts{}
	p := &Isolated{Timeout: 5 * time.Second}
	p.command = func(account string) *exec.Cmd {
		s.mu.Lock()
		s.accounts = append(s.accounts, account)
		s.mu.Unlock()
		cmd := exec.Command(os.Args[0], "-test.run=^TestFakeResolverProcess$")
		cmd.Env = append(os.Environ(), "CREDLOCK_FAKE_RESOLVER="+mode(account), "CREDLOCK_FAKE_ACCOUNT="+account)
		return cmd
	}
	return p, s
}

func always(mode string) func(string) string { return func(string) string { return mode } }

func TestEachAccountIsAnsweredByItsOwnResolver(t *testing.T) {
	p, s := fakeResolvers(always("echo"))
	ctx := context.Background()
	for _, tc := range []struct{ account, ref string }{
		{"personal", "op://v/a/f"},
		{"work", "op://v/a/f"}, // the same reference, in another account
		{"personal", "op://v/b/f"},
	} {
		got, err := p.ResolveAll(ctx, tc.account, []string{tc.ref})
		if err != nil {
			t.Fatal(err)
		}
		if want := tc.account + ":" + tc.ref; got[tc.ref] != want {
			t.Fatalf("%s %s: got %q, want %q", tc.account, tc.ref, got[tc.ref], want)
		}
	}
	if got := strings.Join(s.all(), ","); got != "personal,work" {
		t.Fatalf("resolvers started for %s, want one each for personal and work", got)
	}
}

func TestAReportedFailureKeepsTheResolver(t *testing.T) {
	p, s := fakeResolvers(always("fail"))
	for range 2 {
		_, err := p.ResolveAll(context.Background(), "personal", []string{"op://v/a/f"})
		if err == nil || !strings.Contains(err.Error(), "itemNotFound") {
			t.Fatalf("got %v", err)
		}
	}
	if n := len(s.all()); n != 1 {
		t.Fatalf("%d resolvers started for two failures it reported itself", n)
	}
}

func TestADeadResolverIsReplaced(t *testing.T) {
	first := true
	var mu sync.Mutex
	p, s := fakeResolvers(func(string) string {
		mu.Lock()
		defer mu.Unlock()
		if first {
			first = false
			return "crash"
		}
		return "echo"
	})
	if _, err := p.ResolveAll(context.Background(), "personal", []string{"op://v/a/f"}); err == nil || !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("want an error saying the resolver stopped, got %v", err)
	}
	got, err := p.ResolveAll(context.Background(), "personal", []string{"op://v/a/f"})
	if err != nil || got["op://v/a/f"] != "personal:op://v/a/f" {
		t.Fatalf("after a crash: %v, %v", got, err)
	}
	if n := len(s.all()); n != 2 {
		t.Fatalf("%d resolvers started, want 2", n)
	}
}

func TestAStuckResolverTimesOutAndIsReplaced(t *testing.T) {
	first := true
	var mu sync.Mutex
	p, s := fakeResolvers(func(string) string {
		mu.Lock()
		defer mu.Unlock()
		if first {
			first = false
			return "hang"
		}
		return "echo"
	})
	p.Timeout = 300 * time.Millisecond
	start := time.Now()
	_, err := p.ResolveAll(context.Background(), "personal", []string{"op://v/a/f"})
	if err == nil || !strings.Contains(err.Error(), "didn't answer") || time.Since(start) > 3*time.Second {
		t.Fatalf("want a timeout, got %v after %v", err, time.Since(start))
	}
	p.Timeout = 5 * time.Second
	if _, err := p.ResolveAll(context.Background(), "personal", []string{"op://v/a/f"}); err != nil {
		t.Fatalf("after a timeout: %v", err)
	}
	if n := len(s.all()); n != 2 {
		t.Fatalf("%d resolvers started, want 2", n)
	}
}

func TestNoResolverStartsWithoutAnAccount(t *testing.T) {
	p, s := fakeResolvers(always("echo"))
	if _, err := p.ResolveAll(context.Background(), "", []string{"op://v/a/f"}); err == nil || !strings.Contains(err.Error(), "--account") {
		t.Fatalf("got %v", err)
	}
	if n := len(s.all()); n != 0 {
		t.Fatalf("%d resolvers started without an account", n)
	}
}

func TestTheResolverAnswersEachLineAndSurvivesABadOne(t *testing.T) {
	in := strings.NewReader("not json\n" + `{"id":7,"refs":["op://v/a/f"]}` + "\n")
	var out bytes.Buffer
	if code := serveResolver(echoProvider{}, "personal", in, &out); code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "bad request") || !strings.Contains(lines[1], `"id":7`) || !strings.Contains(lines[1], "personal:op://v/a/f") {
		t.Fatalf("got %q", lines)
	}
}
