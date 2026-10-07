package daemon

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdmckay/credlock/internal/menubar"
)

// fakeBar records every snapshot the menu bar is sent.
type fakeBar struct {
	mu    sync.Mutex
	snaps []menubar.Snapshot
}

func (b *fakeBar) Notify(s menubar.Snapshot) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.snaps = append(b.snaps, s)
}

func (b *fakeBar) last() menubar.Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.snaps) == 0 {
		return menubar.Snapshot{}
	}
	return b.snaps[len(b.snaps)-1]
}

func (b *fakeBar) all() []menubar.Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]menubar.Snapshot(nil), b.snaps...)
}

func withBar(b *fakeBar) func(*Server) { return func(s *Server) { s.Bar = b } }

func TestTheMenuBarHearsOfEveryReadButNeverAValue(t *testing.T) {
	bar := &fakeBar{}
	h := newHarness(t, true, withBar(bar))

	h.ok(sec("A", "op://v/a/f"), sec("B", "op://v/b/f"))
	first := bar.last()
	if !first.Read || len(first.Held) != 2 || len(first.Uses) != 1 {
		t.Fatalf("after the first read: %+v", first)
	}
	if got := first.Held[0]; got.Name != "A" || got.Ref != "op://v/a/f" || got.AccountID != "acct" || got.Account != "acct" || got.Left != "60 min left" {
		t.Errorf("held: %+v", got)
	}
	if u := first.Uses[0]; u.Cached || u.Command != "make deploy" || u.Reason != "testing" || strings.Join(u.Names, ",") != "A,B" {
		t.Errorf("use: %+v", u)
	}

	h.ok(sec("A", "op://v/a/f"))
	second := bar.last()
	if !second.Read || len(second.Uses) != 2 || !second.Uses[0].Cached || second.Uses[1].Cached {
		t.Fatalf("after the cached read, newest first: %+v", second.Uses)
	}

	data, err := json.Marshal(bar.all())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret:") {
		t.Fatalf("a value reached the menu bar: %s", data)
	}
}

func TestForgettingFromTheMenuTakesAccessAway(t *testing.T) {
	bar := &fakeBar{}
	stopped := make(chan struct{})
	h := newHarness(t, true, withBar(bar), func(s *Server) { s.Exit = func() { close(stopped) } })
	a, b := sec("A", "op://v/a/f"), sec("B", "op://v/b/f")
	h.ok(a, b)

	h.server.act(menubar.Action{Op: menubar.OpForget, AccountID: "acct", Ref: a.Ref})
	if held := bar.last().Held; len(held) != 1 || held[0].Name != "B" || bar.last().Read {
		t.Fatalf("after forgetting A: %+v", bar.last())
	}
	h.ok(a)
	if n := len(h.approver.dialogs()); n != 2 {
		t.Fatalf("a forgotten secret must be approved again: %d dialogs", n)
	}

	h.server.act(menubar.Action{Op: menubar.OpForgetAll})
	if held := bar.last().Held; len(held) != 0 {
		t.Fatalf("after forgetting all: %+v", held)
	}

	h.server.act(menubar.Action{Op: menubar.OpStop})
	if !exits(stopped) {
		t.Fatal("stop from the menu didn't stop the helper")
	}
}

func TestTheAccessLogKeepsTheLatest(t *testing.T) {
	bar := &fakeBar{}
	h := newHarness(t, true, withBar(bar))
	for range maxUses + 5 {
		h.ok(sec("A", "op://v/a/f"))
	}
	if n := len(bar.last().Uses); n != maxUses {
		t.Fatalf("the log holds %d uses, want %d", n, maxUses)
	}
}

func TestTheMenuBarHearsWhenSecretsExpire(t *testing.T) {
	c, exited := &clock{now: t0}, make(chan struct{})
	bar := &fakeBar{}
	h := newHarness(t, true, onClock(c, exited), withBar(bar))
	tick := reaping(t, h.server, c)
	h.ok(sec("A", "op://v/a/f"))

	c.advance(15 * time.Minute)
	tick()
	if !eventually(func() bool { l := bar.last(); return len(l.Held) == 1 && l.Held[0].Left == "45 min left" && !l.Read }) {
		t.Fatalf("after 15 minutes: %+v", bar.last())
	}
	c.advance(Window)
	tick()
	if !eventually(func() bool { return len(bar.last().Held) == 0 }) {
		t.Fatalf("after expiry: %+v", bar.last())
	}
}

func TestTimeLeftReads(t *testing.T) {
	for d, want := range map[time.Duration]string{
		30 * time.Second:                "under a minute left",
		47*time.Minute + 30*time.Second: "48 min left",
		time.Hour:                       "60 min left",
		time.Hour + 5*time.Minute:       "1 h 5 min left",
	} {
		if got := left(d); got != want {
			t.Errorf("left(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestTheMenuBarShowsTheHelpersVersion(t *testing.T) {
	bar := &fakeBar{}
	h := newHarness(t, true, withBar(bar), func(s *Server) { s.Version = "9.8.7+abc1234" })
	h.ok(sec("A", "op://v/a/f"))
	if v := bar.last().Version; v != "9.8.7+abc1234" {
		t.Fatalf("version %q", v)
	}
}
