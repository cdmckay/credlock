package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdmckay/credlock/internal/client"
	"github.com/cdmckay/credlock/internal/proto"
)

func (h *harness) search(reason, term string) (proto.Response, error) {
	return client.CallAt(h.sock, proto.Request{
		Op: proto.OpSearch, Account: "acct", Reason: reason, Cwd: "/work", Search: term,
	}, false)
}

func TestASearchShowsTheTermAndReasonThenNamesWhatItFound(t *testing.T) {
	bar := &fakeBar{}
	h := newHarness(t, true, withBar(bar))
	resp, err := h.search("the deploy needs a GitHub token", "github")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Found == nil || len(resp.Found.Items) != 1 || resp.Found.Items[0].Ref != "op://Shared/github" {
		t.Fatalf("got %+v", resp)
	}
	d := h.approver.dialogs()
	if len(d) != 1 || d[0].Search != "github" || d[0].Reason != "the deploy needs a GitHub token" || len(d[0].Secrets) != 0 {
		t.Fatalf("dialogs: %+v", d)
	}
	use := bar.last().Uses[0]
	if use.Search != "github" || use.Summary != "1 item and 3 more" || use.Cached || use.Failed ||
		strings.Join(use.Told, "|") != `op://Shared/github: "credential" (Concealed)|and 3 more, not named` {
		t.Fatalf("access log: %+v", use)
	}
	if !bar.last().Recent || !bar.last().Read {
		t.Fatalf("the icon should show what went back: %+v", bar.last())
	}
}

func TestEverySearchAsks(t *testing.T) {
	h := newHarness(t, true)
	for range 2 {
		if _, err := h.search("looking", "github"); err != nil {
			t.Fatal(err)
		}
	}
	if len(h.approver.dialogs()) != 2 || len(h.provider.fetches()) != 2 {
		t.Fatalf("%d dialogs and %d searches, want 2 of each", len(h.approver.dialogs()), len(h.provider.fetches()))
	}
}

func TestADeniedSearchSearchesNothing(t *testing.T) {
	bar := &fakeBar{}
	h := newHarness(t, false, withBar(bar))
	resp, err := h.search("looking", "github")
	if err != nil || !resp.Denied || resp.Found != nil {
		t.Fatalf("got %+v, %v", resp, err)
	}
	if len(h.provider.fetches()) != 0 || len(bar.all()) != 0 {
		t.Fatalf("a denied search reached 1Password or the log")
	}
}

func TestASearchWithoutAReasonOrAShowableTermAsksNothing(t *testing.T) {
	h := newHarness(t, true)
	for _, tc := range []struct{ reason, term, want string }{
		{"", "github", "needs a reason"},
		{"  ", "github", "needs a reason"},
		{"looking", "g", "at least 2"},
		{"looking", strings.Repeat("x", proto.MaxSearch+1), "at most 100"},
		{"looking", "git\nhub", "control characters"},
		{"looking", " github", "start or end with a space"},
	} {
		_, err := h.search(tc.reason, tc.term)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q %q: got %v, want %q", tc.reason, tc.term, err, tc.want)
		}
	}
	if len(h.approver.dialogs()) != 0 {
		t.Fatalf("%d dialogs for searches that couldn't run", len(h.approver.dialogs()))
	}
}

func TestWhatAFailureAfterAllowSaidIsLogged(t *testing.T) {
	bar := &fakeBar{}
	h := newHarness(t, true, withBar(bar))
	h.provider.fail(errors.New(`could not resolve op://v/a/nope (fieldNotFound: the item's fields are "username" (Text), "credential" (Concealed))`))
	if _, err := h.resolve(sec("A", "op://v/a/nope")); err == nil {
		t.Fatal("no error")
	}
	use := bar.last().Uses[0]
	if !use.Failed || strings.Join(use.Names, ",") != "A" || !strings.Contains(strings.Join(use.Told, " "), `"credential" (Concealed)`) {
		t.Fatalf("access log: %+v", use)
	}
	if !bar.last().Recent {
		t.Fatalf("the icon should show what went back: %+v", bar.last())
	}
}

func TestTheIconShowsForAnHourAfterASearch(t *testing.T) {
	c, exited := &clock{now: t0}, make(chan struct{})
	bar := &fakeBar{}
	h := newHarness(t, true, onClock(c, exited), withBar(bar))
	tick := reaping(t, h.server, c)
	if _, err := h.search("looking", "github"); err != nil {
		t.Fatal(err)
	}
	c.advance(59 * time.Minute)
	tick()
	if !eventually(func() bool { return bar.last().Recent && !bar.last().Read }) {
		t.Fatalf("after 59 minutes: %+v", bar.last())
	}
	c.advance(2 * time.Minute)
	tick()
	if !eventually(func() bool { return !bar.last().Recent }) {
		t.Fatalf("after an hour: %+v", bar.last())
	}
}

func TestALongLineOfWhatWentBackIsWrapped(t *testing.T) {
	head, rest := wrap(strings.Repeat("word ", 30), 20)
	if head != "word word word word" || !strings.HasPrefix(rest, "word") {
		t.Fatalf("got %q / %q", head, rest)
	}
}
