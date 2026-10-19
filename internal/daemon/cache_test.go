package daemon

import (
	"reflect"
	"testing"
	"time"

	"github.com/cdmckay/credlock/internal/proto"
)

var t0 = time.Date(2026, 9, 28, 9, 0, 0, 0, time.UTC)

func TestAnApprovalLastsAWindowAfterItsLastUse(t *testing.T) {
	c := newCache(time.Hour, 24*time.Hour)
	k := key{"", "acct", "op://v/i/f"}
	c.put(k, "s", t0, 0)

	if _, ok := c.peek(k, t0.Add(59*time.Minute)); !ok {
		t.Fatal("gone before its hour was up")
	}
	c.touch(k, t0.Add(59*time.Minute), 0)
	if _, ok := c.peek(k, t0.Add(118*time.Minute)); !ok {
		t.Fatal("using it did not slide its expiry")
	}
	if _, ok := c.peek(k, t0.Add(119*time.Minute)); ok {
		t.Fatal("still there an hour after its last use")
	}
}

func TestPeekingDoesNotSlide(t *testing.T) {
	c := newCache(time.Hour, 24*time.Hour)
	k := key{"", "acct", "op://v/i/f"}
	c.put(k, "s", t0, 0)
	c.peek(k, t0.Add(59*time.Minute))
	if _, ok := c.peek(k, t0.Add(61*time.Minute)); ok {
		t.Fatal("a peek extended the approval")
	}
}

func TestConstantUseStillEndsAtTheCap(t *testing.T) {
	c := newCache(time.Hour, 24*time.Hour)
	k := key{"", "acct", "op://v/i/f"}
	c.put(k, "s", t0, 0)
	for now := t0; now.Before(t0.Add(24 * time.Hour)); now = now.Add(30 * time.Minute) {
		if _, ok := c.peek(k, now); !ok {
			t.Fatalf("gone at %s despite use every 30 minutes", now.Sub(t0))
		}
		c.touch(k, now, 0)
	}
	if _, ok := c.peek(k, t0.Add(24*time.Hour)); ok {
		t.Fatal("outlived its 24 hour cap")
	}
}

func TestTheSameReferenceInTwoAccountsIsTwoEntries(t *testing.T) {
	c := newCache(time.Hour, 24*time.Hour)
	c.put(key{"", "personal", "op://v/i/f"}, "mine", t0, 0)
	if _, ok := c.peek(key{"", "work", "op://v/i/f"}, t0); ok {
		t.Fatal("an approval in one account answered for another")
	}
}

func TestSweepDropsOnlyTheExpired(t *testing.T) {
	c := newCache(time.Hour, 24*time.Hour)
	c.put(key{"", "a", "op://v/old/f"}, "old", t0, 0)
	c.put(key{"", "a", "op://v/new/f"}, "new", t0.Add(30*time.Minute), 0)
	c.sweep(t0.Add(time.Hour))
	if len(c.entries) != 1 {
		t.Fatalf("want 1 entry left, got %d", len(c.entries))
	}
	if _, ok := c.entries[key{"", "a", "op://v/new/f"}]; !ok {
		t.Fatal("swept the live entry")
	}
}

func TestListNeverCarriesValues(t *testing.T) {
	c := newCache(time.Hour, 24*time.Hour)
	c.put(key{"", "a", "op://v/i/f"}, "hunter2", t0, 0)
	got := c.list(t0.Add(10 * time.Minute))
	if len(got) != 1 || got[0].Ref != "op://v/i/f" || got[0].ExpiresIn != 50*60 {
		t.Fatalf("unexpected listing %+v", got)
	}
}

func TestATTLEndsAnApprovalOnTimeEvenInConstantUse(t *testing.T) {
	c := newCache(time.Hour, 24*time.Hour)
	k := key{"", "acct", "op://v/i/f"}
	c.put(k, "s", t0, 10*time.Minute)
	for now := t0; now.Before(t0.Add(10 * time.Minute)); now = now.Add(time.Minute) {
		if _, ok := c.peek(k, now); !ok {
			t.Fatalf("gone at %s, inside its 10 minutes", now.Sub(t0))
		}
		c.touch(k, now, 10*time.Minute) // the same run, still using it
	}
	if _, ok := c.peek(k, t0.Add(10*time.Minute)); ok {
		t.Fatal("use stretched an approval past its TTL")
	}
}

func TestALaterTTLShortensAnApprovalAndNoTTLNeverLengthensIt(t *testing.T) {
	c := newCache(time.Hour, 24*time.Hour)
	k := key{"", "acct", "op://v/i/f"}
	c.put(k, "s", t0, 0)
	c.touch(k, t0.Add(5*time.Minute), 2*time.Minute)
	if _, ok := c.peek(k, t0.Add(7*time.Minute)); ok {
		t.Fatal("a request's TTL didn't shorten the approval it used")
	}

	c.put(k, "s", t0, 2*time.Minute)
	c.touch(k, t0.Add(time.Minute), 0)
	c.touch(k, t0.Add(time.Minute), time.Hour)
	if _, ok := c.peek(k, t0.Add(2*time.Minute)); ok {
		t.Fatal("a later request lengthened an approval past its TTL")
	}
}

func TestForgettingDropsOnlyThoseReferencesForThatMachine(t *testing.T) {
	c := newCache(time.Hour, 24*time.Hour)
	c.put(key{"", "personal", "op://v/a/f"}, "a", t0, 0)
	c.put(key{"", "work", "op://v/a/f"}, "a", t0, 0)
	c.put(key{"", "personal", "op://v/b/f"}, "b", t0, 0)
	c.put(key{"me@papaya", "personal", "op://v/a/f"}, "a", t0, 0)

	got := c.forgetRefs("", "personal", []string{"op://v/a/f"}, t0)
	if want := []proto.Entry{{Account: "personal", Ref: "op://v/a/f"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("forgot %+v, want %+v", got, want)
	}
	if got := c.forgetRefs("", "", []string{"op://v/a/f"}, t0); len(got) != 1 || got[0].Account != "work" {
		t.Fatalf("with no account, forgot %+v", got)
	}
	for _, k := range []key{{"", "personal", "op://v/b/f"}, {"me@papaya", "personal", "op://v/a/f"}} {
		if _, ok := c.peek(k, t0); !ok {
			t.Errorf("forgot %+v, which wasn't asked for", k)
		}
	}
	if got := c.forgetRefs("", "", []string{"op://v/a/f"}, t0); got != nil {
		t.Fatalf("forgot %+v twice", got)
	}
}
