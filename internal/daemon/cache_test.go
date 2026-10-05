package daemon

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 28, 9, 0, 0, 0, time.UTC)

func TestAnApprovalLastsAWindowAfterItsLastUse(t *testing.T) {
	c := newCache(time.Hour, 24*time.Hour)
	k := key{"", "acct", "op://v/i/f"}
	c.put(k, "s", t0)

	if _, ok := c.peek(k, t0.Add(59*time.Minute)); !ok {
		t.Fatal("gone before its hour was up")
	}
	c.touch(k, t0.Add(59*time.Minute))
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
	c.put(k, "s", t0)
	c.peek(k, t0.Add(59*time.Minute))
	if _, ok := c.peek(k, t0.Add(61*time.Minute)); ok {
		t.Fatal("a peek extended the approval")
	}
}

func TestConstantUseStillEndsAtTheCap(t *testing.T) {
	c := newCache(time.Hour, 24*time.Hour)
	k := key{"", "acct", "op://v/i/f"}
	c.put(k, "s", t0)
	for now := t0; now.Before(t0.Add(24 * time.Hour)); now = now.Add(30 * time.Minute) {
		if _, ok := c.peek(k, now); !ok {
			t.Fatalf("gone at %s despite use every 30 minutes", now.Sub(t0))
		}
		c.touch(k, now)
	}
	if _, ok := c.peek(k, t0.Add(24*time.Hour)); ok {
		t.Fatal("outlived its 24 hour cap")
	}
}

func TestTheSameReferenceInTwoAccountsIsTwoEntries(t *testing.T) {
	c := newCache(time.Hour, 24*time.Hour)
	c.put(key{"", "personal", "op://v/i/f"}, "mine", t0)
	if _, ok := c.peek(key{"", "work", "op://v/i/f"}, t0); ok {
		t.Fatal("an approval in one account answered for another")
	}
}

func TestSweepDropsOnlyTheExpired(t *testing.T) {
	c := newCache(time.Hour, 24*time.Hour)
	c.put(key{"", "a", "op://v/old/f"}, "old", t0)
	c.put(key{"", "a", "op://v/new/f"}, "new", t0.Add(30*time.Minute))
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
	c.put(key{"", "a", "op://v/i/f"}, "hunter2", t0)
	got := c.list(t0.Add(10 * time.Minute))
	if len(got) != 1 || got[0].Ref != "op://v/i/f" || got[0].ExpiresIn != 50*60 {
		t.Fatalf("unexpected listing %+v", got)
	}
}
