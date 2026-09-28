package daemon

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cdmckay/credlock/internal/client"
	"github.com/cdmckay/credlock/internal/proto"
)

func TestOnlyOneHelperCanHoldTheLock(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "credlock.sock")
	unlock, err := lockNextTo(sock)
	if err != nil || unlock == nil {
		t.Fatalf("first helper did not get the lock: %v", err)
	}
	second, err := lockNextTo(sock)
	if err != nil || second != nil {
		t.Fatalf("a second helper got the lock too (err %v)", err)
	}
	unlock()
	third, err := lockNextTo(sock)
	if err != nil || third == nil {
		t.Fatalf("the lock was not released: %v", err)
	}
	third()
	if fi, err := os.Stat(filepath.Join(filepath.Dir(sock), "helper.lock")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("lock file: %v %v", fi, err)
	}
}

// clock is a controllable Now.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// onClock sets a server to a fake clock and records its exit. It is a
// newHarness configure func, so it runs before the server serves anything.
func onClock(c *clock, exited chan struct{}) func(*Server) {
	var once sync.Once
	return func(s *Server) {
		s.Now = c.Now
		s.lastUsed = c.Now()
		s.Exit = func() { once.Do(func() { close(exited) }) }
	}
}

// reaping starts the reaper and returns a way to tick it.
func reaping(t *testing.T, s *Server, c *clock) (tick func()) {
	t.Helper()
	ticks := make(chan time.Time)
	go s.reap(ticks)
	t.Cleanup(func() { close(ticks) })
	return func() { ticks <- c.Now() }
}

func exits(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	case <-time.After(2 * time.Second):
		return false
	}
}

func staysUp(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return false
	case <-time.After(50 * time.Millisecond):
		return true
	}
}

func eventually(cond func() bool) bool {
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return false
}

func TestTheHelperExitsAfterAnIdleHourAndNotBefore(t *testing.T) {
	c, exited := &clock{now: t0}, make(chan struct{})
	s := NewServer(&fakeProvider{}, &fakeApprover{allow: true})
	onClock(c, exited)(s)
	tick := reaping(t, s, c)

	c.advance(IdleExit - time.Minute)
	tick()
	if !staysUp(exited) {
		t.Fatal("exited before an idle hour")
	}
	c.advance(time.Minute)
	tick()
	if !exits(exited) {
		t.Fatal("still running after an idle hour")
	}
}

func TestARequestPostponesTheIdleExit(t *testing.T) {
	c, exited := &clock{now: t0}, make(chan struct{})
	h := newHarness(t, true, onClock(c, exited))
	tick := reaping(t, h.server, c)

	c.advance(50 * time.Minute)
	h.ok(sec("A", "op://v/a/f"))
	c.advance(50 * time.Minute)
	tick()
	if !staysUp(exited) {
		t.Fatal("exited 50 minutes after a request")
	}
	c.advance(10 * time.Minute)
	tick()
	if !exits(exited) {
		t.Fatal("still running an hour after the last request")
	}
}

func TestTheReaperSweepsExpiredSecrets(t *testing.T) {
	c, exited := &clock{now: t0}, make(chan struct{})
	h := newHarness(t, true, onClock(c, exited))
	tick := reaping(t, h.server, c)

	h.ok(sec("A", "op://v/a/f"))
	c.advance(Window + time.Second) // expired, but short of the idle hour
	tick()
	if !eventually(func() bool {
		h.server.mu.Lock()
		defer h.server.mu.Unlock()
		return len(h.server.cache.entries) == 0
	}) {
		t.Fatal("an expired secret is still in memory")
	}
}

func TestStopExitsTheHelper(t *testing.T) {
	stopped := make(chan struct{})
	h := newHarness(t, true, func(s *Server) {
		s.Exit = func() { close(stopped) }
	})
	if _, err := client.CallAt(h.sock, proto.Request{Op: proto.OpStop}, false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("stop did not exit the helper")
	}
}
