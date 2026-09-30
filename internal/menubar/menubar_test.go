package menubar

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestFakeBarProcess is the fake icon, not a test: it only acts when fakeBar
// starts it. It appends every snapshot it reads to $CREDLOCK_FAKE_BAR_LOG.
func TestFakeBarProcess(t *testing.T) {
	mode := os.Getenv("CREDLOCK_FAKE_BAR")
	if mode == "" {
		return
	}
	log, err := os.OpenFile(os.Getenv("CREDLOCK_FAKE_BAR_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(3)
	}
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		_, _ = fmt.Fprintln(log, sc.Text())
		switch mode {
		case "act":
			fmt.Println(`{"op":"grant","ref":"op://v/i/f"}`) // not an action: dropped
			fmt.Println(`{"op":"forget","account_id":"acct","ref":"op://v/i/f"}`)
		case "die":
			os.Exit(3) // not 0: the testing package treats os.Exit(0) mid-test as a failure
		}
	}
	os.Exit(4)
}

type recorder struct {
	mu      sync.Mutex
	actions []Action
	starts  int
}

func (r *recorder) act(a Action) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.actions = append(r.actions, a)
}

func (r *recorder) got() ([]Action, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Action(nil), r.actions...), r.starts
}

// fakeBar is a Bar whose icon is this test binary, behaving as mode.
func fakeBar(t *testing.T, mode string) (*Bar, *recorder, string) {
	t.Helper()
	log := filepath.Join(t.TempDir(), "snapshots")
	r := &recorder{}
	b := New(r.act)
	b.command = func() *exec.Cmd {
		r.mu.Lock()
		r.starts++
		r.mu.Unlock()
		cmd := exec.Command(os.Args[0], "-test.run=^TestFakeBarProcess$")
		cmd.Env = append(os.Environ(), "CREDLOCK_FAKE_BAR="+mode, "CREDLOCK_FAKE_BAR_LOG="+log)
		return cmd
	}
	return b, r, log
}

func eventually(cond func() bool) bool {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return false
}

func lines(path string) []string {
	data, _ := os.ReadFile(path)
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

var holding = Snapshot{Held: []Held{{AccountID: "acct", Account: "acct", Name: "A", Ref: "op://v/i/f", Left: "60 min left"}}, Read: true}

func TestNothingStartsUntilASecretIsHeld(t *testing.T) {
	b, r, _ := fakeBar(t, "record")
	b.Notify(Snapshot{})
	time.Sleep(50 * time.Millisecond)
	if _, starts := r.got(); starts != 0 {
		t.Fatalf("an empty snapshot started %d icons", starts)
	}
}

func TestTheIconGetsSnapshotsAndItsActionsComeBack(t *testing.T) {
	b, r, log := fakeBar(t, "act")
	b.Notify(holding)
	if !eventually(func() bool { a, _ := r.got(); return len(a) > 0 }) {
		t.Fatal("no action came back")
	}
	actions, starts := r.got()
	if starts != 1 || len(actions) != 1 || actions[0] != (Action{Op: OpForget, AccountID: "acct", Ref: "op://v/i/f"}) {
		t.Fatalf("starts %d, actions %+v: want only the valid forget", starts, actions)
	}
	got := lines(log)
	var s Snapshot
	if len(got) != 1 || json.Unmarshal([]byte(got[0]), &s) != nil || len(s.Held) != 1 || !s.Read {
		t.Fatalf("the icon read %q", got)
	}
}

func TestADeadIconIsReplaced(t *testing.T) {
	// Each fake icon reads one snapshot and dies. A snapshot sent while one
	// is dying can be lost with it (the helper sends another within a
	// minute), so keep sending: the property is that later snapshots reach a
	// new icon.
	b, r, log := fakeBar(t, "die")
	if !eventually(func() bool { b.Notify(holding); return len(lines(log)) >= 2 }) {
		_, starts := r.got()
		t.Fatalf("no second icon read a snapshot (%d started)", starts)
	}
	if _, starts := r.got(); starts < 2 {
		t.Fatalf("%d icons started, want at least 2", starts)
	}
}

func TestOnlyActionsThatTakeAccessAwayAreValid(t *testing.T) {
	for a, want := range map[Action]bool{
		{Op: OpForget, AccountID: "acct", Ref: "op://v/i/f"}: true,
		{Op: OpForget, Ref: "op://v/i/f"}:                    false,
		{Op: OpForgetAll}:                                    true,
		{Op: OpStop}:                                         true,
		{Op: "allow"}:                                        false,
	} {
		if a.valid() != want {
			t.Errorf("%+v valid = %v", a, !want)
		}
	}
}
