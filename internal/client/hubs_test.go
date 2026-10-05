package client

import (
	"bufio"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdmckay/credlock/internal/proto"
)

// fakeHub answers like a hub: "holds" has the secrets already; "allow",
// "deny" and "timeout" are how its window ends; "wait" never answers, and
// notices when the asker hangs up.
type fakeHub struct {
	addr     string
	mu       sync.Mutex
	prompted int  // requests that would have opened a window
	hungUp   bool // the asker closed the connection while it waited
}

func startHub(t *testing.T, behaviour string, delay time.Duration) *fakeHub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	h := &fakeHub{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go h.serve(conn, behaviour, delay)
		}
	}()
	return h
}

func (h *fakeHub) serve(conn net.Conn, behaviour string, delay time.Duration) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	line, err := r.ReadBytes('\n')
	if err != nil {
		return
	}
	var req proto.Request
	_ = json.Unmarshal(line, &req)
	values := map[string]string{}
	for _, s := range req.Secrets {
		values[s.Ref] = h.addr + ":" + s.Ref
	}
	answer := func(resp proto.Response) { _ = json.NewEncoder(conn).Encode(resp) }
	if req.NoPrompt {
		if behaviour == "holds" {
			answer(proto.Response{Values: values})
		} else {
			answer(proto.Response{NotHeld: true})
		}
		return
	}
	h.mu.Lock()
	h.prompted++
	h.mu.Unlock()
	if behaviour == "wait" {
		_, err := r.ReadByte() // returns when the asker hangs up
		h.mu.Lock()
		h.hungUp = err != nil
		h.mu.Unlock()
		return
	}
	time.Sleep(delay)
	switch behaviour {
	case "allow":
		answer(proto.Response{Values: values})
	case "deny":
		answer(proto.Response{Denied: true})
	case "timeout":
		answer(proto.Response{Denied: true, TimedOut: true})
	}
}

func (h *fakeHub) state() (prompted int, hungUp bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.prompted, h.hungUp
}

func waitFor(cond func() bool) bool {
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return false
}

var request = proto.Request{Op: proto.OpResolve, Account: "acct", Reason: "testing",
	Command: []string{"true"}, Secrets: []proto.Secret{{Name: "A", Ref: "op://v/a/f"}}}

func TestAHubThatHoldsTheSecretsAnswersBeforeAnyWindowOpens(t *testing.T) {
	holds, other := startHub(t, "holds", 0), startHub(t, "allow", 0)
	resp, err := askHubs([]string{other.addr, holds.addr}, request)
	if err != nil || resp.Values["op://v/a/f"] != holds.addr+":op://v/a/f" {
		t.Fatalf("got %+v, %v", resp, err)
	}
	if p, _ := other.state(); p != 0 {
		t.Fatalf("a window opened on the other hub (%d)", p)
	}
}

func TestTheFirstAllowWinsAndTheOtherWindowsClose(t *testing.T) {
	allow, wait := startHub(t, "allow", 50*time.Millisecond), startHub(t, "wait", 0)
	resp, err := askHubs([]string{wait.addr, allow.addr}, request)
	if err != nil || resp.Values["op://v/a/f"] != allow.addr+":op://v/a/f" {
		t.Fatalf("got %+v, %v", resp, err)
	}
	if !waitFor(func() bool { _, hung := wait.state(); return hung }) {
		t.Fatal("the other hub's window was left open")
	}
}

func TestADenyEndsTheRequestEverywhere(t *testing.T) {
	deny, wait := startHub(t, "deny", 20*time.Millisecond), startHub(t, "wait", 0)
	resp, err := askHubs([]string{deny.addr, wait.addr}, request)
	if err != nil || !resp.Denied || resp.TimedOut {
		t.Fatalf("got %+v, %v", resp, err)
	}
	if !waitFor(func() bool { _, hung := wait.state(); return hung }) {
		t.Fatal("the other hub's window was left open after a deny")
	}
}

func TestAWindowNobodyAnsweredDoesNotCount(t *testing.T) {
	timeout, allow := startHub(t, "timeout", 0), startHub(t, "allow", 100*time.Millisecond)
	resp, err := askHubs([]string{timeout.addr, allow.addr}, request)
	if err != nil || resp.Values["op://v/a/f"] != allow.addr+":op://v/a/f" {
		t.Fatalf("got %+v, %v", resp, err)
	}
	both := []string{startHub(t, "timeout", 0).addr, startHub(t, "timeout", 0).addr}
	if resp, err := askHubs(both, request); err != nil || !resp.TimedOut {
		t.Fatalf("every window timed out: got %+v, %v", resp, err)
	}
}

func TestAnUnreachableHubIsSkipped(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	down := ln.Addr().String()
	_ = ln.Close()
	allow := startHub(t, "allow", 0)
	if resp, err := askHubs([]string{down, allow.addr}, request); err != nil || len(resp.Values) != 1 {
		t.Fatalf("got %+v, %v", resp, err)
	}
	if _, err := askHubs([]string{down}, request); err == nil || !strings.Contains(err.Error(), "hub.allow") {
		t.Fatalf("with no hub reachable: %v", err)
	}
}
