package client

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdmckay/credlock/internal/proto"
	"github.com/cdmckay/credlock/internal/state"
)

// testAuth is a fresh key for this machine user, with no hubs paired.
func testAuth(t *testing.T) hubAuth {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return hubAuth{key: priv, user: "me", paired: map[string]bool{}}
}

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
	challenge := []byte("a fresh challenge")
	_ = json.NewEncoder(conn).Encode(proto.Response{Challenge: base64.StdEncoding.EncodeToString(challenge)})
	r := bufio.NewReader(conn)
	line, err := r.ReadBytes('\n')
	if err != nil {
		return
	}
	var req proto.Request
	_ = json.Unmarshal(line, &req)
	// A real hub refuses a request that isn't signed with the key it sends.
	pub, err := state.ParsePublicKey(req.Key)
	proof, _ := base64.StdEncoding.DecodeString(req.Proof)
	if err != nil || !ed25519.Verify(pub, challenge, proof) || req.User != "me" {
		_ = json.NewEncoder(conn).Encode(proto.Response{Error: "refused: unsigned"})
		return
	}
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
	resp, _, err := askHubs([]string{other.addr, holds.addr}, request, testAuth(t))
	if err != nil || resp.Values["op://v/a/f"] != holds.addr+":op://v/a/f" {
		t.Fatalf("got %+v, %v", resp, err)
	}
	if p, _ := other.state(); p != 0 {
		t.Fatalf("a window opened on the other hub (%d)", p)
	}
}

func TestTheFirstAllowWinsAndTheOtherWindowsClose(t *testing.T) {
	allow, wait := startHub(t, "allow", 50*time.Millisecond), startHub(t, "wait", 0)
	resp, winner, err := askHubs([]string{wait.addr, allow.addr}, request, testAuth(t))
	if err != nil || resp.Values["op://v/a/f"] != allow.addr+":op://v/a/f" || winner != allow.addr {
		t.Fatalf("got %+v from %q, %v", resp, winner, err)
	}
	if !waitFor(func() bool { _, hung := wait.state(); return hung }) {
		t.Fatal("the other hub's window was left open")
	}
}

func TestADenyEndsTheRequestEverywhere(t *testing.T) {
	deny, wait := startHub(t, "deny", 20*time.Millisecond), startHub(t, "wait", 0)
	resp, _, err := askHubs([]string{deny.addr, wait.addr}, request, testAuth(t))
	if err != nil || !resp.Denied || resp.TimedOut {
		t.Fatalf("got %+v, %v", resp, err)
	}
	if !waitFor(func() bool { _, hung := wait.state(); return hung }) {
		t.Fatal("the other hub's window was left open after a deny")
	}
}

func TestAWindowNobodyAnsweredDoesNotCount(t *testing.T) {
	timeout, allow := startHub(t, "timeout", 0), startHub(t, "allow", 100*time.Millisecond)
	resp, _, err := askHubs([]string{timeout.addr, allow.addr}, request, testAuth(t))
	if err != nil || resp.Values["op://v/a/f"] != allow.addr+":op://v/a/f" {
		t.Fatalf("got %+v, %v", resp, err)
	}
	both := []string{startHub(t, "timeout", 0).addr, startHub(t, "timeout", 0).addr}
	if resp, _, err := askHubs(both, request, testAuth(t)); err != nil || !resp.TimedOut {
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
	if resp, _, err := askHubs([]string{down, allow.addr}, request, testAuth(t)); err != nil || len(resp.Values) != 1 {
		t.Fatalf("got %+v, %v", resp, err)
	}
	if _, _, err := askHubs([]string{down}, request, testAuth(t)); err == nil || !strings.Contains(err.Error(), "credlock hub on") {
		t.Fatalf("with no hub reachable: %v", err)
	}
}

func TestAHubIsToldTheCodeOnlyWhenNotYetPaired(t *testing.T) {
	hub := startHub(t, "allow", 0)
	auth := testAuth(t)
	var said []string
	auth.say = func(s string) { said = append(said, s) }
	if _, _, err := askHubs([]string{hub.addr}, request, auth); err != nil {
		t.Fatal(err)
	}
	if len(said) != 1 || !strings.Contains(said[0], "its window shows this code") {
		t.Fatalf("an unpaired hub: %q", said)
	}
	said = nil
	auth.paired[strings.ToLower(hub.addr)] = true
	if _, _, err := askHubs([]string{hub.addr}, request, auth); err != nil || len(said) != 0 {
		t.Fatalf("a paired hub: %q, %v", said, err)
	}
}
