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
	return hubAuth{key: priv, user: "me", pinned: map[string]string{}}
}

// fakeHub answers like a hub: "holds" has the secrets already; "allow",
// "deny" and "timeout" are how its window ends; "wait" never answers, and
// notices when the asker hangs up; "impostor" sends a hub key it can't sign
// with, as something else holding the hub's port would.
type fakeHub struct {
	addr     string
	key      ed25519.PrivateKey
	mu       sync.Mutex
	prompted int  // requests that would have opened a window
	hungUp   bool // the asker closed the connection while it waited
	asked    bool // a request reached it
}

func startHub(t *testing.T, behaviour string, delay time.Duration) *fakeHub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHub{addr: ln.Addr().String(), key: key}
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
	var hello proto.Request
	if line, err := r.ReadBytes('\n'); err != nil || json.Unmarshal(line, &hello) != nil {
		return
	}
	nonce, _ := base64.StdEncoding.DecodeString(hello.Nonce)
	challenge := []byte("a fresh challenge")
	hubKey, signer := state.PublicKey(h.key), h.key
	if behaviour == "impostor" {
		_, signer, _ = ed25519.GenerateKey(nil)
	}
	_ = json.NewEncoder(conn).Encode(proto.Response{
		Challenge: base64.StdEncoding.EncodeToString(challenge),
		HubKey:    hubKey,
		HubProof:  base64.StdEncoding.EncodeToString(ed25519.Sign(signer, state.HubProof(nonce, challenge))),
	})
	line, err := r.ReadBytes('\n')
	if err != nil {
		return
	}
	var req proto.Request
	_ = json.Unmarshal(line, &req)
	h.mu.Lock()
	h.asked = true
	h.mu.Unlock()
	// A real hub refuses a request that isn't signed with the key it sends.
	pub, err := state.ParsePublicKey(req.Key)
	proof, _ := base64.StdEncoding.DecodeString(req.Proof)
	if err != nil || !ed25519.Verify(pub, state.ClientProof(challenge, nonce, hubKey), proof) || req.User != "me" {
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

func (h *fakeHub) wasAsked() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.asked
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
	got, err := askHubs([]string{other.addr, holds.addr}, request, testAuth(t))
	if err != nil || got.resp.Values["op://v/a/f"] != holds.addr+":op://v/a/f" || got.key != state.PublicKey(holds.key) {
		t.Fatalf("got %+v, %v", got, err)
	}
	if p, _ := other.state(); p != 0 {
		t.Fatalf("a window opened on the other hub (%d)", p)
	}
}

func TestTheFirstAllowWinsAndTheOtherWindowsClose(t *testing.T) {
	allow, wait := startHub(t, "allow", 50*time.Millisecond), startHub(t, "wait", 0)
	got, err := askHubs([]string{wait.addr, allow.addr}, request, testAuth(t))
	if err != nil || got.resp.Values["op://v/a/f"] != allow.addr+":op://v/a/f" || got.hub != allow.addr {
		t.Fatalf("got %+v, %v", got, err)
	}
	if !waitFor(func() bool { _, hung := wait.state(); return hung }) {
		t.Fatal("the other hub's window was left open")
	}
}

func TestADenyEndsTheRequestEverywhere(t *testing.T) {
	deny, wait := startHub(t, "deny", 20*time.Millisecond), startHub(t, "wait", 0)
	got, err := askHubs([]string{deny.addr, wait.addr}, request, testAuth(t))
	if err != nil || !got.resp.Denied || got.resp.TimedOut {
		t.Fatalf("got %+v, %v", got, err)
	}
	if !waitFor(func() bool { _, hung := wait.state(); return hung }) {
		t.Fatal("the other hub's window was left open after a deny")
	}
}

func TestAWindowNobodyAnsweredDoesNotCount(t *testing.T) {
	timeout, allow := startHub(t, "timeout", 0), startHub(t, "allow", 100*time.Millisecond)
	got, err := askHubs([]string{timeout.addr, allow.addr}, request, testAuth(t))
	if err != nil || got.resp.Values["op://v/a/f"] != allow.addr+":op://v/a/f" {
		t.Fatalf("got %+v, %v", got, err)
	}
	both := []string{startHub(t, "timeout", 0).addr, startHub(t, "timeout", 0).addr}
	if got, err := askHubs(both, request, testAuth(t)); err != nil || !got.resp.TimedOut {
		t.Fatalf("every window timed out: got %+v, %v", got, err)
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
	if got, err := askHubs([]string{down, allow.addr}, request, testAuth(t)); err != nil || len(got.resp.Values) != 1 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := askHubs([]string{down}, request, testAuth(t)); err == nil || !strings.Contains(err.Error(), "credlock hub on") {
		t.Fatalf("with no hub reachable: %v", err)
	}
}

func TestAHubIsToldTheCodeOnlyWhenNotYetPaired(t *testing.T) {
	hub := startHub(t, "allow", 0)
	auth := testAuth(t)
	var said []string
	auth.say = func(s string) { said = append(said, s) }
	if _, err := askHubs([]string{hub.addr}, request, auth); err != nil {
		t.Fatal(err)
	}
	if len(said) != 1 || !strings.Contains(said[0], "its window shows this code") {
		t.Fatalf("an unpaired hub: %q", said)
	}
	said = nil
	auth.pinned[strings.ToLower(hub.addr)] = state.PublicKey(hub.key)
	if _, err := askHubs([]string{hub.addr}, request, auth); err != nil || len(said) != 0 {
		t.Fatalf("a paired hub: %q, %v", said, err)
	}
}

func TestAnAnswerThatCantProveItIsTheHubIsRefused(t *testing.T) {
	impostor := startHub(t, "impostor", 0)
	got, err := askHubs([]string{impostor.addr}, request, testAuth(t))
	if err == nil || !strings.Contains(err.Error(), "couldn't prove it is a credlock hub") || len(got.resp.Values) != 0 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if strings.Contains(err.Error(), "online") {
		t.Fatalf("a refusal was taken for a hub that is offline: %v", err)
	}
	if impostor.wasAsked() {
		t.Fatal("the request was sent before the hub proved itself")
	}
}

func TestAPairedHubAnsweringWithAnotherKeyIsRefused(t *testing.T) {
	hub := startHub(t, "holds", 0)
	auth := testAuth(t)
	_, other, _ := ed25519.GenerateKey(nil)
	auth.pinned[strings.ToLower(hub.addr)] = state.PublicKey(other)
	got, err := askHubs([]string{hub.addr}, request, auth)
	if err == nil || !strings.Contains(err.Error(), "didn't pair with") || len(got.resp.Values) != 0 || hub.wasAsked() {
		t.Fatalf("got %+v, %v", got, err)
	}
}
