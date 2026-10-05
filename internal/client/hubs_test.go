package client

import (
	"bufio"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdmckay/credlock/internal/channel"
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
	cert, err := channel.Certificate(priv)
	if err != nil {
		t.Fatal(err)
	}
	return hubAuth{cert: cert, user: "me", pinned: map[string]string{}}
}

// fakeHub answers like a hub: "holds" has the secrets already; "allow",
// "deny" and "timeout" are how its window ends; "pairing" says it is opening
// its pairing window, then allows; "wait" never answers, and notices when the
// asker hangs up; "plain" doesn't speak TLS, as something else holding the
// hub's port might not.
type fakeHub struct {
	addr     string
	key      ed25519.PrivateKey
	cert     tls.Certificate
	mu       sync.Mutex
	prompted int    // requests that would have opened a window
	hungUp   bool   // the asker closed the connection while it waited
	asked    bool   // a request reached it
	code     string // the pairing code its window would show
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
	cert, err := channel.Certificate(key)
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHub{addr: ln.Addr().String(), key: key, cert: cert}
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

func (h *fakeHub) serve(raw net.Conn, behaviour string, delay time.Duration) {
	defer func() { _ = raw.Close() }()
	answer := func(w io.Writer, resp proto.Response) { _ = json.NewEncoder(w).Encode(resp) }
	if behaviour == "plain" {
		answer(raw, proto.Response{Values: map[string]string{"op://v/a/f": "made up"}})
		return
	}
	conn := channel.Server(raw, h.cert)
	if err := conn.Handshake(); err != nil {
		return
	}
	cs := conn.ConnectionState()
	key, err := channel.PeerKey(cs)
	code, _ := channel.PairingCode(cs)
	r := bufio.NewReader(conn)
	line, rerr := r.ReadBytes('\n')
	if rerr != nil {
		return
	}
	var req proto.Request
	_ = json.Unmarshal(line, &req)
	h.mu.Lock()
	h.asked, h.code = true, code
	h.mu.Unlock()
	if err != nil || key == "" || req.User != "me" {
		answer(conn, proto.Response{Error: "refused: no key"})
		return
	}
	values := map[string]string{}
	for _, s := range req.Secrets {
		values[s.Ref] = h.addr + ":" + s.Ref
	}
	if req.NoPrompt {
		if behaviour == "holds" {
			answer(conn, proto.Response{Values: values})
		} else {
			answer(conn, proto.Response{NotHeld: true})
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
	case "pairing":
		answer(conn, proto.Response{Pairing: true})
		answer(conn, proto.Response{Values: values})
	case "allow":
		answer(conn, proto.Response{Values: values})
	case "deny":
		answer(conn, proto.Response{Denied: true})
	case "timeout":
		answer(conn, proto.Response{Denied: true, TimedOut: true})
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

func TestTheCodeShowsOnlyWhenTheHubSaysItIsPairing(t *testing.T) {
	pairing, allow := startHub(t, "pairing", 0), startHub(t, "allow", 0)
	auth := testAuth(t)
	var said []string
	auth.say = func(s string) { said = append(said, s) }
	// Pinned already, as a machine is after the hub forgets it: the hub says
	// it is pairing, so the code shows all the same.
	auth.pinned[strings.ToLower(pairing.addr)] = state.PublicKey(pairing.key)
	if _, err := askHubs([]string{pairing.addr}, request, auth); err != nil {
		t.Fatal(err)
	}
	pairing.mu.Lock()
	code := strings.Join(strings.Split(pairing.code, ""), " ")
	pairing.mu.Unlock()
	if len(said) != 1 || !strings.Contains(said[0], "Pair only if its window shows this code") || !strings.Contains(said[0], code) {
		t.Fatalf("a hub that is pairing: %q, its code %s", said, code)
	}
	said = nil
	if _, err := askHubs([]string{allow.addr}, request, auth); err != nil || len(said) != 0 {
		t.Fatalf("a hub that isn't pairing: %q, %v", said, err)
	}
}

func TestSomethingThatDoesntCompleteTheHandshakeIsRefused(t *testing.T) {
	plain := startHub(t, "plain", 0)
	got, err := askHubs([]string{plain.addr}, request, testAuth(t))
	if err == nil || !strings.Contains(err.Error(), "didn't complete credlock's handshake") || !strings.Contains(err.Error(), "port 7177") ||
		len(got.resp.Values) != 0 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if strings.Contains(err.Error(), "online") {
		t.Fatalf("a refusal was taken for a hub that is offline: %v", err)
	}
}

func TestAPairedHubAnsweringWithAnotherKeyIsRefused(t *testing.T) {
	hub := startHub(t, "holds", 0)
	auth := testAuth(t)
	_, other, _ := ed25519.GenerateKey(nil)
	auth.pinned[strings.ToLower(hub.addr)] = state.PublicKey(other)
	got, err := askHubs([]string{hub.addr}, request, auth)
	if err == nil || !strings.Contains(err.Error(), "different key from the one it paired with") ||
		!strings.Contains(err.Error(), "credlock pair --forget") || len(got.resp.Values) != 0 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if hub.wasAsked() {
		t.Fatal("the request was sent to a hub whose key changed")
	}
}

func TestAPairedHubIsAskedWithItsKeyChecked(t *testing.T) {
	hub := startHub(t, "holds", 0)
	auth := testAuth(t)
	auth.pinned[strings.ToLower(hub.addr)] = state.PublicKey(hub.key)
	if got, err := askHubs([]string{hub.addr}, request, auth); err != nil || got.key != state.PublicKey(hub.key) || len(got.resp.Values) != 1 {
		t.Fatalf("got %+v, %v", got, err)
	}
}
