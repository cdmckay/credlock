package daemon

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdmckay/credlock/internal/approve"
	"github.com/cdmckay/credlock/internal/client"
	"github.com/cdmckay/credlock/internal/proto"
	"github.com/cdmckay/credlock/internal/state"
)

// remote is the hub's tailnet side, on loopback, with Tailscale's answer to
// "who is this?" faked as host, and hub mode on with nothing paired.
type remote struct {
	t    *testing.T
	h    *harness
	addr string
}

func newRemote(t *testing.T, host string, allow bool, configure ...func(*Server)) *remote {
	t.Helper()
	hub := func(s *Server) {
		s.Identify = func(net.Addr) (string, error) { return host, nil }
		s.Accounts = func() []client.Account {
			return []client.Account{{ID: "ACMEACCOUNTID", User: "ACMEUSER", Email: "me@acme.example", URL: "acme.1password.com"}}
		}
		s.SaveHub = func(state.Hub) error { return nil }
		s.hub = state.Hub{Enabled: true, Tailnet: "example.org", Peers: map[string]state.Peer{}}
		s.self = "potato"
	}
	h := newHarness(t, allow, append([]func(*Server){hub}, configure...)...)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go h.server.serveRemote(ln)
	return &remote{t: t, h: h, addr: ln.Addr().String()}
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// ask sends req signed with key, as user, and returns the answer and the
// pairing code a client would show for it.
func (r *remote) ask(key ed25519.PrivateKey, user string, req proto.Request) (proto.Response, string) {
	r.t.Helper()
	conn, err := net.Dial("tcp", r.addr)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	rd := bufio.NewReader(conn)
	first := read(r.t, rd)
	if first.Error != "" {
		return first, ""
	}
	challenge, err := base64.StdEncoding.DecodeString(first.Challenge)
	if err != nil || len(challenge) == 0 {
		r.t.Fatalf("no challenge: %+v", first)
	}
	req.Key, req.User = state.PublicKey(key), user
	req.Proof = base64.StdEncoding.EncodeToString(ed25519.Sign(key, challenge))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		r.t.Fatal(err)
	}
	return read(r.t, rd), state.PairingCode(challenge, req.Key)
}

func read(t *testing.T, r *bufio.Reader) proto.Response {
	t.Helper()
	line, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var resp proto.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func resolveReq(account string, secrets ...proto.Secret) proto.Request {
	return proto.Request{Op: proto.OpResolve, Account: account, Reason: "testing",
		Command: []string{"make"}, Cwd: "/srv", Secrets: secrets}
}

func (r *remote) peers() map[string]state.Peer {
	r.h.server.mu.Lock()
	defer r.h.server.mu.Unlock()
	return r.h.server.hub.Peers
}

func (r *remote) alerts() []string {
	r.h.server.mu.Lock()
	defer r.h.server.mu.Unlock()
	var out []string
	for _, a := range r.h.server.alerts {
		out = append(out, a.Text)
	}
	return out
}

func TestAFirstRequestPairsInItsWindowAndThenNeedsNone(t *testing.T) {
	r := newRemote(t, "papaya", true)
	key, a := newKey(t), sec("A", "op://v/a/f")

	resp, code := r.ask(key, "me", resolveReq("acme", a))
	if resp.Error != "" || resp.Values[a.Ref] != "secret:"+a.Ref {
		t.Fatalf("first request: %+v", resp)
	}
	shown := r.h.approver.dialogs()
	if len(shown) != 1 || shown[0].Pairing != "new" || shown[0].Code != code || shown[0].Origin != "papaya" ||
		shown[0].Requester != "me on papaya, over Tailscale" || shown[0].Account != "acme.1password.com (me@acme.example)" {
		t.Fatalf("the window showed %+v (code %s)", shown, code)
	}
	if p := r.peers()["me@papaya"]; p.Key != state.PublicKey(key) {
		t.Fatalf("not paired: %+v", r.peers())
	}

	// Paired, and approved: the same request again needs no window at all.
	if resp, _ := r.ask(key, "me", resolveReq("acme", a)); resp.Values[a.Ref] == "" {
		t.Fatalf("second request: %+v", resp)
	}
	if n := len(r.h.approver.dialogs()); n != 1 {
		t.Fatalf("%d windows for a paired, approved request", n)
	}
	// A new secret asks again, without pairing.
	r.ask(key, "me", resolveReq("acme", sec("B", "op://v/b/f")))
	if shown := r.h.approver.dialogs(); len(shown) != 2 || shown[1].Pairing != "" {
		t.Fatalf("a paired machine's new secret: %+v", shown)
	}
}

func TestADeniedPairingIsNotRemembered(t *testing.T) {
	r := newRemote(t, "papaya", false)
	if resp, _ := r.ask(newKey(t), "me", resolveReq("acme", sec("A", "op://v/a/f"))); !resp.Denied {
		t.Fatalf("got %+v", resp)
	}
	if len(r.peers()) != 0 {
		t.Fatalf("a denied pairing was kept: %+v", r.peers())
	}
}

func TestAKeyThatDoesntMatchIsRefusedAndRaisesAnAlert(t *testing.T) {
	r := newRemote(t, "papaya", true)
	mine, other := newKey(t), newKey(t)
	r.ask(mine, "me", resolveReq("acme", sec("A", "op://v/a/f")))

	resp, _ := r.ask(other, "me", resolveReq("acme", sec("A", "op://v/a/f")))
	if !strings.Contains(resp.Error, "different key") || !strings.Contains(resp.Error, "credlock hub forget papaya") {
		t.Fatalf("got %+v", resp)
	}
	if n := len(r.h.approver.dialogs()); n != 1 {
		t.Fatalf("a mismatched key reached a window (%d windows)", n)
	}
	if got := r.alerts(); len(got) != 1 || !strings.Contains(got[0], "possibly an attack") {
		t.Fatalf("alerts: %q", got)
	}
	if r.peers()["me@papaya"].Key != state.PublicKey(mine) {
		t.Fatal("the pairing was changed or dropped")
	}
}

func TestFiveDeniedPairingsCoolTheMachineDown(t *testing.T) {
	r := newRemote(t, "papaya", false)
	for i := range maxPairingDenials {
		if resp, _ := r.ask(newKey(t), "me", resolveReq("acme", sec("A", "op://v/a/f"))); !resp.Denied {
			t.Fatalf("denial %d: %+v", i+1, resp)
		}
	}
	resp, _ := r.ask(newKey(t), "me", resolveReq("acme", sec("A", "op://v/a/f")))
	if !strings.Contains(resp.Error, "too many pairing requests") {
		t.Fatalf("after %d denials: %+v", maxPairingDenials, resp)
	}
	if n := len(r.h.approver.dialogs()); n != maxPairingDenials {
		t.Fatalf("%d windows, want %d", n, maxPairingDenials)
	}
	if got := r.alerts(); len(got) != 1 || !strings.Contains(got[0], "refused until") {
		t.Fatalf("alerts: %q", got)
	}
}

func TestAnAllowedPairingClearsEarlierDenials(t *testing.T) {
	r := newRemote(t, "papaya", false)
	for range maxPairingDenials - 1 {
		r.ask(newKey(t), "me", resolveReq("acme", sec("A", "op://v/a/f")))
	}
	r.h.approver.setAllow(true)
	r.ask(newKey(t), "me", resolveReq("acme", sec("A", "op://v/a/f")))
	r.h.approver.setAllow(false)
	if resp, _ := r.ask(newKey(t), "you", resolveReq("acme", sec("A", "op://v/a/f"))); !resp.Denied {
		t.Fatalf("the count wasn't reset: %+v", resp)
	}
}

func TestPairingOnItsOwnShowsNoSecrets(t *testing.T) {
	r := newRemote(t, "papaya", true)
	key := newKey(t)
	pair := proto.Request{Op: proto.OpPair, Reason: "pair me on papaya with potato", Command: []string{"credlock", "pair", "potato"}}
	resp, code := r.ask(key, "me", pair)
	if !resp.Paired {
		t.Fatalf("got %+v", resp)
	}
	shown := r.h.approver.dialogs()
	if len(shown) != 1 || len(shown[0].Secrets) != 0 || shown[0].Pairing != "new" || shown[0].Code != code {
		t.Fatalf("the window showed %+v", shown)
	}
	if resp, _ := r.ask(key, "me", pair); !resp.Paired || len(r.h.approver.dialogs()) != 1 {
		t.Fatalf("pairing again: %+v", resp)
	}
	if got := r.h.provider.fetches(); len(got) != 0 {
		t.Fatalf("pairing fetched secrets: %v", got)
	}
}

func TestTheHubsOwnMachineIsRefused(t *testing.T) {
	r := newRemote(t, "Potato", true)
	resp, _ := r.ask(newKey(t), "me", resolveReq("acme", sec("A", "op://v/a/f")))
	if !strings.Contains(resp.Error, "hub's own machine") || len(r.h.approver.dialogs()) != 0 {
		t.Fatalf("got %+v", resp)
	}
}

func TestAnUnsignedRequestIsRefused(t *testing.T) {
	r := newRemote(t, "papaya", true)
	conn, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	rd := bufio.NewReader(conn)
	read(t, rd) // the challenge
	req := resolveReq("acme", sec("A", "op://v/a/f"))
	req.Key, req.User = state.PublicKey(newKey(t)), "me"
	req.Proof = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatal(err)
	}
	if resp := read(t, rd); !strings.Contains(resp.Error, "isn't signed") || len(r.h.approver.dialogs()) != 0 {
		t.Fatalf("got %+v", resp)
	}
}

func TestARemoteMachineIsApprovedApartFromThisMac(t *testing.T) {
	r := newRemote(t, "papaya", true)
	key, a := newKey(t), sec("A", "op://v/a/f")
	r.ask(key, "me", resolveReq("acme", a))
	// The same secret, in the same account, on this Mac is a new approval:
	// papaya's isn't this Mac's.
	local, err := client.CallAt(r.h.sock, resolveReq("ACMEACCOUNTID", a), false)
	if err != nil || local.Values[a.Ref] == "" {
		t.Fatalf("local: %+v, %v", local, err)
	}
	if n := len(r.h.approver.dialogs()); n != 2 {
		t.Fatalf("this Mac used papaya's approval: %d windows", n)
	}
}

func TestTheAccountIsResolvedOnTheHubAndListedOnce(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	p := &recordAccount{}
	r := newRemote(t, "papaya", true, func(s *Server) {
		s.Provider = p
		s.Accounts = func() []client.Account {
			mu.Lock()
			defer mu.Unlock()
			calls++
			return []client.Account{{ID: "ACMEACCOUNTID", Email: "me@acme.example", URL: "acme.1password.com"}}
		}
	})
	key := newKey(t)
	for _, ref := range []string{"op://v/a/f", "op://v/b/f", "op://v/c/f"} {
		r.ask(key, "me", resolveReq("me@acme.example", sec("X", ref)))
	}
	if got := p.got(); got != "ACMEACCOUNTID" {
		t.Fatalf("the provider was asked for account %q", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("op was asked %d times", calls)
	}
}

type recordAccount struct {
	mu      sync.Mutex
	account string
}

func (p *recordAccount) ResolveAll(_ context.Context, account string, refs []string) (map[string]string, error) {
	p.mu.Lock()
	p.account = account
	p.mu.Unlock()
	out := map[string]string{}
	for _, r := range refs {
		out[r] = "v"
	}
	return out, nil
}

func (p *recordAccount) got() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.account
}

func TestOnlyPairingAndResolvingAreServedOverTheTailnet(t *testing.T) {
	r := newRemote(t, "papaya", true)
	for _, op := range []string{proto.OpStatus, proto.OpClear, proto.OpStop, proto.OpHub} {
		if resp, _ := r.ask(newKey(t), "me", proto.Request{Op: op}); !strings.Contains(resp.Error, "only pairs and resolves") {
			t.Errorf("%s: %+v", op, resp)
		}
	}
}

func TestACheckOnlyRequestNeverOpensAWindow(t *testing.T) {
	r := newRemote(t, "papaya", true)
	key, a := newKey(t), sec("A", "op://v/a/f")
	check := resolveReq("acme", a)
	check.NoPrompt = true
	if resp, _ := r.ask(key, "me", check); !resp.NotHeld || len(r.h.approver.dialogs()) != 0 {
		t.Fatalf("unpaired: %+v", resp)
	}
	r.ask(key, "me", resolveReq("acme", a))
	if resp, _ := r.ask(key, "me", check); resp.NotHeld || resp.Values[a.Ref] == "" {
		t.Fatalf("paired and approved: %+v", resp)
	}
}

func TestForgettingAMachineUnpairsItAndDropsWhatItHeld(t *testing.T) {
	r := newRemote(t, "papaya", true)
	key := newKey(t)
	r.ask(key, "me", resolveReq("acme", sec("A", "op://v/a/f")))
	resp, err := client.CallAt(r.h.sock, proto.Request{Op: proto.OpHub, Hub: proto.HubForget, Host: "papaya"}, false)
	if err != nil || resp.Hub == nil || len(resp.Hub.Peers) != 0 {
		t.Fatalf("forget: %+v, %v", resp, err)
	}
	r.h.server.mu.Lock()
	held := len(r.h.server.cache.list(r.h.server.Now()))
	r.h.server.mu.Unlock()
	if held != 0 {
		t.Fatalf("papaya's approvals outlived its pairing: %d", held)
	}
	// It pairs again as new.
	r.ask(key, "me", resolveReq("acme", sec("A", "op://v/a/f")))
	if shown := r.h.approver.dialogs(); len(shown) != 2 || shown[1].Pairing != "new" {
		t.Fatalf("after forget: %+v", shown)
	}
}

func TestOnlyDevicesOfTheHubsTailnetAreNamed(t *testing.T) {
	for fqdn, want := range map[string]string{
		"papaya.tail1234.ts.net.":     "papaya",
		"Papaya.Tail1234.ts.net":      "papaya",
		"papaya.other99.ts.net.":      "", // another tailnet
		"papaya.sub.tail1234.ts.net.": "", // not directly in it
		"tail1234.ts.net.":            "", // no device name
	} {
		got, ok := inTailnet(fqdn, "tail1234.ts.net")
		if got != want || ok != (want != "") {
			t.Errorf("inTailnet(%q) = %q, %v; want %q", fqdn, got, ok, want)
		}
	}
	if _, ok := inTailnet("papaya.tail1234.ts.net.", ""); ok {
		t.Error("a hub serving no tailnet named a device")
	}
}

// waitingApprover holds its window open until the asker hangs up.
type waitingApprover struct {
	mu     sync.Mutex
	closed bool
}

func (w *waitingApprover) Approve(ctx context.Context, _ approve.Request) (bool, error) {
	<-ctx.Done()
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	return false, ctx.Err()
}

func (w *waitingApprover) wasClosed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closed
}

func TestHangingUpClosesTheWindow(t *testing.T) {
	w := &waitingApprover{}
	r := newRemote(t, "papaya", true, func(s *Server) { s.Approver = w })
	key := newKey(t)
	conn, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	rd := bufio.NewReader(conn)
	first := read(t, rd)
	challenge, _ := base64.StdEncoding.DecodeString(first.Challenge)
	req := resolveReq("acme", sec("A", "op://v/a/f"))
	req.Key, req.User = state.PublicKey(key), "me"
	req.Proof = base64.StdEncoding.EncodeToString(ed25519.Sign(key, challenge))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // the window is open
	_ = conn.Close()
	if !eventually(w.wasClosed) {
		t.Fatal("the window stayed open after the asker hung up")
	}
}
