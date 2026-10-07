package daemon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cdmckay/credlock/internal/approve"
	"github.com/cdmckay/credlock/internal/channel"
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
	key  ed25519.PrivateKey // the hub's own
}

func newRemote(t *testing.T, host string, allow bool, configure ...func(*Server)) *remote {
	t.Helper()
	hubKey := newKey(t)
	hub := func(s *Server) {
		s.Identify = func(net.Addr) (string, error) { return host, nil }
		s.Accounts = func() []client.Account {
			return []client.Account{{ID: "ACMEACCOUNTID", User: "ACMEUSER", Email: "me@acme.example", URL: "acme.1password.com"}}
		}
		s.SaveHub = func(state.Hub) error { return nil }
		s.LoadKey = func() (ed25519.PrivateKey, error) { return hubKey, nil }
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
	return &remote{t: t, h: h, addr: ln.Addr().String(), key: hubKey}
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// session is one connection to the hub, after the TLS handshake and the
// hub's first line.
type session struct {
	conn  *tls.Conn
	rd    *bufio.Reader
	cs    tls.ConnectionState
	first proto.Response // the hub's commitment to its part of a pairing code, or a refusal
}

// open connects as a machine with key does, and checks that the hub proved
// its own key.
func (r *remote) open(key ed25519.PrivateKey) (*session, error) {
	cert, err := channel.Certificate(key)
	if err != nil {
		return nil, err
	}
	raw, err := net.Dial("tcp", r.addr)
	if err != nil {
		return nil, err
	}
	conn := channel.Client(raw, cert, func(hubKey string) error {
		if hubKey != state.PublicKey(r.key) {
			return fmt.Errorf("the hub proved another key: %s", hubKey)
		}
		return nil
	})
	if err := conn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	s := &session{conn: conn, rd: bufio.NewReader(conn), cs: conn.ConnectionState()}
	if s.first, err = readAnswer(s.rd); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if s.first.Error == "" && s.first.Commit == "" {
		_ = conn.Close()
		return nil, fmt.Errorf("the hub didn't commit first: %+v", s.first)
	}
	return s, nil
}

// write sends req as user, with a fresh nonce, which it returns.
func (s *session) write(user string, req proto.Request) ([]byte, error) {
	nonce := make([]byte, channel.NonceSize)
	_, _ = rand.Read(nonce)
	req.User, req.Nonce = user, base64.StdEncoding.EncodeToString(nonce)
	return nonce, json.NewEncoder(s.conn).Encode(req)
}

// send sends req as user, and returns the answer and the pairing code the
// hub's pairing line gives, if it sent one, checked against its commitment.
func (s *session) send(user string, req proto.Request) (proto.Response, string, error) {
	nonce, err := s.write(user, req)
	if err != nil {
		return proto.Response{}, "", err
	}
	code := ""
	for {
		resp, err := readAnswer(s.rd)
		if err != nil || !resp.Pairing {
			return resp, code, err
		}
		commit, _ := base64.StdEncoding.DecodeString(s.first.Commit)
		reveal, _ := base64.StdEncoding.DecodeString(resp.Reveal)
		if !bytes.Equal(channel.Commit(reveal), commit) {
			return resp, "", errors.New("the hub's reveal doesn't match its commitment")
		}
		if code, err = channel.PairingCode(s.cs, reveal, nonce); err != nil {
			return resp, "", err
		}
	}
}

// try sends req as user, from a machine with key, and returns the answer and
// the pairing code its terminal would show: none unless the hub revealed one,
// as it opened its pairing window. It fails nothing, so goroutines can use it.
func (r *remote) try(key ed25519.PrivateKey, user string, req proto.Request) (proto.Response, string, error) {
	s, err := r.open(key)
	if err != nil {
		return proto.Response{}, "", err
	}
	defer func() { _ = s.conn.Close() }()
	if s.first.Error != "" {
		return s.first, "", nil
	}
	return s.send(user, req)
}

// ask is try, failing the test on any error.
func (r *remote) ask(key ed25519.PrivateKey, user string, req proto.Request) (proto.Response, string) {
	r.t.Helper()
	resp, code, err := r.try(key, user, req)
	if err != nil {
		r.t.Fatal(err)
	}
	return resp, code
}

func readAnswer(r *bufio.Reader) (proto.Response, error) {
	var resp proto.Response
	line, err := r.ReadBytes('\n')
	if err == nil {
		err = json.Unmarshal(line, &resp)
	}
	return resp, err
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
	if resp.Error != "" || resp.Values[a.Ref] != "secret:"+a.Ref || code == "" {
		t.Fatalf("first request: %+v, code %q", resp, code)
	}
	// Two windows, one job each: the pairing, with no secrets in it, then the
	// approval, with no pairing in it.
	shown := r.h.approver.dialogs()
	if len(shown) != 2 || shown[0].Pairing != "new" || shown[0].Code != code || len(shown[0].Secrets) != 0 ||
		shown[0].Origin != "papaya" || shown[0].User != "me" || shown[0].Requester != "me (as papaya reports it)" {
		t.Fatalf("the pairing window showed %+v (code %s)", shown, code)
	}
	if shown[1].Pairing != "" || len(shown[1].Secrets) != 1 || shown[1].Account != "acme.1password.com (me@acme.example)" {
		t.Fatalf("the approval window showed %+v", shown[1])
	}
	if p := r.peers()["me@papaya"]; p.Key != state.PublicKey(key) {
		t.Fatalf("not paired: %+v", r.peers())
	}

	// Paired, and approved: the same request again needs no window at all,
	// and the terminal shows no code.
	if resp, code := r.ask(key, "me", resolveReq("acme", a)); resp.Values[a.Ref] == "" || code != "" {
		t.Fatalf("second request: %+v, code %q", resp, code)
	}
	if n := len(r.h.approver.dialogs()); n != 2 {
		t.Fatalf("%d windows after a paired, approved request again", n)
	}
	// A new secret asks again, without pairing.
	r.ask(key, "me", resolveReq("acme", sec("B", "op://v/b/f")))
	if shown := r.h.approver.dialogs(); len(shown) != 3 || shown[2].Pairing != "" {
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
	if n := len(r.h.approver.dialogs()); n != 2 {
		t.Fatalf("a mismatched key reached a window (%d windows)", n)
	}
	// The user is only what the machine says; the alert says so.
	if got := r.alerts(); len(got) != 1 || !strings.Contains(got[0], "Something on papaya, saying it is me") || !strings.Contains(got[0], "may be an attack") {
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
	if !strings.Contains(resp.Error, "too many pairing windows") {
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

func TestAMachineWithoutAKeyIsRefused(t *testing.T) {
	r := newRemote(t, "papaya", true)
	raw, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	defer func() { _ = conn.Close() }()
	_ = conn.Handshake() // a TLS 1.3 client finishes before the hub refuses it
	_ = json.NewEncoder(conn).Encode(resolveReq("acme", sec("A", "op://v/a/f")))
	if resp, err := readAnswer(bufio.NewReader(conn)); err == nil {
		t.Fatalf("the hub answered a machine with no key: %+v", resp)
	}
	if len(r.h.approver.dialogs()) != 0 {
		t.Fatal("a window opened")
	}
}

func TestAMachineThatDoesntSpeakTLSGetsNothing(t *testing.T) {
	r := newRemote(t, "papaya", true)
	conn, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := json.NewEncoder(conn).Encode(resolveReq("acme", sec("A", "op://v/a/f"))); err != nil {
		t.Fatal(err)
	}
	if resp, err := readAnswer(bufio.NewReader(conn)); err == nil {
		t.Fatalf("got %+v", resp)
	}
	if len(r.h.approver.dialogs()) != 0 {
		t.Fatal("a window opened")
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
	if n := len(r.h.approver.dialogs()); n != 3 {
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
	// Unpaired, but a check opens no window, so the hub reveals no code.
	if resp, code := r.ask(key, "me", check); !resp.NotHeld || code != "" || len(r.h.approver.dialogs()) != 0 {
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
	if shown := r.h.approver.dialogs(); len(shown) != 4 || shown[2].Pairing != "new" || shown[3].Pairing != "" {
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
	s, err := r.open(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.write("me", resolveReq("acme", sec("A", "op://v/a/f"))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // the window is open
	_ = s.conn.Close()
	if !eventually(w.wasClosed) {
		t.Fatal("the window stayed open after the asker hung up")
	}
}

// queue starts each request at once and lets the approver answer only after
// all of them have had time to queue for their turn.
func (r *remote) queue(hold chan struct{}, n int, ask func(i int) proto.Response) []proto.Response {
	r.t.Helper()
	out := make([]proto.Response, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = ask(i)
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(hold)
	wg.Wait()
	return out
}

func TestPairingRequestsQueuedTogetherStillStopAtFiveDenials(t *testing.T) {
	hold := make(chan struct{})
	r := newRemote(t, "papaya", false, func(s *Server) { s.Approver.(*fakeApprover).hold = hold })
	const n = maxPairingDenials + 3
	keys := make([]ed25519.PrivateKey, n)
	for i := range keys {
		keys[i] = newKey(t)
	}
	got := r.queue(hold, n, func(i int) proto.Response {
		resp, _, err := r.try(keys[i], fmt.Sprintf("user%d", i), proto.Request{Op: proto.OpPair, Reason: "pair"})
		if err != nil {
			resp.Error = err.Error()
		}
		return resp
	})
	refused := 0
	for _, resp := range got {
		if strings.Contains(resp.Error, "too many pairing windows") {
			refused++
		}
	}
	if shown := len(r.h.approver.dialogs()); shown != maxPairingDenials || refused != n-maxPairingDenials {
		t.Fatalf("%d windows and %d refusals for %d requests: %+v", shown, refused, n, got)
	}
}

func TestAPairingQueuedBehindTheSameUsersIsRefused(t *testing.T) {
	hold := make(chan struct{})
	r := newRemote(t, "papaya", true, func(s *Server) { s.Approver.(*fakeApprover).hold = hold })
	keys := []ed25519.PrivateKey{newKey(t), newKey(t)}
	got := r.queue(hold, 2, func(i int) proto.Response {
		resp, _, err := r.try(keys[i], "me", proto.Request{Op: proto.OpPair, Reason: "pair"})
		if err != nil {
			resp.Error = err.Error()
		}
		return resp
	})
	winner := 0
	if !got[0].Paired {
		winner = 1
	}
	// One window, for whichever came first; the other is a different key for
	// a paired user, refused with no window at all.
	if !got[winner].Paired || !strings.Contains(got[1-winner].Error, "different key") || len(r.h.approver.dialogs()) != 1 {
		t.Fatalf("got %+v, %d windows", got, len(r.h.approver.dialogs()))
	}
	if r.peers()["me@papaya"].Key != state.PublicKey(keys[winner]) || len(r.alerts()) != 1 {
		t.Fatalf("the pairing changed: %+v, alerts %q", r.peers(), r.alerts())
	}
}

func TestPairingNeverReplacesAPairedKey(t *testing.T) {
	r := newRemote(t, "papaya", true)
	mine, theirs := state.PublicKey(newKey(t)), state.PublicKey(newKey(t))
	if err := r.h.server.pairPeer(state.Peer{Host: "papaya", User: "me", Key: mine}); err != nil {
		t.Fatal(err)
	}
	if err := r.h.server.pairPeer(state.Peer{Host: "papaya", User: "me", Key: theirs}); err == nil || r.peers()["me@papaya"].Key != mine {
		t.Fatalf("replaced: %v, %+v", err, r.peers())
	}
}

func TestAPortSomethingElseHoldsRaisesAnAlert(t *testing.T) {
	r := newRemote(t, "papaya", true)
	r.h.server.listenFailed("100.64.0.1:7177", &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)})
	if a := r.alerts(); len(a) != 1 || !strings.Contains(a[0], "holds 100.64.0.1:7177") {
		t.Fatalf("alerts %q", a)
	}
	r.h.server.listenFailed("100.64.0.1:7177", errors.New("some other failure"))
	if a := r.alerts(); len(a) != 1 {
		t.Fatalf("an ordinary failure raised an alert: %q", a)
	}
}

// timingOut is a window nobody answers.
type timingOut struct {
	mu    sync.Mutex
	shown int
}

func (w *timingOut) Approve(context.Context, approve.Request) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.shown++
	return false, approve.ErrTimedOut
}

func TestUnansweredPairingWindowsCountTowardTheCooldown(t *testing.T) {
	w := &timingOut{}
	r := newRemote(t, "papaya", true, func(s *Server) { s.Approver = w })
	pair := proto.Request{Op: proto.OpPair, Reason: "pair"}
	for i := range maxPairingDenials {
		if resp, _ := r.ask(newKey(t), "me", pair); !resp.TimedOut {
			t.Fatalf("window %d: %+v", i, resp)
		}
	}
	resp, _ := r.ask(newKey(t), "me", pair)
	if !strings.Contains(resp.Error, "too many pairing windows") || w.shown != maxPairingDenials {
		t.Fatalf("after %d unanswered windows: %+v", w.shown, resp)
	}
}

func TestTheTerminalShowsTheCodeOnceTheHubSaysItIsPairing(t *testing.T) {
	r := newRemote(t, "papaya", true)
	key := newKey(t)
	pair := proto.Request{Op: proto.OpPair, Reason: "pair"}
	resp, code := r.ask(key, "me", pair)
	if shown := r.h.approver.dialogs(); !resp.Paired || code == "" || len(shown) != 1 || shown[0].Code != code {
		t.Fatalf("got %+v, code %q, windows %+v", resp, code, shown)
	}
	// Forgotten on the hub, but not on the machine: the hub still says so,
	// so the terminal still shows the code its window does.
	r.h.server.hubOp(proto.Request{Op: proto.OpHub, Hub: proto.HubForget, Host: "papaya"})
	resp, code = r.ask(key, "me", resolveReq("acme", sec("A", "op://v/a/f")))
	if shown := r.h.approver.dialogs(); resp.Values == nil || code == "" || len(shown) != 3 || shown[1].Code != code {
		t.Fatalf("after forget: %+v, code %q, windows %+v", resp, code, shown)
	}
}

func TestARequestWithoutItsPartOfThePairingCodeIsRefused(t *testing.T) {
	r := newRemote(t, "papaya", true)
	s, err := r.open(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.conn.Close() }()
	req := resolveReq("acme", sec("A", "op://v/a/f"))
	req.User = "me"
	if err := json.NewEncoder(s.conn).Encode(req); err != nil {
		t.Fatal(err)
	}
	if resp, err := readAnswer(s.rd); err != nil || !strings.Contains(resp.Error, "part of the pairing code") || len(r.h.approver.dialogs()) != 0 {
		t.Fatalf("got %+v, %v", resp, err)
	}
}

// failing is a window that never opens.
type failing struct{}

func (failing) Approve(context.Context, approve.Request) (bool, error) {
	return false, errors.New("no window")
}

// Once the code is revealed it costs a window, whatever the window then
// does, so a device can't learn codes for free.
func TestAWindowThatFailsAfterItsCodeIsRevealedStillCounts(t *testing.T) {
	r := newRemote(t, "papaya", true, func(s *Server) { s.Approver = failing{} })
	pair := proto.Request{Op: proto.OpPair, Reason: "pair"}
	for i := range maxPairingDenials {
		if resp, code := r.ask(newKey(t), "me", pair); code == "" || !strings.Contains(resp.Error, "no window") {
			t.Fatalf("window %d: %+v, code %q", i, resp, code)
		}
	}
	if resp, code := r.ask(newKey(t), "me", pair); !strings.Contains(resp.Error, "too many pairing windows") || code != "" {
		t.Fatalf("got %+v, code %q", resp, code)
	}
}
