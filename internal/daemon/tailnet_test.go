package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdmckay/credlock/internal/approve"
	"github.com/cdmckay/credlock/internal/client"
	"github.com/cdmckay/credlock/internal/proto"
)

// remote is the hub's tailnet side, on loopback, with Tailscale's answer to
// "who is this?" faked as host.
type remote struct {
	t    *testing.T
	h    *harness
	addr string
}

func newRemote(t *testing.T, host string, configure ...func(*Server)) *remote {
	t.Helper()
	identify := func(s *Server) {
		s.Identify = func(net.Addr) (string, error) { return host, nil }
		s.Accounts = func() []client.Account {
			return []client.Account{{ID: "ACMEACCOUNTID", User: "ACMEUSER", Email: "me@acme.example", URL: "acme.1password.com"}}
		}
		s.Allow([]string{"Papaya"}) // matched without regard to case
	}
	h := newHarness(t, true, append([]func(*Server){identify}, configure...)...)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go h.server.serveRemote(ln)
	return &remote{t: t, h: h, addr: ln.Addr().String()}
}

func (r *remote) ask(req proto.Request) proto.Response {
	r.t.Helper()
	conn, err := net.Dial("tcp", r.addr)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		r.t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		r.t.Fatal(err)
	}
	var resp proto.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		r.t.Fatal(err)
	}
	return resp
}

func resolveReq(account string, secrets ...proto.Secret) proto.Request {
	return proto.Request{Op: proto.OpResolve, Account: account, Reason: "testing",
		Command: []string{"make"}, Cwd: "/srv", Secrets: secrets}
}

func TestARemoteMachineIsApprovedApartFromThisMac(t *testing.T) {
	r := newRemote(t, "papaya")
	a := sec("A", "op://v/a/f")

	resp := r.ask(resolveReq("acme", a))
	if resp.Error != "" || resp.Values[a.Ref] != "secret:"+a.Ref {
		t.Fatalf("remote: %+v", resp)
	}
	shown := r.h.approver.dialogs()
	if len(shown) != 1 || shown[0].Requester != "papaya, over Tailscale" || shown[0].Account != "acme.1password.com (me@acme.example)" {
		t.Fatalf("the window showed %+v", shown)
	}
	if got := r.h.provider.fetches(); len(got) != 1 {
		t.Fatalf("fetches: %v", got)
	}

	// The same secret, in the same account, on this Mac is a new approval:
	// papaya's isn't this Mac's.
	local, err := client.CallAt(r.h.sock, resolveReq("ACMEACCOUNTID", a), false)
	if err != nil || local.Values[a.Ref] == "" {
		t.Fatalf("local: %+v, %v", local, err)
	}
	if n := len(r.h.approver.dialogs()); n != 2 {
		t.Fatalf("this Mac used papaya's approval: %d windows", n)
	}

	// papaya again: from its own approval, with no window.
	if resp := r.ask(resolveReq("acme", a)); resp.Values[a.Ref] == "" {
		t.Fatalf("papaya again: %+v", resp)
	}
	if n := len(r.h.approver.dialogs()); n != 2 {
		t.Fatalf("papaya's second request opened a window: %d", n)
	}
}

func TestTheAccountIsResolvedOnTheHub(t *testing.T) {
	p := &recordAccount{}
	r := newRemote(t, "papaya", func(s *Server) { s.Provider = p })
	r.ask(resolveReq("me@acme.example", sec("A", "op://v/a/f")))
	if got := p.got(); got != "ACMEACCOUNTID" {
		t.Fatalf("the provider was asked for account %q", got)
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

func TestAMachineNotAllowedIsRefused(t *testing.T) {
	r := newRemote(t, "mango")
	resp := r.ask(resolveReq("acme", sec("A", "op://v/a/f")))
	if !strings.Contains(resp.Error, "mango is not in this hub's allow list") || len(r.h.approver.dialogs()) != 0 {
		t.Fatalf("got %+v", resp)
	}
}

func TestOnlyResolvingIsServedOverTheTailnet(t *testing.T) {
	r := newRemote(t, "papaya")
	for _, op := range []string{proto.OpStatus, proto.OpClear, proto.OpStop} {
		if resp := r.ask(proto.Request{Op: op}); !strings.Contains(resp.Error, "only resolves") {
			t.Errorf("%s: %+v", op, resp)
		}
	}
}

func TestACheckOnlyRequestNeverOpensAWindow(t *testing.T) {
	r := newRemote(t, "papaya")
	a := sec("A", "op://v/a/f")
	check := resolveReq("acme", a)
	check.NoPrompt = true
	if resp := r.ask(check); !resp.NotHeld || len(r.h.approver.dialogs()) != 0 {
		t.Fatalf("before approval: %+v", resp)
	}
	r.ask(resolveReq("acme", a))
	if resp := r.ask(check); resp.NotHeld || resp.Values[a.Ref] == "" {
		t.Fatalf("after approval: %+v", resp)
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
	r := newRemote(t, "papaya", func(s *Server) { s.Approver = w })
	conn, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(conn).Encode(resolveReq("acme", sec("A", "op://v/a/f"))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // the window is open
	_ = conn.Close()
	if !eventually(w.wasClosed) {
		t.Fatal("the window stayed open after the asker hung up")
	}
}
