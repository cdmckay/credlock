package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/cdmckay/credlock/internal/approve"
	"github.com/cdmckay/credlock/internal/client"
	"github.com/cdmckay/credlock/internal/platform"
	"github.com/cdmckay/credlock/internal/proto"
)

// fakeProvider answers every reference with "secret:<ref>" and records calls.
type fakeProvider struct {
	mu    sync.Mutex
	calls [][]string
	err   error
}

func (p *fakeProvider) ResolveAll(_ context.Context, _ string, refs []string) (map[string]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, append([]string(nil), refs...))
	if p.err != nil {
		return nil, p.err
	}
	out := map[string]string{}
	for _, r := range refs {
		out[r] = "secret:" + r
	}
	return out, nil
}

// fakeApprover answers with allow, records what it was shown, and can be
// held open to test that dialogs are one at a time.
func (p *fakeProvider) fail(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.err = err
}

func (p *fakeProvider) fetches() [][]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([][]string(nil), p.calls...)
}

type fakeApprover struct {
	mu    sync.Mutex
	allow bool
	shown []approve.Request
	hold  chan struct{}
}

func (a *fakeApprover) Approve(_ context.Context, r approve.Request) (bool, error) {
	if a.hold != nil {
		<-a.hold
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.shown = append(a.shown, r)
	return a.allow, nil
}

func (a *fakeApprover) setAllow(allow bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.allow = allow
}

func (a *fakeApprover) dialogs() []approve.Request {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]approve.Request(nil), a.shown...)
}

type harness struct {
	t        *testing.T
	sock     string
	provider *fakeProvider
	approver *fakeApprover
	server   *Server
}

func newHarness(t *testing.T, allow bool, configure ...func(*Server)) *harness {
	t.Helper()
	// The harness talks to a helper over its socket, which needs the platform
	// layer to say who is calling. Only macOS has one; elsewhere credlock asks a
	// hub instead, and the helper never runs.
	if !platform.HasHelper {
		t.Skip("no credlock helper on this system")
	}
	// Unix socket paths are capped near 104 bytes on macOS, so keep it short.
	dir, err := os.MkdirTemp("/tmp", "cl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	ln, err := listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	h := &harness{t: t, sock: sock, provider: &fakeProvider{}, approver: &fakeApprover{allow: allow}}
	h.server = NewServer(h.provider, h.approver)
	for _, c := range configure {
		c(h.server) // before Serve, so no goroutine can see it change
	}
	go func() { _ = h.server.Serve(ln) }()
	return h
}

func (h *harness) resolve(secrets ...proto.Secret) (proto.Response, error) {
	return client.CallAt(h.sock, proto.Request{
		Op: proto.OpResolve, Account: "acct", Reason: "testing",
		Command: []string{"make", "deploy"}, Cwd: "/work", Secrets: secrets,
	}, false)
}

// ok resolves and fails the test on any error.
func (h *harness) ok(secrets ...proto.Secret) proto.Response {
	h.t.Helper()
	resp, err := h.resolve(secrets...)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func sec(name, ref string) proto.Secret { return proto.Secret{Name: name, Ref: ref} }

func TestAllowedSecretsAreFetchedTogetherThenServedFromMemory(t *testing.T) {
	h := newHarness(t, true)
	resp, err := h.resolve(sec("A", "op://v/a/f"), sec("B", "op://v/b/f"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"op://v/a/f": "secret:op://v/a/f", "op://v/b/f": "secret:op://v/b/f"}
	if !reflect.DeepEqual(resp.Values, want) {
		t.Fatalf("values %v, want %v", resp.Values, want)
	}
	if len(h.provider.fetches()) != 1 || len(h.provider.fetches()[0]) != 2 {
		t.Fatalf("want one fetch of both, got %v", h.provider.fetches())
	}

	if _, err := h.resolve(sec("A", "op://v/a/f"), sec("B", "op://v/b/f")); err != nil {
		t.Fatal(err)
	}
	if len(h.provider.fetches()) != 1 || len(h.approver.dialogs()) != 1 {
		t.Fatalf("second request asked again: %d fetches, %d dialogs", len(h.provider.fetches()), len(h.approver.dialogs()))
	}
}

func TestTheDialogShowsWhoAndWhyAndOnlyWhatIsNew(t *testing.T) {
	h := newHarness(t, true)
	h.ok(sec("A", "op://v/a/f"))
	h.ok(sec("A", "op://v/a/f"), sec("B", "op://v/b/f"))
	if len(h.approver.dialogs()) != 2 {
		t.Fatalf("want 2 dialogs, got %d", len(h.approver.dialogs()))
	}
	second := h.approver.dialogs()[1]
	if !reflect.DeepEqual(second.Secrets, []proto.Secret{sec("B", "op://v/b/f")}) || second.Approved != 1 {
		t.Fatalf("second dialog showed %v with %d already approved", second.Secrets, second.Approved)
	}
	if second.Reason != "testing" || second.Cwd != "/work" || !reflect.DeepEqual(second.Command, []string{"make", "deploy"}) {
		t.Fatalf("dialog lost the request's context: %+v", second)
	}
	if second.Requester == "" {
		t.Fatal("dialog does not say who asked")
	}
	if len(h.provider.fetches()) != 2 || !reflect.DeepEqual(h.provider.fetches()[1], []string{"op://v/b/f"}) {
		t.Fatalf("refetched an approved secret: %v", h.provider.fetches())
	}
}

func TestDeniedRequestsFetchAndCacheNothing(t *testing.T) {
	h := newHarness(t, false)
	resp, err := h.resolve(sec("A", "op://v/a/f"))
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Denied || resp.Values != nil {
		t.Fatalf("want a bare denial, got %+v", resp)
	}
	if len(h.provider.fetches()) != 0 {
		t.Fatal("fetched a secret nobody approved")
	}
	h.approver.setAllow(true)
	h.ok(sec("A", "op://v/a/f"))
	if len(h.approver.dialogs()) != 2 {
		t.Fatal("a denial was remembered as an approval")
	}
}

func TestAProviderFailureCachesNothing(t *testing.T) {
	h := newHarness(t, true)
	h.provider.fail(errors.New("1Password is locked"))
	if _, err := h.resolve(sec("A", "op://v/a/f")); err == nil || err.Error() != "1Password is locked" {
		t.Fatalf("want the provider's error, got %v", err)
	}
	h.provider.fail(nil)
	h.ok(sec("A", "op://v/a/f"))
	if len(h.approver.dialogs()) != 2 {
		t.Fatal("a failed fetch left something approved")
	}
}

func TestReferencesNoProviderHandlesAreRefusedBeforeAnyDialog(t *testing.T) {
	h := newHarness(t, true)
	if _, err := h.resolve(sec("A", "vault://nope")); err == nil {
		t.Fatal("accepted a reference with no provider")
	}
	if len(h.approver.dialogs()) != 0 {
		t.Fatal("asked about a reference it could never resolve")
	}
}

func TestOtherUsersAreRefused(t *testing.T) {
	h := newHarness(t, true, func(s *Server) {
		s.Peer = func(*net.UnixConn) (platform.Peer, error) {
			return platform.Peer{UID: os.Getuid() + 1, PID: 1, Name: "intruder"}, nil
		}
	})
	if _, err := h.resolve(sec("A", "op://v/a/f")); err == nil {
		t.Fatal("served another user")
	}
	if len(h.approver.dialogs()) != 0 || len(h.provider.fetches()) != 0 {
		t.Fatal("another user's request reached the dialog or the provider")
	}
}

func TestConcurrentRequestsForTheSameSecretAskOnce(t *testing.T) {
	h := newHarness(t, true)
	h.approver.hold = make(chan struct{})
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := h.resolve(sec("A", "op://v/a/f")); err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(h.approver.hold)
	wg.Wait()
	if len(h.approver.dialogs()) != 1 || len(h.provider.fetches()) != 1 {
		t.Fatalf("3 concurrent requests made %d dialogs and %d fetches", len(h.approver.dialogs()), len(h.provider.fetches()))
	}
}

func TestStatusListsWithoutValues(t *testing.T) {
	h := newHarness(t, true)
	h.ok(sec("A", "op://v/a/f"), sec("B", "op://v/b/f"))
	resp, err := client.CallAt(h.sock, proto.Request{Op: proto.OpStatus}, false)
	if err != nil {
		t.Fatal(err)
	}
	var refs []string
	for _, e := range resp.Entries {
		refs = append(refs, e.Ref)
	}
	sort.Strings(refs)
	if !reflect.DeepEqual(refs, []string{"op://v/a/f", "op://v/b/f"}) || resp.Values != nil {
		t.Fatalf("status: %+v", resp)
	}
}
