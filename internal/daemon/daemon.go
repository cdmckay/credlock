// Package daemon is credlock's helper: a per-user process that holds approved
// secrets in memory, asks before handing out anything new, and exits after an
// idle hour, unless hub mode is on. The client starts it on first use.
package daemon

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/cdmckay/credlock/internal/approve"
	"github.com/cdmckay/credlock/internal/client"
	"github.com/cdmckay/credlock/internal/menubar"
	"github.com/cdmckay/credlock/internal/platform"
	"github.com/cdmckay/credlock/internal/proto"
	"github.com/cdmckay/credlock/internal/provider"
	"github.com/cdmckay/credlock/internal/state"
)

const (
	// Window is how long an approval lasts after the secret's last use...
	Window = time.Hour
	// Cap is the most it lasts in all, however often it is used.
	Cap = 24 * time.Hour
	// IdleExit is how long the helper waits for a request before exiting.
	IdleExit = time.Hour
	// ApprovalTimeout is how long a dialog waits before counting as a denial.
	ApprovalTimeout = 2 * time.Minute
	// Sweep is how often expired secrets are dropped.
	Sweep = time.Minute

	// maxUses is how many deliveries the access log keeps.
	maxUses = 30

	maxRequest = 1 << 20
)

// Notifier is told what the helper holds and how it is used, for the menu bar
// icon: menubar.Bar.
type Notifier interface {
	Notify(menubar.Snapshot)
}

// Server answers client requests.
type Server struct {
	Provider provider.Provider
	Approver approve.Approver
	Now      func() time.Time
	// Peer reports who is on the other end of a connection; platform.PeerOf.
	Peer func(*net.UnixConn) (platform.Peer, error)
	// Exit ends the helper, for `stop` and the idle timeout. Main's removes
	// the socket and exits the process.
	Exit func()
	// Bar is told what is held and how it is used, after every change. Nil
	// for none.
	Bar Notifier
	// Identify names the tailnet host at a remote address: tailscale whois,
	// unless a test fakes it.
	Identify func(net.Addr) (string, error)
	// Accounts lists this Mac's 1Password accounts, to resolve the --account
	// a remote machine gives (it has no op of its own). The hub keeps the
	// first list it gets: op waits while 1Password is locked, and a request
	// the cache can answer mustn't.
	Accounts func() []client.Account

	// Tailnet reports this Mac's Tailscale state: tailscaleStatus, unless a
	// test fakes it.
	Tailnet func() (tailnetState, error)
	// SaveHub stores hub mode: state.Hub.Save, unless a test keeps it in
	// memory.
	SaveHub func(state.Hub) error
	// LoadKey gives the key the hub proves itself with: this Mac user's
	// credlock key (state.Key), unless a test makes one.
	LoadKey func() (ed25519.PrivateKey, error)

	// hub is hub mode: whether this Mac answers other machines on its tailnet,
	// and who is paired. A hub stays up instead of idling out.
	hub state.Hub
	// hubWake tells the tailnet listener to look again now, after hub mode
	// changes, instead of at its next tick.
	hubWake chan struct{}
	// listening is where the hub listens now, for `credlock hub status`.
	listening []string
	// suffix is the MagicDNS domain of the tailnet the hub serves, while it
	// serves one; callers must be in it. self is this Mac's own name there,
	// which the hub refuses: local requests use the local socket.
	suffix, self string
	// known is the account list, once Accounts has given one.
	known []client.Account
	// cert is LoadKey's key in a TLS certificate, once a machine has asked.
	cert *tls.Certificate
	// alerts are what the person should look at, newest first; the menu bar
	// key turns red until they are dismissed.
	alerts []menubar.Alert
	// denials counts pairing windows that ended without Pair, by machine, for
	// the cooldown.
	denials map[string]*pairingDenials

	mu       sync.Mutex // guards everything below
	cache    *cache
	lastUsed time.Time
	names    map[key]string    // the variable each secret was last delivered as
	labels   map[string]string // how to show each account
	uses     []menubar.Use     // the access log, newest first

	asking sync.Mutex // one approval at a time, so one request can't hide behind another
}

// NewServer makes a server with credlock's lifetimes.
func NewServer(p provider.Provider, a approve.Approver) *Server {
	s := &Server{
		Provider: p,
		Approver: a,
		Now:      time.Now,
		Peer:     platform.PeerOf,
		Exit:     func() { os.Exit(0) },
		cache:    newCache(Window, Cap),
		lastUsed: time.Now(),
		names:    map[key]string{},
		labels:   map[string]string{},
		Accounts: func() []client.Account { return client.AccountsWithin(5 * time.Second) },
		Tailnet:  tailscaleStatus,
		SaveHub:  state.Hub.Save,
		LoadKey:  state.Key,
		hubWake:  make(chan struct{}, 1),
	}
	s.Identify = s.identify
	return s
}

// Main runs the helper on the user's socket until it idles out or is stopped.
func Main(version string) error {
	path, err := platform.SocketPath()
	if err != nil {
		return err
	}
	unlock, err := lockNextTo(path)
	if err != nil {
		return err
	}
	if unlock == nil {
		return nil // another helper already serves this user
	}
	defer unlock()
	ln, err := listen(path)
	if err != nil {
		return err
	}
	// One resolver process per account: the 1Password SDK can only reach one
	// account per process (cdmckay/credlock#8).
	s := NewServer(&provider.Isolated{Version: version}, approve.Default(ApprovalTimeout))
	s.Exit = func() { _ = os.Remove(path); os.Exit(0) }
	if menubar.Supported {
		s.Bar = menubar.New(s.act)
	}
	// Hub mode, as `credlock hub on` left it. Unreadable state must not stop
	// the helper serving this Mac, so it is reported and hub mode left off.
	if hub, err := state.LoadHub(); err != nil {
		fmt.Fprintln(os.Stderr, "credlock helper: hub mode is off:", err)
	} else {
		s.hub = hub
	}
	go s.serveTailnet(time.Tick(time.Minute))
	go s.reap(time.Tick(Sweep))
	return s.Serve(ln)
}

// lockNextTo takes an exclusive lock beside the socket, so two helpers never
// serve one user. It returns nil, nil when another helper holds it.
func lockNextTo(sock string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(filepath.Dir(sock), "helper.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, nil
		}
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}

// listen replaces any stale socket and makes the new one owner-only.
func listen(path string) (*net.UnixListener, error) {
	_ = os.Remove(path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// Serve accepts connections until the listener closes.
func (s *Server) Serve(ln *net.UnixListener) error {
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

// reap drops expired secrets on every tick and exits the helper once it has
// gone IdleExit without a request. By then every secret has expired anyway.
// A hub stays up: other machines may ask at any time.
func (s *Server) reap(ticks <-chan time.Time) {
	for range ticks {
		s.mu.Lock()
		now := s.Now()
		s.cache.sweep(now)
		idle := now.Sub(s.lastUsed) >= IdleExit && !s.hub.Enabled
		s.mu.Unlock()
		s.notify(false) // times left, and anything that expired
		if idle {
			s.Exit()
			return
		}
	}
}

func (s *Server) handle(conn *net.UnixConn) {
	defer func() { _ = conn.Close() }()
	peer, err := s.Peer(conn)
	if err != nil || peer.UID != os.Getuid() {
		reply(conn, proto.Response{Error: "refused: not this user's helper"})
		return
	}
	var req proto.Request
	line, err := bufio.NewReader(io.LimitReader(conn, maxRequest)).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return
	}
	if err := json.Unmarshal(line, &req); err != nil {
		reply(conn, proto.Response{Error: "bad request: " + err.Error()})
		return
	}
	switch req.Op {
	case proto.OpResolve:
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go watchHangup(conn, cancel)
		reply(conn, s.resolve(ctx, req, asker{requester: fmt.Sprintf("this Mac: %s (pid %d)", peer.Name, peer.PID)}))
	case proto.OpHub:
		reply(conn, s.hubOp(req))
	case proto.OpStatus:
		s.mu.Lock()
		entries := s.cache.list(s.Now())
		s.mu.Unlock()
		reply(conn, proto.Response{Entries: entries, PID: os.Getpid()})
	case proto.OpClear:
		s.mu.Lock()
		s.cache.clear()
		s.mu.Unlock()
		s.notify(false)
		reply(conn, proto.Response{})
	case proto.OpStop:
		reply(conn, proto.Response{})
		s.Exit()
	default:
		reply(conn, proto.Response{Error: fmt.Sprintf("unknown op %q", req.Op)})
	}
}

// resolve answers a request from what is already approved, and asks about the
// rest before fetching it all from the provider in one call.
//
// from is who asks; ctx ends when they hang up, which closes a window still
// waiting for an answer.
func (s *Server) resolve(ctx context.Context, req proto.Request, from asker) proto.Response {
	origin := from.origin
	if len(req.Secrets) == 0 {
		return proto.Response{Error: "no secrets requested"}
	}
	for _, sec := range req.Secrets {
		if err := provider.Supported(sec.Ref); err != nil {
			return proto.Response{Error: err.Error()}
		}
	}

	values, missing := s.lookup(req, origin)
	if len(missing) > 0 && req.NoPrompt {
		return proto.Response{NotHeld: true}
	}
	asked := false
	if len(missing) > 0 {
		// One dialog at a time. Look again once it is our turn: the request
		// ahead of us may have been approved for the same secrets.
		s.asking.Lock()
		defer s.asking.Unlock()
		values, missing = s.lookup(req, origin)
	}
	if len(missing) > 0 {
		asked = true
		ok, err := s.Approver.Approve(ctx, approve.Request{
			Reason:    req.Reason,
			Command:   req.Command,
			Cwd:       req.Cwd,
			Requester: from.requester,
			Origin:    from.host,
			User:      from.user,
			Account:   firstNonEmpty(req.AccountLabel, req.Account),
			Secrets:   missing,
			Approved:  len(uniqueRefs(req.Secrets)) - len(uniqueRefs(missing)),
			Window:    Window,
			Cap:       Cap,
		})
		if errors.Is(err, approve.ErrTimedOut) {
			return proto.Response{Denied: true, TimedOut: true}
		}
		if ctx.Err() != nil {
			return proto.Response{Error: "the asker hung up before you answered"}
		}
		if err != nil {
			return proto.Response{Error: "showing the approval dialog: " + err.Error()}
		}
		if !ok {
			return proto.Response{Denied: true}
		}
		refs := uniqueRefs(missing)
		// Approved: finish the fetch even if the asker has gone, so the
		// approval isn't wasted, and an account's resolver isn't killed
		// halfway through.
		fetched, err := s.Provider.ResolveAll(context.WithoutCancel(ctx), req.Account, refs)
		if err != nil {
			return proto.Response{Error: err.Error()}
		}
		s.mu.Lock()
		now := s.Now()
		for _, ref := range refs {
			s.cache.put(key{origin, req.Account, ref}, fetched[ref], now)
			values[ref] = fetched[ref]
		}
		s.mu.Unlock()
	}

	// Delivered: slide every secret this request used, and log it.
	s.mu.Lock()
	now := s.Now()
	for ref := range values {
		s.cache.touch(key{origin, req.Account, ref}, now)
	}
	s.lastUsed = now
	s.logUse(req, origin, asked, now)
	s.mu.Unlock()
	s.notify(true)
	return proto.Response{Values: values}
}

// asker is who a request comes from.
type asker struct {
	origin    string // whose approvals: "" for this Mac, or "user@host"
	requester string // how the window names them
	host      string // another machine's Tailscale name; empty for this Mac
	user, key string // the user another machine reports, and the key it proved
	// code is set while the caller still has to pair, in a pairing window of
	// its own: the four digits its terminal shows once announce tells it the
	// window is open.
	code     string
	announce func()
}

// logUse records a delivery in the access log, and the names it used. The
// caller holds s.mu.
func (s *Server) logUse(req proto.Request, origin string, asked bool, now time.Time) {
	s.labels[req.Account] = firstNonEmpty(req.AccountLabel, req.Account)
	seen := map[string]bool{}
	var names []string
	for _, sec := range req.Secrets {
		s.names[key{origin, req.Account, sec.Ref}] = sec.Name
		if n := approve.Clean(sec.Name, 60); !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	use := menubar.Use{
		At:      now.Format("15:04"),
		Command: approve.CommandLine(req.Command, 80),
		Reason:  approve.Clean(req.Reason, 120),
		Names:   names,
		Cached:  !asked,
		Origin:  origin,
	}
	s.uses = append([]menubar.Use{use}, s.uses...)
	if len(s.uses) > maxUses {
		s.uses = s.uses[:maxUses]
	}
}

// notify tells the menu bar what is held now. read means secrets were just
// handed out. Never a value: only names, references and times.
func (s *Server) notify(read bool) {
	if s.Bar == nil {
		return
	}
	s.mu.Lock()
	now := s.Now()
	snap := menubar.Snapshot{Read: read, Uses: append([]menubar.Use(nil), s.uses...), Alerts: append([]menubar.Alert(nil), s.alerts...)}
	for _, e := range s.cache.list(now) {
		k := key{e.Origin, e.Account, e.Ref}
		snap.Held = append(snap.Held, menubar.Held{
			AccountID: e.Account,
			Account:   approve.Clean(firstNonEmpty(s.labels[e.Account], e.Account), 100),
			Origin:    e.Origin,
			Name:      approve.Clean(firstNonEmpty(s.names[k], e.Ref), 60),
			Ref:       approve.Clean(e.Ref, 200),
			Left:      left(time.Duration(e.ExpiresIn) * time.Second),
		})
	}
	s.mu.Unlock()
	sort.SliceStable(snap.Held, func(i, j int) bool {
		if snap.Held[i].Account != snap.Held[j].Account {
			return snap.Held[i].Account < snap.Held[j].Account
		}
		return snap.Held[i].Name < snap.Held[j].Name
	})
	s.Bar.Notify(snap)
}

// act does what was chosen in the menu bar. Each action takes access away.
func (s *Server) act(a menubar.Action) {
	switch a.Op {
	case menubar.OpForget:
		s.mu.Lock()
		s.cache.forget(key{a.Origin, a.AccountID, a.Ref})
		s.mu.Unlock()
		s.notify(false)
	case menubar.OpForgetAll:
		s.mu.Lock()
		s.cache.clear()
		s.mu.Unlock()
		s.notify(false)
	case menubar.OpStop:
		s.Exit()
	case menubar.OpDismiss:
		s.mu.Lock()
		s.alerts = nil
		s.mu.Unlock()
		s.notify(false)
	}
}

// left renders the time an approval has left: "48 min left".
func left(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute left"
	case d <= time.Hour:
		return fmt.Sprintf("%d min left", int((d+time.Minute-1)/time.Minute))
	default:
		return fmt.Sprintf("%d h %d min left", int(d/time.Hour), int(d%time.Hour/time.Minute))
	}
}

// lookup splits a request into what is already approved and what is not.
func (s *Server) lookup(req proto.Request, origin string) (map[string]string, []proto.Secret) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now()
	s.lastUsed = now
	values := map[string]string{}
	var missing []proto.Secret
	for _, sec := range req.Secrets {
		if v, ok := s.cache.peek(key{origin, req.Account, sec.Ref}, now); ok {
			values[sec.Ref] = v
		} else {
			missing = append(missing, sec)
		}
	}
	return values, missing
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func uniqueRefs(secrets []proto.Secret) []string {
	seen := map[string]bool{}
	var refs []string
	for _, sec := range secrets {
		if !seen[sec.Ref] {
			seen[sec.Ref] = true
			refs = append(refs, sec.Ref)
		}
	}
	return refs
}

// watchHangup cancels once the asker closes its connection. It sends nothing
// after its request, so any read returning means it has gone.
func watchHangup(conn net.Conn, cancel func()) {
	var b [1]byte
	_, _ = conn.Read(b[:])
	cancel()
}

func reply(conn net.Conn, resp proto.Response) {
	_ = json.NewEncoder(conn).Encode(resp)
}
