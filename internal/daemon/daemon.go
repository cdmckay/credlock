// Package daemon is credlock's helper: a per-user process that holds approved
// secrets in memory, asks before handing out anything new, and exits after an
// idle hour. The client starts it on first use.
package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cdmckay/credlock/internal/approve"
	"github.com/cdmckay/credlock/internal/platform"
	"github.com/cdmckay/credlock/internal/proto"
	"github.com/cdmckay/credlock/internal/provider"
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

	maxRequest = 1 << 20
)

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

	mu       sync.Mutex // guards cache and lastUsed
	cache    *cache
	lastUsed time.Time

	asking sync.Mutex // one approval at a time, so one request can't hide behind another
}

// NewServer makes a server with credlock's lifetimes.
func NewServer(p provider.Provider, a approve.Approver) *Server {
	return &Server{
		Provider: p,
		Approver: a,
		Now:      time.Now,
		Peer:     platform.PeerOf,
		Exit:     func() { os.Exit(0) },
		cache:    newCache(Window, Cap),
		lastUsed: time.Now(),
	}
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
	s := NewServer(&provider.OnePassword{Version: version}, approve.Dialog{Timeout: ApprovalTimeout})
	s.Exit = func() { _ = os.Remove(path); os.Exit(0) }
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
func (s *Server) reap(ticks <-chan time.Time) {
	for range ticks {
		s.mu.Lock()
		now := s.Now()
		s.cache.sweep(now)
		idle := now.Sub(s.lastUsed) >= IdleExit
		s.mu.Unlock()
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
		reply(conn, s.resolve(context.Background(), req, peer))
	case proto.OpStatus:
		s.mu.Lock()
		entries := s.cache.list(s.Now())
		s.mu.Unlock()
		reply(conn, proto.Response{Entries: entries, PID: os.Getpid()})
	case proto.OpClear:
		s.mu.Lock()
		s.cache.clear()
		s.mu.Unlock()
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
func (s *Server) resolve(ctx context.Context, req proto.Request, peer platform.Peer) proto.Response {
	if len(req.Secrets) == 0 {
		return proto.Response{Error: "no secrets requested"}
	}
	for _, sec := range req.Secrets {
		if err := provider.Supported(sec.Ref); err != nil {
			return proto.Response{Error: err.Error()}
		}
	}

	values, missing := s.lookup(req)
	if len(missing) > 0 {
		// One dialog at a time. Look again once it is our turn: the request
		// ahead of us may have been approved for the same secrets.
		s.asking.Lock()
		defer s.asking.Unlock()
		values, missing = s.lookup(req)
	}
	if len(missing) > 0 {
		ok, err := s.Approver.Approve(ctx, approve.Request{
			Reason:    req.Reason,
			Command:   req.Command,
			Cwd:       req.Cwd,
			Requester: fmt.Sprintf("%s (pid %d)", peer.Name, peer.PID),
			Account:   req.Account,
			Secrets:   missing,
			Approved:  len(uniqueRefs(req.Secrets)) - len(uniqueRefs(missing)),
			Window:    Window,
			Cap:       Cap,
		})
		if err != nil {
			return proto.Response{Error: "showing the approval dialog: " + err.Error()}
		}
		if !ok {
			return proto.Response{Denied: true}
		}
		refs := uniqueRefs(missing)
		fetched, err := s.Provider.ResolveAll(ctx, req.Account, refs)
		if err != nil {
			return proto.Response{Error: err.Error()}
		}
		s.mu.Lock()
		now := s.Now()
		for _, ref := range refs {
			s.cache.put(key{req.Account, ref}, fetched[ref], now)
			values[ref] = fetched[ref]
		}
		s.mu.Unlock()
	}

	// Delivered: slide every secret this request used.
	s.mu.Lock()
	now := s.Now()
	for ref := range values {
		s.cache.touch(key{req.Account, ref}, now)
	}
	s.lastUsed = now
	s.mu.Unlock()
	return proto.Response{Values: values}
}

// lookup splits a request into what is already approved and what is not.
func (s *Server) lookup(req proto.Request) (map[string]string, []proto.Secret) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now()
	s.lastUsed = now
	values := map[string]string{}
	var missing []proto.Secret
	for _, sec := range req.Secrets {
		if v, ok := s.cache.peek(key{req.Account, sec.Ref}, now); ok {
			values[sec.Ref] = v
		} else {
			missing = append(missing, sec)
		}
	}
	return values, missing
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

func reply(conn net.Conn, resp proto.Response) {
	_ = json.NewEncoder(conn).Encode(resp)
}
