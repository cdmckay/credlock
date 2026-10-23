package provider

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/cdmckay/credlock/internal/proto"
)

// ResolverCommand is the hidden subcommand that resolves references for one
// 1Password account: `credlock __resolver ACCOUNT`.
const ResolverCommand = "__resolver"

// DefaultResolveTimeout is how long a resolver gets to answer. It covers the
// 1Password app's own approval, which waits for a person.
const DefaultResolveTimeout = 3 * time.Minute

// Isolated resolves each account in its own child process. The 1Password SDK
// connects to the desktop app once per process, for the first account it is
// given, and sends every later client's calls to that account
// (cdmckay/credlock#8). One process per account gives each account its own
// connection. It also means a resolver stuck on a locked app can be killed
// and replaced without the helper losing anything it holds.
type Isolated struct {
	Version string
	// Timeout is how long one resolve may take; DefaultResolveTimeout if zero.
	Timeout time.Duration

	// command starts an account's resolver: credlock itself, unless a test
	// swaps in a fake.
	command func(account string) *exec.Cmd

	mu       sync.Mutex
	children map[string]*childResolver
}

// resolveRequest asks a resolver for Refs, or, with Search set, for the items
// whose titles contain it.
type resolveRequest struct {
	ID     uint64   `json:"id"`
	Refs   []string `json:"refs,omitempty"`
	Search string   `json:"search,omitempty"`
}

type resolveResponse struct {
	ID     uint64            `json:"id"`
	Values map[string]string `json:"values,omitempty"`
	Found  *proto.Found      `json:"found,omitempty"`
	Error  string            `json:"error,omitempty"`
}

// childResolver is one account's running child.
type childResolver struct {
	account string
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	out     *bufio.Scanner
	next    uint64
	mu      sync.Mutex // one request at a time
}

// ResolveAll fetches refs from account through that account's resolver.
func (p *Isolated) ResolveAll(ctx context.Context, account string, refs []string) (map[string]string, error) {
	resp, err := p.ask(ctx, account, resolveRequest{Refs: refs})
	return resp.Values, err
}

// Search searches account through that account's resolver.
func (p *Isolated) Search(ctx context.Context, account, term string) (proto.Found, error) {
	resp, err := p.ask(ctx, account, resolveRequest{Search: term})
	if err != nil {
		return proto.Found{}, err
	}
	if resp.Found == nil {
		return proto.Found{}, fmt.Errorf("the resolver for account %s answered a search without its results", account)
	}
	return *resp.Found, nil
}

// ask sends req to account's resolver and waits, at most Timeout, for its
// answer.
func (p *Isolated) ask(ctx context.Context, account string, req resolveRequest) (resolveResponse, error) {
	if account == "" {
		return resolveResponse{}, errors.New("no 1Password account given: pass --account, or set CREDLOCK_ACCOUNT or OP_ACCOUNT")
	}
	r, err := p.child(account)
	if err != nil {
		return resolveResponse{}, err
	}
	timeout := p.Timeout
	if timeout == 0 {
		timeout = DefaultResolveTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := r.call(ctx, req)
	if err != nil && !errors.As(err, new(*remoteError)) {
		// The child is gone, broken or stuck: replace it next time.
		p.drop(r)
	}
	return resp, err
}

func (p *Isolated) child(account string) (*childResolver, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r, ok := p.children[account]; ok {
		return r, nil
	}
	start := p.command
	if start == nil {
		start = p.selfCommand
	}
	cmd := start(account)
	if cmd == nil {
		return nil, errors.New("finding credlock's own binary to resolve with")
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting the resolver for account %s: %w", account, err)
	}
	out := bufio.NewScanner(stdout)
	out.Buffer(make([]byte, 64<<10), maxResolverLine)
	r := &childResolver{account: account, cmd: cmd, stdin: stdin, out: out}
	if p.children == nil {
		p.children = map[string]*childResolver{}
	}
	p.children[account] = r
	return r, nil
}

// drop kills r and forgets it, if it is still the account's resolver.
func (p *Isolated) drop(r *childResolver) {
	p.mu.Lock()
	if p.children[r.account] == r {
		delete(p.children, r.account)
	}
	p.mu.Unlock()
	_ = r.stdin.Close()
	if r.cmd.Process != nil {
		_ = r.cmd.Process.Kill()
	}
	go func() { _ = r.cmd.Wait() }()
}

func (p *Isolated) selfCommand(account string) *exec.Cmd {
	self, err := os.Executable()
	if err != nil {
		return nil
	}
	cmd := exec.Command(self, ResolverCommand, account)
	cmd.Dir = "/"
	return cmd
}

// remoteError is a failure the resolver reported, such as a reference that
// doesn't exist. The resolver itself is fine.
type remoteError struct{ msg string }

func (e *remoteError) Error() string { return e.msg }

func (r *childResolver) call(ctx context.Context, req resolveRequest) (resolveResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next++
	id := r.next
	req.ID = id
	line, err := json.Marshal(req)
	if err != nil {
		return resolveResponse{}, err
	}

	type result struct {
		resp resolveResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		if _, err := r.stdin.Write(append(line, '\n')); err != nil {
			done <- result{err: err}
			return
		}
		if !r.out.Scan() {
			err := r.out.Err()
			if err == nil {
				err = io.EOF
			}
			done <- result{err: err}
			return
		}
		var resp resolveResponse
		err := json.Unmarshal(r.out.Bytes(), &resp)
		done <- result{resp: resp, err: err}
	}()

	select {
	case <-ctx.Done():
		return resolveResponse{}, fmt.Errorf("1Password didn't answer for account %s in time: is the app locked, or waiting for you to approve credlock?", r.account)
	case res := <-done:
		switch {
		case res.err != nil:
			return resolveResponse{}, fmt.Errorf("the resolver for account %s stopped: %w", r.account, res.err)
		case res.resp.ID != id:
			return resolveResponse{}, fmt.Errorf("the resolver for account %s answered request %d, not %d", r.account, res.resp.ID, id)
		case res.resp.Error != "":
			return resolveResponse{}, &remoteError{res.resp.Error}
		}
		return res.resp, nil
	}
}

// maxResolverLine bounds one answer from a resolver: every value of one
// request, as JSON.
const maxResolverLine = 16 << 20

// ResolverMain is `credlock __resolver ACCOUNT`: it resolves each request read
// from stdin against that one account, through the 1Password SDK, and writes
// each answer to stdout. It exits when stdin closes, which is when the helper
// does.
func ResolverMain(args []string, version string, stdin io.Reader, stdout io.Writer) int {
	if len(args) != 1 || args[0] == "" {
		fmt.Fprintln(os.Stderr, "credlock: the resolver needs exactly one account")
		return 2
	}
	return serveResolver(&OnePassword{Version: version}, args[0], stdin, stdout)
}

func serveResolver(p Provider, account string, stdin io.Reader, stdout io.Writer) int {
	in := bufio.NewScanner(stdin)
	in.Buffer(make([]byte, 64<<10), 1<<20)
	enc := json.NewEncoder(stdout)
	for in.Scan() {
		var req resolveRequest
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			_ = enc.Encode(resolveResponse{Error: "bad request: " + err.Error()})
			continue
		}
		resp := resolveResponse{ID: req.ID}
		var err error
		if req.Search != "" {
			var found proto.Found
			found, err = p.Search(context.Background(), account, req.Search)
			resp.Found = &found
		} else {
			resp.Values, err = p.ResolveAll(context.Background(), account, req.Refs)
		}
		if err != nil {
			resp = resolveResponse{ID: req.ID, Error: err.Error()}
		}
		if err := enc.Encode(resp); err != nil {
			return 1
		}
	}
	return 0
}
