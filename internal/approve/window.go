package approve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cdmckay/credlock/internal/proto"
)

// WindowCommand is the hidden subcommand that shows credlock's own approval
// window. The helper runs it as a child process: AppKit needs the main thread,
// and the helper's is busy serving.
const WindowCommand = "__approve"

// The window process's exit statuses. Allow is status 0 with "allow" on
// stdout; anything that is neither that nor one of these is a failure.
const (
	windowDenied   = 1
	windowTimedOut = 3
)

// View is the approval window's content, every string already cleaned and cut
// to length, so the window does nothing but lay it out.
type View struct {
	Title        string         `json:"title"`
	Subtitle     string         `json:"subtitle"`
	Question     string         `json:"question"`
	Reason       string         `json:"reason"`
	Command      string         `json:"command"`
	Directory    string         `json:"directory"`
	Requester    string         `json:"requester"`
	Account      string         `json:"account"`
	Lifetime     string         `json:"lifetime"`
	SecretsTitle string         `json:"secrets_title"`
	Secrets      []proto.Secret `json:"secrets"`
	Approved     string         `json:"approved,omitempty"`
	Footer       string         `json:"footer"`
	Timeout      int            `json:"timeout"` // seconds until it counts as Deny
}

// NewView lays out r for the window. Everything in it except Requester came
// from the client, so it gets the same flattening as Body: a reason with
// newlines in it must not be able to draw fake lines.
func NewView(r Request, timeout time.Duration) View {
	n := len(r.Secrets)
	noun := "secrets"
	if n == 1 {
		noun = "secret"
	}
	v := View{
		Title:        "Secret access request",
		Subtitle:     "credlock",
		Question:     fmt.Sprintf("Allow this command to use %d %s?", n, noun),
		Reason:       clean(r.Reason, 200),
		Command:      clean(quote(r.Command), 300),
		Directory:    clean(tildify(r.Cwd), 200),
		Requester:    clean(r.Requester, 100),
		Account:      clean(r.Account, 100),
		Lifetime:     fmt.Sprintf("%s after last use, %s at most", human(r.Window), human(r.Cap)),
		SecretsTitle: fmt.Sprintf("Requested %s (%d)", noun, n),
		Footer:       "Values go only to this command's environment, and are never printed.",
		Timeout:      int(timeout / time.Second),
	}
	if v.Reason == "" {
		v.Reason = "(none given)"
	}
	if v.Account == "" {
		v.Account = "(not given)"
	}
	for _, s := range r.Secrets {
		v.Secrets = append(v.Secrets, proto.Secret{Name: clean(s.Name, 80), Ref: clean(s.Ref, 200)})
	}
	if r.Approved > 0 {
		v.Approved = fmt.Sprintf("Plus %d already approved.", r.Approved)
	}
	return v
}

// Window asks through credlock's approval window. Deny is the default: Allow
// takes a mouse click, and a window nobody answers within Timeout counts as a
// denial. A window that fails or crashes never counts as Allow.
type Window struct {
	Timeout time.Duration

	// command starts the window process: credlock itself, unless a test swaps
	// in a fake.
	command func(ctx context.Context) (*exec.Cmd, error)
	// grace is how long past Timeout the helper waits before killing a window
	// that hasn't closed itself.
	grace time.Duration
}

// Approve shows r in a window and waits for Allow or Deny.
func (w Window) Approve(ctx context.Context, r Request) (bool, error) {
	in, err := json.Marshal(NewView(r, w.Timeout))
	if err != nil {
		return false, err
	}
	grace := w.grace
	if grace == 0 {
		grace = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, w.Timeout+grace)
	defer cancel()
	start := w.command
	if start == nil {
		start = selfCommand
	}
	cmd, err := start(ctx)
	if err != nil {
		return false, err
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdin = bytes.NewReader(in)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()

	var exit *exec.ExitError
	switch {
	case err == nil && stdout.String() == "allow\n":
		return true, nil
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return false, ErrTimedOut
	case ctx.Err() != nil:
		return false, ctx.Err()
	case errors.As(err, &exit) && exit.ExitCode() == windowDenied:
		return false, nil
	case errors.As(err, &exit) && exit.ExitCode() == windowTimedOut:
		return false, ErrTimedOut
	case err == nil:
		return false, errors.New("the approval window closed without an answer")
	default:
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = msg[:500] + "…"
		}
		if msg == "" {
			return false, fmt.Errorf("the approval window failed: %w", err)
		}
		return false, fmt.Errorf("the approval window failed: %w: %s", err, msg)
	}
}

func selfCommand(ctx context.Context) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("finding credlock's own binary for the approval window: %w", err)
	}
	return exec.CommandContext(ctx, self, WindowCommand), nil
}
