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
	// Origin is set for a request from another machine, and the window then
	// leads with OriginTitle and OriginNote in a card of their own. Nothing a
	// requester sends can produce that card: only the hub sets Origin.
	Origin      string `json:"origin,omitempty"`
	OriginTitle string `json:"origin_title,omitempty"`
	OriginNote  string `json:"origin_note,omitempty"`
	// OriginTone colours the card: "remote" for a paired machine, "pair" for
	// a first pairing.
	OriginTone string `json:"origin_tone,omitempty"`
	// Kind is "pair" for the pairing window, laid out unlike an approval so
	// it isn't answered by habit, with Code large and CodeNote under it. It
	// never shows secrets: those are asked about after, in an approval.
	Kind     string `json:"kind,omitempty"`
	Code     string `json:"code,omitempty"`
	CodeNote string `json:"code_note,omitempty"`
}

// NewView lays out r for the window. Nearly all of it came from the client,
// so all of it gets the same flattening as Body: a reason with newlines in it
// must not be able to draw fake lines. Only Origin is Tailscale's word, and
// only the window's origin card states anything as verified.
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
	if origin := clean(r.Origin, 60); origin != "" {
		user := clean(r.User, 40)
		code := clean(r.Code, 8)
		v.Origin = origin
		v.Subtitle = "credlock · another machine is asking"
		v.Title = "Secret request from " + origin
		v.Question = fmt.Sprintf("Allow %s's command to use %d %s?", origin, n, noun)
		v.Footer = fmt.Sprintf("Values go only to this command's environment on %s, and are never printed.", origin)
		v.OriginTone = "remote"
		v.OriginTitle = fmt.Sprintf("From %s, another machine on your tailnet", origin)
		v.OriginNote = fmt.Sprintf("Tailscale verified that this request comes from %s. The user, command, directory and reason are what %s reports. If you allow it, the values are sent to %s.", origin, origin, origin)
		if r.Pairing == "new" {
			v.Kind = "pair"
			v.Title = fmt.Sprintf("Pair a user on %s with this Mac?", origin)
			v.Subtitle = "credlock · pairing a machine"
			v.OriginNote = fmt.Sprintf("Tailscale verified that this comes from %s, which says the user is %s. Once paired, that user's key can ask this Mac for secrets, and each new one still needs your Allow.", origin, user)
			v.Code = code
			v.CodeNote = fmt.Sprintf("Pair only if %s's terminal shows this code", origin)
			v.Footer = "Pairing sends no secrets."
		}
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
