// Package approve asks the person at the keyboard whether a request may have
// the secrets it names.
package approve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ncruces/zenity"

	"github.com/cdmckay/credlock/internal/proto"
)

// Request is everything the person is shown before deciding.
type Request struct {
	Reason    string
	Command   []string
	Cwd       string
	Requester string // e.g. "bash (pid 4242)", from the kernel
	Account   string
	Secrets   []proto.Secret // the ones not yet approved
	Approved  int            // how many others the request also uses, already approved
	Window    time.Duration  // an approval lasts this long after its last use...
	Cap       time.Duration  // ...and never longer than this
}

// Approver decides a request. false with a nil error means "denied";
// ErrTimedOut means nobody answered, which also counts as a denial.
type Approver interface {
	Approve(ctx context.Context, r Request) (bool, error)
}

// ErrTimedOut is a dialog nobody answered in time.
var ErrTimedOut = errors.New("nobody answered the approval dialog in time")

// Dialog asks through the zenity library's plain dialog: zenity or kdialog on
// Linux, the system alert on macOS. It is the approver where credlock has no
// window of its own (see Default). Deny is the default, and a dialog nobody
// answers within Timeout counts as a denial.
type Dialog struct {
	Timeout time.Duration
}

// Approve shows the request and waits for Allow or Deny.
func (d Dialog) Approve(ctx context.Context, r Request) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, d.Timeout)
	defer cancel()
	err := zenity.Question(Body(r),
		zenity.Title(Title(r)),
		zenity.OKLabel("Allow"),
		zenity.CancelLabel("Deny"),
		zenity.DefaultCancel(),
		zenity.Context(ctx),
	)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, zenity.ErrCanceled):
		return false, nil
	case ctx.Err() != nil:
		return false, ErrTimedOut
	default:
		return false, err
	}
}

// Title is the dialog's headline.
func Title(r Request) string {
	if len(r.Secrets) == 1 {
		return "credlock: allow 1 secret?"
	}
	return fmt.Sprintf("credlock: allow %d secrets?", len(r.Secrets))
}

// Body is the dialog's text. Everything in it except Requester came from the
// client, so each field is flattened onto one line and cut to length: a reason
// with newlines in it must not be able to draw fake lines into the dialog.
func Body(r Request) string {
	var b strings.Builder
	reason := clean(r.Reason, 200)
	if reason == "" {
		reason = "(none given)"
	}
	fmt.Fprintf(&b, "Reason:  %s\n", reason)
	fmt.Fprintf(&b, "Command:  %s\n", clean(quote(r.Command), 300))
	fmt.Fprintf(&b, "Directory:  %s\n", clean(tildify(r.Cwd), 200))
	fmt.Fprintf(&b, "Requested by:  %s\n", clean(r.Requester, 100))
	if r.Account != "" {
		fmt.Fprintf(&b, "1Password account:  %s\n", clean(r.Account, 100))
	}
	b.WriteString("\n")
	for _, s := range r.Secrets {
		fmt.Fprintf(&b, "%s  →  %s\n", clean(s.Name, 80), clean(s.Ref, 200))
	}
	if r.Approved > 0 {
		fmt.Fprintf(&b, "(plus %d already approved)\n", r.Approved)
	}
	fmt.Fprintf(&b, "\nApproved secrets stay available for %s after their last use, and %s at most.",
		human(r.Window), human(r.Cap))
	return b.String()
}

// clean flattens control characters, newlines included, to spaces and cuts s
// to at most n runes.
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return ' '
		}
		return r
	}, s)
	if runes := []rune(s); len(runes) > n {
		return string(runes[:n-1]) + "…"
	}
	return s
}

// quote renders argv the way a shell would need it typed.
func quote(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		if a == "" || strings.ContainsAny(a, " \t'\"\\$`!*?[]{}()<>|&;#~") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		parts[i] = a
	}
	return strings.Join(parts, " ")
}

func tildify(path string) string {
	if home, err := os.UserHomeDir(); err == nil && home != "" && strings.HasPrefix(path, home) {
		return "~" + strings.TrimPrefix(path, home)
	}
	return path
}

// human renders the lifetimes the dialog quotes: "1 hour", "24 hours", "90 minutes".
func human(d time.Duration) string {
	switch {
	case d%time.Hour == 0 && d == time.Hour:
		return "1 hour"
	case d%time.Hour == 0:
		return fmt.Sprintf("%d hours", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%d minutes", d/time.Minute)
	default:
		return d.String()
	}
}

// Clean flattens control characters in client text and cuts it to n runes,
// for anything else that shows it, such as the menu bar's access log.
func Clean(s string, n int) string { return clean(s, n) }

// CommandLine renders argv as a shell would need it typed, flattened and cut
// to n runes.
func CommandLine(argv []string, n int) string { return clean(quote(argv), n) }
