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

	"github.com/cdmckay/credlock/internal/proto"
)

// Request is everything the person is shown before deciding.
type Request struct {
	Reason  string
	Command []string
	Cwd     string
	// Requester is who asked: e.g. "bash (pid 4242)", from the kernel, or
	// for another machine the user it reports, marked as its report.
	Requester string
	// Origin is the tailnet machine that asked, as Tailscale identified it;
	// empty for this Mac. User is the user it says asked. Those, its
	// command, directory and reason are its own claims.
	Origin, User string
	// Pairing is "new" for a machine user this hub hasn't paired with; the
	// pairing window's Pair button pairs it. Code is the four digits its
	// terminal shows for this pairing. A key that differs from the paired one
	// never reaches a window: the hub refuses it.
	Pairing, Code string
	Account       string
	// Search is set for a search of item titles, which names items and their
	// fields but asks for no secret. Secrets is then empty.
	Search   string
	Secrets  []proto.Secret // the ones not yet approved
	Approved int            // how many others the request also uses, already approved
	Window   time.Duration  // an approval lasts this long after its last use...
	Cap      time.Duration  // ...and never longer than this, which a request's TTL can bring in
}

// Approver decides a request. false with a nil error means "denied";
// ErrTimedOut means nobody answered, which also counts as a denial.
type Approver interface {
	Approve(ctx context.Context, r Request) (bool, error)
}

// ErrTimedOut is a window nobody answered in time.
var ErrTimedOut = errors.New("nobody answered the approval window in time")

// SearchNote says what a search sends back, for the window: names, never
// values, and nothing kept.
var SearchNote = fmt.Sprintf("If you allow it, it gets back the titles, references and field names of up to %d matching items. "+
	"Never a value. Nothing is kept: the next search asks again.", proto.MaxFound)

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

// lifetime says how long an approval lasts: "1 hour after last use, 24 hours
// at most", or just "15 minutes" when a TTL ends it.
func lifetime(window, cap time.Duration) string {
	if cap <= window {
		return human(cap)
	}
	return fmt.Sprintf("%s after last use, %s at most", human(window), human(cap))
}

// human renders the lifetimes the dialog quotes: "1 hour", "24 hours", "90 minutes".
func human(d time.Duration) string {
	switch {
	case d == time.Hour:
		return "1 hour"
	case d%time.Hour == 0:
		return fmt.Sprintf("%d hours", d/time.Hour)
	case d == time.Minute:
		return "1 minute"
	case d%time.Minute == 0:
		return fmt.Sprintf("%d minutes", d/time.Minute)
	default:
		return d.String()
	}
}

// CheckSearch refuses a search term the window couldn't show exactly as it
// would be searched: too short, too long to show whole, or holding
// characters the window flattens.
func CheckSearch(term string) error {
	n := len([]rune(term))
	switch {
	case strings.TrimSpace(term) != term:
		return errors.New("a search term can't start or end with a space")
	case n < proto.MinSearch:
		return fmt.Errorf("a search takes at least %d characters, so it can't list nearly everything", proto.MinSearch)
	case n > proto.MaxSearch:
		return fmt.Errorf("a search takes at most %d characters, which the approval window shows whole", proto.MaxSearch)
	case clean(term, proto.MaxSearch) != term:
		return errors.New("a search term can't hold control characters or line breaks")
	}
	return nil
}

// Clean flattens control characters in client text and cuts it to n runes,
// for anything else that shows it, such as the menu bar's access log.
func Clean(s string, n int) string { return clean(s, n) }

// CommandLine renders argv as a shell would need it typed, flattened and cut
// to n runes.
func CommandLine(argv []string, n int) string { return clean(quote(argv), n) }
