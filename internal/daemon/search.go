package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdmckay/credlock/internal/approve"
	"github.com/cdmckay/credlock/internal/menubar"
	"github.com/cdmckay/credlock/internal/proto"
)

// search answers a search of item titles, after asking. It names items and
// their fields, never a value, and keeps nothing: every search asks, so a
// later one can't run silently. Only this Mac's own callers get here: the
// tailnet listener only pairs and resolves.
func (s *Server) search(ctx context.Context, req proto.Request, from asker) proto.Response {
	if strings.TrimSpace(req.Reason) == "" {
		return proto.Response{Error: "a search needs a reason: pass --reason, saying what you are looking for and why. The person sees it before deciding"}
	}
	if err := approve.CheckSearch(req.Search); err != nil {
		return proto.Response{Error: err.Error()}
	}
	if req.Account == "" {
		return proto.Response{Error: "no 1Password account given: pass --account, or set CREDLOCK_ACCOUNT or OP_ACCOUNT"}
	}
	s.mu.Lock()
	s.lastUsed = s.Now()
	s.mu.Unlock()

	// One dialog at a time, as for secrets.
	s.asking.Lock()
	defer s.asking.Unlock()
	ok, err := s.Approver.Approve(ctx, approve.Request{
		Reason:    req.Reason,
		Cwd:       req.Cwd,
		Requester: from.requester,
		Account:   firstNonEmpty(req.AccountLabel, req.Account),
		Search:    req.Search,
	})
	switch {
	case errors.Is(err, approve.ErrTimedOut):
		return proto.Response{Denied: true, TimedOut: true}
	case ctx.Err() != nil:
		return proto.Response{Error: "the asker hung up before you answered"}
	case err != nil:
		return proto.Response{Error: "showing the approval dialog: " + err.Error()}
	case !ok:
		return proto.Response{Denied: true}
	}
	// Allowed: finish even if the asker has gone, as for secrets.
	found, err := s.Provider.Search(context.WithoutCancel(ctx), req.Account, req.Search)
	s.mu.Lock()
	now := s.Now()
	s.lastUsed = now
	// Only the term: a search hands no secret to any command, whatever else
	// the request carries.
	use := menubar.Use{Search: approve.Clean(req.Search, proto.MaxSearch)}
	if err != nil {
		use.Failed, use.Summary = true, "the search failed"
		s.logTold(req, from.origin, use, []string{err.Error()}, now)
	} else {
		use.Summary = summary(found)
		s.logTold(req, from.origin, use, told(found), now)
	}
	s.mu.Unlock()
	s.notify(true)
	if err != nil {
		return proto.Response{Error: err.Error()}
	}
	return proto.Response{Found: &found}
}

// logTold records in the access log what went back for a search, or for a
// request that failed after Allow, by name: use with its Told lines filled in
// from lines. What it was (a search's term, or a request's command and
// secret names) is the caller's to fill in, so a request can't pass for the
// other kind. The caller holds s.mu.
func (s *Server) logTold(req proto.Request, origin string, use menubar.Use, lines []string, now time.Time) {
	s.labels[req.Account] = firstNonEmpty(req.AccountLabel, req.Account)
	use.At = now.Format("15:04")
	use.Reason = approve.Clean(req.Reason, logReason)
	use.Origin = origin
	for _, l := range lines {
		for len(use.Told) < maxToldLines {
			head, rest := wrap(approve.Clean(l, 4000), toldWidth)
			use.Told = append(use.Told, head)
			if rest == "" {
				break
			}
			l = "    " + rest
		}
	}
	s.uses = append([]menubar.Use{use}, s.uses...)
	if len(s.uses) > maxUses {
		s.uses = s.uses[:maxUses]
	}
	s.told = now
}

// toldWidth is how wide, in characters, a line of what went back is in the
// menu, and maxToldLines how many lines one entry keeps.
const (
	toldWidth    = 100
	maxToldLines = 120
)

// wrap cuts s at a space before width characters, if it is longer.
func wrap(s string, width int) (head, rest string) {
	r := []rune(s)
	if len(r) <= width {
		return s, ""
	}
	cut := width
	for i := width; i > width/2; i-- {
		if r[i] == ' ' {
			cut = i
			break
		}
	}
	return strings.TrimRight(string(r[:cut]), " "), strings.TrimLeft(string(r[cut:]), " ")
}

// summary is a search's answer in a few words: "2 items", "20 items and 3
// more", or "nothing found".
func summary(f proto.Found) string {
	n := len(f.Items)
	noun := "items"
	if n == 1 {
		noun = "item"
	}
	switch {
	case n == 0:
		return "nothing found"
	case f.More > 0:
		return fmt.Sprintf("%d %s and %d more", n, noun, f.More)
	default:
		return fmt.Sprintf("%d %s", n, noun)
	}
}

// told is a search's answer as the access log shows it: each item's
// reference and its field names, then what wasn't named or couldn't be read.
func told(f proto.Found) []string {
	var lines []string
	for _, it := range f.Items {
		ref := it.Ref
		if ref != "op://"+it.Vault+"/"+it.Title {
			ref += fmt.Sprintf(" (%q)", it.Title) // an ID stands in for the title
		}
		switch {
		case it.Fields != "":
			lines = append(lines, ref+": "+it.Fields)
		case it.Why != "":
			lines = append(lines, ref+": "+it.Why)
		default:
			lines = append(lines, ref)
		}
	}
	if f.More > 0 {
		lines = append(lines, fmt.Sprintf("and %d more, not named", f.More))
	}
	for _, u := range f.Unread {
		lines = append(lines, "couldn't search vault "+u)
	}
	if f.Closed > 0 {
		lines = append(lines, fmt.Sprintf("skipped %d vaults it can see but not read items in", f.Closed))
	}
	if len(lines) == 0 {
		lines = append(lines, "no item titles matched")
	}
	return lines
}
