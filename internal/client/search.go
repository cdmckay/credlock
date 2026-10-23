package client

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cdmckay/credlock/internal/approve"
	"github.com/cdmckay/credlock/internal/platform"
	"github.com/cdmckay/credlock/internal/proto"
)

// SearchArgs is a parsed `credlock search` command line.
type SearchArgs struct {
	Reason  string
	Account string
	Term    string
}

// ParseSearch reads `--reason TEXT [--account NAME] [--] TERM...`. The words of
// the term are joined with spaces. A reason is required: the person sees what
// is being looked for, and why, before deciding.
func ParseSearch(args []string) (SearchArgs, error) {
	var s SearchArgs
	var words []string
	for len(args) > 0 {
		a := args[0]
		name, value, inline := strings.Cut(a, "=")
		switch {
		case a == "--":
			words = append(words, args[1:]...)
			args = nil
			continue
		case name == "--reason" || name == "--account":
			args = args[1:]
			if !inline {
				if len(args) == 0 {
					return s, fmt.Errorf("%s needs a value", a)
				}
				value, args = args[0], args[1:]
			}
			if name == "--reason" {
				s.Reason = value
			} else {
				s.Account = value
			}
			continue
		case strings.HasPrefix(a, "-"):
			return s, fmt.Errorf("unknown flag %s: credlock search takes --reason and --account, then what to search for (see 'credlock help')", a)
		}
		words = append(words, a)
		args = args[1:]
	}
	s.Term = strings.Join(words, " ")
	if strings.TrimSpace(s.Reason) == "" {
		return s, errors.New("credlock search needs --reason, saying what you are looking for and why: the person sees it before deciding. " +
			`For example: credlock search --reason "listing my open pull requests needs a GitHub token" github`)
	}
	if s.Term == "" {
		return s, errors.New("nothing to search for: credlock search --reason TEXT [--account ACCOUNT] TERM, where TERM is part of an item's title")
	}
	if err := approve.CheckSearch(s.Term); err != nil {
		return s, err
	}
	if s.Account == "" {
		s.Account = defaultAccount()
	}
	return s, nil
}

// Search is `credlock search`: it asks the person, then prints the items
// whose titles contain the term, with each one's reference and field names.
// Never a value.
func Search(args []string) int {
	s, err := ParseSearch(args)
	if err != nil {
		return fail(err)
	}
	if !platform.HasHelper {
		return fail(errors.New("credlock search works only on the Mac with 1Password for now, not through a hub. " +
			"Ask the person for the reference you need"))
	}
	account, label, err := ResolveAccount(s.Account, Accounts())
	if err != nil {
		return fail(err)
	}
	cwd, _ := os.Getwd()
	resp, err := Call(proto.Request{
		Op:           proto.OpSearch,
		Account:      account,
		AccountLabel: label,
		Reason:       s.Reason,
		Cwd:          cwd,
		Search:       s.Term,
	}, true)
	switch {
	case err != nil && strings.HasPrefix(err.Error(), "unknown op"):
		return fail(errors.New("the helper running now is from an older credlock, which can't search. " +
			"credlock stop ends it, forgetting every approval; the next credlock command starts this version's"))
	case err != nil:
		return fail(err)
	case resp.TimedOut:
		fmt.Fprintf(os.Stderr, "credlock: nobody answered the approval dialog within %s, which counts as a denial. "+
			"Ask the person to watch for it, then search again.\n", approvalWindow)
		return ExitDenied
	case resp.Denied:
		fmt.Fprintln(os.Stderr, "credlock: the search was denied in the approval dialog. Don't retry it: ask the person why, or what to do instead.")
		return ExitDenied
	case resp.Found == nil:
		return fail(errors.New("the helper answered the search without its results"))
	}
	if err := PrintFound(os.Stdout, *resp.Found, s.Term, firstNonEmpty(label, account)); err != nil {
		return fail(err)
	}
	return 0
}

// PrintFound writes a search's answer for whoever asked, often an agent:
// each item's reference, ready for a field to be added, and its fields.
func PrintFound(w io.Writer, f proto.Found, term, account string) error {
	var b strings.Builder
	switch len(f.Items) {
	case 0:
		fmt.Fprintf(&b, "No item titles in %s contain %q.\n", account, term)
	case 1:
		fmt.Fprintf(&b, "1 item in %s has %q in its title (names only, never values):\n", account, term)
	default:
		fmt.Fprintf(&b, "%d items in %s have %q in their titles, best match first (names only, never values):\n", len(f.Items), account, term)
	}
	for _, it := range f.Items {
		fmt.Fprintf(&b, "\n  %s\n", it.Ref)
		if it.Ref != "op://"+it.Vault+"/"+it.Title {
			// An ID stands in for a title a reference can't carry: say which.
			fmt.Fprintf(&b, "    title: %q, in vault %q\n", it.Title, it.Vault)
		}
		switch {
		case it.Fields != "":
			fmt.Fprintf(&b, "    fields: %s\n", it.Fields)
		case it.Why != "":
			fmt.Fprintf(&b, "    %s\n", it.Why)
		}
	}
	if len(f.Items) > 0 {
		fmt.Fprintf(&b, "\nAdd a field to a reference to use it, such as %s/FIELD, with credlock run.\n", f.Items[0].Ref)
	}
	if f.More > 0 {
		fmt.Fprintf(&b, "And %d more match: search for something narrower to see them.\n", f.More)
	}
	for _, u := range f.Unread {
		fmt.Fprintf(&b, "Couldn't search vault %s.\n", u)
	}
	if f.Closed > 0 {
		fmt.Fprintf(&b, "Skipped %d vaults this account can see but not read items in.\n", f.Closed)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
