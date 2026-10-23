package provider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	onepassword "github.com/1password/onepassword-sdk-go"

	"github.com/cdmckay/credlock/internal/proto"
)

// Search names the items in account whose titles contain term, ignoring case,
// and each one's fields: the same names a fieldNotFound hint gives, never a
// value. It runs only after the person has allowed this search.
func (p *OnePassword) Search(ctx context.Context, account, term string) (proto.Found, error) {
	if account == "" {
		return proto.Found{}, errors.New("no 1Password account given: pass --account, or set CREDLOCK_ACCOUNT or OP_ACCOUNT")
	}
	if utf8.RuneCountInString(strings.TrimSpace(term)) < proto.MinSearch {
		return proto.Found{}, fmt.Errorf("a search takes at least %d characters", proto.MinSearch)
	}
	// The search is the whole answer, so it may take the time 1Password's own
	// approval needs, but must be done before the helper stops waiting.
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(DefaultResolveTimeout-hintMargin))
	defer cancel()
	found, err := p.search(ctx, account, term)
	if errors.Is(err, errVaults) && ctx.Err() == nil {
		// As for ResolveAll: the app may have ended this client's session.
		// Try once more with a new client, which asks for approval again.
		p.forget(account)
		found, err = p.search(ctx, account, term)
	}
	return found, err
}

// errVaults marks a search that couldn't list the account's vaults, the
// first thing it asks for.
var errVaults = errors.New("listing the vaults")

func (p *OnePassword) search(ctx context.Context, account, term string) (proto.Found, error) {
	client, err := p.client(ctx, account)
	if err != nil {
		return proto.Found{}, connectError(account, err)
	}
	vaults, err := bounded(ctx, client.Vaults)
	if err != nil {
		return proto.Found{}, fmt.Errorf("1Password account %s: %w: %w", account, errVaults, err)
	}
	var found proto.Found
	var matches []match
	for _, v := range vaults {
		items, err := bounded(ctx, func(ctx context.Context) ([]named, error) { return client.Items(ctx, v.ID) })
		switch {
		case err != nil && closed(err):
			found.Closed++
			continue
		case err != nil:
			found.Unread = append(found.Unread, fmt.Sprintf("%q: %v", v.Title, err))
			continue
		}
		for _, it := range items {
			if rank, ok := matchTitle(it.Title, term); ok {
				matches = append(matches, match{vault: v, item: it, rank: rank, vaults: vaults, items: items})
			}
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		a, b := matches[i], matches[j]
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		if at, bt := strings.ToLower(a.item.Title), strings.ToLower(b.item.Title); at != bt {
			return at < bt
		}
		return strings.ToLower(a.vault.Title) < strings.ToLower(b.vault.Title)
	})
	if len(matches) > proto.MaxFound {
		found.More = len(matches) - proto.MaxFound
		matches = matches[:proto.MaxFound]
	}
	for _, m := range matches {
		f := proto.FoundItem{
			Ref:   "op://" + refPart(m.vault, m.vaults) + "/" + refPart(m.item, m.items),
			Vault: m.vault.Title,
			Title: m.item.Title,
		}
		// Getting an item fetches its values too; Item keeps only names.
		item, err := bounded(ctx, func(ctx context.Context) (onepassword.Item, error) {
			return client.Item(ctx, m.vault.ID, m.item.ID)
		})
		switch {
		case err != nil:
			f.Why = "its fields couldn't be listed: " + err.Error()
		case len(item.Fields) == 0:
			f.Why = "it has no fields"
		default:
			f.Fields = fieldList(item)
		}
		found.Items = append(found.Items, f)
	}
	return found, nil
}

// closed says whether 1Password refused to list a vault's items because the
// account may see the vault but not what is in it. The SDK has no error type
// for that, only its message, seen live from a Business account's owner.
func closed(err error) bool {
	return strings.Contains(err.Error(), "do not have the right permissions")
}

// match is one item whose title matches, with the lists it came from, which
// decide whether its title can stand in a reference.
type match struct {
	vault, item   named
	rank          int
	vaults, items []named
}

// matchTitle says whether title contains term, ignoring case, and how well:
// 0 for the whole title, 1 for its start, 2 for anywhere in it. The item
// someone means is then never the one past the cap.
func matchTitle(title, term string) (int, bool) {
	t, s := strings.ToLower(title), strings.ToLower(strings.TrimSpace(term))
	switch {
	case t == s:
		return 0, true
	case strings.HasPrefix(t, s):
		return 1, true
	case strings.Contains(t, s):
		return 2, true
	}
	return 0, false
}

// refPart is how a reference names a vault or an item: by title when the
// title is one a reference can carry and nothing else in the list shares it,
// ignoring case, and by ID otherwise. 1Password references take letters,
// digits, spaces, '-', '_' and '.'; anything else needs the ID.
func refPart(n named, list []named) string {
	if n.Title == "" || strings.TrimSpace(n.Title) != n.Title {
		return n.ID
	}
	for _, r := range n.Title {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != ' ' && r != '-' && r != '_' && r != '.' {
			return n.ID
		}
	}
	for _, other := range list {
		if other.ID != n.ID && strings.EqualFold(other.Title, n.Title) {
			return n.ID
		}
	}
	return n.Title
}
