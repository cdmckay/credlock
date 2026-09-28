package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	onepassword "github.com/1password/onepassword-sdk-go"
)

// OnePassword resolves op:// references through the 1Password desktop app.
// The app asks you to approve this process (Touch ID or your password) the
// first time, and again once it has sat unused for ten minutes. There is one
// SDK client per account, made on first use.
type OnePassword struct {
	Version string

	mu      sync.Mutex
	clients map[string]*onepassword.Client
}

// ResolveAll fetches refs from account in a single SDK call.
func (p *OnePassword) ResolveAll(ctx context.Context, account string, refs []string) (map[string]string, error) {
	if account == "" {
		return nil, errors.New("no 1Password account given: pass --account, or set CREDLOCK_ACCOUNT or OP_ACCOUNT")
	}
	values, err := p.resolveAll(ctx, account, refs)
	var missing *unresolved
	if err != nil && !errors.As(err, &missing) {
		// The app may have ended this client's session (it idles out after ten
		// minutes, and ends when 1Password locks). Try once more with a new
		// client, which asks for approval again. Not for references that simply
		// don't resolve: a new client would only prompt again for nothing.
		p.forget(account)
		values, err = p.resolveAll(ctx, account, refs)
	}
	return values, err
}

// unresolved is 1Password answering, but not with a secret for every reference.
type unresolved struct{ refs []string }

func (e *unresolved) Error() string {
	return "1Password could not resolve " + strings.Join(e.refs, ", ")
}

func (p *OnePassword) resolveAll(ctx context.Context, account string, refs []string) (map[string]string, error) {
	client, err := p.client(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("connecting to the 1Password app: %w", err)
	}
	resp, err := client.Secrets().ResolveAll(ctx, refs)
	if err != nil {
		return nil, fmt.Errorf("1Password: %w", err)
	}
	values := make(map[string]string, len(refs))
	var failed []string
	for _, ref := range refs {
		r, ok := resp.IndividualResponses[ref]
		switch {
		case !ok || (r.Content == nil && r.Error == nil):
			failed = append(failed, ref+" (no answer)")
		case r.Error != nil:
			why := string(r.Error.Type)
			if strings.HasPrefix(ref, "op://Private/") && why == "vaultNotFound" {
				// The op CLI accepts "Private" as an alias for the built-in vault;
				// the SDK wants its real name, which in a personal account is
				// "Personal" (or its vault ID).
				why += `; the SDK has no "Private" alias, try op://Personal/…`
			}
			failed = append(failed, fmt.Sprintf("%s (%s)", ref, why))
		default:
			values[ref] = r.Content.Secret
		}
	}
	if len(failed) > 0 {
		return nil, &unresolved{refs: failed}
	}
	return values, nil
}

func (p *OnePassword) client(ctx context.Context, account string) (*onepassword.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[account]; ok {
		return c, nil
	}
	c, err := onepassword.NewClient(ctx,
		onepassword.WithDesktopAppIntegration(account),
		onepassword.WithIntegrationInfo("credlock", p.Version),
	)
	if err != nil {
		return nil, err
	}
	if p.clients == nil {
		p.clients = map[string]*onepassword.Client{}
	}
	p.clients[account] = c
	return c, nil
}

func (p *OnePassword) forget(account string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.clients, account)
}
