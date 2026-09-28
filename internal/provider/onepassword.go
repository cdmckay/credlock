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

	// connect makes one account's client. The 1Password SDK, unless a test
	// swaps in a fake.
	connect func(ctx context.Context, account, version string) (resolver, error)

	mu      sync.Mutex
	clients map[string]resolver
}

// resolver is what credlock asks of one account: the secrets, and the names of
// its vaults, for explaining a vault that isn't there.
type resolver interface {
	ResolveAll(ctx context.Context, refs []string) (onepassword.ResolveAllResponse, error)
	VaultTitles(ctx context.Context) ([]string, error)
}

type sdkClient struct{ c *onepassword.Client }

func (s sdkClient) ResolveAll(ctx context.Context, refs []string) (onepassword.ResolveAllResponse, error) {
	return s.c.Secrets().ResolveAll(ctx, refs)
}

func (s sdkClient) VaultTitles(ctx context.Context) ([]string, error) {
	vaults, err := s.c.Vaults().List(ctx)
	if err != nil {
		return nil, err
	}
	titles := make([]string, len(vaults))
	for i, v := range vaults {
		titles[i] = v.Title
	}
	return titles, nil
}

func connectSDK(ctx context.Context, account, version string) (resolver, error) {
	c, err := onepassword.NewClient(ctx,
		onepassword.WithDesktopAppIntegration(account),
		onepassword.WithIntegrationInfo("credlock", version),
	)
	if err != nil {
		return nil, err
	}
	return sdkClient{c}, nil
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
type unresolved struct {
	account string
	refs    []string
	vaults  []string // the account's vault names, when a vault was not found
}

func (e *unresolved) Error() string {
	msg := fmt.Sprintf("1Password account %s could not resolve %s", e.account, strings.Join(e.refs, "; "))
	if len(e.vaults) > 0 {
		quoted := make([]string, len(e.vaults))
		for i, v := range e.vaults {
			quoted[i] = fmt.Sprintf("%q", v)
		}
		msg += fmt.Sprintf(". The vaults in this account are %s. If yours isn't among them, it is in another account: check --account", strings.Join(quoted, ", "))
	}
	return msg
}

// connectError explains a failure to get a client for account.
func connectError(account string, err error) error {
	if strings.Contains(err.Error(), "Denied authorization") {
		return fmt.Errorf("1Password did not authorize credlock for account %s: the approval was declined in 1Password, "+
			"or that account's SDK integration is off (1Password > Settings > Developer > Integrate with the 1Password SDKs > "+
			"Integrate with other apps). Ask the person which, then run the command again: %w", account, err)
	}
	return fmt.Errorf("connecting to the 1Password app for account %s: %w. Check that 1Password is running and unlocked, and that "+
		"Settings > Developer > Integrate with other apps is on", account, err)
}

func (p *OnePassword) resolveAll(ctx context.Context, account string, refs []string) (map[string]string, error) {
	client, err := p.client(ctx, account)
	if err != nil {
		return nil, connectError(account, err)
	}
	resp, err := client.ResolveAll(ctx, refs)
	if err != nil {
		return nil, fmt.Errorf("1Password: %w", err)
	}
	values := make(map[string]string, len(refs))
	var failed []string
	var vaultMissing bool
	for _, ref := range refs {
		r, ok := resp.IndividualResponses[ref]
		switch {
		case !ok || (r.Content == nil && r.Error == nil):
			failed = append(failed, ref+" (no answer)")
		case r.Error != nil:
			vaultMissing = vaultMissing || r.Error.Type == onepassword.ResolveReferenceErrorTypeVariantVaultNotFound
			failed = append(failed, fmt.Sprintf("%s (%s)", ref, explain(ref, r.Error.Type)))
		default:
			values[ref] = r.Content.Secret
		}
	}
	if len(failed) > 0 {
		e := &unresolved{account: account, refs: failed}
		if vaultMissing {
			// Same client, same approval: listing names costs no extra prompt.
			e.vaults, _ = client.VaultTitles(ctx)
		}
		return nil, e
	}
	return values, nil
}

// explain turns the SDK's error types into what to check next.
func explain(ref string, why onepassword.ResolveReferenceErrorTypes) string {
	switch {
	case why == onepassword.ResolveReferenceErrorTypeVariantVaultNotFound && strings.HasPrefix(ref, "op://Private/"):
		// The names of the built-in vault cross over between the op CLI and
		// the SDK: op takes "Private" for a personal account's, which the SDK
		// calls "Personal"; in 1Password Business it is "Private" to the SDK.
		return `vaultNotFound: in a personal account the SDK calls the built-in vault "Personal" (the op CLI's "Private" alias doesn't work here); "Private" is only right in 1Password Business`
	case why == onepassword.ResolveReferenceErrorTypeVariantVaultNotFound && strings.HasPrefix(ref, "op://Employee/"):
		return `vaultNotFound: in 1Password Business the SDK calls the vault the app shows as "Employee" "Private"; try op://Private/…`
	case why == onepassword.ResolveReferenceErrorTypeVariantVaultNotFound:
		return "vaultNotFound: no such vault in this account; check --account first, then the vault name"
	case why == onepassword.ResolveReferenceErrorTypeVariantItemNotFound:
		return "itemNotFound: no such item in that vault"
	case why == onepassword.ResolveReferenceErrorTypeVariantFieldNotFound:
		return "fieldNotFound: the item has no such field"
	default:
		return string(why)
	}
}

func (p *OnePassword) client(ctx context.Context, account string) (resolver, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[account]; ok {
		return c, nil
	}
	connect := p.connect
	if connect == nil {
		connect = connectSDK
	}
	c, err := connect(ctx, account, p.Version)
	if err != nil {
		return nil, err
	}
	if p.clients == nil {
		p.clients = map[string]resolver{}
	}
	p.clients[account] = c
	return c, nil
}

func (p *OnePassword) forget(account string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.clients, account)
}
