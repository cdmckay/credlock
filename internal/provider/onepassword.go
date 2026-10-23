package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

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

// resolver is what credlock asks of one account: the secrets, and what it
// needs to explain a reference that doesn't resolve. That is the names of the
// account's vaults and of one vault's items, and the fields of one item.
type resolver interface {
	ResolveAll(ctx context.Context, refs []string) (onepassword.ResolveAllResponse, error)
	Vaults(ctx context.Context) ([]named, error)
	Items(ctx context.Context, vaultID string) ([]named, error)
	// Item is one item's fields and sections, by ID, with their names and
	// types only.
	Item(ctx context.Context, vaultID, itemID string) (onepassword.Item, error)
}

// named is a vault or an item: what a reference may call it by.
type named struct{ ID, Title string }

type sdkClient struct{ c *onepassword.Client }

func (s sdkClient) ResolveAll(ctx context.Context, refs []string) (onepassword.ResolveAllResponse, error) {
	return s.c.Secrets().ResolveAll(ctx, refs)
}

func (s sdkClient) Vaults(ctx context.Context) ([]named, error) {
	vaults, err := s.c.Vaults().List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]named, len(vaults))
	for i, v := range vaults {
		out[i] = named{v.ID, v.Title}
	}
	return out, nil
}

func (s sdkClient) Items(ctx context.Context, vaultID string) ([]named, error) {
	items, err := s.c.Items().List(ctx, vaultID)
	if err != nil {
		return nil, err
	}
	out := make([]named, len(items))
	for i, it := range items {
		out[i] = named{it.ID, it.Title}
	}
	return out, nil
}

func (s sdkClient) Item(ctx context.Context, vaultID, itemID string) (onepassword.Item, error) {
	item, err := s.c.Items().Get(ctx, vaultID, itemID)
	return namesOnly(item), err
}

// namesOnly keeps an item's field and section names and types, and drops
// everything else, values first. The SDK has no way to get an item without
// its values, so they are dropped as soon as it hands them over.
func namesOnly(item onepassword.Item) onepassword.Item {
	out := onepassword.Item{Fields: make([]onepassword.ItemField, len(item.Fields)), Sections: item.Sections}
	for i, f := range item.Fields {
		out.Fields[i] = onepassword.ItemField{ID: f.ID, Title: f.Title, SectionID: f.SectionID, FieldType: f.FieldType}
	}
	return out
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
	// Same client, same approval: looking up names costs no extra prompt. The
	// answer is already a failure, so a slow hint mustn't hold it up.
	hintCtx, cancel := context.WithTimeout(ctx, hintTimeout)
	defer cancel()
	hints := &hinter{client: client}
	for _, ref := range refs {
		r, ok := resp.IndividualResponses[ref]
		switch {
		case !ok || (r.Content == nil && r.Error == nil):
			failed = append(failed, ref+" (no answer)")
		case r.Error != nil:
			vaultMissing = vaultMissing || r.Error.Type == onepassword.ResolveReferenceErrorTypeVariantVaultNotFound
			why := explain(ref, r.Error.Type)
			if r.Error.Type == onepassword.ResolveReferenceErrorTypeVariantFieldNotFound {
				if fields, err := hints.fields(hintCtx, ref); err != nil {
					why += "; its fields couldn't be listed: " + err.Error()
				} else {
					why = "fieldNotFound: the item's fields are " + fields
				}
			}
			failed = append(failed, fmt.Sprintf("%s (%s)", ref, why))
		default:
			values[ref] = r.Content.Secret
		}
	}
	if len(failed) > 0 {
		e := &unresolved{account: account, refs: failed}
		if vaultMissing {
			vaults, _ := hints.vaults(hintCtx)
			for _, v := range vaults {
				e.vaults = append(e.vaults, v.Title)
			}
		}
		return nil, e
	}
	return values, nil
}

// hintTimeout bounds the lookups made to explain the references of one
// request that didn't resolve, all together.
const hintTimeout = 30 * time.Second

// maxHintFields is as many of an item's fields as a hint names.
const maxHintFields = 50

// hinter looks up the names that explain why references didn't resolve. It
// runs only after the person has allowed those references, and only on the
// account they named. A lookup that fails gives no hint, never a guess.
type hinter struct {
	client resolver

	listed    bool
	vaultList []named
	vaultErr  error
	items     map[string][]named // by vault ID
}

func (h *hinter) vaults(ctx context.Context) ([]named, error) {
	if !h.listed {
		h.listed = true
		h.vaultList, h.vaultErr = h.client.Vaults(ctx)
	}
	return h.vaultList, h.vaultErr
}

// fields names the fields of the item ref points to, in the item's order:
// each one's title (or ID, when it has none), type and section, never its
// value. The error says which lookup failed, without naming anything the
// account holds.
func (h *hinter) fields(ctx context.Context, ref string) (string, error) {
	vaultPart, itemPart, ok := vaultAndItem(ref)
	if !ok {
		return "", errors.New("the reference isn't op://VAULT/ITEM/[SECTION/]FIELD")
	}
	vaults, err := h.vaults(ctx)
	if err != nil {
		return "", fmt.Errorf("listing the vaults: %w", err)
	}
	vaultID, ok := find(vaults, vaultPart)
	if !ok {
		return "", errors.New("no one vault by that name or ID")
	}
	items, listed := h.items[vaultID]
	if !listed {
		if items, err = h.client.Items(ctx, vaultID); err != nil {
			return "", fmt.Errorf("listing the vault's items: %w", err)
		}
		if h.items == nil {
			h.items = map[string][]named{}
		}
		h.items[vaultID] = items
	}
	itemID, ok := find(items, itemPart)
	if !ok {
		return "", errors.New("no one item by that name or ID")
	}
	item, err := h.client.Item(ctx, vaultID, itemID)
	if err != nil {
		return "", fmt.Errorf("getting the item: %w", err)
	}
	if len(item.Fields) == 0 {
		return "", errors.New("the item has no fields")
	}
	return fieldList(item), nil
}

// vaultAndItem splits op://VAULT/ITEM/[SECTION/]FIELD[?attribute=…] into its
// vault and item parts.
func vaultAndItem(ref string) (vault, item string, ok bool) {
	path, _, _ := strings.Cut(strings.TrimPrefix(ref, "op://"), "?")
	parts := strings.Split(path, "/")
	if len(parts) < 3 || len(parts) > 4 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// find picks the one vault or item a reference part names: by ID, or else by
// title, exactly or else ignoring case. Two that match is no answer: naming
// the wrong item's fields would be worse than naming none.
func find(list []named, part string) (string, bool) {
	for _, match := range []func(n named) bool{
		func(n named) bool { return n.ID == part },
		func(n named) bool { return n.Title == part },
		func(n named) bool { return strings.EqualFold(n.Title, part) },
	} {
		var found []string
		for _, n := range list {
			if match(n) {
				found = append(found, n.ID)
			}
		}
		if len(found) > 0 {
			return found[0], len(found) == 1
		}
	}
	return "", false
}

// fieldList is the hint for one item, such as
// "username" (Text), "credential" (Concealed), "host" (Text, in section "Server").
// It reads names and types only.
func fieldList(item onepassword.Item) string {
	sections := make(map[string]string, len(item.Sections))
	for _, s := range item.Sections {
		sections[s.ID] = s.Title
	}
	var names []string
	for i, f := range item.Fields {
		if i == maxHintFields {
			names = append(names, fmt.Sprintf("and %d more", len(item.Fields)-i))
			break
		}
		name := f.Title
		if name == "" {
			name = f.ID
		}
		desc := fmt.Sprintf("%q (%s", name, f.FieldType)
		if f.SectionID != nil && sections[*f.SectionID] != "" {
			desc += fmt.Sprintf(", in section %q", sections[*f.SectionID])
		}
		names = append(names, desc+")")
	}
	return strings.Join(names, ", ")
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
