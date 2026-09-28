package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	onepassword "github.com/1password/onepassword-sdk-go"
)

type response = onepassword.Response[onepassword.ResolvedReference, onepassword.ResolveReferenceError]

// fakeClient answers ResolveAll from answer, or fails with err.
type fakeClient struct {
	err    error
	answer func(ref string) response
	vaults []string
	calls  int
}

func (c *fakeClient) VaultTitles(context.Context) ([]string, error) { return c.vaults, nil }

func (c *fakeClient) ResolveAll(_ context.Context, refs []string) (onepassword.ResolveAllResponse, error) {
	c.calls++
	if c.err != nil {
		return onepassword.ResolveAllResponse{}, c.err
	}
	out := onepassword.ResolveAllResponse{IndividualResponses: map[string]response{}}
	for _, r := range refs {
		out.IndividualResponses[r] = c.answer(r)
	}
	return out, nil
}

func secret(v string) response {
	return response{Content: &onepassword.ResolvedReference{Secret: v}}
}

func failure(e onepassword.ResolveReferenceError) response { return response{Error: &e} }

// harness hands out the given clients in order and counts connections.
type harness struct {
	clients  []*fakeClient
	accounts []string
}

func (h *harness) provider() *OnePassword {
	return &OnePassword{connect: func(_ context.Context, account, _ string) (resolver, error) {
		h.accounts = append(h.accounts, account)
		if len(h.clients) == 0 {
			return nil, errors.New("no more clients")
		}
		c := h.clients[0]
		h.clients = h.clients[1:]
		return c, nil
	}}
}

func ok(ref string) response { return secret("secret:" + ref) }

func TestAnExpiredSessionReconnectsOnce(t *testing.T) {
	expired := &fakeClient{err: errors.New("session expired")}
	fresh := &fakeClient{answer: ok}
	h := &harness{clients: []*fakeClient{expired, fresh}}
	got, err := h.provider().ResolveAll(context.Background(), "acct", []string{"op://v/i/f"})
	if err != nil || got["op://v/i/f"] != "secret:op://v/i/f" {
		t.Fatalf("got %v, %v", got, err)
	}
	if len(h.accounts) != 2 || expired.calls != 1 || fresh.calls != 1 {
		t.Fatalf("want one reconnect: %d connections, %d and %d calls", len(h.accounts), expired.calls, fresh.calls)
	}
}

func TestAMissingSecretDoesNotReconnect(t *testing.T) {
	c := &fakeClient{answer: func(string) response {
		return failure(onepassword.NewResolveReferenceErrorTypeVariantFieldNotFound())
	}}
	h := &harness{clients: []*fakeClient{c, {answer: ok}}}
	_, err := h.provider().ResolveAll(context.Background(), "acct", []string{"op://v/i/nope"})
	var missing *unresolved
	if !errors.As(err, &missing) || !strings.Contains(err.Error(), "op://v/i/nope (fieldNotFound") {
		t.Fatalf("got %v", err)
	}
	if len(h.accounts) != 1 {
		t.Fatalf("reconnected (a second approval prompt) for a secret that isn't there: %d connections", len(h.accounts))
	}
}

func TestAFailedReconnectIsReportedNotRetriedAgain(t *testing.T) {
	h := &harness{clients: []*fakeClient{{err: errors.New("locked")}, {err: errors.New("still locked")}, {answer: ok}}}
	_, err := h.provider().ResolveAll(context.Background(), "acct", []string{"op://v/i/f"})
	if err == nil || !strings.Contains(err.Error(), "still locked") {
		t.Fatalf("got %v", err)
	}
	if len(h.accounts) != 2 {
		t.Fatalf("want exactly one retry, got %d connections", len(h.accounts))
	}
}

func TestOneClientPerAccountIsReused(t *testing.T) {
	h := &harness{clients: []*fakeClient{{answer: ok}, {answer: ok}}}
	p := h.provider()
	for _, account := range []string{"personal", "personal", "work", "personal"} {
		if _, err := p.ResolveAll(context.Background(), account, []string{"op://v/i/f"}); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(h.accounts, ",") != "personal,work" {
		t.Fatalf("connections: %v", h.accounts)
	}
}

func TestEveryReferenceMustResolve(t *testing.T) {
	c := &fakeClient{answer: func(ref string) response {
		if strings.HasSuffix(ref, "/bad") {
			return failure(onepassword.NewResolveReferenceErrorTypeVariantItemNotFound())
		}
		return ok(ref)
	}}
	h := &harness{clients: []*fakeClient{c}}
	got, err := h.provider().ResolveAll(context.Background(), "acct", []string{"op://v/i/good", "op://v/i/bad"})
	if err == nil || got != nil {
		t.Fatalf("a partial answer got through: %v, %v", got, err)
	}
}

func TestThePrivateAliasGetsAHint(t *testing.T) {
	c := &fakeClient{answer: func(string) response {
		return failure(onepassword.NewResolveReferenceErrorTypeVariantVaultNotFound())
	}}
	h := &harness{clients: []*fakeClient{c}}
	_, err := h.provider().ResolveAll(context.Background(), "acct", []string{"op://Private/i/f"})
	if err == nil || !strings.Contains(err.Error(), `no "Private" alias`) || !strings.Contains(err.Error(), "op://Employee/") {
		t.Fatalf("got %v", err)
	}
}

func TestAVaultNotFoundNamesTheAccountAndItsVaults(t *testing.T) {
	c := &fakeClient{vaults: []string{"Employee", "Shared"}, answer: func(string) response {
		return failure(onepassword.NewResolveReferenceErrorTypeVariantVaultNotFound())
	}}
	h := &harness{clients: []*fakeClient{c}}
	_, err := h.provider().ResolveAll(context.Background(), "WORKACCOUNTID", []string{"op://Employee/i/f"})
	for _, want := range []string{"account WORKACCOUNTID", "check --account", `The vaults in this account are "Employee", "Shared"`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("error lacks %q: %v", want, err)
		}
	}
}

func TestADeniedApprovalSaysWhatToCheck(t *testing.T) {
	p := &OnePassword{connect: func(context.Context, string, string) (resolver, error) {
		return nil, errors.New("error initializing client: Denied authorization for SDK client")
	}}
	_, err := p.ResolveAll(context.Background(), "WORKACCOUNTID", []string{"op://v/i/f"})
	for _, want := range []string{"did not authorize credlock for account WORKACCOUNTID", "Integrate with other apps", "Ask the person"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("error lacks %q: %v", want, err)
		}
	}
}

func TestAnAccountIsRequired(t *testing.T) {
	h := &harness{}
	if _, err := h.provider().ResolveAll(context.Background(), "", []string{"op://v/i/f"}); err == nil {
		t.Fatal("resolved with no account")
	}
	if len(h.accounts) != 0 {
		t.Fatal("connected with no account")
	}
}
