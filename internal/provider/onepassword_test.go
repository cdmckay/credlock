package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
)

type response = onepassword.Response[onepassword.ResolvedReference, onepassword.ResolveReferenceError]

// fakeClient answers ResolveAll from answer, or fails with err. It holds the
// vaults, items and fields that explain a reference that doesn't resolve.
type fakeClient struct {
	err       error
	answer    func(ref string) response
	vaults    []named
	vaultsErr error
	items     map[string][]named          // by vault ID
	item      map[string]onepassword.Item // by "vault ID/item ID"
	stuck     chan struct{}               // when set, Item waits for it to close
	calls     int
	vaulted   int // calls to Vaults
	listed    int // calls to Items
	got       int // calls to Item
}

func (c *fakeClient) Vaults(context.Context) ([]named, error) {
	c.vaulted++
	return c.vaults, c.vaultsErr
}

func (c *fakeClient) Items(_ context.Context, vaultID string) ([]named, error) {
	c.listed++
	items, ok := c.items[vaultID]
	if !ok {
		return nil, errors.New("no such vault")
	}
	return items, nil
}

func (c *fakeClient) Item(_ context.Context, vaultID, itemID string) (onepassword.Item, error) {
	c.got++
	if c.stuck != nil {
		<-c.stuck
	}
	item, ok := c.item[vaultID+"/"+itemID]
	if !ok {
		return onepassword.Item{}, errors.New("no such item")
	}
	return item, nil
}

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
	if err == nil || !strings.Contains(err.Error(), `SDK calls the built-in vault "Personal"`) {
		t.Fatalf("got %v", err)
	}
}

func TestTheEmployeeNameGetsAHint(t *testing.T) {
	c := &fakeClient{answer: func(string) response {
		return failure(onepassword.NewResolveReferenceErrorTypeVariantVaultNotFound())
	}}
	h := &harness{clients: []*fakeClient{c}}
	_, err := h.provider().ResolveAll(context.Background(), "acct", []string{"op://Employee/i/f"})
	if err == nil || !strings.Contains(err.Error(), "try op://Private/") {
		t.Fatalf("got %v", err)
	}
}

func TestAVaultNotFoundNamesTheAccountAndItsVaults(t *testing.T) {
	c := &fakeClient{vaults: []named{{"v1", "Private"}, {"v2", "Shared"}}, answer: func(string) response {
		return failure(onepassword.NewResolveReferenceErrorTypeVariantVaultNotFound())
	}}
	h := &harness{clients: []*fakeClient{c}}
	_, err := h.provider().ResolveAll(context.Background(), "WORKACCOUNTID", []string{"op://Engineering/i/f"})
	for _, want := range []string{"account WORKACCOUNTID", "check --account", `The vaults in this account are "Private", "Shared"`} {
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

func fieldNotFound(string) response {
	return failure(onepassword.NewResolveReferenceErrorTypeVariantFieldNotFound())
}

const leaked = "VALUE-THAT-MUST-NOT-LEAK"

// spotify is an account with one item, whose fields all hold a value.
func spotify(answer func(string) response) *fakeClient {
	server := "s1"
	return &fakeClient{
		answer: answer,
		vaults: []named{{"vaultid1", "Personal"}, {"vaultid2", "Shared"}},
		items: map[string][]named{
			"vaultid1": {{"itemid1", "Spotify"}, {"itemid2", "Other"}},
		},
		item: map[string]onepassword.Item{"vaultid1/itemid1": {
			Title: "Spotify " + leaked,
			Notes: leaked,
			Fields: []onepassword.ItemField{
				{ID: "username", Title: "username", FieldType: onepassword.ItemFieldTypeText, Value: leaked},
				{ID: "credential", Title: "credential", FieldType: onepassword.ItemFieldTypeConcealed, Value: leaked},
				{ID: "x7f2k", Title: "host", SectionID: &server, FieldType: onepassword.ItemFieldTypeURL, Value: leaked},
				{ID: "untitled", FieldType: onepassword.ItemFieldTypeText, Value: leaked},
			},
			Sections: []onepassword.ItemSection{{ID: server, Title: "Server"}},
		}},
	}
}

const spotifyFields = `fieldNotFound: the item's fields are "username" (Text), "credential" (Concealed), ` +
	`"host" (Url, in section "Server"), "untitled" (Text)`

func TestAFieldNotFoundNamesTheItemsFieldsButNoValue(t *testing.T) {
	h := &harness{clients: []*fakeClient{spotify(fieldNotFound)}}
	_, err := h.provider().ResolveAll(context.Background(), "acct", []string{"op://Personal/Spotify/token"})
	if err == nil || !strings.Contains(err.Error(), "op://Personal/Spotify/token ("+spotifyFields+")") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), leaked) {
		t.Fatalf("a value got into the error: %v", err)
	}
}

func TestTheItemIsFoundByIDOrByTitle(t *testing.T) {
	for _, ref := range []string{
		"op://vaultid1/itemid1/token",
		"op://Personal/itemid1/token",
		"op://vaultid1/Spotify/token",
		"op://personal/spotify/token",
		"op://Personal/Spotify/Server/token",
		"op://Personal/Spotify/token?attribute=otp",
	} {
		h := &harness{clients: []*fakeClient{spotify(fieldNotFound)}}
		_, err := h.provider().ResolveAll(context.Background(), "acct", []string{ref})
		if err == nil || !strings.Contains(err.Error(), spotifyFields) {
			t.Errorf("%s: got %v", ref, err)
		}
	}
}

func TestAnItemThatCantBeFoundAgainGetsTheUsualMessageAndWhy(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(c *fakeClient)
		why    string
	}{
		"the item went away":      {func(c *fakeClient) { delete(c.item, "vaultid1/itemid1") }, "getting the item: no such item"},
		"the vault went away":     {func(c *fakeClient) { c.vaults = c.vaults[1:] }, "no one vault by that name or ID"},
		"the items can't be read": {func(c *fakeClient) { delete(c.items, "vaultid1") }, "listing the vault's items: no such vault"},
		"two items have its name": {func(c *fakeClient) {
			c.items["vaultid1"] = append(c.items["vaultid1"], named{"itemid3", "Spotify"})
		}, "no one item by that name or ID"},
		"it has no fields":           {func(c *fakeClient) { c.item["vaultid1/itemid1"] = onepassword.Item{} }, "the item has no fields"},
		"the vaults can't be listed": {func(c *fakeClient) { c.vaultsErr = errors.New("locked") }, "listing the vaults: locked"},
	} {
		c := spotify(fieldNotFound)
		tc.change(c)
		h := &harness{clients: []*fakeClient{c}}
		_, err := h.provider().ResolveAll(context.Background(), "acct", []string{"op://Personal/Spotify/token"})
		want := "op://Personal/Spotify/token (fieldNotFound: the item has no such field; its fields couldn't be listed: " + tc.why + ")"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestOnlyAFieldNotFoundLooksAtTheItem(t *testing.T) {
	for _, why := range []onepassword.ResolveReferenceError{
		onepassword.NewResolveReferenceErrorTypeVariantVaultNotFound(),
		onepassword.NewResolveReferenceErrorTypeVariantItemNotFound(),
	} {
		c := spotify(func(string) response { return failure(why) })
		h := &harness{clients: []*fakeClient{c}}
		_, err := h.provider().ResolveAll(context.Background(), "acct", []string{"op://Personal/Spotify/token"})
		if err == nil || !strings.Contains(err.Error(), "("+explain("op://Personal/Spotify/token", why.Type)+")") {
			t.Errorf("%s: the message changed: %v", why.Type, err)
		}
		if c.listed != 0 || c.got != 0 {
			t.Errorf("%s: listed a vault's items %d times and got an item %d times", why.Type, c.listed, c.got)
		}
	}
}

func TestAnItemIsLookedUpOncePerRequest(t *testing.T) {
	c := spotify(fieldNotFound)
	h := &harness{clients: []*fakeClient{c}}
	_, err := h.provider().ResolveAll(context.Background(), "acct", []string{"op://Personal/Spotify/a", "op://Personal/Spotify/b"})
	if err == nil || strings.Count(err.Error(), spotifyFields) != 2 {
		t.Fatalf("got %v", err)
	}
	if c.vaulted != 1 || c.listed != 1 || c.got != 1 {
		t.Fatalf("listed the vaults %d times, the vault's items %d times, and got the item %d times", c.vaulted, c.listed, c.got)
	}
}

func TestAFailedVaultListingIsTriedOncePerRequest(t *testing.T) {
	c := spotify(func(ref string) response {
		if strings.HasPrefix(ref, "op://Nope/") {
			return failure(onepassword.NewResolveReferenceErrorTypeVariantVaultNotFound())
		}
		return fieldNotFound(ref)
	})
	c.vaultsErr = errors.New("locked")
	h := &harness{clients: []*fakeClient{c}}
	_, err := h.provider().ResolveAll(context.Background(), "acct", []string{"op://Personal/Spotify/a", "op://Nope/Spotify/b"})
	if err == nil || !strings.Contains(err.Error(), "its fields couldn't be listed: listing the vaults: locked") {
		t.Fatalf("got %v", err)
	}
	if c.vaulted != 1 {
		t.Fatalf("listed the vaults %d times", c.vaulted)
	}
}

func TestAStuckLookupStillAnswersInTime(t *testing.T) {
	c := spotify(fieldNotFound)
	c.stuck = make(chan struct{})
	t.Cleanup(func() { close(c.stuck) })
	h := &harness{clients: []*fakeClient{c}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := h.provider().ResolveAll(ctx, "acct", []string{"op://Personal/Spotify/token"})
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("waited %s for a stuck lookup", took)
	}
	want := "op://Personal/Spotify/token (fieldNotFound: the item has no such field; its fields couldn't be listed: " +
		"getting the item: 1Password didn't answer in time: context deadline exceeded)"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("got %v", err)
	}
}

func TestALongItemIsCut(t *testing.T) {
	item := onepassword.Item{}
	for i := range maxHintFields + 7 {
		item.Fields = append(item.Fields, onepassword.ItemField{Title: fmt.Sprint("f", i), FieldType: onepassword.ItemFieldTypeText})
	}
	got := fieldList(item)
	if !strings.HasSuffix(got, `"f49" (Text), and 7 more`) {
		t.Fatalf("got %q", got)
	}
}

func TestNamesOnlyDropsEveryValue(t *testing.T) {
	c := spotify(nil)
	item := namesOnly(c.item["vaultid1/itemid1"])
	if strings.Contains(fmt.Sprintf("%+v", item), leaked) {
		t.Fatalf("kept a value: %+v", item)
	}
	if len(item.Fields) != 4 || item.Fields[2].Title != "host" || *item.Fields[2].SectionID != "s1" || len(item.Sections) != 1 {
		t.Fatalf("lost a name: %+v", item)
	}
}
