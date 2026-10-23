package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	onepassword "github.com/1password/onepassword-sdk-go"

	"github.com/cdmckay/credlock/internal/proto"
)

func search(t *testing.T, c *fakeClient, term string) proto.Found {
	t.Helper()
	h := &harness{clients: []*fakeClient{c}}
	found, err := h.provider().Search(context.Background(), "acct", term)
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func TestASearchNamesTheItemAndItsFieldsButNoValue(t *testing.T) {
	found := search(t, spotify(nil), "spot")
	want := proto.FoundItem{
		Ref:    "op://Personal/Spotify",
		Vault:  "Personal",
		Title:  "Spotify",
		Fields: strings.TrimPrefix(spotifyFields, "fieldNotFound: the item's fields are "),
	}
	if len(found.Items) != 1 || found.Items[0] != want || found.More != 0 || len(found.Unread) != 0 {
		t.Fatalf("got %+v", found)
	}
	if strings.Contains(fmt.Sprintf("%+v", found), leaked) {
		t.Fatalf("a value got into the answer: %+v", found)
	}
}

// titled is an account with one vault, holding items with these titles and
// one field each.
func titled(titles ...string) *fakeClient {
	c := &fakeClient{vaults: []named{{"v1", "Shared"}}, items: map[string][]named{}, item: map[string]onepassword.Item{}}
	for i, title := range titles {
		id := fmt.Sprint("i", i)
		c.items["v1"] = append(c.items["v1"], named{id, title})
		c.item["v1/"+id] = onepassword.Item{Fields: []onepassword.ItemField{{Title: "credential", FieldType: onepassword.ItemFieldTypeConcealed}}}
	}
	return c
}

func titles(found proto.Found) []string {
	var out []string
	for _, it := range found.Items {
		out = append(out, it.Title)
	}
	return out
}

func TestTheWholeTitleComesFirstThenItsStartThenAnywhere(t *testing.T) {
	found := search(t, titled("My GitHub", "GitHubber", "Gitlab", "GitHub Actions", "github"), "GitHub")
	got := strings.Join(titles(found), ", ")
	if want := "github, GitHub Actions, GitHubber, My GitHub"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestASearchPastTheCapCountsTheRest(t *testing.T) {
	var many []string
	for i := range proto.MaxFound + 5 {
		many = append(many, fmt.Sprintf("token %02d", i))
	}
	c := titled(many...)
	found := search(t, c, "token")
	if len(found.Items) != proto.MaxFound || found.More != 5 || found.Items[0].Title != "token 00" {
		t.Fatalf("got %d items, %d more, first %q", len(found.Items), found.More, found.Items[0].Title)
	}
	if c.got != proto.MaxFound {
		t.Fatalf("got %d items' fields, want only the %d named", c.got, proto.MaxFound)
	}
}

func TestATitleAReferenceCantCarryIsNamedByID(t *testing.T) {
	found := search(t, titled("key a/b", "key?", "Key dup", "key DUP", " key lead", "key.name_-1 ok"), "key")
	refs := map[string]string{}
	for _, it := range found.Items {
		refs[it.Title] = it.Ref
	}
	for title, want := range map[string]string{
		"key a/b":        "op://Shared/i0",
		"key?":           "op://Shared/i1",
		"Key dup":        "op://Shared/i2",
		"key DUP":        "op://Shared/i3",
		" key lead":      "op://Shared/i4",
		"key.name_-1 ok": "op://Shared/key.name_-1 ok",
	} {
		if refs[title] != want {
			t.Errorf("%q: got %q, want %q", title, refs[title], want)
		}
	}
}

func TestAVaultThatCantBeListedIsNamedInTheAnswer(t *testing.T) {
	c := spotify(nil)
	delete(c.items, "vaultid2")
	found := search(t, c, "spotify")
	if len(found.Items) != 1 || len(found.Unread) != 1 || found.Unread[0] != `"Shared": no such vault` {
		t.Fatalf("got %+v", found)
	}
}

func TestAVaultTheAccountCantReadIsCountedNotNamed(t *testing.T) {
	c := spotify(nil)
	c.itemsErr = map[string]error{"vaultid2": errors.New("you do not have the right permissions to perform this action: performing an item operation")}
	found := search(t, c, "spotify")
	if len(found.Items) != 1 || found.Closed != 1 || len(found.Unread) != 0 {
		t.Fatalf("got %+v", found)
	}
}

func TestAnItemWhoseFieldsCantBeReadSaysWhy(t *testing.T) {
	c := spotify(nil)
	delete(c.item, "vaultid1/itemid1")
	found := search(t, c, "spotify")
	if len(found.Items) != 1 || found.Items[0].Fields != "" || found.Items[0].Why != "its fields couldn't be listed: no such item" {
		t.Fatalf("got %+v", found)
	}
}

func TestASearchTriesANewClientWhenTheVaultsCantBeListed(t *testing.T) {
	stale := spotify(nil)
	stale.vaultsErr = errors.New("session expired")
	h := &harness{clients: []*fakeClient{stale, spotify(nil)}}
	found, err := h.provider().Search(context.Background(), "acct", "spotify")
	if err != nil || len(found.Items) != 1 {
		t.Fatalf("got %+v, %v", found, err)
	}
	if len(h.accounts) != 2 {
		t.Fatalf("connected %d times, want 2", len(h.accounts))
	}
}

func TestASearchNeedsTwoCharactersAndAnAccount(t *testing.T) {
	h := &harness{clients: []*fakeClient{spotify(nil)}}
	if _, err := h.provider().Search(context.Background(), "acct", " s "); err == nil || !strings.Contains(err.Error(), "at least 2") {
		t.Fatalf("got %v", err)
	}
	if _, err := h.provider().Search(context.Background(), "", "spotify"); err == nil || !strings.Contains(err.Error(), "--account") {
		t.Fatalf("got %v", err)
	}
	if len(h.accounts) != 0 {
		t.Fatalf("connected for a search that couldn't run")
	}
}
