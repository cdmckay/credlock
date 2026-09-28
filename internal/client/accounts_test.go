package client

import (
	"strings"
	"testing"
)

var fixture = []Account{
	{ID: "WORKACCOUNTID0000000000000", User: "WORKUSERID0000000000000000", Email: "me@acme.example", URL: "acme.1password.com"},
	{ID: "HOMEACCOUNTID0000000000000", User: "HOMEUSERID0000000000000000", Email: "me@home.example", URL: "my.1password.com"},
}

func TestEveryWayOfNamingAnAccountResolvesToItsID(t *testing.T) {
	const work = "WORKACCOUNTID0000000000000"
	for _, given := range []string{
		"WORKACCOUNTID0000000000000", // the account ID
		"WORKUSERID0000000000000000", // the user ID from the same row: the mistake that started this
		"acme.1password.com",
		"acme",
		"me@acme.example",
		"Me@Acme.Example",
	} {
		id, label, err := ResolveAccount(given, fixture)
		if err != nil || id != work || label != "acme.1password.com (me@acme.example)" {
			t.Errorf("ResolveAccount(%q) = %q, %q, %v", given, id, label, err)
		}
	}
}

func TestAnUnknownAccountIsPassedThroughForTheSDK(t *testing.T) {
	// The SDK also accepts the name shown top left in the app.
	id, label, err := ResolveAccount("Acme Corp", fixture)
	if err != nil || id != "Acme Corp" || label != "Acme Corp" {
		t.Fatalf("got %q, %q, %v", id, label, err)
	}
}

func TestNoAccountListsTheChoices(t *testing.T) {
	_, _, err := ResolveAccount("", fixture)
	if err == nil {
		t.Fatal("no account accepted")
	}
	for _, want := range []string{"--account", "WORKACCOUNTID0000000000000", "acme.1password.com (me@acme.example)", "my.1password.com"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not show %q:\n%s", want, err)
		}
	}
}

func TestAnAmbiguousAccountIsRefused(t *testing.T) {
	twins := []Account{
		{ID: "A1", Email: "me@example.com", URL: "one.1password.com"},
		{ID: "A2", Email: "me@example.com", URL: "two.1password.com"},
	}
	if _, _, err := ResolveAccount("me@example.com", twins); err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("got %v", err)
	}
}

func TestWithoutOpAccountsPassThrough(t *testing.T) {
	id, _, err := ResolveAccount("HOMEACCOUNTID0000000000000", nil)
	if err != nil || id != "HOMEACCOUNTID0000000000000" {
		t.Fatalf("got %q, %v", id, err)
	}
}
