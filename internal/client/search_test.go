package client

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cdmckay/credlock/internal/proto"
)

func TestASearchTakesAReasonAndJoinsItsWords(t *testing.T) {
	t.Setenv("CREDLOCK_ACCOUNT", "")
	t.Setenv("OP_ACCOUNT", "")
	for _, args := range [][]string{
		{"--reason", "the deploy needs it", "--account", "my", "aws", "staging"},
		{"--reason=the deploy needs it", "--account=my", "--", "aws", "staging"},
		{"aws", "--account", "my", "staging", "--reason", "the deploy needs it"},
	} {
		s, err := ParseSearch(args)
		if err != nil {
			t.Fatalf("%q: %v", args, err)
		}
		if s.Reason != "the deploy needs it" || s.Account != "my" || s.Term != "aws staging" {
			t.Fatalf("%q: got %+v", args, s)
		}
	}
}

func TestASearchWithoutAReasonSaysHowToGiveOne(t *testing.T) {
	_, err := ParseSearch([]string{"github"})
	if err == nil || !strings.Contains(err.Error(), "needs --reason") || !strings.Contains(err.Error(), "credlock search --reason") {
		t.Fatalf("got %v", err)
	}
}

func TestASearchRefusesWhatTheWindowCouldntShowWhole(t *testing.T) {
	for _, term := range []string{"", "g", strings.Repeat("x", proto.MaxSearch+1)} {
		if _, err := ParseSearch([]string{"--reason", "r", term}); err == nil {
			t.Errorf("%q: no error", term)
		}
	}
	if _, err := ParseSearch([]string{"--reason", "r", "--format", "json", "x"}); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("got %v", err)
	}
}

func TestTheAnswerGivesReferencesReadyForAField(t *testing.T) {
	var b bytes.Buffer
	_ = PrintFound(&b, proto.Found{
		Items: []proto.FoundItem{
			{Ref: "op://Shared/GitHub", Vault: "Shared", Title: "GitHub", Fields: `"username" (Text), "token" (Concealed)`},
			{Ref: "op://Shared/abc123", Vault: "Shared", Title: "GitHub / old", Why: "its fields couldn't be listed: timed out"},
		},
		More:   4,
		Unread: []string{`"Archive": not allowed`},
		Closed: 3,
	}, "github", "my.1password.com")
	got := b.String()
	for _, want := range []string{
		`2 items in my.1password.com have "github" in their titles, best match first (names only, never values):`,
		"\n  op://Shared/GitHub\n    fields: \"username\" (Text), \"token\" (Concealed)\n",
		"\n  op://Shared/abc123\n    title: \"GitHub / old\", in vault \"Shared\"\n    its fields couldn't be listed: timed out\n",
		"such as op://Shared/GitHub/FIELD, with credlock run",
		"And 4 more match: search for something narrower",
		`Couldn't search vault "Archive": not allowed.`,
		"Skipped 3 vaults this account can see but not read items in.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	b.Reset()
	_ = PrintFound(&b, proto.Found{}, "nothing", "my")
	if b.String() != "No item titles in my contain \"nothing\".\n" {
		t.Fatalf("got %q", b.String())
	}
}
