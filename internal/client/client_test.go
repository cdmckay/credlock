package client

import (
	"reflect"
	"testing"
	"time"

	"github.com/cdmckay/credlock/internal/proto"
)

func TestParseRun(t *testing.T) {
	t.Setenv("CREDLOCK_ACCOUNT", "")
	t.Setenv("OP_ACCOUNT", "")
	for _, tc := range []struct {
		args []string
		want RunArgs
	}{
		{[]string{"--", "make", "deploy"}, RunArgs{Command: []string{"make", "deploy"}}},
		{[]string{"make", "-j", "4"}, RunArgs{Command: []string{"make", "-j", "4"}}},
		{[]string{"--reason", "ship it", "--account=acct", "--", "make"}, RunArgs{Reason: "ship it", Account: "acct", Command: []string{"make"}}},
		{[]string{"--account", "acct", "make", "--reason", "x"}, RunArgs{Account: "acct", Command: []string{"make", "--reason", "x"}}},
		{[]string{"--ttl", "15m", "make"}, RunArgs{TTL: 15 * time.Minute, Command: []string{"make"}}},
		{[]string{"--ttl=1h", "--", "make"}, RunArgs{TTL: time.Hour, Command: []string{"make"}}},
	} {
		got, err := ParseRun(tc.args)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParseRun(%q) = %+v, %v; want %+v", tc.args, got, err, tc.want)
		}
	}
	for _, bad := range [][]string{{}, {"--"}, {"--reason"}, {"--bogus", "make"},
		{"--ttl", "make"}, {"--ttl", "0s", "make"}, {"--ttl=-5m", "make"}, {"--ttl", "500ms", "make"}, {"--ttl", "61m", "make"}, {"--ttl"}} {
		if _, err := ParseRun(bad); err == nil {
			t.Errorf("ParseRun(%q) accepted", bad)
		}
	}
}

func TestTheAccountFallsBackToTheEnvironment(t *testing.T) {
	t.Setenv("CREDLOCK_ACCOUNT", "")
	t.Setenv("OP_ACCOUNT", "from-op")
	if r, _ := ParseRun([]string{"make"}); r.Account != "from-op" {
		t.Fatalf("got %q", r.Account)
	}
	t.Setenv("CREDLOCK_ACCOUNT", "from-credlock")
	if r, _ := ParseRun([]string{"make"}); r.Account != "from-credlock" {
		t.Fatalf("got %q", r.Account)
	}
}

func TestOnlyReferencesAreCollectedAndOnlyTheyAreFilled(t *testing.T) {
	env := []string{"PATH=/bin", "B=op://v/b/f", "A=op://v/a/f", "NOT=not op://", "EMPTY="}
	secrets := Refs(env)
	if !reflect.DeepEqual(secrets, []proto.Secret{{Name: "A", Ref: "op://v/a/f"}, {Name: "B", Ref: "op://v/b/f"}}) {
		t.Fatalf("Refs = %v", secrets)
	}
	got := Fill(env, secrets, map[string]string{"op://v/a/f": "sa", "op://v/b/f": "sb=with=equals"})
	want := []string{"PATH=/bin", "B=sb=with=equals", "A=sa", "NOT=not op://", "EMPTY="}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Fill = %v", got)
	}
}

func TestParseForget(t *testing.T) {
	t.Setenv("CREDLOCK_ACCOUNT", "")
	t.Setenv("OP_ACCOUNT", "")
	env := []string{"PATH=/bin", "B=op://v/b/f", "A=op://v/a/f"}
	for _, tc := range []struct {
		args    []string
		account string
		refs    []string
	}{
		{nil, "", []string{"op://v/a/f", "op://v/b/f"}},
		{[]string{"--account", "my"}, "my", []string{"op://v/a/f", "op://v/b/f"}},
		{[]string{"op://v/c/f", "--account=my"}, "my", []string{"op://v/c/f"}},
	} {
		account, refs, err := ParseForget(tc.args, env)
		if err != nil || account != tc.account || !reflect.DeepEqual(refs, tc.refs) {
			t.Errorf("ParseForget(%q) = %q, %q, %v; want %q, %q", tc.args, account, refs, err, tc.account, tc.refs)
		}
	}
	for _, bad := range [][]string{{"--account"}, {"--bogus"}, {"GITHUB_TOKEN"}} {
		if _, _, err := ParseForget(bad, env); err == nil {
			t.Errorf("ParseForget(%q) accepted", bad)
		}
	}
	if _, _, err := ParseForget(nil, []string{"PATH=/bin"}); err == nil {
		t.Error("forgot nothing without saying so")
	}
	t.Setenv("CREDLOCK_ACCOUNT", "from-env")
	if account, _, _ := ParseForget(nil, env); account != "from-env" {
		t.Errorf("the account didn't fall back to the environment: %q", account)
	}
}
