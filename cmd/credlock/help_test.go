package main

import (
	"strings"
	"testing"
)

// The help is the one guide an agent is sure to see, so these are the facts it
// must keep carrying. Each was learned from an agent that got it wrong.
func TestTheHelpCarriesWhatAnAgentNeeds(t *testing.T) {
	flat := strings.Join(strings.Fields(runHelp), " ") // immune to line wrapping
	for _, want := range []string{
		"credlock run --account", // a worked example
		"--reason",
		"the account_uuid column of 'op account list', not user_uuid",
		`personal account SDK: "Personal" (op also takes "Private"; the SDK doesn't)`,
		`1Password Business SDK: "Private" (the app and op show it as "Employee")`,
		"A vaultNotFound error lists the vaults",
		"a fieldNotFound error lists the item's fields",
		"77 the request was denied",
		"vaultNotFound",
		"Only a person can answer it",
		"never prints a secret",
		"--ttl DURATION",
		"credlock forget --account", // and how to clean up after
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("run help lost %q", want)
		}
	}
	if !strings.Contains(overview, runHelp) {
		t.Error("the overview does not include the run help")
	}
}

// An agent that doesn't know a reference reaches for 'op item list' unless
// the help says where else to look.
func TestTheHelpSaysHowToFindAReference(t *testing.T) {
	flat := strings.Join(strings.Fields(searchHelp), " ")
	for _, want := range []string{
		"credlock search --account my --reason", // a worked example
		"--reason TEXT Required",
		"Never a value",
		"Every search asks again",
		"77 if the person denied it",
		"not from a machine that asks a hub",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("search help lost %q", want)
		}
	}
	if run := strings.Join(strings.Fields(runHelp), " "); !strings.Contains(run, "use credlock search") || !strings.Contains(run, "no need for 'op item list'") {
		t.Error("the run help no longer points to credlock search")
	}
	if !strings.Contains(overview, searchHelp) {
		t.Error("the overview does not include the search help")
	}
}
