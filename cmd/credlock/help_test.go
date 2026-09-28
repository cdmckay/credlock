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
		`there is no "Private" alias`,
		`"Personal" in a personal account, "Employee" in 1Password Business`,
		"77 the request was denied",
		"vaultNotFound",
		"Only a person can answer it",
		"never prints a secret",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("run help lost %q", want)
		}
	}
	if !strings.Contains(overview, runHelp) {
		t.Error("the overview does not include the run help")
	}
}
