package client

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// Account is one 1Password account the op CLI knows about.
type Account struct {
	ID    string `json:"account_uuid"`
	User  string `json:"user_uuid"`
	Email string `json:"email"`
	URL   string `json:"url"` // e.g. my.1password.com
}

// Label is how an account is shown to people: its sign-in address and email.
func (a Account) Label() string {
	return fmt.Sprintf("%s (%s)", a.URL, a.Email)
}

// Accounts asks the op CLI which accounts are set up. It only reads local
// configuration, so it never prompts. Without op it returns nothing, and
// accounts are passed through as given.
func Accounts() []Account {
	out, err := exec.Command("op", "account", "list", "--format", "json").Output()
	if err != nil {
		return nil
	}
	var accounts []Account
	if json.Unmarshal(out, &accounts) != nil {
		return nil
	}
	return accounts
}

// ResolveAccount turns whatever identifies an account into its account ID,
// the one form the 1Password SDK is sure to understand. It accepts the account
// ID itself, the user ID from the same `op account list` row (an easy one to
// pick up by mistake), the sign-in address with or without ".1password.com",
// or the email. Anything else is passed through unchanged, because the SDK
// also takes the account's name as shown in the app.
func ResolveAccount(given string, accounts []Account) (id, label string, err error) {
	if given == "" {
		return "", "", fmt.Errorf("no 1Password account given: pass --account, or set CREDLOCK_ACCOUNT or OP_ACCOUNT%s", listAccounts(accounts))
	}
	var matches []Account
	for _, a := range accounts {
		if strings.EqualFold(given, a.ID) || strings.EqualFold(given, a.User) ||
			strings.EqualFold(given, a.URL) || strings.EqualFold(given, strings.TrimSuffix(a.URL, ".1password.com")) ||
			strings.EqualFold(given, a.Email) {
			matches = append(matches, a)
		}
	}
	switch len(matches) {
	case 0:
		return given, given, nil
	case 1:
		return matches[0].ID, matches[0].Label(), nil
	default:
		return "", "", fmt.Errorf("%q matches more than one 1Password account; pass the account ID instead%s", given, listAccounts(matches))
	}
}

func listAccounts(accounts []Account) string {
	if len(accounts) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(". Accounts set up here:")
	for _, a := range accounts {
		fmt.Fprintf(&b, "\n  --account %s   %s", a.ID, a.Label())
	}
	return b.String()
}

// labels maps account IDs to their labels, for showing people.
func labels(accounts []Account) map[string]string {
	m := map[string]string{}
	for _, a := range accounts {
		m[a.ID] = a.Label()
	}
	return m
}
