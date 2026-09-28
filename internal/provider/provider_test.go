package provider

import (
	"errors"
	"testing"
)

func TestOnlyOpReferencesAreSupported(t *testing.T) {
	if err := Supported("op://Personal/item/field"); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"", "op:/x", "OP://x/y/z", "vault://x", "https://x"} {
		if Supported(ref) == nil {
			t.Errorf("accepted %q", ref)
		}
	}
}

func TestUnresolvedReferencesAreNotRetried(t *testing.T) {
	// A retry means a fresh client and a fresh approval prompt, so it must be
	// kept for session failures, never for references that don't resolve.
	var err error = &unresolved{refs: []string{"op://v/i/f (fieldNotFound)"}}
	var u *unresolved
	if !errors.As(err, &u) {
		t.Fatal("an unresolved reference would be retried")
	}
	if err.Error() != "1Password could not resolve op://v/i/f (fieldNotFound)" {
		t.Fatalf("message %q", err.Error())
	}
}
