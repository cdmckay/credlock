// Package provider fetches secrets from where they live. A reference's scheme
// names its provider; 1Password (op://) is the only one so far.
package provider

import (
	"context"
	"fmt"
	"strings"
)

// Provider fetches secrets.
type Provider interface {
	// ResolveAll fetches every reference in one go, or fails as a whole.
	ResolveAll(ctx context.Context, account string, refs []string) (map[string]string, error)
}

// Supported reports whether some provider handles ref.
func Supported(ref string) error {
	if strings.HasPrefix(ref, "op://") {
		return nil
	}
	return fmt.Errorf("%q is not a reference credlock can resolve: only op://VAULT/ITEM/FIELD (1Password) so far", ref)
}
