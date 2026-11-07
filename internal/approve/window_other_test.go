//go:build !darwin && !(linux && gtk)

package approve

import (
	"context"
	"testing"
)

func TestABuildWithoutAWindowAllowsNothing(t *testing.T) {
	ok, err := Default(0).Approve(context.Background(), sample)
	if ok || err == nil {
		t.Fatalf("got %v, %v", ok, err)
	}
}
