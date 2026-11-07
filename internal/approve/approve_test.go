package approve

import (
	"strings"
	"testing"
)

func TestLongFieldsAreCut(t *testing.T) {
	if got := clean(strings.Repeat("x", 500), 200); len([]rune(got)) != 200 || !strings.HasSuffix(got, "…") {
		t.Fatalf("got %d runes", len([]rune(got)))
	}
}
