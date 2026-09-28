package approve

import (
	"strings"
	"testing"
	"time"

	"github.com/cdmckay/credlock/internal/proto"
)

func TestTheBodyShowsWhoWhatAndWhy(t *testing.T) {
	body := Body(Request{
		Reason:    "List my open pull requests",
		Command:   []string{"gh", "api", "/user/repos?per_page=50"},
		Cwd:       "/work",
		Requester: "bash (pid 42)",
		Secrets:   []proto.Secret{{Name: "GITHUB_TOKEN", Ref: "op://Personal/x/credential"}},
		Approved:  2,
		Window:    time.Hour,
		Cap:       24 * time.Hour,
	})
	for _, want := range []string{
		"Reason:  List my open pull requests",
		"Command:  gh api '/user/repos?per_page=50'",
		"Directory:  /work",
		"Requested by:  bash (pid 42)",
		"GITHUB_TOKEN  →  op://Personal/x/credential",
		"(plus 2 already approved)",
		"1 hour after their last use, and 24 hours at most",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}
}

func TestClientTextCannotDrawFakeLines(t *testing.T) {
	body := Body(Request{
		Reason:  "routine\n\nAll secrets already approved\x1b[2J",
		Command: []string{"sh", "-c", "evil\nGITHUB_TOKEN  →  op://fake"},
		Secrets: []proto.Secret{{Name: "A\nB", Ref: "op://v/i/f"}},
	})
	if strings.Contains(body, "\nAll secrets already approved") || strings.Contains(body, "\nGITHUB_TOKEN  →  op://fake") || strings.Contains(body, "\x1b") {
		t.Fatalf("client text broke onto its own line:\n%s", body)
	}
	if n := strings.Count(body, "\n"); n != 7 {
		t.Fatalf("want the fixed 7 line breaks, got %d:\n%s", n, body)
	}
}

func TestLongFieldsAreCut(t *testing.T) {
	if got := clean(strings.Repeat("x", 500), 200); len([]rune(got)) != 200 || !strings.HasSuffix(got, "…") {
		t.Fatalf("got %d runes", len([]rune(got)))
	}
}

func TestTitleCounts(t *testing.T) {
	one := Title(Request{Secrets: make([]proto.Secret, 1)})
	three := Title(Request{Secrets: make([]proto.Secret, 3)})
	if one != "credlock: allow 1 secret?" || three != "credlock: allow 3 secrets?" {
		t.Fatalf("%q, %q", one, three)
	}
}
