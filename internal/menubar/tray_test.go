//go:build linux && gtk

package menubar

import (
	"regexp"
	"strings"
	"testing"
)

var sampleTray = Snapshot{
	Held: []Held{
		{AccountID: "ACCT", Account: "my.1password.com (me@example.com)", Name: "GITHUB_TOKEN", Ref: "op://Private/GitHub/token", Left: "48 min left"},
		{AccountID: "ACCT", Account: "my.1password.com (me@example.com)", Origin: "papaya", Name: "IN_TOKEN", Ref: "op://Private/Invoice Ninja/credential", Left: "12 min left"},
	},
	Uses: []Use{
		{At: "16:00", Command: "gh pr list", Reason: "List my 'open' pull requests\\now", Names: []string{"GITHUB_TOKEN"}},
		{At: "15:50", Search: "github", Reason: "Find a token", Summary: "2 items", Told: []string{`op://Private/GitHub: "token" (Concealed)`}},
		{At: "15:40", Command: "a", Reason: "b", Names: []string{"A"}, Cached: true},
		{At: "15:30", Command: "c", Reason: "d", Names: []string{"B"}, Failed: true, Told: []string{"fieldNotFound"}},
		{At: "15:20", Command: "e", Reason: "f", Names: []string{"C"}},
		{At: "15:10", Command: "g", Reason: "h", Names: []string{"D"}},
	},
	Alerts:  []Alert{{At: "14:02", Text: "papaya asked with a key it didn't pair with"}},
	Version: "0.6.0",
}

// labels lists every label in e and below, as the panel would get them.
func labels(e *entry) []string {
	var out []string
	for _, c := range e.children {
		if !c.separator {
			out = append(out, c.label)
		}
		out = append(out, labels(c)...)
	}
	return out
}

// find is the first entry whose label starts with prefix.
func find(e *entry, prefix string) *entry {
	for _, c := range e.children {
		if strings.HasPrefix(c.label, prefix) {
			return c
		}
		if f := find(c, prefix); f != nil {
			return f
		}
	}
	return nil
}

func TestTheTrayMenuParses(t *testing.T) {
	for _, gnome := range []bool{false, true} {
		root, _, _ := buildMenu(sampleTray, 0, gnome)
		if !parses(root.layout()) {
			t.Fatalf("gnome %v: the layout doesn't parse:\n%s", gnome, root.layout())
		}
	}
	if parses("(0, {}, [<(1, {'label': <'unterminated>}, [])>])") {
		t.Fatal("a broken layout parsed")
	}
}

func TestTheTrayMenuShowsWhatTheMacsShows(t *testing.T) {
	root, _, _ := buildMenu(sampleTray, 0, false)
	all := strings.Join(labels(root), "\n")
	for _, want := range []string{
		"Alerts", "14:02  papaya asked with a key it didn't pair with", "Dismiss alerts",
		"credlock is holding 2 secrets", "Access log",
		"16:00  List my 'open' pull requests\\now\nGITHUB__TOKEN · you allowed it",
		"15:50  Find a token\nsearch “github” · 2 items · you allowed it",
		"15:40  b\nA · allowed earlier", "15:30  d\nB · failed after you allowed it", "1 earlier",
		"Held secrets", "my.1password.com (me@example.com)", "GITHUB__TOKEN    48 min left", "IN__TOKEN · papaya    12 min left",
		"op://Private/GitHub/token", "Forget GITHUB__TOKEN", "Forget all", "Stop credlock", "credlock 0.6.0",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("no %q in:\n%s", want, all)
		}
	}
	if find(root, "15:10") != nil && find(find(root, "1 earlier"), "15:10") == nil {
		t.Error("the sixth use isn't under Earlier")
	}
}

func TestTrayItemsDoWhatTheySay(t *testing.T) {
	root, actions, _ := buildMenu(sampleTray, 0, false)
	for label, want := range map[string]Action{
		"Forget all":           {Op: OpForgetAll},
		"Stop credlock":        {Op: OpStop},
		"Dismiss alerts":       {Op: OpDismiss},
		"Forget GITHUB__TOKEN": {Op: OpForget, AccountID: "ACCT", Ref: "op://Private/GitHub/token"},
		"Forget IN__TOKEN":     {Op: OpForget, AccountID: "ACCT", Ref: "op://Private/Invoice Ninja/credential", Origin: "papaya"},
	} {
		e := find(root, label)
		if e == nil {
			t.Fatalf("no %q", label)
		}
		if got := actions[e.id]; got != want {
			t.Errorf("%q does %+v, want %+v", label, got, want)
		}
	}
	for id, a := range actions {
		if !a.valid() {
			t.Errorf("item %d does %+v, which isn't a valid action", id, a)
		}
	}
	if len(actions) != 5 {
		t.Errorf("%d clickable items, want 5: %v", len(actions), actions)
	}
}

func TestAClickOnAReplacedMenuDoesNothing(t *testing.T) {
	_, first, last := buildMenu(sampleTray, 0, false)
	_, second, _ := buildMenu(sampleTray, last, false)
	for id := range first {
		if _, ok := second[id]; ok {
			t.Fatalf("item %d of the old menu does something in the new one", id)
		}
	}
}

func TestUnderscoresShowAsTheyAre(t *testing.T) {
	// GNOME's AppIndicator extension drops the first underscore before
	// another character; the dbusmenu spec turns "__" into "_" and drops
	// the rest, as KDE does.
	gnome := func(s string) string {
		re := regexp.MustCompile(`_([^_])`)
		if loc := re.FindStringIndex(s); loc != nil {
			return s[:loc[0]] + s[loc[0]+1:]
		}
		return s
	}
	spec := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(s, "__", "\x00"), "_", ""), "\x00", "_")
	}
	for _, name := range []string{"GITHUB_TOKEN", "METRICS_COLLECTOR_DEPLOY_KEY_0", "A__B", "_X", "PLAIN"} {
		if got := strings.TrimPrefix(gnome(escape(name, true)), "\u200b"); got != name {
			t.Errorf("GNOME shows %q as %q", name, got)
		}
		if got := spec(escape(name, false)); got != name {
			t.Errorf("KDE shows %q as %q", name, got)
		}
	}
}

func TestTheIconSaysWhatIsHappening(t *testing.T) {
	if iconFor(sampleTray, false) != iconAlert {
		t.Error("alerts don't turn the key red")
	}
	quiet := sampleTray
	quiet.Alerts = nil
	if iconFor(quiet, true) != iconReading || iconFor(quiet, false) != iconKey {
		t.Error("reading doesn't show the dot, or it stays")
	}
	if got := tooltip(quiet, true); got != "credlock: 2 secrets held, being read now" {
		t.Errorf("tooltip %q", got)
	}
}
