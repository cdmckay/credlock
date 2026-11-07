//go:build linux && gtk

package menubar

import (
	"fmt"
	"strings"
)

// The tray icon's menu on Linux. It holds what the Mac's menu holds, built
// here from the same Snapshot, and menubar_sni.c serves it over D-Bus as a
// com.canonical.dbusmenu layout, handed over as GVariant text.

// shownUses is how many uses the menu lists before the rest go under
// Earlier, as on the Mac.
const shownUses = 5

// entry is one item in the menu.
type entry struct {
	id        int32
	label     string
	separator bool
	enabled   bool
	children  []*entry
}

// menuBuilder builds one menu. Every menu's ids are new, so a click on an
// item of a menu that has since been replaced matches nothing, rather than
// whatever now has its id.
type menuBuilder struct {
	next    int32
	gnome   bool // escape labels for GNOME's AppIndicator extension
	actions map[int32]Action
}

func (b *menuBuilder) add(parent *entry, label string, enabled bool) *entry {
	b.next++
	e := &entry{id: b.next, label: escape(label, b.gnome), enabled: enabled}
	parent.children = append(parent.children, e)
	return e
}

// note is text to read, greyed as in the Mac's menu.
func (b *menuBuilder) note(parent *entry, label string) *entry { return b.add(parent, label, false) }

// action is an item that does op.
func (b *menuBuilder) action(parent *entry, label string, a Action) *entry {
	e := b.add(parent, label, true)
	b.actions[e.id] = a
	return e
}

func (b *menuBuilder) separator(parent *entry) {
	b.next++
	parent.children = append(parent.children, &entry{id: b.next, separator: true})
}

// buildMenu makes the menu for s, its ids following after.
func buildMenu(s Snapshot, after int32, gnome bool) (*entry, map[int32]Action, int32) {
	b := &menuBuilder{next: after, gnome: gnome, actions: map[int32]Action{}}
	root := &entry{id: 0, enabled: true}
	if len(s.Alerts) > 0 {
		b.note(root, "Alerts")
		for _, a := range s.Alerts {
			b.add(root, a.At+"  "+a.Text, true)
		}
		b.action(root, "Dismiss alerts", Action{Op: OpDismiss})
		b.separator(root)
	}
	b.note(root, fmt.Sprintf("credlock is holding %d secret%s", len(s.Held), plural(len(s.Held))))

	b.separator(root)
	b.note(root, "Access log")
	if len(s.Uses) == 0 {
		b.note(root, "Nothing read yet")
	}
	var earlier *entry
	for i, u := range s.Uses {
		parent := root
		if i == shownUses {
			earlier = b.add(root, fmt.Sprintf("%d earlier", len(s.Uses)-shownUses), true)
		}
		if earlier != nil {
			parent = earlier
		}
		b.use(parent, u)
	}

	b.separator(root)
	b.note(root, "Held secrets")
	account := ""
	for i, h := range s.Held {
		if i == 0 || h.Account != account {
			account = h.Account
			b.note(root, account)
		}
		name := h.Name
		if h.Origin != "" {
			name += " · " + h.Origin // held for another machine
		}
		e := b.add(root, name+"    "+h.Left, true)
		b.note(e, h.Ref)
		b.separator(e)
		b.action(e, "Forget "+h.Name, Action{Op: OpForget, AccountID: h.AccountID, Ref: h.Ref, Origin: h.Origin})
	}

	b.separator(root)
	b.action(root, "Forget all", Action{Op: OpForgetAll})
	b.action(root, "Stop credlock", Action{Op: OpStop})
	if s.Version != "" {
		b.separator(root)
		b.note(root, "credlock "+s.Version)
	}
	return root, b.actions, b.next
}

// use is one entry of the access log, in two lines as on the Mac: when, and
// what it was for in the requester's words; then which secrets, or what was
// searched for, and whether you were asked. The command, and what went back
// for a search or a failure, are in its submenu.
func (b *menuBuilder) use(parent *entry, u Use) {
	what := u.Reason
	if what == "" && u.Search != "" {
		what = "Search “" + u.Search + "”"
	}
	if what == "" {
		what = u.Command
	}
	var parts []string
	if u.Origin != "" {
		parts = append(parts, u.Origin)
	}
	switch {
	case u.Search != "":
		parts = append(parts, "search “"+u.Search+"”")
		if !u.Failed && u.Summary != "" {
			parts = append(parts, u.Summary)
		}
	case len(u.Names) > 0:
		parts = append(parts, strings.Join(u.Names, ", "))
	case u.Command != "":
		parts = append(parts, u.Command) // what happened, such as "paired with this Mac"
	}
	switch {
	case u.Cached:
		parts = append(parts, "allowed earlier")
	case u.Failed:
		parts = append(parts, "failed after you allowed it")
	default:
		parts = append(parts, "you allowed it")
	}
	e := b.add(parent, u.At+"  "+what+"\n"+strings.Join(parts, " · "), true)
	if len(u.Names) > 0 && u.Command != "" {
		b.note(e, "Command")
		b.note(e, u.Command)
	}
	if len(u.Told) > 0 {
		if u.Search != "" {
			b.note(e, "What went back")
		} else {
			b.note(e, "What its error said")
		}
		for _, line := range u.Told {
			b.note(e, line)
		}
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// escape makes s show as it is in the tray host's menu. The dbusmenu spec
// reads "_" as marking an access key and "__" as one underscore, which KDE
// follows. GNOME's AppIndicator extension instead drops only the first "_"
// that comes before another character, and shows the rest as they are: there,
// a leading "_" and a zero-width space take the drop.
func escape(s string, gnome bool) string {
	if !strings.Contains(s, "_") {
		return s
	}
	if gnome {
		return "_\u200b" + s
	}
	return strings.ReplaceAll(s, "_", "__")
}

// layout is e as GVariant text of type (ia{sv}av), the form GetLayout returns.
func (e *entry) layout() string {
	var b strings.Builder
	e.write(&b)
	return b.String()
}

func (e *entry) write(b *strings.Builder) {
	var props []string
	if e.separator {
		props = append(props, "'type': <'separator'>")
	} else if e.id != 0 {
		props = append(props, "'label': <"+quote(e.label)+">")
		if !e.enabled {
			props = append(props, "'enabled': <false>")
		}
	}
	if len(e.children) > 0 {
		props = append(props, "'children-display': <'submenu'>")
	}
	// Typed throughout: inside a variant, an empty {} or [] has no type to
	// take from its context.
	fmt.Fprintf(b, "(int32 %d, @a{sv} {%s}, @av [", e.id, strings.Join(props, ", "))
	for i, c := range e.children {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("<")
		c.write(b)
		b.WriteString(">")
	}
	b.WriteString("])")
}

// quote is s as a GVariant text string: nothing in it can end the string or
// be read as anything but text.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		switch {
		case r == '\'' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// The tray's icons: a key, as on the Mac, as symbolic icons, so the tray
// draws them in the panel's own colour. While secrets are read, an orange
// dot sits on the key's corner (the theme's warning colour); while there are
// alerts, the key is red (its error colour).
const (
	iconKey     = "credlock-key-symbolic"
	iconReading = "credlock-key-reading-symbolic"
	iconAlert   = "credlock-key-alert-symbolic"
)

const keyShape = `<path d="M5 3.75a4.25 4.25 0 1 0 0 8.5a4.25 4.25 0 1 0 0-8.5zm0 2.5a1.75 1.75 0 1 1 0 3.5a1.75 1.75 0 1 1 0-3.5z" fill-rule="evenodd"/>` +
	`<rect x="8.5" y="7" width="7" height="2"/><rect x="11.5" y="9" width="1.75" height="2.5"/><rect x="14" y="9" width="1.5" height="3"/>`

var icons = map[string]string{
	iconKey:     svg(`<g fill="#2e3436">` + keyShape + `</g>`),
	iconReading: svg(`<g fill="#2e3436">` + keyShape + `</g><circle class="warning" fill="#f57900" cx="13" cy="3.5" r="2.5"/>`),
	iconAlert:   svg(`<g class="error" fill="#cc0000">` + keyShape + `</g>`),
}

func svg(body string) string {
	return `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">` + body + `</svg>` + "\n"
}

// iconFor is the icon for s: red with alerts, dotted while being read.
func iconFor(s Snapshot, reading bool) string {
	switch {
	case len(s.Alerts) > 0:
		return iconAlert
	case reading:
		return iconReading
	default:
		return iconKey
	}
}

// tooltip says what the icon means, as the Mac's does.
func tooltip(s Snapshot, reading bool) string {
	t := fmt.Sprintf("credlock: %d secret%s held", len(s.Held), plural(len(s.Held)))
	if reading {
		t += ", being read now"
	}
	return t
}
