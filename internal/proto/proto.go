// Package proto is the wire format between the credlock client and its helper:
// one JSON request line and one JSON response line per connection.
package proto

// HelperCommand is the hidden subcommand the client runs to start the helper.
const HelperCommand = "__helper"

// Ops a request can carry.
const (
	OpResolve = "resolve"
	OpStatus  = "status"
	OpClear   = "clear"
	OpStop    = "stop"
	OpForget  = "forget" // drop this machine's approvals for Secrets' references
	OpHub     = "hub"    // hub mode: Hub says what to do
	OpPair    = "pair"   // over the tailnet: pair this machine user with the hub
	OpSearch  = "search" // item titles in Account containing Search: names only, never values
)

// Hub mode actions, for OpHub.
const (
	HubStatus = "status"
	HubOn     = "on"
	HubOff    = "off"
	HubForget = "forget" // unpair Host
)

// Secret is one environment variable the client wants filled in.
type Secret struct {
	Name string `json:"name"` // the environment variable, e.g. GITHUB_TOKEN
	Ref  string `json:"ref"`  // where it lives, e.g. op://Private/item/field
}

// Request is what the client asks of the helper.
type Request struct {
	Op      string `json:"op"`
	Account string `json:"account,omitempty"`
	// AccountLabel is how the dialog names the account, e.g.
	// "my.1password.com (me@example.com)". Display only.
	AccountLabel string   `json:"account_label,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	Command      []string `json:"command,omitempty"`
	Cwd          string   `json:"cwd,omitempty"`
	Secrets      []Secret `json:"secrets,omitempty"`
	// NoPrompt asks only for what is already approved: a request that needs
	// a new approval gets NotHeld instead of a window. A client asking several
	// hubs uses it first, so a hub that holds the secrets answers before any
	// window opens elsewhere.
	NoPrompt bool `json:"no_prompt,omitempty"`
	// TTL is the most, in seconds, the approval for these secrets should last
	// from now (credlock run --ttl). It is at most an hour, the time an
	// approval lasts after its last use, so it only ever shortens one. Zero
	// for no limit of its own.
	TTL int64 `json:"ttl,omitempty"`
	// Search is what OpSearch looks for in item titles.
	Search string `json:"search,omitempty"`

	// User is the user another machine says is asking. Its key is the one in
	// its TLS certificate, and Nonce its part of a pairing code (see
	// internal/channel).
	User  string `json:"user,omitempty"`
	Nonce string `json:"nonce,omitempty"`

	// For OpHub.
	Hub  string `json:"hub,omitempty"`
	Host string `json:"host,omitempty"`
}

// HubInfo is hub mode as `credlock hub status` shows it.
type HubInfo struct {
	Enabled   bool       `json:"enabled"`
	Tailnet   string     `json:"tailnet,omitempty"`
	Listening []string   `json:"listening,omitempty"`
	Peers     []PeerInfo `json:"peers,omitempty"`
}

// PeerInfo is one paired machine user.
type PeerInfo struct {
	Host     string `json:"host"`
	User     string `json:"user"`
	PairedAt string `json:"paired_at"`
}

// Entry describes one approved secret for `credlock status`. It never carries
// the value.
type Entry struct {
	Account   string `json:"account"`
	Ref       string `json:"ref"`
	ExpiresIn int64  `json:"expires_in"` // seconds
	// Origin is the tailnet host the approval is for; empty for this machine.
	Origin string `json:"origin,omitempty"`
}

// Response is the helper's answer.
type Response struct {
	Values map[string]string `json:"values,omitempty"` // by reference
	Denied bool              `json:"denied,omitempty"`
	// TimedOut marks a denial because nobody answered the dialog.
	TimedOut bool `json:"timed_out,omitempty"`
	// NotHeld answers a NoPrompt request that needs a new approval.
	NotHeld bool    `json:"not_held,omitempty"`
	Error   string  `json:"error,omitempty"`
	Entries []Entry `json:"entries,omitempty"`
	// Commit is a hub's first line to another machine: a hash of its part of
	// a pairing code. Pairing comes before its answer, as it opens its
	// pairing window, with Reveal, that part; the other machine checks it
	// against Commit and shows the code the window shows.
	Commit  string `json:"commit,omitempty"`
	Pairing bool   `json:"pairing,omitempty"`
	Reveal  string `json:"reveal,omitempty"`
	// Paired answers OpPair: this machine user is paired with the hub.
	Paired bool     `json:"paired,omitempty"`
	Hub    *HubInfo `json:"hub,omitempty"`
	PID    int      `json:"pid,omitempty"`
	// Found answers OpSearch.
	Found *Found `json:"found,omitempty"`
}

// MaxFound is as many items as a search names. Past it, the answer counts
// the rest, so the requester searches for something narrower rather than
// missing them.
const MaxFound = 20

// MinSearch is the shortest term a search takes, in characters: a shorter one
// would list nearly everything. MaxSearch is the longest, which the approval
// window shows whole: a term cut for display would search for more than the
// person saw.
const (
	MinSearch = 2
	MaxSearch = 100
)

// Found is what a search found: names, references and field types, never a
// value.
type Found struct {
	Items []FoundItem `json:"items,omitempty"` // best match first
	// More counts the matches past the last of Items.
	More int `json:"more,omitempty"`
	// Unread names the vaults whose items couldn't be listed, and why, so an
	// empty answer isn't taken for "no such item".
	Unread []string `json:"unread,omitempty"`
	// Closed counts the vaults the account can see but not read items in,
	// as an owner of a 1Password Business account sees every vault. They
	// aren't named: that would list the company's vaults for nothing.
	Closed int `json:"closed,omitempty"`
}

// FoundItem is one item a search found.
type FoundItem struct {
	// Ref is op://VAULT/ITEM, ready for a field to be added, with a title
	// where the title works in a reference and an ID where it doesn't.
	Ref   string `json:"ref"`
	Vault string `json:"vault"`
	Title string `json:"title"`
	// Fields names the item's fields, as a fieldNotFound hint does: each
	// one's title, type and section. Why says why they couldn't be listed.
	Fields string `json:"fields,omitempty"`
	Why    string `json:"why,omitempty"`
}
