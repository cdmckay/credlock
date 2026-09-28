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
)

// Secret is one environment variable the client wants filled in.
type Secret struct {
	Name string `json:"name"` // the environment variable, e.g. GITHUB_TOKEN
	Ref  string `json:"ref"`  // where it lives, e.g. op://Private/item/field
}

// Request is what the client asks of the helper.
type Request struct {
	Op      string   `json:"op"`
	Account string   `json:"account,omitempty"`
	Reason  string   `json:"reason,omitempty"`
	Command []string `json:"command,omitempty"`
	Cwd     string   `json:"cwd,omitempty"`
	Secrets []Secret `json:"secrets,omitempty"`
}

// Entry describes one approved secret for `credlock status`. It never carries
// the value.
type Entry struct {
	Account   string `json:"account"`
	Ref       string `json:"ref"`
	ExpiresIn int64  `json:"expires_in"` // seconds
}

// Response is the helper's answer.
type Response struct {
	Values  map[string]string `json:"values,omitempty"` // by reference
	Denied  bool              `json:"denied,omitempty"`
	Error   string            `json:"error,omitempty"`
	Entries []Entry           `json:"entries,omitempty"`
	PID     int               `json:"pid,omitempty"`
}
