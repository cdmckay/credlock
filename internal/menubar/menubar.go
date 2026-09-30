// Package menubar is credlock's menu bar icon: a key with the number of
// secrets the helper holds, which turns into an eye while secrets are being
// read. Its menu is the access log, the held secrets, and ways to forget them.
//
// The icon runs as a child of the helper, `credlock __menubar`, because AppKit
// needs a main thread. The helper writes Snapshots to its stdin, one JSON line
// each, and reads Actions from its stdout. A snapshot never carries a secret's
// value, and an action can only take access away.
package menubar

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"sync"
)

// Command is the hidden subcommand that runs the icon.
const Command = "__menubar"

// Snapshot is everything the icon shows.
type Snapshot struct {
	Held []Held `json:"held"`
	Uses []Use  `json:"uses"` // newest first
	// Read means secrets were just handed out: show the eye for a moment.
	Read bool `json:"read,omitempty"`
}

// Held is one approved secret.
type Held struct {
	AccountID string `json:"account_id"` // for forgetting it
	Account   string `json:"account"`    // for showing, e.g. "my.1password.com (me@example.com)"
	Name      string `json:"name"`       // the variable it was last delivered as
	Ref       string `json:"ref"`
	Left      string `json:"left"` // e.g. "48 min left"
}

// Use is one delivery of secrets to a command.
type Use struct {
	At      string   `json:"at"` // e.g. "14:02"
	Command string   `json:"command"`
	Reason  string   `json:"reason"`
	Names   []string `json:"names"`
	// Cached means every secret came from an earlier approval, with no window.
	Cached bool `json:"cached"`
}

// Action is something done from the menu.
type Action struct {
	Op        string `json:"op"` // one of the Op constants
	AccountID string `json:"account_id,omitempty"`
	Ref       string `json:"ref,omitempty"`
}

// Menu actions. Each takes access away; none can grant it.
const (
	OpForget    = "forget"     // forget one secret
	OpForgetAll = "forget_all" // forget every secret
	OpStop      = "stop"       // stop the helper
)

// Bar keeps the icon process showing the latest snapshot. It starts the
// process when there is first something to show, and starts a new one on the
// next snapshot if it dies. Notify never blocks the helper.
type Bar struct {
	onAction func(Action)
	command  func() *exec.Cmd // credlock itself, unless a test swaps in a fake

	mu      sync.Mutex
	pending *Snapshot
	wake    chan struct{}
}

// New makes a Bar that calls onAction for everything done from the menu.
func New(onAction func(Action)) *Bar {
	return &Bar{onAction: onAction, command: selfCommand}
}

// Notify shows s. Snapshots that arrive faster than the icon takes them are
// merged: the last one wins, but a read in any of them still shows the eye.
func (b *Bar) Notify(s Snapshot) {
	b.mu.Lock()
	if b.pending != nil && b.pending.Read {
		s.Read = true
	}
	b.pending = &s
	if b.wake == nil {
		if len(s.Held) == 0 {
			// Nothing to show yet: don't start an icon just to hide it.
			b.pending = nil
			b.mu.Unlock()
			return
		}
		b.wake = make(chan struct{}, 1)
		go b.run()
	}
	b.mu.Unlock()
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

func (b *Bar) take() *Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.pending
	b.pending = nil
	return s
}

func (b *Bar) run() {
	var c *child
	for range b.wake {
		s := b.take()
		if s == nil {
			continue
		}
		// A second try, for an icon that died since the last snapshot but
		// hasn't been noticed yet: the send fails, and a new one gets it.
		for range 2 {
			if c == nil || c.dead() {
				if len(s.Held) == 0 {
					break // nothing to show: don't start one just to hide it
				}
				var err error
				if c, err = b.start(); err != nil {
					c = nil
					break
				}
			}
			if c.send(*s) == nil {
				break
			}
			c.kill()
			c = nil
		}
	}
}

// child is one running icon process.
type child struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	done  chan struct{}
}

func (b *Bar) start() (*child, error) {
	cmd := b.command()
	if cmd == nil {
		return nil, os.ErrNotExist
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &child{cmd: cmd, stdin: stdin, done: make(chan struct{})}
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			var a Action
			if json.Unmarshal(sc.Bytes(), &a) == nil && a.valid() && b.onAction != nil {
				b.onAction(a)
			}
		}
		_ = cmd.Wait()
		close(c.done)
	}()
	return c, nil
}

func (c *child) dead() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *child) send(s Snapshot) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	_, err = c.stdin.Write(append(data, '\n'))
	return err
}

func (c *child) kill() {
	_ = c.stdin.Close()
	if c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
}

func (a Action) valid() bool {
	switch a.Op {
	case OpForget:
		return a.AccountID != "" && a.Ref != ""
	case OpForgetAll, OpStop:
		return true
	}
	return false
}

func selfCommand() *exec.Cmd {
	self, err := os.Executable()
	if err != nil {
		return nil
	}
	return exec.Command(self, Command)
}
