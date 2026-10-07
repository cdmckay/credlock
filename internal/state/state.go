// Package state is what credlock learns and keeps for itself, so nobody has
// to write it down: on a hub, the machines paired with it; on a remote
// machine, its key and the hubs it has paired with. It lives in
// $XDG_STATE_HOME/credlock (~/.local/state/credlock) on every system, in a
// folder only its owner can open: apart from ~/.config, which people sync and
// commit as dotfiles, since it holds a private key.
package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Dir is the state folder, created mode 0700 if missing. $CREDLOCK_STATE
// overrides it, for tests.
func Dir() (string, error) {
	dir := os.Getenv("CREDLOCK_STATE")
	if dir == "" {
		base := os.Getenv("XDG_STATE_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, ".local", "state")
		}
		dir = filepath.Join(base, "credlock")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := private(dir, true); err != nil {
		return "", err
	}
	return dir, nil
}

// private checks that only this user can reach path.
func private(path string, dir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.IsDir() != dir || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a plain %s", path, map[bool]string{true: "folder", false: "file"}[dir])
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s belongs to someone else", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s can be read by others (mode %o): only its owner should, so run chmod %o %s", path, fi.Mode().Perm(), map[bool]int{true: 0o700, false: 0o600}[dir], path)
	}
	return nil
}

func read(name string, v any) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := private(path, false); err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	return nil
}

// write replaces name atomically, readable only by its owner.
func write(name string, v any) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, name+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}

// Hub is a Mac's hub mode: whether it answers other machines, on which
// tailnet, and the machines paired with it.
type Hub struct {
	Enabled bool   `json:"enabled"`
	Tailnet string `json:"tailnet,omitempty"` // the tailnet it was turned on in
	// Peers are the paired machines, by PeerID.
	Peers map[string]Peer `json:"peers,omitempty"`
}

// Peer is a machine user paired with this hub.
type Peer struct {
	Host     string    `json:"host"` // its Tailscale name
	User     string    `json:"user"` // as it reported itself
	Key      string    `json:"key"`  // its public key
	PairedAt time.Time `json:"paired_at"`
}

// PeerID names a user on a machine: "cdmckay@papaya".
func PeerID(user, host string) string { return user + "@" + host }

// LoadHub reads hub mode; never set up is off.
func LoadHub() (Hub, error) {
	var h Hub
	err := read("hub.json", &h)
	return h, err
}

// Save writes hub mode.
func (h Hub) Save() error { return write("hub.json", h) }

// Client is what a machine without 1Password remembers: the hubs it has
// paired with, which it then asks, and each one's own key.
type Client struct {
	Hubs []string `json:"hubs,omitempty"`
	// Keys are the paired hubs' keys, by hub name in lower case. A hub that
	// answers with another key isn't the credlock this machine paired with.
	Keys map[string]string `json:"keys,omitempty"`
}

// LoadClient reads the paired hubs.
func LoadClient() (Client, error) {
	var c Client
	err := read("client.json", &c)
	return c, err
}

// Save writes the paired hubs.
func (c Client) Save() error { return write("client.json", c) }

// Forget drops hub and its key, and says whether it was there.
func (c *Client) Forget(hub string) bool {
	_, had := c.Keys[strings.ToLower(hub)]
	delete(c.Keys, strings.ToLower(hub))
	kept := c.Hubs[:0]
	for _, h := range c.Hubs {
		if strings.EqualFold(h, hub) {
			had = true
			continue
		}
		kept = append(kept, h)
	}
	c.Hubs = kept
	return had
}

// Remember adds hub, with its key, to the paired hubs, and says whether
// anything changed.
func (c *Client) Remember(hub, key string) bool {
	changed := c.Keys[strings.ToLower(hub)] != key
	if c.Keys == nil {
		c.Keys = map[string]string{}
	}
	c.Keys[strings.ToLower(hub)] = key
	for _, h := range c.Hubs {
		if strings.EqualFold(h, hub) {
			return changed
		}
	}
	c.Hubs = append(c.Hubs, hub)
	return true
}

const keyPrefix = "ed25519:"

// Key is this user's credlock key on this machine, made on first use and
// readable only by them. A hub pairs with it, so another user on the same
// machine, without it, can't ask in their name; and a hub proves itself with
// its own, which a paired machine checks, so another user on the hub's Mac
// can't answer in its place.
func Key() (ed25519.PrivateKey, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "key")
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		line := base64.StdEncoding.EncodeToString(priv.Seed()) + "\n"
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		if _, err := f.WriteString(line); err != nil {
			_ = f.Close()
			return nil, err
		}
		return priv, f.Close()
	}
	if err != nil {
		return nil, err
	}
	if err := private(path, false); err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s is not a credlock key", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// PublicKey is how a key is shown and stored: "ed25519:…".
func PublicKey(priv ed25519.PrivateKey) string {
	return EncodeKey(priv.Public().(ed25519.PublicKey))
}

// EncodeKey writes a public key as PublicKey does.
func EncodeKey(pub ed25519.PublicKey) string {
	return keyPrefix + base64.StdEncoding.EncodeToString(pub)
}

// ParsePublicKey reads a key PublicKey wrote.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, keyPrefix))
	if !strings.HasPrefix(s, keyPrefix) || err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("not a credlock public key")
	}
	return ed25519.PublicKey(b), nil
}

// Phone is what a hub keeps for approving from a phone (#14): its VAPID key,
// which signs every push, and the phone's push subscription.
type Phone struct {
	// VAPID is the hub's push-signing key, PKCS #8 DER.
	VAPID []byte `json:"vapid,omitempty"`
	// Device is the phone's Tailscale name, Subscription its push
	// subscription as the browser gave it.
	Device       string          `json:"device,omitempty"`
	Subscription json.RawMessage `json:"subscription,omitempty"`
}

// LoadPhone reads the phone state; never set up is empty.
func LoadPhone() (Phone, error) {
	var p Phone
	err := read("phone.json", &p)
	return p, err
}

// Save writes the phone state.
func (p Phone) Save() error { return write("phone.json", p) }
