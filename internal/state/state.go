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
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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
// paired with, which it then asks instead of searching the tailnet.
type Client struct {
	Hubs []string `json:"hubs,omitempty"`
}

// LoadClient reads the paired hubs.
func LoadClient() (Client, error) {
	var c Client
	err := read("client.json", &c)
	return c, err
}

// Save writes the paired hubs.
func (c Client) Save() error { return write("client.json", c) }

// Remember adds hub to the paired hubs, if it isn't there yet.
func (c *Client) Remember(hub string) bool {
	for _, h := range c.Hubs {
		if strings.EqualFold(h, hub) {
			return false
		}
	}
	c.Hubs = append(c.Hubs, hub)
	return true
}

const keyPrefix = "ed25519:"

// Key is this user's credlock key on this machine, made on first use and
// readable only by them. A hub pairs with it, so another user on the same
// machine, without it, can't ask in their name.
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

// PublicKey is how a key is sent and stored: "ed25519:…".
func PublicKey(priv ed25519.PrivateKey) string {
	return keyPrefix + base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

// ParsePublicKey reads a key PublicKey wrote.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, keyPrefix))
	if !strings.HasPrefix(s, keyPrefix) || err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("not a credlock public key")
	}
	return ed25519.PublicKey(b), nil
}

// PairingCode is the four digits a hub's window and the remote's terminal both
// show for one pairing, from the hub's challenge and the remote's key.
func PairingCode(challenge []byte, publicKey string) string {
	sum := sha256.Sum256(append(append([]byte{}, challenge...), publicKey...))
	return fmt.Sprintf("%04d", binary.BigEndian.Uint32(sum[:4])%10000)
}
