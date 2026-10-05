// Package config reads credlock's settings, from ~/.config/credlock/config.toml
// unless $CREDLOCK_CONFIG names another file. A machine with no file has no
// hubs and serves none: the settings only matter for asking or serving across
// the tailnet.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// DefaultPort is the tailnet port a hub listens on, and clients ask.
const DefaultPort = 7177

// Config is the whole file.
type Config struct {
	Client Client `toml:"client"`
	Hub    Hub    `toml:"hub"`
}

// Client is for a machine without 1Password, which asks hubs for secrets.
type Client struct {
	// Hubs are the tailnet hosts to ask, e.g. "potato", or "potato:7177". All
	// are asked at once.
	Hubs []string `toml:"hubs"`
}

// Hub is for a Mac that resolves secrets for other machines on the tailnet.
type Hub struct {
	// Tailnet is the tailnet the names in Allow belong to, e.g. "cdmckay.org".
	// The hub serves only while this Mac is on it: a name means nothing on
	// another tailnet, where anyone could have a device called "papaya".
	Tailnet string `toml:"tailnet"`
	// Allow is every tailnet host that may ask, by its Tailscale name. A hub
	// with none listens only on its local socket.
	Allow []string `toml:"allow"`
	// Port is where it listens on its Tailscale addresses; DefaultPort if 0.
	Port int `toml:"port"`
}

// Path is where the settings are read from.
func Path() string {
	if p := os.Getenv("CREDLOCK_CONFIG"); p != "" {
		return p
	}
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "credlock", "config.toml")
}

// Load reads the settings. A missing file is no settings, not an error; a
// misspelled key is an error, so a typo can't silently turn a feature off.
func Load() (Config, error) {
	var c Config
	path := Path()
	if path == "" {
		return c, nil
	}
	md, err := toml.DecodeFile(path, &c)
	if errors.Is(err, fs.ErrNotExist) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("reading %s: %w", path, err)
	}
	if bad := md.Undecoded(); len(bad) > 0 {
		keys := make([]string, len(bad))
		for i, k := range bad {
			keys[i] = k.String()
		}
		return Config{}, fmt.Errorf("%s: unknown setting %s", path, strings.Join(keys, ", "))
	}
	if len(c.Hub.Allow) > 0 && c.Hub.Tailnet == "" {
		return Config{}, fmt.Errorf(`%s: hub.allow needs hub.tailnet, the tailnet those names belong to (e.g. tailnet = "cdmckay.org", as 'tailscale switch --list' shows it)`, path)
	}
	if c.Hub.Port < 0 || c.Hub.Port > 65535 {
		return Config{}, fmt.Errorf("%s: hub.port %d is not a port", path, c.Hub.Port)
	}
	return c, nil
}

// ListenPort is the hub's port.
func (h Hub) ListenPort() int {
	if h.Port == 0 {
		return DefaultPort
	}
	return h.Port
}

// Addr is a hub's address: the host as given, with DefaultPort unless it
// names its own.
func Addr(hub string) string {
	if _, _, err := net.SplitHostPort(hub); err == nil {
		return hub
	}
	return net.JoinHostPort(hub, strconv.Itoa(DefaultPort))
}
