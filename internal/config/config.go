// Package config reads credlock's settings, from ~/.config/credlock/config.toml
// unless $CREDLOCK_CONFIG names another file. No setting is needed: they only
// pin what credlock otherwise works out for itself.
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

// Config is the whole file. Nothing in it is needed: it pins what credlock
// would otherwise work out for itself.
type Config struct {
	Client Client `toml:"client"`
}

// Client is for a machine without 1Password, which asks hubs for secrets.
type Client struct {
	// Hubs are the tailnet hosts to ask, e.g. "potato", or "potato:7177", in
	// place of the hubs this machine has paired with (credlock pair).
	// All are asked at once.
	Hubs []string `toml:"hubs"`
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
	return c, nil
}

// Addr is a hub's address: the host as given, with DefaultPort unless it
// names its own.
func Addr(hub string) string {
	if _, _, err := net.SplitHostPort(hub); err == nil {
		return hub
	}
	return net.JoinHostPort(hub, strconv.Itoa(DefaultPort))
}
