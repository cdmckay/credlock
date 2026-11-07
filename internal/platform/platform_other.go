//go:build !darwin && !linux

package platform

import (
	"errors"
	"net"
)

var errUnsupported = errors.New("credlock only supports macOS and Linux so far")

// Supported says whether credlock has this system's half of the helper: where
// its socket lives, and who is calling it.
const Supported = false

// Hub says whether this system can be a hub, answering other machines on its
// tailnet.
const Hub = false

// HasHelper says whether this system runs a credlock helper. Without one,
// credlock asks the hubs in its config instead.
func HasHelper() bool { return false }

// Protect does nothing here: no helper runs on this system.
func Protect() error { return nil }

// SocketPath is not implemented on this system yet.
func SocketPath() (string, error) { return "", errUnsupported }

// PeerOf is not implemented on this system yet.
func PeerOf(*net.UnixConn) (Peer, error) { return Peer{}, errUnsupported }
