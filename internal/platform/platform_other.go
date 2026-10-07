//go:build !darwin

package platform

import (
	"errors"
	"net"
)

// On Linux the socket belongs in $XDG_RUNTIME_DIR (per-user, mode 0700, wiped
// at logout) and the peer comes from SO_PEERCRED plus /proc/<pid>/comm. Neither
// is written yet; until then credlock says so rather than guessing.
var errUnsupported = errors.New("credlock only supports macOS so far")

// HasHelper says whether this system runs a credlock helper. Without one,
// credlock asks the hubs in its config instead.
const HasHelper = false

// SocketPath is not implemented on this system yet.
func SocketPath() (string, error) { return "", errUnsupported }

// PeerOf is not implemented on this system yet.
func PeerOf(*net.UnixConn) (Peer, error) { return Peer{}, errUnsupported }
