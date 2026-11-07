//go:build darwin

package platform

import (
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Supported says whether credlock has this system's half of the helper: where
// its socket lives, and who is calling it.
const Supported = true

// Hub says whether this system can be a hub, answering other machines on its
// tailnet.
const Hub = true

// HasHelper says whether this system runs a credlock helper. Without one,
// credlock asks the hubs in its config instead.
func HasHelper() bool { return true }

// Protect does nothing on macOS, which already keeps a process's memory from
// others running as the same user: reading it takes root, or a debugger the
// system allows.
func Protect() error { return nil }

// SocketPath is the helper's socket, inside ~/Library/Caches/credlock, which
// is made private on every call. Never a shared directory like /tmp, where
// another user could plant a socket first and collect whatever is sent to it.
func SocketPath() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "credlock")
	if err := privateDir(dir); err != nil {
		return "", err
	}
	return filepath.Join(dir, "credlock.sock"), nil
}

// PeerOf asks the kernel who is on the other end of conn.
func PeerOf(conn *net.UnixConn) (Peer, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var cred *unix.Xucred
	var pid int
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if serr == nil {
			pid, serr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		}
	}); err != nil {
		return Peer{}, err
	}
	if serr != nil {
		return Peer{}, serr
	}
	peer := Peer{UID: int(cred.Uid), PID: pid}
	if kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid); err == nil {
		peer.Name = unix.ByteSliceToString(kp.Proc.P_comm[:])
	}
	return peer, nil
}
