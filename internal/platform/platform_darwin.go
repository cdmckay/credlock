//go:build darwin

package platform

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

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

// privateDir makes dir if needed and insists it is this user's alone: a real
// directory, not a symlink to one, owned by us and mode 0700.
func privateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not owned by you", dir)
	}
	if fi.Mode().Perm() != 0o700 {
		return os.Chmod(dir, 0o700)
	}
	return nil
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
