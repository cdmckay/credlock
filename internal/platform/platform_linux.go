//go:build linux

package platform

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Supported says whether credlock has this system's half of the helper: where
// its socket lives, and who is calling it.
const Supported = true

// Hub says whether this system can be a hub, answering other machines on its
// tailnet. Only a Mac can so far.
const Hub = false

// HasHelper says whether this system runs a credlock helper. Without one,
// credlock asks the hubs in its config instead, as it always has on Linux.
func HasHelper() bool { return os.Getenv(HelperSwitch) == "1" }

// Protect keeps other processes out of this one's memory, where the helper and
// its resolvers hold secret values. Linux lets a process running as the same
// user read another's memory, through ptrace or /proc/PID/mem, wherever Yama
// allows it: everywhere with ptrace_scope 0, and from an ancestor with 1. A
// process that isn't dumpable can be read only by root, and leaves no core
// dump. exec undoes it, so the command credlock run becomes is an ordinary
// process again.
func Protect() error { return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }

// SocketPath is the helper's socket, inside $XDG_RUNTIME_DIR/credlock: the
// user's own runtime directory, which only they can enter and which goes at
// logout. The credlock directory in it is made private on every call. Never a
// shared directory like /tmp, where another user could plant a socket first
// and collect whatever is sent to it.
func SocketPath() (string, error) {
	base, err := runtimeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "credlock")
	if err := privateDir(dir); err != nil {
		return "", err
	}
	return filepath.Join(dir, "credlock.sock"), nil
}

// runtimeDir is $XDG_RUNTIME_DIR. Where that isn't set, as under cron, it is
// /run/user/UID if that is ours, the same directory under systemd, so the
// helper is found there too; without either, ~/.cache.
func runtimeDir() (string, error) {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(dir) {
		return dir, nil
	}
	dir := fmt.Sprintf("/run/user/%d", os.Getuid())
	if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) == os.Getuid() {
			return dir, nil
		}
	}
	return os.UserCacheDir()
}

// PeerOf asks the kernel who is on the other end of conn. The PID is 0 when
// the caller is in a process namespace this one can't see into.
func PeerOf(conn *net.UnixConn) (Peer, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var cred *unix.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Peer{}, err
	}
	if serr != nil {
		return Peer{}, serr
	}
	peer := Peer{UID: int(cred.Uid), PID: int(cred.Pid)}
	if peer.PID > 0 {
		if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", peer.PID)); err == nil {
			peer.Name = strings.TrimSpace(string(comm))
		}
	}
	return peer, nil
}
