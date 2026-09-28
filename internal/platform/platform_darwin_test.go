//go:build darwin

package platform

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPeerOfReportsTheCallerFromTheKernel(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "clp")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		if c, err := net.Dial("unix", filepath.Join(dir, "s")); err == nil {
			defer func() { _ = c.Close() }()
			_, _ = c.Read(make([]byte, 1))
		}
	}()
	conn, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	peer, err := PeerOf(conn)
	if err != nil {
		t.Fatal(err)
	}
	if peer.UID != os.Getuid() || peer.PID != os.Getpid() || peer.Name == "" {
		t.Fatalf("got %+v, want uid %d pid %d and a name", peer, os.Getuid(), os.Getpid())
	}
}

func TestPrivateDirTightensAndRefusesSymlinks(t *testing.T) {
	base := t.TempDir()
	loose := filepath.Join(base, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := privateDir(loose); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(loose); fi.Mode().Perm() != 0o700 {
		t.Fatalf("left it at %o", fi.Mode().Perm())
	}

	link := filepath.Join(base, "link")
	if err := os.Symlink(loose, link); err != nil {
		t.Fatal(err)
	}
	if err := privateDir(link); err == nil {
		t.Fatal("accepted a symlink as the socket directory")
	}
}
