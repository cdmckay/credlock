//go:build linux

package platform

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestTheSocketIsInTheRuntimeDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	path, err := SocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "credlock", "credlock.sock"); path != want {
		t.Fatalf("socket at %s, want %s", path, want)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("its directory: %v, %v", fi, err)
	}
}

func TestARelativeRuntimeDirectoryIsIgnored(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "run")
	dir, err := runtimeDir()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(dir) {
		t.Fatalf("used %q", dir)
	}
}

func TestAProtectedProcessCantBeReadEvenByItsParent(t *testing.T) {
	// Unprotected, a child is the one process Yama's ptrace_scope 1 still
	// lets its parent read, so this shows Protect is what stops it.
	if err := readMemoryOf(t, false); err != nil {
		t.Skipf("this system already keeps a parent out of its child's memory: %v", err)
	}
	if err := readMemoryOf(t, true); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("opening a protected child's memory: got %v, want permission denied", err)
	}
}

// readMemoryOf starts this test binary as a child that protects itself or
// not, and tries to open its memory.
func readMemoryOf(t *testing.T, protect bool) error {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFakeProtectedProcess$")
	cmd.Env = append(os.Environ(), fmt.Sprintf("CREDLOCK_FAKE_PROTECTED=%t", protect))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close(); _ = cmd.Wait() }()
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("the child said %q: %v", line, err)
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", cmd.Process.Pid))
	if err != nil {
		return err
	}
	return f.Close()
}

// TestFakeProtectedProcess is the child readMemoryOf starts, not a test: it
// protects itself if asked, says so, and waits for its stdin to close.
func TestFakeProtectedProcess(t *testing.T) {
	switch os.Getenv("CREDLOCK_FAKE_PROTECTED") {
	case "":
		return
	case "true":
		if err := Protect(); err != nil {
			os.Exit(5)
		}
	}
	fmt.Println("ready")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	os.Exit(0)
}

func TestTheHelperRunsOnlyWhereOnePasswordIs(t *testing.T) {
	saved := sdkLibraries
	t.Cleanup(func() { sdkLibraries = saved })
	lib := filepath.Join(t.TempDir(), "libop_sdk_ipc_client.so")
	sdkLibraries = []string{lib}
	if HasHelper() {
		t.Fatal("a helper without 1Password: a server would stop asking its hub")
	}
	if err := os.WriteFile(lib, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if HasHelper() != hasWindow {
		t.Fatalf("with 1Password installed, HasHelper is %v in a build whose window is %v", HasHelper(), hasWindow)
	}
}
