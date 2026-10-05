package approve

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework Cocoa
#include <stdlib.h>
#include "window_darwin.h"
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"
	"unsafe"
)

// AppKit must run on the process's main thread. Locking in an init keeps the
// main goroutine there, so WindowMain, called from main, can use it.
func init() { runtime.LockOSThread() }

// Default is the approver the helper uses: credlock's own window.
func Default(timeout time.Duration) Approver { return Window{Timeout: timeout} }

// WindowMain is `credlock __approve`, the window process. It reads one View
// as JSON on stdin and shows it. On Allow it prints "allow" and returns 0; it
// returns 1 on Deny, 3 when nobody answered in time, and 2 when it could not
// show the window at all.
func WindowMain(stdin io.Reader, stdout io.Writer) int {
	v, err := readView(stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credlock:", err)
		return 2
	}
	js := C.CString(v)
	defer C.free(unsafe.Pointer(js))
	switch C.credlock_window_run(js) {
	case C.CREDLOCK_WINDOW_ALLOW:
		if _, err := fmt.Fprintln(stdout, "allow"); err != nil {
			return 2
		}
		return 0
	case C.CREDLOCK_WINDOW_DENY:
		return windowDenied
	case C.CREDLOCK_WINDOW_TIMED_OUT:
		return windowTimedOut
	default:
		fmt.Fprintln(os.Stderr, "credlock: the approval window could not read its content")
		return 2
	}
}

// readView reads the helper's View and re-encodes it, so the window sees only
// the fields credlock defines.
func readView(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return "", err
	}
	var v View
	if err := json.Unmarshal(data, &v); err != nil {
		return "", fmt.Errorf("reading the approval window's content: %w", err)
	}
	if (len(v.Secrets) == 0 && v.Origin == "") || v.Timeout <= 0 {
		return "", errors.New("the approval window was started without secrets or a timeout")
	}
	out, err := json.Marshal(v)
	return string(out), err
}

// snapshot renders v to a PNG at path without showing it, for checking the
// layout by eye. It must run on the main thread.
func snapshot(v View, path string, dark bool) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	js, p := C.CString(string(data)), C.CString(path)
	defer C.free(unsafe.Pointer(js))
	defer C.free(unsafe.Pointer(p))
	d := C.int(0)
	if dark {
		d = 1
	}
	if C.credlock_window_snapshot(js, p, d) != 0 {
		return fmt.Errorf("rendering %s failed", path)
	}
	return nil
}
