//go:build linux && gtk

package approve

/*
#cgo pkg-config: gtk4 libadwaita-1
#include <stdlib.h>
#include "window_gtk.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"
	"unsafe"

	"github.com/cdmckay/credlock/internal/platform"
)

// GTK must run on the thread it started on, the process's main thread.
// Locking in an init keeps the main goroutine there, so WindowMain, called
// from main, can use it.
func init() { runtime.LockOSThread() }

// Default is the approver the helper uses: credlock's own window.
func Default(timeout time.Duration) Approver { return Window{Timeout: timeout} }

// hubViews says whether this window shows requests from other machines and
// pairings. Only a Mac can be a hub so far, so nothing here produces them.
const hubViews = false

// WindowMain is `credlock __approve`, the window process. It reads one View
// as JSON on stdin and shows it. On Allow it prints "allow" and returns 0; it
// returns 1 on Deny, 3 when nobody answered in time, and 2 when it could not
// show the window at all.
func WindowMain(stdin io.Reader, stdout io.Writer) int {
	v, err := parseView(stdin)
	if err == nil {
		err = showable(v)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "credlock:", err)
		return 2
	}
	// Under Wayland, other programs can't click in this window or read it.
	// Under X11 any of them could click Allow, so it isn't shown there.
	if os.Getenv("WAYLAND_DISPLAY") == "" {
		fmt.Fprintln(os.Stderr, "credlock: the approval window needs a Wayland session: under X11, any program could click its Allow")
		return 2
	}
	_ = os.Setenv("GDK_BACKEND", "wayland")
	if C.credlock_window_start() != 0 {
		fmt.Fprintln(os.Stderr, "credlock: the approval window could not start GTK; is there a display?")
		return 2
	}
	// Only now that GTK has read the desktop's settings: its portal doesn't
	// answer a process that isn't dumpable, and the window would show light
	// in dark mode. It holds no secret, but nothing may attach to it and
	// answer for the person, so it is protected before it shows anything.
	if err := platform.Protect(); err != nil {
		fmt.Fprintln(os.Stderr, "credlock: keeping other processes out of the approval window:", err)
		return 2
	}
	cv, free := cView(v)
	defer free()
	switch C.credlock_window_run(cv) {
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
		fmt.Fprintln(os.Stderr, "credlock: the approval window could not start GTK; is there a display?")
		return 2
	}
}

// showable refuses what only a hub produces. A View with an origin or a
// pairing here came from somewhere it shouldn't have.
func showable(v View) error {
	if v.Origin != "" || v.Kind == "pair" {
		return errors.New("requests from other machines reach only a Mac's window so far")
	}
	return nil
}

// cView copies v into C memory for the window, and returns how to free it.
func cView(v View) (*C.credlock_view, func()) {
	var strs []*C.char
	s := func(str string) *C.char {
		p := C.CString(str)
		strs = append(strs, p)
		return p
	}
	cv := (*C.credlock_view)(C.calloc(1, C.size_t(unsafe.Sizeof(C.credlock_view{}))))
	cv.kind, cv.title, cv.subtitle, cv.question = s(v.Kind), s(v.Title), s(v.Subtitle), s(v.Question)
	cv.reason, cv.command, cv.directory, cv.requester = s(v.Reason), s(v.Command), s(v.Directory), s(v.Requester)
	cv.account, cv.lifetime, cv.secrets_title = s(v.Account), s(v.Lifetime), s(v.SecretsTitle)
	cv.approved, cv.footer = s(v.Approved), s(v.Footer)
	cv.origin, cv.origin_title, cv.origin_note, cv.origin_tone = s(v.Origin), s(v.OriginTitle), s(v.OriginNote), s(v.OriginTone)
	cv.code, cv.code_note, cv.search, cv.search_note = s(v.Code), s(v.CodeNote), s(v.Search), s(v.SearchNote)
	cv.timeout = C.int(v.Timeout)
	if n := len(v.Secrets); n > 0 {
		secrets := (*[1 << 20]C.credlock_secret)(C.calloc(C.size_t(n), C.size_t(unsafe.Sizeof(C.credlock_secret{}))))[:n:n]
		for i, sec := range v.Secrets {
			secrets[i].name, secrets[i].ref = s(sec.Name), s(sec.Ref)
		}
		cv.secrets, cv.n_secrets = &secrets[0], C.int(n)
	}
	return cv, func() {
		for _, p := range strs {
			C.free(unsafe.Pointer(p))
		}
		if cv.secrets != nil {
			C.free(unsafe.Pointer(cv.secrets))
		}
		C.free(unsafe.Pointer(cv))
	}
}

// snapshot renders v to a PNG at path, for checking the layout by eye. It
// must run on the main thread. Unlike the Mac's, it puts the window on
// screen for a moment: GTK only draws what is shown.
func snapshot(v View, path string, dark bool) error {
	if err := showable(v); err != nil {
		return err
	}
	_ = os.Setenv("GDK_BACKEND", "wayland")
	cv, free := cView(v)
	defer free()
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	d := C.int(0)
	if dark {
		d = 1
	}
	if C.credlock_window_snapshot(cv, p, d) != 0 {
		return fmt.Errorf("rendering %s failed", path)
	}
	return nil
}
