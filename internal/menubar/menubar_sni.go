//go:build linux && gtk

package menubar

/*
#cgo pkg-config: gio-2.0
#include <stdlib.h>
#include "menubar_sni.h"
*/
import "C"

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/cdmckay/credlock/internal/platform"
)

// Supported says whether this system has a menu bar icon. On Linux it is a
// tray icon, which the panel shows if it hosts StatusNotifierItems: KDE and
// most desktops do, GNOME with its AppIndicator extension.
const Supported = true

// dotFor is how long the reading icon stays after the last read, as on the
// Mac.
const dotFor = 4 * time.Second

// tray is the icon process's state: the latest snapshot and the menu built
// from it.
var tray struct {
	mu      sync.Mutex
	snap    Snapshot
	have    bool
	reading bool
	dot     *time.Timer
	gnome   bool             // the panel is gnome-shell's
	lastID  int32            // the last id given to a menu item
	actions map[int32]Action // what the current menu's items do
	out     io.Writer        // where actions go: the helper
	outMu   sync.Mutex
}

// Main is `credlock __menubar`, the icon process. It shows each Snapshot read
// from stdin, writes an Action to stdout for each thing done from the menu,
// and exits when stdin closes, which is when the helper exits.
func Main(stdin io.Reader, stdout io.Writer) int {
	dir, err := writeIcons()
	if err != nil {
		fmt.Fprintln(os.Stderr, "credlock: the tray icon's images:", err)
		return 2
	}
	tray.mu.Lock()
	tray.out = stdout
	tray.mu.Unlock()
	go func() {
		sc := bufio.NewScanner(stdin)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var s Snapshot
			if json.Unmarshal(sc.Bytes(), &s) == nil {
				show(s)
			}
		}
		C.credlock_tray_quit()
	}()
	d := C.CString(dir)
	defer C.free(unsafe.Pointer(d))
	if C.credlock_tray_run(d) != 0 {
		fmt.Fprintln(os.Stderr, "credlock: the tray icon could not reach the session bus")
		return 2
	}
	return 0
}

// writeIcons puts the icons beside the helper's socket, in a directory only
// this user can read, where the panel finds them by name.
func writeIcons() (string, error) {
	sock, err := platform.SocketPath()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(filepath.Dir(sock), "icons")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for name, svg := range icons {
		if err := os.WriteFile(filepath.Join(dir, name+".svg"), []byte(svg), 0o600); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// show takes a snapshot: a read shows the reading icon until dotFor after
// the last one.
func show(s Snapshot) {
	tray.mu.Lock()
	defer tray.mu.Unlock()
	tray.snap, tray.have = s, true
	if s.Read && (len(s.Held) > 0 || s.Recent) {
		tray.reading = true
		if tray.dot != nil {
			tray.dot.Stop()
		}
		tray.dot = time.AfterFunc(dotFor, func() {
			tray.mu.Lock()
			defer tray.mu.Unlock()
			tray.reading = false
			push()
		})
	}
	push()
}

// push hands the latest snapshot to the icon. The caller holds tray.mu.
func push() {
	if !tray.have {
		return
	}
	s := tray.snap
	root, actions, last := buildMenu(s, tray.lastID, tray.gnome)
	l := C.CString(root.layout())
	i, n := C.CString(iconFor(s, tray.reading)), C.CString(strconv.Itoa(len(s.Held)))
	tip := C.CString(tooltip(s, tray.reading))
	defer func() {
		for _, p := range []*C.char{l, i, n, tip} {
			C.free(unsafe.Pointer(p))
		}
	}()
	if !layoutOK(l) {
		return // never show a menu that doesn't parse: keep the last one
	}
	tray.lastID, tray.actions = last, actions
	active := C.int(0)
	if s.shows() {
		active = 1
	}
	C.credlock_tray_update(l, i, n, tip, active)
}

// layoutOK says whether layout parses as the menu's GVariant type.
func layoutOK(layout *C.char) bool { return C.credlock_tray_layout_ok(layout) != 0 }

// parses is layoutOK for a Go string.
func parses(layout string) bool {
	l := C.CString(layout)
	defer C.free(unsafe.Pointer(l))
	return layoutOK(l)
}

//export credlockTrayEvent
func credlockTrayEvent(id C.int) {
	tray.mu.Lock()
	a, ok := tray.actions[int32(id)]
	out := tray.out
	tray.mu.Unlock()
	if !ok || !a.valid() || out == nil {
		return
	}
	data, err := json.Marshal(a)
	if err != nil {
		return
	}
	tray.outMu.Lock()
	defer tray.outMu.Unlock()
	_, _ = out.Write(append(data, '\n'))
}

//export credlockTrayHost
func credlockTrayHost(gnome C.int) {
	tray.mu.Lock()
	defer tray.mu.Unlock()
	tray.gnome = gnome != 0
	push()
}
