package menubar

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework Cocoa
#include <stdlib.h>
#include "menubar_darwin.h"
*/
import "C"

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"runtime"
	"sync"
	"unsafe"
)

// Supported says whether this system has a menu bar icon.
const Supported = true

// AppKit must run on the process's main thread. Locking in an init keeps the
// main goroutine there, so Main, called from main, can use it.
func init() { runtime.LockOSThread() }

var (
	actionsMu sync.Mutex
	actions   io.Writer
)

// Main is `credlock __menubar`, the icon process. It shows each Snapshot read
// from stdin, writes an Action to stdout for each thing done from the menu,
// and exits when stdin closes, which is when the helper exits.
func Main(stdin io.Reader, stdout io.Writer) int {
	actionsMu.Lock()
	actions = stdout
	actionsMu.Unlock()
	go func() {
		sc := bufio.NewScanner(stdin)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			// Re-encode, so the icon sees only the fields credlock defines.
			var s Snapshot
			if json.Unmarshal(sc.Bytes(), &s) != nil {
				continue
			}
			data, err := json.Marshal(s)
			if err != nil {
				continue
			}
			js := C.CString(string(data))
			C.credlock_menubar_update(js)
			C.free(unsafe.Pointer(js))
		}
		C.credlock_menubar_quit()
	}()
	C.credlock_menubar_run()
	return 0
}

// iconSnapshot renders the icon to a PNG at path, for checking it by eye. It
// must run on the main thread.
func iconSnapshot(path string, dark bool) error {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	d := C.int(0)
	if dark {
		d = 1
	}
	if C.credlock_menubar_icon_snapshot(p, d) != 0 {
		return os.ErrInvalid
	}
	return nil
}

//export credlockMenubarAction
func credlockMenubarAction(js *C.char) {
	var a Action
	if json.Unmarshal([]byte(C.GoString(js)), &a) != nil || !a.valid() {
		return
	}
	data, err := json.Marshal(a)
	if err != nil {
		return
	}
	actionsMu.Lock()
	defer actionsMu.Unlock()
	if actions != nil {
		_, _ = actions.Write(append(data, '\n'))
	}
}
