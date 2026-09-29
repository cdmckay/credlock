//go:build !darwin

package approve

import (
	"fmt"
	"io"
	"os"
	"time"
)

// Default is the approver the helper uses. Outside macOS, credlock has no
// window of its own yet, so it is the zenity dialog.
func Default(timeout time.Duration) Approver { return Dialog{Timeout: timeout} }

// WindowMain is `credlock __approve`, which only exists on macOS so far.
func WindowMain(io.Reader, io.Writer) int {
	fmt.Fprintln(os.Stderr, "credlock: the approval window is macOS-only so far")
	return 2
}
