//go:build !darwin && !(linux && gtk)

package menubar

import (
	"fmt"
	"io"
	"os"
)

// Supported says whether this system has a menu bar icon.
const Supported = false

// Main is `credlock __menubar`, which this build doesn't have. On Linux the
// tray icon is behind the gtk build tag, with the approval window.
func Main(io.Reader, io.Writer) int {
	fmt.Fprintln(os.Stderr, "credlock: this credlock has no menu bar or tray icon")
	return 2
}
