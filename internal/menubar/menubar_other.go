//go:build !darwin

package menubar

import (
	"fmt"
	"io"
	"os"
)

// Supported says whether this system has a menu bar icon.
const Supported = false

// Main is `credlock __menubar`, which only exists on macOS so far.
func Main(io.Reader, io.Writer) int {
	fmt.Fprintln(os.Stderr, "credlock: the menu bar icon is macOS-only so far")
	return 2
}
