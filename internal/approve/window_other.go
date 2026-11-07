//go:build !darwin && !(linux && gtk)

package approve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// errNoWindow is why this build can't ask: it has no approval window. On
// Linux the window is GTK 4, behind the gtk build tag.
var errNoWindow = errors.New("this credlock has no approval window: on Linux, it is built with the gtk tag " +
	"(go build -tags gtk, or the Nix package's default output)")

// Default is the approver the helper uses. This build has no window, so it
// refuses every request: without one, nothing can count as Allow.
func Default(time.Duration) Approver { return noWindow{} }

type noWindow struct{}

func (noWindow) Approve(context.Context, Request) (bool, error) { return false, errNoWindow }

// WindowMain is `credlock __approve`, which this build doesn't have.
func WindowMain(io.Reader, io.Writer) int {
	fmt.Fprintln(os.Stderr, "credlock:", errNoWindow)
	return 2
}
