// Command credlock hands secrets to one command at a time, after you have seen
// which secrets are being asked for, by whom, and why.
package main

import (
	"fmt"
	"os"

	"github.com/cdmckay/credlock/internal/client"
	"github.com/cdmckay/credlock/internal/daemon"
	"github.com/cdmckay/credlock/internal/proto"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "0.1.0-dev"

const usage = `credlock hands secrets to one command at a time, after you approve what and why.

Usage:
  credlock run [--reason TEXT] [--account NAME] [--] COMMAND [ARGS...]
      Run COMMAND with every environment variable whose value is an op://
      reference replaced by its secret. Anything not yet approved is shown to
      you in a dialog first. An approval lasts an hour after its last use, and
      a day at most. The account defaults to $CREDLOCK_ACCOUNT, then $OP_ACCOUNT.
      Exits 77 if you deny the request.
  credlock status   Show whether the helper is running and what it holds (never values).
  credlock clear    Forget every approved secret.
  credlock stop     Stop the helper, forgetting everything.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "run":
		os.Exit(client.Run(args))
	case "status":
		os.Exit(client.Status())
	case "clear":
		os.Exit(client.Clear())
	case "stop":
		os.Exit(client.Stop())
	case proto.HelperCommand:
		if err := daemon.Main(version); err != nil {
			fmt.Fprintln(os.Stderr, "credlock helper:", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		fmt.Print(usage)
	case "version", "--version":
		fmt.Println("credlock", version)
	default:
		fmt.Fprintf(os.Stderr, "credlock: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
}
