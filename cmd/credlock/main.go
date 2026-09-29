// Command credlock hands secrets to one command at a time, after you have seen
// which secrets are being asked for, by whom, and why.
package main

import (
	"fmt"
	"os"

	"github.com/cdmckay/credlock/internal/approve"
	"github.com/cdmckay/credlock/internal/client"
	"github.com/cdmckay/credlock/internal/daemon"
	"github.com/cdmckay/credlock/internal/proto"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, overview)
		os.Exit(2)
	}
	os.Exit(dispatch(os.Args[1], os.Args[2:]))
}

func dispatch(cmd string, args []string) int {
	switch cmd {
	case "run":
		if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
			fmt.Print(runHelp)
			return 0
		}
		return client.Run(args)
	case "status":
		return client.Status()
	case "clear":
		return client.Clear()
	case "stop":
		return client.Stop()
	case proto.HelperCommand:
		if err := daemon.Main(version); err != nil {
			fmt.Fprintln(os.Stderr, "credlock helper:", err)
			return 1
		}
		return 0
	case approve.WindowCommand:
		return approve.WindowMain(os.Stdin, os.Stdout)
	case "help", "-h", "--help":
		if len(args) > 0 && args[0] == "run" {
			fmt.Print(runHelp)
		} else {
			fmt.Print(overview)
		}
		return 0
	case "version", "--version":
		fmt.Println("credlock", version)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "credlock: unknown command %q; see 'credlock help'\n", cmd)
		return 2
	}
}
