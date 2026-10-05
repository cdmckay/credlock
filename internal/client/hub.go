package client

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cdmckay/credlock/internal/platform"
	"github.com/cdmckay/credlock/internal/proto"
)

// Hub is `credlock hub [on|off|status|forget HOST]`, on a Mac: whether it
// answers other machines on its tailnet. Turning it on is all there is to set
// up. The tailnet it's on is remembered, machines pair the first time they
// ask, and a login item keeps it answering after a restart.
func Hub(args []string) int {
	if !platform.HasHelper {
		return fail(fmt.Errorf("hub mode runs on a Mac with the 1Password app; this machine asks one instead (credlock run does that on its own)"))
	}
	req := proto.Request{Op: proto.OpHub, Hub: proto.HubStatus}
	switch {
	case len(args) == 0:
	case len(args) == 1 && (args[0] == proto.HubOn || args[0] == proto.HubOff || args[0] == proto.HubStatus):
		req.Hub = args[0]
	case len(args) == 2 && args[0] == proto.HubForget:
		req.Hub, req.Host = proto.HubForget, args[1]
	default:
		fmt.Fprintln(os.Stderr, "usage: credlock hub [on | off | status | forget HOST]")
		return 2
	}
	resp, err := Call(req, true)
	if err != nil {
		return fail(err)
	}
	switch req.Hub {
	case proto.HubOn:
		if err := installLoginItem(); err != nil {
			fmt.Fprintf(os.Stderr, "credlock: hub mode is on, but it won't come back after a restart until you run credlock hub on again: %v\n", err)
		}
	case proto.HubOff:
		// Rare, so it ends cleanly rather than leaving a helper behind: the
		// helper stops first, so it exits rather than being killed, and
		// forgets every approval, this Mac's own too. Then the login item goes.
		_, stopErr := Call(proto.Request{Op: proto.OpStop}, false)
		if err := removeLoginItem(); err != nil {
			fmt.Fprintf(os.Stderr, "credlock: couldn't remove the login item: %v\n", err)
		}
		printHub(resp.Hub)
		if stopErr != nil && !errors.Is(stopErr, errNotRunning) {
			fmt.Fprintf(os.Stderr, "credlock: couldn't stop the helper (%v); run credlock stop\n", stopErr)
			return 1
		}
		fmt.Println("credlock: the helper stopped, so every approval is gone, this Mac's too.")
		return 0
	case proto.HubForget:
		fmt.Printf("credlock: forgot %s; it pairs again, in a pairing window, the next time it asks (or with credlock pair there)\n", req.Host)
	}
	printHub(resp.Hub)
	return 0
}

func printHub(h *proto.HubInfo) {
	if h == nil || !h.Enabled {
		fmt.Println("credlock: hub mode is off. Only this Mac can ask it for secrets. Turn it on with: credlock hub on")
		return
	}
	where := "not listening yet: is Tailscale connected to that tailnet?"
	if len(h.Listening) > 0 {
		where = "listening on " + strings.Join(h.Listening, ", ")
	}
	fmt.Printf("credlock: hub mode is on, for tailnet %q, %s.\n", h.Tailnet, where)
	fmt.Println("Machines on that tailnet can ask this Mac; each pairs first, with credlock pair or when it first asks, in a pairing window.")
	if len(h.Peers) == 0 {
		fmt.Println("No machines paired yet.")
		return
	}
	fmt.Println("Paired:")
	for _, p := range h.Peers {
		fmt.Printf("  %s on %s, since %s\n", p.User, p.Host, p.PairedAt)
	}
}
