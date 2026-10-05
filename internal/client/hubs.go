package client

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cdmckay/credlock/internal/config"
	"github.com/cdmckay/credlock/internal/proto"
)

const (
	hubDial  = 3 * time.Second  // to reach a hub at all
	hubCheck = 15 * time.Second // for "do you already hold these?"
	// hubAsk covers a hub's approval window and its fetch from 1Password.
	hubAsk = 10 * time.Minute
)

// askHubs asks every hub at once, for a machine with no helper of its own.
//
// First it asks only for what each hub already holds, with NoPrompt: if any
// does, that answer is used and no window opens anywhere. Otherwise it asks
// every hub that answered, and each shows its window. The first decisive
// answer wins: values, or an explicit Deny, which ends the request everywhere.
// The other hubs' connections are then closed, which closes their windows. A
// hub that can't be reached, or whose window times out, doesn't count; the
// request fails only if no hub says yes.
func askHubs(hubs []string, req proto.Request) (proto.Response, error) {
	check := req
	check.NoPrompt = true
	var reachable []string
	var failures []string
	for res := range fanOut(context.Background(), hubs, check, hubCheck) {
		switch {
		case res.err != nil:
			failures = append(failures, fmt.Sprintf("%s: %v", res.hub, res.err))
		case res.resp.NotHeld:
			reachable = append(reachable, res.hub)
		default:
			return res.resp, nil // that hub already holds them all
		}
	}
	if len(reachable) == 0 {
		return proto.Response{}, fmt.Errorf("no hub could be asked (%s). Check that a hub is online on the tailnet, and that this machine is in its hub.allow",
			strings.Join(failures, "; "))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // closes every other hub's connection, and so its window
	timedOut := false
	for res := range fanOut(ctx, reachable, req, hubAsk) {
		switch {
		case res.err != nil:
			if ctx.Err() == nil {
				failures = append(failures, fmt.Sprintf("%s: %v", res.hub, res.err))
			}
		case res.resp.TimedOut:
			timedOut = true
		case res.resp.Denied, len(res.resp.Values) > 0:
			return res.resp, nil
		}
	}
	if timedOut {
		return proto.Response{Denied: true, TimedOut: true}, nil
	}
	return proto.Response{}, errors.New(strings.Join(failures, "; "))
}

type hubResult struct {
	hub  string
	resp proto.Response
	err  error
}

// fanOut sends req to every hub at once and yields each answer as it comes.
// The channel closes once every hub has answered or failed.
func fanOut(ctx context.Context, hubs []string, req proto.Request, wait time.Duration) <-chan hubResult {
	out := make(chan hubResult, len(hubs))
	done := make(chan struct{}, len(hubs))
	for _, hub := range hubs {
		go func() {
			resp, err := callHub(ctx, config.Addr(hub), req, wait)
			out <- hubResult{hub: hub, resp: resp, err: err}
			done <- struct{}{}
		}()
	}
	go func() {
		for range hubs {
			<-done
		}
		close(out)
	}()
	return out
}

// callHub sends one request to one hub over the tailnet and reads its answer.
// Cancelling ctx closes the connection, which the hub takes as a hang-up.
func callHub(ctx context.Context, addr string, req proto.Request, wait time.Duration) (proto.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: hubDial}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return proto.Response{}, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	defer func() { _ = conn.Close() }()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return proto.Response{}, err
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		if ctx.Err() != nil {
			return proto.Response{}, ctx.Err()
		}
		return proto.Response{}, fmt.Errorf("reading its answer: %w", err)
	}
	var resp proto.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return proto.Response{}, err
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}
