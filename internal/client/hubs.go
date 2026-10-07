package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cdmckay/credlock/internal/channel"
	"github.com/cdmckay/credlock/internal/config"
	"github.com/cdmckay/credlock/internal/proto"
)

// hubAuth is how this user on this machine proves who they are to hubs, and
// knows the hubs it paired with.
type hubAuth struct {
	cert tls.Certificate // this machine user's key, for TLS
	user string
	// pinned is the key each paired hub proved itself with, by hub name in
	// lower case. A hub not in it is trusted on first use, as SSH trusts a
	// new host.
	pinned map[string]string
	// say shows a pairing code to the person, on stderr.
	say func(string)
}

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
//
// It returns the hub that answered, with the key it proved itself with.
func askHubs(hubs []string, req proto.Request, auth hubAuth) (hubResult, error) {
	check := req
	check.NoPrompt = true
	var reachable []string
	var failures []string
	offline := false
	checking, stop := context.WithCancel(context.Background())
	defer stop() // closes the checks still waiting once one hub has answered
	for res := range fanOut(checking, hubs, check, hubCheck, auth) {
		switch {
		case res.err != nil:
			failures = append(failures, fmt.Sprintf("%s: %v", res.hub, res.err))
			offline = offline || res.resp.Error == "" // unreachable, rather than refused
		case res.resp.NotHeld:
			reachable = append(reachable, res.hub)
		default:
			return res, nil // that hub already holds them all
		}
	}
	if len(reachable) == 0 {
		return hubResult{}, &unreachable{failures, offline}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // closes every other hub's connection, and so its window
	timedOut := false
	for res := range fanOut(ctx, reachable, req, hubAsk, auth) {
		switch {
		case res.err != nil:
			if ctx.Err() == nil {
				failures = append(failures, fmt.Sprintf("%s: %v", res.hub, res.err))
			}
		case res.resp.TimedOut:
			timedOut = true
		case res.resp.Denied, len(res.resp.Values) > 0:
			return res, nil
		}
	}
	if timedOut {
		return hubResult{resp: proto.Response{Denied: true, TimedOut: true}}, nil
	}
	return hubResult{}, errors.New(strings.Join(failures, "; "))
}

// unreachable is no hub taking the request: offline, or refusing it.
type unreachable struct {
	failures []string
	offline  bool // some couldn't be reached at all
}

func (e *unreachable) Error() string {
	msg := "no hub took the request: " + strings.Join(e.failures, "; ")
	if e.offline {
		msg += ". Check that the Mac is online on the tailnet, with hub mode on (credlock hub on)"
	}
	return msg
}

type hubResult struct {
	hub  string
	key  string // the key the hub proved itself with
	resp proto.Response
	err  error
}

// fanOut sends req to every hub at once and yields each answer as it comes.
// The channel closes once every hub has answered or failed.
func fanOut(ctx context.Context, hubs []string, req proto.Request, wait time.Duration, auth hubAuth) <-chan hubResult {
	out := make(chan hubResult, len(hubs))
	done := make(chan struct{}, len(hubs))
	for _, hub := range hubs {
		go func() {
			resp, key, err := callHub(ctx, hub, req, wait, auth)
			out <- hubResult{hub: hub, key: key, resp: resp, err: err}
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

// callHub sends one request to one hub over the tailnet and reads its answer,
// with the key the hub proved itself with. The connection is TLS 1.3 with
// this machine user's key and the hub's (see internal/channel), and the hub's
// key is checked against the one this machine paired with, if it has, before
// anything is sent. If the hub opens its pairing window, it says so first, and
// the code shows here. Cancelling ctx closes the connection, which the hub
// takes as a hang-up.
func callHub(ctx context.Context, hub string, req proto.Request, wait time.Duration, auth hubAuth) (proto.Response, string, error) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	raw, err := (&net.Dialer{Timeout: hubDial}).DialContext(ctx, "tcp", config.Addr(hub))
	if err != nil {
		return proto.Response{}, "", err
	}
	var refused error
	conn := channel.Client(raw, auth.cert, func(hubKey string) error {
		if pinned := auth.pinned[strings.ToLower(hub)]; pinned != "" && pinned != hubKey {
			refused = fmt.Errorf("refused: %s answered with a different key from the one it paired with. "+
				"If credlock was reinstalled there, forget the old key (credlock pair --forget %s), then pair again, "+
				"and only if its window shows the code printed here. If it wasn't, something else may be answering for %s", hub, hub, hub)
			return refused
		}
		return nil
	})
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	defer func() { _ = conn.Close() }()
	handshake, done := context.WithTimeout(ctx, hubCheck)
	err = conn.HandshakeContext(handshake)
	done()
	switch {
	case refused != nil:
		return refuse(refused.Error())
	case err != nil && ctx.Err() != nil:
		return proto.Response{}, "", ctx.Err()
	case err != nil:
		return refuse(fmt.Sprintf("refused: %s didn't complete credlock's handshake (%v). Check that it runs credlock hub on "+
			"with a current credlock, and that nothing else there uses port %d", hub, err, config.DefaultPort))
	}
	cs := conn.ConnectionState()
	hubKey, err := channel.PeerKey(cs)
	if err != nil {
		return proto.Response{}, "", err
	}
	// The hub commits to its part of a pairing code first; only then does
	// this machine send its own (see channel.PairingCode).
	r := bufio.NewReader(conn)
	first, err := readResponse(ctx, r)
	if err != nil {
		return first, hubKey, err
	}
	commit, err := base64.StdEncoding.DecodeString(first.Commit)
	if err != nil || len(commit) == 0 {
		return refuse(fmt.Sprintf("refused: %s didn't commit to a pairing code. Check that it runs a credlock as current as this one", hub))
	}
	ours := make([]byte, channel.NonceSize)
	if _, err := rand.Read(ours); err != nil {
		return proto.Response{}, "", err
	}
	req.User, req.Nonce = auth.user, base64.StdEncoding.EncodeToString(ours)
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return proto.Response{}, "", err
	}
	for {
		resp, err := readResponse(ctx, r)
		if err != nil || !resp.Pairing {
			return resp, hubKey, err
		}
		theirs, err := base64.StdEncoding.DecodeString(resp.Reveal)
		code, cerr := channel.PairingCode(cs, theirs, ours)
		if err != nil || cerr != nil || !bytes.Equal(channel.Commit(theirs), commit) {
			return refuse(fmt.Sprintf("refused: %s's pairing code isn't the one it committed to, so something may be in the middle. This machine hung up, which closes the window there; don't pair with it", hub))
		}
		if auth.say != nil {
			auth.say(fmt.Sprintf("credlock: %s is asking whether to pair with this machine. Pair only if its window shows this code:\n\n      %s\n", hub, strings.Join(strings.Split(code, ""), " ")))
		}
	}
}

// refuse is a refusal from a hub: an answer, not a hub that can't be reached.
func refuse(msg string) (proto.Response, string, error) {
	return proto.Response{Error: msg}, "", errors.New(msg)
}

func readResponse(ctx context.Context, r *bufio.Reader) (proto.Response, error) {
	line, err := r.ReadBytes('\n')
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
