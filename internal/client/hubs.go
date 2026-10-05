package client

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cdmckay/credlock/internal/config"
	"github.com/cdmckay/credlock/internal/proto"
	"github.com/cdmckay/credlock/internal/state"
)

// hubAuth is how this user on this machine proves who they are to hubs, and
// knows the hubs it paired with.
type hubAuth struct {
	key  ed25519.PrivateKey
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
	for res := range fanOut(context.Background(), hubs, check, hubCheck, auth) {
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
// with the key the hub proved itself with. This machine speaks first, with a
// nonce, and the hub signs it: so before saying anything about what it wants,
// this machine knows it reached a credlock hub, and the one it paired with if
// it has (see state.HubProof). The request then signs the hub's challenge
// with this machine user's key. Cancelling ctx closes the connection, which
// the hub takes as a hang-up.
func callHub(ctx context.Context, hub string, req proto.Request, wait time.Duration, auth hubAuth) (proto.Response, string, error) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: hubDial}).DialContext(ctx, "tcp", config.Addr(hub))
	if err != nil {
		return proto.Response{}, "", err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	defer func() { _ = conn.Close() }()
	nonce := make([]byte, state.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return proto.Response{}, "", err
	}
	if err := json.NewEncoder(conn).Encode(proto.Request{Nonce: base64.StdEncoding.EncodeToString(nonce)}); err != nil {
		return proto.Response{}, "", err
	}
	r := bufio.NewReader(conn)
	hello, err := readResponse(ctx, r)
	if err != nil {
		return hello, "", err
	}
	challenge, err := verifyHub(hub, hello, nonce, auth)
	if err != nil {
		return proto.Response{Error: err.Error()}, "", err
	}
	req.Key = state.PublicKey(auth.key)
	req.User = auth.user
	req.Proof = base64.StdEncoding.EncodeToString(ed25519.Sign(auth.key, state.ClientProof(challenge, nonce, hello.HubKey)))
	if !req.NoPrompt && auth.pinned[strings.ToLower(hub)] == "" && auth.say != nil {
		code := state.PairingCode(challenge, nonce, req.Key, hello.HubKey)
		auth.say(fmt.Sprintf("credlock: if %s asks to pair with this machine, its window shows this code:\n\n      %s\n", hub, strings.Join(strings.Split(code, ""), " ")))
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return proto.Response{}, "", err
	}
	resp, err := readResponse(ctx, r)
	return resp, hello.HubKey, err
}

// verifyHub checks the hub's answer to this machine's nonce: signed with the
// key it sent, and that key the one this machine paired with, if it has. It
// returns the hub's challenge.
func verifyHub(hub string, hello proto.Response, nonce []byte, auth hubAuth) ([]byte, error) {
	challenge, err := base64.StdEncoding.DecodeString(hello.Challenge)
	pub, kerr := state.ParsePublicKey(hello.HubKey)
	proof, perr := base64.StdEncoding.DecodeString(hello.HubProof)
	if err != nil || len(challenge) == 0 || kerr != nil || perr != nil || !ed25519.Verify(pub, state.HubProof(nonce, challenge), proof) {
		return nil, fmt.Errorf("refused: what answered at %s couldn't prove it is a credlock hub", hub)
	}
	if pinned := auth.pinned[strings.ToLower(hub)]; pinned != "" && pinned != hello.HubKey {
		return nil, fmt.Errorf("refused: %s answered with a key it didn't pair with, so it may not be credlock on that Mac. "+
			"If credlock was reinstalled there, pair again: credlock pair %s", hub, hub)
	}
	return challenge, nil
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
