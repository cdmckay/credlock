package daemon

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdmckay/credlock/internal/approve"
	"github.com/cdmckay/credlock/internal/client"
	"github.com/cdmckay/credlock/internal/config"
	"github.com/cdmckay/credlock/internal/menubar"
	"github.com/cdmckay/credlock/internal/proto"
	"github.com/cdmckay/credlock/internal/state"
)

// serveTailnet keeps the hub's listeners in step with hub mode: while it is
// on, and this Mac is on the tailnet it was turned on in, it listens at each
// of the Mac's Tailscale addresses; otherwise at none. It looks again on every
// tick, and whenever hub mode changes. Only the tailnet can reach these
// listeners, never the local network.
func (s *Server) serveTailnet(ticks <-chan time.Time) {
	listening := map[string]net.Listener{}
	reported := ""
	for {
		s.mu.Lock()
		hub := s.hub
		s.mu.Unlock()
		var ips []string
		suffix, self := "", ""
		if hub.Enabled {
			st, err := s.Tailnet()
			switch {
			case err != nil:
				if reported != err.Error() {
					fmt.Fprintln(os.Stderr, "credlock hub:", err)
					reported = err.Error()
				}
			case !strings.EqualFold(st.Tailnet, hub.Tailnet):
				if msg := fmt.Sprintf("on tailnet %q, not %q, where hub mode was turned on: not listening", st.Tailnet, hub.Tailnet); reported != msg {
					fmt.Fprintln(os.Stderr, "credlock hub:", msg)
					reported = msg
				}
			default:
				ips, suffix, self, reported = st.IPs, st.Suffix, st.Self, ""
			}
		}
		want := map[string]bool{}
		for _, ip := range ips {
			want[ip] = true
			if listening[ip] != nil {
				continue
			}
			ln, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(config.DefaultPort)))
			if err != nil {
				fmt.Fprintln(os.Stderr, "credlock hub:", err)
				continue
			}
			listening[ip] = ln
			go s.serveRemote(ln)
		}
		var addrs []string
		for ip, ln := range listening {
			if !want[ip] {
				_ = ln.Close()
				delete(listening, ip)
				continue
			}
			addrs = append(addrs, ln.Addr().String())
		}
		sort.Strings(addrs)
		s.mu.Lock()
		s.suffix, s.self, s.listening = suffix, self, addrs
		s.mu.Unlock()
		select {
		case <-s.hubWake:
		case _, ok := <-ticks:
			if !ok {
				for _, ln := range listening {
					_ = ln.Close()
				}
				return
			}
		}
	}
}

func (s *Server) wakeHub() {
	select {
	case s.hubWake <- struct{}{}:
	default:
	}
}

func (s *Server) serveRemote(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go s.handleRemote(conn)
	}
}

// handleRemote answers another machine on the tailnet. Tailscale says which
// machine it is. The machine then proves it holds the key it sends, by signing
// a challenge: a key paired with this hub is that user on that machine. An
// unpaired one is a first pairing, which the approval window shows and Allow
// completes. A key that differs from the paired one is refused outright, with
// no window to accept it in: the person unpairs the machine on the hub, and
// it pairs again as new. Only resolving is served, and everything approved is kept
// for that user on that machine alone.
func (s *Server) handleRemote(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	host, err := s.Identify(conn.RemoteAddr())
	if err != nil {
		reply(conn, proto.Response{Error: "refused: " + err.Error()})
		return
	}
	// Anything on this Mac must use the local socket, where the kernel says
	// which user is asking. Over the tailnet, any user here would be "this
	// Mac", and could try to pair under someone else's name.
	s.mu.Lock()
	self := s.self
	s.mu.Unlock()
	if self != "" && strings.EqualFold(host, self) {
		reply(conn, proto.Response{Error: "refused: this is the hub's own machine; ask through its local socket instead (credlock run does)"})
		return
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return
	}
	reply(conn, proto.Response{Challenge: base64.StdEncoding.EncodeToString(challenge)})

	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(conn, maxRequest)).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	var req proto.Request
	if err := json.Unmarshal(line, &req); err != nil {
		reply(conn, proto.Response{Error: "bad request: " + err.Error()})
		return
	}
	if req.Op != proto.OpResolve && req.Op != proto.OpPair {
		reply(conn, proto.Response{Error: fmt.Sprintf("refused: a hub only pairs and resolves for other machines, not %q", req.Op)})
		return
	}
	pub, err := state.ParsePublicKey(req.Key)
	proof, perr := base64.StdEncoding.DecodeString(req.Proof)
	if err != nil || perr != nil || !ed25519.Verify(pub, challenge, proof) {
		reply(conn, proto.Response{Error: "refused: the request isn't signed with the key it sent"})
		return
	}
	user := approve.Clean(req.User, 40)
	if user == "" {
		user = "someone"
	}
	id := state.PeerID(user, host)

	from := asker{
		origin:    id,
		requester: fmt.Sprintf("%s on %s, over Tailscale", user, host),
		host:      host,
	}
	s.mu.Lock()
	peer, known := s.hub.Peers[id]
	s.mu.Unlock()
	switch {
	case known && peer.Key != req.Key:
		// A reinstall has no key at all, so a different one is no accident:
		// refuse it, and tell the person. The pairing stays, so an attacker
		// doesn't get a fresh pairing window by trying.
		s.alert(fmt.Sprintf("%s on %s asked with a key it didn't pair with, possibly an attack. It was refused.", user, host))
		reply(conn, proto.Response{Error: fmt.Sprintf("refused: %s on %s paired with this hub using a different key. "+
			"If credlock was reinstalled there, unpair it on the hub (credlock hub forget %s), then pair again (credlock pair %s)", user, host, host, s.selfName())})
		return
	case known && req.Op == proto.OpPair:
		reply(conn, proto.Response{Paired: true})
		return
	case !known:
		if until, cooling := s.coolingDown(host); cooling {
			reply(conn, proto.Response{Error: fmt.Sprintf("refused: too many pairing requests from %s were denied; try again after %s", host, until.Local().Format("15:04"))})
			return
		}
		from.pairing = "new"
		from.code = state.PairingCode(challenge, req.Key)
		from.pair = func() error {
			return s.pairPeer(state.Peer{Host: host, User: user, Key: req.Key, PairedAt: s.Now()})
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchHangup(conn, cancel)
	if req.Op == proto.OpPair {
		resp := s.pairOnly(ctx, req, from)
		s.countPairing(host, resp)
		reply(conn, resp)
		return
	}

	// The remote machine has no op to resolve "my" or an email with.
	accountID, label, err := client.ResolveAccount(req.Account, s.accountList())
	if err != nil {
		reply(conn, proto.Response{Error: err.Error()})
		return
	}
	req.Account, req.AccountLabel = accountID, label
	if from.pairing != "" {
		if req.NoPrompt {
			reply(conn, proto.Response{NotHeld: true}) // a check never opens a window
			return
		}
		// One window, one job: pair first, in the pairing window, and only
		// then ask about the secrets, in the usual one.
		resp := s.pairOnly(ctx, req, from)
		s.countPairing(host, resp)
		if !resp.Paired {
			reply(conn, resp)
			return
		}
		from.pairing, from.code, from.pair = "", "", nil
	}
	reply(conn, s.resolve(ctx, req, from))
}

// pairOnly asks the person whether to pair a machine user, with no secrets
// involved: `credlock pair` on the other machine.
func (s *Server) pairOnly(ctx context.Context, req proto.Request, from asker) proto.Response {
	s.asking.Lock()
	defer s.asking.Unlock()
	ok, err := s.Approver.Approve(ctx, approve.Request{
		Reason:    req.Reason,
		Command:   req.Command,
		Cwd:       req.Cwd,
		Requester: from.requester,
		Origin:    from.host,
		Pairing:   from.pairing,
		Code:      from.code,
		Window:    Window,
		Cap:       Cap,
	}) // no Secrets: the pairing window shows none, whatever the request wants
	switch {
	case errors.Is(err, approve.ErrTimedOut):
		return proto.Response{Denied: true, TimedOut: true}
	case ctx.Err() != nil:
		return proto.Response{Error: "the asker hung up before you answered"}
	case err != nil:
		return proto.Response{Error: "showing the approval window: " + err.Error()}
	case !ok:
		return proto.Response{Denied: true}
	}
	if err := from.pair(); err != nil {
		return proto.Response{Error: "pairing: " + err.Error()}
	}
	s.mu.Lock()
	s.uses = append([]menubar.Use{{At: s.Now().Format("15:04"), Command: "paired with this Mac", Reason: approve.Clean(req.Reason, 120), Origin: from.origin}}, s.uses...)
	if len(s.uses) > maxUses {
		s.uses = s.uses[:maxUses]
	}
	s.mu.Unlock()
	s.notify(false)
	return proto.Response{Paired: true}
}

// pairingDenials is how many pairing requests from one machine were denied,
// and until when it is refused once that reached maxPairingDenials.
type pairingDenials struct {
	count int
	until time.Time
}

const (
	maxPairingDenials = 5
	pairingCooldown   = time.Hour
)

// countPairing notes how a pairing request ended. A Deny counts; a window
// nobody answered doesn't. The fifth denial refuses the machine's pairing
// requests for an hour, so a device can't keep putting windows up until one
// is allowed by habit, and an accidental Deny or two costs nothing.
func (s *Server) countPairing(host string, resp proto.Response) {
	s.mu.Lock()
	if s.denials == nil {
		s.denials = map[string]*pairingDenials{}
	}
	d := s.denials[host]
	if d == nil {
		d = &pairingDenials{}
		s.denials[host] = d
	}
	var alert string
	switch {
	case resp.Paired || len(resp.Values) > 0:
		delete(s.denials, host)
	case resp.Denied && !resp.TimedOut:
		d.count++
		if d.count >= maxPairingDenials {
			d.count, d.until = 0, s.Now().Add(pairingCooldown)
			alert = fmt.Sprintf("%d pairing requests from %s were denied, so its requests to pair are refused until %s.", maxPairingDenials, host, d.until.Local().Format("15:04"))
		}
	}
	s.mu.Unlock()
	if alert != "" {
		s.alert(alert)
	}
}

func (s *Server) coolingDown(host string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.denials[host]; d != nil && s.Now().Before(d.until) {
		return d.until, true
	}
	return time.Time{}, false
}

// alert tells the person something they should look at: the menu bar key
// turns red, and the menu says what happened, until they dismiss it.
func (s *Server) alert(text string) {
	fmt.Fprintln(os.Stderr, "credlock hub:", text)
	s.mu.Lock()
	s.alerts = append([]menubar.Alert{{At: s.Now().Format("15:04"), Text: text}}, s.alerts...)
	if len(s.alerts) > 20 {
		s.alerts = s.alerts[:20]
	}
	s.mu.Unlock()
	s.notify(false)
}

func (s *Server) selfName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != "" {
		return s.self
	}
	return "THIS-MAC"
}

// pairPeer remembers a machine user, once the person has allowed it.
func (s *Server) pairPeer(p state.Peer) error {
	return s.updateHub(func(h *state.Hub) { h.Peers[state.PeerID(p.User, p.Host)] = p })
}

// forgetOrigin drops every approval held for one origin.
func (s *Server) forgetOrigin(origin string) {
	s.mu.Lock()
	for k := range s.cache.entries {
		if k.origin == origin {
			delete(s.cache.entries, k)
		}
	}
	s.mu.Unlock()
	s.notify(false)
}

// hubOp is `credlock hub`: turning hub mode on and off, unpairing a machine,
// and saying where things stand.
func (s *Server) hubOp(req proto.Request) proto.Response {
	switch req.Hub {
	case proto.HubOn:
		st, err := s.Tailnet()
		if err != nil {
			return proto.Response{Error: err.Error()}
		}
		if len(st.IPs) == 0 || st.Tailnet == "" {
			return proto.Response{Error: "Tailscale isn't connected: connect this Mac to the tailnet the other machines are on, then run credlock hub on again"}
		}
		if err := s.updateHub(func(h *state.Hub) { h.Enabled, h.Tailnet = true, st.Tailnet }); err != nil {
			return proto.Response{Error: err.Error()}
		}
	case proto.HubOff:
		if err := s.updateHub(func(h *state.Hub) { h.Enabled = false }); err != nil {
			return proto.Response{Error: err.Error()}
		}
	case proto.HubForget:
		var gone []string
		if err := s.updateHub(func(h *state.Hub) {
			for id, p := range h.Peers {
				if strings.EqualFold(p.Host, req.Host) {
					gone = append(gone, id)
					delete(h.Peers, id)
				}
			}
		}); err != nil {
			return proto.Response{Error: err.Error()}
		}
		if len(gone) == 0 {
			return proto.Response{Error: fmt.Sprintf("%s isn't paired with this Mac", req.Host)}
		}
		for _, id := range gone {
			s.forgetOrigin(id)
		}
	case proto.HubStatus, "":
	default:
		return proto.Response{Error: fmt.Sprintf("unknown hub action %q", req.Hub)}
	}
	if req.Hub == proto.HubOn || req.Hub == proto.HubOff {
		s.wakeHub()
		time.Sleep(200 * time.Millisecond) // let the listener catch up, for the status below
	}
	return proto.Response{Hub: s.hubInfo()}
}

// updateHub changes hub mode and saves it; on a failed save nothing changes.
func (s *Server) updateHub(change func(*state.Hub)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hub := s.hub
	hub.Peers = map[string]state.Peer{}
	for id, p := range s.hub.Peers {
		hub.Peers[id] = p
	}
	change(&hub)
	if err := s.SaveHub(hub); err != nil {
		return err
	}
	s.hub = hub
	return nil
}

func (s *Server) hubInfo() *proto.HubInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	info := &proto.HubInfo{Enabled: s.hub.Enabled, Tailnet: s.hub.Tailnet, Listening: append([]string(nil), s.listening...)}
	for _, p := range s.hub.Peers {
		info.Peers = append(info.Peers, proto.PeerInfo{Host: p.Host, User: p.User, PairedAt: p.PairedAt.Local().Format("2006-01-02 15:04")})
	}
	sort.Slice(info.Peers, func(i, j int) bool {
		return state.PeerID(info.Peers[i].User, info.Peers[i].Host) < state.PeerID(info.Peers[j].User, info.Peers[j].Host)
	})
	return info
}

// accountList is this Mac's 1Password accounts: the first list Accounts
// gives, kept, so op is asked once rather than on every request. Without one
// (1Password locked, or no op), accounts pass through as given, which works
// for an account ID.
func (s *Server) accountList() []client.Account {
	s.mu.Lock()
	known := s.known
	s.mu.Unlock()
	if known != nil {
		return known
	}
	got := s.Accounts()
	if len(got) > 0 {
		s.mu.Lock()
		s.known = got
		s.mu.Unlock()
	}
	return got
}

var tailscaleCLI = sync.OnceValue(func() string {
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p
	}
	for _, p := range []string{
		"/Applications/Tailscale.app/Contents/MacOS/Tailscale",
		"/usr/local/bin/tailscale",
		"/opt/homebrew/bin/tailscale",
		"/run/current-system/sw/bin/tailscale",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
})

// tailnetState is what Tailscale says about this machine now.
type tailnetState struct {
	Tailnet string   // e.g. "example.org"
	Suffix  string   // its MagicDNS domain, e.g. "tail1234.ts.net"
	Self    string   // this machine's own name on it, e.g. "potato"
	IPs     []string // empty unless Tailscale is running
}

func tailscaleStatus() (tailnetState, error) {
	cli := tailscaleCLI()
	if cli == "" {
		return tailnetState{}, errors.New("the tailscale command isn't installed, so the hub can't listen on the tailnet")
	}
	out, err := exec.Command(cli, "status", "--json").Output()
	if err != nil {
		return tailnetState{}, fmt.Errorf("tailscale status: %w (is Tailscale running?)", err)
	}
	var st struct {
		BackendState   string
		CurrentTailnet *struct{ Name, MagicDNSSuffix string }
		Self           *struct {
			DNSName      string
			TailscaleIPs []string
		}
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return tailnetState{}, err
	}
	var ts tailnetState
	if st.CurrentTailnet != nil {
		ts.Tailnet, ts.Suffix = st.CurrentTailnet.Name, st.CurrentTailnet.MagicDNSSuffix
	}
	if st.Self != nil {
		ts.Self, _ = inTailnet(st.Self.DNSName, ts.Suffix)
	}
	if st.BackendState == "Running" && st.Self != nil {
		for _, ip := range st.Self.TailscaleIPs {
			if net.ParseIP(ip) != nil {
				ts.IPs = append(ts.IPs, ip)
			}
		}
		sort.Strings(ts.IPs)
	}
	return ts, nil
}

// identify names the device at addr by its Tailscale name, if it belongs to
// the tailnet the hub serves. Its full name must be in that tailnet's domain,
// so a device from another tailnet, or shared in from one, can't pass for one
// of its own.
func (s *Server) identify(addr net.Addr) (string, error) {
	fqdn, err := whois(addr)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	suffix := s.suffix
	s.mu.Unlock()
	host, ok := inTailnet(fqdn, suffix)
	if !ok {
		return "", fmt.Errorf("%s isn't a device of this hub's tailnet", strings.TrimSuffix(fqdn, "."))
	}
	return host, nil
}

// inTailnet returns the device's short name when fqdn is a device directly in
// the tailnet whose MagicDNS domain is suffix: "papaya.tail1234.ts.net." in
// "tail1234.ts.net" is "papaya".
func inTailnet(fqdn, suffix string) (string, bool) {
	fqdn = strings.TrimSuffix(strings.ToLower(fqdn), ".")
	suffix = strings.Trim(strings.ToLower(suffix), ".")
	host, rest, ok := strings.Cut(fqdn, ".")
	if !ok || host == "" || suffix == "" || rest != suffix {
		return "", false
	}
	return host, true
}

// whois asks Tailscale for the full name of the device at addr.
func whois(addr net.Addr) (string, error) {
	cli := tailscaleCLI()
	if cli == "" {
		return "", errors.New("the tailscale command isn't installed")
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", err
	}
	out, err := exec.Command(cli, "whois", "--json", host).Output()
	if err != nil {
		return "", fmt.Errorf("tailscale whois %s: %w", host, err)
	}
	var who struct {
		Node struct {
			Name string // e.g. "papaya.tail1234.ts.net."
		}
	}
	if err := json.Unmarshal(out, &who); err != nil {
		return "", err
	}
	if who.Node.Name == "" {
		return "", fmt.Errorf("tailscale has no name for %s", host)
	}
	return who.Node.Name, nil
}
