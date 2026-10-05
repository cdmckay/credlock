package daemon

import (
	"bufio"
	"context"
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

	"github.com/cdmckay/credlock/internal/client"
	"github.com/cdmckay/credlock/internal/config"
	"github.com/cdmckay/credlock/internal/proto"
)

// Allow sets the tailnet hosts that may ask this helper, which makes it a hub.
func (s *Server) Allow(hosts []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allow = map[string]bool{}
	for _, h := range hosts {
		s.allow[strings.ToLower(h)] = true
	}
}

func (s *Server) allowed(host string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allow[strings.ToLower(host)]
}

// serveTailnet listens at each of this Mac's Tailscale addresses while it is
// on hub.Tailnet, and on every tick follows them as they change: Tailscale may
// start after the helper, or switch to another tailnet, where the hub stops
// listening. Only the tailnet can reach these listeners, never the local
// network.
func (s *Server) serveTailnet(hub config.Hub, ticks <-chan time.Time) {
	listening := map[string]net.Listener{}
	reported := ""
	for {
		var ips []string
		st, err := tailscaleStatus()
		switch {
		case err != nil:
			fmt.Fprintln(os.Stderr, "credlock hub:", err)
		case !strings.EqualFold(st.Tailnet, hub.Tailnet):
			if reported != st.Tailnet {
				fmt.Fprintf(os.Stderr, "credlock hub: on tailnet %q, not %q: not listening\n", st.Tailnet, hub.Tailnet)
				reported = st.Tailnet
			}
		default:
			ips = st.IPs
			reported = ""
		}
		suffix := ""
		if len(ips) > 0 {
			suffix = st.Suffix
		}
		s.mu.Lock()
		s.suffix = suffix
		s.mu.Unlock()
		port := hub.ListenPort()
		want := map[string]bool{}
		for _, ip := range ips {
			want[ip] = true
			if listening[ip] != nil {
				continue
			}
			ln, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
			if err != nil {
				fmt.Fprintln(os.Stderr, "credlock hub:", err)
				continue
			}
			listening[ip] = ln
			go s.serveRemote(ln)
		}
		for ip, ln := range listening {
			if !want[ip] {
				_ = ln.Close()
				delete(listening, ip)
			}
		}
		if _, ok := <-ticks; !ok {
			for _, ln := range listening {
				_ = ln.Close()
			}
			return
		}
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
// machine it is; only resolving is served, and only to hosts in the allow
// list. Everything it approves is kept for that host alone.
func (s *Server) handleRemote(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	host, err := s.Identify(conn.RemoteAddr())
	if err != nil {
		reply(conn, proto.Response{Error: "refused: this hub couldn't tell which tailnet device you are: " + err.Error()})
		return
	}
	if !s.allowed(host) {
		reply(conn, proto.Response{Error: fmt.Sprintf("refused: %s is not in this hub's allow list (hub.allow in its credlock config)", host)})
		return
	}
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
	if req.Op != proto.OpResolve {
		reply(conn, proto.Response{Error: fmt.Sprintf("refused: a hub only resolves for other machines, not %q", req.Op)})
		return
	}
	// The remote machine has no op to resolve "my" or an email with.
	id, label, err := client.ResolveAccount(req.Account, s.accountList())
	if err != nil {
		reply(conn, proto.Response{Error: err.Error()})
		return
	}
	req.Account, req.AccountLabel = id, label
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchHangup(conn, cancel)
	reply(conn, s.resolve(ctx, req, host, host+", over Tailscale"))
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
	Tailnet string   // e.g. "cdmckay.org"
	Suffix  string   // its MagicDNS domain, e.g. "tail1234.ts.net"
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
		Self           *struct{ TailscaleIPs []string }
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return tailnetState{}, err
	}
	var state tailnetState
	if st.CurrentTailnet != nil {
		state.Tailnet, state.Suffix = st.CurrentTailnet.Name, st.CurrentTailnet.MagicDNSSuffix
	}
	if st.BackendState == "Running" && st.Self != nil {
		for _, ip := range st.Self.TailscaleIPs {
			if net.ParseIP(ip) != nil {
				state.IPs = append(state.IPs, ip)
			}
		}
		sort.Strings(state.IPs)
	}
	return state, nil
}

// identify names the device at addr by its Tailscale name, if it belongs to
// the tailnet the hub serves. Its full name must be in that tailnet's domain,
// so a device from another tailnet, or shared in from one, can't pass for a
// name in the allow list.
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
