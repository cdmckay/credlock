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

// serveTailnet listens on port at each of this Mac's Tailscale addresses, and
// on every tick follows them as they change: Tailscale may start after the
// helper, or switch to another tailnet. Only the tailnet can reach these
// listeners, never the local network.
func (s *Server) serveTailnet(port int, ticks <-chan time.Time) {
	listening := map[string]net.Listener{}
	for {
		ips, err := tailscaleIPs()
		if err != nil {
			fmt.Fprintln(os.Stderr, "credlock hub:", err)
		}
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
	id, label, err := client.ResolveAccount(req.Account, s.Accounts())
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

// tailscaleIPs are this machine's Tailscale addresses.
func tailscaleIPs() ([]string, error) {
	cli := tailscaleCLI()
	if cli == "" {
		return nil, errors.New("the tailscale command isn't installed, so the hub can't listen on the tailnet")
	}
	out, err := exec.Command(cli, "ip").Output()
	if err != nil {
		return nil, fmt.Errorf("tailscale ip: %w (is Tailscale running?)", err)
	}
	var ips []string
	for _, f := range strings.Fields(string(out)) {
		if net.ParseIP(f) != nil {
			ips = append(ips, f)
		}
	}
	sort.Strings(ips)
	return ips, nil
}

// whois asks Tailscale which machine is at addr, by its tailnet name.
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
			Name         string // e.g. "papaya.tail1234.ts.net."
			ComputedName string // e.g. "papaya"
		}
	}
	if err := json.Unmarshal(out, &who); err != nil {
		return "", err
	}
	if who.Node.ComputedName != "" {
		return who.Node.ComputedName, nil
	}
	if name, _, _ := strings.Cut(who.Node.Name, "."); name != "" {
		return name, nil
	}
	return "", fmt.Errorf("tailscale has no name for %s", host)
}
