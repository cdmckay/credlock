package channel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/cdmckay/credlock/internal/state"
)

func newCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := Certificate(key)
	if err != nil {
		t.Fatal(err)
	}
	return cert, state.PublicKey(key)
}

// end is one side of a finished handshake.
type end struct {
	conn *tls.Conn
	key  string // the other side's
	code string
	err  error
}

func finish(conn *tls.Conn) end {
	e := end{conn: conn}
	if e.err = conn.Handshake(); e.err != nil {
		return e
	}
	cs := conn.ConnectionState()
	if e.key, e.err = PeerKey(cs); e.err != nil {
		return e
	}
	e.code, e.err = PairingCode(cs, hubNonce, machineNonce)
	return e
}

var (
	hubNonce     = bytes.Repeat([]byte("h"), NonceSize)
	machineNonce = bytes.Repeat([]byte("m"), NonceSize)
)

// tcp is two ends of a loopback TCP connection. A net.Pipe won't do: it has
// no buffer, so a TLS alert nobody reads blocks for ever.
func tcp(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b := <-accepted
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

// connect shakes hands between a client and a server.
func connect(t *testing.T, client func(net.Conn) *tls.Conn, server func(net.Conn) *tls.Conn) (c, s end) {
	a, b := tcp(t)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s = finish(server(b))
		if s.err != nil {
			_ = b.Close()
		}
	}()
	c = finish(client(a))
	if c.err != nil {
		_ = a.Close()
	}
	wg.Wait()
	return c, s
}

func trustAny(string) error { return nil }

func TestBothEndsLearnEachOthersKeyAndShowTheSameCode(t *testing.T) {
	machine, machineKey := newCert(t)
	hub, hubKey := newCert(t)
	var checked string
	c, s := connect(t,
		func(conn net.Conn) *tls.Conn {
			return Client(conn, machine, func(k string) error { checked = k; return nil })
		},
		func(conn net.Conn) *tls.Conn { return Server(conn, hub) })
	if c.err != nil || s.err != nil {
		t.Fatalf("handshake: %v, %v", c.err, s.err)
	}
	if checked != hubKey || c.key != hubKey || s.key != machineKey {
		t.Fatalf("keys: checked %s, client saw %s, server saw %s", checked, c.key, s.key)
	}
	if len(c.code) != 4 || strings.Trim(c.code, "0123456789") != "" || c.code != s.code {
		t.Fatalf("codes %q and %q", c.code, s.code)
	}
}

func TestAHubKeyTheCheckRefusesEndsTheHandshake(t *testing.T) {
	machine, _ := newCert(t)
	hub, _ := newCert(t)
	refused := errors.New("not the hub this machine paired with")
	c, s := connect(t,
		func(conn net.Conn) *tls.Conn {
			return Client(conn, machine, func(string) error { return refused })
		},
		func(conn net.Conn) *tls.Conn { return Server(conn, hub) })
	if !errors.Is(c.err, refused) || s.err == nil {
		t.Fatalf("client %v, server %v", c.err, s.err)
	}
}

func TestAMachineWithoutACertificateIsRefused(t *testing.T) {
	hub, _ := newCert(t)
	c, s := connect(t,
		func(conn net.Conn) *tls.Conn {
			return tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		},
		func(conn net.Conn) *tls.Conn { return Server(conn, hub) })
	if s.err == nil {
		t.Fatalf("the hub took a machine with no key (client: %v)", c.err)
	}
}

// Something in the middle has to hold a TLS session with each end, and each
// session has its own code, so the person sees two different ones.
func TestSomethingInTheMiddleShowsEachEndADifferentCode(t *testing.T) {
	machine, _ := newCert(t)
	hub, _ := newCert(t)
	middle, _ := newCert(t)
	a, b := tcp(t) // machine to middle
	x, y := tcp(t) // middle to hub
	var wg sync.WaitGroup
	var toMachine, toHub, atHub end
	wg.Add(3)
	go func() { defer wg.Done(); toMachine = finish(Server(b, middle)) }()
	go func() { defer wg.Done(); toHub = finish(Client(x, middle, trustAny)) }()
	go func() { defer wg.Done(); atHub = finish(Server(y, hub)) }()
	atMachine := finish(Client(a, machine, trustAny))
	wg.Wait()
	for _, e := range []end{atMachine, toMachine, toHub, atHub} {
		if e.err != nil {
			t.Fatal(e.err)
		}
	}
	if atMachine.code != toMachine.code || toHub.code != atHub.code {
		t.Fatal("a session's two ends disagree on its code")
	}
	if atMachine.code == atHub.code {
		t.Skipf("the two sessions' codes collided (1 in 10,000): %s", atMachine.code)
	}
}

// Whatever relays the bytes, as something holding the hub's port could, sees
// none of what is said, and the code still matches end to end.
func TestARelayCantReadTheConnection(t *testing.T) {
	machine, _ := newCert(t)
	hub, _ := newCert(t)
	a, b := tcp(t) // machine to relay
	x, y := tcp(t) // relay to hub
	var seen bytes.Buffer
	var mu sync.Mutex
	pipe := func(dst, src net.Conn, record bool) {
		buf := make([]byte, 4096)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if record {
					mu.Lock()
					seen.Write(buf[:n])
					mu.Unlock()
				}
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				_ = dst.Close()
				return
			}
		}
	}
	go pipe(x, b, true)
	go pipe(b, x, true)
	got := make(chan string, 1)
	var atHub end
	go func() {
		atHub = finish(Server(y, hub))
		if atHub.err != nil {
			got <- ""
			return
		}
		line, _ := io.ReadAll(io.LimitReader(atHub.conn, 64))
		got <- string(line)
	}()
	atMachine := finish(Client(a, machine, trustAny))
	if atMachine.err != nil {
		t.Fatal(atMachine.err)
	}
	const secret = "op://Private/db/url=postgres://hunter2"
	if _, err := io.WriteString(atMachine.conn, secret); err != nil {
		t.Fatal(err)
	}
	_ = atMachine.conn.Close()
	if g := <-got; g != secret {
		t.Fatalf("the hub got %q", g)
	}
	mu.Lock()
	defer mu.Unlock()
	if bytes.Contains(seen.Bytes(), []byte("hunter2")) {
		t.Fatal("the relay saw the request")
	}
	if atMachine.code != atHub.code {
		t.Fatalf("relayed codes differ: %s and %s", atMachine.code, atHub.code)
	}
}

func TestTheCodeDependsOnBothNonces(t *testing.T) {
	machine, _ := newCert(t)
	hub, _ := newCert(t)
	c, s := connect(t,
		func(conn net.Conn) *tls.Conn { return Client(conn, machine, trustAny) },
		func(conn net.Conn) *tls.Conn { return Server(conn, hub) })
	if c.err != nil || s.err != nil {
		t.Fatal(c.err, s.err)
	}
	cs := c.conn.ConnectionState()
	other := bytes.Repeat([]byte("x"), NonceSize)
	a, _ := PairingCode(cs, other, machineNonce)
	b, _ := PairingCode(cs, hubNonce, other)
	if a == c.code && b == c.code {
		t.Fatal("the code ignores the nonces")
	}
	if _, err := PairingCode(cs, hubNonce[:4], machineNonce); err == nil {
		t.Fatal("a short nonce was taken")
	}
	if bytes.Equal(Commit(hubNonce), Commit(other)) || !bytes.Equal(Commit(hubNonce), Commit(hubNonce)) {
		t.Fatal("Commit doesn't bind its nonce")
	}
}
