package daemon

// Slice 1 of approving from a phone (#14): prove that a hub can serve the
// phone web app over the tailnet with Tailscale's certificate, that the phone
// can subscribe from its Home Screen, and that an encrypted push reaches it.
// It runs as a developer command of its own, apart from the helper, and
// handles no secrets. Later slices move the listener into the helper.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/cdmckay/credlock/internal/state"
	"github.com/cdmckay/credlock/internal/webpush"
)

// PhoneSpikeCommand is the developer command for slice 1 of #14.
const PhoneSpikeCommand = "__phone-spike"

// phonePort is the phone listener's port, next to the hub's 7177.
const phonePort = "7178"

// vapidSubject is the contact the push service is given for this sender.
const vapidSubject = "https://github.com/cdmckay/credlock"

//go:embed phoneapp
var phoneApp embed.FS

// PhoneSpike runs the slice 1 developer command:
//
//	credlock __phone-spike serve         serve the web app on the tailnet
//	credlock __phone-spike push [TEXT]   ask the running server to push TEXT
func PhoneSpike(args []string) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = servePhone()
	case "push":
		err = pushViaServer(strings.Join(args, " "))
	default:
		err = fmt.Errorf("unknown subcommand %q: use serve or push", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "credlock phone:", err)
		return 1
	}
	return 0
}

// phoneDomain is this Mac's full MagicDNS name, which Tailscale's
// certificate is for.
func phoneDomain() (tailnetState, string, error) {
	ts, err := tailscaleStatus()
	if err != nil {
		return ts, "", err
	}
	if len(ts.IPs) == 0 || ts.Self == "" || ts.Suffix == "" {
		return ts, "", errors.New("tailscale isn't running, or MagicDNS is off")
	}
	return ts, ts.Self + "." + ts.Suffix, nil
}

// tailscaleCert gets domain's certificate and key from Tailscale, which
// renews it as needed. It can take a while the first time: Tailscale has the
// certificate issued then.
func tailscaleCert(domain string) (tls.Certificate, error) {
	cli := tailscaleCLI()
	if cli == "" {
		return tls.Certificate{}, errors.New("the tailscale command isn't installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, cli, "cert", "--cert-file", "-", "--key-file", "-", domain).Output()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tailscale cert %s: %w (is HTTPS on in the tailnet's DNS settings?)", domain, err)
	}
	// Both go to stdout: the certificate chain and the key, as PEM blocks.
	return tls.X509KeyPair(out, out)
}

// loadVAPID reads the hub's push-signing key, making one the first time.
func loadVAPID() (state.Phone, webpush.Key, error) {
	ph, err := state.LoadPhone()
	if err != nil {
		return ph, webpush.Key{}, err
	}
	if len(ph.VAPID) > 0 {
		k, err := webpush.ParseKey(ph.VAPID)
		return ph, k, err
	}
	k, err := webpush.NewKey()
	if err != nil {
		return ph, k, err
	}
	if ph.VAPID, err = k.Marshal(); err != nil {
		return ph, k, err
	}
	return ph, k, ph.Save()
}

// addr is a remote address as net.Addr, for whois.
type addr string

func (a addr) Network() string { return "tcp" }
func (a addr) String() string  { return string(a) }

type phoneServer struct {
	suffix string
	self   string
	key    webpush.Key

	mu       sync.Mutex
	messages map[string]string // what each test notification said, by ID
}

func servePhone() error {
	ts, domain, err := phoneDomain()
	if err != nil {
		return err
	}
	cert, err := tailscaleCert(domain)
	if err != nil {
		return err
	}
	_, key, err := loadVAPID()
	if err != nil {
		return err
	}
	s := &phoneServer{suffix: ts.Suffix, self: ts.Self, key: key, messages: map[string]string{}}
	srv := &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	errs := make(chan error, len(ts.IPs))
	for _, ip := range ts.IPs {
		ln, err := net.Listen("tcp", net.JoinHostPort(ip, phonePort))
		if err != nil {
			return err
		}
		go func() { errs <- srv.ServeTLS(ln, "", "") }()
	}
	log.Printf("serving https://%s:%s/ on %s, to devices in this tailnet only", domain, phonePort, strings.Join(ts.IPs, ", "))
	return <-errs
}

func (s *phoneServer) routes() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(phoneApp, "phoneapp")
	files := http.FileServerFS(static)
	mux.Handle("GET /{$}", files)
	mux.Handle("GET /app.js", files)
	mux.Handle("GET /app.css", files)
	mux.Handle("GET /manifest.webmanifest", files)
	mux.HandleFunc("GET /sw.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})
	for _, size := range []int{180, 192, 512} {
		mux.HandleFunc(fmt.Sprintf("GET /icon-%d.png", size), func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(icon(size))
		})
	}
	mux.HandleFunc("GET /api/vapid", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"key": s.key.Public()})
	})
	mux.HandleFunc("POST /api/caps", s.caps)
	mux.HandleFunc("POST /api/subscribe", s.subscribe)
	mux.HandleFunc("POST /api/test", s.test)
	mux.HandleFunc("GET /api/message", s.message)
	return s.tailnetOnly(mux)
}

// tailnetOnly refuses anything Tailscale doesn't name as a device of this
// Mac's tailnet, and logs who asked for what.
func (s *phoneServer) tailnetOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fqdn, err := whois(addr(r.RemoteAddr))
		host, ok := inTailnet(fqdn, s.suffix)
		if err != nil || !ok {
			log.Printf("refused %s %s from %s: not a device of this tailnet", r.Method, r.URL.Path, r.RemoteAddr)
			http.Error(w, "not a device of this tailnet", http.StatusForbidden)
			return
		}
		log.Printf("%s %s %s", host, r.Method, r.URL.Path)
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		r = r.WithContext(context.WithValue(r.Context(), deviceKey{}, host))
		next.ServeHTTP(w, r)
	})
}

type deviceKey struct{}

func device(r *http.Request) string { s, _ := r.Context().Value(deviceKey{}).(string); return s }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *phoneServer) caps(w http.ResponseWriter, r *http.Request) {
	var caps map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&caps); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	b, _ := json.Marshal(caps)
	log.Printf("%s supports: %s", device(r), b)
	w.WriteHeader(http.StatusNoContent)
}

func (s *phoneServer) subscribe(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8<<10))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var sub webpush.Subscription
	if err := json.Unmarshal(raw, &sub); err != nil || !strings.HasPrefix(sub.Endpoint, "https://") || sub.Keys.P256dh == "" || sub.Keys.Auth == "" {
		http.Error(w, "not a push subscription", http.StatusBadRequest)
		return
	}
	ph, _, err := loadVAPID()
	if err != nil {
		http.Error(w, "can't read the phone state", http.StatusInternalServerError)
		return
	}
	ph.Device, ph.Subscription = device(r), json.RawMessage(raw)
	if err := ph.Save(); err != nil {
		http.Error(w, "can't save the subscription", http.StatusInternalServerError)
		return
	}
	// The endpoint names the push service; the rest of it is the device's
	// address there, which isn't logged.
	service, _, _ := strings.Cut(strings.TrimPrefix(sub.Endpoint, "https://"), "/")
	log.Printf("%s subscribed, through %s", device(r), service)
	w.WriteHeader(http.StatusNoContent)
}

// test sends a test notification to the subscribed phone: from the phone's
// own button, or from `credlock __phone-spike push` on this Mac.
func (s *phoneServer) test(w http.ResponseWriter, r *http.Request) {
	var body struct{ Text string }
	_ = json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body)
	text := strings.TrimSpace(body.Text)
	if text == "" {
		text = "A test notification from credlock on " + s.self + "."
	}
	ph, _, err := loadVAPID()
	if err != nil || len(ph.Subscription) == 0 {
		http.Error(w, "no phone has subscribed yet", http.StatusConflict)
		return
	}
	var sub webpush.Subscription
	if err := json.Unmarshal(ph.Subscription, &sub); err != nil {
		http.Error(w, "the saved subscription is unreadable", http.StatusInternalServerError)
		return
	}
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	n := hex.EncodeToString(id)
	s.mu.Lock()
	s.messages[n] = text
	s.mu.Unlock()
	payload, _ := json.Marshal(map[string]string{
		"title": "credlock",
		"body":  text,
		"url":   "/?n=" + n,
		"tag":   "credlock-" + n,
	})
	start := time.Now()
	err = webpush.Send(r.Context(), s.key, sub, payload, webpush.Options{TTL: 5 * time.Minute, Urgency: "high", Subject: vapidSubject})
	if err != nil {
		log.Printf("push to %s failed: %v", ph.Device, err)
		http.Error(w, "push failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	log.Printf("pushed %s to %s; the push service took it in %v", n, ph.Device, time.Since(start).Round(time.Millisecond))
	w.WriteHeader(http.StatusNoContent)
}

func (s *phoneServer) message(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	text, ok := s.messages[r.URL.Query().Get("n")]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "no such notification", http.StatusNotFound)
		return
	}
	log.Printf("%s opened notification %s", device(r), r.URL.Query().Get("n"))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, text)
}

// pushViaServer asks the running server, over the tailnet, to push text.
func pushViaServer(text string) error {
	_, domain, err := phoneDomain()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"text": text})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+domain+":"+phonePort+"/api/test", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("is `credlock %s serve` running? %w", PhoneSpikeCommand, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(msg))
	}
	fmt.Println("pushed")
	return nil
}

// icon draws the web app's icon: credlock's purple, with a light ring.
func icon(size int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	bg := color.RGBA{0x6d, 0x4a, 0xff, 0xff}
	fg := color.RGBA{0xf3, 0xf0, 0xff, 0xff}
	c, outer, inner := float64(size)/2, float64(size)*0.30, float64(size)*0.20
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx, dy := float64(x)+0.5-c, float64(y)+0.5-c
			d := dx*dx + dy*dy
			if d <= outer*outer && d >= inner*inner {
				img.Set(x, y, fg)
			} else {
				img.Set(x, y, bg)
			}
		}
	}
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	return b.Bytes()
}
