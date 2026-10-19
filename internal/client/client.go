// Package client is the credlock command people and agents run. It finds the
// op:// references in its environment, asks the helper for their values
// (starting the helper if it isn't running), and replaces itself with the
// command, now holding the secrets. Values never touch stdout or argv.
package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cdmckay/credlock/internal/channel"
	"github.com/cdmckay/credlock/internal/config"
	"github.com/cdmckay/credlock/internal/platform"
	"github.com/cdmckay/credlock/internal/proto"
	"github.com/cdmckay/credlock/internal/state"
)

// ExitDenied is the exit status when you deny a request (EX_NOPERM).
const ExitDenied = 77

// approvalWindow is how long the dialog waits, for messages; see daemon.ApprovalTimeout.
const approvalWindow = "2 minutes"

// maxTTL is the longest --ttl: the hour an approval lasts after its last use,
// daemon.Window. A longer one would keep an unused approval past it.
const maxTTL = time.Hour

// RunArgs is a parsed `credlock run` command line.
type RunArgs struct {
	Reason  string
	Account string
	TTL     time.Duration // zero for credlock's own lifetimes
	Command []string
}

// ParseRun reads `[--reason TEXT] [--account NAME] [--ttl DURATION] [--] COMMAND [ARGS...]`.
func ParseRun(args []string) (RunArgs, error) {
	var r RunArgs
flags:
	for len(args) > 0 {
		a := args[0]
		name, value, inline := strings.Cut(a, "=")
		switch {
		case a == "--":
			args = args[1:]
			break flags
		case name == "--reason" || name == "--account" || name == "--ttl":
			args = args[1:]
			if !inline {
				if len(args) == 0 {
					return r, fmt.Errorf("%s needs a value", a)
				}
				value, args = args[0], args[1:]
			}
			if err := set(&r, name, value); err != nil {
				return r, err
			}
		case strings.HasPrefix(a, "-"):
			return r, fmt.Errorf("unknown flag %s: credlock run takes --account, --reason and --ttl, before the command; '--' ends them (see 'credlock help run')", a)
		default:
			break flags
		}
	}
	if len(args) == 0 {
		return r, errors.New("no command given: credlock run [--account ACCOUNT] [--reason TEXT] [--ttl DURATION] [--] COMMAND [ARGS...] (see 'credlock help run')")
	}
	r.Command = args
	if r.Account == "" {
		r.Account = defaultAccount()
	}
	return r, nil
}

func set(r *RunArgs, flag, value string) error {
	switch flag {
	case "--reason":
		r.Reason = value
	case "--account":
		r.Account = value
	case "--ttl":
		ttl, err := time.ParseDuration(value)
		if err != nil || ttl < time.Second || ttl > maxTTL {
			return fmt.Errorf("--ttl takes how long the approval should last, from 1s to 1h, such as 90s or 15m; not %q", value)
		}
		r.TTL = ttl
	}
	return nil
}

func defaultAccount() string {
	return firstNonEmpty(os.Getenv("CREDLOCK_ACCOUNT"), os.Getenv("OP_ACCOUNT"))
}

// Refs returns every environment variable whose value is a secret reference,
// sorted by name.
func Refs(environ []string) []proto.Secret {
	var out []proto.Secret
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if ok && strings.HasPrefix(value, "op://") {
			out = append(out, proto.Secret{Name: name, Ref: value})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Fill replaces each secret variable in environ with its value.
func Fill(environ []string, secrets []proto.Secret, values map[string]string) []string {
	byName := map[string]string{}
	for _, s := range secrets {
		byName[s.Name] = values[s.Ref]
	}
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if v, ok := byName[name]; ok {
			kv = name + "=" + v
		}
		out = append(out, kv)
	}
	return out
}

// Run is `credlock run`.
func Run(args []string) int {
	r, err := ParseRun(args)
	if err != nil {
		return fail(err)
	}
	secrets := Refs(os.Environ())
	env := os.Environ()
	if len(secrets) == 0 {
		fmt.Fprintf(os.Stderr, "credlock: no environment variable holds an op:// reference, so %s runs without secrets. "+
			"Set them for the command, e.g. TOKEN='op://Vault/Item/field' credlock run ... (see 'credlock help run')\n", r.Command[0])
	}
	if len(secrets) > 0 {
		cfg, err := config.Load()
		if err != nil {
			return fail(err)
		}
		account, label, err := ResolveAccount(r.Account, Accounts())
		if err != nil {
			return fail(err)
		}
		cwd, _ := os.Getwd()
		req := proto.Request{
			Op:           proto.OpResolve,
			Account:      account,
			AccountLabel: label,
			Reason:       r.Reason,
			Command:      r.Command,
			Cwd:          cwd,
			Secrets:      secrets,
			TTL:          int64(r.TTL / time.Second),
		}
		var resp proto.Response
		switch {
		case platform.HasHelper:
			resp, err = Call(req, true)
		default:
			// No 1Password here: a Mac on the tailnet asks you, and sends
			// the values back. Nothing is kept on this machine.
			resp, err = viaHubs(cfg, req)
		}
		if err != nil {
			return fail(err)
		}
		if resp.TimedOut {
			fmt.Fprintf(os.Stderr, "credlock: nobody answered the approval dialog within %s, which counts as a denial. "+
				"Ask the person to watch for it, then run the command again.\n", approvalWindow)
			return ExitDenied
		}
		if resp.Denied {
			fmt.Fprintln(os.Stderr, "credlock: the request was denied in the approval dialog. Don't retry it: ask the person why, or what to do instead.")
			return ExitDenied
		}
		env = Fill(env, secrets, resp.Values)
	}
	path, err := exec.LookPath(r.Command[0])
	if err != nil {
		return fail(fmt.Errorf("%s: not found on PATH (credlock runs the command itself, so pass the program and its arguments after --)", r.Command[0]))
	}
	err = syscall.Exec(path, r.Command, env)
	return fail(fmt.Errorf("running %s: %w", r.Command[0], err))
}

// Status is `credlock status`.
func Status() int {
	resp, err := Call(proto.Request{Op: proto.OpStatus}, false)
	if errors.Is(err, errNotRunning) {
		fmt.Println("credlock: helper not running, nothing approved")
		return 0
	}
	if err != nil {
		return fail(err)
	}
	fmt.Printf("credlock: helper running (pid %d)\n", resp.PID)
	if len(resp.Entries) == 0 {
		fmt.Println("nothing approved")
		return 0
	}
	fmt.Println("approved (no values shown):")
	names := labels(Accounts())
	for _, e := range resp.Entries {
		account := e.Account
		if label, ok := names[e.Account]; ok {
			account = label
		}
		forWhom := ""
		if e.Origin != "" {
			forWhom = ", for " + e.Origin
		}
		fmt.Printf("  %s  in %s%s, expires in %s\n", e.Ref, account, forWhom, (time.Duration(e.ExpiresIn) * time.Second).Round(time.Minute))
	}
	return 0
}

// Forget is `credlock forget [--account ACCOUNT] [REF...]`: it drops this
// machine's approvals for those references, or for the op:// references in
// the environment if none are named, as credlock run would find them.
func Forget(args []string) int {
	account, refs, err := ParseForget(args, os.Environ())
	if err != nil {
		return fail(err)
	}
	if !platform.HasHelper {
		return fail(errors.New("this machine keeps no approvals: the Mac it asks holds them, and forgets them an hour after their last use. " +
			"To keep them shorter, pass --ttl to credlock run"))
	}
	accounts := Accounts()
	label := "every account"
	if account != "" {
		if account, label, err = ResolveAccount(account, accounts); err != nil {
			return fail(err)
		}
	}
	req := proto.Request{Op: proto.OpForget, Account: account}
	for _, ref := range refs {
		req.Secrets = append(req.Secrets, proto.Secret{Ref: ref})
	}
	resp, err := Call(req, false)
	switch {
	case errors.Is(err, errNotRunning):
		fmt.Println("credlock: helper not running, nothing to forget")
		return 0
	case err != nil && strings.HasPrefix(err.Error(), "unknown op"):
		return fail(errors.New("the helper running now is from an older credlock, which can't forget one approval. " +
			"credlock stop ends it, forgetting every approval; the next credlock run starts this version's"))
	case err != nil:
		return fail(err)
	case len(resp.Entries) == 0:
		fmt.Printf("credlock: none of those were approved in %s, so there was nothing to forget\n", label)
		return 0
	}
	names := labels(accounts)
	for _, e := range resp.Entries {
		fmt.Printf("credlock: forgot %s in %s\n", e.Ref, firstNonEmpty(names[e.Account], e.Account))
	}
	return 0
}

// ParseForget reads `[--account ACCOUNT] [REF...]`, taking the references
// from environ when none are named. The account defaults as credlock run's
// does; empty means every account.
func ParseForget(args, environ []string) (account string, refs []string, err error) {
	for len(args) > 0 {
		a := args[0]
		name, value, inline := strings.Cut(a, "=")
		switch {
		case name == "--account":
			args = args[1:]
			if !inline {
				if len(args) == 0 {
					return "", nil, errors.New("--account needs a value")
				}
				value, args = args[0], args[1:]
			}
			account = value
		case strings.HasPrefix(a, "-"):
			return "", nil, fmt.Errorf("unknown flag %s: credlock forget takes --account, then the op:// references to forget (see 'credlock help')", a)
		case !strings.HasPrefix(a, "op://"):
			return "", nil, fmt.Errorf("%q is not an op:// reference: credlock forget takes the references themselves, such as op://Vault/Item/field", a)
		default:
			refs = append(refs, a)
			args = args[1:]
		}
	}
	if len(refs) == 0 {
		for _, s := range Refs(environ) {
			refs = append(refs, s.Ref)
		}
	}
	if len(refs) == 0 {
		return "", nil, errors.New("nothing to forget: name the op:// references, or run it with them in the environment, as for credlock run. " +
			"credlock clear forgets every approval")
	}
	if account == "" {
		account = defaultAccount()
	}
	return account, refs, nil
}

// Clear is `credlock clear`.
func Clear() int { return simple(proto.OpClear, "cleared", "helper not running, nothing to clear") }

// Stop is `credlock stop`.
func Stop() int { return simple(proto.OpStop, "stopped", "helper not running") }

func simple(op, done, absent string) int {
	_, err := Call(proto.Request{Op: op}, false)
	switch {
	case errors.Is(err, errNotRunning):
		fmt.Println("credlock:", absent)
	case err != nil:
		return fail(err)
	default:
		fmt.Println("credlock:", done)
	}
	return 0
}

var errNotRunning = errors.New("helper not running")

// Call sends one request to the helper, starting it first if start is set.
func Call(req proto.Request, start bool) (proto.Response, error) {
	path, err := platform.SocketPath()
	if err != nil {
		return proto.Response{}, err
	}
	return CallAt(path, req, start)
}

// CallAt is Call against a given socket.
func CallAt(path string, req proto.Request, start bool) (proto.Response, error) {
	conn, err := net.Dial("unix", path)
	if err != nil && start {
		conn, err = startHelper(path)
	}
	if err != nil {
		if start {
			return proto.Response{}, fmt.Errorf("starting the helper: %w", err)
		}
		return proto.Response{}, errNotRunning
	}
	defer func() { _ = conn.Close() }()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return proto.Response{}, err
	}
	var resp proto.Response
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return proto.Response{}, fmt.Errorf("reading the helper's answer: %w", err)
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		return proto.Response{}, err
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// startHelper launches this binary as the helper in its own session, with no
// terminal and stdio on /dev/null, then waits for its socket.
func startHelper(path string) (net.Conn, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, proto.HelperCommand)
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	_ = cmd.Process.Release()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.Dial("unix", path)
		if err == nil || time.Now().After(deadline) {
			return conn, err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "credlock:", err)
	return 1
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// viaHubs asks the Macs this machine was paired with (credlock pair), or the
// ones [client] hubs in the config names, for a machine without 1Password.
// The key is made on first use; nothing else is kept here.
func viaHubs(cfg config.Config, req proto.Request) (proto.Response, error) {
	cert, err := machineCert()
	if err != nil {
		return proto.Response{}, err
	}
	remembered, err := state.LoadClient()
	if err != nil {
		return proto.Response{}, err
	}
	hubs := cfg.Client.Hubs
	if len(hubs) == 0 {
		hubs = remembered.Hubs
	}
	if len(hubs) == 0 {
		return proto.Response{}, errors.New("this machine has no 1Password, and no Mac to ask for secrets. " +
			"Pair it with a Mac on the tailnet, once: credlock pair MAC (the Mac needs credlock hub on)")
	}
	// A copy: calls still under way read it while Remember below writes.
	auth := hubAuth{cert: cert, user: currentUser(), pinned: maps.Clone(remembered.Keys),
		say: func(s string) { fmt.Fprintln(os.Stderr, s) }}
	got, err := askHubs(hubs, req, auth)
	if err == nil && len(got.resp.Values) > 0 && remembered.Remember(got.hub, got.key) {
		_ = remembered.Save()
	}
	return got.resp, err
}

// Pair is `credlock pair MAC`, on a machine without 1Password: it pairs this
// user here with a Mac on the tailnet, which asks in its pairing window, and
// remembers the Mac and its key, so credlock run asks it from then on. A Mac
// that answers with a different key from the one it paired with is refused,
// as credlock run refuses it: `credlock pair --forget MAC` drops the old key
// on purpose, after a reinstall there.
func Pair(args []string) int {
	if platform.HasHelper {
		return fail(errors.New("this Mac has its own helper and pairs nothing; to let other machines ask it, run credlock hub on"))
	}
	forget := len(args) == 2 && args[0] == "--forget"
	if forget {
		args = args[1:]
	}
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(os.Stderr, "usage: credlock pair MAC, naming a Mac on the tailnet that has hub mode on; or credlock pair --forget MAC")
		return 2
	}
	hub := args[0]
	remembered, err := state.LoadClient()
	if err != nil {
		return fail(err)
	}
	if forget {
		if !remembered.Forget(hub) {
			dir, _ := state.Dir()
			return fail(fmt.Errorf("this machine isn't paired with %s, so there's nothing to forget. The Macs it has paired with are in %s", hub, filepath.Join(dir, "client.json")))
		}
		if err := remembered.Save(); err != nil {
			return fail(err)
		}
		fmt.Printf("credlock: forgot %s and its key. To pair again: credlock pair %s, and pair only if its window shows the code printed here.\n", hub, hub)
		return 0
	}
	cert, err := machineCert()
	if err != nil {
		return fail(err)
	}
	host, _ := os.Hostname()
	host, _, _ = strings.Cut(host, ".")
	cwd, _ := os.Getwd()
	auth := hubAuth{cert: cert, user: currentUser(), pinned: maps.Clone(remembered.Keys),
		say: func(s string) { fmt.Fprintln(os.Stderr, s) }}
	fmt.Fprintf(os.Stderr, "credlock: asking %s to pair; answer in its pairing window.\n", hub)
	resp, hubKey, err := callHub(context.Background(), hub, proto.Request{
		Op:      proto.OpPair,
		Reason:  fmt.Sprintf("pair %s on %s with %s", auth.user, host, hub),
		Command: []string{"credlock", "pair", hub},
		Cwd:     cwd,
	}, hubAsk, auth)
	switch {
	case err != nil:
		return fail(err)
	case resp.TimedOut:
		fmt.Fprintf(os.Stderr, "credlock: nobody answered %s's window in time, so it didn't pair. Run credlock pair %s again when you're at it.\n", hub, hub)
		return ExitDenied
	case resp.Denied:
		fmt.Fprintf(os.Stderr, "credlock: %s denied the pairing.\n", hub)
		return ExitDenied
	case !resp.Paired:
		return fail(fmt.Errorf("%s didn't say whether it paired. Check that it runs a credlock as current as this one", hub))
	}
	if remembered.Remember(hub, hubKey) {
		if err := remembered.Save(); err != nil {
			return fail(err)
		}
	}
	fmt.Printf("credlock: paired with %s. credlock run asks it from now on.\n", hub)
	return 0
}

// machineCert is this user's credlock key on this machine, made on first use,
// in a certificate for TLS.
func machineCert() (tls.Certificate, error) {
	key, err := state.Key()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("this machine's credlock key: %w", err)
	}
	return channel.Certificate(key)
}

func currentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}
