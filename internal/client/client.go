// Package client is the credlock command people and agents run. It finds the
// op:// references in its environment, asks the helper for their values
// (starting the helper if it isn't running), and replaces itself with the
// command, now holding the secrets. Values never touch stdout or argv.
package client

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cdmckay/credlock/internal/platform"
	"github.com/cdmckay/credlock/internal/proto"
)

// ExitDenied is the exit status when you deny a request (EX_NOPERM).
const ExitDenied = 77

// RunArgs is a parsed `credlock run` command line.
type RunArgs struct {
	Reason  string
	Account string
	Command []string
}

// ParseRun reads `[--reason TEXT] [--account NAME] [--] COMMAND [ARGS...]`.
func ParseRun(args []string) (RunArgs, error) {
	var r RunArgs
flags:
	for len(args) > 0 {
		a := args[0]
		switch {
		case a == "--":
			args = args[1:]
			break flags
		case a == "--reason" || a == "--account":
			if len(args) < 2 {
				return r, fmt.Errorf("%s needs a value", a)
			}
			set(&r, a, args[1])
			args = args[2:]
		case strings.HasPrefix(a, "--reason=") || strings.HasPrefix(a, "--account="):
			name, value, _ := strings.Cut(a, "=")
			set(&r, name, value)
			args = args[1:]
		case strings.HasPrefix(a, "-"):
			return r, fmt.Errorf("unknown flag %s", a)
		default:
			break flags
		}
	}
	if len(args) == 0 {
		return r, errors.New("no command given")
	}
	r.Command = args
	if r.Account == "" {
		r.Account = firstNonEmpty(os.Getenv("CREDLOCK_ACCOUNT"), os.Getenv("OP_ACCOUNT"))
	}
	return r, nil
}

func set(r *RunArgs, flag, value string) {
	if flag == "--reason" {
		r.Reason = value
	} else {
		r.Account = value
	}
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
	if len(secrets) > 0 {
		cwd, _ := os.Getwd()
		resp, err := Call(proto.Request{
			Op:      proto.OpResolve,
			Account: r.Account,
			Reason:  r.Reason,
			Command: r.Command,
			Cwd:     cwd,
			Secrets: secrets,
		}, true)
		if err != nil {
			return fail(err)
		}
		if resp.Denied {
			fmt.Fprintln(os.Stderr, "credlock: request denied")
			return ExitDenied
		}
		env = Fill(env, secrets, resp.Values)
	}
	path, err := exec.LookPath(r.Command[0])
	if err != nil {
		return fail(err)
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
	}
	for _, e := range resp.Entries {
		fmt.Printf("  %s  (%s)  expires in %s\n", e.Ref, e.Account, (time.Duration(e.ExpiresIn) * time.Second).Round(time.Minute))
	}
	return 0
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
