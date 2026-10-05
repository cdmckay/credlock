# credlock

credlock hands secrets from 1Password to one command at a time, after a
person has seen what is asked for, by whom and why. Read the README for what
it does, and RELEASING.md before cutting a release.

## Design principles

### Low config: if credlock can do it for the user, it does it

credlock has to be usable without manual setup. This is a design requirement,
weighed against every feature, not a polish item for later.

- **Using it on one Mac needs nothing** beyond installing it and turning on
  1Password's SDK integration. No config file, no setup command.
- **Anything credlock can work out or do itself, it does.** It finds what it
  can find (accounts, hubs on the tailnet), creates what it needs (keys, state
  files, folders, with the right permissions) and remembers what it learns
  (paired machines). It never asks the user to copy a key, edit a file, or
  run a setup step it could run itself.
- **Turning a feature on is one switch** at most, such as a menu item or a
  single command. That's preferable to a config section.
- **Security decisions still reach the person**, but as part of what they're
  already doing. Pairing a new machine, for example, happens inside the first
  approval window, with no separate step.
- **Config files are overrides,** for people who want to pin something down.
  A feature that only works once a file is written is unfinished.

When a design needs the user to configure something, first look for a way to
remove that need. If there isn't one, say so explicitly in the design, along
with the cost of each way around it.

### The approval window is the security boundary

- Deny is the default. Esc denies, Return does nothing, and Allow takes a
  mouse click that it ignores for its first second.
- Everything a requester sends (reason, command, directory, secret names) is
  its own claim. It is flattened and cut before display, so it can't draw fake
  lines. Only what the kernel or Tailscale verifies may be presented as fact.
- Where a request comes from is decided by how it arrives, never by its
  contents. A request from another machine opens with a card that only the
  hub can produce.
- A window that fails, crashes or times out never counts as Allow.

### Values

- Never print, log or write a secret value, including in tests, debug output
  and error messages. There is deliberately no `credlock read`.
- Values live in the helper's memory and the command's environment, nowhere
  else. A remote machine keeps nothing between runs.
- The menu bar icon, status and logs see names, references and times, never
  values.
- Approvals are kept per origin. One machine's approvals are never served to
  another.

## Things learned the hard way

- **The 1Password Go SDK reaches only one account per process** (#8). It
  loads its desktop-app connection once and records the first account. Each
  account is resolved in its own `credlock __resolver` process.
- **`op account list` waits while 1Password is locked,** because it gets its
  accounts from the app. Never put it on a path that must answer quickly, such
  as a cached lookup. Ask once, with a timeout, and keep the answer.
- **AppKit needs the main thread,** so the approval window and the menu bar
  icon are child processes of the helper (`__approve`, `__menubar`). A crash
  there must not lose what the helper holds.
- **An unbundled binary can't post Notification Center notifications:** the
  API crashes without an app bundle. The menu bar icon is credlock's own UI
  instead.
- **Homebrew won't load a formula from a tap that has only been added** until
  it is trusted. Installing by full name trusts it implicitly. See
  RELEASING.md for the bump.
- **A Tailscale device name means nothing on another tailnet.** Pin anything
  name-based to the tailnet it was set up on, and check the caller's full
  MagicDNS name.

## Working on it

- Build and test in the dev shell: `nix develop`. CI runs `gofmt`, `go vet`,
  `go test -race`, golangci-lint, govulncheck, `nix build` and a Linux build.
- UI changes: render them with `CREDLOCK_SNAPSHOT_DIR=/tmp/shots go test
  ./internal/approve ./internal/menubar`, and look at both light and dark.
  Then test live, because tests can't click.
- A change people will notice gets a line under Unreleased in CHANGELOG.md, in
  the same pull request. Releases follow RELEASING.md, with SemVer.
- A dependency added to `go.mod` changes the flake's `vendorHash`. Recompute
  it, or the Nix build fails.
- This is a public repository: keep personal details (account IDs, emails,
  tailnet names, hostnames beyond examples) out of code, tests, docs and
  commit messages.
