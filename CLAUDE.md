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

### Fail closed, and never hang

- Anything that fails, crashes, times out or can't be verified counts as a
  denial. An unknown caller, a missing signature or an unreadable answer is a
  refusal, never a guess.
- The helper must never block on something outside it. Every external call
  has a time limit: a resolver gets three minutes, `op` five seconds, a hub
  dial three. Notifying the menu bar never waits. A stuck part is killed and
  replaced.
- Anything that can crash or hang runs in its own child process (the window,
  the menu bar icon, each account's resolver), so a failure there never costs
  the helper what it holds.

### Agents are users too

- credlock is mostly called by coding agents. `credlock help` must be enough
  for an agent that has never seen it, and every error says what to check
  next, not just what failed.
- Distinct outcomes get distinct exits: 77 for a denial, so an agent can stop
  and ask a person rather than retry.
- Text shown to people says plainly what is verified (by the kernel or
  Tailscale) and what is the requester's claim.

### Least exposure

- Serve the minimum: the tailnet listener only resolves, and only on the
  Mac's Tailscale addresses, never the local network. Status, clear and stop
  are local only.
- Tightening is never a breaking change. Loosening anything (what needs
  approval, who may ask, how long an approval lasts) gets its own changelog
  line under Security.
- Every known limit is written down in the README's Limits section, with
  known attack vectors named. Never let the docs claim more than credlock
  does.

### Few, well-known dependencies

- The approval path uses what the OS provides (AppKit, Go's standard
  library, including its crypto) before any library. A new dependency needs a
  reason that beats writing the code, and it has to be widely used and
  maintained.
- CI pins every action to a commit SHA, since a moved tag would run someone
  else's code against a secrets tool.

### Build the thin slice, then prove it live

- Ship a slice that works end to end, then fill it in. One account, one
  machine, one window, working for real, beats layers built separately.
- Tests can't click, and they can't see a real 1Password or Tailscale. Before
  merging anything that touches the window, the menu bar, 1Password or the
  tailnet, run it live, and say in the PR what was tested that way. Most of
  the bugs fixed so far were only found live.
- Check the actual artifact before assuming: read the SDK's source, Tailscale's
  real `whois` output, Homebrew's own docs.

### Leave the door open to Linux

- Keep platform code behind small interfaces (`platform`, `approve.Approver`,
  `menubar.Supported`), with a stub that says what's missing, so other systems
  can be added without reworking the rest.

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

- Write like the code around you. Comments explain why, not what. Test names
  read as the behaviour they check, such as
  `TestADenyEndsTheRequestEverywhere`. Commit messages say why the change
  was needed and how it was tested.

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
