# Changelog

Every change people will notice goes here, newest first, in the form of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). credlock follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); what counts as a
breaking change, and how a release is cut, is in [RELEASING.md](RELEASING.md).

## [Unreleased]

## [0.5.1] - 2026-10-28

### Fixed

- 1Password connection errors now point first to the full SDK integration
  setting, distinguish it from CLI integration, and explain checking the app
  and restarting a stale helper with `credlock stop` before retrying.

### Changed

- The access log in the menu bar shows the last five uses instead of twenty,
  in two lines each: when and what it was for, then which secrets it used
  (or what was searched for) and whether you were asked. The other 25 it
  keeps are under Earlier, where before the last ten weren't shown at all.
  The command moved into each entry's submenu, and the log keeps 80
  characters of a reason, down from 120.

### Security

- Nix builds and the development shell use Go 1.26.10, which fixes
  GO-2026-6809 in certificate verification used by hub connections. The
  flake's nixpkgs lock is updated; consumer flakes that override that input
  must also use a nixpkgs revision containing the fixed Go version.

## [0.5.0] - 2026-10-23

### Security

- Allowing a reference that fails with `fieldNotFound` now tells the
  requester the names and types of that item's fields, never their values
  (below). Before, it learned nothing about the item.
- A requester can now ask to search item titles with `credlock search`
  (below). Once the person allows it, the requester learns the titles,
  references and field names of up to 20 items whose titles contain the
  term it chose, never their values. Before, it could learn names only for
  an item it already knew the reference of.

### Added

- `credlock search --reason TEXT TERM` finds the items whose titles contain
  TERM, for an agent that doesn't know a reference. A search window shows
  the term and the reason, which is required. After Allow, it prints up to
  20 matching items, best match first, each with a reference ready for a
  field and its fields' names and types, never a value, and says how many
  more match. Every search asks: nothing is kept. It works only on the Mac
  with 1Password, not through a hub. An agent no longer needs `op item
  list` or `op item get`, whose prompts show neither what it is looking for
  nor what it gets back. A helper still running from an older credlock
  can't search, and says so: `credlock stop` ends it, and the next command
  starts this version's. Everything else works with it as before.
- The access log in the menu bar shows what went back for each search, by
  name: each item's reference and field names, in a submenu. The key stays
  in the menu bar for an hour after a search, even with nothing held.

### Changed

- The access log now also records a request that failed after you allowed
  it, with what its error said, such as a `fieldNotFound`'s field names.
  Before, only deliveries were logged.
- A reference that fails with `fieldNotFound` now names the item's fields:
  each one's name and type, and its section when it has one, never its
  value, such as `"username" (Text), "credential" (Concealed)`. An agent
  that guessed the field wrong no longer has to fall back to `op item get`,
  with its own Touch ID prompt, to find the right one. The names come only
  after the person has allowed that reference, through the same 1Password
  session, so they cost no extra prompt.

## [0.4.0] - 2026-10-20

### Security

- The Nix flake builds credlock with Go 1.26.9, which fixes vulnerabilities
  in the standard library's `net/http`, `net/textproto` and `crypto/tls` that
  credlock's code reaches (GO-2026-6603, -6607, -6608, -6611, -6612, -6613
  and -6617). Hub mode's connections between machines use `crypto/tls`. The
  release binaries were already built with the latest Go 1.26.

### Added

- `credlock run --ttl DURATION` says how long a run expects to need its
  secrets, up to an hour, such as `--ttl 15m`. Their approval then ends that
  long from now, however often they are used, and the approval window shows
  it. It only ever shortens an approval, including ones the run uses that
  were given before. A hub running an older credlock ignores it, and keeps
  the usual lifetimes.
- `credlock forget [--account NAME] [REF…]` forgets this machine's approvals
  for those references at once, so they don't stay approved for the rest of
  the hour. With no references named, it takes the `op://` variables in the
  environment, as `credlock run` does. `credlock help` tells agents to use
  both ([#15](https://github.com/cdmckay/credlock/issues/15)). After
  upgrading, a helper that is still running from before ignores `--ttl` and
  can't forget: `credlock stop` once, or wait for it to exit after an idle
  hour.
- The Nix flake builds credlock on Linux too, for x86_64 and aarch64, so a
  NixOS machine can install it from the flake and use it to ask a Mac in hub
  mode. Before, Nix refused to build it there
  ([#13](https://github.com/cdmckay/credlock/pull/13)).

## [0.3.0] - 2026-10-07

### Security

- Hub mode lets other machines ask a Mac for secrets. With `credlock hub on`,
  users on machines in the Mac's tailnet who have paired with it can ask, and
  each new secret still needs your Allow in the Mac's window. What you
  approve is kept for that user on that machine alone. Hub mode is off
  unless you turn it on.

### Added

- Machines without 1Password, such as Linux servers on your Tailscale
  network, can use `credlock run`. A Mac turned on with `credlock hub on`
  answers them: it shows its usual approval window, which says first which
  machine is asking, and sends the values back over the tailnet. The other
  machine keeps nothing. A login item keeps the Mac answering after a
  restart; `credlock hub off` removes it and stops the helper, forgetting
  every approval. Hub mode needs Tailscale on every machine involved. After
  upgrading from 0.2, run `credlock stop` once before `credlock hub on` if a
  helper is still running: a 0.2 helper doesn't know hub mode.
- Pairing: `credlock pair MAC` on the other machine pairs its user with the
  Mac, in a window that shows a code its terminal shows too. Each user there
  gets a key of their own, made on first use, and the Mac has its own; they
  connect over TLS 1.3 with them, and the machine remembers the Mac's key
  when it pairs. A key that doesn't match is refused, and on the Mac raises
  an alert in the menu bar; five pairing windows from one machine that end
  without Pair pause its pairing requests for an hour. `credlock hub status`
  lists the paired machines, `credlock hub forget HOST` unpairs one, and
  `credlock pair --forget MAC` forgets a Mac's key after a reinstall there.
- A menu bar alert: the key turns red, and its menu says what happened, until
  dismissed.
- The menu bar menu shows the running helper's version at its foot.
- A request whose asker goes away, such as a `credlock run` stopped with
  Ctrl-C, now closes its approval window.

## [0.2.1] - 2026-10-02

### Fixed

- A request for a second 1Password account went to the first account the
  helper had used, because the 1Password SDK connects to the app once per
  process ([#8](https://github.com/cdmckay/credlock/issues/8)). The approval
  window named the account asked for while the secret came from the other,
  and when the other account had no such reference the request failed. Each
  account is now resolved in its own process, so several accounts work side by
  side.
- A request no longer waits forever when 1Password doesn't answer, as when the
  app is locked: after three minutes it fails, and the next request starts
  afresh.

## [0.2.0] - 2026-09-30

### Added

- A menu bar icon shows a key and the number of secrets credlock is holding.
  An orange dot appears on the key for a few seconds whenever secrets are
  read, so a cached secret can't be used without your seeing it. Clicking it
  shows the access log (when, which command and why, which secrets, and
  whether they came from the cache), the held secrets with the time each has
  left, and ways to forget one secret, forget them all, or stop credlock. The
  icon never sees a secret's value, and nothing in its menu can approve
  anything.

## [0.1.0] - 2026-09-29

The first release. macOS only.

### Added

- `credlock run --account ACCOUNT --reason TEXT -- COMMAND` runs a command with
  every `op://` reference in its environment replaced by the secret it names.
- An approval window shows the reason, the command, the directory, the
  requesting process, the 1Password account, how long an approval lasts and
  each secret, before anything is fetched. Deny is the default: Esc denies,
  Return does nothing, and Allow takes a mouse click, which it ignores for its
  first second on screen. A window left unanswered for two minutes counts as a
  denial.
- Approved secrets stay available, with no prompt, for an hour after their last
  use and a day at most. A per-user helper holds them in memory only, and exits
  after an idle hour.
- `credlock status` lists what is approved (never the values), `credlock clear`
  forgets it all, and `credlock stop` ends the helper.
- `--account` takes the account ID, the sign-in address or its first part, the
  email, or the account's name; `CREDLOCK_ACCOUNT` and `OP_ACCOUNT` are the
  defaults.
- A denial exits with status 77, so an agent can tell it from a failure.
- Errors say what to check next, such as the 1Password SDK's names for the
  built-in vault and the vaults an account does have.
- A Nix flake, and a Homebrew formula in
  [cdmckay/homebrew-tap](https://github.com/cdmckay/homebrew-tap).

[Unreleased]: https://github.com/cdmckay/credlock/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/cdmckay/credlock/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/cdmckay/credlock/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/cdmckay/credlock/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/cdmckay/credlock/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/cdmckay/credlock/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/cdmckay/credlock/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/cdmckay/credlock/releases/tag/v0.1.0
