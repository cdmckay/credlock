# Changelog

Every change people will notice goes here, newest first, in the form of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). credlock follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); what counts as a
breaking change, and how a release is cut, is in [RELEASING.md](RELEASING.md).

## [Unreleased]

### Added

- Machines without 1Password, such as Linux servers on the same Tailscale
  network, can use `credlock run`. They ask the Macs listed under
  `[client] hubs` in `~/.config/credlock/config.toml`, all at once. A Mac
  answers the machines listed under its `[hub] allow`, on the tailnet named
  in its `[hub] tailnet` only, checking each with `tailscale whois`. It shows
  its usual approval window, and sends the values back over the tailnet. The other machine keeps nothing. Approvals are kept
  per machine, and the window, the menu bar and `credlock status` say which
  machine each is for.
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

[Unreleased]: https://github.com/cdmckay/credlock/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/cdmckay/credlock/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/cdmckay/credlock/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/cdmckay/credlock/releases/tag/v0.1.0
