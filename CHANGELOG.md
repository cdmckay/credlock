# Changelog

Every change people will notice goes here, newest first, in the form of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). credlock follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); what counts as a
breaking change, and how a release is cut, is in [RELEASING.md](RELEASING.md).

## [Unreleased]

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

[Unreleased]: https://github.com/cdmckay/credlock/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cdmckay/credlock/releases/tag/v0.1.0
