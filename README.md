# credlock

credlock hands secrets to one command at a time, after you've seen exactly what
is being asked for, by whom, and why.

```bash
GITHUB_TOKEN='op://Personal/GitHub/token' \
  credlock run --account my --reason "list my open pull requests" -- gh pr list
```

The first time, a native dialog shows the reason, the command, the directory,
the requesting process, and each secret it wants. If you allow it, credlock
fetches everything it is missing from 1Password in one call and runs the command
with the real values in its environment. An approval lasts an hour after its
last use, and a day at most, so the next hour of runs needs no prompt at all.

It was written for coding agents, which run each command in a fresh shell with
no terminal. There, a bare `op read` asks for Touch ID on every call, because the
1Password CLI ties its approval to a terminal. credlock's helper is one
long-lived process, and the 1Password SDK ties its approval to a process.

Secret values never touch stdout, a command line, disk, or an agent's
transcript. Only the command you approve receives them.

## Setup

1. In the 1Password app, open **Settings → Developer** and, under
   **Integrate with the 1Password SDKs**, choose **Integrate with other apps**.
2. Install: `nix profile install github:cdmckay/credlock`, or build with
   `go build ./cmd/credlock` (cgo is required).
3. Tell credlock which account the secrets are in, with `--account` or
   `CREDLOCK_ACCOUNT`. It takes the account ID (the `account_uuid` column of
   `op account list`), the sign-in address or its first part (`my`), your
   email, or the account's name as shown in the app. Run `credlock run` with no
   account to list the accounts set up on the machine.

References use the SDK's syntax, `op://vault/item/field`. The built-in
vault's name differs from the `op` CLI's, and crosses over: in a personal
account the SDK calls it `Personal` (`op` also takes `Private`), while in
1Password Business the SDK calls it `Private` (the app and `op` show
`Employee`). A `vaultNotFound` error lists the account's vaults.

## Commands

| Command | What it does |
|---|---|
| `credlock run [--reason TEXT] [--account NAME] [--] COMMAND…` | Runs the command with every `op://` environment variable replaced by its secret. Exits 77 if you deny the request. |
| `credlock status` | Whether the helper is running, and what it holds: references and time left, never values. |
| `credlock clear` | Forget every approved secret. |
| `credlock stop` | Stop the helper, which forgets everything. |

## How it works

- `credlock run` finds the `op://` variables in its environment and sends them,
  with the reason, command, directory and account, to a per-user helper over a
  unix socket. It starts the helper if it isn't running.
- The helper checks with the kernel that the caller is the same user, then
  answers what it already holds. Anything new goes to the dialog, one dialog at
  a time. Deny is the default, and a dialog left unanswered for two minutes
  counts as a denial.
- On Allow, it resolves every missing reference in one `ResolveAll` call. The
  1Password app shows its own approval only when its session for the helper has
  lapsed, after ten idle minutes.
- The client then replaces itself with the command, holding the secrets.
- The helper keeps values in memory only, drops each an hour after its last use
  or a day after its approval, and exits after an idle hour.

The socket lives in `~/Library/Caches/credlock`, a directory credlock keeps at
mode 0700 and refuses to use if anyone else owns it.

## Limits

- Within its hour, an approved secret is served to any process running as you,
  without a prompt. Approvals are not tied to one command.
- **Known attack vector: any app with macOS Accessibility permission can click
  Allow for you.** An agent running inside such an app could approve its own
  request. Without that permission, macOS refuses scripted clicks and keystrokes
  and drops synthetic mouse events (tested), so keep terminals, IDEs and agent
  hosts out of System Settings → Privacy & Security → Accessibility. A planned,
  optional fix is to require a security-key tap after Allow
  ([#1](https://github.com/cdmckay/credlock/issues/1)).
- The dialog records your consent. It is not a barrier against malware already
  running as you, which could read the environment of the command you
  approved.
- The command you approve can do anything with the secrets it receives, as with
  `op run`.
- macOS only for now. The operating-system pieces sit behind
  `internal/platform`, and the dialog library already supports Linux.

## License

GPL-3.0-or-later, with an additional permission to link against the 1Password
SDK and its compiled core. See [LICENSE](LICENSE) and
[LICENSE-EXCEPTION](LICENSE-EXCEPTION).
