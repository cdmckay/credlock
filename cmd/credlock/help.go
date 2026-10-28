package main

// overview is `credlock help`. It is written for agents as much as people: an
// agent that has never seen credlock should be able to use it from this alone.
const overview = `credlock gives a command its secrets, after a person approves what it asks for and why.

Usage:
  credlock run --account ACCOUNT --reason TEXT [--ttl DURATION] [--] COMMAND [ARGS...]
  credlock search --account ACCOUNT --reason TEXT TERM
                         find an item's reference by its title (names only)
  credlock forget [--account ACCOUNT] [REF...]
                         forget approvals now, when you are done with them
  credlock status        what is approved right now, per account (never values)
  credlock clear         forget every approval
  credlock stop          stop the helper, forgetting everything
  credlock hub [on|off|status|forget HOST]
                         on a Mac: answer other machines on the tailnet
  credlock pair [--forget] MAC
                         on a machine without 1Password: pair with a Mac,
                         or forget its key after credlock was reinstalled there
  credlock help [run|search]
                         this, or just the part about run or search
  credlock version

` + runHelp + `
` + searchHelp + `
Other machines
  A machine without 1Password asks a Mac on the tailnet instead: run
  'credlock hub on' on the Mac, then 'credlock pair MAC' on the machine, and
  answer the pairing window on the Mac (its code matches the one printed
  here). After that, credlock run works the same there, and its approvals
  are that machine's alone. 'credlock hub off' turns it off and stops the
  helper, forgetting every approval. A Mac that answers with a different key
  from the one it paired with is refused; after a reinstall on it, run
  'credlock pair --forget MAC', then pair again.

Other commands
  status, clear and stop talk to the helper, a per-user background process
  that credlock starts on first use and that exits after an idle hour,
  unless hub mode is on. It keeps approved values in memory only. While it
  holds any, a key in the menu bar shows how many, and gets an orange dot
  whenever they are read; its menu is the access log.
`

// runHelp is `credlock run --help`.
const runHelp = `credlock run
  Runs COMMAND with every environment variable whose value is an op://
  reference replaced by the secret it names. Put the references in the
  environment, then wrap the command:

    GITHUB_TOKEN='op://Personal/GitHub/token' \
      credlock run --account my --reason "open the release PR" --ttl 10m -- gh pr create

  Anything not yet approved opens a dialog showing the reason, the command,
  the directory, the requesting process and each secret. Only a person can
  answer it; wait for them. On Allow, the 1Password app may also ask for
  Touch ID. The values then stay available with no prompt for an hour after
  their last use, and a day at most, or less with --ttl. They reach only
  COMMAND's environment: credlock never prints a secret, and has no command
  that would.

  --account ACCOUNT  The 1Password account the references live in. Any of:
                       - the account ID: the account_uuid column of
                         'op account list', not user_uuid
                       - the sign-in address, or its first part: my, acme
                       - the email you sign in with
                       - the account's name, as shown top left in the app
                     Run 'credlock run' with no --account to list the
                     accounts set up here. Defaults to $CREDLOCK_ACCOUNT,
                     then $OP_ACCOUNT.
  --reason TEXT      Why COMMAND needs these secrets, in a few plain words.
                     The person reads it in the dialog before deciding.
  --ttl DURATION     How long you expect to need the secrets, such as 90s or
                     15m, up to 1h. Their approval then ends that long from
                     now, however often they are used, and the dialog says
                     so. It shortens approvals the command uses that were
                     already given, and never lengthens one.

When you are done
  Forget the secrets, so they don't stay approved for the rest of the hour.
  Name the references, or give credlock forget the same environment as
  credlock run:

    GITHUB_TOKEN='op://Personal/GitHub/token' credlock forget --account my

  Without an account, it forgets them in every account. Approvals are shared
  by everything running as you, so forgetting one ends it for any other
  command using it too; that command gets a new dialog. A machine that asks
  a Mac keeps no approvals of its own to forget: use --ttl there.

References
  op://VAULT/ITEM/FIELD, or op://VAULT/ITEM/SECTION/FIELD, each part by name
  or ID, as with 'op read'. Vault names are the 1Password SDK's, which differ
  from the op CLI's for the built-in vault, and cross over:
    personal account     SDK: "Personal"  (op also takes "Private"; the SDK doesn't)
    1Password Business   SDK: "Private"   (the app and op show it as "Employee")
  When in doubt, use the vault's ID. A vaultNotFound error lists the vaults
  the account has, and a fieldNotFound error lists the item's fields (names
  and types, never values). To find an item you don't know the reference
  of, use credlock search, below. There is no need for 'op item list' or
  'op item get'.

Exit status
  COMMAND's own, once it runs.
  77  the request was denied. Don't retry it: ask the person.
  1   credlock could not get the secrets. The message says why.

Troubleshooting
  vaultNotFound        The vault isn't in that account. Check --account
                       first, then the vault's name.
  itemNotFound         No item by that name or ID in that vault.
  fieldNotFound        The item has no field by that name. The message
                       names the fields it has: use one of those.
  no 1Password account given
                       Pass --account; the message lists what's set up here.
  connecting to the 1Password app
                       Check 1Password > Settings > Developer >
                       Integrate with the 1Password SDKs > Integrate with other apps.
                       This is separate from Integrate with 1Password CLI.
                       Then check that 1Password is running and unlocked.
                       If it still fails, run 'credlock stop', then retry
                       the command to clear a stale helper. Stopping
                       forgets every approval. This also applies to
                       "desktop app connection channel is closed".
`

// searchHelp is `credlock search --help`.
const searchHelp = `credlock search
  Finds the items whose titles contain TERM, ignoring case, for when you
  don't know a reference. It asks the person first, in a window that shows
  TERM and your reason, then prints up to 20 matching items, best match
  first, each with its reference and its fields' names and types. Never a
  value. Add a field to a reference it prints to use it with credlock run:

    credlock search --account my --reason "listing my PRs needs a GitHub token" github
    GITHUB_TOKEN='op://Personal/GitHub/token' credlock run --account my ...

  Every search asks again: nothing is kept. More than 20 matches ends with
  how many more; search for something narrower to see them. It works only
  on the Mac with 1Password, not from a machine that asks a hub.

  --reason TEXT      Required. What you are looking for, and why, in a few
                     plain words. The person reads it before deciding.
  --account ACCOUNT  As for credlock run.
  TERM               Part of an item's title, 2 to 100 characters. Several
                     words are searched for as one phrase.

  Exit status: 0 once it searched, matches or not; 77 if the person denied
  it, so don't retry; 1 if it couldn't search, and the message says why.
`
