package main

// overview is `credlock help`. It is written for agents as much as people: an
// agent that has never seen credlock should be able to use it from this alone.
const overview = `credlock gives a command its secrets, after a person approves what it asks for and why.

Usage:
  credlock run --account ACCOUNT --reason TEXT [--] COMMAND [ARGS...]
  credlock status        what is approved right now, per account (never values)
  credlock clear         forget every approval
  credlock stop          stop the helper, forgetting everything
  credlock help [run]    this, or just the part about run
  credlock version

` + runHelp + `
Other commands
  status, clear and stop talk to the helper, a per-user background process
  that credlock starts on first use and that exits after an idle hour. It
  keeps approved values in memory only. While it holds any, a key in the
  menu bar shows how many, and gets an orange dot whenever they are read;
  its menu is the access log.
`

// runHelp is `credlock run --help`.
const runHelp = `credlock run
  Runs COMMAND with every environment variable whose value is an op://
  reference replaced by the secret it names. Put the references in the
  environment, then wrap the command:

    GITHUB_TOKEN='op://Personal/GitHub/token' \
      credlock run --account my --reason "open the release PR" -- gh pr create

  Anything not yet approved opens a dialog showing the reason, the command,
  the directory, the requesting process and each secret. Only a person can
  answer it; wait for them. On Allow, the 1Password app may also ask for
  Touch ID. The values then stay available with no prompt for an hour after
  their last use, and a day at most. They reach only COMMAND's environment:
  credlock never prints a secret, and has no command that would.

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

References
  op://VAULT/ITEM/FIELD, or op://VAULT/ITEM/SECTION/FIELD, each part by name
  or ID, as with 'op read'. Vault names are the 1Password SDK's, which differ
  from the op CLI's for the built-in vault, and cross over:
    personal account     SDK: "Personal"  (op also takes "Private"; the SDK doesn't)
    1Password Business   SDK: "Private"   (the app and op show it as "Employee")
  When in doubt, use the vault's ID. A vaultNotFound error lists the vaults
  the account has.

Exit status
  COMMAND's own, once it runs.
  77  the request was denied. Don't retry it: ask the person.
  1   credlock could not get the secrets. The message says why.

Troubleshooting
  vaultNotFound        The vault isn't in that account. Check --account
                       first, then the vault's name.
  itemNotFound         No item by that name or ID in that vault.
  fieldNotFound        The item has no field by that name.
  no 1Password account given
                       Pass --account; the message lists what's set up here.
  connecting to the 1Password app
                       1Password isn't running or unlocked, or its SDK
                       integration is off: Settings > Developer >
                       "Integrate with other apps".
`
