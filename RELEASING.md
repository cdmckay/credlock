# Releasing credlock

credlock uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each
release is a tag like `v1.2.3` on `main`, with a dated section in
[CHANGELOG.md](CHANGELOG.md) and the same version in `VERSION`.

## What goes in the changelog

Every pull request that changes something people will notice adds a line
under `## [Unreleased]` in `CHANGELOG.md`, in the same pull request. Use the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) headings: Added,
Changed, Deprecated, Removed, Fixed, Security. Write for the person using
credlock, not the person reading the diff. Refactors, tests and CI changes
don't need a line.

## Which number to bump

credlock's public interface is what scripts and agents depend on:

- the commands, their flags and `CREDLOCK_ACCOUNT`;
- the exit statuses, 77 for a denial in particular;
- the `op://` reference syntax, and what reaches the command's environment;
- the approval rules: what needs a new approval, and how long one lasts.

| Change | Before 1.0 | From 1.0 |
|---|---|---|
| Breaks something in that list | minor: 0.1.0 → 0.2.0 | major: 1.2.0 → 2.0.0 |
| Adds to it, without breaking anything | minor | minor |
| Fixes a bug, with the interface unchanged | patch: 0.1.0 → 0.1.1 | patch |

A change that makes approvals stricter, such as asking more often, is not a
breaking change. A change that makes them looser needs its own changelog line
under Security, whatever it is numbered.

The helper and the client are the same binary, but an upgrade can leave an old
helper running under a new client until it idles out. Keep the protocol
between them compatible within a major version, or say in the changelog that
`credlock stop` is needed after upgrading.

## Cutting a release

1. **Prepare.** On an up-to-date `main`, with CI green and the Unreleased
   section filled in:

   ```bash
   scripts/prepare-release.sh 0.2.0
   ```

   It dates the Unreleased entries as `0.2.0`, updates the comparison links,
   sets `VERSION`, checks the result with `scripts/check-release.sh`, and
   commits it on a new branch, `release/v0.2.0`. It pushes nothing.

2. **Review.** Push the branch and open a pull request. Its diff only dates
   the changelog, so give it the release notes and the pull requests since the
   last release as its description. Read the notes as the release will show
   them, check they still describe what shipped, and merge once CI passes.

   ```bash
   git push -u origin release/v0.2.0
   gh pr create --base main --title "Release 0.2.0" \
     --body-file <(scripts/release-notes.sh 0.2.0 --pr)
   ```

3. **Tag.** Tag the commit that landed on `main`, and push the tag:

   ```bash
   git switch main && git pull --ff-only
   git tag -a v0.2.0 -m "credlock 0.2.0"
   git push origin v0.2.0
   ```

   The Release workflow then checks that the tag, `VERSION` and the changelog
   agree and that the tag is on `main`, runs the tests, and publishes the
   GitHub release with the changelog section as its notes. A tag with a
   pre-release suffix, like `v0.2.0-rc.1`, is published as a pre-release.
   If a check fails, delete the tag (`git push origin :v0.2.0`, then
   `git tag -d v0.2.0`), fix the cause and tag again. Never move a tag that
   has a published release: release a new patch version instead.

4. **Homebrew.** The formula lives in
   [cdmckay/homebrew-tap](https://github.com/cdmckay/homebrew-tap). Its
   autobump workflow checks for a new release every day and opens a pull
   request that updates the formula's URL and checksum. To do it straight
   away, open that pull request yourself:

   ```bash
   HOMEBREW_GITHUB_API_TOKEN=$(gh auth token --user cdmckay) \
     brew bump-formula-pr --no-fork --version 0.2.0 cdmckay/tap/credlock
   ```

   The tap's tests build and test the formula on the pull request. A pull
   request opened by the autobump workflow does not start them (GitHub doesn't
   run workflows for its own token's pull requests), so close and reopen it
   to run them. Merge once they pass.

5. **Nix.** The flake needs nothing: a build reports the last release plus the
   commit it came from, like `0.2.0+1a2b3c4`. Machines that pin credlock
   through another flake pick the release up with `nix flake update credlock`
   there.

## Versions in builds

- The Nix flake reads `VERSION` and adds the commit: `0.1.0+6d36c09`.
- The Homebrew formula passes the tagged version: `0.1.0`.
- `go install github.com/cdmckay/credlock/cmd/credlock@v0.1.0` reports the
  module version, `0.1.0`.
- A plain `go build` in a checkout reports what Go works out from the git tags,
  like `0.1.0+dirty` or a pseudo-version; built without git, it reports `dev`.
