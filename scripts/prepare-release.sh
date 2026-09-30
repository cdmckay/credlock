#!/usr/bin/env bash
# prepare-release.sh X.Y.Z turns the Unreleased section of CHANGELOG.md into
# release X.Y.Z, dated today, sets VERSION, and commits both on a new branch,
# release/vX.Y.Z, cut from an up-to-date main. It pushes nothing: open the
# pull request yourself. See RELEASING.md.
set -euo pipefail
version=${1:?usage: prepare-release.sh X.Y.Z}
cd "$(dirname "$0")/.."
fail() { echo "prepare-release: $*" >&2; exit 1; }

current=$(cat VERSION)
[[ $(git branch --show-current) == main ]] || fail "run it on main"
[[ -z $(git status --porcelain) ]] || fail "the working tree has changes; commit or stash them first"
git fetch --quiet origin
[[ $(git rev-parse HEAD) == $(git rev-parse origin/main) ]] || fail "main is not at origin/main; pull first"
[[ $version != "$current" ]] || fail "VERSION is already $version"
[[ $(printf '%s\n%s\n' "$current" "$version" | sort -V | tail -1) == "$version" ]] ||
  fail "$version is not newer than $current"

unreleased=$(awk '/^## \[Unreleased\]/ { on = 1; next } on && /^## \[/ { exit } on' CHANGELOG.md | grep -v '^[[:space:]]*$' || true)
[[ -n $unreleased ]] || fail "the Unreleased section of CHANGELOG.md is empty; describe the changes there first"

today=$(date +%F)
repo=https://github.com/cdmckay/credlock
awk -v v="$version" -v prev="$current" -v today="$today" -v repo="$repo" '
  /^## \[Unreleased\]$/ { print; print ""; print "## [" v "] - " today; next }
  /^\[Unreleased\]: / {
    print "[Unreleased]: " repo "/compare/v" v "...HEAD"
    print "[" v "]: " repo "/compare/v" prev "...v" v
    next
  }
  { print }
' CHANGELOG.md > CHANGELOG.md.new
mv CHANGELOG.md.new CHANGELOG.md
printf '%s\n' "$version" > VERSION

scripts/check-release.sh "v$version"
git switch --quiet -c "release/v$version"
git add CHANGELOG.md VERSION
git commit --quiet -m "Release $version"
cat <<MSG
Prepared release $version on branch release/v$version. Next:
  git push -u origin release/v$version
  gh pr create --base main --title "Release $version" --body-file <(scripts/release-notes.sh $version --pr)
Read the notes in that pull request before merging it. Once it's merged, tag
the merge commit and push the tag (RELEASING.md, step 3).
MSG
