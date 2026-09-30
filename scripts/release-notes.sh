#!/usr/bin/env bash
# release-notes.sh VERSION prints that version's section of CHANGELOG.md,
# without its heading: the body of the GitHub release.
#
# release-notes.sh VERSION --pr prints a description for the release pull
# request instead: the same notes, then the pull requests merged since the
# last release and a link to the full comparison. A release PR's own diff only
# dates the changelog, so this is where a reviewer sees what is being released.
set -euo pipefail
version=${1:?usage: release-notes.sh VERSION [--pr]}
cd "$(dirname "$0")/.."

notes() {
  awk -v v="$version" '
    index($0, "## [" v "]") == 1 { on = 1; next }
    on && (/^## \[/ || /^\[[^]]+\]: /) { exit }
    on { print }
  ' CHANGELOG.md | sed -e '/./,$!d' | awk '{ lines[NR] = $0 } END { n = NR; while (n > 0 && lines[n] == "") n--; for (i = 1; i <= n; i++) print lines[i] }'
}

if [[ ${2:-} != --pr ]]; then
  notes
  exit
fi

previous=$(git describe --tags --abbrev=0 --match 'v*' HEAD 2>/dev/null || true)
echo "Releases **$version**: this dates the Unreleased changelog entries and sets \`VERSION\`. Once it merges, the v$version tag goes on the merge commit (RELEASING.md, step 3)."
echo
echo "## What $version changes"
echo
notes
if [[ -n $previous ]]; then
  echo
  echo "## Merged since $previous"
  echo
  merged=0
  for c in $(git log --first-parent --merges --format=%H "$previous..HEAD"); do
    subject=$(git log -1 --format=%s "$c")
    title=$(git log -1 --format=%b "$c" | sed -n '1p')
    if [[ $subject =~ ^Merge\ pull\ request\ (#[0-9]+) ]]; then
      echo "- ${title:-$subject} (${BASH_REMATCH[1]})"
      merged=$((merged + 1))
    fi
  done
  [[ $merged -gt 0 ]] || echo "- (no pull requests)"
  echo
  # The commit, not the branch: the branch is deleted when the PR merges.
  echo "Full comparison: https://github.com/cdmckay/credlock/compare/$previous...$(git rev-parse --short HEAD)"
fi
