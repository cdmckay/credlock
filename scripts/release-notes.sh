#!/usr/bin/env bash
# release-notes.sh VERSION prints that version's section of CHANGELOG.md,
# without its heading: the body of the GitHub release.
set -euo pipefail
version=${1:?usage: release-notes.sh VERSION}
cd "$(dirname "$0")/.."
awk -v v="$version" '
  index($0, "## [" v "]") == 1 { on = 1; next }
  on && (/^## \[/ || /^\[[^]]+\]: /) { exit }
  on { print }
' CHANGELOG.md | sed -e '/./,$!d' | awk '{ lines[NR] = $0 } END { n = NR; while (n > 0 && lines[n] == "") n--; for (i = 1; i <= n; i++) print lines[i] }'
