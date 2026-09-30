#!/usr/bin/env bash
# check-release.sh vX.Y.Z checks that a release tag agrees with the tree: the
# tag is SemVer, VERSION says the same version, and CHANGELOG.md has a dated
# section and a link for it. With --on-main it also checks that the tagged
# commit is on origin/main. The release workflow runs it before publishing.
set -euo pipefail
tag=${1:?usage: check-release.sh vX.Y.Z [--on-main]}
cd "$(dirname "$0")/.."
fail() { echo "check-release: $*" >&2; exit 1; }

semver='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
[[ $tag =~ $semver ]] || fail "$tag is not a SemVer tag like v1.2.3 or v1.2.3-rc.1"
version=${tag#v}

[[ $(cat VERSION) == "$version" ]] || fail "VERSION says $(cat VERSION), the tag says $version"
grep -Eq "^## \[${version//./\\.}\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" CHANGELOG.md ||
  fail "CHANGELOG.md has no '## [$version] - YYYY-MM-DD' section"
grep -q "^\[$version\]: " CHANGELOG.md || fail "CHANGELOG.md has no [$version] link"
[[ -n $(scripts/release-notes.sh "$version") ]] || fail "CHANGELOG.md's $version section is empty"

if [[ ${2:-} == --on-main ]]; then
  git merge-base --is-ancestor "$tag^{commit}" origin/main || fail "$tag is not on origin/main"
fi
echo "check-release: $tag is consistent"
