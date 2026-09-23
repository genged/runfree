#!/usr/bin/env bash
set -euo pipefail

# Resolves a release tag to exactly one immutable commit SHA, so every later
# release job builds, tests, signs, and publishes the same bytes.
#
# The whole release depends on this being one commit: jobs that each resolve the
# tag themselves can silently disagree if the tag moves mid-run. Every input
# arrives through the environment rather than workflow-expression interpolation,
# because a `${{ }}` splice of an attacker-chosen tag is shell injection into
# this script.
#
# Inputs (environment):
#   TAG              required, the candidate release tag
#   DEFAULT_BRANCH   required, the branch the tag must be reachable from
#   REPLACE_ASSETS   optional, "true" to request draft-recovery mode
#   GITHUB_OUTPUT    optional, GitHub Actions step output file

die() {
  printf 'resolve-release-tag: %s\n' "$*" >&2
  exit 1
}

tag="${TAG:-}"
default_branch="${DEFAULT_BRANCH:-}"
replace_assets="${REPLACE_ASSETS:-false}"

[ -n "${tag}" ] || die 'TAG is required'
[ -n "${default_branch}" ] || die 'DEFAULT_BRANCH is required'

# Strict, anchored, and no shell metacharacters: `v*.*.*` as a case pattern
# accepts `v1.2.3; rm -rf /` and `v.a.b`.
if ! printf '%s' "${tag}" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$'; then
  die "tag must look like v0.5.0 or v0.5.0-rc.1, got ${tag}"
fi

case "${replace_assets}" in
  true|false) ;;
  *) die "REPLACE_ASSETS must be true or false, got ${replace_assets}" ;;
esac

if ! git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
  die "tag not found in this checkout: ${tag}"
fi

# `^{}` dereferences an annotated tag to its commit; a lightweight tag already
# names one.
sha="$(git rev-list -n 1 "refs/tags/${tag}")"
if ! printf '%s' "${sha}" | grep -Eq '^[0-9a-f]{40}$'; then
  die "could not resolve ${tag} to a commit SHA"
fi

if [ -n "${EXPECTED_SHA:-}" ] && [ "${sha}" != "${EXPECTED_SHA}" ]; then
  die "tag ${tag} moved since release discovery: expected ${EXPECTED_SHA}, found ${sha}"
fi

git fetch --no-tags origin "+refs/heads/${default_branch}:refs/remotes/origin/${default_branch}"
if ! git merge-base --is-ancestor "${sha}" "refs/remotes/origin/${default_branch}"; then
  die "release tag ${tag} (${sha}) must point to a commit reachable from ${default_branch}"
fi

version="${tag#v}"
targets="$("$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/release-targets.sh" matrix)"

printf 'resolved %s to %s on %s\n' "${tag}" "${sha}" "${default_branch}"
printf 'release targets: %s\n' "${targets}"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    printf 'tag=%s\n' "${tag}"
    printf 'version=%s\n' "${version}"
    printf 'sha=%s\n' "${sha}"
    printf 'targets=%s\n' "${targets}"
    printf 'replace_assets=%s\n' "${replace_assets}"
  } >> "${GITHUB_OUTPUT}"
fi
