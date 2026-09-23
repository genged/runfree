#!/usr/bin/env bash
set -euo pipefail

# Re-checks, immediately before publication, that the remote tag still names the
# SHA this release run resolved, built, signed, and accepted.
#
# The tag is resolved once at the start of a release, but a tag is a mutable
# pointer: it can be force-moved while the macOS jobs run. Without this check the
# run would publish artifacts built from one commit under a tag that now names a
# different one, and the published bytes would not correspond to the tagged
# source.
#
# Inputs (environment):
#   TAG            required, the release tag
#   EXPECTED_SHA   required, the SHA resolved at the start of the run
#   REMOTE         optional, defaults to origin

die() {
  printf 'require-unmoved-tag: %s\n' "$*" >&2
  exit 1
}

tag="${TAG:-}"
expected_sha="${EXPECTED_SHA:-}"
remote="${REMOTE:-origin}"

[ -n "${tag}" ] || die 'TAG is required'
[ -n "${expected_sha}" ] || die 'EXPECTED_SHA is required'
printf '%s' "${expected_sha}" | grep -Eq '^[0-9a-f]{40}$' || die "EXPECTED_SHA must be a full SHA, got ${expected_sha}"

remote_refs="$(git ls-remote "${remote}" "refs/tags/${tag}" "refs/tags/${tag}^{}")"
[ -n "${remote_refs}" ] || die "tag ${tag} no longer exists on ${remote}"

# An annotated tag reports both its own object and, under `^{}`, the commit it
# points at. The commit is the one that must match.
actual_sha="$(printf '%s\n' "${remote_refs}" | awk -v ref="refs/tags/${tag}^{}" '$2 == ref { print $1 }')"
if [ -z "${actual_sha}" ]; then
  actual_sha="$(printf '%s\n' "${remote_refs}" | awk -v ref="refs/tags/${tag}" '$2 == ref { print $1 }')"
fi

[ -n "${actual_sha}" ] || die "could not read ${tag} from ${remote}"

if [ "${actual_sha}" != "${expected_sha}" ]; then
  die "tag ${tag} moved during this release: resolved ${expected_sha}, remote now names ${actual_sha}. Nothing was published."
fi

printf 'tag %s still names %s on %s\n' "${tag}" "${expected_sha}" "${remote}"
