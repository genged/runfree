#!/usr/bin/env bash
# Discover release requests for the Release workflow. Tag pushes and manual
# dispatches resolve one tag to its commit SHA.
# Writes targets=[{tag,sha},...] to GITHUB_OUTPUT for the per-tag release matrix.
# This only discovers requests; the release lane checks ancestry and whether the
# release is already published before building or publishing.
set -euo pipefail

repository="${GITHUB_REPOSITORY:?repository is required}"
event="${GITHUB_EVENT_PATH:?event payload is required}"
tag_pattern='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$'

case "${GITHUB_EVENT_NAME}" in
  push|workflow_dispatch)
    if [ "${GITHUB_EVENT_NAME}" = workflow_dispatch ]; then
      tag="$(jq -er '.inputs.tag' "${event}")"
    else
      [[ "${GITHUB_REF}" = refs/tags/* ]] || { printf 'release push must name a tag\n' >&2; exit 1; }
      tag="${GITHUB_REF#refs/tags/}"
    fi
    [[ "${tag}" =~ ${tag_pattern} ]] || { printf 'invalid release tag: %s\n' "${tag}" >&2; exit 1; }
    sha="$(gh api "repos/${repository}/commits/refs/tags/${tag}" --jq .sha)"
    [[ "${sha}" =~ ^[0-9a-f]{40}$ ]] || { printf 'invalid tagged commit: %s\n' "${sha}" >&2; exit 1; }
    targets="$(jq -cn --arg tag "${tag}" --arg sha "${sha}" '[{tag: $tag, sha: $sha}]')"
    ;;
  *) printf 'unsupported release event: %s\n' "${GITHUB_EVENT_NAME}" >&2; exit 1 ;;
esac

printf 'Release requests: %s\n' "${targets}"
printf 'targets=%s\n' "${targets}" >> "${GITHUB_OUTPUT}"
