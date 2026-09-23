#!/usr/bin/env bash
set -euo pipefail

# Called after resolve-release-tag has checked ancestry and the requested SHA.
# A duplicate event skips a published release; the publisher still refuses any
# overwrite, and draft recovery still requires replace_assets=true.
printf 'ready=false\n' >> "${GITHUB_OUTPUT}"
releases="$(gh api "repos/${REPO:?}/releases?per_page=100" --paginate --slurp)"
published="$(jq -r --arg tag "${TAG:?}" 'any(.[][]; .tag_name == $tag and .draft == false)' <<< "${releases}")"
if [ "${published}" = true ]; then
  published_sha="$(jq -r --arg tag "${TAG}" '.[][] | select(.tag_name == $tag and .draft == false) | .target_commitish' <<< "${releases}")"
  if [ "${published_sha}" != "${SHA:?}" ]; then
    printf 'release %s published source %s does not match requested SHA %s; refusing duplicate release\n' "${TAG}" "${published_sha}" "${SHA}" >&2
    exit 1
  fi
  printf '%s is already published. Skipping this release.\n' "${TAG}"
  exit 0
fi

printf 'ready=true\n' >> "${GITHUB_OUTPUT}"
