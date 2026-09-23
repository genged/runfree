#!/usr/bin/env bash
set -euo pipefail

# Defines what a release archive contains, in one place.
#
# Two scripts build the tarball: scripts/package-homebrew-artifacts.sh produces
# the unsigned candidate, and scripts/sign-adhoc-macos-target.sh re-packs it
# after codesigning. If each kept its own file list they could drift, and the
# published archive would not match the one the candidate tests ran against.
#
# Redistribution: a compiled Runfree binary carries third-party code, so the
# license and notice files ship inside the archive rather than only in the
# repository.

usage() {
  printf '%s\n' \
    'usage: scripts/stage-release-archive.sh <members|stage <build-dir>>' \
    '' \
    '  members            print the archive member names, one per line' \
    '  stage <build-dir>  copy the redistribution files next to the built binary'
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The binary first: the installer and the candidate acceptance step extract
# `runfree` by name.
members=(
  "runfree"
  "LICENSE"
  "NOTICE"
)

# Members that are copied in from the repository rather than built.
staged_members=(
  "LICENSE"
  "NOTICE"
)

case "${1:-}" in
  members)
    printf '%s\n' "${members[@]}"
    ;;
  stage)
    build_dir="${2:-}"
    if [ -z "${build_dir}" ]; then
      usage >&2
      exit 2
    fi
    if [ ! -d "${build_dir}" ]; then
      printf 'missing build directory: %s\n' "${build_dir}" >&2
      exit 1
    fi
    for member in "${staged_members[@]}"; do
      source_path="${repo_root}/${member}"
      if [ ! -f "${source_path}" ]; then
        printf 'missing redistribution file: %s\n' "${source_path}" >&2
        exit 1
      fi
      cp "${source_path}" "${build_dir}/${member}"
    done
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
