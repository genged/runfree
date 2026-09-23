#!/usr/bin/env bash
set -euo pipefail

# Reads scripts/release-targets.txt so the packaging, signing, checksum,
# acceptance, installer, and GitHub Actions matrix paths cannot drift apart.
#
# Parsing stays in pure shell on purpose: the packaging scripts run under fake
# tool PATHs in their tests, so depending on node or jq here would make the
# target list a function of whichever stub answered.

usage() {
  printf '%s\n' \
    'usage: scripts/release-targets.sh <list|runner <target>|matrix|is-known <target>>' \
    '' \
    '  list              print every release target, one per line' \
    '  runner <target>   print the GitHub Actions runner label for one target' \
    '  matrix            print the build matrix include list as JSON' \
    '  is-known <target> exit 0 when the target is a release target'
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
targets_file="${RUNFREE_RELEASE_TARGETS_FILE:-${repo_root}/scripts/release-targets.txt}"

if [ ! -f "${targets_file}" ]; then
  printf 'missing release target list: %s\n' "${targets_file}" >&2
  exit 1
fi

target_names=()
target_runners=()
while IFS= read -r line || [ -n "${line}" ]; do
  line="${line%%#*}"
  # shellcheck disable=SC2295
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  [ -n "${line}" ] || continue
  read -r name runner _rest <<< "${line}"
  if [ -z "${name}" ] || [ -z "${runner}" ]; then
    printf 'malformed release target row: %s\n' "${line}" >&2
    exit 1
  fi
  target_names+=("${name}")
  target_runners+=("${runner}")
done < "${targets_file}"

if [ "${#target_names[@]}" -eq 0 ]; then
  printf 'release target list is empty: %s\n' "${targets_file}" >&2
  exit 1
fi

runner_for() {
  local wanted="$1"
  local index=0
  while [ "${index}" -lt "${#target_names[@]}" ]; do
    if [ "${target_names[${index}]}" = "${wanted}" ]; then
      printf '%s\n' "${target_runners[${index}]}"
      return 0
    fi
    index=$((index + 1))
  done
  return 1
}

command_name="${1:-}"
case "${command_name}" in
  list)
    printf '%s\n' "${target_names[@]}"
    ;;
  runner)
    wanted="${2:-}"
    if [ -z "${wanted}" ]; then
      usage >&2
      exit 2
    fi
    if ! runner_for "${wanted}"; then
      printf 'unknown release target: %s\n' "${wanted}" >&2
      exit 1
    fi
    ;;
  is-known)
    wanted="${2:-}"
    if [ -z "${wanted}" ]; then
      usage >&2
      exit 2
    fi
    runner_for "${wanted}" >/dev/null
    ;;
  matrix)
    printf '['
    index=0
    while [ "${index}" -lt "${#target_names[@]}" ]; do
      if [ "${index}" -gt 0 ]; then
        printf ','
      fi
      printf '{"target":"%s","runner":"%s"}' "${target_names[${index}]}" "${target_runners[${index}]}"
      index=$((index + 1))
    done
    printf ']\n'
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
