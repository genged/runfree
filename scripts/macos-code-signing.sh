#!/usr/bin/env bash
set -euo pipefail

# The macOS code-signing identifier of the Runfree CLI, in one place.
#
# A Bun-compiled executable carries no Info.plist, so codesign derives its
# identifier from the linker default: every such binary on a machine advertises
# `a.out`. macOS records Gatekeeper decisions, protected-folder decisions and
# keychain ACLs against that identifier, so Runfree shared an identity with
# every other generically signed tool on the host, and nothing the system
# recorded about Runfree named Runfree.
#
# The identifier is deliberately stable across releases and identical for local
# ad-hoc builds and Developer-ID release binaries. Changing it discards the
# TCC and Gatekeeper decisions users already made for Runfree, and a local
# build that signs differently from the release binary would not reproduce the
# release binary's prompts.

usage() {
  printf '%s\n' \
    'usage: scripts/macos-code-signing.sh <identifier|sign-local <binary>|assert <binary>>' \
    '' \
    '  identifier        print the expected code-signing identifier' \
    '  sign-local <bin>  ad-hoc sign a locally built binary with that identifier' \
    '  assert <bin>      exit non-zero unless the binary reports that identifier'
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
entitlements="${repo_root}/scripts/macos-entitlements.plist"

# Reverse-DNS, tool-scoped, and free of a version number: the identifier names
# the program, not the build.
runfree_code_signing_identifier="dev.runfree.cli"

die() {
  printf 'macos-code-signing: %s\n' "$*" >&2
  exit 1
}

require_codesign() {
  command -v codesign >/dev/null 2>&1 || die 'missing required command: codesign'
}

read_identifier() {
  local binary="$1"
  local display
  # codesign writes its display output to stderr.
  if ! display="$(codesign --display --verbose=2 "${binary}" 2>&1)"; then
    die "cannot read code signature of ${binary}"
  fi
  printf '%s\n' "${display}" | sed -n 's/^Identifier=//p' | head -n 1
}

case "${1:-}" in
  identifier)
    printf '%s\n' "${runfree_code_signing_identifier}"
    ;;
  sign-local)
    binary="${2:-}"
    [ -n "${binary}" ] || { usage >&2; exit 2; }
    [ -f "${binary}" ] || die "missing binary: ${binary}"
    [ -f "${entitlements}" ] || die "missing entitlements file: ${entitlements}"
    require_codesign
    # Ad-hoc, without the hardened runtime: a locally built binary is not
    # notarized and never passes Gatekeeper assessment. The point here is the
    # identifier, so that a developer build prompts as Runfree.
    codesign \
      --force \
      --sign - \
      --identifier "${runfree_code_signing_identifier}" \
      --entitlements "${entitlements}" \
      "${binary}"
    printf 'signed %s as %s\n' "${binary}" "${runfree_code_signing_identifier}"
    ;;
  assert)
    binary="${2:-}"
    [ -n "${binary}" ] || { usage >&2; exit 2; }
    [ -f "${binary}" ] || die "missing binary: ${binary}"
    require_codesign
    actual="$(read_identifier "${binary}")"
    if [ "${actual}" = "a.out" ]; then
      die "${binary} still carries the generic linker identifier a.out; it would share macOS permission prompts with unrelated tools. Expected ${runfree_code_signing_identifier}."
    fi
    if [ "${actual}" != "${runfree_code_signing_identifier}" ]; then
      die "${binary} reports code-signing identifier ${actual:-<none>}, expected ${runfree_code_signing_identifier}"
    fi
    printf 'code-signing identifier verified for %s: %s\n' "${binary}" "${actual}"
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac