#!/usr/bin/env bash
set -euo pipefail

# Run this with bash, not sh. It uses bash arrays, so `curl ... | sh` fails on a
# dash /bin/sh even though the shebang says bash: piping a script into an
# interpreter ignores its shebang. The documented command is `| bash`.
usage() {
  cat <<'EOF'
Usage: scripts/install.sh [--help]

Environment:
  RUNFREE_REPO         GitHub repository to install from. Default: genged/runfree
  RUNFREE_VERSION      Release version without or with leading v, or latest. Default: latest
  RUNFREE_INSTALL_DIR  Directory for the runfree binary. Default: $HOME/.local/bin

The installer downloads the matching release archive and checksum manifest,
verifies the archive checksum, extracts only the runfree binary, and installs it
with mode 0755. It never accepts or processes service credentials.
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

if [ "$#" -gt 0 ]; then
  printf 'unknown argument: %s\n\n' "$1" >&2
  usage >&2
  exit 2
fi

repo="${RUNFREE_REPO:-genged/runfree}"
version="${RUNFREE_VERSION:-latest}"
install_dir="${RUNFREE_INSTALL_DIR:-${HOME}/.local/bin}"

die() {
  printf 'runfree installer: %s\n' "$*" >&2
  exit 1
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

need_command curl
need_command tar
need_command install

if command -v shasum >/dev/null 2>&1; then
  checksum_command=(shasum -a 256)
elif command -v sha256sum >/dev/null 2>&1; then
  checksum_command=(sha256sum)
else
  die "missing required command: shasum or sha256sum"
fi

# This script is fetched standalone, so it cannot read
# scripts/release-targets.txt the way the packaging scripts do. The mapping
# below must stay equal to that list; scripts/install-script.test.ts asserts it,
# so an installer that offers a target the release does not build fails in CI
# rather than at a user's shell.
os_name="$(uname -s)"
arch_name="$(uname -m)"
case "${os_name}:${arch_name}" in
  Darwin:arm64) target="darwin-arm64" ;;
  Darwin:x86_64) die "Intel macOS release binaries are not published; Runfree 0.5.0 supports Apple Silicon macOS only. Build from source to run on Intel." ;;
  Linux:*) die "Linux release binaries are not published yet; build from source on Linux" ;;
  *) die "unsupported OS/architecture: ${os_name} ${arch_name}" ;;
esac

if [ "${version}" = "latest" ]; then
  latest_json="$(mktemp)"
  curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" -o "${latest_json}"
  tag="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${latest_json}" | head -n 1)"
  rm -f "${latest_json}"
  [ -n "${tag}" ] || die "could not resolve latest release tag for ${repo}"
  version="${tag#v}"
else
  version="${version#v}"
fi

[ -n "${version}" ] || die "empty release version"

archive_name="runfree-${version}-${target}.tar.gz"
manifest_name="runfree-${version}.sha256"
base_url="https://github.com/${repo}/releases/download/v${version}"
archive_url="${base_url}/${archive_name}"
manifest_url="${base_url}/${manifest_name}"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

archive_path="${tmp_dir}/${archive_name}"
manifest_path="${tmp_dir}/${manifest_name}"
extract_dir="${tmp_dir}/extract"

curl -fsSL "${archive_url}" -o "${archive_path}"
curl -fsSL "${manifest_url}" -o "${manifest_path}"

expected_hash=""
while read -r hash file _rest; do
  case "${file}" in
    "${archive_name}" | */"${archive_name}")
      expected_hash="${hash}"
      break
      ;;
  esac
done < "${manifest_path}"

[ -n "${expected_hash}" ] || die "${manifest_name} does not contain ${archive_name}"

actual_hash="$("${checksum_command[@]}" "${archive_path}" | awk '{ print $1 }')"
if [ "${actual_hash}" != "${expected_hash}" ]; then
  die "checksum mismatch for ${archive_name}: expected ${expected_hash}, got ${actual_hash}"
fi

mkdir -p "${extract_dir}"
tar -xzf "${archive_path}" -C "${extract_dir}" runfree
[ -f "${extract_dir}/runfree" ] || die "archive did not contain runfree binary"

install -d -m 0755 "${install_dir}"
install -m 0755 "${extract_dir}/runfree" "${install_dir}/runfree"

printf 'installed runfree to %s\n' "${install_dir}/runfree"
case ":${PATH:-}:" in
  *:"${install_dir}":*) ;;
  *) printf 'warning: %s is not on PATH\n' "${install_dir}" >&2 ;;
esac
