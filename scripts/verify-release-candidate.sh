#!/usr/bin/env bash
set -euo pipefail

# Accepts one signed release candidate as bytes, before anything publishes it.
#
# Source tests prove the tree builds a working CLI. They say nothing about the
# archive that actually ships: the archive can be repacked, truncated, signed
# from a stale build directory, or built from a different version of the tree,
# and every source test stays green. So this runs against the downloaded
# archive: verify it against the hash the signing job recorded, extract it,
# confirm it carries its redistribution files, and ask the extracted binary
# which version it is.
#
# Prints the absolute path of the extracted executable on the last line, for
# RUNFREE_E2E_ARTIFACT.
#
# Inputs:
#   $1                      release version, without the leading v
#   $2                      release target
# Environment:
#   RUNFREE_ARTIFACT_DIR    directory holding the downloaded archive
#   RUNFREE_CANDIDATE_DIR   extraction directory; defaults to <artifact dir>/candidate/<target>

die() {
  printf 'verify-release-candidate: %s\n' "$*" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_dir="${repo_root}/scripts"

version="${1:-}"
target="${2:-}"

[ -n "${version}" ] || die 'usage: scripts/verify-release-candidate.sh <version> <target>'
[ -n "${target}" ] || die 'usage: scripts/verify-release-candidate.sh <version> <target>'
"${script_dir}/release-targets.sh" is-known "${target}" || die "unknown release target: ${target}"

artifact_dir="${RUNFREE_ARTIFACT_DIR:-${repo_root}/dist/release}"
candidate_dir="${RUNFREE_CANDIDATE_DIR:-${artifact_dir}/candidate/${target}}"

archive_name="runfree-${version}-${target}.tar.gz"
archive="${artifact_dir}/${archive_name}"
recorded_file="${archive}.sha256"

[ -f "${archive}" ] || die "missing release archive: ${archive}"
[ -f "${recorded_file}" ] || die "missing candidate checksum: ${recorded_file}"

if command -v shasum >/dev/null 2>&1; then
  checksum_command=(shasum -a 256)
elif command -v sha256sum >/dev/null 2>&1; then
  checksum_command=(sha256sum)
else
  die 'missing required command: shasum or sha256sum'
fi

recorded_hash="$(awk 'NR == 1 { print $1 }' "${recorded_file}")"
[ -n "${recorded_hash}" ] || die "unreadable candidate checksum: ${recorded_file}"
actual_hash="$(cd "${artifact_dir}" && "${checksum_command[@]}" "${archive_name}" | awk '{ print $1 }')"

if [ "${recorded_hash}" != "${actual_hash}" ]; then
  die "checksum mismatch for ${archive_name}: signing job recorded ${recorded_hash}, this copy hashes ${actual_hash}"
fi
printf 'checksum verified for %s: %s\n' "${archive_name}" "${actual_hash}" >&2

rm -rf "${candidate_dir}"
mkdir -p "${candidate_dir}"
tar -xzf "${archive}" -C "${candidate_dir}"

while IFS= read -r member; do
  [ -n "${member}" ] || continue
  [ -e "${candidate_dir}/${member}" ] || die "release archive ${archive_name} is missing ${member}"
done < <("${script_dir}/stage-release-archive.sh" members)

binary="${candidate_dir}/runfree"
[ -x "${binary}" ] || die "extracted runfree is not executable: ${binary}"

reported_version="$("${binary}" version)"
if [ "${reported_version}" != "${version}" ]; then
  die "candidate reports version ${reported_version}, release is ${version}"
fi
printf 'candidate reports version %s\n' "${reported_version}" >&2

printf '%s\n' "${binary}"
