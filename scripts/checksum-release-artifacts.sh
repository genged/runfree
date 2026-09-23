#!/usr/bin/env bash
set -euo pipefail

# Hashes release archives, in two modes.
#
#   scripts/checksum-release-artifacts.sh <version> <target>...
#     Per-target mode, run on the build runner right after signing. Writes
#     runfree-<version>-<target>.tar.gz.sha256 next to the archive so the exact
#     bytes leaving the signing job are recorded before they travel.
#
#   scripts/checksum-release-artifacts.sh <version>
#     Publication mode. Requires an archive for every advertised release target,
#     re-hashes each one, and refuses to continue if a per-target record from the
#     build job disagrees with what arrived. That mismatch is the case this gate
#     exists for: a repacked, truncated, or substituted candidate would otherwise
#     be published under a manifest generated from the substituted bytes, and the
#     manifest would agree with itself.
#
# Inputs (environment):
#   RUNFREE_ARTIFACT_DIR   directory holding the archives; defaults to dist/homebrew

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-}"
shift || true
requested_targets=("$@")
out_dir="${RUNFREE_ARTIFACT_DIR:-${repo_root}/dist/homebrew}"

if [ -z "${version}" ]; then
  if ! command -v node >/dev/null 2>&1; then
    printf 'missing required command: node\n' >&2
    exit 1
  fi
  version="$(
    node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).version)' \
      "${repo_root}/package.json"
  )"
fi

if command -v shasum >/dev/null 2>&1; then
  checksum_command=(shasum -a 256)
elif command -v sha256sum >/dev/null 2>&1; then
  checksum_command=(sha256sum)
else
  printf 'missing required command: shasum or sha256sum\n' >&2
  exit 1
fi

release_targets=()
while IFS= read -r target; do
  [ -n "${target}" ] || continue
  release_targets+=("${target}")
done < <("${repo_root}/scripts/release-targets.sh" list)

if [ "${#requested_targets[@]}" -gt 0 ]; then
  for target in "${requested_targets[@]}"; do
    if ! "${repo_root}/scripts/release-targets.sh" is-known "${target}"; then
      printf 'unknown release target: %s\n' "${target}" >&2
      exit 1
    fi
    name="runfree-${version}-${target}.tar.gz"
    if [ ! -f "${out_dir}/${name}" ]; then
      printf 'missing release tarball: %s\n' "${out_dir}/${name}" >&2
      exit 1
    fi
    (
      cd "${out_dir}"
      "${checksum_command[@]}" "${name}" > "${name}.sha256"
    )
    printf 'wrote %s\n' "${out_dir}/${name}.sha256"
  done
  exit 0
fi

names=()
for target in "${release_targets[@]}"; do
  name="runfree-${version}-${target}.tar.gz"
  if [ ! -f "${out_dir}/${name}" ]; then
    printf 'missing release tarball: %s\n' "${out_dir}/${name}" >&2
    exit 1
  fi
  names+=("${name}")
done

for name in "${names[@]}"; do
  recorded_file="${out_dir}/${name}.sha256"
  [ -f "${recorded_file}" ] || continue
  recorded_hash="$(awk 'NR == 1 { print $1 }' "${recorded_file}")"
  actual_hash="$(cd "${out_dir}" && "${checksum_command[@]}" "${name}" | awk '{ print $1 }')"
  if [ -z "${recorded_hash}" ]; then
    printf 'unreadable recorded checksum: %s\n' "${recorded_file}" >&2
    exit 1
  fi
  if [ "${recorded_hash}" != "${actual_hash}" ]; then
    printf 'candidate checksum mismatch for %s: build job recorded %s, this copy hashes %s. Nothing was published.\n' \
      "${name}" "${recorded_hash}" "${actual_hash}" >&2
    exit 1
  fi
  printf 'verified %s against its build-job checksum\n' "${name}"
done

(
  cd "${out_dir}"
  "${checksum_command[@]}" "${names[@]}" > "runfree-${version}.sha256"
)

printf 'wrote %s\n' "${out_dir}/runfree-${version}.sha256"
