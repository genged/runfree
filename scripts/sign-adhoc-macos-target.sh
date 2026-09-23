#!/usr/bin/env bash
set -euo pipefail

# Ad-hoc signs one macOS release candidate, and packs the archive that ships.
#
# What an ad-hoc signature does and does not buy:
#
#   - it gives the binary a stable code-signing identifier, so macOS attributes
#     Runfree's permission prompts to Runfree rather than to whichever other
#     tool it recorded under the generic `a.out` first, and arm64 macOS will
#     load it at all;
#   - it carries no identity, no timestamp, no team, and no notarization
#     ticket. There is nothing for `spctl` to assess and nothing to revoke. A
#     user who downloads the tarball in a browser gets a Gatekeeper refusal,
#     because the download is quarantined and the signature proves no
#     publisher. The supported install paths (Homebrew and the install script)
#     fetch over curl, which sets no quarantine attribute.
#
# So this script deliberately does not run `spctl --assess`. An ad-hoc binary
# fails that assessment by definition; running it here would either fail every
# release or teach the reader that the assessment means something it does not.
# The SHA-256 manifest is what a user can verify against for this release.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

target="${1:-}"
if [ -z "${target}" ] || ! "${script_dir}/release-targets.sh" is-known "${target}"; then
  printf 'usage: %s <%s>\n' "$0" "$("${script_dir}/release-targets.sh" list | tr '\n' '|' | sed 's/|$//')" >&2
  exit 1
fi

for command in codesign tar; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "${command}" >&2
    exit 1
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${RUNFREE_RELEASE_VERSION:-}"
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

artifact_dir="${RUNFREE_ARTIFACT_DIR:-${repo_root}/dist/homebrew}"
build_dir="${artifact_dir}/build/${target}"
binary="${build_dir}/runfree"
archive="${artifact_dir}/runfree-${version}-${target}.tar.gz"

if [ ! -f "${binary}" ]; then
  printf 'missing release binary: %s\n' "${binary}" >&2
  exit 1
fi

native_smoke_supported() {
  local runner_arch target_arch
  runner_arch="$(uname -m)"
  case "${target##*-}" in
    arm64) target_arch="arm64" ;;
    x64) target_arch="x86_64" ;;
    *) return 1 ;;
  esac
  [ "${runner_arch}" = "${target_arch}" ]
}

run_native_smoke_for_path() {
  local smoke_binary="$1"
  local phase="$2"
  if native_smoke_supported; then
    "${smoke_binary}" help
    printf 'native %s smoke test passed for %s\n' "${phase}" "${target}"
  else
    printf 'skipping native %s smoke test for %s on %s\n' "${phase}" "${target}" "$(uname -m)"
  fi
}

tmp_root="${RUNNER_TEMP:-/tmp}"
mkdir -p "${tmp_root}"
tmp_dir="$(mktemp -d "${tmp_root}/runfree-adhoc-signing.XXXXXX")"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

run_native_smoke_for_path "${binary}" "pre-sign"

"${script_dir}/macos-code-signing.sh" sign-local "${binary}"
codesign --verify --strict --verbose=2 "${binary}"
"${script_dir}/macos-code-signing.sh" assert "${binary}"

rm -f "${archive}" "${archive}.sha256"
"${script_dir}/stage-release-archive.sh" stage "${build_dir}"
archive_members=()
while IFS= read -r member; do
  [ -n "${member}" ] || continue
  archive_members+=("${member}")
done < <("${script_dir}/stage-release-archive.sh" members)
tar -C "${build_dir}" -czf "${archive}" "${archive_members[@]}"

# Check the bytes that come back out of the archive, not only the file that was
# signed: a repack from a stale build directory would otherwise ship an
# unsigned or differently identified binary.
extract_dir="${tmp_dir}/final-artifact"
mkdir -p "${extract_dir}"
tar -xzf "${archive}" -C "${extract_dir}"
final_binary="${extract_dir}/runfree"
codesign --verify --strict --verbose=2 "${final_binary}"
"${script_dir}/macos-code-signing.sh" assert "${final_binary}"
run_native_smoke_for_path "${final_binary}" "post-sign"

# Record the hash of the exact bytes leaving this job, before the archive
# travels through artifact upload and download. The publication step re-hashes
# what arrives and refuses to publish if the two disagree. With no notarization
# ticket to check, this manifest is the release's only integrity evidence.
RUNFREE_ARTIFACT_DIR="${artifact_dir}" "${script_dir}/checksum-release-artifacts.sh" "${version}" "${target}"

printf 'wrote ad-hoc signed macOS artifact: %s\n' "${archive}"
