#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

all_targets=()
while IFS= read -r known_target; do
  [ -n "${known_target}" ] || continue
  all_targets+=("${known_target}")
done < <("${script_dir}/release-targets.sh" list)

if [ "$#" -gt 0 ]; then
  targets=("$@")
elif [ -n "${RUNFREE_ARTIFACT_TARGETS:-}" ]; then
  read -r -a targets <<< "${RUNFREE_ARTIFACT_TARGETS}"
else
  targets=("${all_targets[@]}")
fi

if [ "${#targets[@]}" -eq 0 ]; then
  printf 'no release targets selected\n' >&2
  exit 1
fi

is_known_target() {
  local candidate="$1"
  local target
  for target in "${all_targets[@]}"; do
    if [ "${candidate}" = "${target}" ]; then
      return 0
    fi
  done
  return 1
}

for target in "${targets[@]}"; do
  if ! is_known_target "${target}"; then
    printf 'unknown release target: %s\n' "${target}" >&2
    exit 1
  fi
done

for command in node bun tar; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "${command}" >&2
    exit 1
  fi
done

if [ -n "${RUNFREE_BUN_VERSION:-}" ]; then
  actual_bun_version="$(bun --version)"
  if [ "${actual_bun_version}" != "${RUNFREE_BUN_VERSION}" ]; then
    printf 'bun version mismatch: expected %s, got %s\n' "${RUNFREE_BUN_VERSION}" "${actual_bun_version}" >&2
    exit 1
  fi
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(
  node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).version)' \
    "${repo_root}/package.json"
)"
out_dir="${RUNFREE_ARTIFACT_DIR:-${repo_root}/dist/homebrew}"

mkdir -p "${out_dir}"

shopt -s nullglob
for stale_archive in "${out_dir}/runfree-${version}-"*.tar.gz; do
  stale_name="$(basename "${stale_archive}")"
  keep=0
  for target in "${targets[@]}"; do
    if [ "${stale_name}" = "runfree-${version}-${target}.tar.gz" ]; then
      keep=1
      break
    fi
  done
  if [ "${keep}" -ne 1 ]; then
    rm -f "${stale_archive}" "${stale_archive}.sha256"
  fi
done
shopt -u nullglob
rm -f "${out_dir}/runfree-${version}.sha256"

pnpm --dir "${repo_root}" build:runtime
pnpm --dir "${repo_root}" generate:assets

for target in "${targets[@]}"; do
  build_dir="${out_dir}/build/${target}"
  binary="${build_dir}/runfree"
  archive="${out_dir}/runfree-${version}-${target}.tar.gz"

  rm -rf "${build_dir}"
  mkdir -p "${build_dir}"

  bun_cwd="$(mktemp -d)"
  if ! (
    cd "${bun_cwd}"
    bun build "${repo_root}/packages/cli/src/cli.ts" \
      --compile \
      --target "bun-${target}" \
      --outfile "${binary}"
  ); then
    rm -rf "${bun_cwd}"
    exit 1
  fi
  rm -rf "${bun_cwd}"

  "${script_dir}/stage-release-archive.sh" stage "${build_dir}"
  archive_members=()
  while IFS= read -r member; do
    [ -n "${member}" ] || continue
    archive_members+=("${member}")
  done < <("${script_dir}/stage-release-archive.sh" members)
  tar -C "${build_dir}" -czf "${archive}" "${archive_members[@]}"
  printf 'built %s\n' "${target}"
done

if [ "${RUNFREE_SKIP_CHECKSUM:-}" != "1" ]; then
  RUNFREE_ARTIFACT_DIR="${out_dir}" "${repo_root}/scripts/checksum-release-artifacts.sh" "${version}"
fi

printf 'wrote Homebrew artifacts to %s\n' "${out_dir}"
