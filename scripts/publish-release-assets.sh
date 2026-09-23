#!/usr/bin/env bash
set -euo pipefail

# Publishes the exact archives the release run built, signed, and accepted.
#
# Three rules this enforces, each with a failure it exists to prevent:
#
#   * Every advertised target must be present. Publishing a partial set gives
#     users an install command that resolves to a missing asset.
#   * A published release is immutable. Replacing the bytes behind a tag people
#     have already downloaded and checksummed is indistinguishable from an
#     attack; fixes ship as a new patch release. Recovery is limited to a draft
#     the same run left behind.
#   * Draft recovery must be the same candidate. It re-checks the source SHA the
#     draft was created for and the checksum manifest already attached to it, so
#     a rebuild from different bytes cannot be uploaded over a half-finished
#     draft under the same tag.
#
# Inputs (environment):
#   TAG                    required, the release tag
#   VERSION                required, the release version without the leading v
#   SHA                    required, the resolved release commit
#   REPLACE_ASSETS         optional, "true" to allow draft recovery
#   RUNFREE_ARTIFACT_DIR   required, directory holding the final archives
#   GH_TOKEN               required by gh, needs contents:write

die() {
  printf 'publish-release-assets: %s\n' "$*" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_dir="${repo_root}/scripts"

tag="${TAG:-}"
version="${VERSION:-}"
sha="${SHA:-}"
replace_assets="${REPLACE_ASSETS:-false}"
artifact_dir="${RUNFREE_ARTIFACT_DIR:-${repo_root}/dist/release}"

[ -n "${tag}" ] || die 'TAG is required'
[ -n "${version}" ] || die 'VERSION is required'
[ -n "${sha}" ] || die 'SHA is required'
printf '%s' "${sha}" | grep -Eq '^[0-9a-f]{40}$' || die "SHA must be a full commit SHA, got ${sha}"
command -v gh >/dev/null 2>&1 || die 'missing required command: gh'

notes_file="${RUNFREE_RELEASE_NOTES_FILE:-${repo_root}/docs/release-notes/${version}.md}"
if [ ! -f "${notes_file}" ]; then
  die "missing release notes: ${notes_file}. Write the release body before publishing; a published body is fixed afterwards and corrections have to ship as errata."
fi

manifest_name="runfree-${version}.sha256"
manifest_path="${artifact_dir}/${manifest_name}"
[ -f "${manifest_path}" ] || die "missing checksum manifest: ${manifest_path}"

assets=()
while IFS= read -r target; do
  [ -n "${target}" ] || continue
  archive="${artifact_dir}/runfree-${version}-${target}.tar.gz"
  [ -f "${archive}" ] || die "missing release archive for advertised target ${target}: ${archive}"
  assets+=("${archive}")
done < <("${script_dir}/release-targets.sh" list)

[ "${#assets[@]}" -gt 0 ] || die 'no release targets are configured'
assets+=("${manifest_path}")

read_release_field() {
  # Reads one field out of the `gh release view --json` payload. node rather
  # than gh's --jq so the existence check stays a single gh call: asking gh
  # twice could straddle a concurrent change to the release.
  printf '%s' "$1" | node -e '
    const field = process.argv[1];
    let raw = "";
    process.stdin.on("data", (chunk) => { raw += chunk; });
    process.stdin.on("end", () => {
      let parsed;
      try {
        parsed = JSON.parse(raw || "{}");
      } catch {
        process.exit(1);
      }
      process.stdout.write(String(parsed?.[field] ?? ""));
    });
  ' "$2"
}

if existing_release="$(gh release view "${tag}" --json isDraft,targetCommitish 2>/dev/null)"; then
  command -v node >/dev/null 2>&1 || die 'missing required command: node'
  is_draft="$(read_release_field "${existing_release}" isDraft)"
  target_commitish="$(read_release_field "${existing_release}" targetCommitish)"

  if [ "${is_draft}" != "true" ]; then
    die "release ${tag} is already published. Public release assets are immutable: ship the fix as a new patch tag rather than replacing bytes users have already downloaded."
  fi

  if [ "${replace_assets}" != "true" ]; then
    die "a draft release already exists for ${tag}. Re-run this workflow with replace_assets=true to finish that draft, or delete it and tag a new patch release."
  fi

  if [ "${target_commitish}" != "${sha}" ]; then
    die "draft ${tag} was created for ${target_commitish}, this run resolved ${sha}. Recovery does not move a draft to different source. Delete the draft and start again."
  fi

  existing_dir="${artifact_dir}/existing-assets"
  rm -rf "${existing_dir}"
  mkdir -p "${existing_dir}"
  if gh release download "${tag}" --pattern "${manifest_name}" --dir "${existing_dir}" 2>/dev/null; then
    if ! diff -u "${existing_dir}/${manifest_name}" "${manifest_path}" >&2; then
      die "draft ${tag} already carries a different checksum manifest. These are not the same candidate bytes; recovery stopped without uploading."
    fi
    printf 'draft %s carries the same candidate hashes\n' "${tag}"
  fi

  printf 'finishing draft %s for %s\n' "${tag}" "${sha}"
  gh release upload "${tag}" "${assets[@]}" --clobber
  gh release edit "${tag}" --draft=false --notes-file "${notes_file}"
else
  printf 'publishing %s for %s\n' "${tag}" "${sha}"
  gh release create "${tag}" "${assets[@]}" \
    --verify-tag \
    --target "${sha}" \
    --notes-file "${notes_file}"
fi

printf 'published %s assets for %s\n' "${#assets[@]}" "${tag}"
