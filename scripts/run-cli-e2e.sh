#!/usr/bin/env bash
set -euo pipefail

build=1
project="cli-e2e"

usage() {
  printf '%s\n' \
    'usage: scripts/run-cli-e2e.sh [--no-build] [--live]' \
    '' \
    '  default     build dist/runfree, then run packaged offline scenarios' \
    '  --no-build  test the absolute executable in RUNFREE_E2E_ARTIFACT' \
    '  --live      run the real-Docker packaged runtime scenario'
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-build) build=0 ;;
    --live) project="cli-e2e-live" ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$build" -eq 1 ]; then
  pnpm --dir "$repo_root" run build:bin
  RUNFREE_E2E_ARTIFACT="$repo_root/dist/runfree"
elif [ -z "${RUNFREE_E2E_ARTIFACT:-}" ]; then
  printf 'RUNFREE_E2E_ARTIFACT is required with --no-build and must name the absolute packaged executable\n' >&2
  exit 1
fi

case "$RUNFREE_E2E_ARTIFACT" in
  /*) ;;
  *) printf 'RUNFREE_E2E_ARTIFACT must be absolute: %s\n' "$RUNFREE_E2E_ARTIFACT" >&2; exit 1 ;;
esac

RUNFREE_E2E_REPORT="${RUNFREE_E2E_REPORT:-$repo_root/dist/e2e-evidence.json}"
export RUNFREE_E2E_ARTIFACT RUNFREE_E2E_REPORT

if [ "$project" = "cli-e2e-live" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    printf 'docker is required for --live\n' >&2
    exit 1
  fi
  RUNFREE_E2E_DOCKER_HOST="${RUNFREE_E2E_DOCKER_HOST:-$(docker context inspect --format '{{.Endpoints.docker.Host}}')}"
  TEST_RUNTIME_BACKEND="${TEST_RUNTIME_BACKEND:-docker-desktop}"
  export RUNFREE_E2E_DOCKER_HOST TEST_RUNTIME_BACKEND
fi

pnpm --dir "$repo_root" exec vitest run --project "$project"
