#!/usr/bin/env bash
# dev-runfree.sh - run runfree from this checkout against an isolated XDG root.
#
# `bin/runfree.js` already runs the working tree's TypeScript without a build or
# an install, but it still reads and writes the same XDG roots the installed
# runfree uses. A development `up` therefore materializes runtime assets,
# records projects, and syncs proxy-managed credentials into the state your real
# runfree depends on. This wrapper redirects all three roots so it cannot.
#
# What this does NOT isolate: Docker. `composeProjectName` is
# `runfree-<sha256(projectRoot)[:12]>` — derived from the project's path alone,
# never from XDG state — so a development run against a directory your installed
# runfree also manages targets the same containers, networks, and volumes, and
# the two will fight over them. Point development runs at a scratch project
# directory, which is what --workspace is for.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Stable by default rather than under TMPDIR: the Docker resources a run creates
# outlive a reboot, and a wiped state root leaves `runfree destroy` unable to
# find the runtime it is meant to tear down, which orphans containers.
STATE_ROOT="${RUNFREE_DEV_STATE_ROOT:-${XDG_CACHE_HOME:-${HOME}/.cache}/runfree-dev}"

clean=0
print_env=0

usage() {
  cat <<'USAGE'
Usage: scripts/dev-runfree.sh [options] [--] [runfree args...]

Options:
  --state-root DIR  Isolated XDG root to use (default:
                    ${XDG_CACHE_HOME:-~/.cache}/runfree-dev, or
                    $RUNFREE_DEV_STATE_ROOT)
  --print-env       Print the environment assignments and exit, for `eval`
  --clean           Remove the isolated root and exit
  -h, --help        Show this help

Examples:
  scripts/dev-runfree.sh --workspace ~/scratch/demo up
  scripts/dev-runfree.sh --workspace ~/scratch/demo claude
  scripts/dev-runfree.sh --workspace ~/scratch/demo destroy
  eval "$(scripts/dev-runfree.sh --print-env)"   # then use ./bin/runfree.js directly
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --state-root)
      [ "$#" -ge 2 ] || { echo "dev-runfree: --state-root requires a directory" >&2; exit 1; }
      STATE_ROOT="$2"
      shift 2
      ;;
    --state-root=*)
      STATE_ROOT="${1#--state-root=}"
      shift
      ;;
    --print-env)
      print_env=1
      shift
      ;;
    --clean)
      clean=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      break
      ;;
  esac
done

# Absolute, so the printed paths and the child's env agree no matter the cwd.
case "$STATE_ROOT" in
  /*) ;;
  *) STATE_ROOT="$(pwd)/$STATE_ROOT" ;;
esac

if [ "$clean" -eq 1 ]; then
  if [ ! -e "$STATE_ROOT" ]; then
    echo "dev-runfree: nothing to remove at $STATE_ROOT"
    exit 0
  fi
  # Deliberately not silent: removing the state root while a runtime is up
  # strands its containers, and only the operator knows whether one is.
  echo "dev-runfree: removing $STATE_ROOT"
  echo "dev-runfree: if a development runtime is still up, run 'destroy' first or its containers are orphaned"
  rm -rf "$STATE_ROOT"
  exit 0
fi

if [ "$print_env" -eq 1 ]; then
  printf 'export XDG_DATA_HOME=%q\n' "$STATE_ROOT/data"
  printf 'export XDG_STATE_HOME=%q\n' "$STATE_ROOT/state"
  printf 'export XDG_CONFIG_HOME=%q\n' "$STATE_ROOT/config"
  exit 0
fi

if [ "$#" -eq 0 ]; then
  usage >&2
  exit 1
fi

mkdir -p "$STATE_ROOT/data" "$STATE_ROOT/state" "$STATE_ROOT/config"

# stderr, so it never contaminates a command whose stdout is parsed.
echo "dev-runfree: isolated XDG root $STATE_ROOT" >&2

XDG_DATA_HOME="$STATE_ROOT/data" \
XDG_STATE_HOME="$STATE_ROOT/state" \
XDG_CONFIG_HOME="$STATE_ROOT/config" \
exec "$REPO_ROOT/bin/runfree.js" "$@"
