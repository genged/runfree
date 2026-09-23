#!/bin/sh
#
# Runfree session entry: the session container's first process.
#
# Argv is the typed agent launch, `[agentPath, ...agentArgs]`. The entry polls
# the request proxy with the exact admission readiness request (see
# `session-ready-probe`) until the proxy reports the session active, then
# replaces itself with the agent. Before activation the proxy answers every
# ordinary request 403, and a client that sends at start may exit, retry, or
# persist state on that answer; the entry moves the agent's first request past
# activation for every client.
#
# This is cooperation, not enforcement. A project image may replace it; a
# replaced entry that sends early receives the same 403s the proxy answers
# today. Nothing in the trust boundary depends on this file.
#
# Exit codes:
#   111  the wait bound elapsed without the proxy reporting the session active
#   143  SIGTERM while waiting (the container was stopped)
#   130  SIGINT while waiting
#    64  invalid argv or an invalid host-rendered wait bound
#
# The wait bound is `RUNFREE_SESSION_ENTRY_TIMEOUT_MS` (host-rendered into the
# pinned session environment; default 60000 when absent).

set -u

RUNFREE_SESSION_ENTRY_TIMEOUT_EXIT=111
RUNFREE_SESSION_ENTRY_USAGE_EXIT=64
RUNFREE_SESSION_ENTRY_DEFAULT_TIMEOUT_MS=60000
RUNFREE_SESSION_ENTRY_POLL_SLEEP=0.25
RUNFREE_SESSION_ENTRY_NOTICE_AFTER_S=2

if [ "$#" -eq 0 ]; then
  echo "runfree: session entry requires the agent path as its first argument" >&2
  exit "$RUNFREE_SESSION_ENTRY_USAGE_EXIT"
fi
case "$1" in
  /*) ;;
  *)
    echo "runfree: session entry agent path must be absolute: $1" >&2
    exit "$RUNFREE_SESSION_ENTRY_USAGE_EXIT"
    ;;
esac

timeout_ms="${RUNFREE_SESSION_ENTRY_TIMEOUT_MS:-$RUNFREE_SESSION_ENTRY_DEFAULT_TIMEOUT_MS}"
case "$timeout_ms" in
  ''|*[!0-9]*|0*)
    echo "runfree: RUNFREE_SESSION_ENTRY_TIMEOUT_MS must be a positive integer, got: $timeout_ms" >&2
    exit "$RUNFREE_SESSION_ENTRY_USAGE_EXIT"
    ;;
esac
# Whole seconds, rounded up: `date +%s` is the only portable clock in POSIX sh
# and one-second granularity is fine against a 60 s default bound.
timeout_s=$(( (timeout_ms + 999) / 1000 ))

entry_path="$0"
while [ -L "$entry_path" ]; do
  link_target="$(readlink "$entry_path")"
  case "$link_target" in
    /*) entry_path="$link_target" ;;
    *) entry_path="$(dirname -- "$entry_path")/$link_target" ;;
  esac
done
entry_dir="$(CDPATH= cd -- "$(dirname -- "$entry_path")" && pwd)"
probe="$entry_dir/session-ready-probe"

# The entry is PID 1 until it execs the agent, so a stop signal must end it
# promptly. Children run in the background and are awaited: a shell whose
# `wait` is interruptible runs the trap at once, and one that is not (dash)
# runs it as soon as the current child returns. Every child is bounded (the
# probe by its own 2 s total timeout, the pause by its 250 ms sleep), so a stop
# lands within one poll cycle either way. The handler ends the child first.
child=""
on_term() {
  [ -n "$child" ] && kill "$child" 2>/dev/null
  exit 143
}
on_int() {
  [ -n "$child" ] && kill "$child" 2>/dev/null
  exit 130
}
trap on_term TERM
trap on_int INT

run_interruptible() {
  "$@" &
  child=$!
  wait "$child"
  interruptible_status=$?
  child=""
  return "$interruptible_status"
}

started_at="$(date +%s)"
notified=0
while :; do
  if run_interruptible "$probe"; then
    break
  fi
  now="$(date +%s)"
  elapsed=$(( now - started_at ))
  if [ "$elapsed" -ge "$timeout_s" ]; then
    echo "runfree: session was not activated within ${timeout_ms} ms (RUNFREE_SESSION_ENTRY_TIMEOUT_MS); giving up" >&2
    exit "$RUNFREE_SESSION_ENTRY_TIMEOUT_EXIT"
  fi
  if [ "$notified" -eq 0 ] && [ "$elapsed" -ge "$RUNFREE_SESSION_ENTRY_NOTICE_AFTER_S" ]; then
    echo "runfree: waiting for session admission" >&2
    notified=1
  fi
  run_interruptible sleep "$RUNFREE_SESSION_ENTRY_POLL_SLEEP"
done

exec "$@"
