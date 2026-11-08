#!/bin/sh
#
# Runfree session entry: the session container's first project-controlled
# process (under Docker's init in a new session; PID 1 in an older one).
#
# Argv is the typed agent launch, `[agentPath, ...agentArgs]`, optionally
# preceded by `--stdin-file <promptPath>` for a headless run (headless-run
# spec §3.2). The prompt path must name one host-minted run file directly in
# the read-only inbox mount (`/runfree/inbox/run-*.prompt`); the entry opens
# it as the agent's stdin in the final `exec`, so the prompt is data on stdin
# and never agent argv. The host's launch builder is the authority on that
# path; the check here only refuses a malformed argv early. The entry polls
# the request proxy with the exact admission readiness request (see
# `session-ready-probe`) until the proxy reports the session active, then
# replaces itself with the agent. Before activation the proxy answers every
# ordinary request 403, and a client that sends at start may exit, retry, or
# persist state on that answer; the entry moves the agent's first request past
# activation for every client.
#
# When `RUNFREE_HOST_SERVICES` is set, the entry also starts
# `host-service-relay` in the background, before the readiness loop, and
# never waits on it: a missing relay binary, a crash, or a bind failure never
# changes this entry's exit code and never delays the final `exec` below. The
# relay stays this entry's direct (non-detached) child, so the handoff's
# process shape is unchanged. It is killed alongside the probe on a stop
# signal and on the entry's own activation-timeout exit (111); only the
# final `exec` below leaves it running, deliberately, for the rest of the
# session. See local/specs/2026-10-03-host-services-design.md, "The
# agent-side relay".
#
# This is cooperation, not enforcement. A project image may replace it; a
# replaced entry that sends early receives the same 403s the proxy answers
# today. Nothing in the trust boundary depends on this file.
#
# Exit codes:
#   111  the wait bound elapsed without the proxy reporting the session active
#   112  the readiness probe itself could not run (missing, not executable,
#        or refusing its own argv): a project image that changed this entry's
#        directory, never the proxy, and never worth the whole wait bound
#   143  SIGTERM while waiting (the container was stopped)
#   130  SIGINT while waiting
#    64  invalid argv or an invalid host-rendered wait bound
#    66  the `--stdin-file` prompt cannot be read (checked before the wait;
#        the final `exec` opens it again, and a shell that survives a failed
#        redirection there also exits 66 rather than run the agent)
#
# The wait bound is `RUNFREE_SESSION_ENTRY_TIMEOUT_MS` (host-rendered into the
# pinned session environment; default 60000 when absent).

set -u

RUNFREE_SESSION_ENTRY_TIMEOUT_EXIT=111
RUNFREE_SESSION_ENTRY_PROBE_EXIT=112
RUNFREE_SESSION_ENTRY_USAGE_EXIT=64
RUNFREE_SESSION_ENTRY_DEFAULT_TIMEOUT_MS=60000
# Between probe runs. A run itself retries for up to 2 s (see
# session-ready-probe), so this pause only spaces runs out.
RUNFREE_SESSION_ENTRY_POLL_SLEEP=0.02
RUNFREE_SESSION_ENTRY_NOTICE_AFTER_S=2

RUNFREE_SESSION_ENTRY_NO_INPUT_EXIT=66

# Test seam only: unit tests cannot write the fixed read-only inbox mount. The
# session environment is host-pinned and never renders this name, so a
# session always names the fixed inbox.
inbox_dir="${RUNFREE_SESSION_ENTRY_INBOX_DIR:-/runfree/inbox}"
case "$inbox_dir" in
  /*) ;;
  *)
    echo "runfree: session entry RUNFREE_SESSION_ENTRY_INBOX_DIR must be absolute, got: $inbox_dir" >&2
    exit "$RUNFREE_SESSION_ENTRY_USAGE_EXIT"
    ;;
esac

stdin_file=""
if [ "$#" -gt 0 ] && [ "$1" = "--stdin-file" ]; then
  if [ "$#" -lt 2 ]; then
    echo "runfree: session entry --stdin-file requires a prompt path" >&2
    exit "$RUNFREE_SESSION_ENTRY_USAGE_EXIT"
  fi
  # One run file directly in the inbox: the prefix is matched literally, and
  # the rest may hold no `/`, so no nesting and no `..` component is possible.
  prompt_name="${2#"$inbox_dir"/}"
  case "$2" in
    "$inbox_dir"/run-*.prompt) ;;
    *) prompt_name="/" ;;
  esac
  case "$prompt_name" in
    */*)
      echo "runfree: session entry prompt path must be one run file directly in $inbox_dir: $2" >&2
      exit "$RUNFREE_SESSION_ENTRY_USAGE_EXIT"
      ;;
  esac
  stdin_file="$2"
  shift 2
fi

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

# A missing prompt fails here, before the wait, rather than after the
# session is already active and served.
if [ -n "$stdin_file" ] && { [ ! -f "$stdin_file" ] || [ ! -r "$stdin_file" ]; }; then
  echo "runfree: session entry cannot read the prompt file: $stdin_file" >&2
  exit "$RUNFREE_SESSION_ENTRY_NO_INPUT_EXIT"
fi

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

# Started before the readiness loop and never awaited (see header comment).
# The relay never writes stdout; discarding it here is belt-and-suspenders
# alongside the relay's own post-bind rule against writing to the TUI.
relay="$entry_dir/host-service-relay"
relay_pid=""
if [ -n "${RUNFREE_HOST_SERVICES:-}" ] && [ -x "$relay" ]; then
  "$relay" </dev/null >/dev/null &
  relay_pid=$!
fi

# A stop signal must end the entry promptly. In a session created since
# 2026-09-30 the entry is the child of Docker's init (`docker-init`, PID 1),
# which forwards SIGTERM/SIGINT to it; in an older session container (created
# without `--init`) the entry itself is PID 1, where the kernel drops any
# signal it has no handler for. The traps below cover both: without them a
# PID 1 entry would ignore `docker stop` until the SIGKILL.
#
# Children run in the background and are awaited: a shell whose `wait` is
# interruptible (dash and bash both are) runs the trap at once, and one that
# is not would run it as soon as the current child returns. Every child is
# bounded (a probe run by its own 2 s total budget, the pause by its 20 ms
# sleep), so a stop lands within one probe run either way. The handler ends
# the child first.
child=""
on_term() {
  [ -n "$child" ] && kill "$child" 2>/dev/null
  [ -n "$relay_pid" ] && kill "$relay_pid" 2>/dev/null
  exit 143
}
on_int() {
  [ -n "$child" ] && kill "$child" 2>/dev/null
  [ -n "$relay_pid" ] && kill "$relay_pid" 2>/dev/null
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
  # The probe's own usage exit (64) and the shell's cannot-run statuses (126:
  # not executable, 127: not found) are not answers from the proxy: polling
  # them for the whole bound printed the same failure thousands of times and
  # then blamed the proxy.
  case "$interruptible_status" in
    64|126|127)
      echo "runfree: session readiness probe could not run (exit $interruptible_status): $probe; the agent image's session entry directory is not intact" >&2
      [ -n "$relay_pid" ] && kill "$relay_pid" 2>/dev/null
      exit "$RUNFREE_SESSION_ENTRY_PROBE_EXIT"
      ;;
  esac
  now="$(date +%s)"
  elapsed=$(( now - started_at ))
  if [ "$elapsed" -ge "$timeout_s" ]; then
    echo "runfree: session was not activated within ${timeout_ms} ms (RUNFREE_SESSION_ENTRY_TIMEOUT_MS); giving up" >&2
    [ -n "$relay_pid" ] && kill "$relay_pid" 2>/dev/null
    exit "$RUNFREE_SESSION_ENTRY_TIMEOUT_EXIT"
  fi
  if [ "$notified" -eq 0 ] && [ "$elapsed" -ge "$RUNFREE_SESSION_ENTRY_NOTICE_AFTER_S" ]; then
    echo "runfree: waiting for session admission" >&2
    notified=1
  fi
  run_interruptible sleep "$RUNFREE_SESSION_ENTRY_POLL_SLEEP"
done

# The handoff. The host keeps the launch's lifecycle lock, and reports the
# session `attached`, until it observes (with a daemon-side `docker container
# top`, never an exec) that the container's anchored process — the init's
# child, or PID 1 in a container without the init — no longer runs this
# entry, or until a 10 s ceiling. So this exec must stay the entry's last act
# once the probe has answered active: anything the entry did in between would
# run while the session is already served but not yet reported attached. Changing the poll above (its sleep, its probe)
# only changes how soon this line is reached. A headless run's prompt is
# opened here, as part of the exec itself, and nowhere earlier: no probe or
# relay child ever holds it.
if [ -n "$stdin_file" ]; then
  # `command exec`: a redirection that fails on the special built-in `exec`
  # ends a non-interactive POSIX shell with the shell's own status (2 under
  # dash), not the documented 66; as a regular built-in the failure returns
  # here instead, and the agent never runs with some other stdin.
  command exec "$@" <"$stdin_file"
  echo "runfree: session entry cannot read the prompt file: $stdin_file" >&2
  exit "$RUNFREE_SESSION_ENTRY_NO_INPUT_EXIT"
fi
exec "$@"
