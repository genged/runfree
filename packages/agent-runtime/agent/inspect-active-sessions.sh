#!/bin/sh

for proc in /proc/[0-9]*; do
  [ -d "$proc" ] || continue

  pid=${proc#/proc/}
  fd=$(readlink "$proc/fd/0" 2>/dev/null || true)
  case "$fd" in
    /dev/pts/*|/dev/tty*) ;;
    *) continue ;;
  esac

  cmd=$(tr '\000' ' ' < "$proc/cmdline" 2>/dev/null || true)
  if [ -z "$cmd" ]; then
    cmd=$(cat "$proc/comm" 2>/dev/null || true)
  fi
  [ -n "$cmd" ] || continue

  session_id=$(tr '\000' '\n' < "$proc/environ" 2>/dev/null | sed -n 's/^RUNFREE_SESSION_ID=//p' | head -n 1)
  printf '%s\t%s\t%s\t%s\n' "$pid" "$fd" "$session_id" "$cmd"
done
