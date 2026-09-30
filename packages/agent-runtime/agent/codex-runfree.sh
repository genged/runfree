#!/bin/sh
#
# Runfree Codex launch adapter, installed as /usr/local/bin/codex.
#
# Supplies the session's MCP OAuth callback port to every Codex invocation —
# the main agent and a `codex mcp login` run from a shell or by another agent.
# The host gives each eligible session its own loopback forwarder and port; the
# in-session bridge records that port in the file below before the session
# starts. `-c mcp_oauth_callback_port=<port>` is a root option and overrides the
# config file's port (verified against the pinned Codex). Runfree no longer
# generates `mcp_oauth_callback_url`: Codex would advertise that URL's port
# while listening on this one.
#
# A routing value, not an authority: a session that rewrites the file only
# breaks its own login. Without a valid file, Codex runs unchanged.

set -eu

launcher_path="$0"
while [ -L "$launcher_path" ]; do
  link_target="$(readlink "$launcher_path")"
  case "$link_target" in
    /*) launcher_path="$link_target" ;;
    *) launcher_path="$(dirname -- "$launcher_path")/$link_target" ;;
  esac
done
launcher_dir="$(CDPATH= cd -- "$(dirname -- "$launcher_path")" && pwd)"
real_codex="$launcher_dir/codex-real"

callback_port_file="${RUNFREE_MCP_OAUTH_CALLBACK_PORT_FILE:-/tmp/runfree-mcp-oauth-callback-port}"
if [ -f "$callback_port_file" ] && [ ! -L "$callback_port_file" ]; then
  callback_port="$(head -c 16 "$callback_port_file" 2>/dev/null | tr -d '[:space:]')" || callback_port=""
  case "$callback_port" in
    ''|*[!0-9]*|0*) ;;
    *)
      if [ "$callback_port" -ge 1024 ] && [ "$callback_port" -le 65535 ]; then
        exec "$real_codex" -c "mcp_oauth_callback_port=$callback_port" "$@"
      fi
      ;;
  esac
fi
exec "$real_codex" "$@"
