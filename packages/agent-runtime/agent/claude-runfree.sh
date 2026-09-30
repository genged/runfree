#!/bin/sh

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
real_claude="$launcher_dir/claude-real"
mcp_config="${RUNFREE_CLAUDE_MCP_CONFIG:-/runfree/mcp/claude.json}"

# The session's MCP OAuth callback port. The host gives each eligible session
# its own loopback forwarder and port; the in-session bridge records that port
# here before the session starts. Claude reads MCP_OAUTH_CALLBACK_PORT only when
# the server config has no `oauth.callbackPort`, which is why Runfree's
# generated MCP config no longer carries one. A routing value, not an
# authority: a session that rewrites this file only breaks its own login.
callback_port_file="${RUNFREE_MCP_OAUTH_CALLBACK_PORT_FILE:-/tmp/runfree-mcp-oauth-callback-port}"
if [ -f "$callback_port_file" ] && [ ! -L "$callback_port_file" ]; then
  callback_port="$(head -c 16 "$callback_port_file" 2>/dev/null | tr -d '[:space:]')" || callback_port=""
  case "$callback_port" in
    ''|*[!0-9]*|0*) ;;
    *)
      if [ "$callback_port" -ge 1024 ] && [ "$callback_port" -le 65535 ]; then
        MCP_OAUTH_CALLBACK_PORT="$callback_port"
        export MCP_OAUTH_CALLBACK_PORT
      fi
      ;;
  esac
fi
has_mcp_config=0
has_strict_mcp_config=0

for arg in "$@"; do
  [ "$arg" = "--" ] && break
  case "$arg" in
    --mcp-config | --mcp-config=*) has_mcp_config=1 ;;
    --strict-mcp-config) has_strict_mcp_config=1 ;;
  esac
done

if [ "$has_mcp_config" -eq 0 ] && [ "$has_strict_mcp_config" -eq 0 ]; then
  exec "$real_claude" --mcp-config "$mcp_config" --strict-mcp-config "$@"
fi
if [ "$has_mcp_config" -eq 0 ]; then
  exec "$real_claude" --mcp-config "$mcp_config" "$@"
fi
if [ "$has_strict_mcp_config" -eq 0 ]; then
  exec "$real_claude" --strict-mcp-config "$@"
fi
exec "$real_claude" "$@"
