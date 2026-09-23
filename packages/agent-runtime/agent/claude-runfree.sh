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
