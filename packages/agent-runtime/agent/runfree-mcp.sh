#!/bin/sh
# runfree-mcp <portable-capability-id>
# The fixed launcher that Runfree's generated agent MCP config names for every
# portable MCP capability. The Node entry accepts exactly one compiled
# capability id and nothing else.
exec /usr/bin/node /usr/local/libexec/runfree/mcp/runfree-mcp.mjs "$@"
