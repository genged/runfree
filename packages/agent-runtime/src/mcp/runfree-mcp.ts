// `runfree-mcp <portable-capability-id>`: the fixed dispatcher that Runfree's
// generated agent MCP config names for every portable capability. It accepts
// exactly one argument and only a compiled capability id.

import { isPortableMcpServerId, PORTABLE_MCP_SERVER_IDS } from "./capabilities.ts";
import { runNodeReplServer } from "./node-repl-server.ts";

export const DISPATCHER_USAGE = `usage: runfree-mcp <capability>; supported capabilities: ${PORTABLE_MCP_SERVER_IDS.join(", ")}`;

export async function main(argv: readonly string[]): Promise<number> {
  if (argv.length !== 1 || !isPortableMcpServerId(argv[0])) {
    process.stderr.write(`runfree-mcp: ${argv.length === 1 ? "unknown portable capability" : "expected exactly one argument"}\n${DISPATCHER_USAGE}\n`);
    return 64;
  }
  switch (argv[0]) {
    case "node-repl":
      await runNodeReplServer();
      return 0;
  }
}

const exitCode = await main(process.argv.slice(2));
if (exitCode !== 0) process.exit(exitCode);
