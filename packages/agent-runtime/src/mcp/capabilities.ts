// The compiled list of portable MCP servers the agent image ships, and the
// limits every server enforces. `runfree-mcp` accepts exactly one argument and
// only a value from PORTABLE_MCP_SERVER_IDS; it never takes a path, shell text,
// package name, or extra command.
//
// The host CLI keeps its own catalog (`packages/cli/src/runtime/portable-mcp.ts`).
// `scripts/agent-mcp-bundle.test.ts` asserts that the two lists, their contract
// versions, and the committed bundle manifest agree.

export const PORTABLE_MCP_SERVER_IDS = ["node-repl"] as const;

export type PortableMcpServerId = (typeof PORTABLE_MCP_SERVER_IDS)[number];

// A contract version names the tool surface (tool names, argument schemas, and
// result semantics). A change here must change the host approval digest, so the
// CLI catalog carries the same number and binds it into project approvals.
export const PORTABLE_MCP_CONTRACT_VERSIONS: Readonly<Record<PortableMcpServerId, number>> = Object.freeze({
  "node-repl": 1,
});

// The Runfree-owned bundle version. Bump on any change to the server sources.
export const RUNFREE_MCP_BUNDLE_VERSION = "1.0.0";

export function isPortableMcpServerId(value: unknown): value is PortableMcpServerId {
  return typeof value === "string" && (PORTABLE_MCP_SERVER_IDS as readonly string[]).includes(value);
}

export const NODE_REPL_LIMITS = Object.freeze({
  // UTF-8 bytes of the `code` argument.
  maxCodeBytes: 256 * 1024,
  // Characters of the optional `title` argument.
  maxTitleChars: 256,
  defaultTimeoutMs: 30_000,
  maxTimeoutMs: 600_000,
  // UTF-8 bytes of captured output returned for one call.
  maxOutputBytes: 1024 * 1024,
});

export const NODE_REPL_MESSAGES = Object.freeze({
  // Text compatible with the Codex Desktop `node_repl` server.
  timeout: "js execution timed out; kernel reset, rerun your request",
  reset: "js kernel reset",
  truncated: "[runfree node-repl: output truncated at 1 MiB]",
});
