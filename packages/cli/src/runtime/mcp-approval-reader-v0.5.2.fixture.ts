// Frozen copy of the Runfree v0.5.2 MCP approval record predicate, for the T7
// downgrade test (loopback HTTP MCP design, N3). Do not edit the function body.
// Source: tag v0.5.2, packages/cli/src/runtime/mcp.ts, lines 916-927, copied
// verbatim.
import { isMcpAgentId } from "../agents.ts";
import { isRecord } from "../strict-primitives.ts";
import type { McpApprovalRecord } from "./mcp.ts";

function isMcpApprovalRecord(value: unknown): value is McpApprovalRecord {
  if (!isRecord(value)) return false;
  return value.schemaVersion === 1
    && value.source === "project"
    && isMcpAgentId(typeof value.agent === "string" ? value.agent : undefined)
    && typeof value.approvedAt === "string"
    && typeof value.digest === "string"
    && typeof value.server === "string"
    && typeof value.summary === "string"
    && (value.auth === "public" || value.auth === "static" || value.auth === "oauth" || value.auth === "none")
    && (value.transport === "http" || value.transport === "stdio");
}

export { isMcpApprovalRecord as isMcpApprovalRecordV052 };
