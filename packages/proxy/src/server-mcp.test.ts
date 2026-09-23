// Live-proxy MCP operation policy tests: imported/approved HTTP MCP control
// POSTs are forwarded as reads, while write-like tools are held before
// upstream contact and before credential injection.
import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "vitest";

import {
  APPROVALS_WATCHER_HEARTBEAT_FILE,
  APPROVALS_PROCESS_EPOCH_FILE,
  parsePendingApprovalRecord,
  type PendingApprovalRecord,
} from "@runfree/runtime-contracts/write-approvals";
import {
  httpsViaProxy,
  startHttpsUpstream,
  startProxy,
  tmp,
  waitUntil,
} from "./server.test-harness.ts";

const OWN_UID = String(process.getuid?.() ?? 0);

type ApprovalDirs = { pendingDir: string; decisionsDir: string };

function approvalDirs(): ApprovalDirs {
  const pendingDir = fs.mkdtempSync(path.join(tmp, "mcp-approvals-pending-"));
  const decisionsDir = fs.mkdtempSync(path.join(tmp, "mcp-approvals-decisions-"));
  return { pendingDir, decisionsDir };
}

function attachWatcher(dirs: ApprovalDirs): void {
  fs.writeFileSync(path.join(dirs.decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE), fs.existsSync(path.join(dirs.pendingDir, APPROVALS_PROCESS_EPOCH_FILE)) ? fs.readFileSync(path.join(dirs.pendingDir, APPROVALS_PROCESS_EPOCH_FILE), "utf8") : "watch-requested");
}

function writeDecision(dirs: ApprovalDirs, id: string, fields: Record<string, unknown>): void {
  fs.writeFileSync(path.join(dirs.decisionsDir, `${id}.json`), `${JSON.stringify({
    v: 1,
    processEpoch: fs.readFileSync(path.join(dirs.pendingDir, APPROVALS_PROCESS_EPOCH_FILE), "utf8"),
    id,
    decidedAt: new Date().toISOString(),
    ...fields,
  })}\n`);
}

function mcpOperationPolicyPath(): string {
  const filePath = path.join(fs.mkdtempSync(path.join(tmp, "mcp-operation-policy-")), "mcp-operation-policy.json");
  fs.writeFileSync(filePath, `${JSON.stringify({
    schemaVersion: 1,
    servers: [
      {
        id: "codex:local",
        agent: "codex",
        name: "local",
        source: "user",
        host: "127.0.0.1",
        path: "/mcp",
        defaultToolWriteAction: "ask",
        tools: {
          query: { writeAction: "allow" },
        },
      },
    ],
  }, null, 2)}\n`);
  return filePath;
}

function mcpPolicy() {
  return {
    hosts: ["127.0.0.1"],
    tokens: {
      example: {
        description: "Example token",
        credentials: [
          { host: "127.0.0.1", header: "Authorization", scheme: "bearer", pathPrefix: "/mcp" },
        ],
      },
    },
    requests: {
      "127.0.0.1": { writeAction: "ask" },
    },
  };
}

async function startMcpProxy(dirs?: ApprovalDirs) {
  const upstream = await startHttpsUpstream();
  const proxy = await startProxy({
    extraEnv: {
      NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
      RUNFREE_MCP_OPERATION_POLICY_PATH: mcpOperationPolicyPath(),
      ...(dirs
        ? {
          RUNFREE_APPROVALS_PENDING_DIR: dirs.pendingDir,
          RUNFREE_APPROVALS_DECISIONS_DIR: dirs.decisionsDir,
          RUNFREE_APPROVALS_DECISION_OWNER_UID: OWN_UID,
          RUNFREE_WRITE_APPROVAL_HOLD_SECONDS: "5",
        }
        : {}),
    },
    policy: mcpPolicy(),
    secretFiles: { example: "real-proxy-token\n" },
  });
  if (dirs && fs.existsSync(path.join(dirs.decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE))) attachWatcher(dirs);
  return { proxy, upstream };
}

async function waitForPendingRecord(dirs: ApprovalDirs): Promise<PendingApprovalRecord> {
  let record: PendingApprovalRecord | undefined;
  await waitUntil(() => {
    const entries = fs.readdirSync(dirs.pendingDir).filter((name) => name.endsWith(".json"));
    if (entries.length === 0) return false;
    record = parsePendingApprovalRecord(fs.readFileSync(path.join(dirs.pendingDir, entries[0]), "utf8"));
    return record !== undefined;
  }, "pending MCP approval record");
  if (!record) throw new Error("pending MCP approval record did not appear");
  return record;
}

describe("proxy server MCP operation policy", () => {
  test("MCP initialize POST is forwarded as a protocol read under the default ask posture", async () => {
    const { proxy, upstream } = await startMcpProxy();
    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/mcp",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });

    expect(response.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].headers.authorization).toBe("Bearer real-proxy-token");
  }, 20_000);

  test("write-like MCP tool calls hold with MCP identity and do not reach upstream before approval", async () => {
    const dirs = approvalDirs();
    attachWatcher(dirs);
    const { upstream, proxy } = await startMcpProxy(dirs);

    const responsePromise = httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/mcp",
      headers: { "content-type": "application/json", Authorization: "Bearer agent-forged" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "deleteFeatureFlag" } }),
    });
    const record = await waitForPendingRecord(dirs);

    expect(record).toMatchObject({
      host: "127.0.0.1",
      method: "POST",
      path: "/mcp",
      category: "mcp-tool",
      mcp: {
        agent: "codex",
        server: "local",
        method: "tools/call",
        tool: "deleteFeatureFlag",
      },
    });
    expect(upstream.requests).toHaveLength(0);

    // End the hold with a deny rather than waiting out the minimum hold: the
    // claim is that nothing reaches upstream while unapproved, and a denied
    // hold must stay that way. The timeout path is proven in
    // server-approvals.test.ts.
    writeDecision(dirs, record.id, { decision: "deny" });
    const response = await responsePromise;
    expect(response.statusCode).toBe(403);
    expect(response.raw).toContain("x-runfree-blocked: write-approval-required");
    expect(upstream.requests).toHaveLength(0);
  }, 30_000);
});
