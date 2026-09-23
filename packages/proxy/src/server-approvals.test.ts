// Live-proxy approve-on-write tests: the real server subprocess holds
// classified writes on `ask` hosts, resolves them from decision files, and
// never touches a token or the upstream while a write is unapproved.
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
  replaceJson,
  startHttpsUpstream,
  startProxy,
  tmp,
  waitUntil,
  type RunningProxy,
} from "./server.test-harness.ts";

const OWN_UID = String(process.getuid?.() ?? 0);

type ApprovalDirs = { pendingDir: string; decisionsDir: string };

function approvalDirs(): ApprovalDirs {
  const pendingDir = fs.mkdtempSync(path.join(tmp, "approvals-pending-"));
  const decisionsDir = fs.mkdtempSync(path.join(tmp, "approvals-decisions-"));
  return { pendingDir, decisionsDir };
}

function attachWatcher(dirs: ApprovalDirs): void {
  fs.writeFileSync(path.join(dirs.decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE), fs.existsSync(path.join(dirs.pendingDir, APPROVALS_PROCESS_EPOCH_FILE)) ? fs.readFileSync(path.join(dirs.pendingDir, APPROVALS_PROCESS_EPOCH_FILE), "utf8") : "watch-requested");
}

function approvalEnv(dirs: ApprovalDirs): NodeJS.ProcessEnv {
  return {
    NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
    RUNFREE_APPROVALS_PENDING_DIR: dirs.pendingDir,
    RUNFREE_APPROVALS_DECISIONS_DIR: dirs.decisionsDir,
    RUNFREE_APPROVALS_DECISION_OWNER_UID: OWN_UID,
    RUNFREE_WRITE_APPROVAL_HOLD_SECONDS: "5",
  };
}

function askPolicy(extraRule: Record<string, unknown> = {}): unknown {
  return {
    hosts: ["127.0.0.1"],
    tokens: {
      example: {
        description: "Example token",
        credentials: [
          { host: "127.0.0.1", header: "Authorization", scheme: "bearer" },
        ],
      },
    },
    requests: {
      "127.0.0.1": { writeAction: "ask", ...extraRule },
    },
  };
}

async function waitForPendingRecord(dirs: ApprovalDirs): Promise<PendingApprovalRecord> {
  let record: PendingApprovalRecord | undefined;
  await waitUntil(() => {
    const entries = fs.readdirSync(dirs.pendingDir).filter((entry) => entry.endsWith(".json"));
    if (entries.length === 0) return false;
    record = parsePendingApprovalRecord(fs.readFileSync(path.join(dirs.pendingDir, entries[0]), "utf8"));
    return record !== undefined;
  }, "pending approval record");
  if (!record) throw new Error("pending approval record did not appear");
  return record;
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

async function startAskProxy(dirs: ApprovalDirs, policy: unknown = askPolicy()): Promise<{ proxy: RunningProxy; upstream: Awaited<ReturnType<typeof startHttpsUpstream>> }> {
  const upstream = await startHttpsUpstream();
  const proxy = await startProxy({
    extraEnv: approvalEnv(dirs),
    policy,
    secretFiles: { example: "real-proxy-token\n" },
  });
  if (fs.existsSync(path.join(dirs.decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE))) attachWatcher(dirs);
  return { proxy, upstream };
}

describe("proxy server approve-on-write", () => {
  test("a write on an ask host with no approver attached denies immediately with no upstream contact", async () => {
    const dirs = approvalDirs();
    const { proxy, upstream } = await startAskProxy(dirs);

    const startedAt = Date.now();
    const denied = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/v1/things",
      headers: { Authorization: "Bearer agent-forged" },
      body: "payload",
    });
    expect(denied.statusCode).toBe(403);
    expect(denied.raw).toContain("x-runfree-blocked: write-approval-required");
    expect(denied.body).toContain("writes need approval but no approver is attached");
    expect(Date.now() - startedAt).toBeLessThan(4_000);
    expect(upstream.requests).toHaveLength(0);
    expect(denied.raw).not.toContain("real-proxy-token");
    // Reads still flow, with the credential injected.
    const read = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/v1/things",
    });
    expect(read.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
  }, 20_000);

  test("a held write approved for this request forwards with the injected credential and stripped agent header", async () => {
    const dirs = approvalDirs();
    attachWatcher(dirs);
    const { proxy, upstream } = await startAskProxy(dirs);

    const responsePromise = httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/v1/things",
      headers: { Authorization: "Bearer agent-forged" },
      body: "payload",
    });
    const record = await waitForPendingRecord(dirs);
    expect(record).toMatchObject({
      host: "127.0.0.1",
      method: "POST",
      path: "/v1/things",
      category: "method",
      tokenNames: ["example"],
    });
    await proxy.waitForOutput(`proxy-approval-request: {"v":1`);
    // Held: no upstream contact and no response yet.
    expect(upstream.requests).toHaveLength(0);

    writeDecision(dirs, record.id, { decision: "approve", scope: "request" });
    const response = await responsePromise;
    expect(response.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].headers.authorization).toBe("Bearer real-proxy-token");
    await proxy.waitForOutput(/"outcome":"approved"/);
    expect(fs.readdirSync(dirs.pendingDir).filter((entry) => entry.endsWith(".json"))).toHaveLength(0);

    // The one-shot grant is spent: the next write prompts again (and times
    // out under a fresh hold, so just assert a new pending record appears).
    const second = httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/v1/things",
      body: "payload",
    });
    const secondRecord = await waitForPendingRecord(dirs);
    expect(secondRecord.id).not.toBe(record.id);
    writeDecision(dirs, secondRecord.id, { decision: "deny" });
    const secondResponse = await second;
    expect(secondResponse.statusCode).toBe(403);
    expect(upstream.requests).toHaveLength(1);
  }, 30_000);

  test("a session grant lets further writes to the host flow without prompting", async () => {
    const dirs = approvalDirs();
    attachWatcher(dirs);
    const { proxy, upstream } = await startAskProxy(dirs);

    const first = httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/v1/one",
      body: "one",
    });
    const record = await waitForPendingRecord(dirs);
    writeDecision(dirs, record.id, { decision: "approve", scope: "session" });
    expect((await first).statusCode).toBe(200);

    const second = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "DELETE",
      path: "/v1/two",
    });
    expect(second.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(2);
    expect(fs.readdirSync(dirs.pendingDir).filter((entry) => entry.endsWith(".json"))).toHaveLength(0);
  }, 30_000);

  test("tightening the policy while a write is held cancels the hold before any credential read (MED-4)", async () => {
    const dirs = approvalDirs();
    attachWatcher(dirs);
    const { proxy, upstream } = await startAskProxy(dirs);

    const held = httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/v1/things",
      body: "payload",
    });
    const record = await waitForPendingRecord(dirs);

    // Tighten writeAction ask -> deny; the live reload cancels the hold.
    replaceJson(proxy.policyPath, askPolicy({ writeAction: "deny" }));
    await proxy.waitForOutput(/"outcome":"cancelled"/);
    const response = await held;
    expect(response.statusCode).toBe(403);
    expect(upstream.requests).toHaveLength(0);

    // A late decision for the cancelled id never green-lights anything: the
    // next write is denied outright by the tightened rule.
    writeDecision(dirs, record.id, { decision: "approve", scope: "session" });
    const after = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/v1/things",
      body: "payload",
    });
    expect(after.statusCode).toBe(403);
    expect(after.raw).toContain("x-runfree-blocked: write-denied");
    expect(upstream.requests).toHaveLength(0);
  }, 30_000);

  test("a held write times out fail-closed with the retry remedy", async () => {
    const dirs = approvalDirs();
    attachWatcher(dirs);
    const { proxy, upstream } = await startAskProxy(dirs);

    const held = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/v1/slow",
      body: "payload",
    });
    expect(held.statusCode).toBe(403);
    expect(held.raw).toContain("x-runfree-blocked: write-approval-timeout");
    expect(held.body).toContain("runfree approvals");
    expect(upstream.requests).toHaveLength(0);
    await proxy.waitForOutput(/"outcome":"timeout"/);
    expect(fs.readdirSync(dirs.pendingDir).filter((entry) => entry.endsWith(".json"))).toHaveLength(0);
  }, 30_000);
});
