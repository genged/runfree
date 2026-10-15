// Live-proxy Git LFS batch classification tests (T10): proven against the
// real mockttp request-body buffering in the spawned server subprocess. On a
// host that declares git handling (a `gitPush` rule), a download batch POST
// is a read and forwards without approval with the git-http credential; an
// upload batch POST is a write that hits write approval under `ask` and is
// denied under `deny`, before any token read or upstream contact.
import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "vitest";

import {
  APPROVALS_PROCESS_EPOCH_FILE,
  APPROVALS_WATCHER_HEARTBEAT_FILE,
  parsePendingApprovalRecord,
  type PendingApprovalRecord,
} from "@runfree/runtime-contracts/write-approvals";
import { httpsViaProxy, startHttpsUpstream, startProxy, tmp, waitUntil } from "./server.test-harness.ts";

const OWN_UID = String(process.getuid?.() ?? 0);
const LFS_TYPE = "application/vnd.git-lfs+json";
const BATCH_PATH = "/owner/repo.git/info/lfs/objects/batch";
const BASIC = `Basic ${Buffer.from("x-access-token:real-proxy-token").toString("base64")}`;

const DOWNLOAD = JSON.stringify({ operation: "download", transfers: ["basic"], objects: [{ oid: "a".repeat(64), size: 1 }] });
const UPLOAD = JSON.stringify({ operation: "upload", transfers: ["basic"], objects: [{ oid: "a".repeat(64), size: 1 }] });

type ApprovalDirs = { pendingDir: string; decisionsDir: string };

function approvalDirs(): ApprovalDirs {
  return {
    pendingDir: fs.mkdtempSync(path.join(tmp, "lfs-approvals-pending-")),
    decisionsDir: fs.mkdtempSync(path.join(tmp, "lfs-approvals-decisions-")),
  };
}

function lfsPolicy(writeAction: "deny" | "ask"): unknown {
  return {
    hosts: ["127.0.0.1"],
    tokens: {
      example: {
        description: "Example git token",
        credentials: [
          { host: "127.0.0.1", header: "Authorization", scheme: "basic", username: "x-access-token", protocol: "git-http" },
        ],
      },
    },
    requests: {
      "127.0.0.1": { writeAction, gitPush: "write" },
    },
  };
}

async function startLfsProxy(writeAction: "deny" | "ask", dirs?: ApprovalDirs) {
  const upstream = await startHttpsUpstream();
  const proxy = await startProxy({
    extraEnv: {
      NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
      ...(dirs
        ? {
          RUNFREE_APPROVALS_PENDING_DIR: dirs.pendingDir,
          RUNFREE_APPROVALS_DECISIONS_DIR: dirs.decisionsDir,
          RUNFREE_APPROVALS_DECISION_OWNER_UID: OWN_UID,
          RUNFREE_WRITE_APPROVAL_HOLD_SECONDS: "10",
        }
        : {}),
    },
    policy: lfsPolicy(writeAction),
    secretFiles: { example: "real-proxy-token\n" },
  });
  return { proxy, upstream };
}

function batchPost(proxyPort: number, targetPort: number, body: string, pathName = BATCH_PATH) {
  return httpsViaProxy({
    proxyPort,
    targetPort,
    method: "POST",
    path: pathName,
    headers: { "content-type": LFS_TYPE, accept: LFS_TYPE, Authorization: "Basic YWdlbnQ6Zm9yZ2Vk" },
    body,
  });
}

describe("proxy server Git LFS batch classification", () => {
  test("under deny, a download batch forwards with the git-http credential; upload and lock POSTs are denied before upstream", async () => {
    const { proxy, upstream } = await startLfsProxy("deny");

    const download = await batchPost(proxy.port, upstream.port, DOWNLOAD);
    expect(download.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].headers.authorization).toBe(BASIC);

    for (const [label, body, pathName] of [
      ["upload", UPLOAD, BATCH_PATH],
      ["duplicate operation", '{"operation":"download","operation":"upload"}', BATCH_PATH],
      ["lock create", JSON.stringify({ path: "a.bin" }), "/owner/repo.git/info/lfs/locks"],
      ["download body on a decorated batch path", DOWNLOAD, `${BATCH_PATH};x`],
      // GitLab (Rails) merges the query over the JSON body: an upload upstream.
      ["download body with an operation query", DOWNLOAD, `${BATCH_PATH}?operation=upload`],
    ] as const) {
      const denied = await batchPost(proxy.port, upstream.port, body, pathName);
      expect(denied.statusCode, label).toBe(403);
      expect(denied.raw, label).toContain("x-runfree-blocked: write-denied");
      expect(denied.raw, label).not.toContain("real-proxy-token");
    }
    expect(upstream.requests).toHaveLength(1);
  }, 30_000);

  test("under ask with no approver, a download batch forwards and an upload batch needs approval", async () => {
    const dirs = approvalDirs();
    const { proxy, upstream } = await startLfsProxy("ask", dirs);

    const upload = await batchPost(proxy.port, upstream.port, UPLOAD);
    expect(upload.statusCode).toBe(403);
    expect(upload.raw).toContain("x-runfree-blocked: write-approval-required");
    expect(upstream.requests).toHaveLength(0);

    const download = await batchPost(proxy.port, upstream.port, DOWNLOAD);
    expect(download.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].headers.authorization).toBe(BASIC);
    expect(fs.readdirSync(dirs.pendingDir).filter((entry) => entry.endsWith(".json"))).toHaveLength(0);
  }, 30_000);

  test("under ask, a held upload batch stays a write on revalidation and forwards only once approved", async () => {
    const dirs = approvalDirs();
    fs.writeFileSync(path.join(dirs.decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE), "watch-requested");
    const { proxy, upstream } = await startLfsProxy("ask", dirs);
    // Re-attach with the running proxy's process epoch, as an approver would.
    fs.writeFileSync(
      path.join(dirs.decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE),
      fs.readFileSync(path.join(dirs.pendingDir, APPROVALS_PROCESS_EPOCH_FILE), "utf8"),
    );

    const responsePromise = batchPost(proxy.port, upstream.port, UPLOAD);
    let record: PendingApprovalRecord | undefined;
    await waitUntil(() => {
      const entries = fs.readdirSync(dirs.pendingDir).filter((entry) => entry.endsWith(".json"));
      if (entries.length === 0) return false;
      record = parsePendingApprovalRecord(fs.readFileSync(path.join(dirs.pendingDir, entries[0]), "utf8"));
      return record !== undefined;
    }, "pending approval record");
    if (!record) throw new Error("pending approval record did not appear");
    expect(record).toMatchObject({ host: "127.0.0.1", method: "POST", path: BATCH_PATH, category: "method", tokenNames: ["example"] });
    await proxy.waitForOutput(`proxy-approval-request: {"v":1`);
    expect(upstream.requests).toHaveLength(0);

    fs.writeFileSync(path.join(dirs.decisionsDir, `${record.id}.json`), `${JSON.stringify({
      v: 1,
      processEpoch: fs.readFileSync(path.join(dirs.pendingDir, APPROVALS_PROCESS_EPOCH_FILE), "utf8"),
      id: record.id,
      decidedAt: new Date().toISOString(),
      decision: "approve",
      scope: "request",
    })}\n`);
    const response = await responsePromise;
    expect(response.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].headers.authorization).toBe(BASIC);
  }, 30_000);
});
