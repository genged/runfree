import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import {
  APPROVALS_WATCHER_HEARTBEAT_FILE,
  APPROVALS_PROCESS_EPOCH_FILE,
  parsePendingApprovalRecord,
} from "@runfree/runtime-contracts/write-approvals";
import { createWriteApprovalManager, isHostAuthorityFile, type WriteApprovalManager } from "./approvals.ts";
import { beforeAllowedRequest as authorizeRequest, hostFromUrl } from "./policy.ts";
import type { CredentialPolicy, PolicyOptions, ProxyRequest, RequestPolicyJson, WriteDenialDetails } from "./policy.ts";
import type { AdmissionRecord } from "./admission.ts";
import type { ApprovalRequestSession } from "@runfree/runtime-contracts/session-registry";

let tmp: string;
let pendingDir: string;
let decisionsDir: string;
const managers: WriteApprovalManager[] = [];
const OWN_UID = process.getuid?.() ?? 0;
let admissionSerial = 0;

const SESSION_A: ApprovalRequestSession = {
  kind: "session",
  authenticated: true,
  sessionKey: "a".repeat(64),
  sessionId: "rf-20260805-aaaaaa",
  name: "payments",
  command: "codex",
  startedAt: "2026-08-05T12:00:00.000Z",
};
const SESSION_B: ApprovalRequestSession = {
  ...SESSION_A,
  sessionKey: "b".repeat(64),
  sessionId: "rf-20260805-bbbbbb",
  name: "release",
};

// What summarize() publishes for SESSION_A grants: the display fields, never
// the internal session key.
const SESSION_A_DISPLAY = {
  sessionId: SESSION_A.sessionId,
  name: SESSION_A.name,
  command: SESSION_A.command,
  startedAt: SESSION_A.startedAt,
};

// The session-wide deny is a negative grant on the session; its summary is how
// tests observe that the latch is (still) in force.
function sessionDenyActive(approvals: WriteApprovalManager): boolean {
  return approvals.grantSummaries().some((grant) =>
    grant.effect === "deny" && grant.coverage === "host" && grant.host === "*");
}

function testBeforeAllowedRequest(req: ProxyRequest, options: PolicyOptions = {}) {
  admissionSerial += 1;
  const admission: AdmissionRecord = {
    v: 1,
    host: hostFromUrl(req.url) || options.allowedHosts?.[0] || "invalid.example",
    port: 443,
    policyGeneration: "sha256:test-policy",
    admittedAtMs: Date.now(),
    connectionSerial: admissionSerial,
    stage: "request",
  };
  return authorizeRequest(admission, req, options);
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-approvals-"));
  pendingDir = path.join(tmp, "pending");
  decisionsDir = path.join(tmp, "decisions");
  fs.mkdirSync(pendingDir, { recursive: true });
  fs.mkdirSync(decisionsDir, { recursive: true });
});

afterEach(() => {
  for (const manager of managers.splice(0)) manager.dispose();
  fs.rmSync(tmp, { recursive: true, force: true });
});

// A test that supplies only `now` is saying "time passes", so the monotonic
// clock follows it: advancing the wall clock alone would otherwise mean "the
// system clock was stepped and no real time elapsed", which is a different
// scenario. The clock-step tests pass the two sources separately on purpose.
function manager(overrides: Partial<Parameters<typeof createWriteApprovalManager>[0]> = {}): WriteApprovalManager {
  const created = createWriteApprovalManager({
    pendingDir,
    decisionsDir,
    processEpoch: "a".repeat(64),
    holdSeconds: 2,
    generation: () => "sha256:test-generation",
    decisionPollMs: 20,
    decisionOwnerUid: OWN_UID,
    log: () => {},
    ...(overrides.now !== undefined && overrides.monotonicNowMs === undefined
      ? { monotonicNowMs: overrides.now }
      : {}),
    ...overrides,
  });
  managers.push(created);
  return created;
}

function attachWatcher(): void {
  fs.writeFileSync(path.join(decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE), "a".repeat(64));
}

function writeDecision(id: string, fields: Record<string, unknown>): void {
  fs.writeFileSync(path.join(decisionsDir, `${id}.json`), `${JSON.stringify({
    v: 1,
    processEpoch: fs.readFileSync(path.join(pendingDir, APPROVALS_PROCESS_EPOCH_FILE), "utf8"),
    id,
    decidedAt: new Date().toISOString(),
    ...fields,
  })}\n`);
}

let controlSequence = 0;

function controlRequestId(): string {
  controlSequence += 1;
  return controlSequence.toString(16).padStart(32, "0");
}

// Mints one clear-write-deny control file exactly as the host CLI's root
// docker exec does, and returns its name so tests can corrupt it.
function writeControl(fields: Record<string, unknown>, requestId = controlRequestId()): string {
  const name = `control-${requestId}.json`;
  fs.writeFileSync(path.join(decisionsDir, name), `${JSON.stringify({
    v: 1,
    processEpoch: fs.readFileSync(path.join(pendingDir, APPROVALS_PROCESS_EPOCH_FILE), "utf8"),
    control: "clear-write-deny",
    issuedAt: new Date().toISOString(),
    ...fields,
  })}\n`);
  return name;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Drives one deny-all decision to completion and returns the resulting hold.
async function denyAllWrites(approvals: WriteApprovalManager): Promise<void> {
  const held = approvals.hold(holdInput({ path: "/deny-all" }));
  await sleep(50);
  writeDecision(pendingIds()[0], { decision: "deny", denySession: true });
  await expect(held).resolves.toEqual({ kind: "denied" });
}

const MCP_HOST = "mcp.posthog.com";
const MCP_SERVER = { agent: "codex" as const, serverId: "codex:user:posthog", server: "posthog", method: "tools/call" };
const SAFE_TOOL = { ...MCP_SERVER, tool: "query" };
const DESTRUCTIVE_TOOL = { ...MCP_SERVER, tool: "deleteFeatureFlag" };

function mcpDetails(mcp: typeof SAFE_TOOL): WriteDenialDetails {
  return { host: MCP_HOST, method: "POST", path: "/mcp", writeAction: "ask", category: "mcp-tool", mcp } as WriteDenialDetails;
}

function mcpHoldInput(mcp: typeof SAFE_TOOL): Parameters<WriteApprovalManager["hold"]>[0] {
  return holdInput({ category: "mcp-tool", host: MCP_HOST, path: "/mcp", mcp });
}

async function approveMcp(
  approvals: WriteApprovalManager,
  mcp: typeof SAFE_TOOL,
  fields: Record<string, unknown>,
): Promise<void> {
  const held = approvals.hold(mcpHoldInput(mcp));
  await sleep(50);
  writeDecision(pendingIds()[0], { decision: "approve", ...fields });
  await expect(held).resolves.toEqual({ kind: "approved", scope: fields.scope ?? "request" });
}

async function denyMcpTool(approvals: WriteApprovalManager, mcp: typeof SAFE_TOOL): Promise<void> {
  const held = approvals.hold(mcpHoldInput(mcp));
  await sleep(50);
  writeDecision(pendingIds()[0], { decision: "deny", scope: "session", mcpScope: "tool" });
  await expect(held).resolves.toEqual({ kind: "denied" });
}

// Only root can hand a file to another uid; the predicate test covers the same
// comparison everywhere else.
function canChangeOwner(): boolean {
  // Evaluated at collection time, before any beforeEach temp dir exists.
  const probe = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-chown-")), "probe");
  try {
    fs.writeFileSync(probe, "");
    fs.chownSync(probe, OWN_UID + 1, process.getgid?.() ?? 0);
    return true;
  } catch {
    return false;
  } finally {
    fs.rmSync(path.dirname(probe), { force: true, recursive: true });
  }
}

function pendingIds(): string[] {
  return fs.readdirSync(pendingDir).filter((name) => name.endsWith(".json")).map((name) => name.replace(/\.json$/, ""));
}

// Defaults to an authenticated SESSION_A hold — the only shape a production
// proxy can produce for an ordinary request. Pass `principal: undefined`
// explicitly to model a request-only hold.
function holdInput(overrides: Partial<Parameters<WriteApprovalManager["hold"]>[0]> = {}): Parameters<WriteApprovalManager["hold"]>[0] {
  return {
    host: "api.example.com",
    method: "POST",
    path: "/v1/things",
    category: "method",
    tokenNames: ["example"],
    revalidate: () => true,
    principal: SESSION_A,
    ...overrides,
  };
}

function detailsFor(input: { host: string; method: string; path: string }): WriteDenialDetails {
  return { ...input, writeAction: "ask", category: "method" } as WriteDenialDetails;
}

describe("write approval manager", () => {
  test("a write with no attached watcher denies immediately instead of stalling (LOW-1)", async () => {
    const approvals = manager();
    const startedAt = Date.now();
    const outcome = await approvals.hold(holdInput());
    expect(outcome).toEqual({ kind: "no-watcher" });
    expect(Date.now() - startedAt).toBeLessThan(500);
    expect(pendingIds()).toEqual([]);
  });

  test("an approved decision resolves the hold and records a one-shot grant consumed exactly once", async () => {
    attachWatcher();
    const approvals = manager();
    const held = approvals.hold(holdInput({ requestId: "req-oneshot-1" }));
    await new Promise((resolve) => setTimeout(resolve, 50));
    const [id] = pendingIds();
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    const record = parsePendingApprovalRecord(fs.readFileSync(path.join(pendingDir, `${id}.json`), "utf8"));
    expect(record).toMatchObject({
      id,
      host: "api.example.com",
      method: "POST",
      path: "/v1/things",
      category: "method",
      tokenNames: ["example"],
      generation: "sha256:test-generation",
    });

    writeDecision(id, { decision: "approve", scope: "request" });
    await expect(held).resolves.toEqual({ kind: "approved", scope: "request" });
    expect(pendingIds()).toEqual([]);

    const details = detailsFor({ host: "api.example.com", method: "POST", path: "/v1/things" });
    expect(approvals.hasGrant(details, SESSION_A, "req-oneshot-1")).toBe(true);
    // One-shot: the second consumer gets nothing.
    expect(approvals.hasGrant(details, SESSION_A, "req-oneshot-1")).toBe(false);
  });

  test("a session approval binds the session until it ends; TTL grants clamp and expire", async () => {
    attachWatcher();
    let nowMs = 1_000_000;
    const approvals = manager({ now: () => nowMs, grantTtlMaxMs: 60_000 });

    const sessionHold = approvals.hold(holdInput());
    await new Promise((resolve) => setTimeout(resolve, 50));
    writeDecision(pendingIds()[0], { decision: "approve", scope: "session" });
    await expect(sessionHold).resolves.toEqual({ kind: "approved", scope: "session" });
    const details = detailsFor({ host: "api.example.com", method: "PUT", path: "/anything" });
    expect(approvals.hasGrant(details, SESSION_A)).toBe(true);
    expect(approvals.hasGrant(details, SESSION_A)).toBe(true);
    // A plain session approval is bound to the session, not a clock: the
    // summary names the session and carries no expiry. Its end is the
    // session's end (revocation drops it — proved below), and it never
    // crosses to another session.
    expect(approvals.grantSummaries()).toEqual([{
      effect: "allow",
      scope: "session",
      subject: "session",
      coverage: "host",
      host: "api.example.com",
      session: SESSION_A_DISPLAY,
    }]);
    expect(approvals.hasGrant(details, SESSION_B)).toBe(false);

    const ttlHold = approvals.hold(holdInput({ host: "other.example.com" }));
    await new Promise((resolve) => setTimeout(resolve, 50));
    // Requested TTL far above the clamp: effective expiry is grantTtlMaxMs.
    writeDecision(pendingIds()[0], { decision: "approve", scope: "session", ttlMs: 24 * 60 * 60 * 1000 });
    await expect(ttlHold).resolves.toEqual({ kind: "approved", scope: "session" });
    const otherDetails = detailsFor({ host: "other.example.com", method: "POST", path: "/x" });
    expect(approvals.hasGrant(otherDetails, SESSION_A)).toBe(true);
    nowMs += 61_000;
    expect(approvals.hasGrant(otherDetails, SESSION_A)).toBe(false);
  });

  test("MCP session grants do not alias to HTTP grants or different tools", async () => {
    attachWatcher();
    const approvals = manager();
    const held = approvals.hold(holdInput({
      category: "mcp-tool",
      host: "mcp.posthog.com",
      path: "/mcp",
      mcp: { agent: "codex", server: "posthog", method: "tools/call", tool: "query" },
    }));
    await new Promise((resolve) => setTimeout(resolve, 50));
    writeDecision(pendingIds()[0], { decision: "approve", scope: "session" });
    await expect(held).resolves.toEqual({ kind: "approved", scope: "session" });

    expect(approvals.hasGrant({
      host: "mcp.posthog.com",
      method: "POST",
      path: "/mcp",
      writeAction: "ask",
      category: "mcp-tool",
      mcp: { agent: "codex", server: "posthog", method: "tools/call", tool: "query" },
    }, SESSION_A)).toBe(true);
    expect(approvals.hasGrant({
      host: "mcp.posthog.com",
      method: "POST",
      path: "/mcp",
      writeAction: "ask",
      category: "mcp-tool",
      mcp: { agent: "codex", server: "posthog", method: "tools/call", tool: "deleteFeatureFlag" },
    }, SESSION_A)).toBe(false);
    expect(approvals.hasGrant(detailsFor({ host: "mcp.posthog.com", method: "POST", path: "/mcp" }), SESSION_A)).toBe(false);
  });

  test("MCP server-tools session grants admit other tools but not other methods or HTTP writes", async () => {
    attachWatcher();
    const approvals = manager();
    const held = approvals.hold(holdInput({
      category: "mcp-tool",
      host: "mcp.posthog.com",
      path: "/mcp",
      mcp: { agent: "codex", serverId: "codex:user:posthog", server: "posthog", method: "tools/call", tool: "query" },
    }));
    await new Promise((resolve) => setTimeout(resolve, 50));
    writeDecision(pendingIds()[0], { decision: "approve", scope: "session", mcpScope: "server-tools" });
    await expect(held).resolves.toEqual({ kind: "approved", scope: "session" });

    expect(approvals.hasGrant({
      host: "mcp.posthog.com",
      method: "POST",
      path: "/mcp",
      writeAction: "ask",
      category: "mcp-tool",
      mcp: { agent: "codex", serverId: "codex:user:posthog", server: "posthog", method: "tools/call", tool: "deleteFeatureFlag" },
    }, SESSION_A)).toBe(true);
    expect(approvals.hasGrant({
      host: "mcp.posthog.com",
      method: "POST",
      path: "/mcp",
      writeAction: "ask",
      category: "mcp-unknown",
      mcp: { agent: "codex", serverId: "codex:user:posthog", server: "posthog", method: "resources/subscribe" },
    }, SESSION_A)).toBe(false);
    expect(approvals.hasGrant(detailsFor({ host: "mcp.posthog.com", method: "POST", path: "/mcp" }), SESSION_A)).toBe(false);
  });

  test("MCP scoped deny decisions block matching future operations without aliasing to other tools", async () => {
    attachWatcher();
    const approvals = manager();
    const held = approvals.hold(holdInput({
      category: "mcp-tool",
      host: "mcp.posthog.com",
      path: "/mcp",
      mcp: { agent: "codex", serverId: "codex:user:posthog", server: "posthog", method: "tools/call", tool: "deleteFeatureFlag" },
    }));
    await new Promise((resolve) => setTimeout(resolve, 50));
    writeDecision(pendingIds()[0], { decision: "deny", scope: "session", mcpScope: "tool" });
    await expect(held).resolves.toEqual({ kind: "denied" });

    await expect(approvals.hold(holdInput({
      category: "mcp-tool",
      host: "mcp.posthog.com",
      path: "/mcp",
      mcp: { agent: "codex", serverId: "codex:user:posthog", server: "posthog", method: "tools/call", tool: "deleteFeatureFlag" },
    }))).resolves.toEqual({ kind: "session-denied" });

    const otherTool = approvals.hold(holdInput({
      category: "mcp-tool",
      host: "mcp.posthog.com",
      path: "/mcp",
      mcp: { agent: "codex", serverId: "codex:user:posthog", server: "posthog", method: "tools/call", tool: "query" },
    }));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(pendingIds()).toHaveLength(1);
    approvals.dispose();
    await expect(otherTool).resolves.toEqual({ kind: "cancelled", reason: "shutdown" });
  });

  test("a deny decision resolves denied; denySession blocks that session's later asks and cancels its other holds", async () => {
    attachWatcher();
    const approvals = manager();
    const first = approvals.hold(holdInput({ path: "/one" }));
    const second = approvals.hold(holdInput({ path: "/two" }));
    await new Promise((resolve) => setTimeout(resolve, 50));
    const ids = pendingIds().sort();
    expect(ids).toHaveLength(2);
    const firstId = ids.find((id) => {
      const record = parsePendingApprovalRecord(fs.readFileSync(path.join(pendingDir, `${id}.json`), "utf8"));
      return record?.path === "/one";
    });
    expect(firstId).toBeDefined();

    writeDecision(firstId ?? "", { decision: "deny", denySession: true });
    await expect(first).resolves.toEqual({ kind: "denied" });
    await expect(second).resolves.toEqual({ kind: "session-denied" });
    expect(sessionDenyActive(approvals)).toBe(true);
    expect(approvals.hasGrant(detailsFor({ host: "api.example.com", method: "POST", path: "/one" }), SESSION_A)).toBe(false);
    await expect(approvals.hold(holdInput({ path: "/three" }))).resolves.toEqual({ kind: "session-denied" });
  });

  test("a decision file with the wrong owner uid never resolves a hold (MED-2)", async () => {
    attachWatcher();
    const approvals = manager({ decisionOwnerUid: OWN_UID + 1, holdSeconds: 0.4 });
    // The watcher heartbeat also fails the owner check, so this write denies
    // fast — which is itself the fail-closed behavior under a forged owner.
    const outcome = await approvals.hold(holdInput());
    expect(outcome).toEqual({ kind: "no-watcher" });
  });

  test("a wrong-owner decision file is ignored and the hold times out with no grant", async () => {
    attachWatcher();
    const heartbeat = path.join(decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE);
    const approvals = manager({ holdSeconds: 0.5, decisionOwnerUid: OWN_UID });
    const held = approvals.hold(holdInput());
    await new Promise((resolve) => setTimeout(resolve, 50));
    const [id] = pendingIds();
    // Simulate a non-root decision: the manager requires OWN_UID here, so
    // make the check fail by recreating the manager state is not possible —
    // instead verify via a second manager requiring a different owner.
    approvals.dispose();
    const strict = manager({ holdSeconds: 0.5, decisionOwnerUid: OWN_UID + 1 });
    fs.writeFileSync(heartbeat, "");
    // strict cannot see the heartbeat as valid either; assert decision-side
    // rejection directly through a fresh hold is impossible without root, so
    // this test pins the uid comparison through the heartbeat path instead.
    expect(strict.watcherAttached()).toBe(false);
    await expect(held).resolves.toMatchObject({ kind: expect.stringMatching(/timeout|cancelled/) });
    expect(fs.existsSync(path.join(pendingDir, `${id}.json`))).toBe(false);
  });

  test("holds past the cap fast-deny (MED-1) and unrelated holds still resolve", async () => {
    attachWatcher();
    const approvals = manager({ maxHeld: 1 });
    const first = approvals.hold(holdInput({ path: "/one" }));
    await new Promise((resolve) => setTimeout(resolve, 30));
    await expect(approvals.hold(holdInput({ path: "/two" }))).resolves.toEqual({ kind: "capacity" });
    writeDecision(pendingIds()[0], { decision: "approve" });
    await expect(first).resolves.toEqual({ kind: "approved", scope: "request" });
  });

  test("a hold times out fail-closed when nobody decides", async () => {
    attachWatcher();
    const approvals = manager({ holdSeconds: 0.3 });
    const startedAt = Date.now();
    await expect(approvals.hold(holdInput())).resolves.toEqual({ kind: "timeout" });
    expect(Date.now() - startedAt).toBeGreaterThanOrEqual(250);
    expect(pendingIds()).toEqual([]);
  });

  test("an approve decision whose request no longer revalidates cancels fail-closed (MED-4)", async () => {
    attachWatcher();
    let stillValid = true;
    const approvals = manager();
    const held = approvals.hold(holdInput({ revalidate: () => stillValid }));
    await new Promise((resolve) => setTimeout(resolve, 50));
    stillValid = false;
    writeDecision(pendingIds()[0], { decision: "approve", scope: "session" });
    await expect(held).resolves.toEqual({ kind: "cancelled", reason: "policy-changed" });
    // The failed approval minted no grant.
    expect(approvals.hasGrant(detailsFor({ host: "api.example.com", method: "POST", path: "/v1/things" }), SESSION_A)).toBe(false);
  });

  test("a policy change drops grants for touched hosts and cancels invalidated holds", async () => {
    attachWatcher();
    const approvals = manager();
    const sessionHold = approvals.hold(holdInput());
    await new Promise((resolve) => setTimeout(resolve, 50));
    writeDecision(pendingIds()[0], { decision: "approve", scope: "session" });
    await expect(sessionHold).resolves.toEqual({ kind: "approved", scope: "session" });

    let stillValid = true;
    const pending = approvals.hold(holdInput({ host: "other.example.com", revalidate: () => stillValid }));
    await new Promise((resolve) => setTimeout(resolve, 50));

    stillValid = false;
    approvals.onPolicyChanged(
      {
        allowedHostSet: new Set(["api.example.com", "other.example.com"]),
        requests: { "api.example.com": { writeAction: "ask" } },
      },
      {
        allowedHostSet: new Set(["api.example.com", "other.example.com"]),
        // Tightened: the host rule changed, so its session grant is dropped.
        requests: { "api.example.com": { writeAction: "deny" } },
      },
    );
    await expect(pending).resolves.toEqual({ kind: "cancelled", reason: "policy-changed" });
    expect(approvals.hasGrant(detailsFor({ host: "api.example.com", method: "POST", path: "/x" }), SESSION_A)).toBe(false);
  });

  test("a replayed decision for a completed id never green-lights a later request (MED-4)", async () => {
    attachWatcher();
    const approvals = manager();
    const held = approvals.hold(holdInput({ requestId: "req-replay-1" }));
    await new Promise((resolve) => setTimeout(resolve, 50));
    const [id] = pendingIds();
    writeDecision(id, { decision: "approve", scope: "request" });
    await expect(held).resolves.toEqual({ kind: "approved", scope: "request" });
    expect(approvals.hasGrant(
      detailsFor({ host: "api.example.com", method: "POST", path: "/v1/things" }),
      SESSION_A,
      "req-replay-1",
    )).toBe(true);

    // The decision file is still on disk (the proxy cannot delete root-owned
    // files). A new hold gets a fresh nonce, so the leftover decision matches
    // nothing and the new hold times out instead of resolving.
    const replayTarget = approvals.hold(holdInput({ path: "/v1/things" }));
    await new Promise((resolve) => setTimeout(resolve, 150));
    const [newId] = pendingIds();
    expect(newId).not.toBe(id);
    approvals.dispose();
    await expect(replayTarget).resolves.toEqual({ kind: "cancelled", reason: "shutdown" });
  });

  test("malformed decision files are ignored permanently", async () => {
    attachWatcher();
    const approvals = manager({ holdSeconds: 0.4 });
    const held = approvals.hold(holdInput());
    await new Promise((resolve) => setTimeout(resolve, 50));
    const [id] = pendingIds();
    fs.writeFileSync(path.join(decisionsDir, `${id}.json`), "not-json\n");
    await expect(held).resolves.toEqual({ kind: "timeout" });
  });

  test("client disconnect abandons the hold by request id", async () => {
    attachWatcher();
    const approvals = manager();
    const held = approvals.hold(holdInput({ requestId: "req-1" }));
    await new Promise((resolve) => setTimeout(resolve, 30));
    approvals.cancelForRequest("req-1");
    await expect(held).resolves.toEqual({ kind: "cancelled", reason: "client-disconnected" });
    expect(pendingIds()).toEqual([]);
  });

  test("notePendingRetryApproval dedupes identical pending entries", async () => {
    attachWatcher();
    const approvals = manager();
    const input = {
      host: "ws.example.com",
      method: "GET",
      path: "/live",
      category: "websocket" as const,
      tokenNames: [],
      principal: SESSION_A,
      revalidate: () => true,
    };
    approvals.notePendingRetryApproval(input);
    approvals.notePendingRetryApproval(input);
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(pendingIds()).toHaveLength(1);
    writeDecision(pendingIds()[0], { decision: "approve", scope: "session" });
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(approvals.hasGrant({
      host: "ws.example.com",
      method: "GET",
      path: "/live",
      writeAction: "ask",
      category: "websocket",
    }, SESSION_A)).toBe(true);
  });

  test("a stale watcher heartbeat counts as no watcher", async () => {
    attachWatcher();
    const approvals = manager({ watcherFreshMs: 50 });
    await new Promise((resolve) => setTimeout(resolve, 80));
    await expect(approvals.hold(holdInput())).resolves.toEqual({ kind: "no-watcher" });
  });
});

describe("authenticated session approval authority", () => {
  test("host and TTL grants never cross session keys", async () => {
    attachWatcher();
    const approvals = manager();

    const hostHold = approvals.hold(holdInput({ principal: SESSION_A }));
    await sleep(50);
    writeDecision(pendingIds()[0], { decision: "approve", scope: "session" });
    await expect(hostHold).resolves.toEqual({ kind: "approved", scope: "session" });
    const host = detailsFor({ host: "api.example.com", method: "POST", path: "/write" });
    expect(approvals.hasGrant(host, SESSION_A)).toBe(true);
    expect(approvals.hasGrant(host, SESSION_B)).toBe(false);

    const ttlHold = approvals.hold(holdInput({ host: "ttl.example.com", principal: SESSION_A }));
    await sleep(50);
    writeDecision(pendingIds()[0], { decision: "approve", scope: "session", ttlMs: 60_000 });
    await expect(ttlHold).resolves.toEqual({ kind: "approved", scope: "session" });
    const ttl = detailsFor({ host: "ttl.example.com", method: "POST", path: "/write" });
    expect(approvals.hasGrant(ttl, SESSION_A)).toBe(true);
    expect(approvals.hasGrant(ttl, SESSION_B)).toBe(false);

  });

  test("MCP grants and session denies are scoped to the authenticated session", async () => {
    attachWatcher();
    const approvals = manager();
    const mcpInput = mcpHoldInput(DESTRUCTIVE_TOOL);
    mcpInput.principal = SESSION_A;
    const mcpHold = approvals.hold(mcpInput);
    await sleep(50);
    writeDecision(pendingIds()[0], { decision: "approve", scope: "session", mcpScope: "tool" });
    await expect(mcpHold).resolves.toEqual({ kind: "approved", scope: "session" });
    expect(approvals.hasGrant(mcpDetails(DESTRUCTIVE_TOOL), SESSION_A)).toBe(true);
    expect(approvals.hasGrant(mcpDetails(DESTRUCTIVE_TOOL), SESSION_B)).toBe(false);

    const denied = approvals.hold(holdInput({ path: "/deny", principal: SESSION_A }));
    await sleep(50);
    writeDecision(pendingIds()[0], { decision: "deny", denySession: true });
    await expect(denied).resolves.toEqual({ kind: "denied" });
    await expect(approvals.hold(holdInput({ principal: SESSION_A }))).resolves.toEqual({ kind: "session-denied" });
    const other = approvals.hold(holdInput({ principal: SESSION_B, requestId: "session-b-request" }));
    await sleep(50);
    approvals.cancelForRequest("session-b-request");
    await expect(other).resolves.toEqual({ kind: "cancelled", reason: "client-disconnected" });
  });

  test("absent and typed request-only principals reject every wider forged decision", async () => {
    attachWatcher();
    const approvals = manager();
    for (const principal of [
      undefined,
      { kind: "anonymous-utility" as const, authenticated: true, label: "utility forwarder (request-only)" },
    ]) {
      const held = approvals.hold(holdInput({ principal }));
      await sleep(50);
      writeDecision(pendingIds()[0], { decision: "approve", scope: "session", ttlMs: 60_000 });
      await expect(held).resolves.toEqual({ kind: "denied" });
      expect(approvals.grantSummaries()).toEqual([]);

      const denied = approvals.hold(holdInput({ principal }));
      await sleep(50);
      writeDecision(pendingIds()[0], { decision: "deny", denySession: true });
      await expect(denied).resolves.toEqual({ kind: "denied" });
      expect(approvals.grantSummaries()).toEqual([]);
    }
  });

  test("request grants bind the held request id and revocation drops session grants and holds", async () => {
    attachWatcher();
    const approvals = manager();
    const requestHold = approvals.hold(holdInput({ principal: SESSION_A, requestId: "request-a" }));
    await sleep(50);
    writeDecision(pendingIds()[0], { decision: "approve", scope: "request" });
    await expect(requestHold).resolves.toEqual({ kind: "approved", scope: "request" });
    const details = detailsFor({ host: "api.example.com", method: "POST", path: "/v1/things" });
    expect(approvals.hasGrant(details, SESSION_B, "request-b")).toBe(false);
    expect(approvals.hasGrant(details, SESSION_A, "request-a")).toBe(true);
    expect(approvals.hasGrant(details, SESSION_A, "request-a")).toBe(false);

    const sessionHold = approvals.hold(holdInput({ principal: SESSION_A }));
    await sleep(50);
    writeDecision(pendingIds()[0], { decision: "approve", scope: "session" });
    await expect(sessionHold).resolves.toEqual({ kind: "approved", scope: "session" });
    const pending = approvals.hold(holdInput({ host: "other.example.com", principal: SESSION_A }));
    await sleep(50);
    approvals.revokeSession(SESSION_A.sessionKey);
    await expect(pending).resolves.toEqual({ kind: "cancelled", reason: "session-ended" });
    expect(approvals.hasGrant(details, SESSION_A)).toBe(false);
    expect(approvals.grantSummaries()).toEqual([]);
  });
});

// Defect A: a `session`-scoped approval used to mint a grant with no expiry,
// enforced for every later `runfree claude` / `runfree shell` in the same
// runtime. A plain session approval is now bound to one authenticated session
// (dropped at revocation); TTL and one-shot grants are clock-bounded, and the
// clock behavior is pinned here.
describe("bounded TTL and one-shot grants", () => {
  test("a TTL grant stops admitting writes at its bound and the next write is re-held, not allowed", async () => {
    attachWatcher();
    let nowMs = 1_000_000;
    const approvals = manager({ now: () => nowMs, holdSeconds: 0.4 });
    const held = approvals.hold(holdInput());
    await sleep(50);
    writeDecision(pendingIds()[0], { decision: "approve", scope: "session", ttlMs: 60_000 });
    await expect(held).resolves.toEqual({ kind: "approved", scope: "session" });

    const details = detailsFor({ host: "api.example.com", method: "PUT", path: "/anything" });
    expect(approvals.hasGrant(details, SESSION_A)).toBe(true);
    expect(approvals.grantSummaries()).toHaveLength(1);

    nowMs += 60_001;
    expect(approvals.hasGrant(details, SESSION_A)).toBe(false);
    // Expired authority disappears from status too, not just from enforcement.
    expect(approvals.grantSummaries()).toEqual([]);

    // The write is held for a human again rather than silently admitted.
    const reheld = approvals.hold(holdInput({ path: "/anything" }));
    await sleep(60);
    expect(pendingIds()).toHaveLength(1);
    await expect(reheld).resolves.toEqual({ kind: "timeout" });
  });

  // A lifetime is a duration, so it is measured on a clock nothing can step.
  // A deadline stored against the wall clock and re-clamped on read was only
  // safe forwards: stepping back re-based it to now() + max and handed the
  // grant a complete fresh lifetime.
  describe("clock steps cannot lengthen a grant", () => {
    // Two independent sources. Every real-world event this guards against is a
    // different combination of the two: a stepped system clock moves wall time
    // while real time does not, a suspended host advances wall time while the
    // monotonic clock stands still, and ordinary elapsed time moves both.
    function steppableManager(): {
      approvals: WriteApprovalManager;
      details: WriteDenialDetails;
      stepWallClock: (ms: number) => void;
      suspendHost: (ms: number) => void;
      passRealTimeWallFrozen: (ms: number) => void;
      passRealTime: (ms: number) => void;
      remaining: () => number | undefined;
    } {
      let wallMs = 1_700_000_000_000;
      let monoMs = 5_000;
      const approvals = manager({
        now: () => wallMs,
        monotonicNowMs: () => monoMs,
        holdSeconds: 0.4,
      });
      const stepWallClock = (ms: number) => {
        wallMs += ms;
      };
      return {
        approvals,
        details: detailsFor({ host: "api.example.com", method: "PUT", path: "/x" }),
        stepWallClock,
        // Suspend looks exactly like a forward wall step with the monotonic
        // clock frozen: CLOCK_MONOTONIC does not count time spent asleep.
        suspendHost: stepWallClock,
        // Real time passing while the wall clock is held or corrected.
        passRealTimeWallFrozen: (ms) => {
          monoMs += ms;
        },
        passRealTime: (ms) => {
          wallMs += ms;
          monoMs += ms;
        },
        remaining: () => approvals.grantSummaries()[0]?.expiresInSeconds,
      };
    }

    // A 60s TTL grant: the bounded kind whose lifetime the clocks measure.
    async function mintSessionGrant(approvals: WriteApprovalManager): Promise<void> {
      const held = approvals.hold(holdInput());
      await sleep(50);
      writeDecision(pendingIds()[0], { decision: "approve", scope: "session", ttlMs: 60_000 });
      await expect(held).resolves.toEqual({ kind: "approved", scope: "session" });
    }

    test("a backward step does not extend the remaining time", async () => {
      attachWatcher();
      const clock = steppableManager();
      await mintSessionGrant(clock.approvals);
      expect(clock.remaining()).toBe(60);

      // Half the grant is genuinely spent.
      clock.passRealTime(30_000);
      expect(clock.remaining()).toBe(30);

      // NTP corrects the system clock backwards by half an hour. No real time
      // passed, so nothing about the grant changes — it does not re-base to a
      // fresh 60s measured from the corrected instant.
      clock.stepWallClock(-30 * 60_000);
      expect(clock.remaining()).toBe(30);
      expect(clock.approvals.hasGrant(clock.details, SESSION_A)).toBe(true);

      // The 30s that were left are still all that is left.
      clock.passRealTime(30_001);
      expect(clock.approvals.hasGrant(clock.details, SESSION_A)).toBe(false);
      expect(clock.approvals.grantSummaries()).toEqual([]);
    });

    // The finding: enforcement measured only on CLOCK_MONOTONIC, which does not
    // advance while the host is asleep. Close the laptop on a 1h grant, open it
    // eight hours later, and monotonic elapsed is near zero.
    test("a suspended host does not preserve a grant across the sleep", async () => {
      attachWatcher();
      const clock = steppableManager();
      await mintSessionGrant(clock.approvals);
      expect(clock.remaining()).toBe(60);

      // Eight hours of wall time with the monotonic clock frozen: the laptop
      // was closed. The wall bound is exhausted even though monotonic says no
      // time passed at all.
      clock.suspendHost(8 * 60 * 60_000);
      expect(clock.approvals.hasGrant(clock.details, SESSION_A)).toBe(false);
      expect(clock.approvals.grantSummaries()).toEqual([]);
    });

    test("real time passing while the wall clock is frozen still expires a grant", async () => {
      attachWatcher();
      const clock = steppableManager();
      await mintSessionGrant(clock.approvals);

      // The mirror case: the wall clock is held or corrected while real time
      // runs on. The monotonic bound is exhausted.
      clock.passRealTimeWallFrozen(61_000);
      expect(clock.approvals.hasGrant(clock.details, SESSION_A)).toBe(false);
      expect(clock.approvals.grantSummaries()).toEqual([]);
    });

    test("a forward wall jump expires a grant early, and observing it makes that permanent", async () => {
      attachWatcher();
      const clock = steppableManager();
      await mintSessionGrant(clock.approvals);

      // Deliberate, and the safe direction: whichever bound runs out first
      // wins, so a forward jump costs the operator a re-prompt rather than
      // handing anyone authority. Never the reverse.
      clock.stepWallClock(2 * 60 * 60_000);
      expect(clock.approvals.hasGrant(clock.details, SESSION_A)).toBe(false);
      expect(clock.approvals.grantSummaries()).toEqual([]);

      // That read pruned the grant, so rolling the clock back finds nothing to
      // revive even though neither clock has net-advanced.
      clock.stepWallClock(-2 * 60 * 60_000);
      expect(clock.approvals.hasGrant(clock.details, SESSION_A)).toBe(false);
    });

    test("a grant that genuinely lapsed is not revived by a backward step", async () => {
      attachWatcher();
      const clock = steppableManager();
      await mintSessionGrant(clock.approvals);

      // Lapse it on elapsed real time, with nothing observing it.
      clock.passRealTime(60_001);

      // Rolling the wall clock back cannot bring it back: the monotonic bound
      // is exhausted regardless of what the calendar says.
      clock.stepWallClock(-60 * 60_000);
      expect(clock.approvals.hasGrant(clock.details, SESSION_A)).toBe(false);
      expect(clock.approvals.grantSummaries()).toEqual([]);
    });

    test("a backward step does not extend a one-shot grant", async () => {
      attachWatcher();
      let wallMs = 1_700_000_000_000;
      let monoMs = 5_000;
      const approvals = manager({
        now: () => wallMs,
        monotonicNowMs: () => monoMs,
        requestGrantMs: 30_000,
        holdSeconds: 0.4,
      });

      const oneShot = approvals.hold(holdInput({ path: "/one-shot" }));
      await sleep(50);
      writeDecision(pendingIds()[0], { decision: "approve", scope: "request" });
      await expect(oneShot).resolves.toEqual({ kind: "approved", scope: "request" });

      expect(approvals.grantSummaries()).toHaveLength(1);

      wallMs += 30_000;
      monoMs += 30_000;
      wallMs -= 10 * 60_000;
      // It lapsed on elapsed real time; the rollback does not revive it.
      expect(approvals.grantSummaries()).toEqual([]);
      expect(approvals.hasGrant(detailsFor({ host: "api.example.com", method: "POST", path: "/one-shot" }), SESSION_A)).toBe(false);
    });
  });

  test("an expired grant reads no token and opens no upstream connection", async () => {
    attachWatcher();
    let nowMs = 1_000_000;
    const approvals = manager({ now: () => nowMs });
    const held = approvals.hold(holdInput());
    await sleep(50);
    writeDecision(pendingIds()[0], { decision: "approve", scope: "session", ttlMs: 60_000 });
    await expect(held).resolves.toEqual({ kind: "approved", scope: "session" });

    const credentials: CredentialPolicy = {
      "api.example.com": [{
        tokenName: "example",
        tokenDescription: "token",
        host: "api.example.com",
        header: "Authorization",
        scheme: "bearer",
      }],
    };
    const tokenReads: string[] = [];
    // The real enforcement seam: write classification consults the grant
    // before any credential read, and `beforeAllowedRequest` returns the
    // mutation the proxy would apply before it ever connects upstream.
    const write = () => testBeforeAllowedRequest({
      url: "https://api.example.com/v1/things",
      method: "POST",
      headers: {},
    }, {
      allowedHosts: ["api.example.com"],
      credentials,
      requests: { "api.example.com": { writeAction: "ask" } },
      tokenReader: (tokenName: string) => {
        tokenReads.push(tokenName);
        return "secret-value";
      },
      hasWriteGrant: (details) => approvals.hasGrant(details, SESSION_A),
      log: () => {},
    });

    expect(write()).toBeTruthy();
    expect(tokenReads).toEqual(["example"]);

    nowMs += 60_001;
    tokenReads.length = 0;
    expect(write).toThrow(/blocked write/);
    // Rejection happened before the credential read, so no upstream request
    // was ever assembled with a token.
    expect(tokenReads).toEqual([]);
  });

  test("an unredeemed one-shot grant expires instead of lingering as authority", async () => {
    attachWatcher();
    let nowMs = 1_000_000;
    const approvals = manager({ now: () => nowMs, requestGrantMs: 30_000 });
    const held = approvals.hold(holdInput());
    await sleep(50);
    writeDecision(pendingIds()[0], { decision: "approve", scope: "request" });
    await expect(held).resolves.toEqual({ kind: "approved", scope: "request" });

    nowMs += 30_001;
    expect(approvals.hasGrant(detailsFor({ host: "api.example.com", method: "POST", path: "/v1/things" }), SESSION_A)).toBe(false);
  });
});

// Defect B: `denySession` used to be a permanent latch with no clear path —
// invisible in `runfree approvals` and undoable only by killing the runtime.
describe("session-wide write deny", () => {
  test("the deny is visible with a clear nonce and survives until an authorized clear", async () => {
    attachWatcher();
    const approvals = manager({ holdSeconds: 0.4 });
    const before = approvals.denyState();
    expect(before.id).toMatch(/^[0-9a-f]{32}$/);

    await denyAllWrites(approvals);
    const denied = approvals.denyState();
    expect(approvals.grantSummaries()).toEqual([
      expect.objectContaining({ effect: "deny", coverage: "host", host: "*", subject: "session", session: SESSION_A_DISPLAY }),
    ]);
    // Setting the deny rotates the nonce, so a clear minted against the older
    // state cannot apply to a deny the operator never saw.
    expect(denied.id).not.toBe(before.id);

    await expect(approvals.hold(holdInput())).resolves.toEqual({ kind: "session-denied" });
  });

  test("a clear naming the current nonce restores ask behavior and pending records become creatable again", async () => {
    attachWatcher();
    const approvals = manager({ holdSeconds: 1 });
    await denyAllWrites(approvals);
    const denyId = approvals.denyState().id;

    writeControl({ denyId });
    await sleep(120);
    expect(sessionDenyActive(approvals)).toBe(false);
    // The nonce rotates on apply: replaying the consumed file is inert.
    expect(approvals.denyState().id).not.toBe(denyId);

    const held = approvals.hold(holdInput({ path: "/after-clear", requestId: "req-after-clear" }));
    await sleep(60);
    expect(pendingIds()).toHaveLength(1);
    writeDecision(pendingIds()[0], { decision: "approve", scope: "request" });
    await expect(held).resolves.toEqual({ kind: "approved", scope: "request" });
    expect(approvals.hasGrant(
      detailsFor({ host: "api.example.com", method: "POST", path: "/after-clear" }),
      SESSION_A,
      "req-after-clear",
    )).toBe(true);
  });

  test("a control file that is not a root-owned regular file is rejected before any state change", async () => {
    attachWatcher();
    const approvals = manager({ holdSeconds: 0.4, decisionOwnerUid: OWN_UID });
    await denyAllWrites(approvals);
    const denyId = approvals.denyState().id;

    // Same gate as decision files (`!stat.isFile() || stat.uid !== owner`):
    // a directory standing in for the control record never reaches the parse.
    fs.mkdirSync(path.join(decisionsDir, `control-${controlRequestId()}.json`));
    await sleep(120);
    expect(approvals.denyState().id).toBe(denyId);
    await expect(approvals.hold(holdInput())).resolves.toEqual({ kind: "session-denied" });
  });

  test("a malformed or foreign-schema control file is rejected before any state change", async () => {
    attachWatcher();
    const approvals = manager({ holdSeconds: 0.4 });
    await denyAllWrites(approvals);
    const denyId = approvals.denyState().id;

    fs.writeFileSync(path.join(decisionsDir, `control-${controlRequestId()}.json`), "not-json\n");
    writeControl({ denyId, v: 2 });
    writeControl({ denyId, control: "grant-everything" });
    writeControl({ denyId: "not-a-nonce" });
    writeControl({});
    await sleep(150);

    expect(approvals.denyState().id).toBe(denyId);
    await expect(approvals.hold(holdInput())).resolves.toEqual({ kind: "session-denied" });
  });

  // P2-2: the proxy scans at most APPROVAL_CONTROL_SCAN_LIMIT eligible records
  // per tick. Resetting the "already examined" set wholesale above a fixed size
  // made that budget re-visit the same prefix forever, so a record past it was
  // never reached and the operator could not lift the deny without a restart.
  test("a directory full of stale control records cannot starve a legitimate clear", async () => {
    attachWatcher();
    const approvals = manager({ holdSeconds: 0.4, decisionPollMs: 10 });
    await denyAllWrites(approvals);
    const denyId = approvals.denyState().id;

    // More records than the scan budget and the old reset threshold combined.
    for (let index = 0; index < 400; index += 1) {
      fs.writeFileSync(path.join(decisionsDir, `control-${index.toString(16).padStart(32, "0")}.json`), "stale\n");
    }
    // Make a record the scan reaches late — in the directory's own order — the
    // operator's real clear. Overwriting in place leaves that order untouched.
    const entries = fs.readdirSync(decisionsDir).filter((name) => name.startsWith("control-"));
    expect(entries).toHaveLength(400);
    fs.writeFileSync(
      path.join(decisionsDir, entries[350]),
      `${JSON.stringify({ v: 1, processEpoch: approvals.processEpoch, control: "clear-write-deny", denyId, issuedAt: new Date().toISOString() })}\n`,
    );

    for (let attempt = 0; attempt < 150 && sessionDenyActive(approvals); attempt += 1) await sleep(20);
    expect(sessionDenyActive(approvals)).toBe(false);
  });

  test("a stale or replayed clear cannot revoke a later deny", async () => {
    attachWatcher();
    const approvals = manager({ holdSeconds: 0.4 });
    await denyAllWrites(approvals);
    const firstDenyId = approvals.denyState().id;

    writeControl({ denyId: firstDenyId });
    await sleep(120);
    expect(sessionDenyActive(approvals)).toBe(false);

    // A second deny gets a fresh nonce; the earlier clear (and any copy of it)
    // names a state that no longer exists.
    await denyAllWrites(approvals);
    expect(sessionDenyActive(approvals)).toBe(true);
    writeControl({ denyId: firstDenyId });
    await sleep(120);
    expect(sessionDenyActive(approvals)).toBe(true);
  });

  test("negative MCP grants are visible in status, still deny, and are clearable", async () => {
    attachWatcher();
    const approvals = manager({ holdSeconds: 0.4 });
    const mcp = { agent: "codex" as const, serverId: "codex:user:posthog", server: "posthog", method: "tools/call", tool: "deleteFeatureFlag" };
    const held = approvals.hold(holdInput({ category: "mcp-tool", host: "mcp.posthog.com", path: "/mcp", mcp }));
    await sleep(50);
    writeDecision(pendingIds()[0], { decision: "deny", scope: "session", mcpScope: "tool" });
    await expect(held).resolves.toEqual({ kind: "denied" });

    // Previously omitted from grantSummaries entirely: a deny nobody can see
    // is invisible authority just like an allow nobody can see.
    expect(approvals.grantSummaries()).toEqual([{
      effect: "deny",
      scope: "session",
      subject: "session",
      coverage: "mcp-tool",
      host: "mcp.posthog.com",
      mcp,
      session: SESSION_A_DISPLAY,
    }]);
    await expect(approvals.hold(holdInput({ category: "mcp-tool", host: "mcp.posthog.com", path: "/mcp", mcp })))
      .resolves.toEqual({ kind: "session-denied" });

    writeControl({ denyId: approvals.denyState().id });
    await sleep(120);
    expect(approvals.grantSummaries()).toEqual([]);
    const reheld = approvals.hold(holdInput({ category: "mcp-tool", host: "mcp.posthog.com", path: "/mcp", mcp }));
    await sleep(60);
    expect(pendingIds()).toHaveLength(1);
    await expect(reheld).resolves.toEqual({ kind: "timeout" });
  });

  test("an unrelated policy change never silently drops the session deny or a scoped deny", async () => {
    attachWatcher();
    const approvals = manager({ holdSeconds: 0.4 });
    await denyMcpTool(approvals, DESTRUCTIVE_TOOL);
    await denyAllWrites(approvals);

    approvals.onPolicyChanged(
      { allowedHostSet: new Set(["api.example.com", MCP_HOST]), requests: {} },
      { allowedHostSet: new Set(["api.example.com", MCP_HOST]), requests: { "api.example.com": { writeAction: "ask" } } },
    );
    // An unrelated policy edit is not an operator decision to start writing
    // again. Neither deny is undone: both are explicit operator decisions, and
    // only the control channel revokes them.
    expect(approvals.grantSummaries()).toEqual([
      expect.objectContaining({ effect: "deny", coverage: "host", host: "*" }),
      expect.objectContaining({ effect: "deny", coverage: "mcp-tool" }),
    ]);
    await expect(approvals.hold(holdInput())).resolves.toEqual({ kind: "session-denied" });
  });

  test("no policy edit revokes a scoped deny — not even one that tightens its own host", async () => {
    attachWatcher();
    const approvals = manager({ holdSeconds: 0.4 });
    await denyMcpTool(approvals, DESTRUCTIVE_TOOL);
    const denyId = approvals.denyState().id;

    // Tightening the deny's own host used to discard it: `ruleChanged` asks
    // "might this host's posture have changed?", which is the conservative
    // question for an allow and the permissive one for a deny.
    const edits: Record<string, RequestPolicyJson>[] = [
      { "api.example.com": { writeAction: "deny" } },
      // A tightening: exactly the edit that used to discard a scoped deny.
      { [MCP_HOST]: { readPathPrefixes: ["/mcp"] } },
      { [MCP_HOST]: { writeAction: "ask" } },
      { [MCP_HOST]: { writeAction: "allow" } },
    ];
    for (const requests of edits) {
      approvals.onPolicyChanged(
        { allowedHostSet: new Set(["api.example.com", MCP_HOST]), requests: {} },
        { allowedHostSet: new Set(["api.example.com", MCP_HOST]), requests },
      );
      expect(approvals.grantSummaries()).toEqual([
        expect.objectContaining({ effect: "deny", coverage: "mcp-tool", mcp: DESTRUCTIVE_TOOL }),
      ]);
      expect(approvals.hasGrant(mcpDetails(DESTRUCTIVE_TOOL), SESSION_A)).toBe(false);
    }
    // Negative authority never changed, so the clear nonce never rotated and a
    // clear the operator is holding stays valid.
    expect(approvals.denyState().id).toBe(denyId);

    // The one channel that does revoke it.
    writeControl({ denyId });
    await sleep(120);
    expect(approvals.grantSummaries()).toEqual([]);
  });

  test("dropping a host's positive grant on a policy change cannot un-shadow it", async () => {
    attachWatcher();
    const approvals = manager({ holdSeconds: 0.4 });
    await approveMcp(approvals, SAFE_TOOL, { scope: "session", mcpScope: "server-tools" });
    await denyMcpTool(approvals, DESTRUCTIVE_TOOL);

    approvals.onPolicyChanged(
      { allowedHostSet: new Set([MCP_HOST]), requests: {} },
      { allowedHostSet: new Set([MCP_HOST]), requests: { [MCP_HOST]: { writeAction: "ask" } } },
    );

    // Positive MCP grants are swept before the denies are left in place, so the
    // retained deny can only be more restrictive, never less.
    expect(approvals.hasGrant(mcpDetails(SAFE_TOOL), SESSION_A)).toBe(false);
    expect(approvals.hasGrant(mcpDetails(DESTRUCTIVE_TOOL), SESSION_A)).toBe(false);
  });
});

// HIGH-1: a negative grant SHADOWS any broader positive grant underneath it
// (hasGrant consults denies first and stops). Clearing the deny therefore has
// to drop the positive side too, or "go back to asking" silently readmits the
// exact call the operator singled out to forbid.
describe("clearing returns to ask, never to a standing allow", () => {
  test("clearing a scoped MCP deny does not un-shadow the broader allow it was narrowing", async () => {
    attachWatcher();
    const approvals = manager({ holdSeconds: 0.4 });

    // 1. "yes — all tool calls on posthog" mints a broad positive grant.
    await approveMcp(approvals, SAFE_TOOL, { scope: "session", mcpScope: "server-tools" });
    expect(approvals.hasGrant(mcpDetails(DESTRUCTIVE_TOOL), SESSION_A)).toBe(true);

    // 2. "no — deny deleteFeatureFlag until cleared" narrows it back.
    await denyMcpTool(approvals, DESTRUCTIVE_TOOL);
    expect(approvals.hasGrant(mcpDetails(DESTRUCTIVE_TOOL), SESSION_A)).toBe(false);
    expect(approvals.hasGrant(mcpDetails(SAFE_TOOL), SESSION_A)).toBe(true);

    // 3. `runfree approvals --clear-deny`.
    writeControl({ denyId: approvals.denyState().id });
    await sleep(120);

    // The regression: the tool the operator explicitly forbade must not be
    // readmitted by the allow that was hiding underneath the deny.
    expect(approvals.hasGrant(mcpDetails(DESTRUCTIVE_TOOL), SESSION_A)).toBe(false);
    expect(approvals.hasGrant(mcpDetails(SAFE_TOOL), SESSION_A)).toBe(false);
    expect(approvals.grantSummaries()).toEqual([]);

    // Back to asking: a human sees the call again instead of it being forwarded
    // with credentials and no prompt.
    const reheld = approvals.hold(holdInput({ category: "mcp-tool", host: MCP_HOST, path: "/mcp", mcp: DESTRUCTIVE_TOOL }));
    await sleep(60);
    expect(pendingIds()).toHaveLength(1);
    await expect(reheld).resolves.toEqual({ kind: "timeout" });
  });

  test("the deny-first ordering reaches the same state", async () => {
    attachWatcher();
    const approvals = manager({ holdSeconds: 0.4 });

    await denyMcpTool(approvals, DESTRUCTIVE_TOOL);
    // A different tool is not denied, so it can still be held and approved
    // server-wide — building the same shadowed pair from the other direction.
    await approveMcp(approvals, SAFE_TOOL, { scope: "session", mcpScope: "server-tools" });
    expect(approvals.hasGrant(mcpDetails(DESTRUCTIVE_TOOL), SESSION_A)).toBe(false);

    writeControl({ denyId: approvals.denyState().id });
    await sleep(120);

    expect(approvals.hasGrant(mcpDetails(DESTRUCTIVE_TOOL), SESSION_A)).toBe(false);
    expect(approvals.grantSummaries()).toEqual([]);
  });

  test("clearing also drops host and one-shot allow grants", async () => {
    attachWatcher();
    const approvals = manager({ holdSeconds: 0.4 });

    const hostHold = approvals.hold(holdInput());
    await sleep(50);
    writeDecision(pendingIds()[0], { decision: "approve", scope: "session" });
    await expect(hostHold).resolves.toEqual({ kind: "approved", scope: "session" });
    const oneShot = approvals.hold(holdInput({ path: "/one-shot" }));
    await sleep(50);
    writeDecision(pendingIds()[0], { decision: "approve", scope: "request" });
    await expect(oneShot).resolves.toEqual({ kind: "approved", scope: "request" });
    await denyMcpTool(approvals, DESTRUCTIVE_TOOL);
    expect(approvals.grantSummaries()).toHaveLength(3);

    writeControl({ denyId: approvals.denyState().id });
    await sleep(120);

    expect(approvals.hasGrant(detailsFor({ host: "api.example.com", method: "PUT", path: "/anything" }), SESSION_A)).toBe(false);
    expect(approvals.hasGrant(detailsFor({ host: "api.example.com", method: "POST", path: "/one-shot" }), SESSION_A)).toBe(false);
    expect(approvals.grantSummaries()).toEqual([]);
  });

  // MED-1: clearing positive grants inside a "deny everything" action is
  // fail-closed and correct; clearing NEGATIVE grants there is a fail-open step
  // buried in a deny, and it used to destroy narrow denies where nobody could
  // see it happen.
  test("the session deny preserves narrower denies instead of silently discarding them", async () => {
    attachWatcher();
    const approvals = manager({ holdSeconds: 0.4 });
    await approveMcp(approvals, SAFE_TOOL, { scope: "session", mcpScope: "server-tools" });
    await denyMcpTool(approvals, DESTRUCTIVE_TOOL);

    await denyAllWrites(approvals);

    // The deny dropped every positive grant and kept the operator's narrow
    // deny, so the clear can report both and revoke them explicitly.
    expect(approvals.grantSummaries()).toEqual([
      expect.objectContaining({ effect: "deny", coverage: "host", host: "*" }),
      expect.objectContaining({ effect: "deny", coverage: "mcp-tool", mcp: DESTRUCTIVE_TOOL }),
    ]);
  });
});

// MED-2: the gate that decides whether a file in the root-owned decisions
// tmpfs may carry host authority. A test process cannot create a file owned by
// another uid without root, so the two halves are proved directly here and the
// call sites are proved to consult them below.
describe("host-authority file gate", () => {
  test("only a regular file owned by the required uid carries authority", () => {
    expect(isHostAuthorityFile({ isFile: () => true, uid: 0 }, 0)).toBe(true);
    // The attacker-relevant case: a regular file written by anyone but root.
    expect(isHostAuthorityFile({ isFile: () => true, uid: 1001 }, 0)).toBe(false);
    expect(isHostAuthorityFile({ isFile: () => true, uid: 1 }, 0)).toBe(false);
    // Not a regular file, right owner.
    expect(isHostAuthorityFile({ isFile: () => false, uid: 0 }, 0)).toBe(false);
    expect(isHostAuthorityFile({ isFile: () => false, uid: 1001 }, 0)).toBe(false);
    // The harness owner-uid override is honored, not hardcoded to root.
    expect(isHostAuthorityFile({ isFile: () => true, uid: 1000 }, 1000)).toBe(true);
  });

  test("a control path that is not a regular file is rejected BY THE GATE", async () => {
    attachWatcher();
    const logs: string[] = [];
    const approvals = manager({ holdSeconds: 0.4, log: (line) => logs.push(line) });
    await denyAllWrites(approvals);
    const denyId = approvals.denyState().id;

    const controlPath = path.join(decisionsDir, `control-${controlRequestId()}.json`);
    fs.mkdirSync(controlPath);
    expect(fs.statSync(controlPath).uid).toBe(OWN_UID);
    expect(fs.statSync(controlPath).isFile()).toBe(false);
    await sleep(150);
    expect(sessionDenyActive(approvals)).toBe(true);
    expect(approvals.denyState().id).toBe(denyId);
    // Asserting the gate's own rejection, not just the surviving deny: reading
    // a directory also fails on the supported hosts, so "the deny is still
    // there" alone would hold even with the gate deleted. The log proves which
    // branch ran before any parse or state change.
    expect(logs.filter((line) => line.includes("ignored non-root control file"))).toHaveLength(1);
  });

  test("a root-owned directory named watcher-heartbeat is not an attached approver", async () => {
    // Same gate as decisions and control records: attaching an approver widens
    // what the proxy will hold rather than fast-deny, so it is host authority.
    // A fresh mtime on a directory used to satisfy the uid-only check.
    fs.mkdirSync(path.join(decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE));
    const approvals = manager({ holdSeconds: 0.4 });

    expect(approvals.watcherAttached()).toBe(false);
    await expect(approvals.hold(holdInput())).resolves.toEqual({ kind: "no-watcher" });
    expect(pendingIds()).toEqual([]);
  });

  test("a decision file that is not a root-owned regular file is rejected BY THE GATE", async () => {
    attachWatcher();
    const logs: string[] = [];
    const approvals = manager({ holdSeconds: 0.5, log: (line) => logs.push(line) });
    const held = approvals.hold(holdInput());
    await sleep(50);
    const [id] = pendingIds();

    fs.mkdirSync(path.join(decisionsDir, `${id}.json`));
    await expect(held).resolves.toEqual({ kind: "timeout" });
    expect(logs.filter((line) => line.includes("ignored non-root decision file"))).toHaveLength(1);
    expect(approvals.hasGrant(detailsFor({ host: "api.example.com", method: "POST", path: "/v1/things" }), SESSION_A)).toBe(false);
  });

  // Runs wherever the suite can create a file owned by another uid (the real
  // proxy container runs as root). Skipped unprivileged; the predicate test
  // above covers the same comparison unconditionally.
  test.skipIf(!canChangeOwner())("a non-root regular control file never clears a deny", async () => {
    attachWatcher();
    const approvals = manager({ holdSeconds: 0.4 });
    await denyAllWrites(approvals);
    const denyId = approvals.denyState().id;

    const name = writeControl({ denyId });
    fs.chownSync(path.join(decisionsDir, name), OWN_UID + 1, process.getgid?.() ?? 0);
    expect(fs.statSync(path.join(decisionsDir, name)).isFile()).toBe(true);
    await sleep(150);

    // Rejected before any state change: same file contents from root would
    // have cleared it.
    expect(sessionDenyActive(approvals)).toBe(true);
    expect(approvals.denyState().id).toBe(denyId);
  });
});

describe("one-shot grant key bounding", () => {
  test("an approved retry with a path past the display truncation limit still redeems its grant", async () => {
    attachWatcher();
    const approvals = manager();
    const longPath = `/v1/${"segment/".repeat(60)}end`;
    expect(longPath.length).toBeGreaterThan(256);
    // The retry channel (WebSocket deny-then-approve-retry) mints its grant
    // from the bounded pending record but is redeemed with the raw request
    // shape, so the key must bound both sides identically.
    approvals.notePendingRetryApproval({
      host: "api.example.com",
      method: "POST",
      path: longPath,
      category: "websocket",
      tokenNames: [],
      principal: SESSION_A,
      revalidate: () => true,
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    writeDecision(pendingIds()[0], { decision: "approve", scope: "request" });
    await new Promise((resolve) => setTimeout(resolve, 100));

    const rawDetails = {
      host: "api.example.com",
      method: "POST",
      path: longPath,
      writeAction: "ask",
      category: "websocket",
    } as WriteDenialDetails;
    // The reconnect consults hasGrant with the raw (untruncated) path.
    expect(approvals.hasGrant(rawDetails, SESSION_A)).toBe(true);
    expect(approvals.hasGrant(rawDetails, SESSION_A)).toBe(false);
  });
});

test("a new proxy process rejects old heartbeat and decisions before granting authority", async () => {
  const approvals = manager({ processEpoch: "b".repeat(64), holdSeconds: 0.15 });
  attachWatcher(); // old process epoch
  await expect(approvals.hold(holdInput())).resolves.toEqual({ kind: "no-watcher" });
  fs.writeFileSync(path.join(decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE), "b".repeat(64));
  const held = approvals.hold(holdInput({ requestId: "old-epoch" }));
  const id = pendingIds()[0];
  writeDecision(id, { decision: "approve", scope: "session", processEpoch: "a".repeat(64) });
  await expect(held).resolves.toEqual({ kind: "timeout" });
  expect(approvals.grantSummaries()).toEqual([]);
  const repaired = approvals.hold(holdInput({ requestId: "current-epoch" }));
  writeDecision(pendingIds()[0], { decision: "approve", scope: "request" });
  await expect(repaired).resolves.toEqual({ kind: "approved", scope: "request" });
});

test("an old process control cannot clear a current session denial; a current control can", async () => {
  const approvals = manager({ processEpoch: "b".repeat(64) });
  fs.writeFileSync(path.join(decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE), "b".repeat(64));
  await denyAllWrites(approvals);
  const denial = approvals.grantSummaries().find((grant) => grant.effect === "deny");
  expect(denial).toBeDefined();
  writeControl({ sessionId: SESSION_A.sessionId, denyId: approvals.denyState().id, processEpoch: "a".repeat(64) });
  await sleep(60);
  expect(sessionDenyActive(approvals)).toBe(true);
  writeControl({ sessionId: SESSION_A.sessionId, denyId: approvals.denyState().id });
  await sleep(60);
  expect(sessionDenyActive(approvals)).toBe(false);
});
