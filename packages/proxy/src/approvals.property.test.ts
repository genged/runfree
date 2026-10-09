import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { type ApprovalRequestSession } from "@runfree/runtime-contracts/session-registry";
import {
  APPROVALS_WATCHER_HEARTBEAT_FILE,
  type WriteApprovalGrantSummary,
} from "@runfree/runtime-contracts/write-approvals";
import fc from "fast-check";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { propertyParameters } from "../../../tests/support/property.ts";
import { createWriteApprovalManager, type HoldOutcome, type WriteApprovalManager } from "./approvals.ts";
import type { WriteDenialDetails } from "./policy.ts";

// Model-based test of the write-approval manager's grant state, with both
// clocks injected and the decision poller driven by fake timers. Invariants:
//
//   A grant "expires when EITHER" clock "is exhausted".
//   A deny is never lost: only the root-minted clear naming the current deny
//   nonce, or the end of the session, takes it back ("Negative authority is
//   revoked one way").
//   `revokeSession` removes every grant of that session.

const EPOCH = "a".repeat(64);
const POLL_MS = 20;
const GRANT_TTL_MAX_MS = 60_000;
const HOSTS = ["api.example.com", "uploads.example.com"] as const;
const TOOLS = ["query", "deleteFeatureFlag"] as const;
const MCP_HOST = "mcp.posthog.com";

function session(letter: string, name: string): ApprovalRequestSession {
  return {
    kind: "session",
    authenticated: true,
    sessionKey: letter.repeat(64),
    sessionId: `rf-20260805-${letter.repeat(6)}`,
    name,
    command: "codex",
    startedAt: "2026-08-05T12:00:00.000Z",
  };
}
const SESSIONS = [session("a", "payments"), session("b", "release")] as const;

function mcp(tool: string) {
  return { agent: "codex" as const, serverId: "codex:user:posthog", server: "posthog", method: "tools/call", tool };
}

type Lifetime = { bounded: false } | { bounded: true; wallStartMs: number; monoStartMs: number; durationMs: number };

type Model = {
  wallMs: number;
  monoMs: number;
  // Positive grants by `<session>|host|<host>` or `<session>|tool|<tool>`.
  grants: Map<string, Lifetime>;
  toolDenies: Set<string>;
  sessionDenies: Set<number>;
};

type Real = {
  approvals: WriteApprovalManager;
  pendingDir: string;
  decisionsDir: string;
  clocks: { wallMs: number; monoMs: number };
  // Control file names are single use: the manager remembers names it consumed.
  controlSerial: number;
};

const roots: string[] = [];
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval"] });
});
afterEach(() => {
  vi.useRealTimers();
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function setup(managers: WriteApprovalManager[]): { model: Model; real: Real } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-approvals-model-"));
  roots.push(root);
  const pendingDir = path.join(root, "pending");
  const decisionsDir = path.join(root, "decisions");
  fs.mkdirSync(pendingDir);
  fs.mkdirSync(decisionsDir);
  fs.writeFileSync(path.join(decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE), EPOCH);
  const clocks = { wallMs: 1_700_000_000_000, monoMs: 5_000 };
  const approvals = createWriteApprovalManager({
    pendingDir,
    decisionsDir,
    processEpoch: EPOCH,
    holdSeconds: 600,
    generation: () => "sha256:test-generation",
    decisionPollMs: POLL_MS,
    decisionOwnerUid: process.getuid?.() ?? 0,
    grantTtlMaxMs: GRANT_TTL_MAX_MS,
    // The heartbeat's real mtime is unrelated to the injected wall clock.
    watcherFreshMs: Number.MAX_SAFE_INTEGER,
    now: () => clocks.wallMs,
    monotonicNowMs: () => clocks.monoMs,
    log: () => {},
  });
  managers.push(approvals);
  return {
    model: { wallMs: clocks.wallMs, monoMs: clocks.monoMs, grants: new Map(), toolDenies: new Set(), sessionDenies: new Set() },
    real: { approvals, pendingDir, decisionsDir, clocks, controlSerial: 0 },
  };
}

function active(lifetime: Lifetime, model: Model): boolean {
  if (!lifetime.bounded) return true;
  return model.wallMs - lifetime.wallStartMs < lifetime.durationMs && model.monoMs - lifetime.monoStartMs < lifetime.durationMs;
}

function hostDetails(host: string): WriteDenialDetails {
  return { host, method: "POST", path: "/v1/things", writeAction: "ask", category: "method" } as WriteDenialDetails;
}

function toolDetails(tool: string): WriteDenialDetails {
  return { host: MCP_HOST, method: "POST", path: "/mcp", writeAction: "ask", category: "mcp-tool", mcp: mcp(tool) } as WriteDenialDetails;
}

// Holds one write and, unless the manager answers at once, decides it through
// the decision channel exactly as the host CLI does.
async function decide(
  real: Real,
  input: { sessionIndex: number; host: string; tool?: string },
  decision: Record<string, unknown> | undefined,
): Promise<HoldOutcome> {
  const outcome = real.approvals.hold({
    host: input.host,
    method: "POST",
    path: input.tool === undefined ? "/v1/things" : "/mcp",
    category: input.tool === undefined ? "method" : "mcp-tool",
    ...(input.tool === undefined ? {} : { mcp: mcp(input.tool) }),
    tokenNames: [],
    principal: SESSIONS[input.sessionIndex],
    revalidate: () => true,
  });
  if (decision !== undefined) {
    const ids = fs.readdirSync(real.pendingDir).filter((name) => /^[0-9a-f]{32}\.json$/u.test(name));
    expect(ids).toHaveLength(1);
    const id = ids[0].slice(0, -".json".length);
    fs.writeFileSync(path.join(real.decisionsDir, `${id}.json`), `${JSON.stringify({
      v: 1,
      processEpoch: EPOCH,
      id,
      decidedAt: new Date(real.clocks.wallMs).toISOString(),
      ...decision,
    })}\n`);
    vi.advanceTimersByTime(POLL_MS);
  }
  return await outcome;
}

function summaryKey(summary: WriteApprovalGrantSummary): string {
  const sessionIndex = SESSIONS.findIndex((candidate) => candidate.sessionId === summary.session?.sessionId);
  return `${summary.effect}|${sessionIndex}|${summary.coverage}|${summary.host ?? ""}|${summary.mcp?.tool ?? ""}`;
}

// The status snapshot lists exactly the authority the model holds.
function checkSummaries(model: Model, real: Real): void {
  const expected: string[] = [];
  for (const [key, lifetime] of model.grants) {
    if (!active(lifetime, model)) continue;
    const [sessionIndex, kind, target] = key.split("|");
    expected.push(kind === "host" ? `allow|${sessionIndex}|host|${target}|` : `allow|${sessionIndex}|mcp-tool|${MCP_HOST}|${target}`);
  }
  for (const key of model.toolDenies) {
    const [sessionIndex, tool] = key.split("|");
    expected.push(`deny|${sessionIndex}|mcp-tool|${MCP_HOST}|${tool}`);
  }
  for (const sessionIndex of model.sessionDenies) expected.push(`deny|${sessionIndex}|host|*|`);
  expect(real.approvals.grantSummaries().map(summaryKey).sort()).toEqual(expected.sort());
}

function lifetimeFor(model: Model, ttlMs: number | undefined): Lifetime {
  if (ttlMs === undefined) return { bounded: false };
  return { bounded: true, wallStartMs: model.wallMs, monoStartMs: model.monoMs, durationMs: Math.min(ttlMs, GRANT_TTL_MAX_MS) };
}

function dropPositive(model: Model, sessionIndex: number): void {
  for (const key of Array.from(model.grants.keys())) if (key.startsWith(`${sessionIndex}|`)) model.grants.delete(key);
}

abstract class ApprovalCommand implements fc.AsyncCommand<Model, Real> {
  check(_model: Readonly<Model>): boolean {
    return true;
  }
  async run(model: Model, real: Real): Promise<void> {
    await this.apply(model, real);
    checkSummaries(model, real);
  }
  abstract apply(model: Model, real: Real): Promise<void> | void;
  abstract toString(): string;
}

class ApproveHost extends ApprovalCommand {
  constructor(readonly sessionIndex: number, readonly host: string, readonly ttlMs: number | undefined) {
    super();
  }
  async apply(model: Model, real: Real): Promise<void> {
    const denied = model.sessionDenies.has(this.sessionIndex);
    const outcome = await decide(real, { sessionIndex: this.sessionIndex, host: this.host }, denied
      ? undefined
      : { decision: "approve", scope: "session", ...(this.ttlMs === undefined ? {} : { ttlMs: this.ttlMs }) });
    if (denied) {
      expect(outcome).toEqual({ kind: "session-denied" });
      return;
    }
    expect(outcome).toEqual({ kind: "approved", scope: "session" });
    model.grants.set(`${this.sessionIndex}|host|${this.host}`, lifetimeFor(model, this.ttlMs));
  }
  toString(): string {
    return `approveHost(${this.sessionIndex}, ${this.host}, ttl=${this.ttlMs})`;
  }
}

class ApproveTool extends ApprovalCommand {
  constructor(readonly sessionIndex: number, readonly tool: string, readonly ttlMs: number | undefined) {
    super();
  }
  async apply(model: Model, real: Real): Promise<void> {
    const denied = model.sessionDenies.has(this.sessionIndex) || model.toolDenies.has(`${this.sessionIndex}|${this.tool}`);
    const outcome = await decide(real, { sessionIndex: this.sessionIndex, host: MCP_HOST, tool: this.tool }, denied
      ? undefined
      : {
        decision: "approve",
        scope: "session",
        mcpScope: "tool",
        ...(this.ttlMs === undefined ? {} : { ttlMs: this.ttlMs }),
      });
    if (denied) {
      expect(outcome).toEqual({ kind: "session-denied" });
      return;
    }
    expect(outcome).toEqual({ kind: "approved", scope: "session" });
    model.grants.set(`${this.sessionIndex}|tool|${this.tool}`, lifetimeFor(model, this.ttlMs));
  }
  toString(): string {
    return `approveTool(${this.sessionIndex}, ${this.tool}, ttl=${this.ttlMs})`;
  }
}

class DenySession extends ApprovalCommand {
  constructor(readonly sessionIndex: number) {
    super();
  }
  async apply(model: Model, real: Real): Promise<void> {
    const denied = model.sessionDenies.has(this.sessionIndex);
    const outcome = await decide(real, { sessionIndex: this.sessionIndex, host: HOSTS[0] }, denied
      ? undefined
      : { decision: "deny", denySession: true });
    expect(outcome).toEqual({ kind: denied ? "session-denied" : "denied" });
    // "Stop asking" also drops the session's own positive grants.
    model.sessionDenies.add(this.sessionIndex);
    dropPositive(model, this.sessionIndex);
  }
  toString(): string {
    return `denySession(${this.sessionIndex})`;
  }
}

class DenyTool extends ApprovalCommand {
  constructor(readonly sessionIndex: number, readonly tool: string) {
    super();
  }
  async apply(model: Model, real: Real): Promise<void> {
    const denied = model.sessionDenies.has(this.sessionIndex) || model.toolDenies.has(`${this.sessionIndex}|${this.tool}`);
    const outcome = await decide(real, { sessionIndex: this.sessionIndex, host: MCP_HOST, tool: this.tool }, denied
      ? undefined
      : { decision: "deny", scope: "session", mcpScope: "tool" });
    expect(outcome).toEqual({ kind: denied ? "session-denied" : "denied" });
    if (!denied) model.toolDenies.add(`${this.sessionIndex}|${this.tool}`);
  }
  toString(): string {
    return `denyTool(${this.sessionIndex}, ${this.tool})`;
  }
}

// A probe is the request path's grant check; observing an expired grant drops it.
class ProbeHost extends ApprovalCommand {
  constructor(readonly sessionIndex: number, readonly host: string) {
    super();
  }
  apply(model: Model, real: Real): void {
    const key = `${this.sessionIndex}|host|${this.host}`;
    const lifetime = model.grants.get(key);
    const expected = !model.sessionDenies.has(this.sessionIndex) && lifetime !== undefined && active(lifetime, model);
    if (lifetime !== undefined && !active(lifetime, model) && !model.sessionDenies.has(this.sessionIndex)) {
      model.grants.delete(key);
    }
    expect(real.approvals.hasGrant(hostDetails(this.host), SESSIONS[this.sessionIndex])).toBe(expected);
  }
  toString(): string {
    return `probeHost(${this.sessionIndex}, ${this.host})`;
  }
}

class ProbeTool extends ApprovalCommand {
  constructor(readonly sessionIndex: number, readonly tool: string) {
    super();
  }
  apply(model: Model, real: Real): void {
    const key = `${this.sessionIndex}|tool|${this.tool}`;
    const lifetime = model.grants.get(key);
    const denied = model.sessionDenies.has(this.sessionIndex) || model.toolDenies.has(`${this.sessionIndex}|${this.tool}`);
    const expected = !denied && lifetime !== undefined && active(lifetime, model);
    if (lifetime !== undefined && !active(lifetime, model) && !denied) model.grants.delete(key);
    expect(real.approvals.hasGrant(toolDetails(this.tool), SESSIONS[this.sessionIndex])).toBe(expected);
  }
  toString(): string {
    return `probeTool(${this.sessionIndex}, ${this.tool})`;
  }
}

class AdvanceClocks extends ApprovalCommand {
  constructor(readonly wallDeltaMs: number, readonly monoDeltaMs: number) {
    super();
  }
  apply(model: Model, real: Real): void {
    model.wallMs += this.wallDeltaMs;
    model.monoMs += this.monoDeltaMs;
    real.clocks.wallMs = model.wallMs;
    real.clocks.monoMs = model.monoMs;
  }
  toString(): string {
    return `advance(wall ${this.wallDeltaMs}, mono +${this.monoDeltaMs})`;
  }
}

class RevokeSession extends ApprovalCommand {
  constructor(readonly sessionIndex: number) {
    super();
  }
  apply(model: Model, real: Real): void {
    real.approvals.revokeSession(SESSIONS[this.sessionIndex].sessionKey);
    dropPositive(model, this.sessionIndex);
    model.sessionDenies.delete(this.sessionIndex);
    for (const key of Array.from(model.toolDenies)) if (key.startsWith(`${this.sessionIndex}|`)) model.toolDenies.delete(key);
    expect(real.approvals.grantSummaries().filter((summary) => summary.session?.sessionId === SESSIONS[this.sessionIndex].sessionId))
      .toEqual([]);
  }
  toString(): string {
    return `revokeSession(${this.sessionIndex})`;
  }
}

// A policy reload that drops one host: grants on it go, every positive MCP
// grant goes, and no deny does.
class PolicyDropsHost extends ApprovalCommand {
  constructor(readonly host: string) {
    super();
  }
  apply(model: Model, real: Real): void {
    const all = new Set<string>([...HOSTS, MCP_HOST]);
    const next = new Set(Array.from(all).filter((host) => host !== this.host));
    real.approvals.onPolicyChanged({ allowedHostSet: all, requests: {} }, { allowedHostSet: next, requests: {} });
    for (const key of Array.from(model.grants.keys())) {
      const [, kind, target] = key.split("|");
      if (kind === "tool" || target === this.host) model.grants.delete(key);
    }
  }
  toString(): string {
    return `policyDropsHost(${this.host})`;
  }
}

// A root-owned clear-write-deny record. Only one naming the current deny nonce
// applies, and only while some deny is in force; it then drops authority of
// both signs.
class ClearWriteDeny extends ApprovalCommand {
  constructor(readonly current: boolean) {
    super();
  }
  apply(model: Model, real: Real): void {
    real.controlSerial += 1;
    const name = `control-${real.controlSerial.toString(16).padStart(32, "0")}.json`;
    const file = path.join(real.decisionsDir, name);
    fs.writeFileSync(file, `${JSON.stringify({
      v: 1,
      processEpoch: EPOCH,
      control: "clear-write-deny",
      denyId: this.current ? real.approvals.denyState().id : "f".repeat(32),
      issuedAt: new Date(real.clocks.wallMs).toISOString(),
    })}\n`);
    vi.advanceTimersByTime(POLL_MS);
    fs.rmSync(file);
    if (this.current && (model.sessionDenies.size > 0 || model.toolDenies.size > 0)) {
      model.grants.clear();
      model.toolDenies.clear();
      model.sessionDenies.clear();
    }
  }
  toString(): string {
    return `clearWriteDeny(${this.current ? "current" : "forged"})`;
  }
}

const sessionIndex = fc.integer({ min: 0, max: SESSIONS.length - 1 });
const host = fc.constantFrom(...HOSTS);
const tool = fc.constantFrom(...TOOLS);
const ttl = fc.option(fc.integer({ min: 1, max: 2 * GRANT_TTL_MAX_MS }), { nil: undefined });
const span = 2 * GRANT_TTL_MAX_MS;
const commands = fc.commands(
  [
    fc.tuple(sessionIndex, host, ttl).map(([s, h, t]) => new ApproveHost(s, h, t)),
    fc.tuple(sessionIndex, tool, ttl).map(([s, t, ms]) => new ApproveTool(s, t, ms)),
    sessionIndex.map((s) => new DenySession(s)),
    fc.tuple(sessionIndex, tool).map(([s, t]) => new DenyTool(s, t)),
    fc.tuple(sessionIndex, host).map(([s, h]) => new ProbeHost(s, h)),
    fc.tuple(sessionIndex, tool).map(([s, t]) => new ProbeTool(s, t)),
    fc.integer({ min: -span, max: span }).map((ms) => new AdvanceClocks(ms, 0)),
    fc.nat(span).map((ms) => new AdvanceClocks(0, ms)),
    fc.nat(span).map((ms) => new AdvanceClocks(ms, ms)),
    sessionIndex.map((s) => new RevokeSession(s)),
    fc.constantFrom(...HOSTS, MCP_HOST).map((h) => new PolicyDropsHost(h)),
    fc.boolean().map((current) => new ClearWriteDeny(current)),
  ],
  { maxCommands: 40, size: "+1" },
);

describe("write approval manager model", () => {
  it("P7.4: grants expire on either clock, denies are never lost, and revokeSession removes every grant", async () => {
    await fc.assert(
      fc.asyncProperty(commands, async (sequence) => {
        const managers: WriteApprovalManager[] = [];
        try {
          await fc.asyncModelRun(() => setup(managers), sequence);
        } finally {
          for (const approvals of managers) approvals.dispose();
        }
      }),
      propertyParameters(),
    );
  });
});
