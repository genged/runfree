// approvals.ts — approve-on-write hold manager.
//
// When the write classifier marks a request a write on an `ask` host, the
// proxy holds the live request until a human on the trusted host side
// decides, then lets it re-run the full policy check (with a grant recorded)
// or answers a synthetic 403. Decision authority is the host, never the
// agent: pending records live in proxy-owned tmpfs, while decision files,
// control files, and the watcher heartbeat are root-owned (host-written via
// root docker exec) so neither the agent nor the UID-1001 proxy process can
// self-approve.
//
// Authority model. Every applied grant states two things explicitly:
//
//   subject — whose authority it is. Grants bind to the authenticated
//     session that requested them (keyed by that session's registry identity)
//     or, for one-shot grants, to the single request they admit. There is no
//     runtime-wide subject: a principal without session identity is
//     request-only in every mode.
//   lifetime — how long it lasts. Positive grants are bounded by
//     construction (the union below cannot express an unbounded one), because
//     authority that fails open must never outlive the operator's attention.
//     Negative grants may run until cleared: unbounded negative authority is
//     safe, provided it is visible in status and revocable through the same
//     root-minted channel that created it (see the control record).

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";

import {
  APPROVALS_PROCESS_EPOCH_FILE,
  APPROVAL_PROCESS_EPOCH_PATTERN,
  APPROVAL_CONTROL_SCAN_LIMIT,
  APPROVAL_EVENT_PREFIX,
  APPROVAL_REQUEST_EVENT_PREFIX,
  APPROVALS_WATCHER_HEARTBEAT_FILE,
  WRITE_APPROVAL_GRANT_TTL_MAX_MS,
  WRITE_APPROVAL_MAX_HELD,
  WRITE_APPROVAL_REQUEST_GRANT_MS,
  APPROVAL_WATCHER_FRESH_MS,
  isApprovalControlFileName,
  parseApprovalControlRecord,
  parseApprovalDecisionRecord,
  type ApprovalDecisionRecord,
  type ApprovalGrantSubject,
  type McpApprovalScope,
  type PendingApprovalMcp,
  type PendingApprovalRecord,
  type WriteApprovalGrantSummary,
} from "@runfree/runtime-contracts/write-approvals";
import type {
  ApprovalRequestPrincipal,
  ApprovalRequestSession,
  PendingApprovalSession,
} from "@runfree/runtime-contracts/session-registry";
import { DENIAL_PATH_LIMIT, displayHostname, displayMethod, safePathname } from "./denial.js";
import type { RequestPolicyJson, WriteCategory, WriteDenialDetails } from "./policy.js";

export type HoldOutcome =
  | { kind: "approved"; scope: "request" | "session" }
  | { kind: "denied" }
  // A standing negative grant blocked this write without asking again: a
  // session-wide "stop asking" deny, or a scoped MCP deny.
  | { kind: "session-denied" }
  | { kind: "timeout" }
  | { kind: "no-watcher" }
  | { kind: "capacity" }
  | { kind: "cancelled"; reason: "policy-changed" | "client-disconnected" | "session-ended" | "shutdown" };

export type HoldInput = {
  host: string;
  method: string;
  path: string;
  category: WriteCategory;
  mcp?: PendingApprovalMcp;
  tokenNames: string[];
  principal?: ApprovalRequestPrincipal;
  // mockttp request id, used to abandon the hold on client disconnect.
  requestId?: string;
  // Re-runs the pre-credential policy checks against the CURRENT policy.
  // Consulted when a decision arrives and on every policy generation change;
  // a hold whose request no longer qualifies is cancelled fail-closed.
  revalidate: () => boolean;
};

export type WriteApprovalManagerOptions = {
  processEpoch?: string;
  pendingDir: string;
  decisionsDir: string;
  holdSeconds: number;
  generation: () => string;
  maxHeld?: number;
  watcherFreshMs?: number;
  decisionPollMs?: number;
  grantTtlMaxMs?: number;
  // Duration of a one-shot request grant.
  requestGrantMs?: number;
  // Required owner uid for decision files, control files, and the watcher
  // heartbeat. Root (0) in real runtimes — the compose tmpfs makes anything
  // else impossible — overridable only through host-controlled options so the
  // test harness can exercise the owner check without root.
  decisionOwnerUid?: number;
  // Wall clock: timestamps shown to humans (pending records, status).
  now?: () => number;
  // Monotonic clock: every grant lifetime is measured with this and never with
  // `now`. Injectable so clock-step behavior is directly testable rather than
  // only argued — the two sources move independently in the tests exactly as a
  // stepped system clock makes them move in reality.
  monotonicNowMs?: () => number;
  log?: (line: string) => void;
  // Invoked after any state transition (hold created/resolved, grant minted
  // or dropped, runtime deny set or cleared). The server publishes a
  // level-triggered status snapshot from it; observation only, never
  // authorization state.
  onStateChanged?: () => void;
};

// Negative write-approval authority, as the host CLI needs to see it. `id` is
// the nonce a clear-write-deny control record must name; it rotates whenever
// negative authority changes, so a clear can only ever apply to the state the
// operator actually looked at.
export type WriteApprovalDenyState = {
  id: string;
};

// What a grant covers. Mirrors the coverage vocabulary of the applied-grant
// design so that spec becomes additive: adding a session subject or binding
// request coverage to an approval id is a new field here, not a new state
// machine. Every variant carries the host it was minted for, so a policy
// change can be evaluated per grant instead of per map.
type GrantCoverage =
  | { kind: "request"; host: string; method: string; path: string; category: WriteCategory }
  | { kind: "host"; host: string }
  | { kind: "mcp-tool"; host: string; identity: string; tool: string; mcp: PendingApprovalMcp }
  | { kind: "mcp-method"; host: string; identity: string; method: string; mcp: PendingApprovalMcp }
  | { kind: "mcp-server-tools"; host: string; identity: string; mcp: PendingApprovalMcp };

// A lifetime is a DURATION, and measuring one needs a clock that neither jumps
// nor freezes. No clock available here has both properties, so a lifetime
// carries TWO origins for the same duration and expires when EITHER is
// exhausted.
//
// The two clocks fail in opposite directions, and each failure extends
// authority:
//
//   Wall clock (`Date.now()`) can be stepped BACKWARD — an NTP correction after
//     sleep is the ordinary case. A deadline stored against it re-bases: step
//     back 30 minutes and a 1h grant with 30m left becomes a 1h grant again.
//   Monotonic (`performance.now()` -> libuv `CLOCK_MONOTONIC`, and
//     `mach_absolute_time` on macOS) does not advance while the host is
//     SUSPENDED. Mint a 1h grant, close the laptop, open it eight hours later,
//     and monotonic elapsed is near zero — the grant is still live. The clocks
//     that do count suspend (`CLOCK_BOOTTIME`, `mach_continuous_time`) are not
//     reachable from `performance.now()`, and this is a developer CLI on
//     laptops, where suspend/resume is the most common lifecycle event there is.
//
// Taking the tighter of the two remaining times means extending a grant would
// require corrupting both origins in the same direction simultaneously, which
// is not reachable: a backward wall step does not freeze monotonic, and a
// suspend does not move wall time backward. A forward wall jump expires a grant
// EARLY — deliberate, and the safe direction: the operator is re-prompted.
//
// The "a clock the system can rewrite cannot carry X" half of this is the same
// rule `runtime/host-identity.ts` applies to boot identity, where `kern.boottime`
// is rejected because XNU rewrites it whenever the clock is stepped. The lesson
// this type adds is that the reverse — a clock that can stall — is equally
// disqualifying for a duration.
//
// Grants live in this process's memory and never survive a restart, so a
// per-process monotonic origin is all this needs.
type BoundedLifetime = {
  kind: "bounded";
  // Two independent origins for one duration; both are enforcement inputs.
  grantedAtMs: number;
  grantedAtMonotonicMs: number;
  durationMs: number;
  maxLifetimeMs: number;
};

type GrantLifetime = BoundedLifetime | { kind: "until-cleared"; grantedAtMs: number };

// One applied grant. The union is the enforcement of "nothing that fails open
// is unbounded": a `positive` grant simply cannot be constructed with an
// unbounded lifetime. `scope` records how the operator expressed the decision
// ("until this session ends" vs an explicit TTL); it no longer decides whether
// the grant expires, because now both do.
type AppliedGrant =
  | {
    kind: "positive";
    scope: "request" | "session";
    subject: ApprovalGrantSubject;
    sessionKey?: string;
    session?: PendingApprovalSession;
    coverage: GrantCoverage;
    lifetime: GrantLifetime;
  }
  | {
    kind: "negative";
    scope: "session";
    subject: ApprovalGrantSubject;
    sessionKey?: string;
    session?: PendingApprovalSession;
    coverage: GrantCoverage;
    lifetime: GrantLifetime;
  };

type PendingHold = {
  id: string;
  requestId?: string;
  record: PendingApprovalRecord;
  principal?: ApprovalRequestPrincipal;
  retry: boolean;
  revalidate: () => boolean;
  resolve: (outcome: HoldOutcome) => void;
  timeout: NodeJS.Timeout;
};

export type WriteApprovalManager = {
  readonly processEpoch: string;
  // Grant check consulted by the policy layer for `ask` writes. One-shot
  // grants are consumed here; session/TTL grants persist until they expire or
  // a policy change touches the host.
  hasGrant: (details: WriteDenialDetails, principal?: ApprovalRequestPrincipal, requestId?: string) => boolean;
  denyState: () => WriteApprovalDenyState;
  watcherAttached: () => boolean;
  heldCount: () => number;
  grantSummaries: () => WriteApprovalGrantSummary[];
  hold: (input: HoldInput) => Promise<HoldOutcome>;
  // Deny-then-approve-retry channel for requests the proxy cannot hold in
  // place (WebSocket upgrades): the upgrade fails once, a pending approval
  // appears, and an approve records the chosen grant so the reconnect passes.
  // Deduped against identical pending entries; the outcome only feeds grant
  // state, never a held socket.
  notePendingRetryApproval: (input: Omit<HoldInput, "requestId">) => void;
  cancelForRequest: (requestId: string) => void;
  revokeSession: (sessionKey: string) => void;
  // Called after every applied policy generation change (file-watch reload or
  // restart-free convergence — the same code path in this process). Drops
  // grants for hosts whose rules changed and cancels holds that no longer
  // revalidate.
  onPolicyChanged: (previous: PolicySnapshot, next: PolicySnapshot) => void;
  dispose: () => void;
};

export type PolicySnapshot = {
  allowedHostSet: Set<string>;
  requests: Record<string, RequestPolicyJson>;
  writeApproval?: string;
};

const REQUEST_SUBJECT: ApprovalGrantSubject = "request";

function authenticatedSession(principal: ApprovalRequestPrincipal | undefined): ApprovalRequestSession | undefined {
  return principal?.kind === "session" && principal.authenticated ? principal : undefined;
}

// One-shot grants are minted from the bounded pending record but consumed
// with the live request's raw details, so the key bounds both sides the same
// way (idempotent on already-bounded record fields). Without this, an
// approved request with a path past the display truncation limit could never
// redeem its own grant.
function oneShotKey(details: { host: string; method: string; path: string; category: WriteCategory }): string {
  return [
    displayHostname(details.host),
    displayMethod(details.method),
    details.path.slice(0, DENIAL_PATH_LIMIT),
    details.category,
  ].join("\0");
}

function mintId(): string {
  return crypto.randomBytes(16).toString("hex");
}

// The single gate deciding whether a file in the root-owned decisions tmpfs may
// carry host authority: a decision file that resolves a hold, or a control
// record that revokes a deny. Both callers below delegate here, and it is
// exported so the two halves (regular file, required owner) can be proved
// directly — the container arrangement that would let a test create a file
// owned by another uid needs root, which unit tests do not have.
export function isHostAuthorityFile(stat: { isFile: () => boolean; uid: number }, ownerUid: number): boolean {
  if (!stat.isFile()) return false;
  return stat.uid === ownerUid;
}

export function createWriteApprovalManager(options: WriteApprovalManagerOptions): WriteApprovalManager {
  const processEpoch = options.processEpoch ?? crypto.randomBytes(32).toString("hex");
  if (!APPROVAL_PROCESS_EPOCH_PATTERN.test(processEpoch)) throw new Error("invalid proxy approval process epoch");
  fs.writeFileSync(path.join(options.pendingDir, APPROVALS_PROCESS_EPOCH_FILE), processEpoch, { mode: 0o600 });
  const now = options.now ?? (() => Date.now());
  // `performance.now()` rides libuv's monotonic clock: it counts forward from a
  // per-process origin and no clock adjustment can move it.
  const monotonicNowMs = options.monotonicNowMs ?? (() => performance.now());
  const log = options.log ?? console.log;
  const maxHeld = options.maxHeld ?? WRITE_APPROVAL_MAX_HELD;
  const watcherFreshMs = options.watcherFreshMs ?? APPROVAL_WATCHER_FRESH_MS;
  const decisionPollMs = options.decisionPollMs ?? 250;
  const grantTtlMaxMs = options.grantTtlMaxMs ?? WRITE_APPROVAL_GRANT_TTL_MAX_MS;
  const requestGrantMs = options.requestGrantMs ?? WRITE_APPROVAL_REQUEST_GRANT_MS;
  const decisionOwnerUid = options.decisionOwnerUid ?? 0;
  const notifyStateChanged = () => options.onStateChanged?.();

  const holds = new Map<string, PendingHold>();
  const hostGrants = new Map<string, AppliedGrant>();
  const mcpGrants = new Map<string, AppliedGrant>();
  const mcpDenyGrants = new Map<string, AppliedGrant>();
  const sessionDenyGrants = new Map<string, AppliedGrant>();
  // One-shot ("this request only") grants, keyed by the bounded request shape.
  // Same record type as every other grant so they are bounded, reportable, and
  // cleared by the same transitions: an approval nobody redeemed must not sit
  // in the process as invisible live authority.
  const oneShotGrants = new Map<string, AppliedGrant>();
  // Decision files the proxy has consumed or rejected. The proxy cannot
  // delete root-owned decision files, so single use is enforced here: ids are
  // nonces bound to one hold, and a consumed or rejected id never resolves
  // anything again.
  const deadDecisionIds = new Set<string>();
  // Same idea for control files, keyed by file name.
  const deadControlFiles = new Set<string>();
  // Nonce a clear must name; rotated on every negative-authority change.
  let denyId = mintId();
  let pollTimer: ReturnType<typeof setInterval> | undefined;
  let disposed = false;

  function emitEvent(prefix: string, fields: Record<string, unknown>): void {
    log(`${prefix}${JSON.stringify({ v: 1, ts: new Date(now()).toISOString(), ...fields })}`);
  }

  function boundedRecordFields(input: HoldInput): Pick<PendingApprovalRecord, "host" | "method" | "path"> {
    return {
      host: displayHostname(input.host),
      method: displayMethod(input.method),
      path: safePathname(`https://placeholder.invalid${input.path.startsWith("/") ? input.path : `/${input.path}`}`) ?? "/",
    };
  }

  function boundedMcp(input: PendingApprovalMcp | undefined): PendingApprovalMcp | undefined {
    if (!input) return undefined;
    return {
      agent: input.agent,
      ...(input.serverId !== undefined ? { serverId: input.serverId.slice(0, 128) } : {}),
      server: input.server.slice(0, DENIAL_PATH_LIMIT),
      method: input.method.slice(0, 128),
      ...(input.tool !== undefined ? { tool: input.tool.slice(0, 128) } : {}),
    };
  }

  function sessionDisplay(session: ApprovalRequestSession): PendingApprovalSession {
    return {
      sessionId: session.sessionId,
      name: session.name,
      command: session.command,
      ...(session.agentCommand !== undefined ? { agentCommand: session.agentCommand } : {}),
      ...(session.hostTty !== undefined ? { hostTty: session.hostTty } : {}),
      ...(session.hostTermProgram !== undefined ? { hostTermProgram: session.hostTermProgram } : {}),
      startedAt: session.startedAt,
    };
  }

  function grantSubject(principal: ApprovalRequestPrincipal | undefined): {
    key: string;
    subject: ApprovalGrantSubject;
    sessionKey?: string;
    session?: PendingApprovalSession;
  } | undefined {
    const session = authenticatedSession(principal);
    if (session) {
      return {
        key: session.sessionKey,
        subject: "session",
        sessionKey: session.sessionKey,
        session: sessionDisplay(session),
      };
    }
    return undefined;
  }

  function pendingPath(id: string): string {
    return path.join(options.pendingDir, `${id}.json`);
  }

  function decisionPath(id: string): string {
    return path.join(options.decisionsDir, `${id}.json`);
  }

  function removePendingFile(id: string): void {
    try {
      fs.unlinkSync(pendingPath(id));
    } catch {
      // Best-effort: the pending record is a view for the host CLI, never the
      // authorization state itself.
    }
  }

  // --- Grant lifetimes ------------------------------------------------------

  // Time left on a grant: the tighter of the two bounds, because each clock has
  // a failure mode that extends authority and the other one covers it (see
  // BoundedLifetime). Monotonic alone survives a stepped clock but not a
  // suspended host; wall alone survives a suspend but not a backward step.
  // Whichever ran out first wins.
  //
  // The read-time clamp against `maxLifetimeMs` stays as a second line: a
  // duration is fixed at mint, and this refuses to honor one that somehow
  // exceeds its maximum anyway.
  function remainingLifetimeMs(lifetime: BoundedLifetime): number {
    const effectiveDurationMs = Math.min(lifetime.durationMs, lifetime.maxLifetimeMs);
    const monotonicRemainingMs = effectiveDurationMs - (monotonicNowMs() - lifetime.grantedAtMonotonicMs);
    const wallRemainingMs = effectiveDurationMs - (now() - lifetime.grantedAtMs);
    return Math.min(monotonicRemainingMs, wallRemainingMs);
  }

  function grantActive(grant: AppliedGrant): boolean {
    if (grant.lifetime.kind === "until-cleared") return true;
    return remainingLifetimeMs(grant.lifetime) > 0;
  }

  function remainingSeconds(grant: AppliedGrant): number | undefined {
    if (grant.lifetime.kind === "until-cleared") return undefined;
    return Math.max(1, Math.round(remainingLifetimeMs(grant.lifetime) / 1000));
  }

  // Both origins are stamped at the mint, from the same instant.
  function boundedLifetime(durationMs: number, maxLifetimeMs: number): BoundedLifetime {
    return {
      kind: "bounded",
      grantedAtMs: now(),
      grantedAtMonotonicMs: monotonicNowMs(),
      durationMs,
      maxLifetimeMs,
    };
  }

  // A session-scoped grant without an explicit TTL is bound to the session
  // itself: it is dropped when that session's authority is revoked or the
  // session ends (`revokeSession`), so no separate wall bound applies.
  function positiveLifetime(
    scope: "request" | "session",
    decision?: ApprovalDecisionRecord,
  ): GrantLifetime {
    if (scope === "request") {
      const boundMs = Math.min(requestGrantMs, grantTtlMaxMs);
      return boundedLifetime(boundMs, boundMs);
    }
    if (decision?.ttlMs !== undefined) {
      return boundedLifetime(Math.min(decision.ttlMs, grantTtlMaxMs), grantTtlMaxMs);
    }
    return { kind: "until-cleared", grantedAtMs: now() };
  }

  function negativeLifetime(): GrantLifetime {
    return { kind: "until-cleared", grantedAtMs: now() };
  }

  // --- MCP coverage ---------------------------------------------------------

  // Lookup keys never include the host: an MCP grant is keyed by the server
  // identity the operator saw, so one key function serves both minting and
  // matching and the two cannot drift apart.
  function mcpKey(kind: "mcp-tool" | "mcp-method" | "mcp-server-tools", identity: string, detail = ""): string {
    return [kind, identity, detail].join("\0");
  }

  function coverageKey(coverage: GrantCoverage): string {
    if (coverage.kind === "request") return oneShotKey(coverage);
    if (coverage.kind === "host") return ["host", coverage.host].join("\0");
    if (coverage.kind === "mcp-tool") return mcpKey("mcp-tool", coverage.identity, coverage.tool);
    if (coverage.kind === "mcp-method") return mcpKey("mcp-method", coverage.identity, coverage.method);
    return mcpKey("mcp-server-tools", coverage.identity);
  }

  function mcpIdentity(mcp: PendingApprovalMcp): string {
    return mcp.serverId ?? `${mcp.agent}:${mcp.server}`;
  }

  function mcpCoverageKeysFor(mcp: PendingApprovalMcp): string[] {
    const identity = mcpIdentity(mcp);
    if (mcp.method === "tools/call" && mcp.tool !== undefined) {
      return [mcpKey("mcp-tool", identity, mcp.tool), mcpKey("mcp-server-tools", identity)];
    }
    return [mcpKey("mcp-method", identity, mcp.method)];
  }

  function mcpCoverageFromDecision(
    mcp: PendingApprovalMcp,
    decisionScope: McpApprovalScope | undefined,
    host: string,
  ): GrantCoverage {
    const identity = mcpIdentity(mcp);
    if (decisionScope === "server-tools" && mcp.method === "tools/call") {
      return { kind: "mcp-server-tools", host, identity, mcp };
    }
    if (decisionScope === "method" || mcp.method !== "tools/call" || mcp.tool === undefined) {
      return { kind: "mcp-method", host, identity, method: mcp.method, mcp };
    }
    return { kind: "mcp-tool", host, identity, tool: mcp.tool, mcp };
  }

  function matchingMcpGrant(
    map: Map<string, AppliedGrant>,
    mcp: PendingApprovalMcp,
    subjectKey: string,
  ): AppliedGrant | undefined {
    for (const key of mcpCoverageKeysFor(mcp)) {
      const mapKey = `${subjectKey}\0${key}`;
      const grant = map.get(mapKey);
      if (!grant) continue;
      if (grantActive(grant)) return grant;
      map.delete(mapKey);
    }
    return undefined;
  }

  function mcpCoverageMatches(coverage: GrantCoverage, mcp: PendingApprovalMcp): boolean {
    if (coverage.kind === "host" || coverage.kind === "request") return false;
    if (coverage.identity !== mcpIdentity(mcp)) return false;
    if (coverage.kind === "mcp-server-tools") return mcp.method === "tools/call";
    if (coverage.kind === "mcp-tool") return mcp.method === "tools/call" && mcp.tool === coverage.tool;
    return mcp.method === coverage.method;
  }

  // --- Grant checks ---------------------------------------------------------

  function hasGrant(
    details: WriteDenialDetails,
    principal?: ApprovalRequestPrincipal,
    requestId?: string,
  ): boolean {
    const subject = grantSubject(principal);
    if (!subject) return false;
    const sessionDeny = sessionDenyGrants.get(subject.key);
    if (sessionDeny && grantActive(sessionDeny)) return false;
    if (details.mcp) {
      if (matchingMcpGrant(mcpDenyGrants, details.mcp, subject.key)) return false;
      return matchingMcpGrant(mcpGrants, details.mcp, subject.key) !== undefined;
    }
    const hostKey = `${subject.key}\0host\0${details.host}`;
    const grant = hostGrants.get(hostKey);
    if (grant) {
      if (grantActive(grant)) return true;
      // Expired: the write is re-held rather than silently admitted.
      hostGrants.delete(hostKey);
      log(`proxy-approval: write grant for ${details.host} expired`);
    }
    const key = requestId !== undefined
      ? `request\0${requestId}`
      : `retry\0${subject.key}\0${oneShotKey(details)}`;
    const oneShot = oneShotGrants.get(key);
    if (oneShot !== undefined) {
      oneShotGrants.delete(key);
      if (grantActive(oneShot)) return true;
    }
    return false;
  }

  function watcherAttached(): boolean {
    try {
      const stat = fs.statSync(path.join(options.decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE));
      // Attaching an approver widens what the proxy will hold instead of
      // fast-denying, so the heartbeat is host authority like a decision or a
      // control record and goes through the same gate: the UID-1001 proxy
      // cannot keep itself "attached", and a root-owned *directory* with a
      // fresh mtime is not an approver either.
      if (!isHostAuthorityFile(stat, decisionOwnerUid)) return false;
      return fs.readFileSync(path.join(options.decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE), "utf8").trim() === processEpoch
        && now() - stat.mtimeMs <= watcherFreshMs;
    } catch {
      return false;
    }
  }

  function resolveHold(hold: PendingHold, outcome: HoldOutcome): void {
    if (!holds.has(hold.id)) return;
    holds.delete(hold.id);
    clearTimeout(hold.timeout);
    removePendingFile(hold.id);
    deadDecisionIds.add(hold.id);
    syncPolling();
    emitEvent(APPROVAL_EVENT_PREFIX, {
      id: hold.id,
      host: hold.record.host,
      outcome: outcome.kind,
      ...(outcome.kind === "approved"
        ? { scope: outcome.scope, subject: grantSubject(hold.principal)?.subject ?? REQUEST_SUBJECT }
        : {}),
      ...(outcome.kind === "cancelled" ? { reason: outcome.reason } : {}),
      ...(hold.record.mcp ? { mcp: hold.record.mcp } : {}),
      ...(hold.record.session ? { session: hold.record.session } : {}),
      ...(hold.record.requestOnlyPrincipal ? { requestOnlyPrincipal: hold.record.requestOnlyPrincipal } : {}),
      generation: options.generation(),
    });
    hold.resolve(outcome);
    notifyStateChanged();
  }

  function readDecision(id: string): ApprovalDecisionRecord | undefined {
    const filePath = decisionPath(id);
    let stat: fs.Stats;
    try {
      stat = fs.statSync(filePath);
    } catch {
      return undefined;
    }
    // MED-2: only root-owned regular files mint decisions. Anything else is
    // rejected permanently for this id (the file cannot be trusted later).
    if (!isHostAuthorityFile(stat, decisionOwnerUid)) {
      deadDecisionIds.add(id);
      log(`proxy-approval: ignored non-root decision file for ${id} (uid=${stat.uid})`);
      return undefined;
    }
    let raw: string;
    try {
      raw = fs.readFileSync(filePath, "utf8");
    } catch {
      return undefined;
    }
    const record = parseApprovalDecisionRecord(raw);
    if (!record || record.id !== id || record.processEpoch !== processEpoch || !holds.has(id)) {
      deadDecisionIds.add(id);
      log(`proxy-approval: ignored malformed decision file for ${id}`);
      return undefined;
    }
    return record;
  }

  // --- Negative authority ---------------------------------------------------

  function rotateDenyId(): void {
    denyId = mintId();
  }

  // Whether any LIVE negative authority remains, pruning lapsed grants as it
  // goes. The pruning is the point, not a side effect: a TTL-scoped deny that
  // has expired is not authority, and counting it as such kept the control
  // channel poller — a synchronous readdirSync every `decisionPollMs` — running
  // for the remaining life of the proxy, since nothing else re-synchronized the
  // poller once a request happened to drop the grant on read. `pollChannel`
  // calls this every tick, so an expiry now stops the timer on the next one.
  //
  // Expiry deliberately does NOT rotate the clear nonce: rotation exists so a
  // clear cannot apply to negative state the operator never saw, and a lapse
  // only ever shrinks that state. Invalidating an operator's in-flight clear
  // because an unrelated deny timed out would be pure obstruction.
  function negativeAuthorityPresent(): boolean {
    let expired = 0;
    for (const [key, grant] of Array.from(mcpDenyGrants.entries())) {
      if (grantActive(grant)) continue;
      mcpDenyGrants.delete(key);
      expired += 1;
      log(`proxy-approval: MCP deny grant for ${grant.coverage.host} expired`);
    }
    // Publish the drop rather than leaving status advertising a grant that no
    // longer denies anything: expiry should be observable, not discovered.
    if (expired > 0) notifyStateChanged();
    return sessionDenyGrants.size > 0 || mcpDenyGrants.size > 0;
  }

  function setSessionDeny(subject: NonNullable<ReturnType<typeof grantSubject>>): void {
    const grant: AppliedGrant = {
      kind: "negative",
      scope: "session",
      subject: subject.subject,
      ...(subject.sessionKey !== undefined ? { sessionKey: subject.sessionKey } : {}),
      ...(subject.session !== undefined ? { session: subject.session } : {}),
      coverage: { kind: "host", host: "*" },
      lifetime: negativeLifetime(),
    };
    sessionDenyGrants.set(subject.key, grant);
    for (const map of [hostGrants, mcpGrants, oneShotGrants]) {
      for (const [key, candidate] of map) {
        if (candidate.subject === subject.subject && candidate.sessionKey === subject.sessionKey) map.delete(key);
      }
    }
    rotateDenyId();
  }

  // Applied only for a root-owned, schema-valid control record naming the
  // current nonce; every rejection above returns before reaching this.
  //
  // Clearing a deny returns to ASK, never to a standing allow. A negative grant
  // *shadows* any broader positive grant underneath it (hasGrant consults denies
  // first and stops), so dropping only the negative side would silently
  // un-shadow the very authority the operator narrowed: clearing a "deny this
  // one tool" would readmit it under an older "allow all tools on this server"
  // with no hold and no prompt. Positive grants are cheap — the next write asks
  // again — so the clear drops authority of both signs.
  function applyClearWriteDeny(): void {
    const cleared = {
      denyGrants: sessionDenyGrants.size + mcpDenyGrants.size,
      allowGrants: hostGrants.size + mcpGrants.size + oneShotGrants.size,
    };
    mcpDenyGrants.clear();
    sessionDenyGrants.clear();
    hostGrants.clear();
    mcpGrants.clear();
    oneShotGrants.clear();
    rotateDenyId();
    emitEvent(APPROVAL_EVENT_PREFIX, {
      control: "clear-write-deny",
      clearedNegativeGrants: cleared.denyGrants,
      clearedPositiveGrants: cleared.allowGrants,
      generation: options.generation(),
    });
    syncPolling();
    notifyStateChanged();
  }

  function pollControlFiles(): void {
    // Nothing to clear means nothing to read: a control file minted while no
    // deny is in force names a nonce that has since rotated, so it is inert.
    if (!negativeAuthorityPresent()) return;
    let entries: string[];
    try {
      entries = fs.readdirSync(options.decisionsDir);
    } catch {
      return;
    }
    // Bookkeeping is bounded by what is actually on disk: forget names whose
    // file is gone (the host writer unlinks consumed records), never names of
    // files still present. The previous wholesale reset above a fixed size is
    // what made starvation permanent — with more control files than the reset
    // threshold, every cycle re-marked the same prefix, hit the threshold,
    // forgot everything, and restarted, so a record past that prefix was never
    // reached and an operator's clear could never be observed. Pruning only
    // absent names keeps each pass strictly monotonic: every tick either
    // applies a clear or retires up to SCAN_LIMIT more entries permanently, so
    // no record can be starved regardless of how many are present.
    if (deadControlFiles.size > 0) {
      const present = new Set(entries);
      for (const name of Array.from(deadControlFiles)) {
        if (!present.has(name)) deadControlFiles.delete(name);
      }
    }
    let scanned = 0;
    for (const entry of entries) {
      if (!isApprovalControlFileName(entry) || deadControlFiles.has(entry)) continue;
      if (++scanned > APPROVAL_CONTROL_SCAN_LIMIT) return;
      const filePath = path.join(options.decisionsDir, entry);
      let stat: fs.Stats;
      try {
        stat = fs.statSync(filePath);
      } catch {
        continue;
      }
      // Same gate as decision files, and it runs before any state is touched:
      // only a root-owned regular file can carry host authority.
      if (!isHostAuthorityFile(stat, decisionOwnerUid)) {
        deadControlFiles.add(entry);
        log(`proxy-approval: ignored non-root control file ${entry} (uid=${stat.uid})`);
        continue;
      }
      let raw: string;
      try {
        raw = fs.readFileSync(filePath, "utf8");
      } catch {
        continue;
      }
      const record = parseApprovalControlRecord(raw);
      if (!record || record.processEpoch !== processEpoch) {
        deadControlFiles.add(entry);
        log(`proxy-approval: ignored malformed control file ${entry}`);
        continue;
      }
      if (record.denyId !== denyId) {
        // Stale or replayed: the nonce rotated since it was minted, so the
        // deny it names is not the deny in force.
        deadControlFiles.add(entry);
        log(`proxy-approval: ignored stale control file ${entry}`);
        continue;
      }
      deadControlFiles.add(entry);
      applyClearWriteDeny();
      return;
    }
  }

  // --- Decisions ------------------------------------------------------------

  function applyDecision(hold: PendingHold, decision: ApprovalDecisionRecord): void {
    const subject = grantSubject(hold.principal);
    if (decision.decision === "deny") {
      if (decision.denySession === true) {
        if (!subject) {
          log(`proxy-approval: rejected session-wide decision for request-only principal ${hold.id}`);
          resolveHold(hold, { kind: "denied" });
          return;
        }
        setSessionDeny(subject);
        for (const other of Array.from(holds.values())) {
          const otherSubject = grantSubject(other.principal);
          if (other.id !== hold.id && otherSubject?.key === subject.key) {
            resolveHold(other, { kind: "session-denied" });
          }
        }
      } else if (hold.record.mcp && decision.scope === "session") {
        if (!subject) {
          log(`proxy-approval: rejected MCP session denial for request-only principal ${hold.id}`);
          resolveHold(hold, { kind: "denied" });
          return;
        }
        const coverage = mcpCoverageFromDecision(hold.record.mcp, decision.mcpScope, hold.record.host);
        mcpDenyGrants.set(`${subject.key}\0${coverageKey(coverage)}`, {
          kind: "negative",
          scope: "session",
          subject: subject.subject,
          ...(subject.sessionKey !== undefined ? { sessionKey: subject.sessionKey } : {}),
          ...(subject.session !== undefined ? { session: subject.session } : {}),
          coverage,
          lifetime: negativeLifetime(),
        });
        rotateDenyId();
        for (const other of Array.from(holds.values())) {
          const otherSubject = grantSubject(other.principal);
          if (other.id !== hold.id
            && otherSubject?.key === subject.key
            && other.record.mcp
            && mcpCoverageMatches(coverage, other.record.mcp)) {
            resolveHold(other, { kind: "session-denied" });
          }
        }
      }
      resolveHold(hold, { kind: "denied" });
      return;
    }

    // A decision only resolves the hold after the request revalidates against
    // the CURRENT policy: host removed, rule tightened, or writeAction
    // tightened between hold and decision cancels fail-closed with no
    // credential read.
    if (!hold.revalidate()) {
      resolveHold(hold, { kind: "cancelled", reason: "policy-changed" });
      return;
    }

    const scope = decision.scope ?? "request";
    if (scope === "session" && !subject) {
      log(`proxy-approval: rejected session-wide approval for request-only principal ${hold.id}`);
      resolveHold(hold, { kind: "denied" });
      return;
    }
    if (hold.record.mcp) {
      if (scope === "session" && subject) {
        const coverage = mcpCoverageFromDecision(hold.record.mcp, decision.mcpScope, hold.record.host);
        mcpGrants.set(`${subject.key}\0${coverageKey(coverage)}`, {
          kind: "positive",
          scope,
          subject: subject.subject,
          ...(subject.sessionKey !== undefined ? { sessionKey: subject.sessionKey } : {}),
          ...(subject.session !== undefined ? { session: subject.session } : {}),
          coverage,
          lifetime: positiveLifetime(scope, decision),
        });
      }
    } else if (scope === "session" && subject) {
      hostGrants.set(`${subject.key}\0host\0${hold.record.host}`, {
        kind: "positive",
        scope,
        subject: subject.subject,
        ...(subject.sessionKey !== undefined ? { sessionKey: subject.sessionKey } : {}),
        ...(subject.session !== undefined ? { session: subject.session } : {}),
        coverage: { kind: "host", host: hold.record.host },
        lifetime: positiveLifetime(scope, decision),
      });
    } else {
      const coverage: GrantCoverage = {
        kind: "request",
        host: hold.record.host,
        method: hold.record.method,
        path: hold.record.path,
        category: hold.record.category,
      };
      const requestGrantKey = hold.retry && subject?.subject === "session"
        ? `retry\0${subject.key}\0${oneShotKey(coverage)}`
        : hold.requestId !== undefined
          ? `request\0${hold.requestId}`
          : `request\0${hold.id}`;
      oneShotGrants.set(requestGrantKey, {
        kind: "positive",
        scope: "request",
        subject: REQUEST_SUBJECT,
        ...(subject?.sessionKey !== undefined ? { sessionKey: subject.sessionKey } : {}),
        coverage,
        lifetime: positiveLifetime("request") as BoundedLifetime,
      });
    }
    resolveHold(hold, { kind: "approved", scope });
  }

  function pollChannel(): void {
    for (const hold of Array.from(holds.values())) {
      if (deadDecisionIds.has(hold.id)) continue;
      const decision = readDecision(hold.id);
      if (decision) applyDecision(hold, decision);
    }
    pollControlFiles();
    // Re-synchronize every tick so the poller stops itself once the last hold
    // resolves and the last negative grant lapses. Without this, an expired
    // deny leaves the interval running forever.
    syncPolling();
  }

  // The channel is polled while a hold is waiting for a decision or while
  // negative authority is waiting to be cleared — the deny outlives every
  // hold, so it needs its own reason to keep listening.
  function syncPolling(): void {
    if (!disposed && (holds.size > 0 || negativeAuthorityPresent())) {
      if (pollTimer !== undefined) return;
      pollTimer = setInterval(pollChannel, decisionPollMs);
      pollTimer.unref?.();
      return;
    }
    if (pollTimer === undefined) return;
    clearInterval(pollTimer);
    pollTimer = undefined;
  }

  async function hold(input: HoldInput, retry = false): Promise<HoldOutcome> {
    if (disposed) return { kind: "cancelled", reason: "shutdown" };
    const subject = grantSubject(input.principal);
    if (subject && sessionDenyGrants.has(subject.key)) return { kind: "session-denied" };
    if (input.mcp && subject && matchingMcpGrant(mcpDenyGrants, input.mcp, subject.key)) {
      return { kind: "session-denied" };
    }
    // Held-connection cap (MED-1): past the cap, fast-deny instead of holding
    // so an agent cannot pin the proxy by spamming writes.
    if (holds.size >= maxHeld) return { kind: "capacity" };
    // Headless fast-deny (LOW-1): with no attached approver a write denies
    // immediately instead of stalling for the full hold window.
    if (!watcherAttached()) return { kind: "no-watcher" };

    const id = mintId();
    const heldAtMs = now();
    const requestSession = authenticatedSession(input.principal);
    const record: PendingApprovalRecord = {
      v: 1,
      processEpoch,
      id,
      ...boundedRecordFields(input),
      category: input.category,
      tokenNames: [...input.tokenNames].sort(),
      ...(boundedMcp(input.mcp) ? { mcp: boundedMcp(input.mcp) } : {}),
      ...(requestSession ? { session: sessionDisplay(requestSession) } : {}),
      ...(input.principal?.kind === "anonymous-utility"
        ? { requestOnlyPrincipal: { kind: input.principal.kind, label: input.principal.label } }
        : {}),
      generation: options.generation(),
      heldAt: new Date(heldAtMs).toISOString(),
      expiresAt: new Date(heldAtMs + options.holdSeconds * 1000).toISOString(),
    };
    try {
      fs.writeFileSync(pendingPath(id), `${JSON.stringify(record)}\n`, { mode: 0o600 });
    } catch (error) {
      // No visible pending record means no human can ever approve it: fail
      // closed instead of holding an invisible request.
      log(`proxy-approval: failed to write pending record: ${error instanceof Error ? error.message : String(error)}`);
      return { kind: "no-watcher" };
    }

    return await new Promise<HoldOutcome>((resolve) => {
      const pending: PendingHold = {
        id,
        requestId: input.requestId,
        record,
        principal: input.principal,
        retry,
        revalidate: input.revalidate,
        resolve,
        timeout: setTimeout(() => {
          const current = holds.get(id);
          if (current) resolveHold(current, { kind: "timeout" });
        }, options.holdSeconds * 1000),
      };
      pending.timeout.unref?.();
      holds.set(id, pending);
      emitEvent(APPROVAL_REQUEST_EVENT_PREFIX, {
        id,
        host: record.host,
        method: record.method,
        path: record.path,
        category: record.category,
        tokenNames: record.tokenNames,
        holdSeconds: options.holdSeconds,
        ...(record.mcp ? { mcp: record.mcp } : {}),
        ...(record.session ? { session: record.session } : {}),
        ...(record.requestOnlyPrincipal ? { requestOnlyPrincipal: record.requestOnlyPrincipal } : {}),
        generation: record.generation,
      });
      syncPolling();
      notifyStateChanged();
    });
  }

  function notePendingRetryApproval(input: Omit<HoldInput, "requestId">): void {
    if (disposed || holds.size >= maxHeld || !watcherAttached()) return;
    const bounded = boundedRecordFields(input as HoldInput);
    const duplicate = Array.from(holds.values()).some((hold) => hold.record.host === bounded.host
      && hold.record.method === bounded.method
      && hold.record.path === bounded.path
      && hold.record.category === input.category);
    if (duplicate) return;
    void hold({ ...input }, true).then(() => {});
  }

  function cancelForRequest(requestId: string): void {
    for (const hold of Array.from(holds.values())) {
      if (hold.requestId === requestId) {
        resolveHold(hold, { kind: "cancelled", reason: "client-disconnected" });
      }
    }
  }

  function revokeSession(sessionKey: string): void {
    let negativeChanged = sessionDenyGrants.delete(sessionKey);
    for (const map of [oneShotGrants, hostGrants, mcpGrants, mcpDenyGrants]) {
      for (const [key, grant] of Array.from(map.entries())) {
        if (grant.sessionKey !== sessionKey) continue;
        if (grant.kind === "negative") negativeChanged = true;
        map.delete(key);
      }
    }
    for (const hold of Array.from(holds.values())) {
      if (authenticatedSession(hold.principal)?.sessionKey === sessionKey) {
        resolveHold(hold, { kind: "cancelled", reason: "session-ended" });
      }
    }
    if (negativeChanged) rotateDenyId();
    syncPolling();
    notifyStateChanged();
  }

  function ruleChanged(previous: PolicySnapshot, next: PolicySnapshot, host: string): boolean {
    if (!next.allowedHostSet.has(host)) return true;
    if (JSON.stringify(previous.requests[host] ?? null) !== JSON.stringify(next.requests[host] ?? null)) return true;
    if ((previous.writeApproval ?? "") !== (next.writeApproval ?? "")
      && (previous.requests[host]?.writeAction === undefined || next.requests[host]?.writeAction === undefined)) {
      return true;
    }
    return false;
  }

  function onPolicyChanged(previous: PolicySnapshot, next: PolicySnapshot): void {
    // Drop grants for any host whose effective posture may have changed;
    // one-shot grants are dropped wholesale (they only bridge a decision to
    // its immediate re-run, and fail-closed means the agent retries).
    oneShotGrants.clear();
    for (const [key, grant] of Array.from(hostGrants.entries())) {
      const host = grant.coverage.host;
      if (ruleChanged(previous, next, host)) {
        hostGrants.delete(key);
        log(`proxy-approval: dropped write grant for ${host} after policy change`);
      }
    }
    // Positive MCP grants go wholesale: they also depend on the MCP operation
    // policy, which is not in this snapshot, so dropping them is the
    // fail-closed choice and the agent simply asks again.
    //
    // THIS SWEEP IS LOAD-BEARING, and so is its relationship to the denies
    // below. A deny shadows a broader allow, so the pair (drop a deny, keep the
    // allow it was masking) is HIGH-1 — the un-shadowing bug — arriving through
    // the policy path instead of the clear path. Two properties keep it shut:
    // every positive MCP grant dies here, unconditionally, and no negative one
    // dies at all (see below). Anyone re-introducing deny-dropping here must
    // also drop every positive grant that deny was shadowing, exactly as
    // `applyClearWriteDeny` does, or the bug returns by this route.
    for (const key of Array.from(mcpGrants.keys())) {
      mcpGrants.delete(key);
      log(`proxy-approval: dropped MCP write grant after policy change`);
    }
    // Negative grants are NOT dropped here, by design. `ruleChanged` has the
    // wrong polarity for negative
    // authority: it asks "might this host's posture have changed?", which is
    // the conservative question for an allow (drop it, the agent re-asks) and
    // the permissive one for a deny (drop it, the operator's explicit "no"
    // silently evaporates). Tightening a host — adding a path prefix, say —
    // would have discarded a scoped deny on that host.
    //
    // Nor is "drop only on an explicit widening" worth building: when a host's
    // effective posture widens to `allow`, the write classifier short-circuits
    // before it ever consults a grant, so the deny is already dormant. Keeping
    // it costs nothing there and correctly restores the operator's decision if
    // the posture returns to `ask`. A policy edit is a different channel from
    // an approval decision; making it a second, silent revocation path is the
    // "authority changes where nobody can see it" defect this design exists to
    // close. Negative authority is revoked one way: the root-minted control
    // record, which itemizes exactly what it takes back.
    // Cancel pending holds that no longer revalidate under the new policy.
    for (const hold of Array.from(holds.values())) {
      if (!hold.revalidate()) {
        resolveHold(hold, { kind: "cancelled", reason: "policy-changed" });
      }
    }
    syncPolling();
    notifyStateChanged();
  }

  function summarize(grant: AppliedGrant): WriteApprovalGrantSummary {
    const remaining = remainingSeconds(grant);
    const coverage = grant.coverage;
    return {
      effect: grant.kind === "positive" ? "allow" : "deny",
      scope: grant.scope,
      subject: grant.subject,
      coverage: coverage.kind,
      ...(coverage.kind === "request"
        ? { host: coverage.host, method: coverage.method, path: coverage.path }
        : coverage.kind === "host"
          ? { host: coverage.host }
          : { host: coverage.host, mcp: coverage.mcp }),
      ...(grant.session !== undefined ? { session: grant.session } : {}),
      ...(remaining !== undefined ? { expiresInSeconds: remaining } : {}),
    };
  }

  // Every live grant, positive and negative, including the one-shot request
  // grants: a five-minute allow that readmits any request matching a bounded
  // (host, method, path, category) shape is standing authority too, and a deny
  // nobody can see is as invisible as an allow nobody can see.
  function grantSummaries(): WriteApprovalGrantSummary[] {
    const summaries: WriteApprovalGrantSummary[] = [];
    for (const map of [oneShotGrants, hostGrants, mcpGrants, mcpDenyGrants, sessionDenyGrants]) {
      for (const grant of map.values()) {
        if (!grantActive(grant)) continue;
        summaries.push(summarize(grant));
      }
    }
    return summaries.sort((left, right) => {
      const leftKey = `${left.effect}\0${left.coverage}\0${left.host ?? ""}\0${left.method ?? ""}${left.path ?? ""}\0${left.mcp?.agent ?? ""}:${left.mcp?.server ?? ""}:${left.mcp?.method ?? ""}:${left.mcp?.tool ?? ""}`;
      const rightKey = `${right.effect}\0${right.coverage}\0${right.host ?? ""}\0${right.method ?? ""}${right.path ?? ""}\0${right.mcp?.agent ?? ""}:${right.mcp?.server ?? ""}:${right.mcp?.method ?? ""}:${right.mcp?.tool ?? ""}`;
      return leftKey.localeCompare(rightKey);
    });
  }

  return {
    processEpoch,
    hasGrant,
    denyState: () => ({ id: denyId }),
    watcherAttached,
    heldCount: () => holds.size,
    grantSummaries,
    hold,
    notePendingRetryApproval,
    cancelForRequest,
    revokeSession,
    onPolicyChanged,
    dispose: () => {
      disposed = true;
      for (const hold of Array.from(holds.values())) {
        resolveHold(hold, { kind: "cancelled", reason: "shutdown" });
      }
      syncPolling();
    },
  };
}
