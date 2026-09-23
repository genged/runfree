// Write-approval channel contract (operation-aware approve-on-write design).
// Both halves of the host↔proxy approval channel import this module: the
// proxy-side hold manager (pending records, decision consumption, watcher
// freshness) and the CLI-side `runfree approvals`/`runfree approve` commands
// that read pending records and write root-owned decision files over docker
// exec. Keeping paths, shapes, and limits here means one side cannot silently
// diverge from the other.

// Fixed by contract inside the proxy container (like the proxy status dir).
// The proxy honors env overrides only so its test harness can point the dirs
// at a temp directory; compose.yaml pins the canonical paths explicitly and
// the CLI always uses these constants.
export const APPROVALS_PROCESS_EPOCH_FILE = "process-epoch";
export const APPROVAL_PROCESS_EPOCH_PATTERN = /^[0-9a-f]{64}$/u;

export const APPROVALS_PENDING_DIR = "/run/runfree-approvals/pending";
export const APPROVALS_DECISIONS_DIR = "/run/runfree-approvals/decisions";

// Watcher heartbeat: a root-owned file whose mtime proves an approver is
// attached (a running `runfree approvals --watch` or an attached interactive
// session). Lives in the decisions dir because attaching an approver is a
// boundary-widening signal the UID-1001 proxy must not be able to mint.
export const APPROVALS_WATCHER_HEARTBEAT_FILE = "watcher-heartbeat";
export const APPROVAL_WATCHER_FRESH_MS = 45_000;

export const APPROVAL_REQUEST_EVENT_PREFIX = "proxy-approval-request: ";
export const APPROVAL_EVENT_PREFIX = "proxy-approval: ";

// Level-triggered approval-state snapshot the request proxy writes into its
// own uid-1001 status subdirectory (same channel as request-proxy.json). The
// host CLI reads it over docker exec so `runfree status` can surface held
// writes and grants — grants are invisible authority otherwise. Observation
// only, never authorization state.
export function writeApprovalsStatusPath(statusDir = "/run/runfree-proxy-status"): string {
  return `${statusDir}/request-proxy/write-approvals.json`;
}

import {
  parsePendingApprovalSession,
  type PendingApprovalSession,
} from "./session-registry.js";
import { isRecord } from "./primitives.js";

// Request grants can be bound to one held handler/retry. Every wider grant is
// bound to an authenticated internal session key; the key itself is never
// published in status or pending files.
export type ApprovalGrantSubject = "request" | "session";

export type WriteApprovalGrantCoverage = "request" | "host" | "mcp-tool" | "mcp-method" | "mcp-server-tools";

export type WriteApprovalGrantSummary = {
  // Positive grants admit matching writes, negative grants deny them. Both are
  // authority, so both are reported: invisible authority — of either sign — is
  // the whole defect class this snapshot exists to close.
  effect: "allow" | "deny";
  // How the operator expressed the decision, not how long it lasts.
  scope: "request" | "session";
  subject: ApprovalGrantSubject;
  coverage: WriteApprovalGrantCoverage;
  host?: string;
  // `request` coverage only: the exact call the one-shot grant readmits. It is
  // not "the held request" — any request matching this bounded shape redeems
  // it until it is consumed or expires, so status has to show the shape.
  method?: string;
  path?: string;
  mcp?: PendingApprovalMcp;
  session?: PendingApprovalSession;
  // Absent means "until cleared", which only a negative grant may be: nothing
  // that fails open is ever unbounded, and the parser enforces that here so a
  // malformed snapshot cannot render an allow as open-ended.
  expiresInSeconds?: number;
};

export type WriteApprovalsStatus = {
  processEpoch?: string;
  held: number;
  // Nonce a `clear-write-deny` control record must name. The proxy rotates it
  // whenever negative authority changes, so a stale or replayed clear can
  // never apply to a deny the operator never saw.
  denyId: string;
  grants: WriteApprovalGrantSummary[];
  updatedAt: string;
};

function parseGrantSummary(entry: unknown): WriteApprovalGrantSummary | undefined {
  if (!isRecord(entry)) return undefined;
  if (Object.keys(entry).some((key) => !new Set([
    "effect", "scope", "subject", "coverage", "host", "method", "path", "mcp", "session", "expiresInSeconds",
  ]).has(key))) return undefined;
  if (entry.effect !== "allow" && entry.effect !== "deny") return undefined;
  if (entry.scope !== "request" && entry.scope !== "session") return undefined;
  if (entry.subject !== "request" && entry.subject !== "session") return undefined;
  if (entry.coverage !== "request" && entry.coverage !== "host" && entry.coverage !== "mcp-tool"
    && entry.coverage !== "mcp-method" && entry.coverage !== "mcp-server-tools") {
    return undefined;
  }
  if (entry.host !== undefined && (typeof entry.host !== "string" || entry.host === "")) return undefined;
  if (entry.method !== undefined && (typeof entry.method !== "string" || entry.method === "")) return undefined;
  if (entry.path !== undefined && typeof entry.path !== "string") return undefined;
  if (entry.mcp !== undefined && !isPendingApprovalMcp(entry.mcp)) return undefined;
  const session = entry.session === undefined ? undefined : parsePendingApprovalSession(entry.session);
  if (entry.session !== undefined && session === undefined) return undefined;
  if (entry.subject === "session" && session === undefined) return undefined;
  if (entry.subject !== "session" && session !== undefined) return undefined;
  if (entry.expiresInSeconds !== undefined
    && (typeof entry.expiresInSeconds !== "number" || !Number.isFinite(entry.expiresInSeconds) || entry.expiresInSeconds < 0)) {
    return undefined;
  }
  // An allow with no expiry renders as "until cleared" — the one thing a
  // positive grant may never be. The proxy never emits it; refuse to display
  // it rather than let a malformed snapshot invent open-ended authority.
  if (entry.effect === "allow"
    && entry.expiresInSeconds === undefined
    && !(entry.subject === "session" && entry.scope === "session")) return undefined;
  return {
    effect: entry.effect,
    scope: entry.scope,
    subject: entry.subject,
    coverage: entry.coverage,
    ...(typeof entry.host === "string" ? { host: entry.host } : {}),
    ...(typeof entry.method === "string" ? { method: entry.method } : {}),
    ...(typeof entry.path === "string" ? { path: entry.path } : {}),
    ...(isPendingApprovalMcp(entry.mcp) ? { mcp: entry.mcp } : {}),
    ...(session !== undefined ? { session } : {}),
    ...(typeof entry.expiresInSeconds === "number" ? { expiresInSeconds: entry.expiresInSeconds } : {}),
  };
}

export function parseWriteApprovalsStatus(raw: string): WriteApprovalsStatus | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
  if (!isRecord(parsed)) return undefined;
  if (parsed.processEpoch !== undefined && (typeof parsed.processEpoch !== "string" || !APPROVAL_PROCESS_EPOCH_PATTERN.test(parsed.processEpoch))) return undefined;
  if (Object.keys(parsed).some((key) => !new Set(["held", "denyId", "grants", "updatedAt", "processEpoch"]).has(key))) return undefined;
  if (typeof parsed.held !== "number" || !Number.isInteger(parsed.held) || parsed.held < 0) return undefined;
  if (typeof parsed.denyId !== "string" || !isApprovalId(parsed.denyId)) return undefined;
  if (!Array.isArray(parsed.grants)) return undefined;
  const grants: WriteApprovalGrantSummary[] = [];
  for (const entry of parsed.grants) {
    const grant = parseGrantSummary(entry);
    if (!grant) return undefined;
    grants.push(grant);
  }
  if (typeof parsed.updatedAt !== "string") return undefined;
  return {
    ...(parsed.processEpoch === undefined ? {} : { processEpoch: parsed.processEpoch as string }),
    held: parsed.held,
    denyId: parsed.denyId,
    grants,
    updatedAt: parsed.updatedAt,
  };
}

// Single-use nonce: 16 random bytes, lowercase hex.
export const APPROVAL_ID_PATTERN = /^[0-9a-f]{32}$/;

export const WRITE_APPROVAL_HOLD_SECONDS_DEFAULT = 120;
export const WRITE_APPROVAL_HOLD_SECONDS_MIN = 5;
export const WRITE_APPROVAL_HOLD_SECONDS_MAX = 300;

// Held-connection cap (review MED-1): a held write is a live suspended
// request, so it gets its own explicit cap distinct from denial event caps.
// Writes beyond the cap fast-deny rather than hold.
export const WRITE_APPROVAL_MAX_HELD = 16;

// TTL grants are read-time clamped like audit mode:
// min(expiresAt, min(grantedAt, now) + MAX).
export const WRITE_APPROVAL_GRANT_TTL_MAX_MS = 8 * 60 * 60 * 1000;
export const WRITE_APPROVAL_GRANT_TTL_DEFAULT_MS = 15 * 60 * 1000;

// A `session`-scoped approval without an explicit TTL carries no duration:
// the grant is keyed to the requesting session and dies with it (teardown or
// authority revocation drops it). A forgotten runtime cannot keep it alive —
// the session's lease expiry ends the session and the grant together.

// Duration of a `request`-scoped ("this request only") grant. It exists to
// bridge one decision to the immediate re-run, including the deny-then-retry
// WebSocket path where the agent reconnects on its own schedule. Generous for
// a reconnect and still bounded: an unredeemed one-shot must not linger as
// authority for the life of the proxy.
export const WRITE_APPROVAL_REQUEST_GRANT_MS = 5 * 60 * 1000;

// Compact duration label for CLI prompts and summaries. Shared so the picker,
// the decision summary, and `runfree status` cannot describe the same grant
// three different ways.
export function formatApprovalDuration(ms: number): string {
  if (ms >= 3_600_000 && ms % 3_600_000 === 0) return `${ms / 3_600_000}h`;
  if (ms >= 60_000 && ms % 60_000 === 0) return `${ms / 60_000}m`;
  return `${Math.max(1, Math.round(ms / 1000))}s`;
}

export type ApprovalWriteCategory =
  | "method"
  | "method-override"
  | "git-push"
  | "graphql"
  | "write-path"
  | "websocket"
  | "mcp-tool"
  | "mcp-unknown";

export type PendingApprovalMcp = {
  agent: "claude" | "codex";
  serverId?: string;
  server: string;
  method: string;
  tool?: string;
};

export type PendingApprovalRecord = {
  processEpoch?: string;
  v: 1;
  id: string;
  host: string;
  method: string;
  // Query-stripped, bounded pathname. Never a body and never a secret.
  path: string;
  category: ApprovalWriteCategory;
  // Token names the request would use after approval; names only, never values.
  tokenNames: string[];
  mcp?: PendingApprovalMcp;
  // Safe display metadata only. The internal session key stays in proxy
  // memory and is never serialized into this host-readable record.
  session?: PendingApprovalSession;
  // Typed compatibility principals are deliberately request-only. Absence is
  // also request-only and must never widen to a runtime grant.
  requestOnlyPrincipal?: {
    kind: "anonymous-utility";
    label: string;
  };
  // Policy generation and authorization fingerprint captured at hold time; a
  // decision resolves only after revalidation against the current policy.
  generation: string;
  heldAt: string;
  expiresAt: string;
};

export type ApprovalScope = "request" | "session";
export type McpApprovalScope = "tool" | "method" | "server-tools";

export type ApprovalDecisionRecord = {
  processEpoch?: string;
  v: 1;
  id: string;
  decision: "approve" | "deny";
  // Scope of an approve decision; deny is always one-shot unless denySession.
  scope?: ApprovalScope;
  // For MCP session decisions, this narrows what the session scope means.
  // If omitted, the proxy defaults to the held tool for tools/call and the
  // held method for other classified MCP methods.
  mcpScope?: McpApprovalScope;
  // Host-side prompt action: persist the matching host-owned MCP rule before
  // resolving the current held request. The proxy ignores this field; the CLI
  // must convert it into a rule write + normal request approval.
  saveMcpRule?: "tool" | "server-tools";
  ttlMs?: number;
  // "stop asking": deny this request and all further writes in the held
  // request's authenticated session.
  denySession?: boolean;
  decidedAt: string;
};

// Host -> proxy control channel, carried by the same root-owned decisions
// tmpfs as decision files and with the same trust properties: minted by a root
// `docker exec` on the host, schema-validated by the proxy, ignored unless the
// file is a root-owned regular file, and bound to a nonce the proxy rotates on
// apply so a leftover or replayed file can never apply twice.
//
// Control records exist because the runtime-wide write deny is authority with
// no expiry: something that cannot be undone through the channel that created
// it is a latch, not a decision. The request nonce in the file name is chosen
// by the host, so a junk file can never occupy the path a later clear needs.
export const APPROVAL_CONTROL_FILE_PREFIX = "control-";
// The proxy scans at most this many control files per poll. Only root can
// write this directory, but bounded work beats trusting that.
export const APPROVAL_CONTROL_SCAN_LIMIT = 32;

export type ApprovalControlRecord = {
  processEpoch?: string;
  v: 1;
  control: "clear-write-deny";
  // Must equal the proxy's current deny nonce, or the record is ignored.
  denyId: string;
  issuedAt: string;
};

export function approvalControlFileName(requestId: string): string {
  return `${APPROVAL_CONTROL_FILE_PREFIX}${requestId}.json`;
}

export function isApprovalControlFileName(name: string): boolean {
  if (!name.startsWith(APPROVAL_CONTROL_FILE_PREFIX) || !name.endsWith(".json")) return false;
  return isApprovalId(name.slice(APPROVAL_CONTROL_FILE_PREFIX.length, -".json".length));
}

export function parseApprovalControlRecord(raw: string): ApprovalControlRecord | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
  if (!isRecord(parsed)) return undefined;
  if (parsed.processEpoch !== undefined && (typeof parsed.processEpoch !== "string" || !APPROVAL_PROCESS_EPOCH_PATTERN.test(parsed.processEpoch))) return undefined;
  if (parsed.v !== 1) return undefined;
  if (parsed.control !== "clear-write-deny") return undefined;
  if (typeof parsed.denyId !== "string" || !isApprovalId(parsed.denyId)) return undefined;
  if (typeof parsed.issuedAt !== "string") return undefined;
  return { v: 1, control: "clear-write-deny", denyId: parsed.denyId, issuedAt: parsed.issuedAt, ...(parsed.processEpoch === undefined ? {} : { processEpoch: parsed.processEpoch as string }) };
}

export function isApprovalId(value: string): boolean {
  return APPROVAL_ID_PATTERN.test(value);
}

export function approvalsPendingDirFromEnv(env: NodeJS.ProcessEnv = process.env): string {
  return env.RUNFREE_APPROVALS_PENDING_DIR ?? APPROVALS_PENDING_DIR;
}

export function approvalsDecisionsDirFromEnv(env: NodeJS.ProcessEnv = process.env): string {
  return env.RUNFREE_APPROVALS_DECISIONS_DIR ?? APPROVALS_DECISIONS_DIR;
}

// Host-resolved hold window (spec: validated 5-300s on the host, passed to
// the proxy as runtime env, folded into the runtime security-contract hash).
// The proxy treats an out-of-range or malformed value as the default rather
// than trusting env content.
export function writeApprovalHoldSecondsFromEnv(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.RUNFREE_WRITE_APPROVAL_HOLD_SECONDS;
  if (raw === undefined || !/^\d{1,3}$/.test(raw)) return WRITE_APPROVAL_HOLD_SECONDS_DEFAULT;
  const value = Number(raw);
  if (value < WRITE_APPROVAL_HOLD_SECONDS_MIN || value > WRITE_APPROVAL_HOLD_SECONDS_MAX) {
    return WRITE_APPROVAL_HOLD_SECONDS_DEFAULT;
  }
  return value;
}


const APPROVAL_CATEGORIES: ReadonlySet<string> = new Set([
  "method",
  "method-override",
  "git-push",
  "graphql",
  "write-path",
  "websocket",
  "mcp-tool",
  "mcp-unknown",
]);

function isPendingApprovalMcp(value: unknown): value is PendingApprovalMcp {
  if (!isRecord(value)) return false;
  if (value.agent !== "claude" && value.agent !== "codex") return false;
  if (value.serverId !== undefined && (typeof value.serverId !== "string" || value.serverId === "")) return false;
  if (typeof value.server !== "string" || value.server === "") return false;
  if (typeof value.method !== "string" || value.method === "") return false;
  if (value.tool !== undefined && (typeof value.tool !== "string" || value.tool === "")) return false;
  return true;
}

// Lenient, validating parse: records travel through tmpfs files and docker
// exec output, so malformed content is skipped rather than trusted or fatal.
export function parsePendingApprovalRecord(raw: string): PendingApprovalRecord | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
  if (!isRecord(parsed)) return undefined;
  if (parsed.processEpoch !== undefined && (typeof parsed.processEpoch !== "string" || !APPROVAL_PROCESS_EPOCH_PATTERN.test(parsed.processEpoch))) return undefined;
  if (Object.keys(parsed).some((key) => !new Set([
    "v", "id", "host", "method", "path", "category", "tokenNames", "mcp", "session", "requestOnlyPrincipal",
    "generation", "heldAt", "expiresAt", "processEpoch",
  ]).has(key))) return undefined;
  if (parsed.v !== 1) return undefined;
  if (typeof parsed.id !== "string" || !isApprovalId(parsed.id)) return undefined;
  if (typeof parsed.host !== "string" || parsed.host === "") return undefined;
  if (typeof parsed.method !== "string" || typeof parsed.path !== "string") return undefined;
  if (typeof parsed.category !== "string" || !APPROVAL_CATEGORIES.has(parsed.category)) return undefined;
  if (!Array.isArray(parsed.tokenNames) || !parsed.tokenNames.every((name) => typeof name === "string")) return undefined;
  const mcp = isPendingApprovalMcp(parsed.mcp) ? parsed.mcp : undefined;
  const session = parsed.session === undefined ? undefined : parsePendingApprovalSession(parsed.session);
  if (parsed.session !== undefined && session === undefined) return undefined;
  let requestOnlyPrincipal: PendingApprovalRecord["requestOnlyPrincipal"];
  if (parsed.requestOnlyPrincipal !== undefined) {
    if (!isRecord(parsed.requestOnlyPrincipal)) return undefined;
    if (Object.keys(parsed.requestOnlyPrincipal).some((key) => key !== "kind" && key !== "label")) return undefined;
    if (parsed.requestOnlyPrincipal.kind !== "anonymous-utility") return undefined;
    if (typeof parsed.requestOnlyPrincipal.label !== "string"
      || parsed.requestOnlyPrincipal.label === ""
      || parsed.requestOnlyPrincipal.label.length > 80) return undefined;
    requestOnlyPrincipal = {
      kind: parsed.requestOnlyPrincipal.kind,
      label: parsed.requestOnlyPrincipal.label,
    };
  }
  if (session !== undefined && requestOnlyPrincipal !== undefined) return undefined;
  if (typeof parsed.generation !== "string") return undefined;
  if (typeof parsed.heldAt !== "string" || typeof parsed.expiresAt !== "string") return undefined;
  return {
    v: 1,
    ...(parsed.processEpoch === undefined ? {} : { processEpoch: parsed.processEpoch as string }),
    id: parsed.id,
    host: parsed.host,
    method: parsed.method,
    path: parsed.path,
    category: parsed.category as ApprovalWriteCategory,
    tokenNames: parsed.tokenNames as string[],
    ...(mcp !== undefined ? { mcp } : {}),
    ...(session !== undefined ? { session } : {}),
    ...(requestOnlyPrincipal !== undefined ? { requestOnlyPrincipal } : {}),
    generation: parsed.generation,
    heldAt: parsed.heldAt,
    expiresAt: parsed.expiresAt,
  };
}

export function parseApprovalDecisionRecord(raw: string): ApprovalDecisionRecord | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
  if (!isRecord(parsed)) return undefined;
  if (parsed.processEpoch !== undefined && (typeof parsed.processEpoch !== "string" || !APPROVAL_PROCESS_EPOCH_PATTERN.test(parsed.processEpoch))) return undefined;
  if (Object.keys(parsed).some((key) => !new Set([
    "v", "id", "decision", "scope", "mcpScope", "saveMcpRule", "ttlMs", "denySession", "decidedAt", "processEpoch",
  ]).has(key))) return undefined;
  if (parsed.v !== 1) return undefined;
  if (typeof parsed.id !== "string" || !isApprovalId(parsed.id)) return undefined;
  if (parsed.decision !== "approve" && parsed.decision !== "deny") return undefined;
  let scope: ApprovalScope | undefined;
  if (parsed.scope !== undefined) {
    if (parsed.scope !== "request" && parsed.scope !== "session") return undefined;
    scope = parsed.scope;
  }
  let mcpScope: McpApprovalScope | undefined;
  if (parsed.mcpScope !== undefined) {
    if (parsed.mcpScope !== "tool" && parsed.mcpScope !== "method" && parsed.mcpScope !== "server-tools") return undefined;
    mcpScope = parsed.mcpScope;
  }
  let saveMcpRule: "tool" | "server-tools" | undefined;
  if (parsed.saveMcpRule !== undefined) {
    if (parsed.saveMcpRule !== "tool" && parsed.saveMcpRule !== "server-tools") return undefined;
    saveMcpRule = parsed.saveMcpRule;
  }
  let ttlMs: number | undefined;
  if (parsed.ttlMs !== undefined) {
    if (typeof parsed.ttlMs !== "number" || !Number.isInteger(parsed.ttlMs) || parsed.ttlMs <= 0) return undefined;
    ttlMs = parsed.ttlMs;
  }
  let denySession: boolean | undefined;
  if (parsed.denySession !== undefined) {
    if (typeof parsed.denySession !== "boolean") return undefined;
    denySession = parsed.denySession;
  }
  if (ttlMs !== undefined && (parsed.decision !== "approve" || scope !== "session")) return undefined;
  if (denySession === true && (parsed.decision !== "deny" || scope !== undefined || ttlMs !== undefined)) return undefined;
  if (typeof parsed.decidedAt !== "string") return undefined;
  return {
    v: 1,
    ...(parsed.processEpoch === undefined ? {} : { processEpoch: parsed.processEpoch as string }),
    id: parsed.id,
    decision: parsed.decision,
    ...(scope !== undefined ? { scope } : {}),
    ...(mcpScope !== undefined ? { mcpScope } : {}),
    ...(saveMcpRule !== undefined ? { saveMcpRule } : {}),
    ...(ttlMs !== undefined ? { ttlMs } : {}),
    ...(denySession !== undefined ? { denySession } : {}),
    decidedAt: parsed.decidedAt,
  };
}
