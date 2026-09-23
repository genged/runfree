// server.ts — credential-injection proxy entrypoint.
//
// mockttp HTTPS-intercepting forward proxy. The CA key is proxy-only while the
// public cert is mounted read-only into the agent. Per-host credential
// injection is driven by the project network-policy.json mounted at runtime.

import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import path from "node:path";
import stream from "node:stream";
import {
  auditMarkerPathFromEnv,
  auditResolvedHostsPathFromEnv,
  auditSpoolPathFromEnv,
  createAuditEventEmitter,
  createAuditSpoolWriter,
  readAuditMarkerState,
  type AuditMarkerState,
} from "./audit.js";
import {
  createDenialEventEmitter,
  safePathname,
  syntheticDenialBody,
  type DenialReason,
  type ShapeDenialBodyDetails,
} from "./denial.js";
import {
  OAuthMediator,
  hasOAuthAuthorizationHandle,
  setHeader,
  type OAuthProxyResponse,
  type OAuthRequestResult,
} from "./oauth-mediation.js";
import { validateMcpOperationPolicy, type LoadedMcpOperationPolicy } from "@runfree/runtime-contracts/mcp-operation-policy";
import {
  effectiveProxyRootFromEnv,
  loadEffectiveProxyControl,
  type LoadedEffectiveProxyControl,
} from "@runfree/runtime-contracts/effective-control";
import { requestProxyStatusPath } from "@runfree/runtime-contracts/proxy-status";
import { writeGenerationStatusFile } from "./status.js";
import { installResolvedHostLookup, resolvedHostsPathFromEnv } from "./resolved-hosts.js";
import { AdmissionRegistry, type AdmissionRecord } from "./admission.js";
import {
  createMockttpAdapter,
  generateProxyCA,
  generateProxyLeaf,
  runMockttpAdapterSelfTest,
} from "./mockttp-adapter.js";
import { classifyMcpRequestBody, MCP_BODY_CAP_BYTES, type McpClassification, type McpDisplayFields } from "./mcp-classify.js";
import {
  DEFAULT_WRITE_ACTION,
  ProxyAdmissionHostMismatchError,
  ProxyPolicyDenialError,
  assertAllowedWebSocketRequest,
  assertRequestMatchesAdmission,
  beforeAllowedRequest,
  configuredCredentialHeaderNames,
  evaluateRequestWriteAsk,
  hostFromUrl,
  loadProxyPolicy,
  normalizeHostname,
  type CredentialMutationSummary,
  type LoadedProxyPolicy,
  type ProxyRequest,
  type ShapeDenialDetails,
  type ShapeDenialReason,
} from "./policy.js";
import { createWriteApprovalManager } from "./approvals.js";
import { assertSourceIpSessionIdentityConfig } from "./session-identity-config.js";
import { SessionFileRegistry } from "./session-file-registry.js";
import { SessionIpAssignments } from "./session-ip-reuse.js";
import { SESSION_ADMISSION_PROVISIONING_REQUEST } from "@runfree/runtime-contracts/session-admission";
import {
  isExactSessionSourceIpv4,
  sameProxySessionStableIdentity,
  type ApprovalRequestPrincipal,
} from "@runfree/runtime-contracts/session-registry";
import { GRAPHQL_BODY_CAP_BYTES, classifyGraphqlRequestBody } from "./graphql-classify.js";
import {
  approvalsDecisionsDirFromEnv,
  approvalsPendingDirFromEnv,
  writeApprovalHoldSecondsFromEnv,
  writeApprovalsStatusPath,
} from "@runfree/runtime-contracts/write-approvals";

const CA_DIR  = process.env.CA_DIR;
const CA_CERT = process.env.CA_CERT ?? path.join(CA_DIR ?? "/ca/public", "proxy-ca.crt");
const CA_KEY  = process.env.CA_KEY ?? path.join(CA_DIR ?? "/ca/private", "proxy-ca.key");
const PORT    = parseInt(process.env.PORT ?? "8080", 10);
const POLICY_WATCH_INTERVAL_MS = parseInt(process.env.PROXY_POLICY_WATCH_MS ?? "1000", 10);
const PROXY_VERBOSE_MARKER_DIR = process.env.PROXY_VERBOSE_MARKER_DIR ?? "/run/runfree-proxy-verbose";
const CONNECT_HEADER_LIMIT = 8192;
// Bound on the first request head the guard buffers for a non-CONNECT
// connection. Node's own parser rejects heads over `--max-http-header-size`
// (16 KiB by default), so a head the guard refuses at this bound would have
// been refused by mockttp too: the guard never narrows what mockttp accepts.
const REQUEST_HEAD_LIMIT = 16384;
// The guard buffers the first head before deciding, so a client that opens a
// connection and then stalls must not pin guard memory forever. mockttp's own
// `headersTimeout` cannot help here — nothing has reached mockttp yet.
const REQUEST_HEAD_TIMEOUT_MS = parseIntWithDefault(process.env.PROXY_REQUEST_HEAD_TIMEOUT_MS, 30_000);
// Bound on how many sealed-metadata refusals are logged per proxy process.
const PROXY_AUTH_METADATA_LOG_LIMIT = 20;
// Denied-tunnel cost bounds: cap concurrent denied tunnels (raw pre-TLS 403
// past the cap) and destroy idle denied tunnels aggressively. They never
// reach upstream regardless.
const DENIED_TUNNEL_MAX = parseIntWithDefault(process.env.PROXY_DENIED_TUNNEL_MAX, 32);
const DENIED_TUNNEL_IDLE_MS = parseIntWithDefault(process.env.PROXY_DENIED_TUNNEL_IDLE_MS, 5_000);
// Deliberately retained test-only observability: this flag exists solely so
// server-tunnels.test.ts can prove that a served denied-tunnel's port-state
// entry is removed on client close (the only observable evidence for that
// leak regression). It is never enabled in production and never affects
// denial behavior.
const DENIED_TUNNEL_DEBUG = process.env.PROXY_DENIED_TUNNEL_DEBUG === "1";
const SESSION_ADMISSION_WATCH_MS = 100;
// The exact readiness bytes from a served peer are answered locally with this,
// so the session entry in the agent image can tell its session file has landed
// without sending an ordinary request (activation-gate design D2). Forwards
// nothing.
const SESSION_ADMISSION_ACTIVE_BODY = "active";
const SESSION_ADMISSION_ACTIVE_RESPONSE = Buffer.from([
  "HTTP/1.1 200 OK",
  "Content-Type: text/plain",
  `Content-Length: ${Buffer.byteLength(SESSION_ADMISSION_ACTIVE_BODY, "latin1")}`,
  "Connection: close",
  "",
  SESSION_ADMISSION_ACTIVE_BODY,
].join("\r\n"), "latin1");
const SESSION_ADMISSION_PROVISIONING_REQUEST_BYTES = Buffer.from(SESSION_ADMISSION_PROVISIONING_REQUEST, "latin1");
// Refuses before any listener binds: source-ip-v1 is the only identity mode,
// and a proxy without complete session-identity configuration must not start.
const sessionIdentityConfig = assertSourceIpSessionIdentityConfig();
// Audit mode: the marker is host-written via root docker exec into a
// root-owned tmpfs dir this UID-1001 process can only read; the spool is the
// UID-1001 → root observation channel; the audit snapshot is the supervisor's
// dedicated resolved-host file for audited destinations.
const AUDIT_MARKER_PATH = auditMarkerPathFromEnv();
const AUDIT_SPOOL_PATH = auditSpoolPathFromEnv();
const AUDIT_RESOLVED_HOSTS_PATH = auditResolvedHostsPathFromEnv();
const AUDIT_MARKER_WATCH_MS = parseIntWithDefault(process.env.PROXY_AUDIT_WATCH_MS, 1_000);
const AUDIT_HEARTBEAT_MS = 5 * 60 * 1000;
const REQUEST_LOG_CONTEXT_TTL_MS = parseIntWithDefault(process.env.PROXY_REQUEST_LOG_CONTEXT_TTL_MS, 60 * 60 * 1000);
const REQUEST_LOG_VALUE_LIMIT = 256;
const REQUEST_LOG_METHOD_LIMIT = 16;
const IDENTITY_ACCEPT_ENCODING_HOSTS = new Set([
  "api.anthropic.com",
  "code.claude.com",
  "platform.claude.com",
  "statsig.anthropic.com",
]);

function parseIntWithDefault(value: string | undefined, fallback: number): number {
  const parsed = parseInt(value ?? "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

installResolvedHostLookup({
  path: resolvedHostsPathFromEnv(),
  auditPath: AUDIT_RESOLVED_HOSTS_PATH,
});

const effectiveProxyRoot = effectiveProxyRootFromEnv();
let currentEffectiveControl: LoadedEffectiveProxyControl | undefined = effectiveProxyRoot
  ? loadEffectiveProxyControl(effectiveProxyRoot)
  : undefined;
let currentPolicy = currentEffectiveControl?.networkPolicy ?? loadProxyPolicy();
let currentMcpOperationPolicy = loadMcpOperationPolicy();
let policyRevalidationCandidate: {
  policy: LoadedProxyPolicy;
  mcpOperationGeneration: string | undefined;
} | undefined;
const oauthMediator = new OAuthMediator({
  ...(currentEffectiveControl ? { pairedPolicy: currentEffectiveControl.oauthPolicy } : {}),
});
const admissionRegistry = new AdmissionRegistry();
const sessionSockets = new Map<string, Set<net.Socket>>();

function revokeSessionContexts(sessionKey: string): void {
  writeApprovals.revokeSession(sessionKey);
  admissionRegistry.revokeSession(sessionKey);
  const sockets = sessionSockets.get(sessionKey);
  sessionSockets.delete(sessionKey);
  for (const socket of sockets ?? []) socket.destroy();
}

function writeApprovalGeneration(): string {
  return `${currentPolicy.generation};mcp=${currentMcpOperationPolicy?.generation ?? "unavailable"}`;
}

// Approve-on-write: holds classified writes on `ask` hosts until a host-side
// decision arrives (root-owned decision files; see approvals.ts). Session
// state (grants, deny-all) lives only in this process.
const writeApprovals = createWriteApprovalManager({
  pendingDir: approvalsPendingDirFromEnv(),
  decisionsDir: approvalsDecisionsDirFromEnv(),
  holdSeconds: writeApprovalHoldSecondsFromEnv(),
  generation: writeApprovalGeneration,
  // Host-controlled (compose) like every proxy env var; only the test
  // harness sets it, so real runtimes keep the root-owner requirement.
  ...(process.env.RUNFREE_APPROVALS_DECISION_OWNER_UID !== undefined
    && /^\d{1,7}$/.test(process.env.RUNFREE_APPROVALS_DECISION_OWNER_UID)
    ? { decisionOwnerUid: Number(process.env.RUNFREE_APPROVALS_DECISION_OWNER_UID) }
    : {}),
  onStateChanged: () => publishWriteApprovalsStatus(),
});

const testSessionOwnerUid = process.env.RUNFREE_SESSION_REGISTRY_OWNER_UID !== undefined
  && /^\d{1,7}$/.test(process.env.RUNFREE_SESSION_REGISTRY_OWNER_UID)
  ? Number(process.env.RUNFREE_SESSION_REGISTRY_OWNER_UID)
  : undefined;
// Session files grant leases. Root-owned IP assignments constrain which
// session may hold each address while old authority is retired.
const sessionRegistry = new SessionFileRegistry({
  root: sessionIdentityConfig.registryRoot,
  projectId: sessionIdentityConfig.projectId,
  ...(testSessionOwnerUid !== undefined ? { ownerUid: testSessionOwnerUid } : {}),
  onSessionInvalidated: revokeSessionContexts,
});
const ipAssignments = new SessionIpAssignments(sessionIdentityConfig.registryRoot, testSessionOwnerUid);
const acceptedSocketsByIp = new Map<string, Set<net.Socket>>();
let sessionAdmissionWatchTimer: NodeJS.Timeout | undefined;
let lastSessionAdmissionWatchError: string | undefined;

function reconcileSessionAdmission(): void {
  try {
    // Retire authority and sockets before acknowledging a draining address.
    const assignments = ipAssignments.read();
    const blocked = assignments === undefined ? "all" as const : new Set(
      Array.from(assignments.values()).filter((entry) => entry.state === "draining").map((entry) => entry.sourceIp),
    );
    sessionRegistry.refresh(blocked, assignments);
    for (const [address, sockets] of acceptedSocketsByIp) {
      if (blocked !== "all" && !blocked.has(address)) continue;
      acceptedSocketsByIp.delete(address);
      for (const socket of sockets) socket.destroy();
    }
    for (const assignment of assignments?.values() ?? []) ipAssignments.acknowledge("request-proxy", assignment);
    lastSessionAdmissionWatchError = undefined;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    if (detail !== lastSessionAdmissionWatchError) {
      console.error(`proxy: session admission reconciliation failed: ${detail}`);
      lastSessionAdmissionWatchError = detail;
    }
  }
}

function ipv4PeerAddress(address: string | undefined): string | undefined {
  if (address === undefined) return undefined;
  if (isExactSessionSourceIpv4(address)) return address;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(address)?.[1];
  return mapped && isExactSessionSourceIpv4(mapped) ? mapped : undefined;
}

type GuardIdentity = Pick<AdmissionRecord, "sourceIp" | "principal" | "sessionBinding">;

function identityForPeer(address: string | undefined):
  | { kind: "accepted"; identity: GuardIdentity }
  | { kind: "rejected"; reason: string } {
  const result = sessionRegistry.lookup(ipv4PeerAddress(address));
  if (result.kind !== "active") return { kind: "rejected", reason: result.reason };
  return {
    kind: "accepted",
    identity: {
      sourceIp: result.file.sourceIp,
      principal: result.session,
      sessionBinding: {
        sessionKey: result.file.sessionKey,
        sessionIncarnation: result.file.sessionIncarnation,
        containerId: result.file.containerId,
        sourceIp: result.file.sourceIp,
        networkId: result.file.networkId,
        selectedAgentImageId: result.file.selectedAgentImageId,
        sessionAgentGenerationDigest: result.file.sessionAgentGenerationDigest,
        controlPlaneGenerationDigest: result.file.controlPlaneGenerationDigest,
        admissionContractEpoch: result.file.admissionContractEpoch,
      },
    },
  };
}

function currentAdmissionPrincipal(admission: AdmissionRecord): ApprovalRequestPrincipal | undefined {
  const current = sessionRegistry.lookup(admission.sourceIp);
  if (current.kind !== "active" || admission.principal?.kind !== "session" || !admission.sessionBinding) return undefined;
  const binding = admission.sessionBinding;
  // The registry lookup above proves that the session is currently served. The
  // CONNECT binding proves stable container identity; the file's rotating
  // nonce is deliberately not part of it.
  return sameProxySessionStableIdentity(current.file, binding)
    ? current.session
    : undefined;
}

function registerSessionSocket(identity: GuardIdentity, socket: net.Socket): void {
  const sessionKey = identity.sessionBinding?.sessionKey;
  if (!sessionKey) return;
  const sockets = sessionSockets.get(sessionKey) ?? new Set<net.Socket>();
  sockets.add(socket);
  sessionSockets.set(sessionKey, sockets);
  socket.once("close", () => {
    sockets.delete(socket);
    if (sockets.size === 0 && sessionSockets.get(sessionKey) === sockets) sessionSockets.delete(sessionKey);
  });
}

// Level-triggered approval-state snapshot for `runfree status` (grants are
// invisible authority otherwise). Observation only, never load-bearing.
function publishWriteApprovalsStatus(): void {
  try {
    const deny = writeApprovals.denyState();
    fs.writeFileSync(writeApprovalsStatusPath(), `${JSON.stringify({
      held: writeApprovals.heldCount(),
      denyId: deny.id,
      processEpoch: writeApprovals.processEpoch,
      grants: writeApprovals.grantSummaries(),
      updatedAt: new Date().toISOString(),
    })}\n`);
  } catch {
    // Status is a view; a write failure must never affect enforcement.
  }
}

// --- CA cert + key ---------------------------------------------------------
// First start: mockttp.generateCACertificate() creates a self-signed CA and we
// persist the key in proxy-only storage while publishing the cert separately.
// Subsequent starts load both files so the agent's trust store remains valid
// across proxy restarts.
fs.mkdirSync(path.dirname(CA_CERT), { recursive: true });
fs.mkdirSync(path.dirname(CA_KEY), { recursive: true });

let cert: string;
let key: string;
if (fs.existsSync(CA_CERT) && fs.existsSync(CA_KEY)) {
  cert = fs.readFileSync(CA_CERT, "utf8");
  key  = fs.readFileSync(CA_KEY,  "utf8");
} else {
  const ca = await generateProxyCA();
  cert = ca.cert;
  key  = ca.key;
  fs.writeFileSync(CA_CERT, cert, { mode: 0o644 });
  fs.writeFileSync(CA_KEY,  key,  { mode: 0o600 });
}
// Apply exact permissions on restart too, repairing material created under a
// restrictive umask. Only the public certificate is shared with the agent.
fs.chmodSync(CA_CERT, 0o644);
fs.chmodSync(CA_KEY, 0o600);

// --- Denied-tunnel TLS material ---------------------------------------------
// mockttp mints a CA-signed leaf per SNI hostname and caches it without bound,
// so denied CONNECTs must not reach mockttp's TLS layer: a unique-hostname
// denial loop would amplify proxy CPU and memory. mockttp exposes no way to
// pin a static certificate for unknown/denied SNI, so denied tunnels are
// terminated by a separate minimal TLS endpoint using one pre-generated
// `blocked.invalid` leaf signed by the Runfree CA at startup, reused for
// every denied hostname. No per-host key generation or certificate minting
// happens on the denial path.
await runMockttpAdapterSelfTest({ cert, key });
const blockedLeaf = await generateProxyLeaf({ cert, key }, "blocked.invalid");

// --- Proxy ----------------------------------------------------------------

// The adapter shuts mockttp's agent-writable Proxy-Authorization metadata
// channel before the server exists. Bounded logging keeps a hostile loop from
// growing proxy logs without limit.
let refusedProxyAuthMetadata = 0;
const server = await createMockttpAdapter({
  admissions: admissionRegistry,
  cert,
  key,
  missingAdmissionResponse,
  onMissingWebSocket: isMissingAdmissionWebSocket,
  onProxyAuthRefused: () => {
    refusedProxyAuthMetadata += 1;
    if (refusedProxyAuthMetadata <= PROXY_AUTH_METADATA_LOG_LIMIT) {
      console.log(`proxy: refused proxy-authorization metadata (count=${refusedProxyAuthMetadata})`);
    }
  },
  onSniObservation: (observation) => {
    if (observation.kind === "admitted") return;
    if (observation.kind === "host-mismatch") {
      emitDenial({
        reason: "connect-sni-mismatch",
        host: observation.record.host,
      });
      return;
    }
    emitDenial({
      reason: "missing-admission-record",
      host: "<unknown>",
    });
  },
});

function headerValue(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

function stripPort(host: string): string {
  return host.replace(/:\d+$/, "").toLowerCase();
}

function requestHost(req: ProxyRequest): string {
  const urlHost = hostFromUrl(req.url);
  if (urlHost) return urlHost;
  if (req.destination?.hostname) return req.destination.hostname.toLowerCase();
  const authority = headerValue(req.headers?.[":authority"]);
  if (authority) return stripPort(authority);
  const host = headerValue(req.headers?.host);
  if (host) return stripPort(host);
  return "<unparseable>";
}

type RequestLogContext = {
  id: string;
  method: string;
  scheme?: string;
  host: string;
  port?: number;
  path?: string;
  httpVersion?: string;
  startedAtMs: number;
  policyGeneration?: string;
  audit?: boolean;
  credential?: CredentialMutationSummary;
};

type ClientErrorLogEvent = {
  errorCode?: string;
  request: ProxyRequest & { id?: string };
  response?: "aborted" | { statusCode?: number };
};

const requestLogContexts = new Map<string, RequestLogContext>();

function boundedLogString(value: string | undefined, limit = REQUEST_LOG_VALUE_LIMIT): string | undefined {
  if (value === undefined) return undefined;
  return value.slice(0, limit);
}

function scheduleRequestContextCleanup(id: string): void {
  const timeout = setTimeout(() => requestLogContexts.delete(id), REQUEST_LOG_CONTEXT_TTL_MS);
  timeout.unref?.();
}

function isProxyVerboseEnabled(): boolean {
  try {
    return fs.readdirSync(PROXY_VERBOSE_MARKER_DIR).length > 0;
  } catch {
    return false;
  }
}

function requestId(req: unknown): string | undefined {
  const id = (req as { id?: unknown }).id;
  return typeof id === "string" && id !== "" ? id : undefined;
}

function requestHttpVersion(req: unknown): string | undefined {
  const httpVersion = (req as { httpVersion?: unknown }).httpVersion;
  return typeof httpVersion === "string" && httpVersion !== "" ? httpVersion : undefined;
}

function requestStartedAtMs(req: unknown): number {
  const startTime = (req as { timingEvents?: { startTime?: unknown } }).timingEvents?.startTime;
  return typeof startTime === "number" && Number.isFinite(startTime) ? startTime : Date.now();
}

function requestParts(req: ProxyRequest): Pick<RequestLogContext, "scheme" | "host" | "port" | "path"> {
  try {
    const url = new URL(req.url);
    const port = url.port === "" ? (url.protocol === "https:" || url.protocol === "wss:" ? 443 : undefined) : Number(url.port);
    return {
      scheme: url.protocol.replace(/:$/, ""),
      host: url.hostname.toLowerCase(),
      ...(Number.isFinite(port) ? { port } : {}),
      path: safePathname(req.url),
    };
  } catch {
    return {
      host: requestHost(req),
      path: safePathname(req.url),
    };
  }
}

function contextFromRequest(req: ProxyRequest): RequestLogContext | undefined {
  const id = requestId(req);
  if (!id) return undefined;
  const parts = requestParts(req);
  return {
    id,
    method: boundedLogString(req.method ?? "<unknown>", REQUEST_LOG_METHOD_LIMIT) ?? "<unknown>",
    ...parts,
    httpVersion: requestHttpVersion(req),
    startedAtMs: requestStartedAtMs(req),
  };
}

function requestContext(req: ProxyRequest): RequestLogContext | undefined {
  const id = requestId(req);
  if (!id) return undefined;
  const existing = requestLogContexts.get(id);
  if (existing) return existing;
  const next = contextFromRequest(req);
  if (next) requestLogContexts.set(id, next);
  return next;
}

function updateRequestContext(
  req: ProxyRequest,
  updates: Partial<Omit<RequestLogContext, "id" | "startedAtMs">>,
): RequestLogContext | undefined {
  const existing = requestContext(req);
  if (!existing) return undefined;
  const next = { ...existing, ...updates };
  requestLogContexts.set(existing.id, next);
  return next;
}

function compactEvent(input: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(input).filter(([, value]) => {
    return value !== undefined && !(Array.isArray(value) && value.length === 0);
  }));
}

function durationMs(context: RequestLogContext): number {
  return Math.max(0, Math.round(Date.now() - context.startedAtMs));
}

function logProxyRequestEvent(
  event: string,
  context: RequestLogContext,
  fields: Record<string, unknown> = {},
  options: { verboseOnly?: boolean } = {},
): void {
  if (options.verboseOnly !== false && !isProxyVerboseEnabled()) return;
  const payload = compactEvent({
    v: 1,
    ts: new Date().toISOString(),
    event,
    id: context.id,
    method: context.method,
    scheme: context.scheme,
    host: context.host,
    port: context.port,
    path: context.path,
    http_version: context.httpVersion,
    policy_generation: context.policyGeneration,
    audit: context.audit,
    duration_ms: event === "admitted" ? undefined : durationMs(context),
    ...fields,
  });
  console.log(`proxy-request: ${JSON.stringify(payload)}`);
}

function firstHeader(headers: Record<string, unknown> | undefined, names: readonly string[]): string | undefined {
  if (!headers) return undefined;
  for (const [key, value] of Object.entries(headers)) {
    if (!names.includes(key.toLowerCase())) continue;
    if (Array.isArray(value)) return typeof value[0] === "string" ? boundedLogString(value[0]) : undefined;
    if (typeof value === "string") return boundedLogString(value);
  }
  return undefined;
}

function policySummary(policy: LoadedProxyPolicy): string {
  const hosts = policy.allowedHosts.join(", ");
  const credentialHosts = Object.keys(policy.credentials).join(", ");
  const tokenNames = Object.keys(policy.tokens).join(", ");
  const requestRuleHosts = Object.keys(policy.requests).join(", ");
  return `generation=${policy.generation}, allowed_hosts=[${hosts}], credential_hosts=[${credentialHosts}], tokens=[${tokenNames}], request_rule_hosts=[${requestRuleHosts}]`;
}

function mcpOperationPolicyPath(): string | undefined {
  return process.env.RUNFREE_MCP_OPERATION_POLICY_PATH;
}

function loadMcpOperationPolicy(): LoadedMcpOperationPolicy | undefined {
  const policyPath = mcpOperationPolicyPath();
  if (!policyPath) return undefined;
  try {
    const raw = JSON.parse(fs.readFileSync(policyPath, "utf8")) as unknown;
    return validateMcpOperationPolicy(raw, policyPath);
  } catch (error) {
    console.error(`runfree: mcp operation policy unavailable; HTTP MCP tool calls will require write approval (${error instanceof Error ? error.message : String(error)})`);
    return undefined;
  }
}

// Level-triggered generation status for the host CLI's convergence ack and
// readiness wait. Written after the initial listen and after every successful
// policy reload; an invalid reload keeps the last valid policy AND the last
// valid status (the CLI must not observe a generation this process is not
// enforcing). Best-effort: the status file is an observation channel, never
// load-bearing for whether policy applies. The `proxy: policy reloaded` /
// `proxy: listening on` log lines are human diagnostics only.
function publishRequestProxyStatus(): void {
  try {
    writeGenerationStatusFile(requestProxyStatusPath(), {
      generation: currentPolicy.generation,
      ...(currentEffectiveControl ? {
        controlGeneration: currentEffectiveControl.active.controlGeneration,
        policyGeneration: currentPolicy.generation,
      } : { generation: currentPolicy.generation }),
      appliedAt: new Date().toISOString(),
    });
  } catch (error) {
    console.error(`proxy: failed to publish generation status: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function reloadPolicy(): void {
  try {
    const previous = currentPolicy;
    const nextEffectiveControl = effectiveProxyRoot
      ? loadEffectiveProxyControl(effectiveProxyRoot)
      : undefined;
    const nextPolicy = nextEffectiveControl?.networkPolicy ?? loadProxyPolicy();
    const nextMcpOperationPolicy = loadMcpOperationPolicy();
    if (nextPolicy.generation === previous.generation
      && nextMcpOperationPolicy?.generation === currentMcpOperationPolicy?.generation
      && nextEffectiveControl?.active.controlGeneration === currentEffectiveControl?.active.controlGeneration) {
      return;
    }
    // Restart-free convergence means policy now changes under a live process
    // with holds and grants in flight: drop grants for touched hosts and
    // cancel holds that no longer revalidate, before anything else observes
    // the new generation. Invalid reloads keep prior policy AND prior grants.
    //
    // The MCP operation policy's generation is deliberately not mixed into this
    // snapshot. `ruleChanged` compares field values, so widening the previous
    // snapshot on an MCP-generation change could only drop grants by making the
    // write posture look different than it is — and the two grant families that
    // depend on MCP policy are already handled correctly without it: positive
    // MCP grants are dropped wholesale on every reload, and negative (deny)
    // grants are an explicit operator decision that must only be dropped when
    // the host's own rules changed, since dropping a deny is a fail-open step.
    // Holds must revalidate against the candidate being activated, not the
    // still-live globals. Keep the candidate scoped to this synchronous state
    // transition so requests cannot observe it before activation succeeds.
    policyRevalidationCandidate = {
      policy: nextPolicy,
      mcpOperationGeneration: nextMcpOperationPolicy?.generation,
    };
    try {
      writeApprovals.onPolicyChanged(previous, nextPolicy);
    } finally {
      policyRevalidationCandidate = undefined;
    }
    if (nextEffectiveControl) oauthMediator.activatePairedPolicy(nextEffectiveControl.oauthPolicy);
    currentPolicy = nextPolicy;
    currentEffectiveControl = nextEffectiveControl;
    currentMcpOperationPolicy = nextMcpOperationPolicy;
    console.log(`proxy: policy reloaded, ${policySummary(currentPolicy)}, mcp_operation_generation=${currentMcpOperationPolicy?.generation ?? "unavailable"}`);
    publishRequestProxyStatus();
  } catch (error) {
    console.error(`proxy: policy reload failed; keeping last valid policy previous_generation=${currentPolicy.generation}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

const selectedPolicyPath = effectiveProxyRoot ? path.join(effectiveProxyRoot, "active.json") : currentPolicy.policyPath;
const currentMcpPolicyPath = mcpOperationPolicyPath();

type WatchedFileRevision = {
  exists: boolean;
  ctimeMs?: number;
  ino?: number;
  mtimeMs?: number;
  size?: number;
};

function watchedFileRevision(filePath: string): WatchedFileRevision {
  try {
    const stat = fs.statSync(filePath);
    return {
      exists: true,
      ctimeMs: stat.ctimeMs,
      ino: stat.ino,
      mtimeMs: stat.mtimeMs,
      size: stat.size,
    };
  } catch {
    return { exists: false };
  }
}

function sameWatchedFileRevision(left: WatchedFileRevision, right: WatchedFileRevision): boolean {
  return left.exists === right.exists
    && left.ctimeMs === right.ctimeMs
    && left.ino === right.ino
    && left.mtimeMs === right.mtimeMs
    && left.size === right.size;
}

const watchedPolicyPaths = [selectedPolicyPath, currentMcpPolicyPath].filter((value): value is string => value !== undefined);
let watchedPolicyRevisions = watchedPolicyPaths.map(watchedFileRevision);
let policyWatchNeedsInitialReconciliation = true;
const policyWatchTimer = setInterval(() => {
  const nextRevisions = watchedPolicyPaths.map(watchedFileRevision);
  const changed = nextRevisions.some((revision, index) => !sameWatchedFileRevision(revision, watchedPolicyRevisions[index]));
  watchedPolicyRevisions = nextRevisions;
  // fs.watchFile establishes its baseline asynchronously, which lets an
  // atomic activation immediately after readiness become the unseen baseline.
  // A synchronous baseline plus one initial reconciliation closes that window.
  if (policyWatchNeedsInitialReconciliation || changed) {
    policyWatchNeedsInitialReconciliation = false;
    reloadPolicy();
  }
}, Number.isFinite(POLICY_WATCH_INTERVAL_MS) && POLICY_WATCH_INTERVAL_MS > 0 ? POLICY_WATCH_INTERVAL_MS : 1000);
policyWatchTimer.unref();

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    clearInterval(policyWatchTimer);
    if (sessionAdmissionWatchTimer) clearInterval(sessionAdmissionWatchTimer);
    process.kill(process.pid, signal);
  });
}

// Structured denial events (`proxy-denial: {...}` lines) are the single
// denial log format: doctor and the session-end summary parse them, and every
// emission is rate-bounded per (host, reason).
const denialEvents = createDenialEventEmitter();

function emitDenial(input: {
  reason: DenialReason;
  host: string;
  method?: string;
  path?: string;
  mcp?: McpDisplayFields;
}): void {
  const oauthIssuer = oauthMediator.issuerDenialContext(input.host);
  denialEvents.emit({
    reason: input.reason,
    host: input.host,
    method: input.method,
    path: input.path,
    ...(input.mcp !== undefined ? { mcp: input.mcp } : {}),
    ...(oauthIssuer !== undefined ? { mcpOAuthIssuer: { serverName: oauthIssuer.providerId, resourceHost: oauthIssuer.resourceHost } } : {}),
    generation: currentPolicy.generation,
  });
}

function ruleEventParts(event: unknown): {
  requestId?: string;
  eventType?: string;
  eventData?: Record<string, unknown>;
} {
  if (!event || typeof event !== "object") return {};
  const record = event as { requestId?: unknown; eventType?: unknown; eventData?: unknown };
  return {
    requestId: typeof record.requestId === "string" ? record.requestId : undefined,
    eventType: typeof record.eventType === "string" ? record.eventType : undefined,
    eventData: record.eventData && typeof record.eventData === "object" && !Array.isArray(record.eventData)
      ? record.eventData as Record<string, unknown>
      : undefined,
  };
}

function eventDataString(data: Record<string, unknown> | undefined, key: string): string | undefined {
  const value = data?.[key];
  return typeof value === "string" && value !== "" ? boundedLogString(value) : undefined;
}

function eventDataNumber(data: Record<string, unknown> | undefined, key: string): number | undefined {
  const value = data?.[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function errorRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function handleRuleEvent(event: unknown): void {
  const { requestId: id, eventType, eventData } = ruleEventParts(event);
  if (!id || !eventType) return;
  const context = requestLogContexts.get(id);
  if (!context) return;

  if (eventType === "passthrough-request-head") {
    logProxyRequestEvent("upstream_request", context, {
      upstream_scheme: eventDataString(eventData, "protocol"),
      upstream_host: eventDataString(eventData, "hostname"),
      upstream_port: eventDataNumber(eventData, "port"),
      upstream_path: safePathname(eventDataString(eventData, "path")),
    });
    return;
  }

  if (eventType === "passthrough-abort") {
    const error = errorRecord(eventData?.error);
    logProxyRequestEvent("passthrough_abort", context, {
      side: eventData?.downstreamAborted === true ? "downstream" : "upstream",
      error_name: typeof error?.name === "string" ? boundedLogString(error.name) : undefined,
      error_code: typeof error?.code === "string" ? boundedLogString(error.code) : undefined,
      error_message: typeof error?.message === "string" ? boundedLogString(error.message) : undefined,
      tags: Array.isArray(eventData?.tags)
        ? eventData.tags
          .filter((tag): tag is string => typeof tag === "string")
          .map((tag) => boundedLogString(tag))
          .filter((tag): tag is string => tag !== undefined)
        : undefined,
    }, { verboseOnly: false });
  }
}

await server.on("request-initiated", (req: ProxyRequest) => {
  const context = contextFromRequest(req);
  if (context) {
    requestLogContexts.set(context.id, context);
    scheduleRequestContextCleanup(context.id);
  }
});

await server.on("response-initiated", (res: {
  id: string;
  statusCode: number;
  headers?: Record<string, unknown>;
}) => {
  const context = requestLogContexts.get(res.id);
  if (!context) return;
  logProxyRequestEvent("response_head", context, {
    status: res.statusCode,
    request_id_header: firstHeader(res.headers, ["anthropic-request-id", "request-id", "x-request-id"]),
    retry_after: firstHeader(res.headers, ["retry-after"]),
  });
  scheduleRequestContextCleanup(context.id);
});

await server.on("abort", (req: ProxyRequest & {
  error?: { name?: string; code?: string; message?: string };
}) => {
  // A client that gives up mid-hold abandons the hold: the pending approval
  // expires so a late decision never forwards to a dead socket.
  const abortedId = requestId(req);
  if (abortedId !== undefined) writeApprovals.cancelForRequest(abortedId);
  const context = requestContext(req);
  if (!context) return;
  logProxyRequestEvent("abort", context, {
    side: "downstream",
    error_name: boundedLogString(req.error?.name),
    error_code: boundedLogString(req.error?.code),
    error_message: boundedLogString(req.error?.message),
  }, { verboseOnly: false });
  requestLogContexts.delete(context.id);
});

await server.on("client-error", (error: ClientErrorLogEvent) => {
  const context = requestContext(error.request);
  if (!context) return;
  logProxyRequestEvent("client_error", context, {
    error_code: error.errorCode,
    status: typeof error.response === "object" ? error.response.statusCode : undefined,
    response: error.response === "aborted" ? "aborted" : undefined,
  }, { verboseOnly: false });
  requestLogContexts.delete(context.id);
});

await server.on("rule-event", handleRuleEvent);

// --- Audit mode ---------------------------------------------------------------
// While a valid unexpired marker is active, non-allowlisted port-443 HTTPS is
// permitted and observed instead of denied. Everything else stays enforced:
// HTTPS-only, 443-only, resolved-IP classification (in the supervisor), no
// token reads for audited hosts, and stripped credential headers.

const auditEvents = createAuditEventEmitter();
const auditSpool = createAuditSpoolWriter({ path: AUDIT_SPOOL_PATH });
const auditTunnelSockets = new Set<net.Socket>();

function auditMarkerState(): AuditMarkerState {
  return readAuditMarkerState(AUDIT_MARKER_PATH, Date.now());
}

function observeAuditedHost(host: string, request?: { method?: string; path?: string }): void {
  auditSpool.record(host);
  auditEvents.emit({
    host,
    ...(request?.method !== undefined ? { method: request.method } : {}),
    ...(request?.path !== undefined ? { path: request.path } : {}),
    generation: currentPolicy.generation,
  });
}

function registerAuditTunnel(socket: net.Socket): void {
  auditTunnelSockets.add(socket);
  socket.once("close", () => auditTunnelSockets.delete(socket));
}

// Fast-cadence marker watch. On the active → inactive transition every
// registered guard-side tunnel socket is destroyed, independent of any new
// request: an established CONNECT tunnel never re-enters the request hook, so
// a per-request marker check would never fire for it. This close is resource
// cleanup and agent-visible failure only — the firewall drain-drop, not this
// close, is the severance guarantee for the data-bearing upstream flow (the
// upstream socket is created and owned inside mockttp). While active, a
// heartbeat line keeps the mode unmissable in proxy logs.
let auditWasActive = false;
let auditLastHeartbeatMs = 0;

function auditMarkerWatchTick(nowMs = Date.now()): void {
  const state = readAuditMarkerState(AUDIT_MARKER_PATH, nowMs);
  if (state.active) {
    if (!auditWasActive || nowMs - auditLastHeartbeatMs >= AUDIT_HEARTBEAT_MS) {
      auditLastHeartbeatMs = nowMs;
      const minutesLeft = Math.max(1, Math.ceil((state.effectiveExpiryMs - nowMs) / 60_000));
      console.log(`proxy-audit: network audit mode ACTIVE; non-allowlisted HTTPS hosts are permitted and logged; expires in ${minutesLeft}m`);
    }
    auditWasActive = true;
    return;
  }
  if (auditWasActive) {
    console.log(`proxy-audit: network audit mode ended; destroying ${auditTunnelSockets.size} audited tunnel socket(s)`);
    for (const socket of Array.from(auditTunnelSockets)) {
      socket.destroy();
    }
    auditTunnelSockets.clear();
    // A later audit session must re-observe hosts: the supervisor truncates
    // the spool at teardown, so the writer's dedupe state resets with it.
    auditSpool.reset();
    auditLastHeartbeatMs = 0;
  }
  auditWasActive = false;
}

setInterval(() => auditMarkerWatchTick(), AUDIT_MARKER_WATCH_MS);

// Strips the union of every configured credential header name across every
// token policy. `credentials[host]` is empty for an audited host, so the
// per-host strip would forward a configured header the agent happened to
// send; the union strip guarantees no configured credential header reaches an
// audited host. The OAuth bearer handle survives so handle mediation can
// fail it exactly as in enforce mode.
function stripUnionConfiguredCredentialHeadersExceptOAuthHandle(
  headers: Record<string, string | string[] | undefined> | undefined,
): Record<string, string | string[] | undefined> | undefined {
  const configuredHeaders = configuredCredentialHeaderNames(currentPolicy.credentials);
  if (configuredHeaders.size === 0) return undefined;
  const next = { ...(headers ?? {}) };
  let changed = false;
  for (const key of Object.keys(next)) {
    const lower = key.toLowerCase();
    if (!configuredHeaders.has(lower)) continue;
    if (lower === "authorization" && hasOAuthAuthorizationHandle({ [key]: next[key] })) continue;
    delete next[key];
    changed = true;
  }
  return changed ? next : undefined;
}

function stripUntrustedRunfreeIdentityHeaders(
  headers: Record<string, string | string[] | undefined> | undefined,
): Record<string, string | string[] | undefined> | undefined {
  const next = { ...(headers ?? {}) };
  let changed = false;
  for (const key of Object.keys(next)) {
    const lower = key.toLowerCase();
    if (lower === "proxy-authorization" || lower.startsWith("x-runfree-session")) {
      delete next[key];
      changed = true;
    }
  }
  return changed ? next : undefined;
}

// Repeated header lines surface as arrays; scan every value so a second
// Accept line carrying text/event-stream is not missed.
function requestAcceptsEventStream(headers: Record<string, string | string[] | undefined> | undefined): boolean {
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (key.toLowerCase() !== "accept") continue;
    const values = Array.isArray(value) ? value : [value];
    if (values.some((entry) => typeof entry === "string" && entry.toLowerCase().includes("text/event-stream"))) {
      return true;
    }
  }
  return false;
}

function shouldForceIdentityAcceptEncoding(
  host: string,
  url: URL | undefined,
  headers: Record<string, string | string[] | undefined> | undefined,
): boolean {
  if (!IDENTITY_ACCEPT_ENCODING_HOSTS.has(host)) return false;
  if (requestAcceptsEventStream(headers)) return true;
  return host === "api.anthropic.com" && url?.pathname === "/v1/messages";
}

// Avoid compressed upstream bodies only for Claude Code streaming-shaped
// requests through the intercepting proxy. Its native fetch path can surface
// zlib errors when proxy-mediated response compression/framing is not exactly
// what it expects.
function forceIdentityAcceptEncoding(
  host: string,
  url: URL | undefined,
  headers: Record<string, string | string[] | undefined> | undefined,
): Record<string, string | string[] | undefined> | undefined {
  if (!shouldForceIdentityAcceptEncoding(host, url, headers)) return undefined;
  return setHeader({ ...(headers ?? {}) }, "accept-encoding", "identity");
}

// Audited request path inside mockttp: no denial, no token file reads, no
// credential injection. HTTPS-only still holds, the host is re-validated, and
// OAuth handle mediation runs unchanged.
async function auditedRequestMutation(admission: AdmissionRecord, req: ProxyRequest): Promise<OAuthRequestResult> {
  const { url, host } = assertRequestMatchesAdmission(
    admission,
    req,
    "https:",
    "HTTPS",
    currentPolicy.allowedHosts,
  );
  observeAuditedHost(host, { method: req.method ?? "GET", path: req.url });
  const identityStrippedHeaders = stripUntrustedRunfreeIdentityHeaders(req.headers);
  const strippedHeaders = stripUnionConfiguredCredentialHeadersExceptOAuthHandle(identityStrippedHeaders ?? req.headers);
  const encodedHeaders = forceIdentityAcceptEncoding(host, url, strippedHeaders ?? identityStrippedHeaders ?? req.headers);
  const headers = encodedHeaders ?? strippedHeaders ?? identityStrippedHeaders;
  const nextReq = {
    ...req,
    headers: headers ?? req.headers,
  };
  const oauthMutation = await oauthMediator.beforeRequest(nextReq);
  return combineRequestMutations(headers ? { headers } : {}, oauthMutation);
}

// WebSocket upgrades to audited hosts are observed under the same rules:
// WSS-only, re-validated hostname, valid marker.
function auditedWebSocketHost(req: ProxyRequest): string | undefined {
  if (!auditMarkerState().active) return undefined;
  let url: URL | undefined;
  try {
    url = new URL(req.url);
  } catch {
    return undefined;
  }
  if (url.protocol !== "wss:") return undefined;
  try {
    return normalizeHostname(url.hostname.toLowerCase());
  } catch {
    return undefined;
  }
}

function blockedBody(host: string, reason: string): string {
  return `blocked by agent proxy policy\nreason: ${reason}\nhost: ${host}\n`;
}

// Defensive catch-all for a policy denial no earlier arm classified. The
// event rides the same per-(host, reason) rate bound as every other denial;
// the body keeps the original error message verbatim for the agent.
function blockedResponse(host: string, reason: string) {
  emitDenial({ reason: "policy-denied", host });
  return {
    response: {
      statusCode: 403,
      headers: { "content-type": "text/plain" },
      body: blockedBody(host, reason),
    },
  };
}

function syntheticDenialResponseFields(
  host: string,
  reason: DenialReason,
  details?: ShapeDenialBodyDetails,
  statusCode = 403,
): {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
} {
  const body = syntheticDenialBody(host, reason, details);
  return {
    statusCode,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "x-runfree-blocked": reason,
    },
    body,
  };
}

function missingAdmissionResponse(req: ProxyRequest) {
  const host = requestHost(req);
  emitDenial({
    reason: "missing-admission-record",
    host,
    method: req.method ?? "<unknown>",
    path: req.url,
  });
  const response = syntheticDenialResponseFields(host, "missing-admission-record");
  return { response: { ...response, headers: { ...response.headers, connection: "close" } } };
}

function admissionHostMismatchResponse(req: ProxyRequest, error: ProxyAdmissionHostMismatchError) {
  emitDenial({
    reason: "connect-host-mismatch",
    host: error.claimedHost,
    method: req.method ?? "<unknown>",
    path: req.url,
  });
  return {
    response: syntheticDenialResponseFields(
      error.claimedHost,
      "connect-host-mismatch",
      undefined,
      error.statusCode,
    ),
  };
}

// Local short-circuit for allowlist denials inside mockttp's beforeRequest:
// returning a response here prevents any upstream socket or DNS side effect.
function syntheticBlockedHostResponse(req: ProxyRequest, reason: DenialReason) {
  const host = requestHost(req);
  emitDenial({
    reason,
    host,
    method: req.method ?? "<unknown>",
    path: req.url,
  });
  return { response: syntheticDenialResponseFields(host, reason) };
}

// Request-shape denials short-circuit the same way: the shape check runs
// before credential reads and MCP OAuth mediation, so a denied request has no
// token, DNS, or upstream side effect.
function syntheticShapeDenialResponse(req: ProxyRequest, shape: ShapeDenialDetails) {
  const host = requestHost(req);
  emitDenial({
    reason: shape.reason,
    host,
    method: shape.method,
    path: req.url,
    mcp: shape.mcp,
  });
  return {
    response: syntheticDenialResponseFields(host, shape.reason, {
      method: shape.method,
      path: shape.path,
      allowedMethods: shape.allowedMethods,
      allowedPathPrefixes: shape.allowedPathPrefixes,
      rule: shape.rule,
    }),
  };
}

function isAllowlistDenialMessage(message: string): boolean {
  return message.startsWith("blocked outbound host:");
}

function isNonHttpsUrlMessage(message: string): boolean {
  return message.startsWith("blocked non-HTTPS outbound URL");
}

function isNonWssUrlMessage(message: string): boolean {
  return message.startsWith("blocked non-WSS outbound URL");
}

function isMissingTokenMessage(message: string): boolean {
  return message.startsWith("missing required proxy token");
}

// Maps the remaining policy-denial error classes to a structured denial
// reason so every denial rides the per-(host, reason) rate bound and is
// visible to doctor/session-summary. Returns undefined for allowlist and
// shape denials, which already emit their own events upstream; anything else
// falls through to the `policy-denied` catch-all in blockedResponse.
function residualDenialReason(message: string): DenialReason | undefined {
  if (isNonHttpsUrlMessage(message)) return "non-https-url";
  if (isNonWssUrlMessage(message)) return "non-wss-url";
  if (isMissingTokenMessage(message)) return "missing-required-token";
  return undefined;
}

function isPolicyDenial(error: unknown): error is Error {
  return error instanceof ProxyAdmissionHostMismatchError
    || error instanceof ProxyPolicyDenialError
    || (error instanceof Error && error.message.startsWith("blocked "));
}

function rawBlockedResponse(host: string, reason: string): string {
  const body = blockedBody(host, reason);
  return [
    "HTTP/1.1 403 Forbidden",
    "content-type: text/plain",
    `content-length: ${Buffer.byteLength(body)}`,
    "connection: close",
    "",
    body,
  ].join("\r\n");
}

function logAllowedRequest(req: ProxyRequest, input: {
  audit?: boolean;
  credential?: CredentialMutationSummary;
} = {}): void {
  const url = new URL(req.url);
  const method = req.method ?? "<unknown>";
  const context = updateRequestContext(req, {
    ...requestParts(req),
    method: boundedLogString(method, REQUEST_LOG_METHOD_LIMIT) ?? "<unknown>",
    httpVersion: requestHttpVersion(req),
    policyGeneration: currentPolicy.generation,
    audit: input.audit ?? false,
    credential: input.credential ?? { action: "none", headers: [], tokenNames: [] },
  });
  if (!isProxyVerboseEnabled()) return;
  console.log(`proxy: allowed method=${method} scheme=${url.protocol.replace(/:$/, "")} host=${url.hostname} path=${url.pathname}`);
  if (!context) return;
  logProxyRequestEvent("admitted", context, {
    credential_action: context.credential?.action ?? "none",
    credential_headers: context.credential?.headers,
    token_names: context.credential?.tokenNames,
  }, { verboseOnly: false });
}

function isMissingAdmissionWebSocket(req: ProxyRequest): void {
  const host = requestHost(req);
  emitDenial({
    reason: "missing-admission-record",
    host,
    method: req.method ?? "GET",
    path: req.url,
  });
}

function isAllowedWebSocket(admission: AdmissionRecord, req: ProxyRequest): boolean {
  const principal = currentAdmissionPrincipal(admission);
  if (principal === undefined) {
    emitDenial({
      reason: "unregistered-session-peer",
      host: requestHost(req),
      method: req.method ?? "GET",
      path: req.url,
    });
    return false;
  }
  try {
    assertAllowedWebSocketRequest(admission, req, {
      allowedHosts: currentPolicy.allowedHosts,
      requests: currentPolicy.requests,
      writeApproval: currentPolicy.writeApproval,
      hasWriteGrant: (details) => writeApprovals.hasGrant(details, principal, requestId(req)),
    });
    logAllowedRequest(req);
    return true;
  } catch (error) {
    if (!isPolicyDenial(error)) {
      throw error;
    }
    if (error instanceof ProxyPolicyDenialError && error.shape?.reason === "write-approval-required") {
      // mockttp exposes no per-upgrade hold, so WebSocket approve-on-write is
      // deny-then-approve-retry: the upgrade fails once, a pending approval
      // appears, and an approved grant lets the reconnect pass above.
      const shape = error.shape;
      writeApprovals.notePendingRetryApproval({
        host: shape.host,
        method: shape.method,
        path: shape.path,
        category: shape.writeCategory ?? "websocket",
        tokenNames: (currentPolicy.credentials[shape.host] ?? []).map((mapping) => mapping.tokenName),
        ...(principal !== undefined ? { principal } : {}),
        revalidate: () => {
          const currentAdmission = server.revalidateAdmission(admission, req);
          return currentAdmission !== undefined && evaluateRequestWriteAsk(currentAdmission, req, {
            allowedHosts: currentPolicy.allowedHosts,
            requests: currentPolicy.requests,
            writeApproval: currentPolicy.writeApproval,
          }, { webSocket: true }) !== "denied";
        },
      });
    }
    if (isAllowlistDenialMessage(error.message)) {
      const auditedHost = auditedWebSocketHost(req);
      if (auditedHost !== undefined) {
        observeAuditedHost(auditedHost, { method: req.method ?? "GET", path: req.url });
        return true;
      }
    }
    if (error instanceof ProxyAdmissionHostMismatchError) {
      emitDenial({
        reason: "connect-host-mismatch",
        host: error.claimedHost,
        method: req.method ?? "GET",
        path: req.url,
      });
    } else if (error instanceof ProxyPolicyDenialError && error.shape) {
      // WebSocket upgrades evaluate as GET against the same shape rules.
      emitDenial({
        reason: error.shape.reason,
        host: requestHost(req),
        method: error.shape.method,
        path: req.url,
      });
    } else if (isAllowlistDenialMessage(error.message)) {
      emitDenial({
        reason: "websocket-host-not-allowlisted",
        host: requestHost(req),
        method: req.method ?? "GET",
        path: req.url,
      });
    } else {
      // Remaining websocket denials (notably non-WSS upgrades to an allowed
      // host) ride the structured emitter so they share the per-(host, reason)
      // rate bound and doctor/summary visibility instead of unbounded logging.
      const reason = residualDenialReason(error.message);
      emitDenial({
        reason: reason ?? "websocket-host-not-allowlisted",
        host: requestHost(req),
        method: req.method ?? "GET",
        path: req.url,
      });
    }
    return false;
  }
}

function webSocketAdmissionMismatchStatus(admission: AdmissionRecord, req: ProxyRequest): 403 | 421 | undefined {
  try {
    assertRequestMatchesAdmission(admission, req, "wss:", "WSS", currentPolicy.allowedHosts);
    return undefined;
  } catch (error) {
    if (error instanceof ProxyAdmissionHostMismatchError) return error.statusCode;
    if (isPolicyDenial(error)) return undefined;
    throw error;
  }
}

// Classifies a denied WebSocket upgrade without emitting events so the
// per-reason rejection rules below can attach the right x-runfree-blocked
// header. Event emission happens once, in isAllowedWebSocket above.
function webSocketShapeDenialReason(admission: AdmissionRecord, req: ProxyRequest): ShapeDenialReason | undefined {
  if (currentAdmissionPrincipal(admission) === undefined) return undefined;
  try {
    assertAllowedWebSocketRequest(admission, req, {
      allowedHosts: currentPolicy.allowedHosts,
      requests: currentPolicy.requests,
      writeApproval: currentPolicy.writeApproval,
    });
    return undefined;
  } catch (error) {
    if (error instanceof ProxyPolicyDenialError && error.shape) return error.shape.reason;
    if (isPolicyDenial(error)) return undefined;
    throw error;
  }
}

function combineRequestMutations(
  first: { headers?: Record<string, string | string[] | undefined> },
  second: OAuthRequestResult | undefined,
): OAuthRequestResult {
  if (!second) return first;
  if (second.response) return second;
  return {
    ...first,
    ...second,
    headers: second.headers ?? first.headers,
  };
}

// Body-aware GraphQL classification (the only body parsing in the proxy):
// consulted only for non-safe-method requests to a host's declared graphql
// endpoints when the host's write posture is ask/deny. Reads and allow-hosts
// never reach this, and the classifier fails closed to "write" on anything
// unproven (oversize, compressed, batched, persisted-query, unparseable).
async function graphqlBodyClassForRequest(req: ProxyRequest): Promise<"read" | "write" | undefined> {
  let url: URL;
  try {
    url = new URL(req.url);
  } catch {
    return undefined;
  }
  const host = url.hostname.toLowerCase();
  const rule = currentPolicy.requests[host];
  if (rule?.graphql === undefined) return undefined;
  const writeAction = rule.writeAction ?? currentPolicy.writeApproval ?? DEFAULT_WRITE_ACTION;
  if (writeAction === "allow") return undefined;
  const method = req.method ?? "GET";
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return undefined;
  if (!rule.graphql.endpoints.includes(url.pathname || "/")) return undefined;
  const contentLengthRaw = firstHeader(req.headers, ["content-length"]);
  const contentLength = contentLengthRaw !== undefined && /^\d{1,12}$/.test(contentLengthRaw)
    ? Number(contentLengthRaw)
    : undefined;
  let bodyText: string | undefined;
  if (contentLength === undefined || contentLength <= GRAPHQL_BODY_CAP_BYTES) {
    try {
      bodyText = await req.body?.getText();
    } catch {
      bodyText = undefined;
    }
  }
  return classifyGraphqlRequestBody({
    contentType: firstHeader(req.headers, ["content-type"])?.toLowerCase(),
    contentEncoding: firstHeader(req.headers, ["content-encoding"])?.toLowerCase(),
    contentLength,
    bodyText,
  });
}

async function mcpClassificationForRequest(req: ProxyRequest): Promise<McpClassification | undefined> {
  if (!currentMcpOperationPolicy) return undefined;
  let url: URL;
  try {
    url = new URL(req.url);
  } catch {
    return undefined;
  }
  const method = req.method ?? "GET";
  if (method !== "POST" && method !== "DELETE") return undefined;
  const contentLengthRaw = firstHeader(req.headers, ["content-length"]);
  const contentLength = contentLengthRaw !== undefined && /^\d{1,12}$/.test(contentLengthRaw)
    ? Number(contentLengthRaw)
    : undefined;
  let bodyText: string | undefined;
  if (method === "POST" && (contentLength === undefined || contentLength <= MCP_BODY_CAP_BYTES)) {
    try {
      bodyText = await req.body?.getText();
    } catch {
      bodyText = undefined;
    }
  }
  return classifyMcpRequestBody({
    bodyText,
    contentEncoding: firstHeader(req.headers, ["content-encoding"])?.toLowerCase(),
    contentLength,
    contentType: firstHeader(req.headers, ["content-type"])?.toLowerCase(),
    globalWriteAction: currentPolicy.writeApproval ?? DEFAULT_WRITE_ACTION,
    method,
    policy: currentMcpOperationPolicy,
    url,
  });
}

// The policed request path: policy checks, write classification (with grant
// consultation), credential injection, and OAuth mediation. Re-run in full
// after an approved hold, so approval revalidates current policy by
// construction.
async function policedRequestMutation(
  admission: AdmissionRecord,
  req: ProxyRequest,
  options: { approvedMcp?: McpDisplayFields } = {},
): Promise<OAuthRequestResult> {
  let credential: CredentialMutationSummary | undefined;
  const principal = currentAdmissionPrincipal(admission);
  if (principal === undefined) return missingAdmissionResponse(req);
  const graphqlBodyClass = await graphqlBodyClassForRequest(req);
  const mcpClassification = await mcpClassificationForRequest(req);
  const mutation = beforeAllowedRequest(admission, req, {
    allowedHosts: currentPolicy.allowedHosts,
    credentials: currentPolicy.credentials,
    observeCredentialMutation: (summary) => {
      credential = summary;
    },
    requests: currentPolicy.requests,
    writeApproval: currentPolicy.writeApproval,
    graphqlBodyClass,
    mcpClassification,
    approvedMcp: options.approvedMcp,
    hasWriteGrant: (details) => writeApprovals.hasGrant(details, principal, requestId(req)),
    preserveCredentialHeader: (name, value) => name.toLowerCase() === "authorization"
      && hasOAuthAuthorizationHandle({ [name]: value }),
  });
  let url: URL | undefined;
  try {
    url = new URL(req.url);
  } catch {
    url = undefined;
  }
  const identityStrippedHeaders = stripUntrustedRunfreeIdentityHeaders(mutation.headers ?? req.headers);
  const encodedHeaders = forceIdentityAcceptEncoding(admission.host, url, identityStrippedHeaders ?? mutation.headers ?? req.headers);
  const headers = encodedHeaders ?? identityStrippedHeaders ?? mutation.headers;
  const nextReq = {
    ...req,
    headers: headers ?? req.headers,
  };
  const oauthMutation = await oauthMediator.beforeRequest(nextReq);
  logAllowedRequest(req, { credential });
  return combineRequestMutations(headers ? { headers } : mutation, oauthMutation);
}

function policyDenialResponse(req: ProxyRequest, error: Error) {
  if (error instanceof ProxyAdmissionHostMismatchError) {
    return admissionHostMismatchResponse(req, error);
  }
  if (error instanceof ProxyPolicyDenialError && error.shape) {
    return syntheticShapeDenialResponse(req, error.shape);
  }
  if (isAllowlistDenialMessage(error.message)) {
    return syntheticBlockedHostResponse(req, "host-not-allowlisted");
  }
  const reason = residualDenialReason(error.message);
  if (reason !== undefined) {
    // Route the remaining denial classes (non-HTTPS URL, missing required
    // token) through the structured emitter so they share the per-(host,
    // reason) rate bound and doctor/summary visibility. The synthetic body
    // keeps the original error message verbatim — preserving the
    // missing-token remediation steps.
    const host = requestHost(req);
    emitDenial({
      reason,
      host,
      method: req.method ?? "<unknown>",
      path: req.url,
    });
    return {
      response: {
        statusCode: 403,
        headers: { "content-type": "text/plain" },
        body: blockedBody(host, error.message),
      },
    };
  }
  return blockedResponse(requestHost(req), error.message);
}

function writeApprovalDenial(req: ProxyRequest, shape: ShapeDenialDetails, reason: DenialReason) {
  const denial: ShapeDenialDetails = { ...shape, reason: reason as ShapeDenialReason };
  return syntheticShapeDenialResponse(req, denial);
}

// Approve-on-write hold: the request stays suspended inside this handler
// until a decision, timeout, disconnect, or policy change resolves it. No
// token is read and no upstream connection exists while held; an approved
// hold re-runs the entire policed path with the grant recorded.
async function holdWriteForApproval(admission: AdmissionRecord, req: ProxyRequest, shape: ShapeDenialDetails) {
  const principal = currentAdmissionPrincipal(admission);
  if (principal === undefined) return missingAdmissionResponse(req);
  const heldMcpGeneration = shape.mcp ? currentMcpOperationPolicy?.generation : undefined;
  const revalidate = () => {
    const policy = policyRevalidationCandidate?.policy ?? currentPolicy;
    const mcpOperationGeneration = policyRevalidationCandidate
      ? policyRevalidationCandidate.mcpOperationGeneration
      : currentMcpOperationPolicy?.generation;
    const currentAdmission = server.revalidateAdmission(admission, req);
    const currentPrincipal = currentAdmission ? currentAdmissionPrincipal(currentAdmission) : undefined;
    return currentAdmission !== undefined
      && currentPrincipal !== undefined
      && (!principal || currentPrincipal?.kind !== "session" || principal.kind !== "session"
        || currentPrincipal.sessionKey === principal.sessionKey)
      && evaluateRequestWriteAsk(currentAdmission, req, {
      allowedHosts: policy.allowedHosts,
      requests: policy.requests,
      writeApproval: policy.writeApproval,
    }) !== "denied" && (!shape.mcp || heldMcpGeneration === mcpOperationGeneration);
  };
  const outcome = await writeApprovals.hold({
    host: shape.host,
    method: shape.method,
    path: shape.path,
    category: shape.writeCategory ?? "method",
    ...(shape.mcp ? { mcp: shape.mcp } : {}),
    tokenNames: (currentPolicy.credentials[shape.host] ?? []).map((mapping) => mapping.tokenName),
    requestId: requestId(req),
    ...(principal !== undefined ? { principal } : {}),
    revalidate,
  });
  if (outcome.kind === "approved") {
    try {
      const currentAdmission = server.revalidateAdmission(admission, req);
      if (!currentAdmission) return missingAdmissionResponse(req);
      return await policedRequestMutation(currentAdmission, req, shape.mcp ? { approvedMcp: shape.mcp } : {});
    } catch (error) {
      if (!isPolicyDenial(error)) throw error;
      // Includes a re-thrown ask (grant consumed by a racing request or a
      // policy change mid-decision): fail closed with a retry-403, never
      // re-hold in a loop.
      return policyDenialResponse(req, error);
    }
  }
  if (outcome.kind === "timeout") return writeApprovalDenial(req, shape, "write-approval-timeout");
  if (outcome.kind === "capacity") return writeApprovalDenial(req, shape, "write-approval-capacity");
  if (outcome.kind === "session-denied") {
    return writeApprovalDenial(req, shape, "write-approval-session-denied");
  }
  // denied / no-watcher / cancelled all read as "needs an approval that is
  // not there": the agent-side takeaway is retry after a human acts.
  return writeApprovalDenial(req, shape, "write-approval-required");
}

const handleBeforeRequest = async (admission: AdmissionRecord, req: ProxyRequest) => {
  try {
    if (currentAdmissionPrincipal(admission) === undefined) {
      return missingAdmissionResponse(req);
    }
    assertRequestMatchesAdmission(admission, req, "https:", "HTTPS", currentPolicy.allowedHosts);
    // Audit branch: a non-allowlisted host with a valid marker is observed
    // and forwarded instead of denied. Allowlisted hosts always take the
    // enforce path below, with credentials, in both modes.
    if (!currentPolicy.allowedHostSet.has(requestHost(req)) && auditMarkerState().active) {
      const mutation = await auditedRequestMutation(admission, req);
      logAllowedRequest(req, { audit: true });
      return mutation;
    }
    return await policedRequestMutation(admission, req);
  } catch (error) {
    if (!isPolicyDenial(error)) {
      throw error;
    }
    if (error instanceof ProxyPolicyDenialError && error.shape?.reason === "write-approval-required") {
      return await holdWriteForApproval(admission, req, error.shape);
    }
    return policyDenialResponse(req, error);
  }
};

// mockttp 4.4.2 buffers the *entire* upstream response whenever a pass-through
// rule carries a beforeResponse callback (request-step-impls.ts:
// `originalBody = await streamToBuffer(serverRes)`), which defeats SSE and other
// streaming responses. Attaching beforeResponse to forAnyRequest() therefore
// stalled streaming endpoints such as api.anthropic.com/v1/messages until the
// upstream finished, tripping client timeouts. Scope beforeResponse to exactly
// the OAuth endpoints the mediator may rewrite (token, registration, metadata)
// and leave all other allowlisted responses on the live pass-through path. Both
// rules share handleBeforeRequest, so request-side policy, credentials, audit,
// and OAuth handle mediation are identical regardless of which rule matches.
// `.always()` selects first-matching-incomplete-rule order (matching the
// WebSocket rules below), so the OAuth-scoped rule is registered first and the
// streaming-preserving catch-all last.
await server.forAnyRequest()
  .matching((_admission: AdmissionRecord, req: ProxyRequest) => oauthMediator.requestNeedsResponseMediation(req))
  .always()
  .thenPassThrough({
    beforeRequest: handleBeforeRequest,
    beforeResponse: async (res, req) => {
      return await oauthMediator.beforeResponse(res as OAuthProxyResponse, req);
    },
  });

await server.forAnyRequest()
  .always()
  .thenPassThrough({
    beforeRequest: handleBeforeRequest,
  });

// KNOWN LIMITATION (mockttp 4.4.2): the WebSocket passthrough step mirrors the
// client's raw upgrade headers exactly (`setDefaultHeaders: false`) and exposes
// no per-request callback (no `beforeRequest`) and no header transform — its
// only `transformRequest` covers host/path/query match-replace. So the union
// credential-header strip the HTTP audit path applies via
// `stripUnionConfiguredCredentialHeadersExceptMcpHandle` cannot be applied to an
// audited WSS upgrade here: a configured credential header the agent sends on a
// WSS upgrade to an audited host is forwarded as-is. Tracked for the next
// mockttp upgrade that adds a WS upgrade-header transform; in the meantime
// audited (non-allowlisted) WSS upgrades remain unfiltered for credential
// headers. Enforce-mode WSS to allowlisted hosts is unaffected (no audit).
await server.forAnyWebSocket().matching(isAllowedWebSocket).always().thenPassThrough();
await server.forAnyWebSocket()
  .matching((admission: AdmissionRecord) => currentAdmissionPrincipal(admission) === undefined)
  .always()
  .thenRejectConnection(
    403,
    "Forbidden",
    {
      "content-type": "text/plain; charset=utf-8",
      "x-runfree-blocked": "unregistered-session-peer",
    },
    "blocked by agent proxy policy\nthe admitted session binding is no longer active\n",
  );
for (const statusCode of [421, 403] as const) {
  await server.forAnyWebSocket()
    .matching((admission: AdmissionRecord, req: ProxyRequest) => webSocketAdmissionMismatchStatus(admission, req) === statusCode)
    .always()
    .thenRejectConnection(
      statusCode,
      statusCode === 421 ? "Misdirected Request" : "Forbidden",
      {
        "content-type": "text/plain; charset=utf-8",
        "x-runfree-blocked": "connect-host-mismatch",
      },
      "blocked by agent proxy policy\nrequest host did not match the admitted CONNECT host\n",
    );
}
// Shape-denied upgrades get the matching x-runfree-blocked reason. The
// rejection body is static per rule (mockttp limitation); per-request host,
// method, and path details travel through the structured denial events.
for (const shapeReason of ["method-not-allowed", "path-not-allowed", "git-push-denied", "write-denied", "write-approval-required"] as const) {
  await server.forAnyWebSocket()
    .matching((admission: AdmissionRecord, req: ProxyRequest) => webSocketShapeDenialReason(admission, req) === shapeReason)
    .always()
    .thenRejectConnection(
      403,
      "Forbidden",
      {
        "content-type": "text/plain; charset=utf-8",
        "x-runfree-blocked": shapeReason,
      },
      "blocked by agent proxy policy\nwebsocket upgrades evaluate as GET against this host's request rules\n",
    );
}
await server.forAnyWebSocket().thenRejectConnection(
  403,
  "Forbidden",
  {
    "content-type": "text/plain; charset=utf-8",
    "x-runfree-blocked": "websocket-host-not-allowlisted",
  },
  "blocked by agent proxy policy\n",
);

function parseConnectAuthority(authority: string): { host: string; port: number } {
  const trimmed = authority.trim();
  const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(trimmed);
  if (bracketed) {
    return {
      host: bracketed[1].toLowerCase(),
      port: bracketed[2] ? Number.parseInt(bracketed[2], 10) : 443,
    };
  }

  const match = /^([^:]+)(?::(\d+))?$/.exec(trimmed);
  return {
    host: (match?.[1] ?? trimmed).toLowerCase(),
    port: match?.[2] ? Number.parseInt(match[2], 10) : 443,
  };
}

type ConnectDecision =
  | { action: "pass"; host: string }
  | { action: "audit-pass"; host: string }
  | { action: "denied-tunnel"; host: string }
  | { action: "reject"; host: string; reason: string; denialReason: DenialReason };

// CONNECT matrix: allowed host on 443 passes through to mockttp; a denied
// host on 443 is adopted into the local denied-tunnel TLS endpoint so the
// client gets a readable in-tunnel 403 — unless a valid audit marker is
// active, in which case the validated host passes through to mockttp like an
// allowlisted host (registered + observed). Any non-443 port and malformed
// CONNECT requests keep the raw pre-TLS rejection in every mode because no
// readable in-tunnel response is possible there.
function classifyConnect(authority: string): ConnectDecision {
  const { host, port } = parseConnectAuthority(authority);
  if (port !== 443) {
    return {
      action: "reject",
      host,
      reason: `blocked non-HTTPS CONNECT port: ${Number.isFinite(port) ? port : "<unparseable>"}`,
      denialReason: "non-https-port",
    };
  }
  if (!currentPolicy.allowedHostSet.has(host)) {
    if (auditMarkerState().active) {
      try {
        return { action: "audit-pass", host: normalizeHostname(host) };
      } catch {
        // Hosts that fail validation are never audited; they keep the
        // in-tunnel denial path.
      }
    }
    return { action: "denied-tunnel", host };
  }
  return { action: "pass", host };
}

// --- Denied tunnels ---------------------------------------------------------
// Denied 443 CONNECTs terminate TLS locally with the static `blocked.invalid`
// certificate and answer every in-tunnel request with a synthetic 403. No DNS
// lookup or upstream connection ever happens for a denied host: requests are
// answered entirely from local state.

type DeniedTunnelState = {
  host: string;
  served: boolean;
  // Captured at internal-socket connect time so the client-close handler can
  // delete the map entry even after the internal socket has closed and cleared
  // its own `localPort`.
  internalPort?: number;
};

let activeDeniedTunnels = 0;
const deniedTunnelStatesByPort = new Map<number, DeniedTunnelState>();

function blockedOutboundHostReason(host: string): string {
  return `blocked outbound host: ${host || "<unparseable>"}`;
}

function deniedTunnelState(socket: { remotePort?: number }): DeniedTunnelState | undefined {
  return socket.remotePort === undefined ? undefined : deniedTunnelStatesByPort.get(socket.remotePort);
}

function writeDeniedTunnelResponse(res: http.ServerResponse, host: string, reason: DenialReason): void {
  const denial = syntheticDenialResponseFields(host, reason);
  res.writeHead(denial.statusCode, {
    ...denial.headers,
    "content-length": String(Buffer.byteLength(denial.body)),
    connection: "close",
  });
  res.end(denial.body);
}

function handleDeniedTunnelRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
  const state = deniedTunnelState(req.socket);
  if (!state) {
    res.socket?.destroy();
    return;
  }
  state.served = true;
  // This physical connection was denied at CONNECT and therefore has no
  // admission record. A policy widening cannot upgrade it in place: require a
  // fresh CONNECT so the guard can admit and bind the new connection.
  if (currentPolicy.allowedHostSet.has(state.host)) {
    emitDenial({
      reason: "missing-admission-record",
      host: state.host,
      method: req.method ?? "<unknown>",
      path: req.url,
    });
    writeDeniedTunnelResponse(res, state.host, "missing-admission-record");
    return;
  }
  emitDenial({
    reason: "host-not-allowlisted",
    host: state.host,
    method: req.method ?? "<unknown>",
    path: req.url,
  });
  writeDeniedTunnelResponse(res, state.host, "host-not-allowlisted");
}

async function startDeniedTunnelServer(): Promise<number> {
  const deniedTunnelServer = https.createServer({
    key: blockedLeaf.key,
    cert: `${blockedLeaf.cert}\n${blockedLeaf.ca ?? cert}`,
  }, handleDeniedTunnelRequest);
  deniedTunnelServer.on("clientError", (_error: Error, socket: stream.Duplex) => socket.destroy());
  deniedTunnelServer.on("upgrade", (req: http.IncomingMessage, socket: stream.Duplex) => {
    const state = deniedTunnelState(req.socket);
    const host = state?.host ?? "<unparseable>";
    if (state) state.served = true;
    emitDenial({
      reason: "websocket-host-not-allowlisted",
      host,
      method: req.method ?? "GET",
      path: req.url,
    });
    const denial = syntheticDenialResponseFields(host, "websocket-host-not-allowlisted");
    socket.end([
      "HTTP/1.1 403 Forbidden",
      ...Object.entries(denial.headers).map(([name, value]) => `${name}: ${value}`),
      `content-length: ${Buffer.byteLength(denial.body)}`,
      "connection: close",
      "",
      denial.body,
    ].join("\r\n"));
  });
  await new Promise<void>((resolve, reject) => {
    deniedTunnelServer.once("error", reject);
    deniedTunnelServer.listen(0, "127.0.0.1", () => resolve());
  });
  const address = deniedTunnelServer.address();
  if (!address || typeof address === "string") {
    throw new Error("denied-tunnel server did not report a TCP port");
  }
  return address.port;
}

function adoptDeniedTunnel(clientSocket: net.Socket, host: string, remainder: Buffer): void {
  activeDeniedTunnels += 1;
  const state: DeniedTunnelState = {
    host,
    served: false,
  };
  const internalSocket = net.connect({ host: "127.0.0.1", port: deniedTunnelPort });
  const closeBoth = () => {
    clientSocket.destroy();
    internalSocket.destroy();
  };
  clientSocket.once("close", () => {
    activeDeniedTunnels -= 1;
    // Delete by the port captured at connect time: on the served-403 path the
    // internal socket closes first, so `internalSocket.localPort` is already
    // undefined by the time this client-close handler runs.
    if (state.internalPort !== undefined) {
      deniedTunnelStatesByPort.delete(state.internalPort);
    }
    internalSocket.destroy();
    if (DENIED_TUNNEL_DEBUG) {
      console.log(`proxy-debug: denied-tunnel states=${deniedTunnelStatesByPort.size} served=${state.served} host=${host}`);
    }
    // A denied CONNECT whose tunnel never carried a request (for example a
    // client that aborts on the static `blocked.invalid` certificate) still
    // emits one denial event so doctor and the session summary see it.
    if (!state.served) {
      emitDenial({
        reason: "host-not-allowlisted",
        host,
      });
    }
  });
  // Aggressive idle timeout: denied tunnels are destroyed, never kept open.
  clientSocket.setTimeout(DENIED_TUNNEL_IDLE_MS, closeBoth);
  clientSocket.on("error", closeBoth);
  internalSocket.on("error", closeBoth);
  internalSocket.on("close", () => clientSocket.destroy());
  internalSocket.on("connect", () => {
    if (internalSocket.localPort !== undefined) {
      state.internalPort = internalSocket.localPort;
      deniedTunnelStatesByPort.set(internalSocket.localPort, state);
    }
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (remainder.length > 0) internalSocket.write(remainder);
    clientSocket.pipe(internalSocket);
    internalSocket.pipe(clientSocket);
  });
}

// --- Guard: sole classifier of agent-controlled tunnels ---------------------
//
// Scope, precisely: the guard decides every CONNECT that this proxy ever
// tunnels, and it is the only thing that interprets the first request head on a
// connection. It does not see everything the agent writes — requests inside an
// admitted TLS tunnel are parsed by mockttp, by design, since decrypting and
// re-parsing tunnel content here is exactly the duplicated-parser problem this
// guard exists to avoid. Controls that must also cover in-tunnel requests
// therefore live in the mockttp adapter and admitted rule callbacks above, not
// here.
//
// The guard stays a byte-level dispatcher rather than a second HTTP parser: any
// framing rule the guard and Node's parser disagree about (obsolete line
// folding, bare-LF line endings, leading CRLFs, body delimitation, differing
// header limits) is a request-smuggling surface. Where the guard cannot decide
// without parsing, it refuses, or it changes the connection's disposition so
// that Node — the single parser of those bytes — decides instead.

// httpolyglot (inside mockttp) routes a connection whose first bytes are this
// exact preface to mockttp's HTTP/2 server, where `handleH2Connect` answers 200
// and tunnels with no host classification, no port check, no denied-tunnel path
// and no audit-tunnel registration. mockttp's `http2` option does not help: it
// only shapes TLS ALPN preferences, and the plaintext prior-knowledge dispatch
// in httpolyglot ignores it entirely.
const HTTP2_CLIENT_PREFACE = Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "latin1");
// First byte of a TLS handshake record. A CONNECT tunnel to :443 carries TLS
// and nothing else in this runtime.
const TLS_HANDSHAKE_RECORD = 0x16;
// RFC 9110 token characters — the only bytes an HTTP/1 request line may begin
// with. Node's parser skips CR/LF before the request line and then reads a
// method token, so refusing a non-token first byte both removes that leniency
// gap and refuses the two other things mockttp would otherwise accept on this
// port and tunnel unclassified: a TLS ClientHello (mockttp terminates it,
// mints a per-SNI leaf, and serves HTTP/1 or HTTP/2 CONNECT inside) and a
// SOCKS greeting.
const HTTP_TOKEN_BYTES = new Set<number>(
  [..."!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"]
    .map((character) => character.charCodeAt(0)),
);
// Matched against upper-cased latin1 bytes of a buffered request head. Anchored
// to a line start because a header name can only begin one.
const PROXY_AUTHORIZATION_HEADER_LINE = "\nPROXY-AUTHORIZATION";
const CONNECT_BODY_HEADER_LINE = /(?:^|\r?\n)(?:CONTENT-LENGTH|TRANSFER-ENCODING)\s*:/i;
// Appended to every pass-through request head. The guard classifies the *first*
// head on a connection; Node would keep parsing later requests off the same
// socket, and a CONNECT among them reaches mockttp's `connect` listener with no
// host check, no port check, no denied-tunnel path and no audit registration.
//
// Scanning the payload for later request lines cannot close that: after a
// Content-Length body the next request line starts at the last body byte, with
// no line terminator in front of it, and finding it would mean teaching the
// guard body framing — the second parser this design exists to avoid.
//
// So the pass-through path does not keep connections alive. With this header
// Node serves the first request and then treats *any* trailing bytes as a
// protocol error (400) without emitting `connect`, and closes the socket, which
// the guard mirrors onto the client. The disposition is enforced by the same
// parser that reads the head, so the guard never has to agree with Node about
// where the body ends.
//
// This header is NOT sufficient on its own, and the limit is version-specific:
// Node computes HTTP/1.0 keep-alive from the `F_CONNECTION_KEEP_ALIVE` flag and
// never consults the close token for it, so an HTTP/1.0 request carrying an
// explicit `Connection: keep-alive` ignores this entirely. The pass-through
// path therefore also refuses any request that is not HTTP/1.1 (see `onData`);
// the two together are what make it single-request. Verified against Node 22,
// for both versions. `maxRequestsPerSocket` was measured and rejected: it does
// not stop a pipelined CONNECT at all.
const FORCED_CONNECTION_CLOSE = Buffer.from("\r\nConnection: close", "latin1");

type StreamVerdict = { host: string; detail: string; reason: DenialReason };
type StreamInspector = (chunk: Buffer) => StreamVerdict | undefined;

// Client payload guard for an admitted CONNECT tunnel. Only 443 CONNECTs are
// admitted and every one of them is TLS-intercepted, so the first tunnel byte
// must open a TLS record; cleartext there would let mockttp parse a request
// head the guard never classified.
//
// This checks the first byte only and then disarms: once the tunnel carries
// TLS, its contents are ciphertext and the guard neither can nor should read
// them. Requests inside the tunnel are mockttp's to police — which is why the
// Proxy-Authorization metadata channel is shut at mockttp rather than assumed
// unreachable from here.
function tunnelPayloadInspector(host: string): StreamInspector {
  let checked = false;
  return (chunk) => {
    if (checked || chunk.length === 0) return undefined;
    checked = true;
    if (chunk[0] === TLS_HANDSHAKE_RECORD) return undefined;
    return {
      host,
      detail: "blocked non-TLS payload in a CONNECT tunnel",
      reason: "unsupported-client-protocol",
    };
  };
}

function proxyBufferedConnection(
  clientSocket: net.Socket,
  mockttpPort: number,
  head: Buffer,
  payload: Buffer,
  inspect: StreamInspector | undefined,
  onUpstreamConnected?: (localPort: number, socket: net.Socket) => void,
): void {
  const upstreamSocket = net.connect({ host: "127.0.0.1", port: mockttpPort });
  // The internal connect is async and the guard's data listener has already
  // been removed: without an explicit pause, a client that keeps sending (a
  // large plaintext absolute-form request arriving in multiple chunks) would
  // have those chunks emitted with no listener and silently dropped before
  // forwarding attaches. CONNECT tunnels never hit this — the client waits for
  // the 200 before sending — but pausing is correct for every caller.
  clientSocket.pause();
  const closeBoth = () => {
    clientSocket.destroy();
    upstreamSocket.destroy();
  };
  // Forward client bytes through the inspector rather than `pipe()`, keeping
  // backpressure by hand: a refusal must be able to sever the connection
  // mid-stream, which a plain pipe cannot do.
  const forward = (chunk: Buffer): boolean => {
    const verdict = inspect?.(chunk);
    if (verdict) {
      emitDenial({ reason: verdict.reason, host: verdict.host });
      // Answer before severing: the refused payload was plaintext by
      // definition, so the client can read a diagnosable 403 rather than
      // seeing a bare connection reset.
      clientSocket.end(rawBlockedResponse(verdict.host, verdict.detail));
      upstreamSocket.destroy();
      return false;
    }
    if (!upstreamSocket.write(chunk)) clientSocket.pause();
    return true;
  };
  clientSocket.on("error", closeBoth);
  clientSocket.once("close", () => upstreamSocket.destroy());
  upstreamSocket.on("error", closeBoth);
  upstreamSocket.on("drain", () => clientSocket.resume());
  upstreamSocket.on("connect", () => {
    // The ephemeral port of this proxy-internal connection is chosen by the
    // kernel and never travels to the agent, so it is a connection identity the
    // agent cannot observe or forge. Same correlation the denied-tunnel path
    // already uses via `deniedTunnelStatesByPort`.
    if (onUpstreamConnected) {
      if (upstreamSocket.localPort === undefined) {
        closeBoth();
        return;
      }
      try {
        onUpstreamConnected(upstreamSocket.localPort, upstreamSocket);
      } catch {
        closeBoth();
        return;
      }
    }
    // The head was produced by the guard's own decision and is forwarded
    // verbatim; only client payload is inspected.
    upstreamSocket.write(head);
    // Forward the already-buffered payload before resuming the socket, so a
    // chunk that arrives while the internal connect was in flight cannot
    // overtake it.
    if (payload.length > 0 && !forward(payload)) return;
    clientSocket.on("data", (chunk: Buffer) => {
      forward(chunk);
    });
    clientSocket.on("end", () => upstreamSocket.end());
    upstreamSocket.pipe(clientSocket);
    // Attaching the `data` listener resumes the socket, so re-apply
    // backpressure if the buffered payload already filled the upstream buffer.
    if (upstreamSocket.writableNeedDrain) clientSocket.pause();
    else clientSocket.resume();
  });
}

function handleGuardedConnection(clientSocket: net.Socket, mockttpPort: number): void {
  // Freeze identity at accept, including refusal. Completing a buffered head
  // after address reassignment must never select the replacement session.
  const guardIdentity = identityForPeer(clientSocket.remoteAddress);
  const address = ipv4PeerAddress(clientSocket.remoteAddress);
  if (address !== undefined) {
    const sockets = acceptedSocketsByIp.get(address) ?? new Set<net.Socket>();
    sockets.add(clientSocket);
    acceptedSocketsByIp.set(address, sockets);
    clientSocket.once("close", () => {
      sockets.delete(clientSocket);
      if (sockets.size === 0 && acceptedSocketsByIp.get(address) === sockets) acceptedSocketsByIp.delete(address);
    });
  }
  if (guardIdentity.kind === "accepted") registerSessionSocket(guardIdentity.identity, clientSocket);
  let buffered = Buffer.alloc(0);
  let decided = false;

  // The guard buffers the first head before deciding, so a client that opens a
  // connection and stalls must not pin guard memory forever. Nothing has
  // reached mockttp yet, so mockttp's own header timeout cannot cover this.
  const headTimer = setTimeout(() => {
    if (decided) return;
    reject("<unparseable>", "blocked stalled request head", "request-head-timeout");
  }, REQUEST_HEAD_TIMEOUT_MS);
  headTimer.unref();
  clientSocket.once("close", () => clearTimeout(headTimer));

  const settle = () => {
    decided = true;
    clearTimeout(headTimer);
    clientSocket.off("data", onData);
  };

  // `headerEnd` is the offset of the head terminator; `headEnd` is the offset
  // just past it. `Connection: close` is appended as a final header line rather
  // than re-serializing the client's head: the guard never has to re-emit or
  // re-interpret the client's own header bytes, and if the insertion point were
  // ever wrong Node rejects the whole head instead of keeping the connection
  // alive, so the failure mode stays closed.
  const passThrough = (headerEnd: number, headEnd: number) => {
    if (decided) return;
    settle();
    proxyBufferedConnection(
      clientSocket,
      mockttpPort,
      Buffer.concat([
        buffered.subarray(0, headerEnd),
        FORCED_CONNECTION_CLOSE,
        buffered.subarray(headerEnd, headEnd),
      ]),
      buffered.subarray(headEnd),
      undefined,
    );
  };

  const admitTunnel = (headEnd: number, host: string, identity: GuardIdentity) => {
    if (decided) return;
    settle();
    const admission = admissionRegistry.mint(host, currentPolicy.generation, identity);
    proxyBufferedConnection(
      clientSocket,
      mockttpPort,
      buffered.subarray(0, headEnd),
      buffered.subarray(headEnd),
      tunnelPayloadInspector(host),
      (localPort, upstreamSocket) => {
        admissionRegistry.bind(localPort, admission);
        upstreamSocket.once("close", () => admissionRegistry.release(localPort, admission.connectionSerial));
      },
    );
  };

  const reject = (host: string, reason: string, denialReason: DenialReason) => {
    if (decided) return;
    settle();
    emitDenial({ reason: denialReason, host });
    clientSocket.end(rawBlockedResponse(host, reason));
  };

  const onData = (chunk: Buffer) => {
    buffered = Buffer.concat([buffered, chunk]);

    // HTTP/2 prior-knowledge preface. This mirrors httpolyglot's own state
    // machine byte for byte — keep buffering while the bytes are still a
    // prefix of the preface, refuse once they match it in full — so the two
    // cannot disagree about which connections are HTTP/2.
    const prefaceLength = Math.min(buffered.length, HTTP2_CLIENT_PREFACE.length);
    if (buffered.subarray(0, prefaceLength).equals(HTTP2_CLIENT_PREFACE.subarray(0, prefaceLength))) {
      if (buffered.length >= HTTP2_CLIENT_PREFACE.length) {
        reject("<unparseable>", "blocked non-HTTP/1.1 client protocol", "unsupported-client-protocol");
      }
      return;
    }

    if (!HTTP_TOKEN_BYTES.has(buffered[0])) {
      reject("<unparseable>", "blocked non-HTTP/1.1 client protocol", "unsupported-client-protocol");
      return;
    }

    const text = buffered.toString("latin1");
    const upper = text.toUpperCase();

    // Refuse a client-supplied Proxy-Authorization before anything else looks
    // at this connection. The proxy URLs handed to the agent are credentialless
    // (see the CLI's agent-env module), so the header has no legitimate meaning
    // from the agent; rejecting keeps the single-parser property and needs no
    // re-serialization. Matching raw bytes rather than a parsed header means
    // mixed case, duplicates, obsolete line folding, an oversized value and a
    // malformed head are all refused identically.
    if (upper.includes(PROXY_AUTHORIZATION_HEADER_LINE)) {
      reject("<unparseable>", "blocked client-supplied Proxy-Authorization", "proxy-authorization-not-allowed");
      return;
    }

    const isConnect = upper.startsWith("CONNECT ");
    if (!isConnect && "CONNECT ".startsWith(upper.slice(0, Math.min(upper.length, "CONNECT ".length)))) {
      // Still a prefix of "CONNECT " — undecided, keep buffering.
      return;
    }

    // Head terminator, matching Node's tolerance of bare-LF line endings so the
    // guard never scans a smaller region of the head than Node parses.
    const headMatch = /\r?\n\r?\n/.exec(text);
    if (!headMatch) {
      if (buffered.length > (isConnect ? CONNECT_HEADER_LIMIT : REQUEST_HEAD_LIMIT)) {
        reject("<unparseable>", "blocked oversized request head", "request-head-too-large");
      }
      return;
    }
    // `text` is latin1-decoded, so character offsets equal byte offsets.
    const headEnd = headMatch.index + headMatch[0].length;

    const lineEnd = /\r?\n/.exec(text);
    const firstLine = text.slice(0, lineEnd ? lineEnd.index : text.length);

    // Source identity is authenticated before CONNECT policy classification.
    // An unregistered production peer never reaches host policy, approval,
    // credential, DNS, or upstream paths.
    if (guardIdentity.kind === "rejected") {
      reject("<unparseable>", `blocked unregistered session peer (${guardIdentity.reason})`, "unregistered-session-peer");
      return;
    }

    // A served peer sending the exact readiness bytes is the session entry
    // asking whether its session file has landed. Answered locally before
    // pass-through, before any admission record is minted or session socket
    // registered: no forwarding, DNS, credential, or denial event. Whole-buffer
    // equality, so a readiness request with any extra byte keeps the
    // pass-through behavior.
    if (buffered.equals(SESSION_ADMISSION_PROVISIONING_REQUEST_BYTES)) {
      settle();
      clientSocket.end(SESSION_ADMISSION_ACTIVE_RESPONSE);
      return;
    }

    if (!isConnect) {
      // The forced `Connection: close` below only ends the connection for
      // HTTP/1.1. Node computes HTTP/1.0 keep-alive from the
      // `F_CONNECTION_KEEP_ALIVE` flag alone and never consults the close
      // token there, so an HTTP/1.0 request with an explicit
      // `Connection: keep-alive` keeps the socket parsing and a pipelined
      // CONNECT reaches mockttp's `connect` handler unclassified. Refusing
      // anything but HTTP/1.1 is what makes the pass-through path
      // single-request for every version, rather than only the one whose
      // keep-alive rule the appended header can reach.
      //
      // Nothing legitimate loses here: absolute-form requests to the proxy are
      // not a production path (real clients CONNECT for https), and the
      // denial-feedback paths that do use it are emitted by HTTP/1.1 clients.
      if (!firstLine.endsWith(" HTTP/1.1")) {
        reject("<unparseable>", "blocked non-HTTP/1.1 request on the proxy port", "unsupported-client-protocol");
        return;
      }
      passThrough(headMatch.index, headEnd);
      return;
    }

    const match = /^CONNECT\s+(\S+)\s+HTTP\/\d(?:\.\d)?$/i.exec(firstLine);
    if (!match) {
      reject("<unparseable>", "blocked malformed CONNECT request", "malformed-connect");
      return;
    }

    if (CONNECT_BODY_HEADER_LINE.test(text.slice(0, headEnd))) {
      reject("<unparseable>", "blocked CONNECT request carrying body-framing headers", "malformed-connect");
      return;
    }

    const decision = classifyConnect(match[1]);
    if (decision.action === "reject") {
      reject(decision.host, decision.reason, decision.denialReason);
      return;
    }
    if (decision.action === "audit-pass") {
      if (decided) return;
      // Registered for destroy-on-expiry by the marker watch timer; the
      // observation event and spool entry record the host for the report and
      // the privileged supervisor respectively.
      registerAuditTunnel(clientSocket);
      observeAuditedHost(decision.host);
      admitTunnel(headEnd, decision.host, guardIdentity.identity);
      return;
    }
    if (decision.action === "denied-tunnel") {
      // The readable in-tunnel denial is a best-effort upgrade: past the
      // concurrency cap, degrade to the cheap raw pre-TLS 403.
      if (activeDeniedTunnels >= DENIED_TUNNEL_MAX) {
        reject(decision.host, blockedOutboundHostReason(decision.host), "host-not-allowlisted");
        return;
      }
      if (decided) return;
      settle();
      adoptDeniedTunnel(clientSocket, decision.host, buffered.subarray(headEnd));
      return;
    }

    admitTunnel(headEnd, decision.host, guardIdentity.identity);
  };

  clientSocket.on("data", onData);
  clientSocket.on("error", () => {});
}

await server.start();
const mockttpPort = server.port;
const deniedTunnelPort = await startDeniedTunnelServer();
const guardedServer = net.createServer((socket) => handleGuardedConnection(socket, mockttpPort));
await new Promise<void>((resolve, reject) => {
  guardedServer.once("error", reject);
  // Admission and kernel retirement use IPv4 source addresses. Bind IPv4
  // explicitly so Linux cannot hide IPv4 peers in IPv6-mapped TCP sockets.
  guardedServer.listen(PORT, "0.0.0.0", () => resolve());
});
const listenAddress = guardedServer.address();
const listenPort = listenAddress && typeof listenAddress !== "string" ? listenAddress.port : PORT;

// The served map is the whole request-path authority and it is empty until the
// first refresh, so prime it BEFORE announcing readiness: otherwise the first
// connections after the status file appears are rejected `registry-unavailable`
// for up to one loop.
reconcileSessionAdmission();
// Readiness signal for the host CLI: the level-triggered status file, written
// only once the guarded listener is accepting connections and the served map
// has been refreshed at least once.
publishRequestProxyStatus();
publishWriteApprovalsStatus();
sessionAdmissionWatchTimer = setInterval(reconcileSessionAdmission, SESSION_ADMISSION_WATCH_MS);
sessionAdmissionWatchTimer.unref();

// One-line startup log so `docker compose logs proxy` shows what's loaded.
// Token *names* are listed; values never are. Diagnostics only — readiness
// derives from the status file above, never from scraping this line.
console.log(`proxy: listening on :${listenPort}, ${policySummary(currentPolicy)}`);
