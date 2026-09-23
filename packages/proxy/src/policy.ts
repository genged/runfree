import fs from "node:fs";
import path from "node:path";

import {
  DEFAULT_WRITE_ACTION,
  assertTokenName,
  isHttpMethod,
  pathMatchesPrefix,
  validateNetworkPolicy,
  type CredentialMapping,
  type CredentialPolicy,
  type HttpMethod,
  type LoadedNetworkPolicy,
  type PolicyJson,
  type RequestPolicyJson,
  type WriteAction,
} from "@runfree/runtime-contracts/network-policy";
import type { McpClassification, McpDisplayFields } from "./mcp-classify.js";
import type { AdmissionRecord } from "./admission.js";

const DEFAULT_TOKEN_DIR = "/run/runfree-proxy-secrets";

export {
  DEFAULT_WRITE_ACTION,
  effectiveWriteAction,
  hostFromUrl,
  normalizeHostname,
  normalizePathPrefix,
  pathMatchesPrefix,
  PolicyValidationError,
  validateNetworkPolicy as validateProxyPolicy,
  type CredentialMapping,
  type CredentialPolicy,
  type CredentialPolicyJson,
  type CredentialScheme,
  type PolicyJson,
  type RequestPolicyJson,
  type TokenPolicyJson,
  type WriteAction,
} from "@runfree/runtime-contracts/network-policy";

export type LoadedProxyPolicy = LoadedNetworkPolicy;

export type ProxyRequest = {
  method?: string;
  url: string;
  headers?: Record<string, string | string[] | undefined>;
  // mockttp's buffered request body accessor; present on the async server
  // path, absent in synchronous policy checks.
  body?: {
    getText(): Promise<string | undefined>;
  };
  destination?: {
    hostname?: string;
    port?: number;
  };
  // Ephemeral port of the proxy-internal connection this request arrived on.
  // mockttp reports it from the accepted socket and propagates it onto derived
  // TLS/HTTP2 sockets, so for guard-admitted traffic it is the guard's own
  // `upstreamSocket.localPort` — a value the agent never sees or chooses.
  remotePort?: number;
};

export type PolicyOptions = {
  allowedHosts?: readonly string[];
  credentials?: CredentialPolicy;
  requests?: Record<string, RequestPolicyJson>;
  // Compiled policy-level default write action from the caller's policy state.
  writeApproval?: WriteAction;
  tokenDir?: string;
  tokenReader?: (tokenName: string) => string | null;
  log?: (line: string) => void;
  observeCredentialMutation?: (summary: CredentialMutationSummary) => void;
  preserveCredentialHeader?: (headerName: string, value: string | string[] | undefined) => boolean;
  // Approve-on-write grant check: called when a classified write hits an `ask`
  // host, before any denial. Returning true (a covering grant) lets the
  // request continue to credential injection; false or an absent hook denies
  // fail-closed (a held-and-approved request re-runs this whole check with a
  // grant recorded, so approval revalidates current policy by construction).
  hasWriteGrant?: (details: WriteDenialDetails) => boolean;
  // Per-request body-aware GraphQL verdict (see classifyWrite); precomputed
  // by the async caller because this check is synchronous and body-free.
  graphqlBodyClass?: "read" | "write";
  mcpClassification?: McpClassification;
  approvedMcp?: McpDisplayFields;
};

export type CredentialMutationAction = "none" | "stripped" | "injected" | "anonymous" | "preserved";

export type CredentialMutationSummary = {
  action: CredentialMutationAction;
  headers: readonly string[];
  tokenNames: readonly string[];
};

export type RequestMutation = {
  headers?: Record<string, string | string[] | undefined>;
};

// Request-shape denial reasons mirror the denial-event reason enums so shape
// denials ride the same synthetic-403 and `proxy-denial:` event machinery.
export type ShapeDenialReason =
  | "method-not-allowed"
  | "path-not-allowed"
  | "git-push-denied"
  | "write-denied"
  | "write-approval-required";

// Which classifier input marked the request a write. Presentation maps these
// to plain-language phrases; the enforcement decision never depends on them.
export type WriteCategory =
  | "method"
  | "method-override"
  | "git-push"
  | "graphql"
  | "write-path"
  | "websocket"
  | "mcp-tool"
  | "mcp-unknown";

export type WriteDenialDetails = {
  host: string;
  method: string;
  path: string;
  writeAction: "ask" | "deny";
  category: WriteCategory;
  mcp?: McpDisplayFields;
};

export type ShapeDenialDetails = {
  reason: ShapeDenialReason;
  host: string;
  method: string;
  path: string;
  allowedMethods?: readonly HttpMethod[];
  allowedPathPrefixes?: readonly string[];
  // The host's full request rule, so a widening remedy can reproduce every
  // existing restriction instead of replacing the rule with the delta alone.
  rule?: RequestPolicyJson;
  writeCategory?: WriteCategory;
  mcp?: McpDisplayFields;
};

export class ProxyPolicyDenialError extends Error {
  readonly shape?: ShapeDenialDetails;

  constructor(message: string, shape?: ShapeDenialDetails) {
    super(message);
    this.name = "ProxyPolicyDenialError";
    this.shape = shape;
  }
}

export class ProxyAdmissionHostMismatchError extends Error {
  readonly admittedHost: string;
  readonly claimedHost: string;
  readonly statusCode: 403 | 421;

  constructor(input: { admittedHost: string; claimedHost: string; claimedHostAllowed: boolean }) {
    super(`request host ${input.claimedHost || "<unparseable>"} does not match admitted CONNECT host ${input.admittedHost}`);
    this.name = "ProxyAdmissionHostMismatchError";
    this.admittedHost = input.admittedHost;
    this.claimedHost = input.claimedHost || "<unparseable>";
    this.statusCode = input.claimedHostAllowed ? 421 : 403;
  }
}

function parsedUrl(url: string): URL | undefined {
  try {
    return new URL(url);
  } catch {
    return undefined;
  }
}

function requirePolicyPath(policyPath = process.env.PROXY_POLICY_PATH): string {
  if (!policyPath) {
    throw new Error("PROXY_POLICY_PATH is required; mount the project network-policy.json under /app/proxy/policy");
  }
  return policyPath;
}

export function readPolicyJson(policyPath: string): PolicyJson {
  const raw = fs.readFileSync(policyPath, "utf8");
  return JSON.parse(raw) as PolicyJson;
}

export function loadProxyPolicy(policyPath = process.env.PROXY_POLICY_PATH): LoadedProxyPolicy {
  const resolvedPolicyPath = requirePolicyPath(policyPath);
  const raw = readPolicyJson(resolvedPolicyPath);
  return validateNetworkPolicy(raw, resolvedPolicyPath);
}

export function tokenPath(tokenName: string, tokenDir = process.env.PROXY_SECRET_DIR ?? DEFAULT_TOKEN_DIR): string {
  assertTokenName(tokenName);
  return path.join(tokenDir, tokenName);
}

export function readTokenFile(tokenName: string, tokenDir = process.env.PROXY_SECRET_DIR ?? DEFAULT_TOKEN_DIR): string | null {
  try {
    const value = fs.readFileSync(tokenPath(tokenName, tokenDir), "utf8").trim();
    return value === "" ? null : value;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

// Union of every configured credential header name across every token policy,
// lowercased. Audit mode strips this union from requests toward non-allowlisted
// hosts: `credentials[host]` is empty for an audited host, so the per-host
// strip would do nothing there.
export function configuredCredentialHeaderNames(credentials: CredentialPolicy): Set<string> {
  const names = new Set<string>();
  for (const mappings of Object.values(credentials)) {
    for (const mapping of mappings) {
      names.add(mapping.header.toLowerCase());
    }
  }
  return names;
}

function formatCredentialValue(mapping: CredentialMapping, token: string): string {
  if (mapping.scheme === "bearer") return `Bearer ${token}`;
  return token;
}

function requestPath(url: URL): string {
  return url.pathname || "/";
}

function selectedCredentialMappings(mappings: CredentialMapping[], pathName: string): CredentialMapping[] {
  const scopedMatches = mappings.filter((mapping) => {
    return mapping.pathPrefix !== undefined && pathMatchesPrefix(pathName, mapping.pathPrefix);
  });
  if (scopedMatches.length === 0) return mappings.filter((mapping) => mapping.pathPrefix === undefined);

  const longest = Math.max(...scopedMatches.map((mapping) => mapping.pathPrefix?.length ?? 0));
  return scopedMatches.filter((mapping) => mapping.pathPrefix?.length === longest);
}

function shouldPreserveHeader(
  headers: Record<string, string | string[] | undefined>,
  headerName: string,
  preserve: PolicyOptions["preserveCredentialHeader"],
): boolean {
  if (!preserve) return false;
  const lower = headerName.toLowerCase();
  return Object.entries(headers).some(([key, value]) => key.toLowerCase() === lower && preserve(key, value));
}

// Method-override request headers are stripped on method-ruled hosts because
// override-honoring frameworks would otherwise execute a different verb than
// the one the rule admitted. Body/query overrides are a documented residual.
const METHOD_OVERRIDE_HEADERS = new Set([
  "x-http-method-override",
  "x-http-method",
  "x-method-override",
]);

const ENCODED_PATH_TRAVERSAL_RE = /%2e|%2f|%5c/i;
const DENIAL_MESSAGE_PATH_LIMIT = 256;
// Bound on the decode-to-fixed-point loop. A handful of iterations covers any
// realistic multiply-encoded payload (double, triple, ...) while staying
// constant-cost against a hostile input that re-encodes on every pass.
const MAX_PATH_DECODE_ITERATIONS = 5;

function truncatedPath(pathName: string): string {
  return pathName.slice(0, DENIAL_MESSAGE_PATH_LIMIT);
}

// Decode `%xx` sequences repeatedly until the string stops changing or the
// iteration bound is hit, so a doubly/triply-encoded payload (e.g. `%25252e`)
// is reduced to the same canonical form a multiply-decoding origin would
// reach. Throws on malformed encoding so callers can fail closed.
function decodeToFixedPoint(value: string): string {
  let current = value;
  for (let iteration = 0; iteration < MAX_PATH_DECODE_ITERATIONS; iteration += 1) {
    const next = decodeURIComponent(current);
    if (next === current) return next;
    current = next;
  }
  return current;
}

// A single path segment escapes its prefix if, after stripping any
// `;`-parameter suffix, it equals `..` — servlet/JSP origins strip matrix
// `;params` before normalizing, so `..;` reaches `..`.
function isTraversalSegment(segment: string): boolean {
  const withoutParams = segment.split(";", 1)[0];
  return withoutParams === "..";
}

// `new URL().pathname` resolves literal dot-segments but does not decode
// `%2e`/`%2f`/`%5c`, while many origins do. On `pathPrefixes`-ruled hosts any
// encoded dot/slash/backslash (decoded to a fixed point so multiply-encoded
// forms are covered too), any backslash, and any residual `..` segment —
// including a `..;param` matrix-parameter segment — fail closed so the proxy
// and the origin cannot disagree about the path.
function hasPathConfusion(pathName: string): boolean {
  let decoded: string;
  try {
    decoded = decodeToFixedPoint(pathName);
  } catch {
    return true;
  }
  for (const candidate of [pathName, decoded]) {
    if (ENCODED_PATH_TRAVERSAL_RE.test(candidate)) return true;
    if (candidate.includes("\\")) return true;
    if (candidate.includes("//")) return true;
    if (candidate.split("/").some(isTraversalSegment)) return true;
  }
  return false;
}

// The git-push decision is the only check that runs on a `{gitPush:"deny"}`-only
// host, so it must be self-contained against path confusion: a percent-encoded
// or matrix-parameter segment that a decoding origin (git-http-backend, GitHub)
// routes to `git-receive-pack` must be denied here even though
// `url.pathname.endsWith("/git-receive-pack")` is false on the raw form.
function isGitPushPath(url: URL, pathName: string): boolean {
  let canonicalPath: string;
  try {
    canonicalPath = decodeToFixedPoint(pathName);
  } catch {
    // Malformed encoding on a push-denied host fails closed: treat it as a push.
    return true;
  }
  for (const candidate of [pathName, canonicalPath]) {
    if (candidate.toLowerCase().endsWith("/git-receive-pack")) return true;
  }
  // Capability-probe form: GET .../info/refs?service=git-receive-pack. The
  // service value rides the query, which `URL` already percent-decodes, but
  // decode the canonical pathname so `/info/ref%73` is matched too.
  const service = url.searchParams.get("service");
  if (service === "git-receive-pack") {
    for (const candidate of [pathName, canonicalPath]) {
      if (candidate.toLowerCase().endsWith("/info/refs")) return true;
    }
  }
  return false;
}

// --- Write classification ----------------------------------------------------
// Decides "is this request a write?" for hosts whose effective writeAction is
// ask or deny. The classifier is conservative: anything it cannot positively
// classify as a read is a write. It runs after the shape check and before any
// credential read, so a denied or held write never touches a token file.

const SAFE_CLASSIFIER_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function hasMethodOverrideHeader(headers: Record<string, string | string[] | undefined> | undefined): boolean {
  if (!headers) return false;
  return Object.keys(headers).some((key) => METHOD_OVERRIDE_HEADERS.has(key.toLowerCase()));
}

// Read-side counterpart of isGitPushPath: git fetch negotiation
// (upload-pack). Only consulted for hosts that explicitly declare git
// handling via a `gitPush` rule; malformed encoding fails closed by NOT
// matching (the request then classifies by its method — POST => write).
function isGitUploadPackPath(url: URL, pathName: string): boolean {
  let canonicalPath: string;
  try {
    canonicalPath = decodeToFixedPoint(pathName);
  } catch {
    return false;
  }
  for (const candidate of [pathName, canonicalPath]) {
    if (candidate.toLowerCase().endsWith("/git-upload-pack")) return true;
  }
  if (url.searchParams.get("service") === "git-upload-pack") {
    for (const candidate of [pathName, canonicalPath]) {
      if (candidate.toLowerCase().endsWith("/info/refs")) return true;
    }
  }
  return false;
}

export type WriteClassification = { write: false } | { write: true; category: WriteCategory };

export function classifyWrite(input: {
  method: string;
  url: URL;
  rule: RequestPolicyJson | undefined;
  headers?: Record<string, string | string[] | undefined>;
  webSocket?: boolean;
  // Body-aware GraphQL verdict, precomputed by the async server layer for
  // POSTs to a declared graphql endpoint. "read" means the body was proven a
  // pure query document under the size cap; absent means unproven => write.
  graphqlBodyClass?: "read" | "write";
}): WriteClassification {
  // A wss:// upgrade is an opaque live channel the proxy cannot inspect
  // frame-by-frame, so the whole connection classifies as a write (HIGH-2).
  if (input.webSocket) return { write: true, category: "websocket" };

  const pathName = requestPath(input.url);
  const rule = input.rule;

  // Method-override headers classify as a write whenever classification is
  // active, regardless of any `methods` rule (HIGH-1): GET plus
  // X-HTTP-Method-Override: DELETE reaches a write at the origin.
  if (hasMethodOverrideHeader(input.headers)) return { write: true, category: "method-override" };

  // Git push detection is built in and encoding-safe (v1 machinery). It runs
  // before any read exemption so a push never classifies as a read.
  if (isGitPushPath(input.url, pathName)) return { write: true, category: "git-push" };

  if (rule?.writePathPrefixes !== undefined
    && rule.writePathPrefixes.some((prefix) => pathMatchesPrefix(pathName, prefix))) {
    return { write: true, category: "write-path" };
  }

  // A POST to a declared GraphQL endpoint classifies by operation type:
  // query-only documents (proven by the body-aware classifier under the size
  // cap) are reads; mutations, subscriptions, batches, persisted-query
  // requests, and anything unproven are writes. GET-based GraphQL is a read
  // by construction and needs no parsing.
  if (rule?.graphql !== undefined && rule.graphql.endpoints.includes(pathName)
    && !SAFE_CLASSIFIER_METHODS.has(input.method)) {
    if (input.graphqlBodyClass === "read" && !hasPathConfusion(pathName)) return { write: false };
    return { write: true, category: "graphql" };
  }

  // The closed uppercase safe set: case variants and non-RFC extension verbs
  // fall through to the conservative write classification below.
  if (SAFE_CLASSIFIER_METHODS.has(input.method)) return { write: false };

  // Read exemptions for non-safe methods. Path confusion disqualifies a read
  // classification: the proxy and a decoding origin must not disagree.
  if (!hasPathConfusion(pathName)) {
    if (rule?.readPathPrefixes !== undefined
      && rule.readPathPrefixes.some((prefix) => pathMatchesPrefix(pathName, prefix))) {
      return { write: false };
    }
    if (rule?.gitPush !== undefined && isGitUploadPackPath(input.url, pathName)) {
      return { write: false };
    }
  }

  return { write: true, category: "method" };
}

// Enforcement for the write class: classify, honor grants on `ask` hosts, and
// throw a denial (before any credential read) when the write is not allowed.
function assertWriteAllowed(input: {
  method: string;
  url: URL;
  host: string;
  rule: RequestPolicyJson | undefined;
  writeAction: WriteAction;
  headers?: Record<string, string | string[] | undefined>;
  webSocket?: boolean;
  graphqlBodyClass?: "read" | "write";
  hasWriteGrant?: PolicyOptions["hasWriteGrant"];
  mcpClassification?: McpClassification;
  approvedMcp?: McpDisplayFields;
}): void {
  if (input.mcpClassification) {
    if (input.mcpClassification.kind === "read") return;
    const pathName = requestPath(input.url);
    const details: WriteDenialDetails = input.mcpClassification.kind === "write"
      ? {
        host: input.host,
        method: input.method,
        path: pathName,
        writeAction: input.mcpClassification.writeAction === "deny" ? "deny" : "ask",
        category: input.mcpClassification.category,
        mcp: input.mcpClassification.display,
      }
      : {
        host: input.host,
        method: input.method,
        path: pathName,
        writeAction: input.writeAction === "deny" ? "deny" : "ask",
        category: input.mcpClassification.category,
        ...(input.mcpClassification.display ? { mcp: input.mcpClassification.display } : {}),
      };
    const writeAction = input.mcpClassification.kind === "write" ? input.mcpClassification.writeAction : input.writeAction;
    if (writeAction === "allow") return;
    if (input.approvedMcp && details.mcp && sameMcpDisplay(input.approvedMcp, details.mcp)) return;
    if (writeAction === "ask" && input.hasWriteGrant?.(details) === true) return;
    const reason: ShapeDenialReason = writeAction === "deny" ? "write-denied" : "write-approval-required";
    throw new ProxyPolicyDenialError(
      `blocked write to ${input.host}: ${truncatedPath(pathName)}`,
      {
        reason,
        host: input.host,
        method: input.method,
        path: pathName,
        writeCategory: details.category,
        ...(details.mcp ? { mcp: details.mcp } : {}),
      },
    );
  }
  if (input.writeAction === "allow") return;
  const classification = classifyWrite(input);
  if (!classification.write) return;

  const pathName = requestPath(input.url);
  const details: WriteDenialDetails = {
    host: input.host,
    method: input.method,
    path: pathName,
    writeAction: input.writeAction,
    category: classification.category,
  };
  if (input.writeAction === "ask" && input.hasWriteGrant?.(details) === true) return;

  const reason: ShapeDenialReason = input.writeAction === "deny" ? "write-denied" : "write-approval-required";
  throw new ProxyPolicyDenialError(
    `blocked write to ${input.host}: ${truncatedPath(pathName)}`,
    {
      reason,
      host: input.host,
      method: input.method,
      path: pathName,
      writeCategory: classification.category,
    },
  );
}

function sameMcpDisplay(left: McpDisplayFields, right: McpDisplayFields): boolean {
  return left.agent === right.agent
    && left.serverId === right.serverId
    && left.server === right.server
    && left.method === right.method
    && left.tool === right.tool;
}

// Shape enforcement runs after the hostname allowlist check and before any
// credential read, token injection, or MCP OAuth mediation. Order within the
// shape check: method, then path, then git push.
function assertAllowedRequestShape(
  rawMethod: string,
  url: URL,
  host: string,
  rule: RequestPolicyJson | undefined,
): void {
  if (!rule) return;
  const pathName = requestPath(url);

  if (rule.methods !== undefined) {
    // The closed RFC verb set is uppercase, so case variants and non-RFC
    // extension verbs fail this membership check on method-ruled hosts.
    if (!isHttpMethod(rawMethod) || !rule.methods.includes(rawMethod)) {
      throw new ProxyPolicyDenialError(
        `blocked request method for ${host}: method is not permitted`,
        {
          reason: "method-not-allowed",
          host,
          method: rawMethod,
          path: pathName,
          allowedMethods: rule.methods,
          rule,
        },
      );
    }
  }

  if (rule.pathPrefixes !== undefined) {
    const confused = hasPathConfusion(pathName);
    if (confused || !rule.pathPrefixes.some((pathPrefix) => pathMatchesPrefix(pathName, pathPrefix))) {
      throw new ProxyPolicyDenialError(
        `blocked request path for ${host}: ${truncatedPath(pathName)}`,
        {
          reason: "path-not-allowed",
          host,
          method: rawMethod,
          path: pathName,
          allowedPathPrefixes: rule.pathPrefixes,
          rule,
        },
      );
    }
  }

  if (rule.gitPush === "deny" && isGitPushPath(url, pathName)) {
    throw new ProxyPolicyDenialError(
      `blocked git push for ${host}: ${truncatedPath(pathName)}`,
      {
        reason: "git-push-denied",
        host,
        method: rawMethod,
        path: pathName,
      },
    );
  }
}

// Pre-credential evaluation of a request against the CURRENT policy, with no
// side effects: no token read, no header mutation, no logging. Used to
// revalidate a held write when a decision arrives and on policy generation
// changes — "ask" means the hold may still resolve, "denied" cancels it
// fail-closed, "allowed" means the policy loosened and the request may flow.
export function evaluateRequestWriteAsk(
  admission: AdmissionRecord,
  req: ProxyRequest,
  options: Pick<PolicyOptions, "allowedHosts" | "mcpClassification" | "requests" | "writeApproval">,
  input: { webSocket?: boolean } = {},
): "allowed" | "ask" | "denied" {
  try {
    const allowedHosts = options.allowedHosts ?? [];
    const requests = options.requests ?? {};
    const { url, host } = requireAllowedUrl(
      admission,
      req,
      allowedHosts,
      input.webSocket ? "wss:" : "https:",
      input.webSocket ? "WSS" : "HTTPS",
    );
    const method = input.webSocket ? "GET" : req.method ?? "GET";
    const rule = requests[host];
    assertAllowedRequestShape(method, url, host, rule);
    assertWriteAllowed({
      method,
      url,
      host,
      rule,
      writeAction: rule?.writeAction ?? options.writeApproval ?? DEFAULT_WRITE_ACTION,
      headers: req.headers,
      webSocket: input.webSocket,
      mcpClassification: input.webSocket ? undefined : options.mcpClassification,
    });
    return "allowed";
  } catch (error) {
    if (error instanceof ProxyPolicyDenialError && error.shape?.reason === "write-approval-required") {
      return "ask";
    }
    if (error instanceof Error) return "denied";
    throw error;
  }
}

function firstHeaderValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function hostnameFromAuthority(value: string | undefined): string {
  if (!value) return "";
  try {
    return new URL(`https://${value}`).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function requireAdmissionUrl(
  admission: AdmissionRecord,
  req: ProxyRequest,
  allowedHostSet: ReadonlySet<string>,
  protocol: "https:" | "wss:",
  protocolLabel: string,
): { url: URL; host: string } {
  const url = parsedUrl(req.url);
  const urlHost = url?.hostname.toLowerCase() ?? "";
  const authorityHost = hostnameFromAuthority(
    firstHeaderValue(req.headers?.[":authority"]) ?? firstHeaderValue(req.headers?.host),
  );
  const claimedHosts = [urlHost, ...(authorityHost ? [authorityHost] : [])];
  const mismatchedHost = claimedHosts.find((host) => host !== admission.host);
  if (mismatchedHost !== undefined) {
    throw new ProxyAdmissionHostMismatchError({
      admittedHost: admission.host,
      claimedHost: mismatchedHost,
      claimedHostAllowed: allowedHostSet.has(mismatchedHost),
    });
  }
  if (url?.protocol !== protocol) {
    const safeUrl = url ? `${url.protocol}//${url.host}${url.pathname || "/"}` : "<unparseable>";
    throw new Error(`blocked non-${protocolLabel} outbound URL: ${safeUrl}`);
  }
  return { url, host: admission.host };
}

export function assertRequestMatchesAdmission(
  admission: AdmissionRecord,
  req: ProxyRequest,
  protocol: "https:" | "wss:",
  protocolLabel: string,
  allowedHosts: readonly string[] = [],
): { url: URL; host: string } {
  return requireAdmissionUrl(admission, req, new Set(allowedHosts), protocol, protocolLabel);
}

function requireAllowedUrl(admission: AdmissionRecord, req: ProxyRequest, allowedHosts: readonly string[], protocol: "https:" | "wss:", protocolLabel: string): {
  url: URL;
  host: string;
} {
  const allowedHostSet = new Set(allowedHosts);
  const { url, host } = requireAdmissionUrl(admission, req, allowedHostSet, protocol, protocolLabel);
  if (!allowedHostSet.has(host)) {
    throw new Error(`blocked outbound host: ${host || "<unparseable>"}`);
  }

  return { url, host };
}

// Policy state comes from the caller (the server's hot `currentPolicy`);
// there is no lazy policy-file fallback. An omitted allowlist means deny-all.
export function assertAllowedWebSocketRequest(admission: AdmissionRecord, req: ProxyRequest, options: PolicyOptions = {}): void {
  const allowedHosts = options.allowedHosts ?? [];
  const requests = options.requests ?? {};
  const writeApproval = options.writeApproval;
  const { url, host } = requireAllowedUrl(admission, req, allowedHosts, "wss:", "WSS");
  // WebSocket upgrades evaluate as GET with the upgrade pathname.
  const requestRule = requests[host];
  assertAllowedRequestShape("GET", url, host, requestRule);
  // An upgrade to an ask/deny host is an opaque live channel: classified as a
  // write and gated before any upstream connection (HIGH-2).
  assertWriteAllowed({
    method: "GET",
    url,
    host,
    rule: requestRule,
    writeAction: requestRule?.writeAction ?? writeApproval ?? DEFAULT_WRITE_ACTION,
    headers: req.headers,
    webSocket: true,
    hasWriteGrant: options.hasWriteGrant,
  });
}

// Policy state comes from the caller (the server's hot `currentPolicy`);
// there is no lazy policy-file fallback. An omitted allowlist means deny-all.
export function beforeAllowedRequest(admission: AdmissionRecord, req: ProxyRequest, options: PolicyOptions = {}): RequestMutation {
  const allowedHosts = options.allowedHosts ?? [];
  const credentials = options.credentials ?? {};
  const requests = options.requests ?? {};
  const writeApproval = options.writeApproval;
  const tokenReader = options.tokenReader ?? ((tokenName: string) => readTokenFile(tokenName, options.tokenDir));
  const log = options.log ?? console.log;
  const { url, host } = requireAllowedUrl(admission, req, allowedHosts, "https:", "HTTPS");

  // Shape denial happens before any credential work: a shape-denied request
  // never reads token files and never reaches MCP OAuth mediation.
  const requestRule = requests[host];
  assertAllowedRequestShape(req.method ?? "GET", url, host, requestRule);

  // Write classification runs between the shape check and any credential
  // read: a denied (or unapproved) write never reads a token file and never
  // reaches MCP OAuth mediation.
  const writeAction = requestRule?.writeAction ?? writeApproval ?? DEFAULT_WRITE_ACTION;
  assertWriteAllowed({
    method: req.method ?? "GET",
    url,
    host,
    rule: requestRule,
    writeAction,
    headers: req.headers,
    graphqlBodyClass: options.graphqlBodyClass,
    hasWriteGrant: options.hasWriteGrant,
    mcpClassification: options.mcpClassification,
    approvedMcp: options.approvedMcp,
  });

  const headers = { ...(req.headers ?? {}) };
  let changed = false;

  // Method-override headers are stripped on method-ruled hosts and whenever
  // write classification is active, so an override-honoring origin can never
  // execute a different verb than the one policy admitted or approved.
  if (requestRule?.methods !== undefined || writeAction !== "allow") {
    for (const key of Object.keys(headers)) {
      if (METHOD_OVERRIDE_HEADERS.has(key.toLowerCase())) {
        delete headers[key];
        changed = true;
      }
    }
  }

  const mappings = credentials[host] ?? [];
  if (mappings.length === 0) return changed ? { headers } : {};

  const configuredHeaders = new Set(mappings.map((mapping) => mapping.header.toLowerCase()));
  const canonicalHeaders = new Map(mappings.map((mapping) => [mapping.header.toLowerCase(), mapping.header] as const));
  let strippedCredential = false;
  for (const key of Object.keys(headers)) {
    if (configuredHeaders.has(key.toLowerCase()) && options.preserveCredentialHeader?.(key, headers[key]) !== true) {
      delete headers[key];
      strippedCredential = true;
      changed = true;
    }
  }

  const selectedMappings = selectedCredentialMappings(mappings, requestPath(url));
  const touchedHeaders = new Set<string>();
  const touchedTokenNames = new Set<string>();
  let injectedCredential = false;
  let anonymousCredential = false;
  let preservedCredential = false;
  for (const mapping of selectedMappings) {
    const lower = mapping.header.toLowerCase();
    touchedHeaders.add(canonicalHeaders.get(lower) ?? mapping.header);
    touchedTokenNames.add(mapping.tokenName);
    if (shouldPreserveHeader(headers, mapping.header, options.preserveCredentialHeader)) {
      preservedCredential = true;
      continue;
    }
    const token = tokenReader(mapping.tokenName);
    if (!token) {
      if (mapping.allowAnonymous === true) {
        anonymousCredential = true;
        continue;
      }
      throw new ProxyPolicyDenialError([
        `missing required proxy token: ${mapping.tokenName}`,
        `configure it with: runfree credential set-source ${mapping.tokenName} --from-env ${mapping.tokenName.toUpperCase().replaceAll("-", "_")}_TOKEN`,
        `or set tokens.${mapping.tokenName}.allowAnonymous=true to forward anonymously with ${mapping.header} stripped`,
      ].join("; "));
    }

    headers[lower] = formatCredentialValue(mapping, token);
    injectedCredential = true;
    changed = true;
    log(`proxy: injected ${mapping.header} for ${host} using ${mapping.tokenName}`);
  }

  const action: CredentialMutationAction = injectedCredential
    ? "injected"
    : preservedCredential
      ? "preserved"
      : anonymousCredential
        ? "anonymous"
        : strippedCredential
          ? "stripped"
          : "none";
  options.observeCredentialMutation?.({
    action,
    headers: Array.from(touchedHeaders).sort(),
    tokenNames: Array.from(touchedTokenNames).sort(),
  });

  return changed ? { headers } : {};
}
