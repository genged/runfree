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
  type CredentialProtocol,
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
  isIpLiteralHostname,
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
    // The buffered body after content-encoding decoding (undefined when it
    // cannot be decoded). Optional so synchronous test doubles can omit it;
    // a classifier that needs it treats absence as unproven.
    getDecodedBuffer?(): Promise<Buffer | undefined>;
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
  // Per-request body-aware Git LFS batch verdict (see lfs-classify.ts),
  // precomputed by the async caller: "download" means the body was proven a
  // bounded, unambiguous `"operation": "download"` batch. Only consulted by
  // classifyWrite for POST …/info/lfs/objects/batch on a gitPush-ruled host
  // whose policy has an eligible git-lfs mapping (lfsMediatedRequest).
  lfsBodyClass?: "download";
  // Precomputed by the async server layer: this POST targets an exact,
  // recorded, statically mediated OAuth token or registration endpoint and is
  // protocol-shaped (OAuthMediator.protocolReadEndpoint plus
  // protocolReadBodyAllowed). It makes the POST a read on an `ask` host only.
  oauthProtocolRead?: boolean;
  // Display only: the POST targeted a protocol-read endpoint but its client_id
  // is a client metadata URL Runfree does not recognize. Carried into a write
  // denial so it can say why the request was not a protocol read.
  oauthUnlistedClientIdUrl?: boolean;
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
  oauthUnlistedClientIdUrl?: boolean;
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

// Exhaustive on purpose: a scheme added to the contract must fail to compile
// here rather than fall through to sending the raw token.
function formatCredentialValue(mapping: CredentialMapping, token: string): string {
  switch (mapping.scheme) {
    case "bearer":
      return `Bearer ${token}`;
    case "raw":
      return token;
    case "basic": {
      // Validation guarantees username for basic; refuse rather than send a
      // header with an empty user-id if that invariant is ever broken.
      if (mapping.username === undefined) throw new Error(`basic credential ${mapping.tokenName} has no username`);
      return `Basic ${Buffer.from(`${mapping.username}:${token}`, "utf8").toString("base64")}`;
    }
    default: {
      const unreachable: never = mapping.scheme;
      throw new Error(`unsupported credential scheme: ${String(unreachable)}`);
    }
  }
}

function requestPath(url: URL): string {
  return url.pathname || "/";
}

// A protocol-scoped mapping is eligible for a request when the request's
// protocol (gitRequestProtocol) is the mapping's protocol and the mapping's
// pathPrefix, if any, matches. Each git request kind maps to exactly one
// protocol, so a request is eligible for at most one protocol.
function protocolMappingIsEligible(
  mapping: CredentialMapping,
  pathName: string,
  requestProtocol: () => CredentialProtocol | undefined,
): boolean {
  if (mapping.protocol === undefined) return false;
  if (mapping.pathPrefix !== undefined && !pathMatchesPrefix(pathName, mapping.pathPrefix)) return false;
  switch (mapping.protocol) {
    case "git-http":
    case "git-lfs":
      return requestProtocol() === mapping.protocol;
    default: {
      // A protocol added to the contract without a matcher here must fail
      // to compile; at runtime an unknown value is never eligible.
      const unknownProtocol: never = mapping.protocol;
      void unknownProtocol;
      return false;
    }
  }
}

// Selection is host-wide (one pass over every mapping of the host, whatever
// its header), in three steps:
//   (a) drop protocol-ineligible mappings (protocolMappingIsEligible): a
//       `git-http` mapping is eligible only on git smart-HTTP requests and a
//       `git-lfs` mapping only on Git LFS API requests;
//   (b) if any eligible mapping is protocol-scoped, keep only the
//       protocol-scoped ones (the protocol tier ranks above prefix length);
//   (c) the longest-pathPrefix rule, with unscoped-by-path mappings as the
//       fallback when no prefix matches.
// Validation allows at most one mapping per (host, header, protocol) and
// unique (protocol, pathPrefix) pairs, and the protocols' request sets are
// disjoint, so at most one mapping per header survives.
function selectedCredentialMappings(allMappings: CredentialMapping[], method: string, url: URL): CredentialMapping[] {
  const pathName = requestPath(url);
  const requestProtocol = lazyGitRequestProtocol(method, url);
  const eligible = allMappings.filter((mapping) => {
    if (mapping.protocol === undefined) return true;
    return protocolMappingIsEligible(mapping, pathName, requestProtocol);
  });
  const protocolScoped = eligible.filter((mapping) => mapping.protocol !== undefined);
  const mappings = protocolScoped.length > 0 ? protocolScoped : eligible;
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

// Decodes `%xx` to a fixed point like decodeToFixedPoint, but reports a
// string that is still changing at the iteration bound (or malformed) as
// undefined, so a caller that must match a name can fail closed instead of
// comparing a half-decoded form.
function decodeToConvergence(value: string): string | undefined {
  let current = value;
  for (let iteration = 0; iteration <= MAX_PATH_DECODE_ITERATIONS; iteration += 1) {
    let next: string;
    try {
      next = decodeURIComponent(current);
    } catch {
      return undefined;
    }
    if (next === current) return next;
    current = next;
  }
  return undefined;
}

// The segment half of canonicalPathSegments, factored out so a caller that
// already holds the converged decode (e.g. because it also needs to inspect
// it for a NUL) can reuse it instead of decoding the same path twice: cut at
// a NUL, split on `/` and `\`, each segment stripped of `;params` and
// trailing dots or whitespace, empty segments dropped, and lowercased.
function segmentsFromDecodedPath(decoded: string): string[] {
  const nul = decoded.indexOf("\0");
  return (nul === -1 ? decoded : decoded.slice(0, nul))
    .split(/[\\/]/u)
    .map((segment) => segment.split(";", 1)[0].replace(/[.\s]+$/u, "").toLowerCase())
    .filter((segment) => segment !== "");
}

// The name a routing origin may reduce a path's last segment to: decoded to a
// fixed point, then segmentsFromDecodedPath. Undefined when decoding does not
// converge.
function canonicalPathSegments(pathName: string): string[] | undefined {
  const decoded = decodeToConvergence(pathName);
  if (decoded === undefined) return undefined;
  return segmentsFromDecodedPath(decoded);
}

// The git-push decision is the only check that runs on a `{gitPush:"deny"}`-only
// host, and under `writeApproval: allow` the only check a push meets, so it must
// be self-contained against path confusion: any spelling a decoding or
// normalizing origin (git-http-backend, GitHub) may route to `git-receive-pack`
// is a push. It matches the canonical last segment, not a raw suffix, so a
// trailing `/`, `;param`, `.`, NUL, or encoded separator cannot hide it.
function isGitPushPath(url: URL, pathName: string): boolean {
  const segments = canonicalPathSegments(pathName);
  // Malformed or non-converging encoding on a push-denied host fails closed.
  if (segments === undefined) return true;
  const last = segments.at(-1);
  if (last === "git-receive-pack") return true;
  // Capability-probe form: GET .../info/refs?service=git-receive-pack. Every
  // `service` value counts, since an origin may read the last one, and so
  // does every parameter whose decoded, case-folded name is `service` (the
  // same set hasSingleLiteralGitService counts). A `;` anywhere in the query
  // is a push: an origin that also splits on `;` (Python's parse_qs before
  // 3.10, Perl CGI) may read a `service` this `&` split never sees, and a git
  // client never sends one, so failing closed costs real git nothing.
  if (last === "refs" && segments.at(-2) === "info") {
    const query = url.search.startsWith("?") ? url.search.slice(1) : url.search;
    if (query.includes(";")) return true;
    return query.split("&").some((pair) => {
      if (pair === "") return false;
      const separator = pair.indexOf("=");
      const name = decodeToConvergence((separator === -1 ? pair : pair.slice(0, separator)).replaceAll("+", " "));
      if (name === undefined) return true;
      if (name.trim().toLowerCase() !== "service") return false;
      const value = decodeToConvergence((separator === -1 ? "" : pair.slice(separator + 1)).replaceAll("+", " "));
      return value === undefined || value.trim().toLowerCase() === "git-receive-pack";
    });
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

// --- git smart HTTP / Git LFS request recognition (`git-http`, `git-lfs`) ---
//
// Decides whether a request is one of the git smart-HTTP requests a
// `protocol: "git-http"` credential may be attached to, or one of the Git LFS
// API requests a `protocol: "git-lfs"` credential may be attached to
// (GIT_REQUEST_KIND_PROTOCOL). The recognized shapes, each requiring at least
// one repository segment before the suffix (so `/info/refs` alone is not a git
// request):
//
//   git-http  refs         GET  …/info/refs?service=git-upload-pack|git-receive-pack
//             upload-pack  POST …/git-upload-pack
//             receive-pack POST …/git-receive-pack
//   git-lfs   lfs-batch    POST …/info/lfs/objects/batch
//             lfs-locks    GET  …/info/lfs/locks
//                          POST …/info/lfs/locks
//                          POST …/info/lfs/locks/verify
//                          POST …/info/lfs/locks/<id>/unlock   (raw id ^[A-Za-z0-9._-]+$)
//
// Methods are compared exactly (uppercase); HEAD, OPTIONS, and every other
// method are not eligible on any row (a git client never sends them, and the
// §4.2 table does not list them). It requires raw/decoded agreement: the
// path decodes to convergence with no NUL (a NUL would let
// segmentsFromDecodedPath hide a trailing segment an origin keeps routing
// past), carries
// no path confusion (encoded or literal separators, `..`), its canonical
// segments end with the endpoint, AND the raw lower-cased path's own trailing
// segments are literally the endpoint — so an encoded, `;param`-decorated,
// trailing-`/`, trailing-`.` or NUL-hidden spelling is not a git request and
// gets no credential. A path whose first canonical segment is `api`, or with
// a `-` canonical segment, is never a git request: GitLab serves its REST API
// under `/api/` and non-git routes after `/-/`, where a last segment can be a
// user-chosen name (`/api/v4/projects/<id>/repository/files/git-upload-pack`
// is the file API). That also excludes a github.com owner named `api`, on
// purpose: fail closed rather than guess per provider. isGitPushPath does not
// use this matcher, so those paths still count as pushes. The `info/refs` form needs exactly one query parameter
// whose (decoded, case-folded) name is `service`, spelled literally
// `service=<value>` in the raw query. Every POST form needs an empty query:
// git's remote-curl posts to `<remote>/git-upload-pack|git-receive-pack`
// and git-lfs posts batch and lock requests with their parameters in the
// JSON body, while an origin that merges query parameters over body
// parameters (Rails, so GitLab) would act on a query the proxy never read
// (e.g. `objects/batch?operation=upload` with a download body). Only the GET
// lock listing takes a query (git-lfs sends its path/id/cursor/limit/refspec
// filters there). Anything not recognized returns
// undefined: no credential, and write classification is unaffected.
export type GitHttpRequestKind = "refs" | "upload-pack" | "receive-pack" | "lfs-batch" | "lfs-locks";

// The credential protocol of each recognized git request kind. One matcher,
// one protocol per kind: git smart HTTP is `git-http`, the Git LFS batch and
// locks API is `git-lfs`, so the two protocols' request sets are disjoint by
// construction.
export const GIT_REQUEST_KIND_PROTOCOL: Readonly<Record<GitHttpRequestKind, CredentialProtocol>> = {
  refs: "git-http",
  "upload-pack": "git-http",
  "receive-pack": "git-http",
  "lfs-batch": "git-lfs",
  "lfs-locks": "git-lfs",
};

export function gitRequestProtocol(method: string, url: URL): CredentialProtocol | undefined {
  const kind = gitHttpRequestKind(method, url);
  return kind === undefined ? undefined : GIT_REQUEST_KIND_PROTOCOL[kind];
}

function lazyGitRequestProtocol(method: string, url: URL): () => CredentialProtocol | undefined {
  let computed = false;
  let protocol: CredentialProtocol | undefined;
  return () => {
    if (!computed) {
      protocol = gitRequestProtocol(method, url);
      computed = true;
    }
    return protocol;
  };
}

// The host's policy opts a request into Git LFS mediation when one of the
// host's mappings has `protocol: "git-lfs"` and is eligible for the request
// (it is a Git LFS API request under the mapping's pathPrefix, if any). Only
// then may an LFS download batch classify as a read: on a host without one
// (gitlab.com, whose batch response for a user carries a project-wide LFS
// token that can push) the batch stays a write.
export function lfsMediatedRequest(mappings: readonly CredentialMapping[] | undefined, method: string, url: URL): boolean {
  if (mappings === undefined || !mappings.some((mapping) => mapping.protocol === "git-lfs")) return false;
  const pathName = requestPath(url);
  const requestProtocol = lazyGitRequestProtocol(method, url);
  return mappings.some((mapping) => mapping.protocol === "git-lfs" && protocolMappingIsEligible(mapping, pathName, requestProtocol));
}

// Placeholder in an endpoint suffix for the LFS lock id segment.
const GIT_LFS_LOCK_ID = Symbol("lock-id");
const GIT_LFS_LOCK_ID_RE = /^[A-Za-z0-9._-]+$/u;
const GIT_REFS_SERVICES = new Set(["git-upload-pack", "git-receive-pack"]);

// What the query may carry: `service` is the info/refs rule
// (hasSingleLiteralGitService); `none` means url.search is empty; `any` is
// only the GET lock listing, whose filters git-lfs sends as query parameters.
type GitHttpEndpoint = {
  kind: GitHttpRequestKind;
  method: "GET" | "POST";
  suffix: ReadonlyArray<string | typeof GIT_LFS_LOCK_ID>;
  query: "service" | "none" | "any";
};

const GIT_HTTP_ENDPOINTS: readonly GitHttpEndpoint[] = [
  { kind: "refs", method: "GET", suffix: ["info", "refs"], query: "service" },
  { kind: "upload-pack", method: "POST", suffix: ["git-upload-pack"], query: "none" },
  { kind: "receive-pack", method: "POST", suffix: ["git-receive-pack"], query: "none" },
  { kind: "lfs-batch", method: "POST", suffix: ["info", "lfs", "objects", "batch"], query: "none" },
  { kind: "lfs-locks", method: "GET", suffix: ["info", "lfs", "locks"], query: "any" },
  { kind: "lfs-locks", method: "POST", suffix: ["info", "lfs", "locks"], query: "none" },
  { kind: "lfs-locks", method: "POST", suffix: ["info", "lfs", "locks", "verify"], query: "none" },
  { kind: "lfs-locks", method: "POST", suffix: ["info", "lfs", "locks", GIT_LFS_LOCK_ID, "unlock"], query: "none" },
];

// Exactly one query parameter names `service` (after decoding and ASCII case
// folding, so a `%73ervice` or `Service` duplicate an origin might read is
// counted), and that one is spelled raw as `service=git-upload-pack` or
// `service=git-receive-pack`. Malformed encoding in any name, or any `;` in
// the query, fails closed.
function hasSingleLiteralGitService(url: URL): boolean {
  const query = url.search.startsWith("?") ? url.search.slice(1) : url.search;
  // A `;` may split the query for some origins (see isGitPushPath).
  if (query === "" || query.includes(";")) return false;
  let literal = 0;
  let named = 0;
  for (const pair of query.split("&")) {
    if (pair === "") continue;
    const separator = pair.indexOf("=");
    const rawName = separator === -1 ? pair : pair.slice(0, separator);
    const decodedName = decodeToConvergence(rawName.replaceAll("+", " "));
    if (decodedName === undefined) return false;
    if (decodedName.trim().toLowerCase() !== "service") continue;
    named += 1;
    if (rawName === "service" && separator !== -1 && GIT_REFS_SERVICES.has(pair.slice(separator + 1))) literal += 1;
  }
  return named === 1 && literal === 1;
}

export function gitHttpRequestKind(method: string, url: URL): GitHttpRequestKind | undefined {
  const pathName = requestPath(url);
  if (hasPathConfusion(pathName)) return undefined;
  const decoded = decodeToConvergence(pathName);
  if (decoded === undefined || decoded.includes("\0")) return undefined;
  const canonical = segmentsFromDecodedPath(decoded);
  // No endpoint suffix contains `api` first or a `-` segment, so this is
  // the same as checking the segments before the suffix.
  if (canonical[0] === "api" || canonical.includes("-")) return undefined;
  const rawSegments = pathName.split("/");
  for (const endpoint of GIT_HTTP_ENDPOINTS) {
    if (endpoint.method !== method) continue;
    const length = endpoint.suffix.length;
    // At least one repository segment before the endpoint suffix.
    if (canonical.length <= length || rawSegments.length <= length + 1) continue;
    const rawTail = rawSegments.slice(-length);
    const canonicalTail = canonical.slice(-length);
    const matches = endpoint.suffix.every((expected, index) => {
      const raw = rawTail[index];
      if (expected === GIT_LFS_LOCK_ID) {
        // Unreserved characters only, so the raw id needs no decoding, and
        // the canonical form must not have altered it (e.g. trailing dots).
        return GIT_LFS_LOCK_ID_RE.test(raw) && canonicalTail[index] === raw.toLowerCase();
      }
      return raw.toLowerCase() === expected && canonicalTail[index] === expected;
    });
    if (!matches) continue;
    if (endpoint.query === "service" && !hasSingleLiteralGitService(url)) return undefined;
    if (endpoint.query === "none" && url.search !== "") return undefined;
    return endpoint.kind;
  }
  return undefined;
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
  // See PolicyOptions.oauthProtocolRead; assertWriteAllowed passes it only
  // for an `ask` host.
  oauthProtocolRead?: boolean;
  // See PolicyOptions.lfsBodyClass. Absent means unproven => write.
  lfsBodyClass?: "download";
  // lfsMediatedRequest for this request: the host's policy has an eligible
  // git-lfs mapping. Absent means no => an LFS batch stays a write.
  lfsMediated?: boolean;
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
    // An exact, mediated OAuth protocol exchange (login, refresh, client
    // registration). Runs after every write rule above, so an explicit write
    // path, git push, override header, or GraphQL rule still wins.
    if (input.oauthProtocolRead === true && input.method === "POST") return { write: false };
    if (rule?.readPathPrefixes !== undefined
      && rule.readPathPrefixes.some((prefix) => pathMatchesPrefix(pathName, prefix))) {
      return { write: false };
    }
    // git fetch negotiation (upload-pack) on a host that declares git
    // handling. It uses the shared matcher, so only the exact POST RPC path a
    // git client sends is a read: no encoded, decorated, NUL-hiding, or
    // query-carrying spelling, and no `api` or `-` route (see
    // gitHttpRequestKind). Push detection stays the separate, looser
    // isGitPushPath, which runs first.
    if (rule?.gitPush !== undefined && gitHttpRequestKind(input.method, input.url) === "upload-pack") {
      return { write: false };
    }
    // A Git LFS batch request proven by its body to be a download. Same host
    // gate as the upload-pack exemption (the host declares git handling),
    // plus the host's policy must opt into LFS mediation with a git-lfs
    // mapping eligible for the request (lfsMediatedRequest); the request must
    // be exactly POST on the canonical batch endpoint with an empty query
    // (gitHttpRequestKind), so a Rails origin cannot read an
    // `?operation=upload` the body classifier never saw. An upload
    // batch, an unproven body, a host without a git-lfs mapping, and every
    // lock request stay writes.
    if (rule?.gitPush !== undefined && input.method === "POST" && input.lfsBodyClass === "download"
      && input.lfsMediated === true && gitHttpRequestKind(input.method, input.url) === "lfs-batch") {
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
  lfsBodyClass?: "download";
  lfsMediated?: boolean;
  oauthProtocolRead?: boolean;
  oauthUnlistedClientIdUrl?: boolean;
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
  // An explicit `deny` stays a deny: the protocol read only spares `ask`.
  const classification = classifyWrite({
    ...input,
    oauthProtocolRead: input.writeAction === "ask" && input.oauthProtocolRead === true && input.webSocket !== true,
  });
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
      ...(input.oauthUnlistedClientIdUrl === true ? { oauthUnlistedClientIdUrl: true } : {}),
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
// It is body-free: no GraphQL or LFS body verdict is passed, so a held GraphQL
// or LFS batch request revalidates as the write it was held as.
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
    lfsBodyClass: options.lfsBodyClass,
    lfsMediated: options.lfsBodyClass === "download" && lfsMediatedRequest(credentials[host], req.method ?? "GET", url),
    oauthProtocolRead: options.oauthProtocolRead,
    oauthUnlistedClientIdUrl: options.oauthUnlistedClientIdUrl,
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

  const selectedMappings = selectedCredentialMappings(mappings, req.method ?? "GET", url);
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
