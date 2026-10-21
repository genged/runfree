import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  oauthHostRefusedForProvider,
  validateOAuthMediationPolicy,
  type LoadedOAuthMediationPolicy,
  type OAuthProviderPolicy,
  type OAuthRegistrationEndpoint,
  type OAuthSeed,
  type OAuthTokenEndpoint,
} from "@runfree/runtime-contracts/oauth-mediation-policy";
import { normalizeHostname, normalizePathPrefix, pathMatchesPrefix, readTokenFile } from "./policy.js";
import { isRecord } from "@runfree/runtime-contracts/primitives";
import { classifyGrantShape, responseCarriesOAuthSecret, type GrantShapeFinding, type GrantShapeScope } from "./oauth-grant-shape.js";
import { plainRequestPath, type ProtocolReadKind } from "./oauth-protocol-read.js";

const ACCESS_HANDLE_PREFIX = "runfree_oauth_access_";
const REFRESH_HANDLE_PREFIX = "runfree_oauth_refresh_";
const SECRET_HANDLE_PREFIX = "runfree_oauth_secret_";
const HANDLE_RE = /^runfree_oauth_(?:access|refresh|secret)_[A-Za-z0-9_-]{32,}$/;
const DEFAULT_STATE_DIR = "/run/runfree-oauth";
const STATE_FILE_NAME = "handles.json";

type HeaderValue = string | string[] | undefined;

export type OAuthProxyRequest = {
  body?: {
    // mockttp's raw buffered body, still content-encoded, exactly as it is
    // forwarded upstream. Test doubles may omit it and supply getText only.
    buffer?: Buffer;
    getText(): Promise<string | undefined>;
  };
  headers?: Record<string, HeaderValue>;
  id?: string;
  method?: string;
  url: string;
};

export type OAuthProxyResponse = {
  body: {
    buffer?: Buffer;
    getText(): Promise<string | undefined>;
  };
  headers?: Record<string, HeaderValue>;
  statusCode: number;
};

export type OAuthRequestResult = {
  body?: string;
  headers?: Record<string, HeaderValue>;
  response?: {
    statusCode: number;
    headers: Record<string, string>;
    body: string;
  };
};

export type OAuthResponseResult = {
  body?: string;
  headers?: Record<string, HeaderValue>;
};

type TokenEndpoint = OAuthTokenEndpoint;

type McpOAuthServerPolicy = {
  // User (`--oauth-host`) hosts: binding hosts for run-time capture.
  bindingHosts: string[];
  // False for a share-group non-owner, which never captures metadata.
  captureOwner: boolean;
  kind: "mcp" | "service";
  metadataEndpoints: TokenEndpoint[];
  name: string;
  protocolReadEndpoints: TokenEndpoint[];
  registrationEndpoints: OAuthRegistrationEndpoint[];
  resourceHost: string;
  resourcePathPrefix: string;
  seeds: OAuthSeed[];
  stateEpoch?: string;
  tokenEndpoints: TokenEndpoint[];
};

type LoadedMcpOAuthPolicy = {
  blockedEndpoints: TokenEndpoint[];
  policyPath?: string;
  recordEndpointHosts: string[];
  recordOnlyHosts: string[];
  refusedHosts: string[];
  servers: McpOAuthServerPolicy[];
};

function emptyPolicy(policyPath?: string): LoadedMcpOAuthPolicy {
  return {
    blockedEndpoints: [],
    ...(policyPath !== undefined ? { policyPath } : {}),
    recordEndpointHosts: [],
    recordOnlyHosts: [],
    refusedHosts: [],
    servers: [],
  };
}

type CurrentMcpOAuthPolicy = {
  policy: LoadedMcpOAuthPolicy;
  valid: boolean;
};

type StoredToken = {
  createdAt: string;
  endpointKind?: "registration" | "token";
  expiresAt?: string;
  field?: string;
  handle: string;
  projectId: string;
  resourceHost: string;
  resourcePathPrefix: string;
  secretRef?: string;
  serverName: string;
  // The provider's state epoch when the handle was minted. A handle whose
  // epoch differs from the current policy's is deleted at activation and
  // refused at use (`runfree mcp revoke` publishes a new epoch).
  stateEpoch?: string;
  token?: string;
  tokenEndpointHost: string;
  tokenEndpointPath: string;
  type: "access" | "refresh" | "secret";
};

type StoredDiscoveryEntry = {
  issuerHosts?: string[];
  registrationEndpoints?: TokenEndpoint[];
  stateEpoch?: string;
  tokenEndpoints?: TokenEndpoint[];
};

type StoredDiscovery = Record<string, StoredDiscoveryEntry>;

type StoredMcpOAuthState = {
  discovered?: StoredDiscovery;
  handles?: Record<string, StoredToken>;
};

// A POST the mediator may treat as an OAuth protocol read: its exact path is
// one of this provider's recorded, statically mediated endpoints, and this
// provider alone would mediate it.
export type ProtocolReadMatch = {
  kind: ProtocolReadKind;
  provider: string;
  resourceHost: string;
};

export type OAuthBeforeRequestOptions = {
  // False for a host outside the allowlist (an audited host). The rule that
  // refuses grant-shaped requests to any host while the OAuth policy is
  // invalid covers allowlisted hosts only. Absent means allowlisted.
  allowlisted?: boolean;
  // Which proxy rule the request selected: true for the response-mediating
  // rule. The rule is chosen before the request is handled, so a policy or
  // discovery change in between can leave a now-mediated token request on the
  // plain rule, whose response would reach the agent unmediated.
  responseMediated?: boolean;
  // The protocol-read match the write classification relied on; re-checked
  // before any handle is swapped.
  protocolRead?: ProtocolReadMatch;
};

// Why the proxy refused an OAuth-shaped request that no provider mediates.
// `target` says which rule applied: a host only MCP records allow, a host a
// record names that also serves an MCP endpoint, a host-owned blocked
// endpoint, an endpoint more than one provider claims, or any allowlisted
// host while the OAuth policy is invalid.
//
// A WebSocket upgrade is refused outright (finding `websocket`) where the
// proxy guards OAuth: mockttp hands a non-101 upstream reply straight back to
// the agent, and no rule can read it. `mediated-endpoint` is a WebSocket
// upgrade to an endpoint a provider mediates for HTTPS requests only.
export type UnmediatedOAuthRequestRefusal = {
  finding: GrantShapeFinding | { kind: "websocket" };
  host: string;
  path: string;
  // The providers involved, when known: the colliding claimants, or the MCP
  // providers whose user hosts include this host.
  providers: string[];
  target: "blocked-endpoint" | "endpoint-collision" | "mediated-endpoint" | "policy-unavailable" | "record-endpoint-host" | "record-only-host";
};

export type OAuthIssuerDenialContext = {
  providerId: string;
  resourceHost: string;
};

type SensitiveOAuthRequest = {
  createdAtMs: number;
  endpoint: TokenEndpoint;
  kind: "registration" | "token";
  // The refresh handle swapped into this request, retired on rotation.
  refreshHandle?: string;
  server: McpOAuthServerPolicy;
};

// A request whose response never arrives (upstream error, client abort)
// leaves its entry behind; bound the map by age and size.
const PENDING_MAX_AGE_MS = 10 * 60 * 1000;
const PENDING_MAX_ENTRIES = 1024;
// Per-provider handle cap: repeated exchanges cannot grow the state file
// without bound. The oldest handles go first.
const MAX_HANDLES_PER_PROVIDER = 256;
const MAX_REGISTRATION_HANDLES_PER_PROVIDER = 32;


function firstHeader(value: HeaderValue): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

function headerValue(headers: Record<string, HeaderValue> | undefined, name: string): string | undefined {
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (key.toLowerCase() === lower) return firstHeader(value);
  }
  return undefined;
}

// Shared with server.ts: replace every case variant of a header with one
// lowercase-named value, returning a new map.
export function setHeader(headers: Record<string, HeaderValue>, name: string, value: string): Record<string, HeaderValue> {
  const next = { ...headers };
  for (const key of Object.keys(next)) {
    if (key.toLowerCase() === name.toLowerCase()) delete next[key];
  }
  next[name.toLowerCase()] = value;
  return next;
}

function stripContentLength(headers: Record<string, HeaderValue>): Record<string, HeaderValue> {
  const next = { ...headers };
  for (const key of Object.keys(next)) {
    if (key.toLowerCase() === "content-length") delete next[key];
  }
  return next;
}

function parseUrl(value: string): URL | undefined {
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}

function tokenEndpointFromUrl(value: unknown): TokenEndpoint | undefined {
  if (typeof value !== "string") return undefined;
  const parsed = parseUrl(value);
  if (!parsed || parsed.protocol !== "https:") return undefined;
  return {
    host: normalizeHostname(parsed.hostname),
    path: normalizePathPrefix(parsed.pathname || "/"),
  };
}

function serverPolicyFromProvider(provider: OAuthProviderPolicy): McpOAuthServerPolicy {
  return {
    bindingHosts: provider.bindingHosts,
    captureOwner: provider.captureOwner !== false,
    kind: provider.kind,
    metadataEndpoints: provider.metadataEndpoints,
    name: provider.providerId,
    protocolReadEndpoints: provider.protocolReadEndpoints,
    registrationEndpoints: provider.registrationEndpoints,
    resourceHost: provider.resourceHost,
    resourcePathPrefix: provider.resourcePathPrefix,
    seeds: provider.seeds,
    ...(provider.stateEpoch !== undefined ? { stateEpoch: provider.stateEpoch } : {}),
    tokenEndpoints: provider.tokenEndpoints,
  };
}

function loadPolicy(policyPath: string | undefined): LoadedMcpOAuthPolicy {
  if (!policyPath) return emptyPolicy();
  const raw = JSON.parse(fs.readFileSync(policyPath, "utf8")) as unknown;
  const loaded = validateOAuthMediationPolicy(raw, policyPath);
  return mediatorPolicy(loaded);
}

function mediatorPolicy(loaded: LoadedOAuthMediationPolicy): LoadedMcpOAuthPolicy {
  return {
    blockedEndpoints: loaded.blockedEndpoints,
    ...(loaded.policyPath ? { policyPath: loaded.policyPath } : {}),
    recordEndpointHosts: loaded.recordEndpointHosts,
    recordOnlyHosts: loaded.recordOnlyHosts,
    refusedHosts: loaded.refusedHosts,
    servers: loaded.providers.map(serverPolicyFromProvider),
  };
}

function readState(stateFile: string): StoredMcpOAuthState {
  try {
    const parsed = JSON.parse(fs.readFileSync(stateFile, "utf8")) as unknown;
    return isRecord(parsed) ? parsed as StoredMcpOAuthState : {};
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return {};
    throw error;
  }
}

function writeState(stateFile: string, state: StoredMcpOAuthState): void {
  fs.mkdirSync(path.dirname(stateFile), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.dirname(stateFile), 0o700);
  const tmpPath = `${stateFile}.${process.pid}.tmp`;
  fs.writeFileSync(tmpPath, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(tmpPath, stateFile);
  fs.chmodSync(stateFile, 0o600);
}

function randomHandle(type: "access" | "refresh" | "secret"): string {
  const prefix = type === "access" ? ACCESS_HANDLE_PREFIX : type === "refresh" ? REFRESH_HANDLE_PREFIX : SECRET_HANDLE_PREFIX;
  return `${prefix}${crypto.randomBytes(24).toString("base64url")}`;
}

function isRunfreeHandle(value: string): boolean {
  return HANDLE_RE.test(value);
}

function bearerHandle(headers: Record<string, HeaderValue> | undefined): string | undefined {
  const authorization = headerValue(headers, "authorization");
  const match = /^Bearer\s+(runfree_oauth_(?:access|refresh|secret)_[A-Za-z0-9_-]+)$/i.exec(authorization ?? "");
  return match?.[1];
}

export function hasOAuthBearerHandle(headers: Record<string, HeaderValue> | undefined): boolean {
  return bearerHandle(headers) !== undefined;
}

// True when the Authorization header carries any Runfree OAuth handle: a
// Bearer access/registration handle, or a client_secret_basic password handle.
// Credential-header stripping uses this to preserve the handle so the mediator
// can swap or reject it — without this, a configured Authorization credential on
// the same host as an MCP token endpoint would clobber the handle before
// mediation runs.
export function hasOAuthAuthorizationHandle(headers: Record<string, HeaderValue> | undefined): boolean {
  if (bearerHandle(headers) !== undefined) return true;
  const credentials = decodeBasicCredentials(headerValue(headers, "authorization"));
  if (!credentials) return false;
  if (isRunfreeHandle(credentials.secret)) return true;
  try {
    return isRunfreeHandle(decodeURIComponent(credentials.secret));
  } catch {
    return false;
  }
}

function parseBodyAsJson(body: string): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(body) as unknown;
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function tokenEndpointMatches(endpoint: TokenEndpoint, url: URL): boolean {
  return endpoint.host === url.hostname.toLowerCase() && url.pathname === endpoint.path;
}

function storedTokenEndpointMatches(token: StoredToken, endpoint: TokenEndpoint): boolean {
  return token.tokenEndpointHost === endpoint.host && token.tokenEndpointPath === endpoint.path;
}

// Absent epochs compare equal, so state from before epochs existed survives
// until its provider's first revoke publishes one.
function sameStateEpoch(stored: string | undefined, current: string | undefined): boolean {
  return (stored ?? "") === (current ?? "");
}

function storedTokenMatchesCurrentServer(token: StoredToken, server: McpOAuthServerPolicy): boolean {
  return token.resourceHost === server.resourceHost
    && token.resourcePathPrefix === server.resourcePathPrefix
    && sameStateEpoch(token.stateEpoch, server.stateEpoch);
}

// The discovered entry for a server, only when it was recorded under the
// server's current state epoch: an entry from before a revoke never binds.
function discoveredEntry(server: McpOAuthServerPolicy, state: StoredMcpOAuthState): StoredDiscoveryEntry | undefined {
  const entry = state.discovered?.[server.name];
  return entry && sameStateEpoch(entry.stateEpoch, server.stateEpoch) ? entry : undefined;
}

function pruneStateForPolicy(state: StoredMcpOAuthState, policy: LoadedMcpOAuthPolicy): boolean {
  let changed = false;
  const servers = new Map(policy.servers.map((server) => [server.name, server]));
  for (const [handle, token] of Object.entries(state.handles ?? {})) {
    const server = servers.get(token.serverName);
    if (!server || !storedTokenMatchesCurrentServer(token, server)) {
      delete state.handles?.[handle];
      changed = true;
    }
  }
  for (const [name, entry] of Object.entries(state.discovered ?? {})) {
    const server = servers.get(name);
    if (!server || !sameStateEpoch(entry.stateEpoch, server.stateEpoch)) {
      delete state.discovered?.[name];
      changed = true;
    }
  }
  return changed;
}

function pendingServerStillCurrent(pending: McpOAuthServerPolicy, policy: LoadedMcpOAuthPolicy): boolean {
  const current = policy.servers.find((server) => server.name === pending.name);
  return current !== undefined && sameStateEpoch(pending.stateEpoch, current.stateEpoch);
}

function resourceMatches(server: McpOAuthServerPolicy, url: URL): boolean {
  const pathName = url.pathname || "/";
  return server.resourceHost === url.hostname.toLowerCase()
    && pathMatchesPrefix(pathName, server.resourcePathPrefix);
}

function storedTokenExpired(token: StoredToken, now: Date): boolean {
  return token.expiresAt !== undefined && Date.parse(token.expiresAt) <= now.getTime();
}

function forbidden(reason: string): OAuthRequestResult {
  return {
    response: {
      statusCode: 403,
      headers: { "content-type": "text/plain" },
      body: `blocked by OAuth proxy policy\nreason: ${reason}\n`,
    },
  };
}

function blockedTokenEndpointResponse(reason: string, headers: Record<string, HeaderValue> | undefined): OAuthResponseResult {
  return {
    body: `blocked by OAuth proxy policy\nreason: ${reason}\n`,
    headers: stripContentLength(setHeader(headers ?? {}, "content-type", "text/plain")),
  };
}

function safeTokenEndpoint(url: URL): TokenEndpoint {
  return {
    host: url.hostname.toLowerCase(),
    path: url.pathname || "/",
  };
}

function tokenEndpointList(server: McpOAuthServerPolicy, state: StoredMcpOAuthState): TokenEndpoint[] {
  const discovered = discoveredEntry(server, state)?.tokenEndpoints ?? [];
  return [
    ...server.tokenEndpoints,
    ...discovered,
  ];
}

function registrationEndpointList(server: McpOAuthServerPolicy, state: StoredMcpOAuthState): OAuthRegistrationEndpoint[] {
  const discovered = discoveredEntry(server, state)?.registrationEndpoints ?? [];
  return [
    ...server.registrationEndpoints,
    ...discovered,
  ];
}

// Hosts a server's discovered endpoints may legitimately point at: the MCP
// resource host, the user (`--oauth-host`) hosts the record names, plus any
// statically-configured (host-trusted) metadata, token, or registration hosts. Discovered endpoints are deliberately excluded so one
// runtime-discovered endpoint cannot bootstrap trust for an unrelated one. This
// bounds the "resource-host metadata names an unrelated host for token relay"
// attack: a discovered token/registration endpoint outside this set is ignored.
function serverBindingHosts(server: McpOAuthServerPolicy): Set<string> {
  const hosts = new Set<string>([server.resourceHost, ...server.bindingHosts]);
  for (const endpoint of [...server.metadataEndpoints, ...server.tokenEndpoints, ...server.registrationEndpoints]) {
    hosts.add(endpoint.host);
  }
  return hosts;
}

// Issuer hosts this resource declared for itself via RFC 9728 protected-resource
// metadata served from its own resource host. These are added to the binding set
// so a legitimately-delegated, off-resource-host authorization server's endpoints
// can be mediated — but only because the resource server itself named them.
function discoveredIssuerHosts(server: McpOAuthServerPolicy, state: StoredMcpOAuthState): string[] {
  return discoveredEntry(server, state)?.issuerHosts ?? [];
}

function effectiveBindingHosts(server: McpOAuthServerPolicy, state: StoredMcpOAuthState): Set<string> {
  const hosts = serverBindingHosts(server);
  for (const issuer of discoveredIssuerHosts(server, state)) hosts.add(issuer);
  return hosts;
}

// RFC 8414: an authorization server's `issuer` value must identify the server the
// metadata was fetched from. Require the issuer to be HTTPS and on the same host
// before trusting endpoints advertised by a cross-host issuer's metadata.
function issuerSelfConsistent(issuer: unknown, host: string): boolean {
  if (typeof issuer !== "string") return false;
  const parsed = parseUrl(issuer);
  return parsed?.protocol === "https:" && parsed.hostname.toLowerCase() === host;
}

// A registration endpoint matches by path prefix (the registration client
// URI sits under it), unless it is flagged exact: a cross-host registration
// claim never widens response mediation to a subtree.
function registrationEndpointMatches(endpoint: OAuthRegistrationEndpoint, url: URL): boolean {
  if (endpoint.host !== url.hostname.toLowerCase()) return false;
  const pathName = url.pathname || "/";
  return endpoint.exact === true ? pathName === endpoint.path : pathMatchesPrefix(pathName, endpoint.path);
}

// Who claims a token or registration URL. Exactly one claimant mediates it.
// More than one (a run-time discovery that collides with another provider's
// endpoint) mediates none: the endpoint is blocked like a host-owned blocked
// endpoint, so neither provider can capture the other's tokens. No claimant
// and a host-owned `blockedEndpoints` entry is blocked. Static and bound
// endpoints therefore always match before the block.
type EndpointClaim =
  | { kind: "mediated"; endpointKind: "registration" | "token"; server: McpOAuthServerPolicy }
  | { kind: "collision"; servers: McpOAuthServerPolicy[] }
  | { kind: "blocked" };

function endpointClaim(policy: LoadedMcpOAuthPolicy, state: StoredMcpOAuthState, url: URL): EndpointClaim | undefined {
  const tokenClaimants = policy.servers.filter((server) => {
    return tokenEndpointList(server, state).some((endpoint) => tokenEndpointMatches(endpoint, url));
  });
  const registrationClaimants = policy.servers.filter((server) => {
    return registrationEndpointList(server, state).some((endpoint) => registrationEndpointMatches(endpoint, url));
  });
  const claimants = [...new Set([...tokenClaimants, ...registrationClaimants])];
  if (claimants.length > 1) return { kind: "collision", servers: claimants };
  if (claimants.length === 1) {
    const server = claimants[0];
    return { kind: "mediated", endpointKind: tokenClaimants.includes(server) ? "token" : "registration", server };
  }
  if (policy.blockedEndpoints.some((endpoint) => tokenEndpointMatches(endpoint, url))) return { kind: "blocked" };
  return undefined;
}

function matchingTokenServer(policy: LoadedMcpOAuthPolicy, state: StoredMcpOAuthState, url: URL): McpOAuthServerPolicy | undefined {
  const claim = endpointClaim(policy, state, url);
  return claim?.kind === "mediated" && claim.endpointKind === "token" ? claim.server : undefined;
}

function matchingRegistrationServer(policy: LoadedMcpOAuthPolicy, state: StoredMcpOAuthState, url: URL): McpOAuthServerPolicy | undefined {
  const claim = endpointClaim(policy, state, url);
  return claim?.kind === "mediated" && claim.endpointKind === "registration" ? claim.server : undefined;
}

// A blocked or colliding endpoint: on the response-mediating rule, with no
// provider that mediates it.
function endpointBlocked(policy: LoadedMcpOAuthPolicy, state: StoredMcpOAuthState, url: URL): boolean {
  const claim = endpointClaim(policy, state, url);
  return claim?.kind === "blocked" || claim?.kind === "collision";
}

// A host that carries a blocked or colliding endpoint. Endpoint matching is
// by exact path, but many routers also serve `/oauth/token/`,
// `/OAuth/token`, or `/oauth/%74oken`, which would take the plain rule; so
// the whole host gets a lenient deep scan for grant shapes.
function hostBlockOrCollision(
  policy: LoadedMcpOAuthPolicy,
  state: StoredMcpOAuthState,
  host: string,
): { kind: "blocked" } | { kind: "collision"; servers: McpOAuthServerPolicy[] } | undefined {
  const paths = new Set<string>();
  for (const server of policy.servers) {
    for (const endpoint of [...tokenEndpointList(server, state), ...registrationEndpointList(server, state)]) {
      if (endpoint.host === host) paths.add(endpoint.path);
    }
  }
  for (const endpointPath of paths) {
    const url = parseUrl(`https://${host}${endpointPath}`);
    const claim = url ? endpointClaim(policy, state, url) : undefined;
    if (claim?.kind === "collision") return claim;
  }
  return policy.blockedEndpoints.some((endpoint) => endpoint.host === host) ? { kind: "blocked" } : undefined;
}

// A share-group non-owner (`captureOwner: false`) never captures metadata:
// exactly one provider per shared server records its discoveries.
function matchingMetadataServer(policy: LoadedMcpOAuthPolicy, state: StoredMcpOAuthState, url: URL): McpOAuthServerPolicy | undefined {
  if (!url.pathname.includes("/.well-known/")) return undefined;
  const host = url.hostname.toLowerCase();
  return policy.servers.find((server) => {
    if (!server.captureOwner) return false;
    return server.metadataEndpoints.some((endpoint) => tokenEndpointMatches(endpoint, url))
      || server.resourceHost === host
      || discoveredIssuerHosts(server, state).includes(host);
  });
}

// The server's discovered entry for writing: an entry from another state
// epoch is replaced, never extended.
function writableDiscoveredEntry(state: StoredMcpOAuthState, server: McpOAuthServerPolicy): StoredDiscoveryEntry {
  state.discovered ??= {};
  const current = discoveredEntry(server, state);
  if (current) return current;
  const fresh: StoredDiscoveryEntry = server.stateEpoch !== undefined ? { stateEpoch: server.stateEpoch } : {};
  state.discovered[server.name] = fresh;
  return fresh;
}

function rememberIssuerHost(state: StoredMcpOAuthState, server: McpOAuthServerPolicy, host: string): boolean {
  const entry = writableDiscoveredEntry(state, server);
  const hosts = entry.issuerHosts ?? [];
  if (hosts.includes(host)) return false;
  entry.issuerHosts = [...hosts, host].sort();
  return true;
}

function sameEndpoint(left: TokenEndpoint, right: TokenEndpoint): boolean {
  return left.host === right.host && left.path === right.path;
}

// Hosts where another provider's tokens pass: every other provider's
// resource host, user binding hosts, and static metadata, token, and
// registration hosts. A server's metadata may not bind an issuer or an
// endpoint there, unless the host is in its own static binding set (its own
// resource host, its own user hosts, its own host-trusted static endpoints).
function otherProviderHostOwners(policy: LoadedMcpOAuthPolicy, server: McpOAuthServerPolicy, host: string): string[] {
  if (serverBindingHosts(server).has(host)) return [];
  return policy.servers
    .filter((other) => other !== server && serverBindingHosts(other).has(host))
    .map((other) => other.name);
}

function endpointsOverlap(
  left: OAuthRegistrationEndpoint & { prefix: boolean },
  right: OAuthRegistrationEndpoint & { prefix: boolean },
): boolean {
  if (left.host !== right.host) return false;
  return left.path === right.path
    || (left.prefix && pathMatchesPrefix(right.path, left.path))
    || (right.prefix && pathMatchesPrefix(left.path, right.path));
}

// Other providers whose static or discovered token or registration endpoint
// equals or overlaps (by registration prefix) this candidate.
function collidingProviders(
  policy: LoadedMcpOAuthPolicy,
  state: StoredMcpOAuthState,
  server: McpOAuthServerPolicy,
  candidate: TokenEndpoint,
  field: "registrationEndpoints" | "tokenEndpoints",
): string[] {
  const subject = { ...candidate, prefix: field === "registrationEndpoints" };
  return policy.servers
    .filter((other) => other !== server)
    .filter((other) => {
      return tokenEndpointList(other, state).some((endpoint) => endpointsOverlap(subject, { ...endpoint, prefix: false }))
        || registrationEndpointList(other, state).some((endpoint) => endpointsOverlap(subject, { ...endpoint, prefix: endpoint.exact !== true }));
    })
    .map((other) => other.name);
}

function rememberEndpoint(
  state: StoredMcpOAuthState,
  server: McpOAuthServerPolicy,
  endpoint: TokenEndpoint,
  field: "registrationEndpoints" | "tokenEndpoints",
): boolean {
  const entry = writableDiscoveredEntry(state, server);
  const endpoints = entry[field] ?? [];
  if (endpoints.some((existing) => sameEndpoint(existing, endpoint))) return false;
  entry[field] = [...endpoints, endpoint].sort((left, right) => `${left.host}\0${left.path}`.localeCompare(`${right.host}\0${right.path}`));
  return true;
}

function cloneJsonTokenResponse(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value));
}

function expiresAtFromResponse(value: Record<string, unknown>, now: Date): string | undefined {
  const expiresIn = value.expires_in;
  if (typeof expiresIn !== "number" || !Number.isFinite(expiresIn) || expiresIn <= 0) return undefined;
  return new Date(now.getTime() + Math.floor(expiresIn) * 1000).toISOString();
}

function storeHandle(
  state: StoredMcpOAuthState,
  options: {
    now: Date;
    projectId: string;
    server: McpOAuthServerPolicy;
    token: string;
    tokenEndpoint: TokenEndpoint;
    endpointKind: "registration" | "token";
    type: "access" | "refresh" | "secret";
    expiresAt?: string;
    field?: string;
  },
): string {
  state.handles ??= {};
  let handle: string;
  do {
    handle = randomHandle(options.type);
  } while (state.handles[handle]);
  state.handles[handle] = {
    createdAt: options.now.toISOString(),
    endpointKind: options.endpointKind,
    ...(options.expiresAt ? { expiresAt: options.expiresAt } : {}),
    ...(options.field ? { field: options.field } : {}),
    handle,
    projectId: options.projectId,
    resourceHost: options.server.resourceHost,
    resourcePathPrefix: options.server.resourcePathPrefix,
    serverName: options.server.name,
    ...(options.server.stateEpoch !== undefined ? { stateEpoch: options.server.stateEpoch } : {}),
    token: options.token,
    tokenEndpointHost: options.tokenEndpoint.host,
    tokenEndpointPath: options.tokenEndpoint.path,
    type: options.type,
  };
  capProviderHandles(state, options.server.name, handle, options.now);
  return handle;
}

// Bounds one provider's handles so repeated exchanges cannot grow the state
// without limit, without breaking a long-lived client: expired access
// handles go first; token-response handles are capped at 256, oldest first,
// never the newest refresh handle; registration handles (the client secret
// and registration access token a confidential client keeps using) have
// their own cap of 32.
function capProviderHandles(state: StoredMcpOAuthState, serverName: string, newHandle: string, now: Date): void {
  const handles = state.handles ?? {};
  const byAge = (left: StoredToken, right: StoredToken) => left.createdAt.localeCompare(right.createdAt);
  for (const token of Object.values(handles)) {
    if (token.serverName === serverName && token.handle !== newHandle && token.type === "access" && storedTokenExpired(token, now)) {
      delete handles[token.handle];
    }
  }
  const own = Object.values(handles).filter((token) => token.serverName === serverName);
  const registration = own.filter((token) => token.endpointKind === "registration").sort(byAge);
  const tokens = own.filter((token) => token.endpointKind !== "registration").sort(byAge);
  const newestRefresh = tokens.filter((token) => token.type === "refresh").at(-1)?.handle;
  const evict = (list: StoredToken[], max: number, keep: Set<string | undefined>) => {
    let excess = list.length - max;
    for (const token of list) {
      if (excess <= 0) break;
      if (keep.has(token.handle)) continue;
      delete handles[token.handle];
      excess -= 1;
    }
  };
  evict(registration, MAX_REGISTRATION_HANDLES_PER_PROVIDER, new Set([newHandle]));
  evict(tokens, MAX_HANDLES_PER_PROVIDER, new Set([newHandle, newestRefresh]));
}

// A response on the response-mediating rule that no server mediates: a
// revoke or reload landed while it was in flight, or the endpoint is blocked
// (a host-owned blocked endpoint, or one more than one provider claims). Real
// tokens in it must not reach the agent, at any status and at any depth of
// the body. A body that does not decode is blocked too: what it carries
// cannot be proven harmless.
function unmediatedTokenResponse(
  text: string | undefined,
  rawLength: number,
  headers: Record<string, HeaderValue> | undefined,
): OAuthResponseResult | undefined {
  if (text === undefined) {
    return rawLength > 0
      ? blockedTokenEndpointResponse("undecodable response from an OAuth endpoint the proxy does not mediate", headers)
      : undefined;
  }
  return responseCarriesOAuthSecret(text)
    ? blockedTokenEndpointResponse("OAuth token response from an endpoint that is no longer mediated, or never was", headers)
    : undefined;
}

async function requestBodyFromText(req: OAuthProxyRequest): Promise<Buffer | undefined> {
  if (!req.body) return undefined;
  let text: string | undefined;
  try {
    text = await req.body.getText();
  } catch {
    text = undefined;
  }
  return text === undefined ? undefined : Buffer.from(text, "utf8");
}

function tokenTypeForSeed(seed: OAuthSeed): "refresh" | "secret" {
  return seed.field === "refresh_token" ? "refresh" : "secret";
}

function seedTokenForHandle(
  policy: LoadedMcpOAuthPolicy,
  projectId: string,
  tokenDir: string | undefined,
  handle: string,
): StoredToken | undefined {
  if (!isRunfreeHandle(handle)) return undefined;
  for (const server of policy.servers) {
    for (const seed of server.seeds) {
      if (seed.handle !== handle) continue;
      const tokenEndpoint = server.tokenEndpoints[0];
      if (!tokenEndpoint) return undefined;
      return {
        createdAt: "policy-seed",
        endpointKind: "token",
        field: seed.field,
        handle,
        projectId,
        resourceHost: server.resourceHost,
        resourcePathPrefix: server.resourcePathPrefix,
        secretRef: seed.secretRef,
        serverName: server.name,
        token: readTokenFile(seed.secretRef, tokenDir) ?? undefined,
        tokenEndpointHost: tokenEndpoint.host,
        tokenEndpointPath: tokenEndpoint.path,
        type: tokenTypeForSeed(seed),
      };
    }
  }
  return undefined;
}

function tokenValue(token: StoredToken): string | undefined {
  return token.token;
}

function contentType(headers: Record<string, HeaderValue> | undefined): string {
  return (headerValue(headers, "content-type") ?? "").toLowerCase();
}

function requestHasJsonContent(headers: Record<string, HeaderValue> | undefined): boolean {
  return contentType(headers).includes("application/json");
}

function requestHasFormContent(headers: Record<string, HeaderValue> | undefined): boolean {
  return contentType(headers).includes("application/x-www-form-urlencoded");
}

function replaceRefreshHandleInForm(body: string, token: StoredToken): string | undefined {
  const value = tokenValue(token);
  if (!value) return undefined;
  const params = new URLSearchParams(body);
  if (params.get("grant_type") !== "refresh_token") return undefined;
  if (params.get("refresh_token") !== token.handle) return undefined;
  params.set("refresh_token", value);
  return params.toString();
}

function replaceRefreshHandleInJson(body: string, token: StoredToken): string | undefined {
  const value = tokenValue(token);
  if (!value) return undefined;
  const parsed = parseBodyAsJson(body);
  if (!parsed || parsed.grant_type !== "refresh_token" || parsed.refresh_token !== token.handle) return undefined;
  return JSON.stringify({ ...parsed, refresh_token: value });
}

function secretHandleAllowedForEndpoint(
  token: StoredToken,
  server: McpOAuthServerPolicy,
  state: StoredMcpOAuthState,
  tokenEndpoint: TokenEndpoint,
): boolean {
  if (storedTokenEndpointMatches(token, tokenEndpoint)) return true;
  return token.field === "client_secret"
    && token.endpointKind === "registration"
    && storedTokenMatchesCurrentServer(token, server)
    && registrationEndpointList(server, state).some((endpoint) => storedTokenEndpointMatches(token, endpoint));
}

type SecretHandleReplacement = {
  body?: string;
  error?: string;
};

function sensitiveOauthResponseFields(value: Record<string, unknown>): string[] {
  return Object.entries(value)
    .filter(([key, entry]) => {
      return typeof entry === "string"
        && entry !== ""
        && [
          "access_token",
          "refresh_token",
          "id_token",
          "client_secret",
          "registration_access_token",
        ].includes(key);
    })
    .map(([key]) => key);
}

// Validate that a runfree secret handle the agent presented (in a token-exchange
// body field or the Authorization: Basic password) may be exchanged for the real
// upstream secret at this endpoint. Returns an error string to reject before the
// secret leaves the proxy; undefined means the swap is authorized. `field` is the
// OAuth field the handle stands in for (e.g. "client_secret"); a handle minted for
// a different field, server, project, or endpoint is refused, never forwarded.
function secretHandleError(
  token: StoredToken | undefined,
  field: string,
  server: McpOAuthServerPolicy,
  state: StoredMcpOAuthState,
  projectId: string,
  tokenEndpoint: TokenEndpoint,
): string | undefined {
  if (!token || token.type !== "secret" || token.field !== field) {
    return "unknown OAuth secret handle";
  }
  if (!tokenValue(token)) {
    return "OAuth seed secret unavailable";
  }
  if (token.projectId !== projectId || token.serverName !== server.name) {
    return "OAuth secret handle used for the wrong token endpoint";
  }
  if (!storedTokenMatchesCurrentServer(token, server) || !secretHandleAllowedForEndpoint(token, server, state, tokenEndpoint)) {
    return "OAuth secret handle used for the wrong token endpoint";
  }
  return undefined;
}

function replaceSecretHandlesInForm(
  body: string,
  readHandle: (handle: string) => StoredToken | undefined,
  state: StoredMcpOAuthState,
  server: McpOAuthServerPolicy,
  projectId: string,
  tokenEndpoint: TokenEndpoint,
): SecretHandleReplacement {
  const params = new URLSearchParams(body);
  let changed = false;
  for (const [key, value] of Array.from(params.entries())) {
    if (!isRunfreeHandle(value)) continue;
    const token = readHandle(value);
    const error = secretHandleError(token, key, server, state, projectId, tokenEndpoint);
    const secretValue = token ? tokenValue(token) : undefined;
    if (error || !token || !secretValue) return { error: error ?? "unknown OAuth secret handle" };
    params.set(key, secretValue);
    changed = true;
  }
  return changed ? { body: params.toString() } : {};
}

function replaceSecretHandlesInJson(
  body: string,
  readHandle: (handle: string) => StoredToken | undefined,
  state: StoredMcpOAuthState,
  server: McpOAuthServerPolicy,
  projectId: string,
  tokenEndpoint: TokenEndpoint,
): SecretHandleReplacement {
  const parsed = parseBodyAsJson(body);
  if (!parsed) return {};
  let changed = false;
  const next = { ...parsed };
  for (const [key, value] of Object.entries(parsed)) {
    if (typeof value !== "string" || !isRunfreeHandle(value)) continue;
    const token = readHandle(value);
    const error = secretHandleError(token, key, server, state, projectId, tokenEndpoint);
    const tokenValueForField = token ? tokenValue(token) : undefined;
    if (error || !token || !tokenValueForField) return { error: error ?? "unknown OAuth secret handle" };
    next[key] = tokenValueForField;
    changed = true;
  }
  return changed ? { body: JSON.stringify(next) } : {};
}

type BasicAuthReplacement = {
  error?: string;
  headers?: Record<string, HeaderValue>;
};

// Decode an `Authorization: Basic` value into its client_id / secret halves.
// Per RFC 6749 §2.3.1 the two are joined by the first ":"; the secret half may be
// form-urlencoded, but runfree handles are urlencoding-invariant so the caller can
// match the handle in either form. Returns undefined for any non-Basic or
// malformed header so it passes through untouched.
function decodeBasicCredentials(authorization: string | undefined): { clientId: string; secret: string } | undefined {
  if (typeof authorization !== "string") return undefined;
  const match = /^Basic\s+(\S+)\s*$/i.exec(authorization);
  if (!match) return undefined;
  // Buffer.from(..., "base64") is lenient and never throws; malformed input
  // decodes to bytes with no ":" and is rejected by the separator check below.
  const decoded = Buffer.from(match[1], "base64").toString("utf8");
  const separator = decoded.indexOf(":");
  if (separator < 0) return undefined;
  return { clientId: decoded.slice(0, separator), secret: decoded.slice(separator + 1) };
}

// Confidential OAuth clients (the default when a server's dynamic registration
// returns a client_secret but omits token_endpoint_auth_method) send the secret
// in the Authorization: Basic header at the token endpoint, not the request body.
// The agent only holds the synthetic `runfree_oauth_secret_...` handle, so swap it for
// the real secret here — applying the same authorization checks as the body path —
// or reject the request so the placeholder never reaches the upstream.
function replaceSecretHandleInBasicAuth(
  headers: Record<string, HeaderValue> | undefined,
  readHandle: (handle: string) => StoredToken | undefined,
  state: StoredMcpOAuthState,
  server: McpOAuthServerPolicy,
  projectId: string,
  tokenEndpoint: TokenEndpoint,
): BasicAuthReplacement {
  const credentials = decodeBasicCredentials(headerValue(headers, "authorization"));
  if (!credentials) return {};
  let decodedSecret = credentials.secret;
  try {
    decodedSecret = decodeURIComponent(credentials.secret);
  } catch {
    decodedSecret = credentials.secret;
  }
  const handle = isRunfreeHandle(credentials.secret)
    ? credentials.secret
    : isRunfreeHandle(decodedSecret) ? decodedSecret : undefined;
  if (!handle) return {};
  const token = readHandle(handle);
  const error = secretHandleError(token, "client_secret", server, state, projectId, tokenEndpoint);
  const value = token ? tokenValue(token) : undefined;
  if (error || !token || !value) return { error: error ?? "unknown OAuth secret handle" };
  // Preserve the client_id half exactly as it arrived on the wire and substitute
  // only the secret, mirroring how the MCP client encoded the pair.
  const encoded = Buffer.from(`${credentials.clientId}:${value}`, "utf8").toString("base64");
  return { headers: setHeader(headers ?? {}, "authorization", `Basic ${encoded}`) };
}

export class OAuthMediator {
  private loadedPolicy?: LoadedMcpOAuthPolicy;
  private loadedPolicyMtimeMs?: number;
  private lastPolicyReloadFailure?: string;
  private pairedPolicy = false;
  private pendingSensitiveRequests = new Map<string, SensitiveOAuthRequest>();
  private stateQueue: Promise<void> = Promise.resolve();

  constructor(private readonly options: {
    // Hosts that receive static credential injection from the loaded network
    // policy. A request to one is never an OAuth protocol read (X5): the
    // mediator sees only the OAuth policy, so the server supplies these.
    credentialHosts?: () => ReadonlySet<string>;
    log?: (line: string) => void;
    now?: () => Date;
    pairedPolicy?: LoadedOAuthMediationPolicy;
    policyPath?: string;
    projectId?: string;
    stateDir?: string;
    tokenDir?: string;
    // Renders the refusal of an unmediated OAuth-shaped request that the
    // final in-mediator check catches (P1-c). The server supplies its
    // structured denial; the default is a plain 403.
    unmediatedRequestResponse?: (req: OAuthProxyRequest, refusal: UnmediatedOAuthRequestRefusal) => OAuthRequestResult;
  } = {}) {
    if (options.pairedPolicy) this.activatePairedPolicy(options.pairedPolicy);
  }

  // The effective-control loader has already validated this policy together
  // with the network policy and their shared manifest. Activation is a
  // synchronous in-memory swap: the mediator never stats or watches another
  // path while paired mode is active.
  activatePairedPolicy(policy: LoadedOAuthMediationPolicy): void {
    const next = mediatorPolicy(policy);
    this.pruneStateForLoadedPolicy(next);
    this.loadedPolicy = next;
    this.loadedPolicyMtimeMs = undefined;
    this.lastPolicyReloadFailure = undefined;
    this.pairedPolicy = true;
  }

  private async withStateLock<T>(callback: () => Promise<T> | T): Promise<T> {
    const previous = this.stateQueue;
    let release!: () => void;
    this.stateQueue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await callback();
    } finally {
      release();
    }
  }

  beforeRequest = async (
    req: OAuthProxyRequest,
    options: OAuthBeforeRequestOptions = {},
  ): Promise<OAuthRequestResult | undefined> => {
    // Read the body before the policy: from the policy read to the return
    // below nothing yields, so the final unmediated-request check sees the
    // policy the request is forwarded under. mockttp's buffered body is
    // synchronous; only a test double without one is awaited.
    const body = req.body === undefined ? undefined : req.body.buffer ?? await requestBodyFromText(req);
    const policyState = this.currentPolicyState();
    const url = parseUrl(req.url);
    if (!url || url.protocol !== "https:") return undefined;
    const state = this.currentState();
    const allowlisted = options.allowlisted !== false;
    if (!policyState.valid) {
      const rejected = this.rejectRequestWhilePolicyUnavailable(req, policyState.policy, state, url);
      if (rejected) return rejected;
      const refusal = this.unmediatedRequestRefusalFor(req, url, body, policyState, state, allowlisted);
      return refusal ? this.unmediatedRequestResult(req, refusal) : undefined;
    }
    const policy = policyState.policy;
    // P1-c: the rule was chosen before this request was handled. A policy or
    // discovery change in between can leave a now-mediated or now-blocked
    // endpoint on the plain rule, whose reply is never read.
    if (options.responseMediated === false) {
      const claim = endpointClaim(policy, state, url);
      if (claim?.kind === "mediated") {
        return forbidden("OAuth endpoint became mediated while this request was in flight; retry it");
      }
      if (claim !== undefined) {
        return forbidden("OAuth endpoint became blocked while this request was in flight; retry it");
      }
    }
    // The last check before the request is forwarded: a grant- or
    // registration-shaped request that no provider mediates, to a host or
    // endpoint the policy guards. It repeats the server's early check, which
    // ran before write classification, against the policy current now.
    const refusal = this.unmediatedRequestRefusalFor(req, url, body, policyState, state, allowlisted);
    if (refusal) return this.unmediatedRequestResult(req, refusal);
    if (options.protocolRead) {
      const current = this.protocolReadMatch(req, policy, state);
      if (current?.provider !== options.protocolRead.provider || current.kind !== options.protocolRead.kind) {
        return forbidden("OAuth endpoint is no longer mediated for this server; retry it");
      }
    }
    const handle = bearerHandle(req.headers);
    if (handle) {
      return this.authorizeBearerHandleRequest(req, url, state, handle, policy);
    }
    if (policy.servers.length === 0) return undefined;
    if (!this.rememberSensitiveRequest(req, policy, state, url)) {
      return forbidden("too many OAuth exchanges in flight; retry it");
    }
    const result = await this.replaceRefreshHandleRequest(req, url, policy, state);
    // A refused request never reaches the upstream: drop its entry, so
    // refused requests cannot fill the map and push out a real exchange.
    if (result?.response && typeof req.id === "string") this.pendingSensitiveRequests.delete(req.id);
    return result;
  };

  // True when this request targets an OAuth endpoint whose *response* the
  // mediator may rewrite: a token exchange, dynamic client registration, or
  // authorization-server/protected-resource metadata. This mirrors the URL-shape
  // guards at the top of beforeResponse so the server can attach the
  // response-buffering beforeResponse callback to exactly these requests and
  // leave every other allowlisted response — including SSE/streaming API traffic
  // and MCP resource responses — on the live pass-through path.
  //
  // State is read fresh on every call. The matcher runs at request time, the
  // same point rememberSensitiveRequest reads state, so a token request issued
  // after its metadata response recorded discovered endpoints observes them here
  // too. Plain resource-host traffic is deliberately not matched (only
  // `/.well-known/` metadata, token, and registration endpoints) so MCP resource
  // responses keep streaming. The predicate is a superset of what beforeResponse
  // acts on, so a non-match can never strand a response that needed rewriting.
  //
  // Blocked and colliding endpoints are matched too: their replies are read
  // and sensitive bodies are blocked. Record-only hosts are deliberately not
  // matched (their replies are never buffered); the request-side check
  // guards them.
  requestNeedsResponseMediation = (req: { url: string }): boolean => {
    const url = parseUrl(req.url);
    if (!url || url.protocol !== "https:") return false;
    const policyState = this.currentPolicyState();
    if (!policyState.valid) return false;
    const policy = policyState.policy;
    if (policy.servers.length === 0 && policy.blockedEndpoints.length === 0) return false;
    let state: StoredMcpOAuthState;
    try {
      state = this.currentState();
    } catch {
      return false;
    }
    return matchingMetadataServer(policy, state, url) !== undefined
      || endpointClaim(policy, state, url) !== undefined;
  };

  /**
   * P1-a, the server's early check: the refusal for an OAuth grant- or
   * registration-shaped request that no provider mediates, to a record-only
   * host, a host a record names that also serves an MCP endpoint, a blocked
   * or colliding endpoint, or (while the OAuth policy is invalid) any
   * allowlisted host. The server runs it before write classification and the
   * approval hold, so a refused request creates no prompt, no pending
   * record, no upstream connection, and no state write.
   */
  unmediatedRequestRefusal = async (
    req: OAuthProxyRequest,
    options: { allowlisted: boolean },
  ): Promise<UnmediatedOAuthRequestRefusal | undefined> => {
    const body = req.body === undefined ? undefined : req.body.buffer ?? await requestBodyFromText(req);
    const url = parseUrl(req.url);
    if (!url || url.protocol !== "https:") return undefined;
    const policyState = this.currentPolicyState();
    let state: StoredMcpOAuthState;
    try {
      state = this.currentState();
    } catch {
      // Without readable state no discovered endpoint is known, so nothing
      // discovered is exempt: the check stays at least as strict.
      state = {};
    }
    return this.unmediatedRequestRefusalFor(req, url, body, policyState, state, options.allowlisted);
  };

  private unmediatedRequestRefusalFor(
    req: OAuthProxyRequest,
    url: URL,
    body: Buffer | undefined,
    policyState: CurrentMcpOAuthPolicy,
    state: StoredMcpOAuthState,
    allowlisted: boolean,
  ): UnmediatedOAuthRequestRefusal | undefined {
    const host = url.hostname.toLowerCase();
    const policy = policyState.policy;
    const check = (
      target: UnmediatedOAuthRequestRefusal["target"],
      scope: GrantShapeScope,
      failClosed: boolean,
      providers: string[],
    ): UnmediatedOAuthRequestRefusal | undefined => {
      const finding = classifyGrantShape({ body, failClosed, headers: req.headers, scope, url });
      if (finding === undefined) return undefined;
      return { finding, host, path: url.pathname || "/", providers, target };
    };
    const userHostOwners = () => policy.servers.filter((server) => server.bindingHosts.includes(host)).map((server) => server.name);
    if (!policyState.valid) {
      // The last valid policy's record-only hosts keep their full rule; any
      // other allowlisted host refuses a readable grant shape. Audited hosts
      // are outside the allowlist and outside this rule.
      if (policy.recordOnlyHosts.includes(host)) return check("record-only-host", "deep", true, userHostOwners());
      return allowlisted ? check("policy-unavailable", "deep", false, []) : undefined;
    }
    const claim = endpointClaim(policy, state, url);
    if (claim?.kind === "mediated") return undefined;
    if (claim?.kind === "collision") {
      return check("endpoint-collision", "deep", true, claim.servers.map((server) => server.name));
    }
    if (claim?.kind === "blocked") return check("blocked-endpoint", "deep", true, []);
    if (policy.recordOnlyHosts.includes(host)) return check("record-only-host", "deep", true, userHostOwners());
    // Path variants of a blocked or colliding endpoint: a deep scan of the
    // whole host, without fail-closed rules, so ordinary traffic there is
    // never refused for its size or encoding.
    const hostClaim = hostBlockOrCollision(policy, state, host);
    if (hostClaim?.kind === "collision") {
      return check("endpoint-collision", "deep", false, hostClaim.servers.map((server) => server.name));
    }
    if (hostClaim?.kind === "blocked") return check("blocked-endpoint", "deep", false, []);
    if (policy.recordEndpointHosts.includes(host)) return check("record-endpoint-host", "top-level", false, userHostOwners());
    return undefined;
  }

  /**
   * The refusal for a WebSocket upgrade where the proxy guards OAuth, or
   * undefined. mockttp returns a non-101 upstream reply to the agent as is,
   * so an upgrade GET with a grant in its query could fetch real tokens. An
   * upgrade is refused to a record-only host, to any URL a provider claims
   * or blocks (mediated, blocked, or colliding), to a host with a blocked or
   * colliding endpoint when its query is grant-shaped, and to a host a
   * record names when its query is grant-shaped. While the OAuth policy is
   * invalid, any grant-shaped query is refused. Synchronous: it runs in the
   * WebSocket rule matcher.
   */
  webSocketUpgradeRefusal = (req: { headers?: Record<string, HeaderValue>; url: string }): UnmediatedOAuthRequestRefusal | undefined => {
    const url = parseUrl(req.url);
    if (!url) return undefined;
    const host = url.hostname.toLowerCase();
    const pathName = url.pathname || "/";
    const policyState = this.currentPolicyState();
    const policy = policyState.policy;
    const refuse = (
      target: UnmediatedOAuthRequestRefusal["target"],
      providers: string[],
      finding: UnmediatedOAuthRequestRefusal["finding"] = { kind: "websocket" },
    ): UnmediatedOAuthRequestRefusal => ({ finding, host, path: pathName, providers, target });
    const queryGrant = () => classifyGrantShape({ body: undefined, failClosed: false, headers: req.headers, scope: "top-level", url });
    const userHostOwners = () => policy.servers.filter((server) => server.bindingHosts.includes(host)).map((server) => server.name);
    if (!policyState.valid) {
      if (policy.recordOnlyHosts.includes(host)) return refuse("record-only-host", userHostOwners());
      const finding = queryGrant();
      return finding ? refuse("policy-unavailable", [], finding) : undefined;
    }
    let state: StoredMcpOAuthState;
    try {
      state = this.currentState();
    } catch {
      state = {};
    }
    const claim = endpointClaim(policy, state, url);
    if (claim?.kind === "mediated") return refuse("mediated-endpoint", [claim.server.name]);
    if (claim?.kind === "collision") return refuse("endpoint-collision", claim.servers.map((server) => server.name));
    if (claim?.kind === "blocked") return refuse("blocked-endpoint", []);
    if (policy.recordOnlyHosts.includes(host)) return refuse("record-only-host", userHostOwners());
    const finding = queryGrant();
    if (finding === undefined) return undefined;
    const hostClaim = hostBlockOrCollision(policy, state, host);
    if (hostClaim?.kind === "collision") return refuse("endpoint-collision", hostClaim.servers.map((server) => server.name), finding);
    if (hostClaim?.kind === "blocked") return refuse("blocked-endpoint", [], finding);
    if (policy.recordEndpointHosts.includes(host)) return refuse("record-endpoint-host", userHostOwners(), finding);
    return undefined;
  };

  private unmediatedRequestResult(req: OAuthProxyRequest, refusal: UnmediatedOAuthRequestRefusal): OAuthRequestResult {
    this.log(`proxy: oauth unmediated request refused host=${refusal.host} target=${refusal.target} finding=${refusal.finding.kind}`);
    if (typeof req.id === "string") this.pendingSensitiveRequests.delete(req.id);
    return this.options.unmediatedRequestResponse?.(req, refusal)
      ?? forbidden(`OAuth ${refusal.finding.kind} request to an endpoint the proxy does not mediate`);
  }

  beforeResponse = async (
    res: OAuthProxyResponse,
    req: OAuthProxyRequest,
  ): Promise<OAuthResponseResult | undefined> => {
    const pending = this.takeSensitiveRequest(req);
    const requestUrl = parseUrl(req.url);
    if (!requestUrl || requestUrl.protocol !== "https:") return undefined;
    // Every response on the response-mediating rule is read, even when the
    // policy no longer names a server: a token response that nothing mediates
    // any more is blocked below rather than passed to the agent.
    const text = await res.body.getText();
    const rawLength = res.body.buffer?.length ?? 0;
    // A reply that is not a success is never mediated, but it is still read:
    // an endpoint that returns real tokens with an error status must not get
    // them to the agent.
    if (res.statusCode < 200 || res.statusCode >= 300) return unmediatedTokenResponse(text, rawLength, res.headers);
    return await this.withStateLock(() => {
      // Re-read the policy after the body arrived: an activation (a revoke's
      // new state epoch) may have pruned this server's state meanwhile, and
      // nothing from before it may be written back.
      const live = this.currentPolicyState();
      const livePolicy = live.policy;
      // An exchange that began before its server was removed or revoked must
      // not store tokens into the new state, and its real tokens must not
      // reach the agent: block the response.
      if (pending && live.valid && !pendingServerStillCurrent(pending.server, livePolicy)) {
        return blockedTokenEndpointResponse("MCP OAuth server was revoked during the exchange", res.headers);
      }
      const state = this.currentState();
      // A blocked or colliding endpoint is mediated by nobody.
      if (live.valid && !pending && endpointBlocked(livePolicy, state, requestUrl)) {
        return unmediatedTokenResponse(text, rawLength, res.headers);
      }
      const couldBeMetadata = live.valid && matchingMetadataServer(livePolicy, state, requestUrl) !== undefined;
      const server = pending?.kind === "token"
        ? pending.server
        : live.valid ? matchingTokenServer(livePolicy, state, requestUrl) : undefined;
      const registrationServer = pending?.kind === "registration"
        ? pending.server
        : live.valid ? matchingRegistrationServer(livePolicy, state, requestUrl) : undefined;
      if (!server && !registrationServer && !couldBeMetadata) return unmediatedTokenResponse(text, rawLength, res.headers);
      if (!text) {
        return server || registrationServer
          ? blockedTokenEndpointResponse("empty OAuth token response", res.headers)
          : undefined;
      }
      const parsed = parseBodyAsJson(text);
      if (!parsed) {
        return server || registrationServer
          ? blockedTokenEndpointResponse("malformed OAuth token response", res.headers)
          : undefined;
      }
      if (live.valid && this.captureMetadataEndpoint(livePolicy, state, requestUrl, parsed)) return undefined;
      if (registrationServer) {
        const next = this.replaceRegistrationResponse(
          state,
          registrationServer,
          pending?.kind === "registration" ? pending.endpoint : safeTokenEndpoint(requestUrl),
          parsed,
        );
        if (!next) return undefined;
        writeState(this.stateFile(), state);
        this.log(`proxy: mcp oauth client_registration ok name=${registrationServer.name}`);
        return {
          body: JSON.stringify(next),
          headers: stripContentLength(setHeader(res.headers ?? {}, "content-type", "application/json")),
        };
      }
      if (!server) return undefined;
      const next = this.replaceTokenResponse(
        state,
        server,
        pending?.kind === "token" ? pending.endpoint : safeTokenEndpoint(requestUrl),
        parsed,
      );
      if (!next) return undefined;
      if ("error" in next) return blockedTokenEndpointResponse(next.error, res.headers);
      // A rotated refresh token retires the handle that was swapped for the
      // old one, so the agent cannot replay the old token (which can trip the
      // issuer's reuse detection and revoke the whole grant).
      if (next.refreshStatus === "handle" && pending?.refreshHandle && state.handles?.[pending.refreshHandle]) {
        delete state.handles[pending.refreshHandle];
      }
      writeState(this.stateFile(), state);
      this.log(`proxy: oauth token_exchange ok name=${server.name} access=handle refresh=${next.refreshStatus}`);
      return {
        body: JSON.stringify(next.body),
        headers: stripContentLength(setHeader(res.headers ?? {}, "content-type", "application/json")),
      };
    });
  };

  /**
   * The protocol-read match for a request, or undefined. Exact method (POST),
   * exact raw path (no normalization, query, or encoding), an endpoint listed
   * in exactly one provider's protocolReadEndpoints that is also one of its
   * static token or registration endpoints, and no other provider (MCP or
   * service, static or discovered at run time) that would mediate the URL.
   */
  protocolReadEndpoint = (req: { method?: string; url: string }): ProtocolReadMatch | undefined => {
    const policyState = this.currentPolicyState();
    if (!policyState.valid) return undefined;
    let state: StoredMcpOAuthState;
    try {
      state = this.currentState();
    } catch {
      return undefined;
    }
    return this.protocolReadMatch(req, policyState.policy, state);
  };

  private protocolReadMatch(
    req: { method?: string; url: string },
    policy: LoadedMcpOAuthPolicy,
    state: StoredMcpOAuthState,
  ): ProtocolReadMatch | undefined {
    if (req.method !== "POST") return undefined;
    const pathName = plainRequestPath(req.url);
    const url = parseUrl(req.url);
    if (!pathName || !url || url.protocol !== "https:" || url.search !== "" || url.hash !== "" || url.pathname !== pathName) {
      return undefined;
    }
    const host = url.hostname.toLowerCase();
    // X5: a host that receives static credential injection never gets
    // protocol reads; its writes follow write approval.
    if (this.options.credentialHosts?.().has(host)) return undefined;
    const exact = (endpoint: TokenEndpoint) => endpoint.host === host && endpoint.path === pathName;
    const listed = policy.servers.filter((server) => server.kind === "mcp" && server.protocolReadEndpoints.some(exact));
    if (listed.length !== 1) return undefined;
    const server = listed[0];
    const isToken = server.tokenEndpoints.some(exact);
    const isRegistration = server.registrationEndpoints.some(exact);
    if (isToken === isRegistration) return undefined;
    const claim = endpointClaim(policy, state, url);
    if (claim?.kind !== "mediated" || claim.server !== server) return undefined;
    // The mediator picks a token server before a registration server; the
    // match must be the one it will actually use.
    const tokenServer = matchingTokenServer(policy, state, url);
    if (isToken ? tokenServer !== server : tokenServer !== undefined || matchingRegistrationServer(policy, state, url) !== server) {
      return undefined;
    }
    return { kind: isToken ? "token" : "registration", provider: server.name, resourceHost: server.resourceHost };
  }

  issuerDenialContext(rawHost: string): OAuthIssuerDenialContext | undefined {
    let host: string;
    try {
      host = normalizeHostname(rawHost);
    } catch {
      return undefined;
    }
    const policyState = this.currentPolicyState();
    if (!policyState.valid || policyState.policy.servers.length === 0) return undefined;
    let state: StoredMcpOAuthState;
    try {
      state = this.currentState();
    } catch {
      return undefined;
    }
    for (const server of policyState.policy.servers) {
      if (discoveredIssuerHosts(server, state).includes(host)) {
        return {
          providerId: server.name,
          resourceHost: server.resourceHost,
        };
      }
    }
    return undefined;
  }

  // False when the request is an exchange to remember but the map is full:
  // the caller refuses it rather than evict another exchange's entry.
  private rememberSensitiveRequest(
    req: OAuthProxyRequest,
    policy: LoadedMcpOAuthPolicy,
    state: StoredMcpOAuthState,
    url: URL,
  ): boolean {
    if (typeof req.id !== "string" || req.id === "" || req.method !== "POST") return true;
    const tokenServer = matchingTokenServer(policy, state, url);
    const registrationServer = tokenServer ? undefined : matchingRegistrationServer(policy, state, url);
    const server = tokenServer ?? registrationServer;
    if (!server) return true;
    this.prunePendingSensitiveRequests();
    if (this.pendingSensitiveRequests.size >= PENDING_MAX_ENTRIES) return false;
    this.pendingSensitiveRequests.set(req.id, {
      createdAtMs: Date.now(),
      endpoint: safeTokenEndpoint(url),
      kind: tokenServer ? "token" : "registration",
      server,
    });
    return true;
  }

  private prunePendingSensitiveRequests(): void {
    const cutoff = Date.now() - PENDING_MAX_AGE_MS;
    for (const [id, pending] of this.pendingSensitiveRequests) {
      if (pending.createdAtMs < cutoff) this.pendingSensitiveRequests.delete(id);
    }
  }

  private takeSensitiveRequest(req: OAuthProxyRequest): SensitiveOAuthRequest | undefined {
    if (typeof req.id !== "string" || req.id === "") return undefined;
    const pending = this.pendingSensitiveRequests.get(req.id);
    this.pendingSensitiveRequests.delete(req.id);
    return pending;
  }

  private authorizeBearerHandleRequest(
    req: OAuthProxyRequest,
    url: URL,
    state: StoredMcpOAuthState,
    handle: string,
    policy: LoadedMcpOAuthPolicy,
  ): OAuthRequestResult | undefined {
    const token = this.readHandle(state, handle, policy);
    if (!token) return forbidden("unknown OAuth token handle");
    if (token.type === "access") return this.authorizeResourceRequest(req, url, state, token, policy);
    if (token.type === "secret" && token.field === "registration_access_token") {
      return this.authorizeRegistrationRequest(req, url, state, token, policy);
    }
    return forbidden("unknown OAuth token handle");
  }

  private authorizeResourceRequest(
    req: OAuthProxyRequest,
    url: URL,
    state: StoredMcpOAuthState,
    token: StoredToken,
    policy: LoadedMcpOAuthPolicy,
  ): OAuthRequestResult | undefined {
    if (storedTokenExpired(token, this.now())) return forbidden("expired OAuth token handle");
    if (token.projectId !== this.projectId()) return forbidden("OAuth token handle belongs to another project");
    const server = policy.servers.find((candidate) => candidate.name === token.serverName);
    if (!server || !storedTokenMatchesCurrentServer(token, server) || !resourceMatches(server, url)) {
      return forbidden("OAuth token handle used for the wrong resource");
    }
    const value = tokenValue(token);
    if (!value) return forbidden("OAuth seed secret unavailable");
    return {
      headers: setHeader(req.headers ?? {}, "authorization", `Bearer ${value}`),
    };
  }

  private authorizeRegistrationRequest(
    req: OAuthProxyRequest,
    url: URL,
    state: StoredMcpOAuthState,
    token: StoredToken,
    policy: LoadedMcpOAuthPolicy,
  ): OAuthRequestResult | undefined {
    if (storedTokenExpired(token, this.now())) return forbidden("expired OAuth token handle");
    if (token.projectId !== this.projectId()) return forbidden("OAuth token handle belongs to another project");
    const server = policy.servers.find((candidate) => candidate.name === token.serverName);
    if (!server || !storedTokenMatchesCurrentServer(token, server)) {
      return forbidden("OAuth token handle used for the wrong registration endpoint");
    }
    if (!storedTokenEndpointMatches(token, safeTokenEndpoint(url))) {
      return forbidden("OAuth token handle used for the wrong registration endpoint");
    }
    const value = tokenValue(token);
    if (!value) return forbidden("OAuth seed secret unavailable");
    return {
      headers: setHeader(req.headers ?? {}, "authorization", `Bearer ${value}`),
    };
  }

  private async replaceRefreshHandleRequest(
    req: OAuthProxyRequest,
    url: URL,
    policy: LoadedMcpOAuthPolicy,
    state: StoredMcpOAuthState,
  ): Promise<OAuthRequestResult | undefined> {
    const server = matchingTokenServer(policy, state, url);
    if (!server) return undefined;
    const tokenEndpoint = safeTokenEndpoint(url);
    const projectId = this.projectId();

    // A confidential client (client_secret_basic) carries the secret in the
    // Authorization header rather than the body; swap it independently so the
    // synthetic handle never leaks even when the body has nothing to rewrite.
    const readHandle = (handle: string) => this.readHandle(state, handle, policy);
    const basicReplacement = replaceSecretHandleInBasicAuth(req.headers, readHandle, state, server, projectId, tokenEndpoint);
    if (basicReplacement.error) return forbidden(basicReplacement.error);
    const headers: Record<string, HeaderValue> = basicReplacement.headers ?? req.headers ?? {};
    const headersChanged = basicReplacement.headers !== undefined;

    const text = await req.body?.getText();
    if (!text) return headersChanged ? { headers } : undefined;
    const refreshHandle = this.findRefreshHandleInBody(text, req.headers);
    let body = text;
    let bodyChanged = false;
    if (refreshHandle) {
      const token = this.readTypedHandle(state, refreshHandle, "refresh", policy);
      if (!token) return forbidden("unknown OAuth refresh handle");
      if (!tokenValue(token)) return forbidden("OAuth seed secret unavailable");
      if (token.projectId !== projectId || token.serverName !== server.name) {
        return forbidden("OAuth refresh handle used for the wrong token endpoint");
      }
      if (!storedTokenMatchesCurrentServer(token, server) || !storedTokenEndpointMatches(token, tokenEndpoint)) {
        return forbidden("OAuth refresh handle used for the wrong token endpoint");
      }
      let refreshed: string | undefined;
      if (requestHasFormContent(req.headers)) refreshed = replaceRefreshHandleInForm(body, token);
      if (!refreshed && requestHasJsonContent(req.headers)) refreshed = replaceRefreshHandleInJson(body, token);
      if (!refreshed) return headersChanged ? { headers } : undefined;
      body = refreshed;
      bodyChanged = true;
      const pending = typeof req.id === "string" ? this.pendingSensitiveRequests.get(req.id) : undefined;
      if (pending) pending.refreshHandle = token.handle;
    }

    let secretReplacement: SecretHandleReplacement = {};
    if (requestHasFormContent(req.headers)) {
      secretReplacement = replaceSecretHandlesInForm(body, readHandle, state, server, projectId, tokenEndpoint);
    }
    if (!secretReplacement.body && !secretReplacement.error && requestHasJsonContent(req.headers)) {
      secretReplacement = replaceSecretHandlesInJson(body, readHandle, state, server, projectId, tokenEndpoint);
    }
    if (secretReplacement.error) return forbidden(secretReplacement.error);
    if (secretReplacement.body) {
      body = secretReplacement.body;
      bodyChanged = true;
    }
    if (!bodyChanged) return headersChanged ? { headers } : undefined;
    return {
      body,
      headers: stripContentLength(headers),
    };
  }

  private findRefreshHandleInBody(body: string, headers: Record<string, HeaderValue> | undefined): string | undefined {
    if (requestHasFormContent(headers)) {
      const params = new URLSearchParams(body);
      const value = params.get("refresh_token") ?? "";
      return isRunfreeHandle(value) ? value : undefined;
    }
    if (requestHasJsonContent(headers)) {
      const parsed = parseBodyAsJson(body);
      const value = typeof parsed?.refresh_token === "string" ? parsed.refresh_token : "";
      return isRunfreeHandle(value) ? value : undefined;
    }
    return undefined;
  }

  private replaceTokenResponse(
    state: StoredMcpOAuthState,
    server: McpOAuthServerPolicy,
    tokenEndpoint: TokenEndpoint,
    parsed: Record<string, unknown>,
  ): { body: Record<string, unknown>; refreshStatus: "none" | "handle" } | { error: string } | undefined {
    const accessToken = typeof parsed.access_token === "string" && parsed.access_token !== "" ? parsed.access_token : undefined;
    const refreshToken = typeof parsed.refresh_token === "string" && parsed.refresh_token !== "" ? parsed.refresh_token : undefined;
    const sensitiveFields = sensitiveOauthResponseFields(parsed);
    if (sensitiveFields.length === 0) return undefined;
    if (server.kind === "service") {
      const forbiddenFields = sensitiveFields.filter((field) => field !== "access_token");
      if (forbiddenFields.length > 0) {
        return { error: `service OAuth token response contained ${forbiddenFields.join(", ")}` };
      }
    }
    const now = this.now();
    const body = cloneJsonTokenResponse(parsed);
    if (accessToken) {
      body.access_token = storeHandle(state, {
        now,
        projectId: this.projectId(),
        server,
        token: accessToken,
        tokenEndpoint,
        endpointKind: "token",
        type: "access",
        expiresAt: expiresAtFromResponse(parsed, now),
      });
    }
    let refreshStatus: "none" | "handle" = "none";
    if (refreshToken && server.kind === "mcp") {
      body.refresh_token = storeHandle(state, {
        now,
        projectId: this.projectId(),
        server,
        token: refreshToken,
        tokenEndpoint,
        endpointKind: "token",
        type: "refresh",
      });
      refreshStatus = "handle";
    }
    for (const field of sensitiveFields) {
      if (field === "access_token" || field === "refresh_token") continue;
      if (server.kind !== "mcp") continue;
      body[field] = storeHandle(state, {
        now,
        projectId: this.projectId(),
        server,
        token: parsed[field] as string,
        tokenEndpoint,
        endpointKind: "token",
        type: "secret",
        field,
      });
    }
    return { body, refreshStatus };
  }

  private replaceRegistrationResponse(
    state: StoredMcpOAuthState,
    server: McpOAuthServerPolicy,
    registrationEndpoint: TokenEndpoint,
    parsed: Record<string, unknown>,
  ): Record<string, unknown> | undefined {
    const sensitiveFields = sensitiveOauthResponseFields(parsed);
    if (sensitiveFields.length === 0) return undefined;
    const now = this.now();
    const body = cloneJsonTokenResponse(parsed);
    const registrationClientEndpoint = tokenEndpointFromUrl(parsed.registration_client_uri);
    for (const field of sensitiveFields) {
      body[field] = storeHandle(state, {
        now,
        projectId: this.projectId(),
        server,
        token: parsed[field] as string,
        tokenEndpoint: field === "registration_access_token"
          ? registrationClientEndpoint ?? registrationEndpoint
          : registrationEndpoint,
        endpointKind: "registration",
        type: "secret",
        field,
      });
    }
    return body;
  }

  private assertBoundDiscoveredEndpoint(
    server: McpOAuthServerPolicy,
    bindingHosts: Set<string>,
    endpoint: TokenEndpoint,
    field: "token_endpoint" | "registration_endpoint",
  ): boolean {
    if (bindingHosts.has(endpoint.host)) return true;
    this.log(`proxy: mcp oauth discovery rejected name=${server.name} ${field}_host=${endpoint.host} reason=unbound-host`);
    return false;
  }

  // R1/R9/R2: a host where this server's metadata may never bind an issuer or
  // an endpoint: a host-owned refused host (credential destinations, curated
  // service hosts; only the server's own resource host is exempt), or a host
  // where another provider's tokens pass. Checked before any state is
  // touched, so a refusal writes nothing.
  private captureHostRefused(
    policy: LoadedMcpOAuthPolicy,
    server: McpOAuthServerPolicy,
    host: string,
    field: "issuer" | "token_endpoint" | "registration_endpoint",
  ): boolean {
    if (oauthHostRefusedForProvider(policy, server, host)) {
      this.log(`proxy: mcp oauth discovery rejected name=${server.name} ${field}_host=${host} reason=refused-host`);
      return true;
    }
    const owners = otherProviderHostOwners(policy, server, host);
    if (owners.length > 0) {
      this.log(`proxy: mcp oauth discovery rejected name=${server.name} ${field}_host=${host} reason=other-provider-host providers=${owners.join(",")}`);
      return true;
    }
    return false;
  }

  private capturableEndpoint(
    policy: LoadedMcpOAuthPolicy,
    state: StoredMcpOAuthState,
    server: McpOAuthServerPolicy,
    bindingHosts: Set<string>,
    endpoint: TokenEndpoint,
    field: "registrationEndpoints" | "tokenEndpoints",
  ): boolean {
    const label = field === "tokenEndpoints" ? "token_endpoint" : "registration_endpoint";
    if (!this.assertBoundDiscoveredEndpoint(server, bindingHosts, endpoint, label)) return false;
    if (this.captureHostRefused(policy, server, endpoint.host, label)) return false;
    // R2: an endpoint that another provider also claims is remembered, not
    // dropped: a request that more than one provider claims is mediated by
    // none and blocked, so neither provider can capture the other's tokens,
    // and neither silently wins. `runfree mcp revoke` on one reclaims it.
    const colliding = collidingProviders(policy, state, server, endpoint, field);
    if (colliding.length > 0) {
      this.log(`proxy: mcp oauth endpoint-collision name=${server.name} ${label}_host=${endpoint.host} providers=${colliding.join(",")}; requests to it are blocked`);
    }
    return true;
  }

  private captureMetadataEndpoint(
    policy: LoadedMcpOAuthPolicy,
    state: StoredMcpOAuthState,
    requestUrl: URL,
    parsed: Record<string, unknown>,
  ): boolean {
    const server = matchingMetadataServer(policy, state, requestUrl);
    if (!server) return false;
    const host = requestUrl.hostname.toLowerCase();
    let changed = false;

    // RFC 9728 protected-resource metadata, served from the resource host itself,
    // lets the resource server declare its authorization server(s). Binding the
    // named issuer hosts is what lets a legitimately off-host issuer's endpoints
    // be mediated later — and only because the resource host named them.
    if (host === server.resourceHost && Array.isArray(parsed.authorization_servers)) {
      for (const entry of parsed.authorization_servers) {
        const issuer = tokenEndpointFromUrl(entry);
        if (issuer && this.captureHostRefused(policy, server, issuer.host, "issuer")) continue;
        if (issuer && rememberIssuerHost(state, server, issuer.host)) {
          changed = true;
          this.log(`proxy: mcp oauth issuer bound name=${server.name} issuer_host=${issuer.host}`);
        }
      }
    }

    // RFC 8414 authorization-server metadata from a cross-host (discovered) issuer
    // must be self-consistent (its `issuer` identifies the serving host) before we
    // trust the token/registration endpoints it advertises.
    const fromDiscoveredIssuer = host !== server.resourceHost && discoveredIssuerHosts(server, state).includes(host);
    if (fromDiscoveredIssuer && !issuerSelfConsistent(parsed.issuer, host)) {
      this.log(`proxy: mcp oauth discovery rejected name=${server.name} issuer_host=${host} reason=issuer-mismatch`);
    } else {
      const bindingHosts = effectiveBindingHosts(server, state);
      const tokenEndpoint = tokenEndpointFromUrl(parsed.token_endpoint);
      const registrationEndpoint = tokenEndpointFromUrl(parsed.registration_endpoint);
      let endpointChanged = false;
      if (tokenEndpoint && this.capturableEndpoint(policy, state, server, bindingHosts, tokenEndpoint, "tokenEndpoints")) {
        endpointChanged = rememberEndpoint(state, server, tokenEndpoint, "tokenEndpoints") || endpointChanged;
      }
      if (registrationEndpoint && this.capturableEndpoint(policy, state, server, bindingHosts, registrationEndpoint, "registrationEndpoints")) {
        endpointChanged = rememberEndpoint(state, server, registrationEndpoint, "registrationEndpoints") || endpointChanged;
      }
      if (endpointChanged) {
        this.log(`proxy: mcp oauth discovery ok name=${server.name}${tokenEndpoint ? ` token_host=${tokenEndpoint.host}` : ""}${registrationEndpoint ? ` registration_host=${registrationEndpoint.host}` : ""}`);
      }
      changed = changed || endpointChanged;
    }

    if (changed) writeState(this.stateFile(), state);
    return true;
  }

  private rejectRequestWhilePolicyUnavailable(
    req: OAuthProxyRequest,
    policy: LoadedMcpOAuthPolicy,
    state: StoredMcpOAuthState,
    url: URL,
  ): OAuthRequestResult | undefined {
    if (bearerHandle(req.headers)) return forbidden("OAuth policy unavailable");
    if (policy.servers.length === 0) return forbidden("OAuth policy unavailable");
    if (endpointClaim(policy, state, url) !== undefined || matchingMetadataServer(policy, state, url)) {
      return forbidden("OAuth policy unavailable");
    }
    return undefined;
  }

  private currentPolicyState(): CurrentMcpOAuthPolicy {
    if (this.pairedPolicy && this.loadedPolicy) return { policy: this.loadedPolicy, valid: true };
    const policyPath = this.options.policyPath
      ?? process.env.RUNFREE_OAUTH_POLICY
      ?? process.env.RUNFREE_MCP_OAUTH_POLICY;
    if (!policyPath) return { policy: emptyPolicy(), valid: true };
    let stat: fs.Stats;
    try {
      stat = fs.statSync(policyPath);
    } catch (error) {
      return this.invalidPolicyState(policyPath, error);
    }
    if (this.loadedPolicy && this.loadedPolicyMtimeMs === stat.mtimeMs) {
      return { policy: this.loadedPolicy, valid: true };
    }
    try {
      // Prune before committing, so a failed prune is retried on the next
      // request instead of leaving a committed policy with unpruned state.
      const next = loadPolicy(policyPath);
      this.pruneStateForLoadedPolicy(next);
      this.loadedPolicy = next;
      this.loadedPolicyMtimeMs = stat.mtimeMs;
      this.lastPolicyReloadFailure = undefined;
    } catch (error) {
      return this.invalidPolicyState(policyPath, error);
    }
    return { policy: this.loadedPolicy, valid: true };
  }

  private pruneStateForLoadedPolicy(policy: LoadedMcpOAuthPolicy): void {
    const state = this.currentState();
    if (pruneStateForPolicy(state, policy)) writeState(this.stateFile(), state);
  }

  private invalidPolicyState(policyPath: string, error: unknown): CurrentMcpOAuthPolicy {
    const message = error instanceof Error ? error.message : String(error);
    const cacheKey = `${policyPath}\0${message}`;
    if (this.lastPolicyReloadFailure !== cacheKey) {
      this.log(`proxy: oauth policy reload failed; refusing new OAuth requests: ${message}`);
      this.lastPolicyReloadFailure = cacheKey;
    }
    return {
      policy: this.loadedPolicy ?? emptyPolicy(policyPath),
      valid: false,
    };
  }

  private currentState(): StoredMcpOAuthState {
    return readState(this.stateFile());
  }

  private readHandle(state: StoredMcpOAuthState, handle: string, policy: LoadedMcpOAuthPolicy): StoredToken | undefined {
    if (!isRunfreeHandle(handle)) return undefined;
    const token = state.handles?.[handle];
    if (token && token.handle === handle) return token;
    return seedTokenForHandle(policy, this.projectId(), this.options.tokenDir, handle);
  }

  private readTypedHandle(state: StoredMcpOAuthState, handle: string, type: "access" | "refresh", policy: LoadedMcpOAuthPolicy): StoredToken | undefined {
    const token = this.readHandle(state, handle, policy);
    return token?.type === type ? token : undefined;
  }

  private stateFile(): string {
    return path.join(
      this.options.stateDir
        ?? process.env.RUNFREE_OAUTH_STATE_DIR
        ?? process.env.RUNFREE_MCP_OAUTH_STATE_DIR
        ?? DEFAULT_STATE_DIR,
      STATE_FILE_NAME,
    );
  }

  private projectId(): string {
    return this.options.projectId ?? process.env.RUNFREE_PROJECT_ID ?? "unknown-project";
  }

  private now(): Date {
    return this.options.now?.() ?? new Date();
  }

  private log(line: string): void {
    (this.options.log ?? console.log)(line);
  }
}
