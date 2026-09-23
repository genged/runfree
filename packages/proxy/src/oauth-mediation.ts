import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  validateOAuthMediationPolicy,
  type LoadedOAuthMediationPolicy,
  type OAuthProviderPolicy,
  type OAuthSeed,
  type OAuthTokenEndpoint,
} from "@runfree/runtime-contracts/oauth-mediation-policy";
import { normalizeHostname, normalizePathPrefix, pathMatchesPrefix, readTokenFile } from "./policy.js";
import { isRecord } from "@runfree/runtime-contracts/primitives";

const ACCESS_HANDLE_PREFIX = "runfree_oauth_access_";
const REFRESH_HANDLE_PREFIX = "runfree_oauth_refresh_";
const SECRET_HANDLE_PREFIX = "runfree_oauth_secret_";
const HANDLE_RE = /^runfree_oauth_(?:access|refresh|secret)_[A-Za-z0-9_-]{32,}$/;
const DEFAULT_STATE_DIR = "/run/runfree-oauth";
const STATE_FILE_NAME = "handles.json";

type HeaderValue = string | string[] | undefined;

export type OAuthProxyRequest = {
  body?: {
    getText(): Promise<string | undefined>;
  };
  headers?: Record<string, HeaderValue>;
  id?: string;
  method?: string;
  url: string;
};

export type OAuthProxyResponse = {
  body: {
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
  kind: "mcp" | "service";
  metadataEndpoints: TokenEndpoint[];
  name: string;
  registrationEndpoints: TokenEndpoint[];
  resourceHost: string;
  resourcePathPrefix: string;
  seeds: OAuthSeed[];
  tokenEndpoints: TokenEndpoint[];
};

type LoadedMcpOAuthPolicy = {
  policyPath?: string;
  servers: McpOAuthServerPolicy[];
};

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
  token?: string;
  tokenEndpointHost: string;
  tokenEndpointPath: string;
  type: "access" | "refresh" | "secret";
};

type StoredDiscovery = Record<string, {
  issuerHosts?: string[];
  registrationEndpoints?: TokenEndpoint[];
  tokenEndpoints?: TokenEndpoint[];
}>;

type StoredMcpOAuthState = {
  discovered?: StoredDiscovery;
  handles?: Record<string, StoredToken>;
};

export type OAuthIssuerDenialContext = {
  providerId: string;
  resourceHost: string;
};

type SensitiveOAuthRequest = {
  endpoint: TokenEndpoint;
  kind: "registration" | "token";
  server: McpOAuthServerPolicy;
};


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
    kind: provider.kind,
    metadataEndpoints: provider.metadataEndpoints,
    name: provider.providerId,
    registrationEndpoints: provider.registrationEndpoints,
    resourceHost: provider.resourceHost,
    resourcePathPrefix: provider.resourcePathPrefix,
    seeds: provider.seeds,
    tokenEndpoints: provider.tokenEndpoints,
  };
}

function loadPolicy(policyPath: string | undefined): LoadedMcpOAuthPolicy {
  if (!policyPath) return { servers: [] };
  const raw = JSON.parse(fs.readFileSync(policyPath, "utf8")) as unknown;
  const loaded = validateOAuthMediationPolicy(raw, policyPath);
  return mediatorPolicy(loaded);
}

function mediatorPolicy(loaded: LoadedOAuthMediationPolicy): LoadedMcpOAuthPolicy {
  return {
    ...(loaded.policyPath ? { policyPath: loaded.policyPath } : {}),
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

function storedTokenMatchesCurrentServer(token: StoredToken, server: McpOAuthServerPolicy): boolean {
  return token.resourceHost === server.resourceHost
    && token.resourcePathPrefix === server.resourcePathPrefix;
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
  for (const name of Object.keys(state.discovered ?? {})) {
    if (!servers.has(name)) {
      delete state.discovered?.[name];
      changed = true;
    }
  }
  return changed;
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
  const discovered = state.discovered?.[server.name]?.tokenEndpoints ?? [];
  return [
    ...server.tokenEndpoints,
    ...discovered,
  ];
}

function registrationEndpointList(server: McpOAuthServerPolicy, state: StoredMcpOAuthState): TokenEndpoint[] {
  const discovered = state.discovered?.[server.name]?.registrationEndpoints ?? [];
  return [
    ...server.registrationEndpoints,
    ...discovered,
  ];
}

// Hosts a server's discovered endpoints may legitimately point at: the MCP
// resource host plus any statically-configured (host-trusted) metadata, token,
// or registration hosts. Discovered endpoints are deliberately excluded so one
// runtime-discovered endpoint cannot bootstrap trust for an unrelated one. This
// bounds the "resource-host metadata names an unrelated host for token relay"
// attack: a discovered token/registration endpoint outside this set is ignored.
function serverBindingHosts(server: McpOAuthServerPolicy): Set<string> {
  const hosts = new Set<string>([server.resourceHost]);
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
  return state.discovered?.[server.name]?.issuerHosts ?? [];
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

function matchingTokenServer(policy: LoadedMcpOAuthPolicy, state: StoredMcpOAuthState, url: URL): McpOAuthServerPolicy | undefined {
  return policy.servers.find((server) => {
    return tokenEndpointList(server, state).some((endpoint) => tokenEndpointMatches(endpoint, url));
  });
}

function matchingRegistrationServer(policy: LoadedMcpOAuthPolicy, state: StoredMcpOAuthState, url: URL): McpOAuthServerPolicy | undefined {
  return policy.servers.find((server) => {
    return registrationEndpointList(server, state).some((endpoint) => {
      return endpoint.host === url.hostname.toLowerCase()
        && pathMatchesPrefix(url.pathname || "/", endpoint.path);
    });
  });
}

function matchingMetadataServer(policy: LoadedMcpOAuthPolicy, state: StoredMcpOAuthState, url: URL): McpOAuthServerPolicy | undefined {
  if (!url.pathname.includes("/.well-known/")) return undefined;
  const host = url.hostname.toLowerCase();
  return policy.servers.find((server) => {
    return server.metadataEndpoints.some((endpoint) => tokenEndpointMatches(endpoint, url))
      || server.resourceHost === host
      || discoveredIssuerHosts(server, state).includes(host);
  });
}

function rememberIssuerHost(state: StoredMcpOAuthState, serverName: string, host: string): boolean {
  state.discovered ??= {};
  const entry = state.discovered[serverName] ?? {};
  const hosts = entry.issuerHosts ?? [];
  if (hosts.includes(host)) return false;
  entry.issuerHosts = [...hosts, host].sort();
  state.discovered[serverName] = entry;
  return true;
}

function sameEndpoint(left: TokenEndpoint, right: TokenEndpoint): boolean {
  return left.host === right.host && left.path === right.path;
}

function rememberEndpoint(
  state: StoredMcpOAuthState,
  serverName: string,
  endpoint: TokenEndpoint,
  field: "registrationEndpoints" | "tokenEndpoints",
): boolean {
  state.discovered ??= {};
  const entry = state.discovered[serverName] ?? {};
  const endpoints = entry[field] ?? [];
  if (endpoints.some((existing) => sameEndpoint(existing, endpoint))) return false;
  entry[field] = [...endpoints, endpoint].sort((left, right) => `${left.host}\0${left.path}`.localeCompare(`${right.host}\0${right.path}`));
  state.discovered[serverName] = entry;
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
    token: options.token,
    tokenEndpointHost: options.tokenEndpoint.host,
    tokenEndpointPath: options.tokenEndpoint.path,
    type: options.type,
  };
  return handle;
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
    log?: (line: string) => void;
    now?: () => Date;
    pairedPolicy?: LoadedOAuthMediationPolicy;
    policyPath?: string;
    projectId?: string;
    stateDir?: string;
    tokenDir?: string;
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

  beforeRequest = async (req: OAuthProxyRequest): Promise<OAuthRequestResult | undefined> => {
    const policyState = this.currentPolicyState();
    const url = parseUrl(req.url);
    if (!url || url.protocol !== "https:") return undefined;
    const state = this.currentState();
    if (!policyState.valid) {
      return this.rejectRequestWhilePolicyUnavailable(req, policyState.policy, state, url);
    }
    const policy = policyState.policy;
    const handle = bearerHandle(req.headers);
    if (handle) {
      return this.authorizeBearerHandleRequest(req, url, state, handle, policy);
    }
    if (policy.servers.length === 0) return undefined;
    this.rememberSensitiveRequest(req, policy, state, url);
    return await this.replaceRefreshHandleRequest(req, url, policy, state);
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
  requestNeedsResponseMediation = (req: { url: string }): boolean => {
    const url = parseUrl(req.url);
    if (!url || url.protocol !== "https:") return false;
    const policyState = this.currentPolicyState();
    if (!policyState.valid || policyState.policy.servers.length === 0) return false;
    let state: StoredMcpOAuthState;
    try {
      state = this.currentState();
    } catch {
      return false;
    }
    const policy = policyState.policy;
    return matchingMetadataServer(policy, state, url) !== undefined
      || matchingTokenServer(policy, state, url) !== undefined
      || matchingRegistrationServer(policy, state, url) !== undefined;
  };

  beforeResponse = async (
    res: OAuthProxyResponse,
    req: OAuthProxyRequest,
  ): Promise<OAuthResponseResult | undefined> => {
    const pending = this.takeSensitiveRequest(req);
    const policyState = this.currentPolicyState();
    const policy = policyState.policy;
    const requestUrl = parseUrl(req.url);
    if (!requestUrl || requestUrl.protocol !== "https:") return undefined;
    if ((!policyState.valid || policy.servers.length === 0) && !pending) return undefined;
    if (res.statusCode < 200 || res.statusCode >= 300) return undefined;
    const text = await res.body.getText();
    return await this.withStateLock(() => {
      const state = this.currentState();
      const couldBeMetadata = policyState.valid && matchingMetadataServer(policy, state, requestUrl) !== undefined;
      const server = pending?.kind === "token"
        ? pending.server
        : policyState.valid ? matchingTokenServer(policy, state, requestUrl) : undefined;
      const registrationServer = pending?.kind === "registration"
        ? pending.server
        : policyState.valid ? matchingRegistrationServer(policy, state, requestUrl) : undefined;
      if (!server && !registrationServer && !couldBeMetadata) return undefined;
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
      if (policyState.valid && this.captureMetadataEndpoint(policy, state, requestUrl, parsed)) return undefined;
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
      writeState(this.stateFile(), state);
      this.log(`proxy: oauth token_exchange ok name=${server.name} access=handle refresh=${next.refreshStatus}`);
      return {
        body: JSON.stringify(next.body),
        headers: stripContentLength(setHeader(res.headers ?? {}, "content-type", "application/json")),
      };
    });
  };

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

  private rememberSensitiveRequest(
    req: OAuthProxyRequest,
    policy: LoadedMcpOAuthPolicy,
    state: StoredMcpOAuthState,
    url: URL,
  ): void {
    if (typeof req.id !== "string" || req.id === "") return;
    const tokenServer = matchingTokenServer(policy, state, url);
    if (tokenServer) {
      this.pendingSensitiveRequests.set(req.id, {
        endpoint: safeTokenEndpoint(url),
        kind: "token",
        server: tokenServer,
      });
      return;
    }
    const registrationServer = matchingRegistrationServer(policy, state, url);
    if (registrationServer) {
      this.pendingSensitiveRequests.set(req.id, {
        endpoint: safeTokenEndpoint(url),
        kind: "registration",
        server: registrationServer,
      });
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
        if (issuer && rememberIssuerHost(state, server.name, issuer.host)) {
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
      if (tokenEndpoint && this.assertBoundDiscoveredEndpoint(server, bindingHosts, tokenEndpoint, "token_endpoint")) {
        endpointChanged = rememberEndpoint(state, server.name, tokenEndpoint, "tokenEndpoints") || endpointChanged;
      }
      if (registrationEndpoint && this.assertBoundDiscoveredEndpoint(server, bindingHosts, registrationEndpoint, "registration_endpoint")) {
        endpointChanged = rememberEndpoint(state, server.name, registrationEndpoint, "registrationEndpoints") || endpointChanged;
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
    if (matchingTokenServer(policy, state, url)
      || matchingRegistrationServer(policy, state, url)
      || matchingMetadataServer(policy, state, url)) {
      return forbidden("OAuth policy unavailable");
    }
    return undefined;
  }

  private currentPolicyState(): CurrentMcpOAuthPolicy {
    if (this.pairedPolicy && this.loadedPolicy) return { policy: this.loadedPolicy, valid: true };
    const policyPath = this.options.policyPath
      ?? process.env.RUNFREE_OAUTH_POLICY
      ?? process.env.RUNFREE_MCP_OAUTH_POLICY;
    if (!policyPath) return { policy: { servers: [] }, valid: true };
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
      this.loadedPolicy = loadPolicy(policyPath);
      this.loadedPolicyMtimeMs = stat.mtimeMs;
      this.lastPolicyReloadFailure = undefined;
      this.pruneStateForLoadedPolicy(this.loadedPolicy);
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
      policy: this.loadedPolicy ?? { policyPath, servers: [] },
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
