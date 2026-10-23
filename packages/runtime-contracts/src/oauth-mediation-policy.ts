import { isReservedRunfreeHostname } from "./host-services.js";
import {
  TOKEN_NAME_PATTERN,
  assertTokenName,
  isIpLiteralHostname,
  normalizeHostname,
  normalizePathPrefix,
} from "./network-policy.js";
import { isRecord } from "./primitives.js";

export type OAuthProviderKind = "mcp" | "service";
export type OAuthSeedField = "refresh_token" | "client_secret";
export type OAuthTokenEndpointJson = string | { host: string; path: string };
// A registration endpoint entry may carry `exact: true`: the proxy then
// matches it by exact path, as it matches token endpoints, instead of by
// prefix. Discovery sets it on a registration endpoint that sits on another
// host than the server's binding hosts (cross-host), so that such a claim
// never widens response mediation to a subtree. Only registration endpoints
// accept the flag; token endpoints are always exact.
export type OAuthRegistrationEndpointJson = string | { exact?: true; host: string; path: string };
// An exact host-owned endpoint, always in object form with a normalized host.
export type OAuthExactEndpointJson = { host: string; path: string };

export type OAuthSeedJson = {
  field: OAuthSeedField;
  handle: string;
  secretRef: string;
};

export type OAuthProviderPolicyJson = {
  // The server's user (`--oauth-host`) hosts. The proxy adds them to this
  // server's binding set, so run-time capture binds a token or registration
  // endpoint that the server's own metadata names there and mediates it
  // instead of refusing it as unbound. Exact normalized hostnames, no IP
  // literals, sorted, no duplicates. MCP providers only.
  bindingHosts?: string[];
  // `false` marks a share-group non-owner: one MCP server enabled for several
  // agents is captured by exactly one owner provider, and the proxy skips
  // non-owners when it matches metadata to a server. Absent means the
  // provider captures as before. Only `false` is accepted. MCP providers only.
  captureOwner?: false;
  kind?: OAuthProviderKind;
  metadataEndpoints?: OAuthTokenEndpointJson[];
  oauth?: Record<string, unknown>;
  // Exact token/registration endpoints (a subset of this provider's static
  // tokenEndpoints/registrationEndpoints) whose POSTs the proxy classifies as
  // OAuth protocol reads while it mediates them. MCP providers only.
  protocolReadEndpoints?: OAuthTokenEndpointJson[];
  registrationEndpoints?: OAuthRegistrationEndpointJson[];
  registrationHost?: string;
  registrationPath?: string;
  resourceHost: string;
  resourcePathPrefix?: string;
  seeds?: OAuthSeedJson[];
  // Host-owned revocation epoch. The proxy stamps handles and discovered
  // endpoints with it and deletes state stamped with any other epoch, so
  // `runfree mcp revoke` clears a server's OAuth state by writing a new one.
  // MCP providers only.
  stateEpoch?: string;
  tokenEndpoints?: OAuthTokenEndpointJson[];
  tokenHost?: string;
  tokenPath?: string;
};

/**
 * Top-level host-owned fields. Each is optional; absent means today's
 * behavior, so a policy written before they existed still validates and
 * re-serializes byte-for-byte.
 *
 * - `recordOnlyHosts`: hosts that only MCP enable records allow (user or
 *   discovered entries), never desired policy, `host add`, services, or a
 *   prepared server's endpoint host. The proxy refuses an unmediated
 *   OAuth-grant- or registration-shaped request to them before any upstream
 *   connection.
 * - `recordEndpointHosts`: hosts that an MCP enable record names and that
 *   also serve a prepared MCP server endpoint, so they are not record-only.
 *   The proxy applies a narrower request check there: it refuses a request
 *   whose top-level query or body keys (or each top-level array element's
 *   keys) are grant- or registration-shaped, so MCP JSON-RPC traffic, whose
 *   nested `params` and `error` are never scanned, still passes, and it does
 *   not fail closed on bodies it cannot read. A host is never in both this
 *   list and `recordOnlyHosts`.
 * - `blockedEndpoints`: exact endpoints that a record names but the
 *   projection does not make static (dropped cross-host claims, refused
 *   declared endpoints, shared drops). The proxy keeps them on the
 *   response-mediating rule and blocks grant-shaped requests and sensitive
 *   token replies there. Matched by exact path.
 * - `refusedHosts`: hosts where no MCP provider may bind a token or
 *   registration endpoint or remember an issuer: credential destinations and
 *   curated service hosts. The proxy checks it before it remembers an issuer
 *   or endpoint, and a refusal writes no state.
 *
 *   Shape decision: one global list with an implicit per-provider exemption
 *   for that provider's own `resourceHost`, and nothing else. A host is
 *   refused for provider P exactly when
 *   `refusedHosts.includes(host) && host !== P.resourceHost`
 *   (see `oauthHostRefusedForProvider`). The refused set is the same for
 *   every provider except for its own resource host, so a per-provider copy
 *   would repeat the curated list once per server. Declared and binding
 *   hosts are deliberately not exempt. Other providers' hosts are not listed
 *   here: the proxy already holds every provider entry and can derive them.
 */
export type OAuthMediationPolicyJson = {
  blockedEndpoints?: OAuthExactEndpointJson[];
  providers: Record<string, OAuthProviderPolicyJson>;
  recordEndpointHosts?: string[];
  recordOnlyHosts?: string[];
  refusedHosts?: string[];
};

export type OAuthTokenEndpoint = {
  host: string;
  path: string;
};

export type OAuthRegistrationEndpoint = OAuthTokenEndpoint & {
  exact?: true;
};

export type OAuthSeed = {
  field: OAuthSeedField;
  handle: string;
  secretRef: string;
};

export type OAuthProviderPolicy = {
  bindingHosts: string[];
  captureOwner?: false;
  kind: OAuthProviderKind;
  metadataEndpoints: OAuthTokenEndpoint[];
  protocolReadEndpoints: OAuthTokenEndpoint[];
  providerId: string;
  registrationEndpoints: OAuthRegistrationEndpoint[];
  resourceHost: string;
  resourcePathPrefix: string;
  seeds: OAuthSeed[];
  stateEpoch?: string;
  tokenEndpoints: OAuthTokenEndpoint[];
};

export type LoadedOAuthMediationPolicy = {
  blockedEndpoints: OAuthTokenEndpoint[];
  policyPath?: string;
  providers: OAuthProviderPolicy[];
  recordEndpointHosts: string[];
  recordOnlyHosts: string[];
  refusedHosts: string[];
};

export class OAuthMediationPolicyValidationError extends Error {
  readonly issues: string[];

  constructor(issues: string[]) {
    super(`invalid OAuth mediation policy:\n${issues.map((issue) => `- ${issue}`).join("\n")}`);
    this.name = "OAuthMediationPolicyValidationError";
    this.issues = issues;
  }
}

const HANDLE_RE = /^runfree_oauth_(?:access|refresh|secret)_[A-Za-z0-9_-]{32,}$/;
export const OAUTH_STATE_EPOCH_RE = /^[A-Za-z0-9_-]{16,128}$/;

/**
 * A host in a host-owned list must already be stored in its exact normalized
 * form: the projection normalizes before it writes, and a value that needs
 * normalizing means two writers computed the host differently. IP literals,
 * localhost names, and the reserved runfree.internal suffix are refused, as
 * the CLI's `checkPolicyHostname` refuses them.
 */
function storedPolicyHost(issues: string[], prefix: string, value: unknown): string | undefined {
  if (typeof value !== "string") {
    issues.push(`${prefix} must be a hostname string`);
    return undefined;
  }
  let host: string;
  try {
    host = normalizeHostname(value);
  } catch (error) {
    issues.push(`${prefix}: ${error instanceof Error ? error.message.split("\n")[0] : String(error)}`);
    return undefined;
  }
  if (host !== value) {
    issues.push(`${prefix} must be stored as the exact normalized hostname ${host}`);
    return undefined;
  }
  if (isIpLiteralHostname(host)) {
    issues.push(`${prefix} must be a hostname, not an IP address`);
    return undefined;
  }
  if (host.endsWith(".localhost")) {
    issues.push(`${prefix} must not be a localhost name`);
    return undefined;
  }
  if (isReservedRunfreeHostname(host)) {
    issues.push(`${prefix} uses the reserved runfree.internal suffix`);
    return undefined;
  }
  return host;
}

// A sorted host list with no duplicates. Duplicates are refused rather than
// merged so that a projection bug that computes a host twice is visible.
function storedHostList(issues: string[], prefix: string, value: unknown): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    issues.push(`${prefix} must be an array of hostnames`);
    return [];
  }
  const hosts = new Set<string>();
  for (const [index, entry] of value.entries()) {
    const host = storedPolicyHost(issues, `${prefix}[${index}]`, entry);
    if (host === undefined) continue;
    if (hosts.has(host)) {
      issues.push(`${prefix}[${index}] duplicates ${host}`);
      continue;
    }
    hosts.add(host);
  }
  return [...hosts].sort();
}

// Exact endpoints in object form only, with a stored-normalized host and an
// exact path. Sorted by host then path, no duplicates.
function storedExactEndpointList(issues: string[], prefix: string, value: unknown): OAuthTokenEndpoint[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    issues.push(`${prefix} must be an array of {host,path} objects`);
    return [];
  }
  const endpoints = new Map<string, OAuthTokenEndpoint>();
  for (const [index, entry] of value.entries()) {
    const entryPrefix = `${prefix}[${index}]`;
    if (!isRecord(entry)) {
      issues.push(`${entryPrefix} must be a {host,path} object`);
      continue;
    }
    const unknownKeys = Object.keys(entry).filter((key) => key !== "host" && key !== "path");
    if (unknownKeys.length > 0) {
      issues.push(`${entryPrefix} has unsupported fields: ${unknownKeys.sort().join(", ")}`);
      continue;
    }
    const host = storedPolicyHost(issues, `${entryPrefix}.host`, entry.host);
    if (host === undefined) continue;
    if (typeof entry.path !== "string") {
      issues.push(`${entryPrefix}.path must be a string`);
      continue;
    }
    let endpointPath: string;
    try {
      endpointPath = normalizePathPrefix(entry.path);
    } catch (error) {
      issues.push(`${entryPrefix}.path: ${error instanceof Error ? error.message : String(error)}`);
      continue;
    }
    if (endpointPath !== entry.path) {
      issues.push(`${entryPrefix}.path must be stored without surrounding whitespace`);
      continue;
    }
    const endpoint = { host, path: endpointPath };
    const key = endpointKey(endpoint);
    if (endpoints.has(key)) {
      issues.push(`${entryPrefix} duplicates ${host}${endpointPath}`);
      continue;
    }
    endpoints.set(key, endpoint);
  }
  return [...endpoints.values()].sort(compareEndpoints);
}

function compareEndpoints(left: OAuthTokenEndpoint, right: OAuthTokenEndpoint): number {
  if (left.host !== right.host) return left.host < right.host ? -1 : 1;
  if (left.path !== right.path) return left.path < right.path ? -1 : 1;
  return 0;
}

/**
 * The proxy's question for `refusedHosts`: may provider P bind an endpoint
 * or remember an issuer on `host`? Refused when the host is listed, unless
 * it is P's own resource host (the only exemption; declared and binding
 * hosts are not exempt).
 */
export function oauthHostRefusedForProvider(
  policy: Pick<LoadedOAuthMediationPolicy, "refusedHosts">,
  provider: Pick<OAuthProviderPolicy, "resourceHost">,
  host: string,
): boolean {
  return host !== provider.resourceHost && policy.refusedHosts.includes(host);
}

function parseUrl(value: string): URL | undefined {
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}

function normalizeOptionalEndpoint(
  issues: string[],
  prefix: string,
  host: unknown,
  endpointPath: unknown,
): OAuthTokenEndpoint | undefined {
  if (host === undefined && endpointPath === undefined) return undefined;
  if (typeof host !== "string" || typeof endpointPath !== "string") {
    issues.push(`${prefix} host and path must both be strings`);
    return undefined;
  }
  try {
    return {
      host: normalizeHostname(host),
      path: normalizePathPrefix(endpointPath),
    };
  } catch (error) {
    issues.push(`${prefix}: ${error instanceof Error ? error.message : String(error)}`);
    return undefined;
  }
}

function endpointFromUrl(issues: string[], prefix: string, value: unknown): OAuthTokenEndpoint | undefined {
  if (typeof value !== "string") {
    issues.push(`${prefix} must be an HTTPS URL string or {host,path}`);
    return undefined;
  }
  const parsed = parseUrl(value);
  if (!parsed || parsed.protocol !== "https:") {
    issues.push(`${prefix} must be an HTTPS URL`);
    return undefined;
  }
  try {
    return {
      host: normalizeHostname(parsed.hostname),
      path: normalizePathPrefix(parsed.pathname || "/"),
    };
  } catch (error) {
    issues.push(`${prefix}: ${error instanceof Error ? error.message : String(error)}`);
    return undefined;
  }
}

function normalizeEndpointEntry(
  issues: string[],
  prefix: string,
  value: unknown,
  allowExact = false,
): OAuthRegistrationEndpoint | undefined {
  if (isRecord(value)) {
    const endpoint = normalizeOptionalEndpoint(issues, prefix, value.host, value.path);
    if (value.exact === undefined) return endpoint;
    if (!allowExact) {
      issues.push(`${prefix}.exact is only supported on registration endpoints`);
      return undefined;
    }
    if (value.exact !== true) {
      issues.push(`${prefix}.exact must be true when present`);
      return undefined;
    }
    return endpoint ? { ...endpoint, exact: true } : undefined;
  }
  return endpointFromUrl(issues, prefix, value);
}

function endpointKey(endpoint: OAuthTokenEndpoint): string {
  return `${endpoint.host}\0${endpoint.path}`;
}

function dedupeEndpoints(endpoints: OAuthTokenEndpoint[]): OAuthTokenEndpoint[] {
  return Array.from(new Map(endpoints.map((endpoint) => [endpointKey(endpoint), endpoint])).values());
}

// Registration endpoints dedupe like the others, except that one endpoint
// listed both exact and by prefix is a conflict, not a duplicate: merging
// either way would silently change how far mediation reaches.
function dedupeRegistrationEndpoints(
  issues: string[],
  prefix: string,
  endpoints: OAuthRegistrationEndpoint[],
): OAuthRegistrationEndpoint[] {
  const byKey = new Map<string, OAuthRegistrationEndpoint>();
  for (const endpoint of endpoints) {
    const key = endpointKey(endpoint);
    const existing = byKey.get(key);
    if (existing === undefined) {
      byKey.set(key, endpoint);
    } else if ((existing.exact === true) !== (endpoint.exact === true)) {
      issues.push(`${prefix} lists ${endpoint.host}${endpoint.path} both exact and by prefix`);
    }
  }
  return [...byKey.values()];
}

function normalizeEndpointArray(
  issues: string[],
  prefix: string,
  value: unknown,
  allowExact = false,
): OAuthRegistrationEndpoint[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    issues.push(`${prefix} must be an array`);
    return [];
  }
  const endpoints: OAuthRegistrationEndpoint[] = [];
  for (const [index, entry] of value.entries()) {
    const endpoint = normalizeEndpointEntry(issues, `${prefix}[${index}]`, entry, allowExact);
    if (endpoint) endpoints.push(endpoint);
  }
  return endpoints;
}

function normalizeSeeds(
  issues: string[],
  prefix: string,
  kind: OAuthProviderKind,
  value: unknown,
): OAuthSeed[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    issues.push(`${prefix}.seeds must be an array`);
    return [];
  }
  if (kind !== "service" && value.length > 0) {
    issues.push(`${prefix}.seeds are only supported for service providers`);
  }
  const seeds: OAuthSeed[] = [];
  const seen = new Set<string>();
  for (const [index, seed] of value.entries()) {
    const seedPrefix = `${prefix}.seeds[${index}]`;
    if (!isRecord(seed)) {
      issues.push(`${seedPrefix} must be an object`);
      continue;
    }
    const field = seed.field;
    if (field !== "refresh_token" && field !== "client_secret") {
      issues.push(`${seedPrefix}.field must be refresh_token or client_secret`);
      continue;
    }
    if (typeof seed.handle !== "string" || !HANDLE_RE.test(seed.handle)) {
      issues.push(`${seedPrefix}.handle must be a runfree_oauth_${field === "refresh_token" ? "refresh" : "secret"} handle`);
      continue;
    }
    if (field === "refresh_token" && !seed.handle.startsWith("runfree_oauth_refresh_")) {
      issues.push(`${seedPrefix}.handle must use the runfree_oauth_refresh_ prefix`);
      continue;
    }
    if (field === "client_secret" && !seed.handle.startsWith("runfree_oauth_secret_")) {
      issues.push(`${seedPrefix}.handle must use the runfree_oauth_secret_ prefix`);
      continue;
    }
    if (typeof seed.secretRef !== "string") {
      issues.push(`${seedPrefix}.secretRef must be a token-name-compatible string`);
      continue;
    }
    try {
      assertTokenName(seed.secretRef);
    } catch {
      issues.push(`${seedPrefix}.secretRef must match ${TOKEN_NAME_PATTERN.source}`);
      continue;
    }
    const key = `${field}\0${seed.handle}`;
    if (seen.has(key)) {
      issues.push(`${seedPrefix} duplicates a seed for ${field}`);
      continue;
    }
    seen.add(key);
    seeds.push({ field, handle: seed.handle, secretRef: seed.secretRef });
  }
  return seeds;
}

function normalizeProvider(
  providerId: string,
  value: unknown,
  issues: string[],
): OAuthProviderPolicy | undefined {
  const prefix = `providers.${providerId}`;
  if (!isRecord(value)) {
    issues.push(`${prefix} must be an object`);
    return undefined;
  }
  const kind = value.kind === undefined ? "mcp" : value.kind;
  if (kind !== "mcp" && kind !== "service") {
    issues.push(`${prefix}.kind must be mcp or service`);
    return undefined;
  }
  if (typeof value.resourceHost !== "string") {
    issues.push(`${prefix}.resourceHost must be a string`);
    return undefined;
  }
  let resourceHost: string;
  let resourcePathPrefix: string;
  try {
    resourceHost = normalizeHostname(value.resourceHost);
    resourcePathPrefix = normalizePathPrefix(
      typeof value.resourcePathPrefix === "string" ? value.resourcePathPrefix : "/",
    );
  } catch (error) {
    issues.push(`${prefix}: ${error instanceof Error ? error.message : String(error)}`);
    return undefined;
  }

  const tokenEndpoints: OAuthTokenEndpoint[] = [];
  const inline = normalizeOptionalEndpoint(issues, `${prefix}.token`, value.tokenHost, value.tokenPath);
  if (inline) tokenEndpoints.push(inline);
  tokenEndpoints.push(...normalizeEndpointArray(issues, `${prefix}.tokenEndpoints`, value.tokenEndpoints));

  const registrationEndpoints: OAuthRegistrationEndpoint[] = [];
  const inlineRegistration = normalizeOptionalEndpoint(issues, `${prefix}.registration`, value.registrationHost, value.registrationPath);
  if (inlineRegistration) registrationEndpoints.push(inlineRegistration);
  registrationEndpoints.push(...normalizeEndpointArray(issues, `${prefix}.registrationEndpoints`, value.registrationEndpoints, true));

  const metadataEndpoints: OAuthTokenEndpoint[] = [];
  const oauth = isRecord(value.oauth) ? value.oauth : undefined;
  const authMetadata = oauth?.authServerMetadataUrl === undefined ? undefined : endpointFromUrl(issues, `${prefix}.oauth.authServerMetadataUrl`, oauth.authServerMetadataUrl);
  if (authMetadata) metadataEndpoints.push(authMetadata);
  // The host re-emits a loaded policy with its metadata endpoints as a list
  // (oauthProviderPolicyJson); read them back so they survive publication.
  metadataEndpoints.push(...normalizeEndpointArray(issues, `${prefix}.metadataEndpoints`, value.metadataEndpoints));
  const oauthRegistration = oauth?.registrationEndpoint ?? oauth?.registration_endpoint;
  const oauthRegistrationEndpoint = oauthRegistration === undefined ? undefined : endpointFromUrl(issues, `${prefix}.oauth.registrationEndpoint`, oauthRegistration);
  if (oauthRegistrationEndpoint) registrationEndpoints.push(oauthRegistrationEndpoint);

  const seeds = normalizeSeeds(issues, prefix, kind, value.seeds);

  let stateEpoch: string | undefined;
  if (value.stateEpoch !== undefined) {
    if (kind !== "mcp") {
      issues.push(`${prefix}.stateEpoch is only supported for mcp providers`);
    } else if (typeof value.stateEpoch !== "string" || !OAUTH_STATE_EPOCH_RE.test(value.stateEpoch)) {
      issues.push(`${prefix}.stateEpoch must match ${OAUTH_STATE_EPOCH_RE.source}`);
    } else {
      stateEpoch = value.stateEpoch;
    }
  }

  let bindingHosts: string[] = [];
  if (value.bindingHosts !== undefined) {
    if (kind !== "mcp") {
      issues.push(`${prefix}.bindingHosts are only supported for mcp providers`);
    } else {
      bindingHosts = storedHostList(issues, `${prefix}.bindingHosts`, value.bindingHosts);
    }
  }

  let captureOwner: false | undefined;
  if (value.captureOwner !== undefined) {
    if (kind !== "mcp") {
      issues.push(`${prefix}.captureOwner is only supported for mcp providers`);
    } else if (value.captureOwner !== false) {
      issues.push(`${prefix}.captureOwner must be false when present (absent means the provider captures)`);
    } else {
      captureOwner = false;
    }
  }

  // A protocol-read endpoint must be one of this provider's static mediated
  // token or registration endpoints, exactly: the proxy classifies a POST to
  // it as a read only while it mediates it, and never by prefix.
  const protocolReadEndpoints: OAuthTokenEndpoint[] = [];
  if (value.protocolReadEndpoints !== undefined) {
    if (kind !== "mcp") {
      issues.push(`${prefix}.protocolReadEndpoints are only supported for mcp providers`);
    } else {
      const mediated = new Set([...tokenEndpoints, ...registrationEndpoints].map(endpointKey));
      const declared = normalizeEndpointArray(issues, `${prefix}.protocolReadEndpoints`, value.protocolReadEndpoints);
      for (const [index, endpoint] of declared.entries()) {
        if (endpoint.path === "/") {
          issues.push(`${prefix}.protocolReadEndpoints[${index}] must not be the root path`);
        } else if (!mediated.has(endpointKey(endpoint))) {
          issues.push(`${prefix}.protocolReadEndpoints[${index}] must be a static token or registration endpoint of the same provider`);
        } else {
          protocolReadEndpoints.push(endpoint);
        }
      }
    }
  }

  return {
    bindingHosts,
    ...(captureOwner !== undefined ? { captureOwner } : {}),
    kind,
    metadataEndpoints: dedupeEndpoints(metadataEndpoints),
    protocolReadEndpoints: dedupeEndpoints(protocolReadEndpoints),
    providerId,
    registrationEndpoints: dedupeRegistrationEndpoints(issues, `${prefix}.registrationEndpoints`, registrationEndpoints),
    resourceHost,
    resourcePathPrefix,
    seeds,
    ...(stateEpoch !== undefined ? { stateEpoch } : {}),
    tokenEndpoints: dedupeEndpoints(tokenEndpoints),
  };
}

/**
 * The one JSON form of a validated provider, used wherever the host re-emits
 * a loaded policy (the effective generation input and payload). The new
 * optional fields appear only when set, so a provider without them serializes
 * exactly as it did before they existed.
 */
export function oauthProviderPolicyJson(provider: OAuthProviderPolicy): OAuthProviderPolicyJson {
  return {
    kind: provider.kind,
    resourceHost: provider.resourceHost,
    resourcePathPrefix: provider.resourcePathPrefix,
    tokenEndpoints: provider.tokenEndpoints.map(({ host, path }) => ({ host, path })),
    registrationEndpoints: provider.registrationEndpoints.map(({ exact, host, path }) => (
      exact === true ? { exact, host, path } : { host, path }
    )),
    metadataEndpoints: provider.metadataEndpoints.map(({ host, path }) => ({ host, path })),
    seeds: provider.seeds.map((seed) => ({ ...seed })),
    ...(provider.protocolReadEndpoints.length > 0
      ? { protocolReadEndpoints: provider.protocolReadEndpoints.map(({ host, path }) => ({ host, path })) }
      : {}),
    ...(provider.stateEpoch !== undefined ? { stateEpoch: provider.stateEpoch } : {}),
    ...(provider.bindingHosts.length > 0 ? { bindingHosts: [...provider.bindingHosts] } : {}),
    ...(provider.captureOwner === false ? { captureOwner: false as const } : {}),
  };
}

/**
 * The top-level fields of a validated policy in JSON form, each only when
 * non-empty, so a policy without them re-serializes exactly as before.
 * Callers that re-emit a loaded policy spread this beside `providers`.
 */
export function oauthMediationPolicyTopLevelJson(
  policy: Pick<LoadedOAuthMediationPolicy, "blockedEndpoints" | "recordEndpointHosts" | "recordOnlyHosts" | "refusedHosts">,
): Omit<OAuthMediationPolicyJson, "providers"> {
  return {
    ...(policy.blockedEndpoints.length > 0
      ? { blockedEndpoints: policy.blockedEndpoints.map(({ host, path }) => ({ host, path })) }
      : {}),
    ...(policy.recordEndpointHosts.length > 0 ? { recordEndpointHosts: [...policy.recordEndpointHosts] } : {}),
    ...(policy.recordOnlyHosts.length > 0 ? { recordOnlyHosts: [...policy.recordOnlyHosts] } : {}),
    ...(policy.refusedHosts.length > 0 ? { refusedHosts: [...policy.refusedHosts] } : {}),
  };
}

/** The one JSON form of a whole validated policy (providers in load order). */
export function oauthMediationPolicyJson(policy: LoadedOAuthMediationPolicy): OAuthMediationPolicyJson {
  return {
    ...oauthMediationPolicyTopLevelJson(policy),
    providers: Object.fromEntries(policy.providers.map((provider) => [provider.providerId, oauthProviderPolicyJson(provider)])),
  };
}

export function validateOAuthMediationPolicy(raw: unknown, policyPath?: string): LoadedOAuthMediationPolicy {
  const issues: string[] = [];
  if (!isRecord(raw)) {
    throw new OAuthMediationPolicyValidationError(["policy must be a JSON object"]);
  }
  if (!isRecord(raw.providers)) {
    throw new OAuthMediationPolicyValidationError(["providers must be an object"]);
  }

  const providers: OAuthProviderPolicy[] = [];
  for (const [providerId, provider] of Object.entries(raw.providers)) {
    if (providerId.trim() === "") {
      issues.push("provider ids must be non-empty");
      continue;
    }
    const normalized = normalizeProvider(providerId, provider, issues);
    if (normalized) providers.push(normalized);
  }

  const recordOnlyHosts = storedHostList(issues, "recordOnlyHosts", raw.recordOnlyHosts);
  const recordEndpointHosts = storedHostList(issues, "recordEndpointHosts", raw.recordEndpointHosts);
  // The two lists select different request checks for one host; a host in
  // both means the projection disagrees with itself about whether the host
  // serves an MCP endpoint.
  const recordOnly = new Set(recordOnlyHosts);
  for (const host of recordEndpointHosts) {
    if (recordOnly.has(host)) issues.push(`recordEndpointHosts lists ${host}, which recordOnlyHosts also lists`);
  }
  const refusedHosts = storedHostList(issues, "refusedHosts", raw.refusedHosts);
  const blockedEndpoints = storedExactEndpointList(issues, "blockedEndpoints", raw.blockedEndpoints);

  if (issues.length > 0) throw new OAuthMediationPolicyValidationError(issues);
  return {
    blockedEndpoints,
    ...(policyPath !== undefined ? { policyPath } : {}),
    providers,
    recordEndpointHosts,
    recordOnlyHosts,
    refusedHosts,
  };
}
