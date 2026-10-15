import {
  TOKEN_NAME_PATTERN,
  assertTokenName,
  normalizeHostname,
  normalizePathPrefix,
} from "./network-policy.js";
import { isRecord } from "./primitives.js";

export type OAuthProviderKind = "mcp" | "service";
export type OAuthSeedField = "refresh_token" | "client_secret";
export type OAuthTokenEndpointJson = string | { host: string; path: string };

export type OAuthSeedJson = {
  field: OAuthSeedField;
  handle: string;
  secretRef: string;
};

export type OAuthProviderPolicyJson = {
  kind?: OAuthProviderKind;
  metadataEndpoints?: OAuthTokenEndpointJson[];
  oauth?: Record<string, unknown>;
  registrationEndpoints?: OAuthTokenEndpointJson[];
  registrationHost?: string;
  registrationPath?: string;
  resourceHost: string;
  resourcePathPrefix?: string;
  seeds?: OAuthSeedJson[];
  tokenEndpoints?: OAuthTokenEndpointJson[];
  tokenHost?: string;
  tokenPath?: string;
};

export type OAuthMediationPolicyJson = {
  providers: Record<string, OAuthProviderPolicyJson>;
};

export type OAuthTokenEndpoint = {
  host: string;
  path: string;
};

export type OAuthSeed = {
  field: OAuthSeedField;
  handle: string;
  secretRef: string;
};

export type OAuthProviderPolicy = {
  kind: OAuthProviderKind;
  metadataEndpoints: OAuthTokenEndpoint[];
  providerId: string;
  registrationEndpoints: OAuthTokenEndpoint[];
  resourceHost: string;
  resourcePathPrefix: string;
  seeds: OAuthSeed[];
  tokenEndpoints: OAuthTokenEndpoint[];
};

export type LoadedOAuthMediationPolicy = {
  policyPath?: string;
  providers: OAuthProviderPolicy[];
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

function normalizeEndpointEntry(issues: string[], prefix: string, value: unknown): OAuthTokenEndpoint | undefined {
  if (isRecord(value)) {
    return normalizeOptionalEndpoint(issues, prefix, value.host, value.path);
  }
  return endpointFromUrl(issues, prefix, value);
}

function dedupeEndpoints(endpoints: OAuthTokenEndpoint[]): OAuthTokenEndpoint[] {
  return Array.from(new Map(endpoints.map((endpoint) => [`${endpoint.host}\0${endpoint.path}`, endpoint])).values());
}

function normalizeEndpointArray(
  issues: string[],
  prefix: string,
  value: unknown,
): OAuthTokenEndpoint[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    issues.push(`${prefix} must be an array`);
    return [];
  }
  const endpoints: OAuthTokenEndpoint[] = [];
  for (const [index, entry] of value.entries()) {
    const endpoint = normalizeEndpointEntry(issues, `${prefix}[${index}]`, entry);
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

  const registrationEndpoints: OAuthTokenEndpoint[] = [];
  const inlineRegistration = normalizeOptionalEndpoint(issues, `${prefix}.registration`, value.registrationHost, value.registrationPath);
  if (inlineRegistration) registrationEndpoints.push(inlineRegistration);
  registrationEndpoints.push(...normalizeEndpointArray(issues, `${prefix}.registrationEndpoints`, value.registrationEndpoints));

  const metadataEndpoints: OAuthTokenEndpoint[] = [];
  const oauth = isRecord(value.oauth) ? value.oauth : undefined;
  const authMetadata = oauth?.authServerMetadataUrl === undefined ? undefined : endpointFromUrl(issues, `${prefix}.oauth.authServerMetadataUrl`, oauth.authServerMetadataUrl);
  if (authMetadata) metadataEndpoints.push(authMetadata);
  const oauthRegistration = oauth?.registrationEndpoint ?? oauth?.registration_endpoint;
  const oauthRegistrationEndpoint = oauthRegistration === undefined ? undefined : endpointFromUrl(issues, `${prefix}.oauth.registrationEndpoint`, oauthRegistration);
  if (oauthRegistrationEndpoint) registrationEndpoints.push(oauthRegistrationEndpoint);

  const seeds = normalizeSeeds(issues, prefix, kind, value.seeds);

  return {
    kind,
    metadataEndpoints: dedupeEndpoints(metadataEndpoints),
    providerId,
    registrationEndpoints: dedupeEndpoints(registrationEndpoints),
    resourceHost,
    resourcePathPrefix,
    seeds,
    tokenEndpoints: dedupeEndpoints(tokenEndpoints),
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

  if (issues.length > 0) throw new OAuthMediationPolicyValidationError(issues);
  return {
    ...(policyPath !== undefined ? { policyPath } : {}),
    providers,
  };
}
