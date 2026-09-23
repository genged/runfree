

import {
  normalizeHostname,
  normalizePathPrefix,
  validateNetworkPolicy,
  type PolicyJson,
  type RequestPolicyJson,
  type TokenPolicyJson,
  type WriteAction,
} from "./network-policy.js";
import { isRecord, stableJson, sha256Digest } from "./primitives.js";

export const DESIRED_NETWORK_POLICY_VERSION = 2 as const;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const PARAMETER_KEY_PATTERN = /^[a-z][a-z0-9-]{0,31}$/;
const OAUTH_FIELD_PATTERN = /^[a-z][a-z0-9_]{0,31}$/;

export type DesiredServiceSelection = {
  skippedHosts?: string[];
  writeMode?: "allow-write" | "read-only";
};

export type DesiredOAuthEndpoint = { host: string; path: string };
export type DesiredOAuthProvider = {
  passthrough?: Array<{ envVar: string; field: "client_id" }>;
  registrationEndpoints?: DesiredOAuthEndpoint[];
  resourceHost: string;
  resourcePathPrefix?: string;
  seeds?: Array<{
    description: string;
    envVar: string;
    field: "refresh_token" | "client_secret";
    tokenName: string;
  }>;
  tokenEndpoints: DesiredOAuthEndpoint[];
};

// A declared non-secret service input, projected into the agent env under
// `envVar` from the host-owned value recorded at enable time. `agentEnv` lists
// the same name; `pattern`/`example` are registry-only supply-time hints.
export type DesiredServiceParameter = {
  description: string;
  envVar: string;
  key: string;
  oauthField?: string;
};

export type DesiredServiceResolved = {
  agentEnv?: string[];
  hosts: string[];
  oauth?: Record<string, DesiredOAuthProvider>;
  parameters?: DesiredServiceParameter[];
  requests?: Record<string, RequestPolicyJson>;
  tokens?: Record<string, TokenPolicyJson>;
};

export type DesiredServiceEntry = {
  definitionDigest: string;
  resolved: DesiredServiceResolved;
  revision: number;
  selection?: DesiredServiceSelection;
};

export type DesiredNetworkPolicyJson = {
  hosts: string[];
  requests?: Record<string, RequestPolicyJson>;
  services?: Record<string, DesiredServiceEntry>;
  tokens?: Record<string, TokenPolicyJson>;
  version: typeof DESIRED_NETWORK_POLICY_VERSION;
  writeApproval?: WriteAction;
};

export class DesiredNetworkPolicyValidationError extends Error {
  readonly issues: string[];

  constructor(issues: string[]) {
    super(`invalid desired network policy:\n${issues.map((issue) => `- ${issue}`).join("\n")}`);
    this.name = "DesiredNetworkPolicyValidationError";
    this.issues = issues;
  }
}


function exactKeys(value: Record<string, unknown>, allowed: readonly string[], prefix: string, issues: string[]): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) issues.push(`${prefix}${key} is not a known field (known: ${allowed.join(", ")})`);
  }
}


function stableUnique(values: readonly string[]): string[] {
  return Array.from(new Set(values)).sort((left, right) => left.localeCompare(right));
}

function validateEndpoint(value: unknown, prefix: string, issues: string[]): DesiredOAuthEndpoint | undefined {
  if (!isRecord(value)) {
    issues.push(`${prefix} must be an object`);
    return undefined;
  }
  exactKeys(value, ["host", "path"], `${prefix}.`, issues);
  if (typeof value.host !== "string" || typeof value.path !== "string") {
    issues.push(`${prefix}.host and .path must be strings`);
    return undefined;
  }
  try {
    const host = normalizeHostname(value.host);
    const endpointPath = normalizePathPrefix(value.path);
    if (host !== value.host) issues.push(`${prefix}.host must be stored as ${host}`);
    if (endpointPath !== value.path) issues.push(`${prefix}.path must be stored as ${endpointPath}`);
    return { host, path: endpointPath };
  } catch (error) {
    issues.push(`${prefix}: ${error instanceof Error ? error.message : String(error)}`);
    return undefined;
  }
}

function validateEndpoints(value: unknown, prefix: string, issues: string[]): DesiredOAuthEndpoint[] {
  if (!Array.isArray(value)) {
    issues.push(`${prefix} must be an array`);
    return [];
  }
  const endpoints = value.flatMap((entry, index) => {
    const endpoint = validateEndpoint(entry, `${prefix}[${index}]`, issues);
    return endpoint ? [endpoint] : [];
  });
  const keys = endpoints.map((endpoint) => `${endpoint.host}\0${endpoint.path}`);
  if (new Set(keys).size !== keys.length) issues.push(`${prefix} must not contain duplicate endpoints`);
  return endpoints.sort((left, right) => `${left.host}\0${left.path}`.localeCompare(`${right.host}\0${right.path}`));
}

function validateOAuthProvider(value: unknown, prefix: string, issues: string[]): DesiredOAuthProvider | undefined {
  if (!isRecord(value)) {
    issues.push(`${prefix} must be an object`);
    return undefined;
  }
  exactKeys(value, [
    "passthrough",
    "registrationEndpoints",
    "resourceHost",
    "resourcePathPrefix",
    "seeds",
    "tokenEndpoints",
  ], `${prefix}.`, issues);
  if (typeof value.resourceHost !== "string") {
    issues.push(`${prefix}.resourceHost must be a string`);
    return undefined;
  }
  let resourceHost: string;
  let resourcePathPrefix: string | undefined;
  try {
    resourceHost = normalizeHostname(value.resourceHost);
    if (resourceHost !== value.resourceHost) issues.push(`${prefix}.resourceHost must be stored as ${resourceHost}`);
    if (value.resourcePathPrefix !== undefined) {
      if (typeof value.resourcePathPrefix !== "string") throw new Error("resourcePathPrefix must be a string");
      resourcePathPrefix = normalizePathPrefix(value.resourcePathPrefix);
      if (resourcePathPrefix !== value.resourcePathPrefix) {
        issues.push(`${prefix}.resourcePathPrefix must be stored as ${resourcePathPrefix}`);
      }
    }
  } catch (error) {
    issues.push(`${prefix}: ${error instanceof Error ? error.message : String(error)}`);
    return undefined;
  }
  const tokenEndpoints = validateEndpoints(value.tokenEndpoints, `${prefix}.tokenEndpoints`, issues);
  const registrationEndpoints = value.registrationEndpoints === undefined
    ? undefined
    : validateEndpoints(value.registrationEndpoints, `${prefix}.registrationEndpoints`, issues);
  const seeds = value.seeds === undefined ? undefined : (() => {
    if (!Array.isArray(value.seeds)) {
      issues.push(`${prefix}.seeds must be an array`);
      return [];
    }
    return value.seeds.flatMap((entry, index) => {
      const itemPrefix = `${prefix}.seeds[${index}]`;
      if (!isRecord(entry)) {
        issues.push(`${itemPrefix} must be an object`);
        return [];
      }
      exactKeys(entry, ["description", "envVar", "field", "tokenName"], `${itemPrefix}.`, issues);
      if ((entry.field !== "refresh_token" && entry.field !== "client_secret")
        || typeof entry.envVar !== "string" || !ENV_NAME_PATTERN.test(entry.envVar)
        || typeof entry.tokenName !== "string" || !/^[a-z][a-z0-9_-]{0,63}$/.test(entry.tokenName)
        || typeof entry.description !== "string" || entry.description.trim() === "") {
        issues.push(`${itemPrefix} is malformed`);
        return [];
      }
      return [{
        description: entry.description,
        envVar: entry.envVar,
        field: entry.field as "refresh_token" | "client_secret",
        tokenName: entry.tokenName,
      }];
    });
  })();
  const passthrough = value.passthrough === undefined ? undefined : (() => {
    if (!Array.isArray(value.passthrough)) {
      issues.push(`${prefix}.passthrough must be an array`);
      return [];
    }
    return value.passthrough.flatMap((entry, index) => {
      const itemPrefix = `${prefix}.passthrough[${index}]`;
      if (!isRecord(entry)) {
        issues.push(`${itemPrefix} must be an object`);
        return [];
      }
      exactKeys(entry, ["envVar", "field"], `${itemPrefix}.`, issues);
      if (entry.field !== "client_id" || typeof entry.envVar !== "string" || !ENV_NAME_PATTERN.test(entry.envVar)) {
        issues.push(`${itemPrefix} is malformed`);
        return [];
      }
      return [{ envVar: entry.envVar, field: "client_id" as const }];
    });
  })();
  return {
    resourceHost,
    tokenEndpoints,
    ...(resourcePathPrefix ? { resourcePathPrefix } : {}),
    ...(registrationEndpoints ? { registrationEndpoints } : {}),
    ...(seeds ? { seeds } : {}),
    ...(passthrough ? { passthrough } : {}),
  };
}

function validateServiceEntry(value: unknown, serviceId: string, issues: string[]): DesiredServiceEntry | undefined {
  const prefix = `services.${serviceId}`;
  if (!/^[a-z][a-z0-9-]{0,63}$/.test(serviceId)) issues.push(`${prefix} has an invalid service id`);
  if (!isRecord(value)) {
    issues.push(`${prefix} must be an object`);
    return undefined;
  }
  exactKeys(value, ["definitionDigest", "resolved", "revision", "selection"], `${prefix}.`, issues);
  if (!Number.isSafeInteger(value.revision) || Number(value.revision) < 1) issues.push(`${prefix}.revision must be a positive integer`);
  if (typeof value.definitionDigest !== "string" || !SHA256_PATTERN.test(value.definitionDigest)) {
    issues.push(`${prefix}.definitionDigest must be a full sha256 digest`);
  }
  let selection: DesiredServiceSelection | undefined;
  if (value.selection !== undefined) {
    if (!isRecord(value.selection)) {
      issues.push(`${prefix}.selection must be an object`);
    } else {
      exactKeys(value.selection, ["skippedHosts", "writeMode"], `${prefix}.selection.`, issues);
      const writeMode = value.selection.writeMode;
      if (writeMode !== undefined && writeMode !== "allow-write" && writeMode !== "read-only") {
        issues.push(`${prefix}.selection.writeMode must be allow-write or read-only`);
      }
      const skippedHosts: string[] = [];
      if (value.selection.skippedHosts !== undefined) {
        if (!Array.isArray(value.selection.skippedHosts)) {
          issues.push(`${prefix}.selection.skippedHosts must be an array`);
        } else {
          for (const [index, host] of value.selection.skippedHosts.entries()) {
            if (typeof host !== "string") {
              issues.push(`${prefix}.selection.skippedHosts[${index}] must be a hostname`);
              continue;
            }
            try {
              const normalized = normalizeHostname(host);
              if (normalized !== host) issues.push(`${prefix}.selection.skippedHosts[${index}] must be stored as ${normalized}`);
              skippedHosts.push(normalized);
            } catch (error) {
              issues.push(`${prefix}.selection.skippedHosts[${index}]: ${error instanceof Error ? error.message : String(error)}`);
            }
          }
        }
      }
      selection = {
        ...(writeMode === "allow-write" || writeMode === "read-only" ? { writeMode } : {}),
        ...(value.selection.skippedHosts !== undefined ? { skippedHosts: stableUnique(skippedHosts) } : {}),
      };
    }
  }
  if (!isRecord(value.resolved)) {
    issues.push(`${prefix}.resolved must be an object`);
    return undefined;
  }
  exactKeys(value.resolved, ["agentEnv", "hosts", "oauth", "parameters", "requests", "tokens"], `${prefix}.resolved.`, issues);
  let policy: ReturnType<typeof validateNetworkPolicy> | undefined;
  try {
    policy = validateNetworkPolicy({
      hosts: value.resolved.hosts,
      ...(value.resolved.requests === undefined ? {} : { requests: value.resolved.requests }),
      ...(value.resolved.tokens === undefined ? {} : { tokens: value.resolved.tokens }),
    }, prefix);
  } catch (error) {
    if (error && typeof error === "object" && "issues" in error && Array.isArray(error.issues)) {
      issues.push(...error.issues.map((issue) => `${prefix}.resolved: ${String(issue)}`));
    } else {
      issues.push(`${prefix}.resolved: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  const agentEnv: string[] = [];
  if (value.resolved.agentEnv !== undefined) {
    if (!Array.isArray(value.resolved.agentEnv)) {
      issues.push(`${prefix}.resolved.agentEnv must be an array`);
    } else {
      for (const [index, envName] of value.resolved.agentEnv.entries()) {
        if (typeof envName !== "string" || !ENV_NAME_PATTERN.test(envName)) {
          issues.push(`${prefix}.resolved.agentEnv[${index}] must be an environment variable name`);
        } else {
          agentEnv.push(envName);
        }
      }
    }
  }
  const parameters: DesiredServiceParameter[] = [];
  if (value.resolved.parameters !== undefined) {
    if (!Array.isArray(value.resolved.parameters)) {
      issues.push(`${prefix}.resolved.parameters must be an array`);
    } else {
      const keys = new Set<string>();
      const envNames = new Set<string>();
      const declaredEnv = new Set(agentEnv);
      for (const [index, entry] of value.resolved.parameters.entries()) {
        const itemPrefix = `${prefix}.resolved.parameters[${index}]`;
        if (!isRecord(entry)) {
          issues.push(`${itemPrefix} must be an object`);
          continue;
        }
        exactKeys(entry, ["description", "envVar", "key", "oauthField"], `${itemPrefix}.`, issues);
        if (typeof entry.key !== "string" || !PARAMETER_KEY_PATTERN.test(entry.key)
          || typeof entry.envVar !== "string" || !ENV_NAME_PATTERN.test(entry.envVar)
          || typeof entry.description !== "string" || entry.description.trim() === ""
          || (entry.oauthField !== undefined && (typeof entry.oauthField !== "string" || !OAUTH_FIELD_PATTERN.test(entry.oauthField)))) {
          issues.push(`${itemPrefix} is malformed`);
          continue;
        }
        if (keys.has(entry.key)) issues.push(`${itemPrefix} duplicates parameter key ${entry.key}`);
        if (envNames.has(entry.envVar)) issues.push(`${itemPrefix} duplicates parameter env ${entry.envVar}`);
        if (!declaredEnv.has(entry.envVar)) issues.push(`${itemPrefix} env ${entry.envVar} must also be listed in resolved.agentEnv`);
        keys.add(entry.key);
        envNames.add(entry.envVar);
        parameters.push({
          description: entry.description,
          envVar: entry.envVar,
          key: entry.key,
          ...(typeof entry.oauthField === "string" ? { oauthField: entry.oauthField } : {}),
        });
      }
      parameters.sort((left, right) => left.key.localeCompare(right.key));
    }
  }
  const oauth: Record<string, DesiredOAuthProvider> = {};
  if (value.resolved.oauth !== undefined) {
    if (!isRecord(value.resolved.oauth)) {
      issues.push(`${prefix}.resolved.oauth must be an object`);
    } else {
      for (const [providerId, provider] of Object.entries(value.resolved.oauth)) {
        const parsed = validateOAuthProvider(provider, `${prefix}.resolved.oauth.${providerId}`, issues);
        if (parsed) oauth[providerId] = parsed;
      }
    }
  }
  if (!policy) return undefined;
  return {
    definitionDigest: typeof value.definitionDigest === "string" ? value.definitionDigest : "",
    revision: Number.isSafeInteger(value.revision) ? Number(value.revision) : 0,
    ...(selection ? { selection } : {}),
    resolved: {
      hosts: stableUnique(policy.allowedHosts),
      ...(Object.keys(policy.requests).length > 0 ? { requests: policy.requests } : {}),
      ...(Object.keys(policy.tokens).length > 0 ? { tokens: policy.tokens } : {}),
      ...(Object.keys(oauth).length > 0 ? { oauth: Object.fromEntries(Object.entries(oauth).sort()) } : {}),
      ...(parameters.length > 0 ? { parameters } : {}),
      ...(value.resolved.agentEnv !== undefined ? { agentEnv: stableUnique(agentEnv) } : {}),
    },
  };
}

export function validateDesiredNetworkPolicy(raw: unknown): DesiredNetworkPolicyJson {
  const issues: string[] = [];
  if (!isRecord(raw)) throw new DesiredNetworkPolicyValidationError(["policy must be a JSON object"]);
  exactKeys(raw, ["hosts", "requests", "services", "tokens", "version", "writeApproval"], "", issues);
  if (raw.version !== DESIRED_NETWORK_POLICY_VERSION) issues.push(`version must be ${DESIRED_NETWORK_POLICY_VERSION}`);
  let direct: ReturnType<typeof validateNetworkPolicy> | undefined;
  try {
    direct = validateNetworkPolicy({
      hosts: raw.hosts,
      ...(raw.requests === undefined ? {} : { requests: raw.requests }),
      ...(raw.tokens === undefined ? {} : { tokens: raw.tokens }),
      ...(raw.writeApproval === undefined ? {} : { writeApproval: raw.writeApproval }),
    });
  } catch (error) {
    if (error && typeof error === "object" && "issues" in error && Array.isArray(error.issues)) {
      issues.push(...error.issues.map(String));
    } else {
      issues.push(error instanceof Error ? error.message : String(error));
    }
  }
  const services: Record<string, DesiredServiceEntry> = {};
  if (raw.services !== undefined) {
    if (!isRecord(raw.services)) {
      issues.push("services must be an object when present");
    } else {
      for (const [serviceId, service] of Object.entries(raw.services)) {
        const parsed = validateServiceEntry(service, serviceId, issues);
        if (parsed) services[serviceId] = parsed;
      }
    }
  }
  if (!direct || issues.length > 0) throw new DesiredNetworkPolicyValidationError(issues);
  return {
    version: DESIRED_NETWORK_POLICY_VERSION,
    hosts: stableUnique(direct.allowedHosts),
    ...(Object.keys(services).length > 0 ? { services: Object.fromEntries(Object.entries(services).sort()) } : {}),
    ...(Object.keys(direct.requests).length > 0 ? { requests: direct.requests } : {}),
    ...(Object.keys(direct.tokens).length > 0 ? { tokens: direct.tokens } : {}),
    ...(direct.writeApproval ? { writeApproval: direct.writeApproval } : {}),
  };
}

export function canonicalDesiredNetworkPolicy(policy: DesiredNetworkPolicyJson): string {
  return stableJson(validateDesiredNetworkPolicy(policy));
}

export function desiredNetworkPolicyDigest(policy: DesiredNetworkPolicyJson): string {
  return sha256Digest(canonicalDesiredNetworkPolicy(policy));
}

export function desiredPolicyDirectProjection(policy: DesiredNetworkPolicyJson): PolicyJson {
  const validated = validateDesiredNetworkPolicy(policy);
  return {
    hosts: validated.hosts,
    ...(validated.requests ? { requests: validated.requests } : {}),
    ...(validated.tokens ? { tokens: validated.tokens } : {}),
    ...(validated.writeApproval ? { writeApproval: validated.writeApproval } : {}),
  };
}
