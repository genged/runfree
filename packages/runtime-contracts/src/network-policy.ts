
import { isIP } from "node:net";

import { isReservedRunfreeHostname, validateHostServices, type HostServicesJson } from "./host-services.js";
import { isRecord, sha256Digest } from "./primitives.js";

const INLINE_POLICY_LABEL = "<inline policy>";
export const TOKEN_NAME_PATTERN = /^[a-z][a-z0-9_-]{0,63}$/;
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const HOST_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
export const CREDENTIAL_SCHEMES = ["bearer", "raw", "basic"] as const;
// Wire protocols a credential destination may be scoped to. Each value is one
// matcher in proxy code; the policy names the class, the code defines it.
export const CREDENTIAL_PROTOCOLS = ["git-http"] as const;
// RFC 7617 user-id for `basic`: policy data, not secret. Visible ASCII only
// (0x21-0x7E, so no space or control byte) and no colon, 1-64 bytes.
const CREDENTIAL_USERNAME_RE = /^[\x21-\x39\x3B-\x7E]{1,64}$/;
const CREDENTIAL_KEYS = ["host", "header", "scheme", "username", "pathPrefix", "protocol"] as const;
const TOKEN_KEYS = ["description", "allowAnonymous", "credentials"] as const;
// `domains` stays known: legacy migration input still reaches this validator.
const POLICY_KEYS = ["hosts", "domains", "tokens", "requests", "writeApproval", "hostServices"] as const;
export const HTTP_METHODS = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"] as const;
export const READ_ONLY_METHODS = ["GET", "HEAD", "OPTIONS"] as const;
// Tri-state action applied to the write operation class of requests to a host:
// allow = writes flow, ask = writes pause for host-side approval, deny = writes
// blocked. Hosts without an explicit per-host writeAction fall back to the
// policy-level compiled `writeApproval`, then to DEFAULT_WRITE_ACTION.
export const WRITE_ACTIONS = ["allow", "ask", "deny"] as const;
// Built-in fallback when neither a per-host writeAction nor a compiled
// policy-level writeApproval is present. "ask" is the secure default shipped
// with approve-on-write: reads flow, writes pause for host-side approval
// (degrading fail-closed to deny with no approver attached). Restore the
// pre-tri-state behavior with desired-policy writeApproval: "allow", per
// service with --allow-write, or per host with `runfree host rules <host>
// --write allow`.
export const DEFAULT_WRITE_ACTION = "ask" as const;
const DEFAULT_GITHUB_TOKEN_DESCRIPTION = "Read-only GitHub API token for rate limit and public metadata";
const LEGACY_DEFAULT_GITHUB_CREDENTIALS = [
  { host: "api.github.com", header: "Authorization", scheme: "bearer" },
  { host: "raw.githubusercontent.com", header: "Authorization", scheme: "bearer" },
] as const;

export type CredentialScheme = typeof CREDENTIAL_SCHEMES[number];
export type CredentialProtocol = typeof CREDENTIAL_PROTOCOLS[number];
export type HttpMethod = typeof HTTP_METHODS[number];
export type WriteAction = typeof WRITE_ACTIONS[number];

export type PolicyJson = {
  hosts: string[];
  /** @deprecated Legacy migration input only. Writers emit hosts. */
  domains?: unknown;
  tokens?: Record<string, TokenPolicyJson>;
  requests?: Record<string, RequestPolicyJson>;
  // Compiled project-wide default write action for hosts without a per-host
  // writeAction. The host compiler resolves the one-run override and merged
  // desired-policy default, then materializes it here so the proxy reads one
  // generation-hashed policy and never reads project config or desired input.
  writeApproval?: WriteAction;
  // Approved agent access to a service on the Docker Desktop host's loopback
  // (local/specs/2026-10-03-host-services-design.md). Present only when
  // non-empty, so a policy with no host services keeps its pre-feature raw
  // shape and generation.
  hostServices?: HostServicesJson;
};

// Per-host request-shape rules. Absent fields mean "unrestricted"; the whole
// section is strictly narrowing relative to the hostname allowlist.
export type RequestPolicyJson = {
  methods?: HttpMethod[];
  pathPrefixes?: string[];
  // "deny": v1 shape rule — git pushes are always 403'd for this host.
  // "write": classification marker — this host serves git over HTTPS; pushes
  // classify as writes (gated by the tri-state) and upload-pack fetch POSTs
  // classify as reads instead of falling into the conservative POST=write.
  gitPush?: "deny" | "write";
  writeAction?: WriteAction;
  // Write-classification refinements (operation-aware read-only): path
  // prefixes that classify as reads regardless of method (search/batch-get/RPC
  // reads over POST), and path prefixes that classify as writes regardless of
  // method. Declared GraphQL endpoints classify by operation type (any POST to
  // one is a write until the body-aware classifier ships).
  readPathPrefixes?: string[];
  writePathPrefixes?: string[];
  graphql?: GraphqlRequestPolicyJson;
};

export type GraphqlRequestPolicyJson = {
  // Exact normalized paths (no wildcards, query, or fragment).
  endpoints: string[];
  // query => read, mutation => write. The only supported classification.
  writeOps: "mutation";
};

export type TokenPolicyJson = {
  description: string;
  allowAnonymous?: boolean;
  credentials: CredentialPolicyJson[];
};

export type CredentialPolicyJson = {
  host: string;
  header: string;
  scheme: CredentialScheme;
  // Present iff scheme is "basic".
  username?: string;
  pathPrefix?: string;
  protocol?: CredentialProtocol;
};

export type CredentialMapping = CredentialPolicyJson & {
  tokenName: string;
  tokenDescription: string;
  allowAnonymous?: boolean;
};

export type CredentialPolicy = Record<string, CredentialMapping[]>;

export type LoadedNetworkPolicy = {
  policyPath: string;
  generation: string;
  raw: PolicyJson;
  allowedHosts: string[];
  allowedHostSet: Set<string>;
  credentials: CredentialPolicy;
  tokens: Record<string, TokenPolicyJson>;
  credentialMappings: CredentialMapping[];
  requests: Record<string, RequestPolicyJson>;
  writeApproval?: WriteAction;
  hostServices: Readonly<HostServicesJson>;
};

export class PolicyValidationError extends Error {
  readonly issues: string[];

  constructor(issues: string[]) {
    super(`invalid proxy policy:\n${issues.map((issue) => `- ${issue}`).join("\n")}`);
    this.name = "PolicyValidationError";
    this.issues = issues;
  }
}

export function isTokenName(value: string): boolean {
  return TOKEN_NAME_PATTERN.test(value);
}

export function assertTokenName(value: string): void {
  if (!isTokenName(value)) throw new Error(`invalid token name: ${value}`);
}

export function isCredentialScheme(value: string): value is CredentialScheme {
  return (CREDENTIAL_SCHEMES as readonly string[]).includes(value);
}

export function credentialSchemeList(): string {
  return CREDENTIAL_SCHEMES.join(", ");
}

export function isCredentialProtocol(value: string): value is CredentialProtocol {
  return (CREDENTIAL_PROTOCOLS as readonly string[]).includes(value);
}

export function credentialProtocolList(): string {
  return CREDENTIAL_PROTOCOLS.join(", ");
}

/** Problem with a `basic` username, or undefined when it is valid (D-7). */
export function credentialUsernameProblem(value: unknown): string | undefined {
  if (typeof value !== "string") return "must be a string";
  if (value.length === 0) return "must be non-empty";
  if (value.length > 64) return "must be at most 64 bytes";
  if (value.includes(":")) return "must not contain ':'";
  if (!CREDENTIAL_USERNAME_RE.test(value)) return "must contain only printable ASCII without spaces or control characters";
  return undefined;
}

/**
 * The credential in canonical key order. Optional fields are present only
 * when set, so a credential without them keeps its pre-feature shape (and the
 * effective policy generation that hashes it).
 */
export function canonicalCredential(credential: CredentialPolicyJson): CredentialPolicyJson {
  return {
    host: credential.host,
    header: credential.header,
    scheme: credential.scheme,
    ...(credential.username !== undefined ? { username: credential.username } : {}),
    ...(credential.pathPrefix !== undefined ? { pathPrefix: credential.pathPrefix } : {}),
    ...(credential.protocol !== undefined ? { protocol: credential.protocol } : {}),
  };
}

/**
 * Identity of a credential destination for duplicate detection and stable
 * sorting: every field that changes what is sent where. Header case is folded
 * (HTTP field names are case-insensitive). username and protocol join only
 * when present, so keys of credentials without them are unchanged.
 */
export function credentialIdentityKey(credential: CredentialPolicyJson): string {
  return [
    credential.host,
    credential.header.toLowerCase(),
    credential.scheme,
    credential.pathPrefix ?? "",
    ...(credential.username !== undefined ? [`username=${credential.username}`] : []),
    ...(credential.protocol !== undefined ? [`protocol=${credential.protocol}`] : []),
  ].join("\0");
}

export function isHttpMethod(value: string): value is HttpMethod {
  return (HTTP_METHODS as readonly string[]).includes(value);
}

export function httpMethodList(): string {
  return HTTP_METHODS.join(", ");
}

export function isWriteAction(value: string): value is WriteAction {
  return (WRITE_ACTIONS as readonly string[]).includes(value);
}

export function writeActionList(): string {
  return WRITE_ACTIONS.join(", ");
}

// The single precedence rule both the proxy and the CLI use: per-host rule ->
// compiled policy-level default -> built-in default.
export function effectiveWriteAction(
  policy: Pick<LoadedNetworkPolicy, "requests" | "writeApproval">,
  host: string,
): WriteAction {
  return policy.requests[host]?.writeAction ?? policy.writeApproval ?? DEFAULT_WRITE_ACTION;
}


export function normalizeHostname(input: string): string {
  const trimmed = input.trim();
  if (trimmed === "") throw new Error("expected hostname, got empty value");
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    let suggestion = "";
    try {
      suggestion = new URL(trimmed).hostname.toLowerCase();
    } catch {
      // The caller still gets the URL-specific error below.
    }
    throw new Error(suggestion ? `expected hostname, got URL\nuse: ${suggestion}` : "expected hostname, got URL");
  }
  if (/[/?#]/.test(trimmed)) throw new Error("expected hostname, got URL or path");
  if (trimmed.includes("*")) throw new Error("wildcard hostnames are not supported");
  if (trimmed.includes(":")) throw new Error("expected hostname without port");

  const host = trimmed.toLowerCase();
  if (host !== trimmed && trimmed !== trimmed.toLowerCase()) {
    // Uppercase input is accepted by CLI callers after normalization; policy
    // validation separately rejects uppercase stored values.
  }
  if (host.endsWith(".")) throw new Error("hostnames must not end with a dot");
  if (host.length > 253) throw new Error("hostname is too long");

  const labels = host.split(".");
  if (labels.length < 2) throw new Error("expected fully-qualified hostname");
  for (const label of labels) {
    if (!HOST_LABEL_RE.test(label)) throw new Error(`invalid hostname label: ${label || "<empty>"}`);
  }

  return host;
}

export function normalizePathPrefix(input: string): string {
  const trimmed = input.trim();
  if (trimmed === "") throw new Error("pathPrefix must be non-empty");
  if (!trimmed.startsWith("/")) throw new Error("pathPrefix must start with /");
  if (trimmed.includes("?") || trimmed.includes("#")) {
    throw new Error("pathPrefix must not contain query or fragment");
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    throw new Error("pathPrefix must be a path, not a URL");
  }
  return trimmed;
}

export function hostFromUrl(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

export function pathMatchesPrefix(pathName: string, pathPrefix: string): boolean {
  if (pathPrefix === "/") return true;
  if (pathName === pathPrefix) return true;
  const childPrefix = pathPrefix.endsWith("/") ? pathPrefix : `${pathPrefix}/`;
  return pathName.startsWith(childPrefix);
}

/**
 * True for an IP literal in any form a resolver or dialer accepts: dotted
 * IPv4, IPv6 (brackets already stripped), or a name whose last label is a
 * number (WHATWG "ends in a number": decimal or hex). Policy hosts are exact
 * names, and an IP literal skips the resolver snapshot when dialled (R20).
 * Desired-policy validation refuses IP-literal hosts with it; the effective
 * policy loader does not, so a host-compiled effective policy is unchanged.
 */
export function isIpLiteralHostname(host: string): boolean {
  if (isIP(host) !== 0) return true;
  const last = host.split(".").at(-1) ?? "";
  return /^[0-9]+$/.test(last) || /^0x[0-9a-f]*$/i.test(last);
}

function validateStoredHost(value: string, issues: string[]): string | undefined {
  if (value !== value.toLowerCase()) {
    issues.push(`${value} must be stored lowercase`);
  }

  let host: string;
  try {
    host = normalizeHostname(value);
  } catch (error) {
    issues.push(`${value}: ${error instanceof Error ? error.message : String(error)}`);
    return undefined;
  }

  if (host !== value) {
    issues.push(`${value} must be stored as exact normalized hostname ${host}`);
  }
  if (isReservedRunfreeHostname(host)) {
    issues.push(`${host} uses the reserved runfree.internal suffix`);
  }
  return host;
}

function credentialKey(credential: CredentialPolicyJson): string {
  // New fields join only when present, so the sort order (and so the
  // generation) of a policy without them is unchanged.
  return [
    credential.host,
    credential.header,
    credential.scheme,
    credential.pathPrefix ?? "",
    ...(credential.username !== undefined ? [`username=${credential.username}`] : []),
    ...(credential.protocol !== undefined ? [`protocol=${credential.protocol}`] : []),
  ].join("\0");
}

function compareStableText(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function isLegacyGeneratedGitHubToken(
  tokenName: string,
  description: unknown,
  credentials: CredentialPolicyJson[],
): boolean {
  if (tokenName !== "github") return false;
  if (description !== DEFAULT_GITHUB_TOKEN_DESCRIPTION) return false;
  const actual = credentials.map(credentialKey).sort();
  const expected = LEGACY_DEFAULT_GITHUB_CREDENTIALS.map(credentialKey).sort();
  return actual.length === expected.length && actual.every((value, index) => value === expected[index]);
}

function policyGeneration(
  allowedHosts: readonly string[],
  tokens: Record<string, TokenPolicyJson>,
  requests: Record<string, RequestPolicyJson>,
  writeApproval: WriteAction | undefined,
  hostServices: HostServicesJson,
): string {
  const normalizedTokens = Object.fromEntries(Object.entries(tokens)
    .sort(([left], [right]) => compareStableText(left, right))
    .map(([name, token]) => [
      name,
      {
        description: token.description,
        ...(token.allowAnonymous !== undefined ? { allowAnonymous: token.allowAnonymous } : {}),
        credentials: token.credentials
          .map(canonicalCredential)
          .sort((left, right) => compareStableText(credentialKey(left), credentialKey(right))),
      },
    ]));
  const normalizedRequests = Object.fromEntries(Object.entries(requests)
    .sort(([left], [right]) => compareStableText(left, right))
    .map(([host, rule]) => [
      host,
      {
        ...(rule.methods !== undefined ? { methods: [...rule.methods].sort(compareStableText) } : {}),
        ...(rule.pathPrefixes !== undefined ? { pathPrefixes: [...rule.pathPrefixes].sort(compareStableText) } : {}),
        ...(rule.gitPush !== undefined ? { gitPush: rule.gitPush } : {}),
        ...(rule.writeAction !== undefined ? { writeAction: rule.writeAction } : {}),
        ...(rule.readPathPrefixes !== undefined ? { readPathPrefixes: [...rule.readPathPrefixes].sort(compareStableText) } : {}),
        ...(rule.writePathPrefixes !== undefined ? { writePathPrefixes: [...rule.writePathPrefixes].sort(compareStableText) } : {}),
        ...(rule.graphql !== undefined
          ? { graphql: { endpoints: [...rule.graphql.endpoints].sort(compareStableText), writeOps: rule.graphql.writeOps } }
          : {}),
      },
    ]));
  const normalizedHostServices = Object.fromEntries(Object.entries(hostServices)
    .sort(([left], [right]) => compareStableText(left, right)));
  const payload = {
    allowedHosts: [...allowedHosts].sort(compareStableText),
    tokens: normalizedTokens,
    // Only present when rules exist so request-less policies keep the exact
    // pre-request-shape generation for unchanged inputs. The same holds for
    // writeApproval and hostServices: absent means the pre-feature generation
    // is preserved for unchanged inputs.
    ...(Object.keys(normalizedRequests).length > 0 ? { requests: normalizedRequests } : {}),
    ...(writeApproval !== undefined ? { writeApproval } : {}),
    ...(Object.keys(normalizedHostServices).length > 0 ? { hostServices: normalizedHostServices } : {}),
  };
  return sha256Digest(JSON.stringify(payload));
}

// Pushes one issue per key outside `known`; true when any was found.
function unknownKeys(
  value: Record<string, unknown>,
  known: readonly string[],
  prefix: string,
  kind: string,
  issues: string[],
): boolean {
  let found = false;
  for (const key of Object.keys(value)) {
    if (!known.includes(key)) {
      issues.push(`${prefix}${key} is not a known ${kind} (known: ${known.join(", ")})`);
      found = true;
    }
  }
  return found;
}

function validatedPathPrefixList(fieldLabel: string, rawValue: unknown, issues: string[]): string[] | undefined {
  if (!Array.isArray(rawValue)) {
    issues.push(`${fieldLabel} must be an array when present`);
    return undefined;
  }
  if (rawValue.length === 0) {
    issues.push(`${fieldLabel} must be non-empty when present`);
  }
  const prefixes: string[] = [];
  for (const [index, value] of rawValue.entries()) {
    if (typeof value !== "string") {
      issues.push(`${fieldLabel}[${index}] must be a string`);
      continue;
    }
    let normalized: string;
    try {
      normalized = normalizePathPrefix(value);
    } catch (error) {
      issues.push(`${fieldLabel}[${index}] ${value}: ${error instanceof Error ? error.message : String(error)}`);
      continue;
    }
    if (normalized !== value) {
      issues.push(`${fieldLabel}[${index}] must be stored as exact normalized path prefix ${normalized}`);
      continue;
    }
    if (prefixes.includes(normalized)) {
      issues.push(`${fieldLabel} contains duplicate ${normalized}`);
      continue;
    }
    prefixes.push(normalized);
  }
  return prefixes;
}

function validatedGraphqlRule(fieldLabel: string, rawValue: unknown, issues: string[]): GraphqlRequestPolicyJson | undefined {
  if (!isRecord(rawValue)) {
    issues.push(`${fieldLabel} must be an object when present`);
    return undefined;
  }
  for (const key of Object.keys(rawValue)) {
    if (key !== "endpoints" && key !== "writeOps") {
      issues.push(`${fieldLabel}.${key} is not a known graphql field (known: endpoints, writeOps)`);
      return undefined;
    }
  }
  if (rawValue.writeOps !== "mutation") {
    issues.push(`${fieldLabel}.writeOps must be "mutation"`);
    return undefined;
  }
  const endpoints = validatedPathPrefixList(`${fieldLabel}.endpoints`, rawValue.endpoints, issues);
  if (endpoints === undefined || endpoints.length === 0) return undefined;
  // Endpoints are exact paths, not prefixes: reject wildcard characters that
  // normalizePathPrefix admits.
  for (const endpoint of endpoints) {
    if (endpoint.includes("*")) {
      issues.push(`${fieldLabel}.endpoints must be exact paths without wildcards: ${endpoint}`);
      return undefined;
    }
  }
  return { endpoints, writeOps: "mutation" };
}

export function validateNetworkPolicy(raw: unknown, policyPath = INLINE_POLICY_LABEL): LoadedNetworkPolicy {
  const issues: string[] = [];
  const hosts: string[] = [];
  const allowedHosts: string[] = [];
  const allowedHostSet = new Set<string>();
  const seenHosts = new Map<string, string>();

  if (!isRecord(raw)) {
    throw new PolicyValidationError(["policy must be a JSON object"]);
  }
  // Strict (spec O-4 rule 1): an older reader that ignored an unknown field
  // would enforce less than the writer meant.
  unknownKeys(raw, POLICY_KEYS, "", "policy field", issues);

  const rawHosts = raw.hosts;
  const rawDomains = raw.domains;
  if (rawHosts !== undefined && rawDomains !== undefined) {
    issues.push("policy must not define both hosts and legacy domains");
  } else if (rawHosts !== undefined) {
    if (!Array.isArray(rawHosts)) {
      issues.push("hosts must be an array of hostnames");
    } else {
      for (const value of rawHosts) {
        if (typeof value !== "string") {
          issues.push("hosts contains a non-string hostname");
          continue;
        }
        const host = validateStoredHost(value, issues);
        if (!host) continue;

        if (seenHosts.has(host)) {
          issues.push(`${host} appears more than once in hosts`);
          continue;
        }

        seenHosts.set(host, "hosts");
        allowedHostSet.add(host);
        allowedHosts.push(host);
        hosts.push(host);
      }
    }
  } else if (Array.isArray(rawDomains)) {
    for (const value of rawDomains) {
      if (typeof value !== "string") {
        issues.push("legacy domains contains a non-string hostname");
        continue;
      }
      const host = validateStoredHost(value, issues);
      if (!host) continue;

      if (seenHosts.has(host)) {
        issues.push(`${host} appears more than once in legacy domains`);
        continue;
      }

      seenHosts.set(host, "domains");
      allowedHostSet.add(host);
      allowedHosts.push(host);
      hosts.push(host);
    }
  } else if (rawDomains !== undefined && isRecord(rawDomains)) {
    for (const [domainKey, domainValue] of Object.entries(rawDomains)) {
      if (Array.isArray(domainValue)) {
        const legacyGroup = domainKey;
        if (legacyGroup.trim() === "") issues.push("legacy domain group names must be non-empty");

        for (const value of domainValue) {
          if (typeof value !== "string") {
            issues.push(`legacy domains.${legacyGroup} contains a non-string hostname`);
            continue;
          }
          const host = validateStoredHost(value, issues);
          if (!host) continue;

          const existing = seenHosts.get(host);
          if (existing) {
            issues.push(`${host} appears in both "${existing}" and "${legacyGroup}"`);
            continue;
          }

          seenHosts.set(host, legacyGroup);
          allowedHostSet.add(host);
          allowedHosts.push(host);
          hosts.push(host);
        }
        continue;
      }

      const host = validateStoredHost(domainKey, issues);
      if (!host) continue;
      if (!isRecord(domainValue)) {
        issues.push(`legacy domains.${domainKey} must be an object`);
        continue;
      }

      seenHosts.set(host, domainKey);
      allowedHostSet.add(host);
      allowedHosts.push(host);
      hosts.push(host);
    }
  } else if (rawDomains !== undefined) {
    issues.push("legacy domains must be an array of hostnames");
  } else {
    issues.push("hosts must be an array of hostnames");
  }

  const rawTokens = raw.tokens;
  const tokens: Record<string, TokenPolicyJson> = {};
  const credentials: CredentialPolicy = {};
  const credentialMappings: CredentialMapping[] = [];
  const credentialOwners = new Map<string, Map<string, string>>();
  const protocolOwners = new Map<string, string>();

  if (rawTokens !== undefined && !isRecord(rawTokens)) {
    issues.push("tokens must be an object when present");
  } else if (isRecord(rawTokens)) {
    for (const [tokenName, tokenValue] of Object.entries(rawTokens)) {
      if (!isTokenName(tokenName)) {
        issues.push(`${tokenName}: token names must match ${TOKEN_NAME_PATTERN.source}`);
      }
      if (!isRecord(tokenValue)) {
        issues.push(`${tokenName}: token policy must be an object`);
        continue;
      }
      unknownKeys(tokenValue, TOKEN_KEYS, `${tokenName}.`, "token field", issues);

      const description = tokenValue.description;
      if (typeof description !== "string" || description.trim() === "") {
        issues.push(`${tokenName}: description must be a non-empty string`);
      }

      const allowAnonymousRaw = tokenValue.allowAnonymous;
      if (allowAnonymousRaw !== undefined && typeof allowAnonymousRaw !== "boolean") {
        issues.push(`${tokenName}: allowAnonymous must be a boolean when present`);
      }

      const rawCredentials = tokenValue.credentials;
      if (!Array.isArray(rawCredentials)) {
        issues.push(`${tokenName}: credentials must be an array`);
        continue;
      }

      const normalizedCredentials: CredentialPolicyJson[] = [];
      for (const [index, credential] of rawCredentials.entries()) {
        const prefix = `${tokenName}.credentials[${index}]`;
        if (!isRecord(credential)) {
          issues.push(`${prefix} must be an object`);
          continue;
        }

        if (unknownKeys(credential, CREDENTIAL_KEYS, `${prefix}.`, "credential field", issues)) continue;
        const host = credential.host;
        const header = credential.header;
        const scheme = credential.scheme;

        if (typeof host !== "string") {
          issues.push(`${prefix}.host must be a string`);
          continue;
        }
        if (host !== host.toLowerCase()) {
          issues.push(`${prefix}.host must be stored lowercase`);
        }
        try {
          normalizeHostname(host);
        } catch (error) {
          issues.push(`${prefix}.host ${host}: ${error instanceof Error ? error.message : String(error)}`);
          continue;
        }
        if (isReservedRunfreeHostname(host)) {
          issues.push(`${prefix}.host ${host} uses the reserved runfree.internal suffix`);
        }
        if (!allowedHostSet.has(host)) {
          issues.push(`${prefix}.host ${host} is credentialed but not allowlisted`);
        }

        if (typeof header !== "string" || !HEADER_NAME_RE.test(header)) {
          issues.push(`${prefix}.header must be a valid HTTP field name`);
          continue;
        }
        if (typeof scheme !== "string" || !isCredentialScheme(scheme)) {
          issues.push(`${prefix}.scheme must be one of: ${credentialSchemeList()}`);
          continue;
        }
        const rawPathPrefix = credential.pathPrefix;
        let pathPrefix: string | undefined;
        if (rawPathPrefix !== undefined) {
          if (typeof rawPathPrefix !== "string") {
            issues.push(`${prefix}.pathPrefix must be a string`);
            continue;
          }
          try {
            pathPrefix = normalizePathPrefix(rawPathPrefix);
          } catch (error) {
            issues.push(`${prefix}.pathPrefix ${rawPathPrefix}: ${error instanceof Error ? error.message : String(error)}`);
            continue;
          }
          if (pathPrefix !== rawPathPrefix) {
            issues.push(`${prefix}.pathPrefix must be stored as exact normalized path prefix ${pathPrefix}`);
            continue;
          }
        }

        const rawUsername = credential.username;
        if (scheme === "basic") {
          const problem = credentialUsernameProblem(rawUsername);
          if (problem !== undefined) {
            issues.push(`${prefix}.username ${rawUsername === undefined ? "is required with scheme basic" : problem}`);
            continue;
          }
        } else if (rawUsername !== undefined) {
          issues.push(`${prefix}.username is valid only with scheme basic`);
          continue;
        }
        const rawProtocol = credential.protocol;
        let protocol: CredentialProtocol | undefined;
        if (rawProtocol !== undefined) {
          if (typeof rawProtocol !== "string" || !isCredentialProtocol(rawProtocol)) {
            issues.push(`${prefix}.protocol must be one of: ${credentialProtocolList()}`);
            continue;
          }
          protocol = rawProtocol;
        }

        // Within one (host, header) the proxy selects by protocol tier, then
        // longest pathPrefix. Each (protocol, pathPrefix) pair must therefore
        // be unique, and at most one mapping may be protocol-scoped, so no
        // request can see two equally ranked mappings for one header.
        const ownerKey = `${host.toLowerCase()}\0${header.toLowerCase()}`;
        const owner = `${tokenName}.${host}.${header}`;
        const scopeKey = `${protocol ?? ""}\0${pathPrefix ?? ""}`;
        const owners = credentialOwners.get(ownerKey) ?? new Map<string, string>();
        const existingOwner = owners.get(scopeKey);
        if (existingOwner) {
          issues.push(`${prefix} conflicts with ${existingOwner} for (${host}, ${header})`);
          continue;
        }
        if (protocol !== undefined) {
          const protocolOwner = protocolOwners.get(ownerKey);
          if (protocolOwner) {
            issues.push(`${prefix} is a second protocol-scoped mapping for (${host}, ${header}); ${protocolOwner} already has one`);
            continue;
          }
          protocolOwners.set(ownerKey, owner);
        }
        owners.set(scopeKey, owner);
        credentialOwners.set(ownerKey, owners);

        normalizedCredentials.push(canonicalCredential({
          host,
          header,
          scheme,
          ...(typeof rawUsername === "string" ? { username: rawUsername } : {}),
          ...(pathPrefix !== undefined ? { pathPrefix } : {}),
          ...(protocol !== undefined ? { protocol } : {}),
        }));
      }

      const allowAnonymous = typeof allowAnonymousRaw === "boolean"
        ? allowAnonymousRaw
        : isLegacyGeneratedGitHubToken(tokenName, description, normalizedCredentials);
      for (const normalized of normalizedCredentials) {
        const mapping: CredentialMapping = {
          ...normalized,
          tokenName,
          tokenDescription: typeof description === "string" ? description : "",
          allowAnonymous,
        };
        credentials[normalized.host] ??= [];
        credentials[normalized.host].push(mapping);
        credentialMappings.push(mapping);
      }

      tokens[tokenName] = {
        description: typeof description === "string" ? description : "",
        ...(allowAnonymousRaw !== undefined || allowAnonymous ? { allowAnonymous } : {}),
        credentials: normalizedCredentials,
      };
    }
  }

  const rawWriteApproval = raw.writeApproval;
  let writeApproval: WriteAction | undefined;
  if (rawWriteApproval !== undefined) {
    if (typeof rawWriteApproval !== "string" || !isWriteAction(rawWriteApproval)) {
      issues.push(`writeApproval must be one of: ${writeActionList()}`);
    } else {
      writeApproval = rawWriteApproval;
    }
  }

  const rawRequests = raw.requests;
  const requests: Record<string, RequestPolicyJson> = {};

  if (rawRequests !== undefined && !isRecord(rawRequests)) {
    issues.push("requests must be an object when present");
  } else if (isRecord(rawRequests)) {
    for (const [host, ruleValue] of Object.entries(rawRequests)) {
      const prefix = `requests.${host}`;
      if (host !== host.toLowerCase()) {
        issues.push(`${prefix} must be stored lowercase`);
      }
      let normalizedHost: string;
      try {
        normalizedHost = normalizeHostname(host);
      } catch (error) {
        issues.push(`${prefix}: ${error instanceof Error ? error.message : String(error)}`);
        continue;
      }
      if (normalizedHost !== host) {
        issues.push(`${prefix} must be stored as exact normalized hostname ${normalizedHost}`);
        continue;
      }
      if (isReservedRunfreeHostname(host)) {
        issues.push(`${prefix} uses the reserved runfree.internal suffix`);
      }
      if (!allowedHostSet.has(host)) {
        issues.push(`${prefix} has request rules but is not allowlisted`);
      }
      if (!isRecord(ruleValue)) {
        issues.push(`${prefix} must be an object`);
        continue;
      }

      const rule: RequestPolicyJson = {};

      const knownRequestKeys = ["methods", "pathPrefixes", "gitPush", "writeAction", "readPathPrefixes", "writePathPrefixes", "graphql"];
      let hasUnknownKey = false;
      for (const key of Object.keys(ruleValue)) {
        if (!knownRequestKeys.includes(key)) {
          issues.push(`${prefix}.${key} is not a known request rule field (known: ${knownRequestKeys.join(", ")})`);
          hasUnknownKey = true;
        }
      }
      if (hasUnknownKey) continue;

      const rawMethods = ruleValue.methods;
      if (rawMethods !== undefined) {
        if (!Array.isArray(rawMethods)) {
          issues.push(`${prefix}.methods must be an array when present`);
        } else {
          if (rawMethods.length === 0) {
            issues.push(`${prefix}.methods must be non-empty; remove ${host} from hosts instead`);
          }
          const methods: HttpMethod[] = [];
          for (const [index, method] of rawMethods.entries()) {
            if (typeof method !== "string" || !isHttpMethod(method)) {
              issues.push(`${prefix}.methods[${index}] must be one of: ${httpMethodList()}`);
              continue;
            }
            if (methods.includes(method)) {
              issues.push(`${prefix}.methods contains duplicate ${method}`);
              continue;
            }
            methods.push(method);
          }
          rule.methods = methods;
        }
      }

      const rawPathPrefixes = ruleValue.pathPrefixes;
      if (rawPathPrefixes !== undefined) {
        const pathPrefixes = validatedPathPrefixList(`${prefix}.pathPrefixes`, rawPathPrefixes, issues);
        if (pathPrefixes !== undefined) rule.pathPrefixes = pathPrefixes;
      }

      const rawGitPush = ruleValue.gitPush;
      if (rawGitPush !== undefined) {
        if (rawGitPush !== "deny" && rawGitPush !== "write") {
          issues.push(`${prefix}.gitPush must be "deny" or "write" when present`);
        } else {
          rule.gitPush = rawGitPush;
        }
      }

      const rawWriteAction = ruleValue.writeAction;
      if (rawWriteAction !== undefined) {
        if (typeof rawWriteAction !== "string" || !isWriteAction(rawWriteAction)) {
          issues.push(`${prefix}.writeAction must be one of: ${writeActionList()}`);
        } else {
          rule.writeAction = rawWriteAction;
        }
      }

      const rawReadPathPrefixes = ruleValue.readPathPrefixes;
      if (rawReadPathPrefixes !== undefined) {
        const readPathPrefixes = validatedPathPrefixList(`${prefix}.readPathPrefixes`, rawReadPathPrefixes, issues);
        if (readPathPrefixes !== undefined) rule.readPathPrefixes = readPathPrefixes;
      }

      const rawWritePathPrefixes = ruleValue.writePathPrefixes;
      if (rawWritePathPrefixes !== undefined) {
        const writePathPrefixes = validatedPathPrefixList(`${prefix}.writePathPrefixes`, rawWritePathPrefixes, issues);
        if (writePathPrefixes !== undefined) rule.writePathPrefixes = writePathPrefixes;
      }

      const rawGraphql = ruleValue.graphql;
      if (rawGraphql !== undefined) {
        const graphql = validatedGraphqlRule(`${prefix}.graphql`, rawGraphql, issues);
        if (graphql !== undefined) rule.graphql = graphql;
      }

      if (rawMethods === undefined && rawPathPrefixes === undefined && rawGitPush === undefined
        && rawWriteAction === undefined && rawReadPathPrefixes === undefined
        && rawWritePathPrefixes === undefined && rawGraphql === undefined) {
        issues.push(`${prefix} must define at least one of: ${knownRequestKeys.join(", ")}`);
        continue;
      }

      requests[host] = rule;
    }
  }

  const rawHostServices = raw.hostServices;
  const hostServices: HostServicesJson = rawHostServices !== undefined
    ? validateHostServices(rawHostServices, "hostServices", issues)
    : {};

  if (issues.length > 0) throw new PolicyValidationError(issues);

  return {
    policyPath,
    generation: policyGeneration(allowedHosts, tokens, requests, writeApproval, hostServices),
    raw: {
      hosts,
      tokens,
      ...(Object.keys(requests).length > 0 ? { requests } : {}),
      ...(writeApproval !== undefined ? { writeApproval } : {}),
      ...(Object.keys(hostServices).length > 0 ? { hostServices } : {}),
    },
    allowedHosts,
    allowedHostSet,
    credentials,
    hostServices,
    tokens,
    credentialMappings,
    requests,
    ...(writeApproval !== undefined ? { writeApproval } : {}),
  };
}

// ---------------------------------------------------------------------------
// Rule-preserving `runfree host rules` remedies.
//
// `runfree host rules <host>` with any rule flag REPLACES the host's whole
// request rule. A remedy that names only the widened element would, if pasted,
// silently drop the host's other restrictions (methods, path prefixes, git-push
// deny, write action). Every emitted widening command is therefore built here
// from the host's full current rule plus the delta, and callers print the
// resulting rule beside it so the replace semantics are visible before pasting.
// This module only renders text; it changes no enforcement.
// ---------------------------------------------------------------------------

export type HostRulesWidening = {
  // Method to add to the rule's allowed methods (must already be an HttpMethod).
  method?: HttpMethod;
  // Path prefix to add to the rule's allowed prefixes; a placeholder such as
  // `<prefix>` is rendered verbatim when the operator must choose one.
  pathPrefix?: string;
};

export type HostRulesCommand = {
  // The argv tokens after `runfree`, unquoted.
  argv: string[];
  // The shell-safe rendering (`runfree host rules ...`).
  command: string;
  // The rule the command produces if pasted, as `host explain` would show it.
  resultingRule: RequestPolicyJson | undefined;
  // Rule fields `runfree host rules` cannot express; pasting the command would
  // drop them, so callers must say so.
  unexpressible: string[];
};

const SHELL_SAFE_TOKEN = /^[A-Za-z0-9_.,:@%+=\/<>-]+$/;

// Single-quote a token unless it is plainly safe; a placeholder like
// `<prefix>` stays readable because `<`/`>` are in the safe set on purpose —
// it is meant to be edited, not pasted.
export function shellQuoteToken(token: string): string {
  if (token !== "" && SHELL_SAFE_TOKEN.test(token)) return token;
  return `'${token.replace(/'/g, "'\\''")}'`;
}

export function widenedRequestRule(
  rule: RequestPolicyJson | undefined,
  widening: HostRulesWidening = {},
): RequestPolicyJson | undefined {
  const next: RequestPolicyJson = { ...(rule ?? {}) };
  if (widening.method !== undefined) {
    const methods = (next.methods ?? []).filter((allowed) => allowed !== widening.method);
    next.methods = [...methods, widening.method];
  }
  if (widening.pathPrefix !== undefined) {
    const prefixes = (next.pathPrefixes ?? []).filter((prefix) => prefix !== widening.pathPrefix);
    next.pathPrefixes = [...prefixes, widening.pathPrefix];
  }
  return Object.keys(next).length === 0 ? undefined : next;
}

export function hostRulesCommand(
  host: string,
  rule: RequestPolicyJson | undefined,
  widening: HostRulesWidening = {},
): HostRulesCommand {
  const resultingRule = widenedRequestRule(rule, widening);
  const argv = ["host", "rules", host];
  const unexpressible: string[] = [];
  if (resultingRule) {
    for (const method of resultingRule.methods ?? []) argv.push("--method", method);
    for (const prefix of resultingRule.pathPrefixes ?? []) argv.push("--request-path-prefix", prefix);
    if (resultingRule.gitPush === "deny") argv.push("--deny-git-push");
    if (resultingRule.writeAction !== undefined) argv.push("--write", resultingRule.writeAction);
    if (resultingRule.gitPush === "write") unexpressible.push("gitPush=write");
    if (resultingRule.readPathPrefixes !== undefined) unexpressible.push("readPathPrefixes");
    if (resultingRule.writePathPrefixes !== undefined) unexpressible.push("writePathPrefixes");
    if (resultingRule.graphql !== undefined) unexpressible.push("graphql");
  }
  return {
    argv,
    command: ["runfree", ...argv.map(shellQuoteToken)].join(" "),
    resultingRule,
    unexpressible,
  };
}

// One-line rule description shared by `host rules`, `host explain`, and the
// proxy's denial remedies, so the "resulting rule" a remedy prints reads the
// same as the rule the operator later inspects.
export function describeRequestRule(rule: RequestPolicyJson | undefined): string {
  if (!rule) return "none (all methods, all paths, git push allowed)";
  return [
    `methods=${rule.methods ? rule.methods.join(",") : "all"}`,
    `pathPrefixes=${rule.pathPrefixes ? rule.pathPrefixes.join(",") : "all"}`,
    `gitPush=${rule.gitPush ?? "allow"}`,
    ...(rule.writeAction !== undefined ? [`writeAction=${rule.writeAction}`] : []),
    ...(rule.readPathPrefixes !== undefined ? [`readPathPrefixes=${rule.readPathPrefixes.join(",")}`] : []),
    ...(rule.writePathPrefixes !== undefined ? [`writePathPrefixes=${rule.writePathPrefixes.join(",")}`] : []),
    ...(rule.graphql !== undefined ? [`graphql=${rule.graphql.endpoints.join(",")}`] : []),
  ].join(" ");
}
