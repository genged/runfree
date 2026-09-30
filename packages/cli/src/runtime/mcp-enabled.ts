// Host-owned record of the OAuth hosts that `runfree mcp enable` approved for
// one MCP server. The hosts are projected into the host-only effective policy
// copy by `prepareMcpRuntime`, beside the MCP endpoint host; they are never
// written to desired policy. The projection is a union over valid records, so
// revoking one server removes exactly its record and leaves every other owner
// of a host (desired policy, services, other MCP servers) unchanged.
//
// The file lives in XDG project state, which the agent cannot see. Reads
// validate every record; an invalid record grants nothing. The next write
// (enable or revoke) keeps only the valid records, which reclaims a corrupt
// file without widening anything.

import fs from "node:fs";
import path from "node:path";

import { normalizePathPrefix } from "@runfree/runtime-contracts/network-policy";

import { isMcpAgentId } from "../agents.ts";
import { checkPolicyHostname } from "../admin/mcp-discovery.ts";
import { projectHash } from "../project-identity.ts";
import { atomicReplaceFile, isPathInsideByRealpath } from "../safe-fs.ts";
import { isRecord } from "../strict-primitives.ts";
import { warn } from "../warnings.ts";
import type { McpAgent, McpSourceScope } from "./mcp.ts";

export const MCP_ENABLED_FILE = "mcp-enabled.json";
export const MCP_ENABLED_LIMITS = Object.freeze({
  maxFileBytes: 256 * 1024,
  maxHostsPerRecord: 16,
  maxEvidenceItems: 4,
  maxEvidenceChars: 512,
  maxEndpointsPerRecord: 32,
});

export type McpEnabledHostOrigin = "discovered" | "user";

export type McpEnabledHost = {
  host: string;
  origin: McpEnabledHostOrigin;
  evidence?: string[];
};

export type McpEnabledEndpointKind = "metadata" | "token" | "registration";

// An exact OAuth endpoint validated by discovery. Projected into the server's
// OAuth mediation policy so the proxy mediates it statically, and into the
// request rules of a projected host so nothing else on that host is reachable.
export type McpEnabledEndpoint = {
  kind: McpEnabledEndpointKind;
  host: string;
  path: string;
};

export type McpEnabledRecord = {
  schemaVersion: 1;
  identity: string;
  agent: McpAgent;
  source: McpSourceScope;
  server: string;
  enabledAt: string;
  oauthHosts: McpEnabledHost[];
  oauthEndpoints?: McpEnabledEndpoint[];
};

export type McpEnabledFile = {
  schemaVersion: 1;
  projectHash: string;
  records: Record<string, McpEnabledRecord>;
};

export type McpEnabledRead = {
  file: McpEnabledFile;
  // Records present in the file that failed validation and grant nothing.
  invalidRecords: number;
  // The whole file was unreadable or malformed (it grants nothing).
  malformed: boolean;
};

const RECORD_KEYS = new Set(["schemaVersion", "identity", "agent", "source", "server", "enabledAt", "oauthHosts", "oauthEndpoints"]);
const HOST_KEYS = new Set(["host", "origin", "evidence"]);
const ENDPOINT_KEYS = new Set(["kind", "host", "path"]);
// Evidence and paths are rendered to the terminal: printable ASCII only.
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;
const FILE_KEYS = new Set(["schemaVersion", "projectHash", "records"]);

export function mcpEnabledPath(stateDir: string): string {
  return path.join(stateDir, MCP_ENABLED_FILE);
}

function emptyFile(projectRoot: string): McpEnabledFile {
  return { schemaVersion: 1, projectHash: projectHash(projectRoot), records: {} };
}

function onlyKeys(value: Record<string, unknown>, allowed: Set<string>): boolean {
  return Object.keys(value).every((key) => allowed.has(key));
}

/** Clamp evidence to the stored bounds; anything but printable ASCII becomes "?". */
export function boundedEvidence(evidence: readonly string[]): string[] {
  return evidence
    .slice(0, MCP_ENABLED_LIMITS.maxEvidenceItems)
    .map((line) => line.replace(/[^\x20-\x7e]/g, "?").slice(0, MCP_ENABLED_LIMITS.maxEvidenceChars));
}

function validHost(value: unknown): McpEnabledHost | undefined {
  if (!isRecord(value) || !onlyKeys(value, HOST_KEYS)) return undefined;
  if (typeof value.host !== "string") return undefined;
  const checked = checkPolicyHostname(value.host);
  if (!checked.ok || checked.host !== value.host) return undefined;
  if (value.origin !== "discovered" && value.origin !== "user") return undefined;
  if (value.evidence !== undefined) {
    if (!Array.isArray(value.evidence) || value.evidence.length > MCP_ENABLED_LIMITS.maxEvidenceItems) return undefined;
    for (const line of value.evidence) {
      if (typeof line !== "string" || line.length > MCP_ENABLED_LIMITS.maxEvidenceChars || !PRINTABLE_ASCII.test(line)) return undefined;
    }
  }
  return {
    host: value.host,
    origin: value.origin,
    ...(value.evidence !== undefined ? { evidence: [...value.evidence as string[]] } : {}),
  };
}

function validEndpoint(value: unknown): McpEnabledEndpoint | undefined {
  if (!isRecord(value) || !onlyKeys(value, ENDPOINT_KEYS)) return undefined;
  if (value.kind !== "metadata" && value.kind !== "token" && value.kind !== "registration") return undefined;
  if (typeof value.host !== "string" || typeof value.path !== "string") return undefined;
  const checked = checkPolicyHostname(value.host);
  if (!checked.ok || checked.host !== value.host) return undefined;
  if (value.path.length > 1024 || !PRINTABLE_ASCII.test(value.path) || !value.path.startsWith("/")) return undefined;
  try {
    // The path must be exactly what a URL parser produces and a valid
    // request-rule prefix, so the proxy's exact match and the rule agree.
    if (new URL(`https://${value.host}${value.path}`).pathname !== value.path) return undefined;
    if (normalizePathPrefix(value.path) !== value.path) return undefined;
  } catch {
    return undefined;
  }
  if (value.kind === "metadata" && !value.path.includes("/.well-known/")) return undefined;
  return { kind: value.kind, host: value.host, path: value.path };
}

function validRecord(key: string, value: unknown): McpEnabledRecord | undefined {
  if (!isRecord(value) || !onlyKeys(value, RECORD_KEYS)) return undefined;
  if (value.schemaVersion !== 1 || value.identity !== key || key === "") return undefined;
  if (typeof value.agent !== "string" || !isMcpAgentId(value.agent)) return undefined;
  if (value.source !== "user" && value.source !== "local" && value.source !== "project") return undefined;
  if (typeof value.server !== "string" || value.server === "") return undefined;
  if (typeof value.enabledAt !== "string" || Number.isNaN(Date.parse(value.enabledAt))) return undefined;
  if (!Array.isArray(value.oauthHosts) || value.oauthHosts.length > MCP_ENABLED_LIMITS.maxHostsPerRecord) return undefined;
  const hosts: McpEnabledHost[] = [];
  for (const entry of value.oauthHosts) {
    const host = validHost(entry);
    if (!host || hosts.some((existing) => existing.host === host.host)) return undefined;
    hosts.push(host);
  }
  const endpoints: McpEnabledEndpoint[] = [];
  if (value.oauthEndpoints !== undefined) {
    if (!Array.isArray(value.oauthEndpoints) || value.oauthEndpoints.length > MCP_ENABLED_LIMITS.maxEndpointsPerRecord) return undefined;
    for (const entry of value.oauthEndpoints) {
      const endpoint = validEndpoint(entry);
      if (!endpoint) return undefined;
      if (!endpoints.some((existing) => existing.kind === endpoint.kind && existing.host === endpoint.host && existing.path === endpoint.path)) {
        endpoints.push(endpoint);
      }
    }
  }
  return {
    schemaVersion: 1,
    identity: key,
    agent: value.agent as McpAgent,
    source: value.source,
    server: value.server,
    enabledAt: value.enabledAt,
    oauthHosts: hosts,
    ...(value.oauthEndpoints !== undefined ? { oauthEndpoints: endpoints } : {}),
  };
}

export function readMcpEnabled(projectRoot: string, filePath: string | undefined, options: { quiet?: boolean } = {}): McpEnabledRead {
  const empty = emptyFile(projectRoot);
  const report = (message: string): void => {
    if (!options.quiet) warn(message);
  };
  if (!filePath) return { file: empty, invalidRecords: 0, malformed: false };
  if (isPathInsideByRealpath(projectRoot, filePath)) {
    report("mcp: ignored project-controlled MCP enable file; enabled OAuth hosts must live outside the project");
    return { file: empty, invalidRecords: 0, malformed: true };
  }
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(filePath);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return { file: empty, invalidRecords: 0, malformed: false };
    }
    report(`mcp: ignored unreadable MCP enable file ${filePath}; enabled OAuth hosts are not applied`);
    return { file: empty, invalidRecords: 0, malformed: true };
  }
  if (!stat.isFile() || stat.size > MCP_ENABLED_LIMITS.maxFileBytes) {
    report(`mcp: ignored MCP enable file ${filePath} (not a regular file or larger than ${MCP_ENABLED_LIMITS.maxFileBytes} bytes); enabled OAuth hosts are not applied; re-run runfree mcp enable to rewrite it`);
    return { file: empty, invalidRecords: 0, malformed: true };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, "utf8")) as unknown;
  } catch {
    report(`mcp: ignored malformed MCP enable file ${filePath}; enabled OAuth hosts are not applied; re-run runfree mcp enable to rewrite it`);
    return { file: empty, invalidRecords: 0, malformed: true };
  }
  if (!isRecord(parsed) || !onlyKeys(parsed, FILE_KEYS) || parsed.schemaVersion !== 1 || !isRecord(parsed.records)) {
    report(`mcp: ignored malformed MCP enable file ${filePath}; enabled OAuth hosts are not applied; re-run runfree mcp enable to rewrite it`);
    return { file: empty, invalidRecords: 0, malformed: true };
  }
  if (parsed.projectHash !== projectHash(projectRoot)) {
    report(`mcp: ignored MCP enable file ${filePath} for another project`);
    return { file: empty, invalidRecords: 0, malformed: true };
  }
  const records: Record<string, McpEnabledRecord> = {};
  let invalidRecords = 0;
  for (const [key, value] of Object.entries(parsed.records)) {
    const record = validRecord(key, value);
    if (record) {
      records[key] = record;
      continue;
    }
    invalidRecords += 1;
    const label = isRecord(value) && typeof value.agent === "string" && typeof value.server === "string"
      ? `${value.agent} ${value.server}`.replace(/[^A-Za-z0-9 ._:@-]/g, "?").slice(0, 120)
      : "unknown server";
    report(`mcp: ignored an invalid MCP enable record (${label}); its OAuth hosts are not applied; remove it with runfree mcp revoke or re-run runfree mcp enable`);
  }
  return { file: { schemaVersion: 1, projectHash: projectHash(projectRoot), records }, invalidRecords, malformed: false };
}

// --- Projection --------------------------------------------------------------

type OAuthEndpointJson = string | { host: string; path: string };

export type EnabledOAuthPolicyTarget = {
  resourceHost: string;
  oauth?: { authServerMetadataUrl?: string };
  tokenEndpoints?: OAuthEndpointJson[];
  registrationEndpoints?: OAuthEndpointJson[];
};

function endpointHost(endpoint: OAuthEndpointJson): string | undefined {
  if (typeof endpoint !== "string") return endpoint.host;
  try {
    return new URL(endpoint).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function hasEndpoint(list: OAuthEndpointJson[], host: string, pathName: string): boolean {
  return list.some((entry) => typeof entry !== "string" && entry.host === host && entry.path === pathName);
}

/**
 * Add a record's validated token and registration endpoints to the server's
 * OAuth mediation policy, so the proxy mediates them statically rather than
 * only after it captures metadata the agent chose to fetch. Only endpoints on
 * a host the mediator binds for this server are applied: the resource host,
 * declared metadata/token hosts, and the record's hosts.
 */
export function projectEnabledOAuthEndpoints(policy: EnabledOAuthPolicyTarget, record: McpEnabledRecord): void {
  const bound = new Set<string>([policy.resourceHost]);
  const metadataUrl = policy.oauth?.authServerMetadataUrl;
  if (metadataUrl) {
    try {
      bound.add(new URL(metadataUrl).hostname.toLowerCase());
    } catch {
      // The contract validator reports a malformed declared URL.
    }
  }
  for (const endpoint of policy.tokenEndpoints ?? []) {
    const host = endpointHost(endpoint);
    if (host) bound.add(host);
  }
  // Endpoints come only from discovery, which accepted them only on the
  // resource host, declared hosts, or issuer hosts the resource metadata named
  // (all of which are recorded hosts or the resource host).
  for (const host of record.oauthHosts) bound.add(host.host);
  for (const endpoint of record.oauthEndpoints ?? []) {
    if (!bound.has(endpoint.host)) continue;
    if (endpoint.kind === "token") {
      policy.tokenEndpoints ??= [];
      if (!hasEndpoint(policy.tokenEndpoints, endpoint.host, endpoint.path)) policy.tokenEndpoints.push({ host: endpoint.host, path: endpoint.path });
    } else if (endpoint.kind === "registration") {
      policy.registrationEndpoints ??= [];
      if (!hasEndpoint(policy.registrationEndpoints, endpoint.host, endpoint.path)) policy.registrationEndpoints.push({ host: endpoint.host, path: endpoint.path });
    }
  }
}

const OAUTH_HOST_METHODS = ["GET", "HEAD", "OPTIONS", "POST"] as const;

/**
 * Add each record's OAuth hosts to the host-only effective policy copy.
 *
 * A host that the policy already allows (desired policy, a service, or an MCP
 * endpoint projection) keeps its existing rules untouched. A host only records
 * add is narrowed when every record that names it found it by discovery: GET,
 * HEAD, OPTIONS, and POST, on `/.well-known` and the exact validated endpoint
 * paths only. A `user` host (`--oauth-host`) is allowed as given, like
 * `runfree host add`. The write action is never raised: token POSTs follow the
 * project write approval setting.
 */
export function projectEnabledOAuthHosts(
  policy: { hosts?: string[]; requests?: Record<string, { methods?: string[]; pathPrefixes?: string[] }> },
  records: readonly McpEnabledRecord[],
): void {
  const existing = new Set(policy.hosts ?? []);
  const broad = new Set<string>();
  const paths = new Map<string, Set<string>>();
  for (const record of records) {
    for (const host of record.oauthHosts) {
      if (existing.has(host.host)) continue;
      if (host.origin === "user") broad.add(host.host);
      const set = paths.get(host.host) ?? new Set<string>(["/.well-known"]);
      for (const endpoint of record.oauthEndpoints ?? []) {
        if (endpoint.host === host.host) set.add(endpoint.path);
      }
      paths.set(host.host, set);
    }
  }
  if (paths.size === 0) return;
  policy.hosts = [...new Set([...(policy.hosts ?? []), ...paths.keys()])].sort((left, right) => left.localeCompare(right));
  for (const [host, set] of paths) {
    if (broad.has(host)) continue;
    policy.requests ??= {};
    policy.requests[host] = {
      methods: [...OAUTH_HOST_METHODS],
      pathPrefixes: [...set].sort(),
    };
  }
}

function writeMcpEnabled(projectRoot: string, filePath: string, file: McpEnabledFile): void {
  if (isPathInsideByRealpath(projectRoot, filePath)) {
    throw new Error("MCP enable file must be outside the project");
  }
  atomicReplaceFile(filePath, `${JSON.stringify(file, null, 2)}\n`, 0o600);
}

function sameServer(record: McpEnabledRecord, target: { agent: McpAgent; server: string; source?: McpSourceScope }): boolean {
  return record.agent === target.agent
    && record.server === target.server
    && (target.source === undefined || record.source === target.source);
}

export type McpEnabledWriteResult = {
  // Invalid records dropped by this rewrite (the reclaim path).
  droppedInvalid: number;
  // Records this write removed.
  removed: McpEnabledRecord[];
};

/**
 * Replace every record for the record's agent, source, and server with this
 * one. Invalid records in the file are dropped (reclaim).
 */
export function saveMcpEnabledRecord(projectRoot: string, filePath: string, record: McpEnabledRecord): McpEnabledWriteResult {
  const validated = validRecord(record.identity, record);
  if (!validated) throw new Error("internal error: refusing to save an invalid MCP enable record");
  const current = readMcpEnabled(projectRoot, filePath, { quiet: true });
  const removed: McpEnabledRecord[] = [];
  for (const [key, existing] of Object.entries(current.file.records)) {
    if (sameServer(existing, record)) {
      removed.push(existing);
      delete current.file.records[key];
    }
  }
  current.file.records[validated.identity] = validated;
  writeMcpEnabled(projectRoot, filePath, current.file);
  return { droppedInvalid: current.invalidRecords, removed };
}

/**
 * Remove every record for an agent and server (optionally one source). Writes
 * only when something changes, including dropping invalid records.
 */
export function removeMcpEnabledRecords(
  projectRoot: string,
  filePath: string,
  target: { agent: McpAgent; server: string; source?: McpSourceScope },
): McpEnabledWriteResult {
  const current = readMcpEnabled(projectRoot, filePath, { quiet: true });
  const removed: McpEnabledRecord[] = [];
  for (const [key, existing] of Object.entries(current.file.records)) {
    if (sameServer(existing, target)) {
      removed.push(existing);
      delete current.file.records[key];
    }
  }
  if (removed.length > 0 || current.invalidRecords > 0 || current.malformed) {
    writeMcpEnabled(projectRoot, filePath, current.file);
  }
  return { droppedInvalid: current.invalidRecords, removed };
}
