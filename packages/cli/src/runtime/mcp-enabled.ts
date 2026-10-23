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
//
// The file also holds the sticky owner of each MCP share group (R16): one
// server enabled for several agents is captured by exactly one owner
// provider, chosen when the group first forms and kept while it is a member.

import fs from "node:fs";
import path from "node:path";

import { isMcpAgentId } from "../agents.ts";
import { checkPolicyHostname, isRecordableEndpoint } from "../admin/mcp-discovery.ts";
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

export type McpCrossHostKind = "token" | "registration";

export type McpEnabledHost = {
  host: string;
  origin: McpEnabledHostOrigin;
  evidence?: string[];
  // Provenance (X3, Q3): a discovered host outside the server's binding set
  // that serves the token endpoint (and possibly an exact registration
  // endpoint) its metadata named. Discovered hosts only.
  crossHost?: true;
  crossHostKinds?: McpCrossHostKind[];
};

export type McpEnabledEndpointKind = "metadata" | "token" | "registration";

// An exact OAuth endpoint validated by discovery. Projected into the server's
// OAuth mediation policy so the proxy mediates it statically, and into the
// request rules of a projected host so nothing else on that host is reachable.
export type McpEnabledEndpoint = {
  kind: McpEnabledEndpointKind;
  host: string;
  path: string;
  // A cross-host registration endpoint (Q8): the proxy matches it by exact
  // path, not by prefix. Registration endpoints on a cross-host host only.
  exact?: true;
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

// Keyed by the share group digest (`mcpShareGroupDigest`): the group's
// sticky owner. It moves only when the owner is no longer a member.
export type McpShareGroupState = {
  owner: string;
};

export type McpEnabledFile = {
  schemaVersion: 1;
  projectHash: string;
  records: Record<string, McpEnabledRecord>;
  shareGroups?: Record<string, McpShareGroupState>;
};

export type McpEnabledRead = {
  file: McpEnabledFile;
  // Records present in the file that failed validation and grant nothing.
  invalidRecords: number;
  // The whole file was unreadable or malformed (it grants nothing).
  malformed: boolean;
};

const RECORD_KEYS = new Set(["schemaVersion", "identity", "agent", "source", "server", "enabledAt", "oauthHosts", "oauthEndpoints"]);
const HOST_KEYS = new Set(["host", "origin", "evidence", "crossHost", "crossHostKinds"]);
const ENDPOINT_KEYS = new Set(["kind", "host", "path", "exact"]);
// Evidence and paths are rendered to the terminal: printable ASCII only.
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;
const FILE_KEYS = new Set(["schemaVersion", "projectHash", "records", "shareGroups"]);
const SHARE_GROUP_KEY = /^[a-f0-9]{64}$/;
const SHARE_GROUP_OWNER = /^mcp:[a-z0-9_-]+$/;
const CROSS_HOST_KINDS: readonly McpCrossHostKind[] = ["registration", "token"];

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
  // Cross-host provenance: discovered hosts only, with a sorted, non-empty,
  // duplicate-free list of the endpoint kinds the host serves.
  if (value.crossHost !== undefined || value.crossHostKinds !== undefined) {
    if (value.crossHost !== true || value.origin !== "discovered") return undefined;
    const kinds = value.crossHostKinds;
    if (!Array.isArray(kinds) || kinds.length === 0) return undefined;
    if (!kinds.every((kind, index) => CROSS_HOST_KINDS.includes(kind as McpCrossHostKind) && (index === 0 || (kinds[index - 1] as string) < (kind as string)))) return undefined;
  }
  return {
    host: value.host,
    origin: value.origin,
    ...(value.evidence !== undefined ? { evidence: [...value.evidence as string[]] } : {}),
    ...(value.crossHost === true ? { crossHost: true as const, crossHostKinds: [...value.crossHostKinds as McpCrossHostKind[]] } : {}),
  };
}

function validEndpoint(value: unknown): McpEnabledEndpoint | undefined {
  if (!isRecord(value) || !onlyKeys(value, ENDPOINT_KEYS)) return undefined;
  if (value.kind !== "metadata" && value.kind !== "token" && value.kind !== "registration") return undefined;
  if (typeof value.host !== "string" || typeof value.path !== "string") return undefined;
  // The same predicate discovery filters with, so every reviewed endpoint can
  // be saved and nothing else can be read back.
  if (!isRecordableEndpoint(value.kind, value.host, value.path)) return undefined;
  if (value.exact !== undefined && (value.exact !== true || value.kind !== "registration")) return undefined;
  return { kind: value.kind, host: value.host, path: value.path, ...(value.exact === true ? { exact: true as const } : {}) };
}

/** Validate a record before it is shown for approval or saved. */
export function validateMcpEnabledRecord(record: McpEnabledRecord): McpEnabledRecord | undefined {
  return validRecord(record.identity, record);
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
      const existing = endpoints.find((other) => other.kind === endpoint.kind && other.host === endpoint.host && other.path === endpoint.path);
      // One endpoint listed both exact and by prefix is a conflict, as in the
      // OAuth mediation contract.
      if (existing && existing.exact !== endpoint.exact) return undefined;
      if (!existing) endpoints.push(endpoint);
    }
  }
  // Every cross-host host lists the kinds it serves, and an exact
  // registration endpoint sits only on a cross-host host that lists it.
  for (const host of hosts) {
    if (!host.crossHost) continue;
    for (const kind of host.crossHostKinds ?? []) {
      if (!endpoints.some((endpoint) => endpoint.host === host.host && endpoint.kind === kind)) return undefined;
    }
  }
  for (const endpoint of endpoints) {
    if (!endpoint.exact) continue;
    const host = hosts.find((entry) => entry.host === endpoint.host);
    if (!host?.crossHost || !host.crossHostKinds?.includes("registration")) return undefined;
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
  const shareGroups = validShareGroups(parsed.shareGroups);
  return {
    file: {
      schemaVersion: 1,
      projectHash: projectHash(projectRoot),
      records,
      ...(Object.keys(shareGroups).length > 0 ? { shareGroups } : {}),
    },
    invalidRecords,
    malformed: false,
  };
}

// Share group owners. An invalid entry is dropped on its own: the group then
// forms again at the next projection, which clears its OAuth state (a new
// login), so a corrupt entry never keeps a stale owner.
function validShareGroups(value: unknown): Record<string, McpShareGroupState> {
  const groups: Record<string, McpShareGroupState> = {};
  if (!isRecord(value)) return groups;
  for (const [key, entry] of Object.entries(value)) {
    if (!SHARE_GROUP_KEY.test(key) || !isRecord(entry) || !onlyKeys(entry, new Set(["owner"]))) continue;
    if (typeof entry.owner !== "string" || !SHARE_GROUP_OWNER.test(entry.owner)) continue;
    groups[key] = { owner: entry.owner };
  }
  return groups;
}

// --- Projection --------------------------------------------------------------

type OAuthEndpointJson = string | { host: string; path: string };
type OAuthRegistrationEndpointJson = string | { exact?: true; host: string; path: string };

export type EnabledOAuthPolicyTarget = {
  resourceHost: string;
  oauth?: { authServerMetadataUrl?: string };
  tokenEndpoints?: OAuthEndpointJson[];
  registrationEndpoints?: OAuthRegistrationEndpointJson[];
};

function endpointHost(endpoint: OAuthEndpointJson): string | undefined {
  if (typeof endpoint !== "string") return endpoint.host;
  try {
    return new URL(endpoint).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function hasEndpoint(list: OAuthRegistrationEndpointJson[], host: string, pathName: string): boolean {
  return list.some((entry) => typeof entry !== "string" && entry.host === host && entry.path === pathName);
}

/**
 * Add a record's validated token and registration endpoints to the server's
 * OAuth mediation policy, so the proxy mediates them statically rather than
 * only after it captures metadata the agent chose to fetch. Only endpoints on
 * a host the mediator binds for this server are applied: the resource host,
 * declared metadata/token hosts, and the record's hosts.
 *
 * Returns the record's token and registration endpoints that are now static
 * mediated endpoints of this server. Those, and only those, become the
 * server's protocol-read endpoints: a POST to exactly one of them is an OAuth
 * protocol read while the proxy mediates it.
 */
export function projectEnabledOAuthEndpoints(policy: EnabledOAuthPolicyTarget, record: McpEnabledRecord): Array<{ host: string; path: string }> {
  const applied: Array<{ host: string; path: string }> = [];
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
  // resource host, declared hosts, issuer hosts the resource metadata named,
  // user hosts, or a cross-host token host (all of which are recorded hosts
  // or the resource host). An endpoint on a user host (`--oauth-host`) that
  // discovery did not record is not static: the proxy binds it when the
  // server's own metadata names it there (`bindingHosts`), and otherwise
  // refuses a token request to it while only MCP records allow the host.
  for (const host of record.oauthHosts) bound.add(host.host);
  for (const endpoint of record.oauthEndpoints ?? []) {
    if (!bound.has(endpoint.host)) continue;
    if (endpoint.kind === "token") {
      policy.tokenEndpoints ??= [];
      if (!hasEndpoint(policy.tokenEndpoints, endpoint.host, endpoint.path)) policy.tokenEndpoints.push({ host: endpoint.host, path: endpoint.path });
    } else if (endpoint.kind === "registration") {
      policy.registrationEndpoints ??= [];
      if (!hasEndpoint(policy.registrationEndpoints, endpoint.host, endpoint.path)) {
        policy.registrationEndpoints.push({ ...(endpoint.exact ? { exact: true as const } : {}), host: endpoint.host, path: endpoint.path });
      }
    } else {
      continue;
    }
    if (!applied.some((entry) => entry.host === endpoint.host && entry.path === endpoint.path)) {
      applied.push({ host: endpoint.host, path: endpoint.path });
    }
  }
  return applied;
}

export type EnabledEndpointClaimant = {
  // Unique per claimant: a prepared server, or one share group (R16), whose
  // members count as one claimant.
  serverKey: string;
  // Shown in the warning.
  label: string;
  policy?: EnabledOAuthPolicyTarget;
  record?: McpEnabledRecord;
};

function endpointKey(host: string, pathName: string): string {
  return `${host}\0${pathName}`;
}

function staticEndpointKeys(policy: EnabledOAuthPolicyTarget | undefined): string[] {
  const keys: string[] = [];
  for (const endpoint of [...(policy?.tokenEndpoints ?? []), ...(policy?.registrationEndpoints ?? [])]) {
    if (typeof endpoint === "string") {
      try {
        const url = new URL(endpoint);
        keys.push(endpointKey(url.hostname.toLowerCase(), url.pathname || "/"));
      } catch {
        // The contract validator reports a malformed declared endpoint.
      }
    } else {
      keys.push(endpointKey(endpoint.host, endpoint.path));
    }
  }
  return keys;
}

/**
 * Returns each claimant's record without the token and registration endpoints
 * that another server also claims, statically or through its own record. The
 * proxy mediates a token request for the first server whose endpoint list
 * matches, so a shared endpoint projected statically could file one server's
 * tokens under another server's handles. The dropped endpoints stay in the
 * record's request rules (callers pass the unfiltered records there; the
 * login still reaches them, as with `host add`); they are only not added to
 * the mediation policy.
 */
export function withoutSharedEnabledEndpoints(claimants: readonly EnabledEndpointClaimant[]): {
  records: Array<McpEnabledRecord | undefined>;
  dropped: string[];
} {
  const claims = new Map<string, Set<string>>();
  const claim = (key: string, serverKey: string): void => {
    const set = claims.get(key) ?? new Set<string>();
    set.add(serverKey);
    claims.set(key, set);
  };
  for (const claimant of claimants) {
    for (const key of staticEndpointKeys(claimant.policy)) claim(key, claimant.serverKey);
    for (const endpoint of claimant.record?.oauthEndpoints ?? []) {
      if (endpoint.kind !== "metadata") claim(endpointKey(endpoint.host, endpoint.path), claimant.serverKey);
    }
  }
  const dropped: string[] = [];
  const records = claimants.map((claimant) => {
    const record = claimant.record;
    if (!record?.oauthEndpoints) return record;
    const kept = record.oauthEndpoints.filter((endpoint) => {
      if (endpoint.kind === "metadata") return true;
      const shared = (claims.get(endpointKey(endpoint.host, endpoint.path))?.size ?? 0) > 1;
      if (shared) {
        dropped.push(`mcp: ${claimant.label} ${endpoint.kind} endpoint https://${endpoint.host}${endpoint.path} is also used by another MCP server; the proxy does not mediate it statically for either`);
      }
      return !shared;
    });
    return { ...record, oauthEndpoints: kept };
  });
  return { records, dropped };
}

const OAUTH_HOST_METHODS = ["GET", "HEAD", "OPTIONS", "POST"] as const;

/**
 * Add each record's OAuth hosts to the host-only effective policy copy, and
 * return the hosts this added: hosts nothing but these records allows (the
 * input for `recordOnlyHosts`, R6).
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
): string[] {
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
  if (paths.size === 0) return [];
  policy.hosts = [...new Set([...(policy.hosts ?? []), ...paths.keys()])].sort((left, right) => left.localeCompare(right));
  for (const [host, set] of paths) {
    if (broad.has(host)) continue;
    policy.requests ??= {};
    policy.requests[host] = {
      methods: [...OAUTH_HOST_METHODS],
      pathPrefixes: [...set].sort(),
    };
  }
  return [...paths.keys()].sort();
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
  // Share groups whose stored owner this write cleared.
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
 * Remove every record for an agent and server (optionally one source).
 * Writes only when something changes, including dropping invalid records.
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

/**
 * Store the share group owners a projection settled on. Writes only when they
 * changed, and never over a file that did not read cleanly (that file grants
 * nothing until enable or revoke reclaims it). Only the owners change: the
 * records, including any invalid one, stay exactly as they are, so enable
 * and revoke remain the only reclaim path and report what they drop.
 */
export function saveMcpShareGroups(
  projectRoot: string,
  filePath: string,
  groups: Record<string, McpShareGroupState>,
): boolean {
  const current = readMcpEnabled(projectRoot, filePath, { quiet: true });
  if (current.malformed) return false;
  const next = Object.fromEntries(Object.entries(groups).sort(([left], [right]) => left.localeCompare(right)));
  if (JSON.stringify(current.file.shareGroups ?? {}) === JSON.stringify(next)) return false;
  let raw: Record<string, unknown>;
  try {
    // readMcpEnabled just validated the file's shape (or found none).
    raw = JSON.parse(fs.readFileSync(filePath, "utf8")) as Record<string, unknown>;
  } catch (error) {
    if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw error;
    raw = { ...current.file };
  }
  if (Object.keys(next).length > 0) raw.shareGroups = next;
  else delete raw.shareGroups;
  writeMcpEnabled(projectRoot, filePath, raw as McpEnabledFile);
  return true;
}
