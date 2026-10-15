import crypto from "node:crypto";
import fs from "node:fs";
import { isIP } from "node:net";
import os from "node:os";
import path from "node:path";

import {
  type McpOperationPolicyJson,
  type McpOperationServerPolicyJson,
  validateMcpOperationPolicy,
  type McpToolOperationPolicyJson,
} from "@runfree/runtime-contracts/mcp-operation-policy";
import {
  type OAuthMediationPolicyJson,
  type OAuthProviderPolicyJson,
  validateOAuthMediationPolicy,
  type OAuthTokenEndpointJson,
  type OAuthProviderKind,
  type OAuthSeedJson,
} from "@runfree/runtime-contracts/oauth-mediation-policy";
import {
  isIpLiteralHostname,
  normalizeHostname,
  normalizePathPrefix,
  validateNetworkPolicy,
  type CredentialPolicyJson,
  type PolicyJson,
} from "@runfree/runtime-contracts/network-policy";
import { HOST_SERVICE_NAME_RE, type HostServicesJson, refusedHostServicePortReason } from "@runfree/runtime-contracts/host-services";
import { parse as parseToml } from "smol-toml";
import { isMcpAgentId, MCP_AGENT_IDS } from "../agents.ts";
import type { ProjectInfo } from "../config.ts";
import { readActiveEffectiveControl } from "../control/effective.ts";
import { projectHash } from "../project-identity.ts";
import { atomicReplaceFile, isPathInsideByRealpath, safeReadProjectFile } from "../safe-fs.ts";
import { runfreeLog, warn } from "../warnings.ts";
import { updateCodexConfig } from "./codex-config.ts";
import { CODEX_DESKTOP_BUILTIN_REASON, isCodexDesktopBuiltIn } from "./mcp-desktop-builtins.ts";
import {
  projectEnabledOAuthEndpoints,
  projectEnabledOAuthHosts,
  readMcpEnabled,
  withoutSharedEnabledEndpoints,
} from "./mcp-enabled.ts";
import { mcpOAuthStateEpoch, updateMcpOAuthEpochs } from "./mcp-oauth-epochs.ts";
import { RUNFREE_RUNTIME_TARGETS, workspaceMetadataTarget } from "./mount-target-policy.ts";
import { sha256Hex, isRecord } from "../strict-primitives.ts";
import { remedy } from "../remedies.ts";

type TokenSource =
  | { source: "env"; env: string }
  | { source: "1password"; ref: string }
  | { source: "named"; name: string }
  | { source: "file"; path: string }
  | { source: "cmd"; command: string };

type TokenSourceConfig = Record<string, TokenSource>;

export type McpAgent = (typeof MCP_AGENT_IDS)[number];
export type McpSourceScope = "user" | "local" | "project";

export type NativeMcpServer = {
  agent: McpAgent;
  config: Record<string, unknown>;
  name: string;
  scope: McpSourceScope;
  sourcePath?: string;
};

type HeaderTokenBinding = {
  credential: CredentialPolicyJson;
  env?: string;
  tokenName: string;
};

type McpTransport = "http" | "http-loopback" | "stdio";

type PreparedMcpServer = {
  agent: McpAgent;
  auth: "public" | "static" | "oauth" | "none";
  codexConfig?: CodexGeneratedServer;
  claudeConfig?: Record<string, unknown>;
  descriptorDigest?: string;
  endpoint?: {
    host: string;
    path: string;
  };
  // `http-loopback` only: the TCP port the normalized URL dials (80 when the
  // URL names none).
  loopbackPort?: number;
  oauthPolicy?: McpOAuthServerPolicyJson;
  name: string;
  source: McpSourceScope;
  tokenBindings: HeaderTokenBinding[];
  transport: McpTransport;
};

// `skipped`: a Codex Desktop built-in that Runfree deliberately ignores (see
// mcp-desktop-builtins.ts). Like `unsupported`, it is never generated,
// approved, enabled, or authenticated.
export type McpDecisionStatus = "approved" | "imported" | "unapproved" | "changed" | "unsupported" | "skipped" | "conflict";

export type McpInventoryEntry = {
  agent: McpAgent;
  auth: PreparedMcpServer["auth"] | "unknown";
  descriptor?: Record<string, unknown>;
  descriptorDigest?: string;
  decision: {
    reason?: string;
    status: McpDecisionStatus;
  };
  endpoint?: {
    host: string;
    path: string;
  };
  // `http-loopback` only: the normalized URL the agent config carries, and its
  // port. `reach` is present only when the caller supplied host services, or
  // when an admin surface could not read them (`unknown`).
  loopback?: {
    port: number;
    reach?: McpLoopbackShownReach;
    url: string;
  };
  mcpPolicy?: {
    defaultToolWriteAction?: McpWriteAction;
    operationServerId: string;
    summary: string;
    tools: Record<string, McpToolOperationPolicyJson>;
  };
  name: string;
  source: McpSourceScope;
  sourcePath?: string;
  target: "excluded" | "generated";
  tokenBindings?: Array<{
    credential: CredentialPolicyJson;
    env?: string;
    tokenName: string;
  }>;
  transport: McpTransport | "unknown";
};

export type McpInventory = {
  entries: McpInventoryEntry[];
};

type McpInventoryRecord = McpInventoryEntry & {
  descriptor?: Record<string, unknown>;
  prepared?: PreparedMcpServer;
  server: NativeMcpServer;
};

export type McpApprovalRecord = {
  agent: McpAgent;
  approvedAt: string;
  auth: PreparedMcpServer["auth"];
  digest: string;
  schemaVersion: 1;
  server: string;
  source: "project";
  summary: string;
  transport: McpTransport;
};

export type McpApprovalFile = {
  approvals: Record<string, McpApprovalRecord>;
  projectHash: string;
  schemaVersion: 1;
};

export type McpWriteAction = "allow" | "ask" | "deny";

export type McpRuleRecord = {
  agent: McpAgent;
  defaultToolWriteAction?: McpWriteAction;
  identity: string;
  schemaVersion: 1;
  server: string;
  source: McpSourceScope;
  tools?: Record<string, McpToolOperationPolicyJson>;
  updatedAt: string;
};

export type McpRulesFile = {
  projectHash: string;
  rules: Record<string, McpRuleRecord>;
  schemaVersion: 1;
};

type CodexGeneratedServer = {
  args?: string[];
  command?: string;
  cwd?: string;
  disabled_tools?: string[];
  enabled?: boolean;
  enabled_tools?: string[];
  env?: Record<string, string>;
  oauth?: boolean;
  oauth_resource?: string;
  required?: boolean;
  scopes?: string[];
  startup_timeout_sec?: number;
  tool_timeout_sec?: number;
  url?: string;
};

export type OAuthProviderPolicyForWrite = Omit<OAuthProviderPolicyJson, "kind"> & {
  kind: OAuthProviderKind;
};

export type OAuthMediationPolicyForWrite = OAuthMediationPolicyJson & {
  callback: { port: number; url: string };
};

type McpOAuthServerPolicyJson = {
  resourceHost: string;
  resourcePathPrefix: string;
  oauth?: {
    authServerMetadataUrl?: string;
  };
  tokenEndpoints?: OAuthTokenEndpointJson[];
  registrationEndpoints?: OAuthTokenEndpointJson[];
  // Set only by the effective preparation, never from MCP config: the
  // recorded mediated endpoints (`mcp enable`) and the revoke epoch.
  protocolReadEndpoints?: Array<{ host: string; path: string }>;
  seeds?: OAuthSeedJson[];
  stateEpoch?: string;
};

export type McpMaskPaths = {
  projectCodexDirMaskPath: string;
};

export type McpAgentMaskProject = {
  paths: McpMaskPaths;
};

export type ClaudeMcpConfigProject = {
  paths: {
    claudeMcpConfigPath: string;
  };
};

export type McpPrepareOptions = {
  approvalPath?: string;
  callbackPort?: number;
  claudeConfigPath: string;
  claudeMcpConfigPath: string;
  codexDir: string;
  env: NodeJS.ProcessEnv;
  // Host-owned `runfree mcp enable` records: their OAuth hosts are projected
  // beside the matching server's endpoint host.
  mcpEnabledPath?: string;
  // Host-owned OAuth state epochs (`runfree mcp revoke` tombstones): each MCP
  // OAuth provider publishes its epoch so the proxy clears older state.
  mcpOAuthEpochsPath?: string;
  mcpOperationPolicyPath?: string;
  mcpOAuthPolicyPath: string;
  mcpRulesPath?: string;
  policy: PolicyJson;
  projectRoot: string;
  tokenConfig: TokenSourceConfig;
};

export type McpPrepareResult = {
  policy: PolicyJson;
  policyChanged: boolean;
  tokenConfig: TokenSourceConfig;
  tokenConfigChanged: boolean;
};

const GENERATED_CODEX_BEGIN = "# BEGIN RUNFREE GENERATED MCP";
const GENERATED_CODEX_END = "# END RUNFREE GENERATED MCP";
const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
export const MCP_APPROVAL_FILE = "approved-mcp.json";
const MCP_OPERATION_POLICY_FILE = "mcp-operation-policy.json";
export const MCP_RULES_FILE = "mcp-rules.json";
const MCP_OAUTH_CALLBACK_BASE_PORT = 47100;
const MCP_OAUTH_CALLBACK_PORT_SPAN = 1000;


function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return isRecord(value) && Object.prototype.toString.call(value) === "[object Object]";
}

function stableJson(value: unknown): string {
  return JSON.stringify(value);
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((entry) => canonicalize(entry));
  if (!isRecord(value)) return value;
  const result: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort((left, right) => left.localeCompare(right))) {
    result[key] = canonicalize(value[key]);
  }
  return result;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}


export function mcpOAuthCallbackPort(projectRoot: string): number {
  const offset = Number.parseInt(projectHash(projectRoot).slice(0, 6), 16) % MCP_OAUTH_CALLBACK_PORT_SPAN;
  return MCP_OAUTH_CALLBACK_BASE_PORT + offset;
}

export function mcpOAuthCallbackUrl(projectRoot: string): string {
  return `http://localhost:${mcpOAuthCallbackPort(projectRoot)}/callback`;
}

function hostHome(env: NodeJS.ProcessEnv): string {
  return env.HOME || os.homedir();
}

function hostClaudeConfigPath(env: NodeJS.ProcessEnv): string {
  return path.join(hostHome(env), ".claude.json");
}

function hostCodexConfigPath(env: NodeJS.ProcessEnv): string {
  const inheritedCodexHome = env.CODEX_HOME && env.CODEX_HOME !== env.RUNFREE_CODEX_HOME && !env.CODEX_HOME.startsWith("/home/agent/")
    ? env.CODEX_HOME
    : undefined;
  const codexHome = inheritedCodexHome && inheritedCodexHome.trim() !== ""
    ? inheritedCodexHome
    : path.join(hostHome(env), ".codex");
  return path.join(codexHome, "config.toml");
}

function safeReadHostText(filePath: string, projectRoot: string, label: string): string | undefined {
  const resolved = path.resolve(filePath);
  if (isPathInsideByRealpath(projectRoot, resolved)) {
    warn(`mcp: skipped ${label} config inside project path: ${path.relative(projectRoot, resolved)}`);
    return undefined;
  }
  try {
    return fs.readFileSync(resolved, "utf8");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    warn(`mcp: skipped ${label} config ${resolved}: ${printable(error instanceof Error ? error.message : String(error))}`);
    return undefined;
  }
}

function readJsonConfig(filePath: string, projectRoot: string, label: string): Record<string, unknown> | undefined {
  const source = safeReadHostText(filePath, projectRoot, label);
  if (source === undefined) return undefined;
  try {
    const parsed = JSON.parse(source) as unknown;
    if (isRecord(parsed)) return parsed;
  } catch (error) {
    warn(`mcp: skipped ${label} config ${filePath}: ${printable(error instanceof Error ? error.message : String(error))}`);
    return undefined;
  }
  warn(`mcp: skipped ${label} config ${filePath}: expected JSON object`);
  return undefined;
}

// Render text that came from MCP config or remote metadata: escape anything
// that is not printable ASCII (control, C1, bidi, and other formatting
// characters), so it cannot move the cursor or reorder the review.
export function printable(value: string): string {
  return value.replace(/[^\x20-\x7e]/g, (char) => `\\u{${(char.codePointAt(0) ?? 0).toString(16)}}`);
}

// Server names each agent's own `mcp add` accepts (Claude Code: letters,
// digits, `-`, `_`; codex-cli 0.156.1 also `:`, `@`, `/`, `.`), with a length
// cap of Runfree's own. A name outside them is skipped, never generated.
const MCP_SERVER_NAME_MAX_LENGTH = 128;
const MCP_SERVER_NAME_RULES: Record<McpAgent, { pattern: RegExp; characters: string }> = {
  claude: { pattern: /^[A-Za-z0-9_-]+$/, characters: "letters, numbers, '-', '_'" },
  codex: { pattern: /^[A-Za-z0-9_\-:@/.]+$/, characters: "letters, numbers, '-', '_', ':', '@', '/', '.'" },
};

export function mcpServerNameRefusal(agent: McpAgent, name: string): string | undefined {
  if (name === "__proto__") return "server name __proto__ is reserved";
  if (name.length === 0 || name.length > MCP_SERVER_NAME_MAX_LENGTH) {
    return `server name must be 1-${MCP_SERVER_NAME_MAX_LENGTH} characters`;
  }
  const rule = MCP_SERVER_NAME_RULES[agent];
  return rule.pattern.test(name) ? undefined : `server name must use only ${rule.characters}`;
}

// Null-prototype so a server named `__proto__` is kept as an entry (and then
// refused by name) instead of replacing the prototype.
function mcpServersFromRecord(value: unknown): Record<string, Record<string, unknown>> {
  const servers: Record<string, Record<string, unknown>> = Object.create(null);
  if (!isRecord(value)) return servers;
  for (const [name, server] of Object.entries(value)) {
    if (!isRecord(server)) continue;
    servers[name] = server;
  }
  return servers;
}

function projectPathAliases(projectRoot: string): Set<string> {
  const aliases = new Set([path.resolve(projectRoot)]);
  try {
    aliases.add(fs.realpathSync(projectRoot));
  } catch {
    // The resolved path is still useful if realpath is unavailable.
  }
  return aliases;
}

function collectClaudeServers(projectRoot: string, env: NodeJS.ProcessEnv): NativeMcpServer[] {
  const servers: NativeMcpServer[] = [];
  const claudeConfigPath = hostClaudeConfigPath(env);
  const native = readJsonConfig(claudeConfigPath, projectRoot, "claude user");
  if (native) {
    for (const [name, config] of Object.entries(mcpServersFromRecord(native.mcpServers))) {
      servers.push({ agent: "claude", scope: "user", name, config, sourcePath: claudeConfigPath });
    }
    const projects = isRecord(native.projects) ? native.projects : {};
    for (const projectPath of projectPathAliases(projectRoot)) {
      const projectConfig = projects[projectPath];
      if (!isRecord(projectConfig)) continue;
      for (const [name, config] of Object.entries(mcpServersFromRecord(projectConfig.mcpServers))) {
        servers.push({ agent: "claude", scope: "local", name, config, sourcePath: claudeConfigPath });
      }
    }
  }

  const projectMcpPath = path.join(projectRoot, ".mcp.json");
  let projectSource: string | undefined;
  try {
    projectSource = safeReadProjectFile(projectRoot, projectMcpPath);
  } catch (error) {
    warn(`mcp: skipped project claude config .mcp.json: ${printable(error instanceof Error ? error.message : String(error))}`);
  }
  if (projectSource !== undefined) {
    if (projectSource.trim() === "") return servers;
    try {
      const parsed = JSON.parse(projectSource) as unknown;
      for (const [name, config] of Object.entries(mcpServersFromRecord(isRecord(parsed) ? parsed.mcpServers : undefined))) {
        servers.push({ agent: "claude", scope: "project", name, config, sourcePath: projectMcpPath });
      }
    } catch (error) {
      warn(`mcp: skipped project claude config .mcp.json: ${printable(error instanceof Error ? error.message : String(error))}`);
    }
  }

  return servers;
}

function unsupportedCodexTomlValuePath(value: unknown, path: string): string | undefined {
  if (typeof value === "string" || typeof value === "boolean") return undefined;
  if (typeof value === "number") return Number.isFinite(value) ? undefined : path;
  if (Array.isArray(value)) return value.every((item) => typeof item === "string") ? undefined : path;
  if (!isPlainRecord(value)) return path;
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === "string" || typeof entry === "boolean") continue;
    if (typeof entry === "number" && Number.isFinite(entry)) continue;
    if (Array.isArray(entry) && entry.every((item) => typeof item === "string")) continue;
    return `${path}.${key}`;
  }
  return undefined;
}

function parseCodexToml(source: string): Record<string, Record<string, unknown>> {
  const servers: Record<string, Record<string, unknown>> = Object.create(null);
  let parsed: Record<string, unknown>;
  try {
    parsed = parseToml(source, { maxDepth: 32 });
  } catch (error) {
    warn(`mcp: skipped codex config reason=invalid TOML: ${printable(error instanceof Error ? error.message : String(error))}`);
    return servers;
  }
  if (!isPlainRecord(parsed.mcp_servers)) return servers;
  for (const [name, config] of Object.entries(parsed.mcp_servers)) {
    if (!isPlainRecord(config)) continue;
    let unsupportedPath: string | undefined;
    for (const [key, value] of Object.entries(config)) {
      unsupportedPath = unsupportedCodexTomlValuePath(value, key);
      if (unsupportedPath) break;
    }
    if (unsupportedPath) {
      warn(`mcp: skipped codex server ${printable(name)} reason=unsupported TOML value for ${printable(unsupportedPath)}`);
      continue;
    }
    servers[name] = config;
  }
  return servers;
}

function collectCodexServers(projectRoot: string, env: NodeJS.ProcessEnv): NativeMcpServer[] {
  const servers: NativeMcpServer[] = [];
  const codexConfigPath = hostCodexConfigPath(env);
  const nativeSource = safeReadHostText(codexConfigPath, projectRoot, "codex user");
  if (nativeSource !== undefined) {
    for (const [name, config] of Object.entries(parseCodexToml(nativeSource))) {
      servers.push({ agent: "codex", scope: "user", name, config, sourcePath: codexConfigPath });
    }
  }

  const projectCodexPath = path.join(projectRoot, ".codex", "config.toml");
  let projectSource: string | undefined;
  try {
    projectSource = safeReadProjectFile(projectRoot, projectCodexPath);
  } catch (error) {
    warn(`mcp: skipped project codex config .codex/config.toml: ${printable(error instanceof Error ? error.message : String(error))}`);
  }
  if (projectSource !== undefined) {
    for (const [name, config] of Object.entries(parseCodexToml(projectSource))) {
      servers.push({ agent: "codex", scope: "project", name, config, sourcePath: projectCodexPath });
    }
  }
  return servers;
}

// L1: a URL is loopback class when WHATWG parsing yields exactly `http:` and
// `127.0.0.1`. WHATWG folds `127.1`, `2130706433`, `0x7f.0.0.1`, and
// `127.0.0.1.` to `127.0.0.1`, the address every agent's parser dials.
function loopbackUrl(raw: string): URL | undefined {
  try {
    const parsed = new URL(raw);
    return parsed.protocol === "http:" && parsed.hostname === "127.0.0.1" ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function nativeTransport(server: NativeMcpServer): McpTransport | undefined {
  const type = typeof server.config.type === "string" ? server.config.type : undefined;
  if (type === "stdio") return "stdio";
  // Any other `type` with a loopback URL (Claude `sse`, `streamable-http`) is
  // classed here and refused by name in `prepareLoopbackHttpServer` (N5).
  if (typeof server.config.url === "string" && loopbackUrl(server.config.url)) return "http-loopback";
  if (type === "http") return "http";
  if (typeof server.config.url === "string") return "http";
  if (typeof server.config.command === "string") return "stdio";
  return undefined;
}

// A deliberate refusal to import an MCP server. The inventory turns it into
// an `unsupported` decision carrying `refused` as the reason and prints the one
// warning line for it; `undefined` from a prepare function instead means the
// entry is deliberately not imported and not a problem to report.
type McpRefusal = { refused: string };

const LOOPBACK_REASONS = {
  userinfo: "loopback MCP URL must not contain a username or password",
  fragment: "loopback MCP URL must not contain a fragment",
  dollar: "loopback MCP URL must not contain $; the agent would expand it",
  portZero: "loopback MCP port must be between 1 and 65535",
  reserved: (port: number, why: string) => `loopback MCP port ${port} is reserved: ${why}`,
  claudeType: (type: string) => `loopback MCP supports only Claude type "http", not ${type}`,
  credentials: "loopback MCP cannot carry credentials or OAuth: its traffic does not pass the proxy",
  key: (key: string) => `loopback MCP does not support config key ${key}`,
  keyType: (key: string, expected: string) => `loopback MCP config key ${key} must be ${expected}`,
  localhost: "loopback MCP must use 127.0.0.1, not localhost: localhost may resolve to ::1, which the session relay does not bind",
  otherLoopback: "loopback MCP must use 127.0.0.1",
  ipv6: "loopback MCP must use 127.0.0.1: the session relay binds IPv4 loopback only",
  plainHttp: "remote HTTP MCP must use https; plain HTTP is allowed only to 127.0.0.1",
} as const;

function isMcpRefusal(value: PreparedMcpServer | McpRefusal | undefined): value is McpRefusal {
  return value !== undefined && "refused" in value;
}

function normalizeMcpUrl(url: string): McpRefusal | { host: string; pathPrefix: string; url: string } {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { refused: "invalid URL" };
  }
  if (parsed.protocol !== "https:") {
    if (parsed.protocol !== "http:") return { refused: "remote HTTP MCP must use https" };
    // `http://127.0.0.1` is `http-loopback` and never reaches here.
    if (parsed.hostname === "localhost") return { refused: LOOPBACK_REASONS.localhost };
    if (parsed.hostname.startsWith("[")) return { refused: LOOPBACK_REASONS.ipv6 };
    if (isIP(parsed.hostname) === 4 && parsed.hostname.startsWith("127.")) return { refused: LOOPBACK_REASONS.otherLoopback };
    return { refused: LOOPBACK_REASONS.plainHttp };
  }
  const bare = parsed.hostname.startsWith("[") ? parsed.hostname.slice(1, -1) : parsed.hostname;
  if (isIpLiteralHostname(bare)) return { refused: "HTTPS MCP endpoint must be a hostname, not an IP address" };
  let host: string;
  try {
    host = normalizeHostname(parsed.hostname);
  } catch (error) {
    return { refused: error instanceof Error ? error.message : String(error) };
  }
  return {
    host,
    pathPrefix: normalizePathPrefix(parsed.pathname && parsed.pathname !== "/" ? parsed.pathname : "/"),
    url,
  };
}

function stringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) return undefined;
  return value;
}

function stringRecord(value: unknown): Record<string, string> | undefined {
  if (!isRecord(value)) return undefined;
  const entries: Record<string, string> = {};
  for (const [key, item] of Object.entries(value)) {
    if (typeof item !== "string") return undefined;
    entries[key] = item;
  }
  return entries;
}

function boolValue(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function headerEnvReference(value: string): { env: string; scheme: "bearer" | "raw" } | undefined {
  const trimmed = value.trim();
  const bearer = /^Bearer\s+(?:\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*))$/i.exec(trimmed);
  if (bearer) return { env: bearer[1] ?? bearer[2], scheme: "bearer" };
  const raw = /^(?:\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*))$/.exec(trimmed);
  if (raw) return { env: raw[1] ?? raw[2], scheme: "raw" };
  return undefined;
}

function tokenNameFor(agent: McpAgent, serverName: string, header: string): string {
  const raw = `mcp-${agent}-${serverName}-${header.toLowerCase() === "authorization" ? "auth" : header}`;
  let slug = raw.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
  if (!/^[a-z]/.test(slug)) slug = `mcp-${slug}`;
  if (slug.length <= 64) return slug;
  const hash = crypto.createHash("sha256").update(raw).digest("hex").slice(0, 8);
  return `${slug.slice(0, 55).replace(/[-_]+$/g, "")}-${hash}`;
}

function bindingFor(
  agent: McpAgent,
  serverName: string,
  host: string,
  pathPrefix: string,
  header: string,
  env: string | undefined,
  scheme: "bearer" | "raw",
): HeaderTokenBinding {
  return {
    tokenName: tokenNameFor(agent, serverName, header),
    env,
    credential: {
      host,
      header,
      scheme,
      ...(pathPrefix === "/" ? {} : { pathPrefix }),
    },
  };
}

function literalHeaderScheme(value: string): "bearer" | "raw" {
  return /^Bearer\s+\S+/i.test(value.trim()) ? "bearer" : "raw";
}

function codexGeneratedOptions(config: Record<string, unknown>, includeUrl: string | undefined): CodexGeneratedServer {
  return {
    ...(includeUrl ? { url: includeUrl } : {}),
    ...(stringArray(config.enabled_tools) ? { enabled_tools: stringArray(config.enabled_tools) } : {}),
    ...(stringArray(config.disabled_tools) ? { disabled_tools: stringArray(config.disabled_tools) } : {}),
    ...(stringArray(config.scopes) ? { scopes: stringArray(config.scopes) } : {}),
    ...(boolValue(config.enabled) === undefined ? {} : { enabled: boolValue(config.enabled) }),
    ...(boolValue(config.oauth) === undefined ? {} : { oauth: boolValue(config.oauth) }),
    ...(boolValue(config.required) === undefined ? {} : { required: boolValue(config.required) }),
    ...(typeof config.oauth_resource === "string" ? { oauth_resource: config.oauth_resource } : {}),
    ...(numberValue(config.startup_timeout_sec) === undefined ? {} : { startup_timeout_sec: numberValue(config.startup_timeout_sec) }),
    ...(numberValue(config.tool_timeout_sec) === undefined ? {} : { tool_timeout_sec: numberValue(config.tool_timeout_sec) }),
  };
}

function hasOAuthConfig(server: NativeMcpServer): boolean {
  if (isRecord(server.config.oauth)) return true;
  if (typeof server.config.oauth === "boolean") return server.config.oauth;
  if (typeof server.config.oauth_resource === "string") return true;
  if (typeof server.config.authServerMetadataUrl === "string") return true;
  if (typeof server.config.mcp_oauth_callback_port === "number") return true;
  return false;
}

function httpsUrl(value: unknown): URL | undefined {
  if (typeof value !== "string") return undefined;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" ? parsed : undefined;
  } catch {
    return undefined;
  }
}

const OAUTH_METADATA_IP_REASON = "OAuth metadata URL must be a hostname, not an IP address";
const OAUTH_TOKEN_ENDPOINT_IP_REASON = "OAuth token endpoint must be a hostname, not an IP address";

// An OAuth URL host becomes an effective policy host, so it must be a name:
// WHATWG folds decimal and hex IPv4 forms first, and IPv6 keeps its brackets.
function ipLiteralUrlHost(parsed: URL): boolean {
  const bare = parsed.hostname.startsWith("[") ? parsed.hostname.slice(1, -1) : parsed.hostname;
  return isIpLiteralHostname(bare);
}

function oauthAuthServerMetadataUrl(config: Record<string, unknown>): McpRefusal | string | undefined {
  const candidates = [config.authServerMetadataUrl, isRecord(config.oauth) ? config.oauth.authServerMetadataUrl : undefined];
  for (const candidate of candidates) {
    const parsed = httpsUrl(candidate);
    if (parsed && ipLiteralUrlHost(parsed)) return { refused: OAUTH_METADATA_IP_REASON };
  }
  for (const candidate of candidates) {
    if (typeof candidate === "string" && httpsUrl(candidate)) return candidate;
  }
  return undefined;
}

function tokenEndpointFromConfigValue(value: unknown): McpRefusal | { host: string; path: string } | undefined {
  const parsed = httpsUrl(value);
  if (!parsed) return undefined;
  if (ipLiteralUrlHost(parsed)) return { refused: OAUTH_TOKEN_ENDPOINT_IP_REASON };
  let host: string;
  try {
    host = normalizeHostname(parsed.hostname);
  } catch (error) {
    return { refused: `OAuth token endpoint: ${error instanceof Error ? error.message : String(error)}` };
  }
  return { host, path: normalizePathPrefix(parsed.pathname || "/") };
}

function oauthTokenEndpoints(config: Record<string, unknown>): McpRefusal | Array<{ host: string; path: string }> {
  const endpoints: Array<{ host: string; path: string }> = [];
  const sources = [config, ...(isRecord(config.oauth) ? [config.oauth] : [])];
  for (const source of sources) {
    for (const key of ["tokenEndpoint", "token_endpoint", "tokenUrl", "token_url"]) {
      const endpoint = tokenEndpointFromConfigValue(source[key]);
      if (endpoint === undefined) continue;
      if ("refused" in endpoint) return endpoint;
      endpoints.push(endpoint);
    }
  }
  return Array.from(new Map(endpoints.map((endpoint) => [`${endpoint.host}\0${endpoint.path}`, endpoint])).values());
}

function oauthPolicyFor(config: Record<string, unknown>, parsed: { host: string; pathPrefix: string }): McpRefusal | McpOAuthServerPolicyJson {
  const authServerMetadataUrl = oauthAuthServerMetadataUrl(config);
  if (typeof authServerMetadataUrl === "object") return authServerMetadataUrl;
  const tokenEndpoints = oauthTokenEndpoints(config);
  if ("refused" in tokenEndpoints) return tokenEndpoints;
  return {
    resourceHost: parsed.host,
    resourcePathPrefix: parsed.pathPrefix,
    ...(authServerMetadataUrl ? { oauth: { authServerMetadataUrl } } : {}),
    ...(tokenEndpoints.length > 0 ? { tokenEndpoints } : {}),
  };
}

const SAFE_OAUTH_CONFIG_KEYS = new Set([
  "authServerMetadataUrl",
  "authorizationEndpoint",
  "authorization_endpoint",
  "clientId",
  "client_id",
  "issuer",
  "scope",
  "scopes",
  "tokenEndpoint",
  "tokenUrl",
  "token_endpoint",
  "token_url",
]);

function sanitizedOauthConfig(value: unknown): true | Record<string, unknown> | undefined {
  if (typeof value === "boolean") return value ? true : undefined;
  if (!isRecord(value)) return undefined;
  const sanitized: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (!SAFE_OAUTH_CONFIG_KEYS.has(key)) continue;
    if (typeof entry === "string" || typeof entry === "number" || typeof entry === "boolean") {
      sanitized[key] = entry;
      continue;
    }
    if (Array.isArray(entry) && entry.every((item) => typeof item === "string")) {
      sanitized[key] = entry;
    }
  }
  return Object.keys(sanitized).length > 0 ? sanitized : true;
}

type McpLogEvent = {
  kind: "imported" | "skipped";
  scope: string;
  agent: "claude" | "codex";
  name: string;
  detail: string;
};

type PrepareServerOptions = {
  allowProject?: boolean;
  // false: silent. A function collects events for the caller to render
  // (filtered to the launched agent and collapsed across agents). Otherwise
  // each event renders as a warning line at once.
  log?: boolean | ((event: McpLogEvent) => void);
};

function renderMcpLogEvent(event: McpLogEvent, agents: readonly string[] = [event.agent]): string {
  const who = agents.length === 1 ? `${agents[0]} server` : `server (${agents.join(", ")})`;
  return `mcp: ${event.kind} ${event.scope} ${who} ${event.name} ${event.detail}`;
}

function logMcp(options: PrepareServerOptions, event: McpLogEvent): void {
  if (options.log === false) return;
  if (typeof options.log === "function") {
    options.log(event);
    return;
  }
  warn(renderMcpLogEvent(event));
}

// The launch context for MCP log lines: `agent` filters import/skip lines to
// the launched agent (a `runfree claude` launch does not report Codex's
// servers); `verbose` gates the OAuth callback guidance. Set by the launch and
// `up` paths in this process before the effective controls are prepared.
let mcpLogContext: { agent?: "claude" | "codex"; verbose?: boolean } = {};

export function setMcpLogContext(context: { agent?: "claude" | "codex"; verbose?: boolean }): void {
  mcpLogContext = { ...context };
}

export function mcpLogContextForTest(): { agent?: "claude" | "codex"; verbose?: boolean } {
  return mcpLogContext;
}

function prepareHttpServer(server: NativeMcpServer, options: PrepareServerOptions = {}): PreparedMcpServer | McpRefusal | undefined {
  if (server.scope === "project" && !options.allowProject) return undefined;
  const url = typeof server.config.url === "string" ? server.config.url : "";
  const parsed = normalizeMcpUrl(url);
  if ("refused" in parsed) return parsed;
  if (hasOAuthConfig(server)) {
    const oauthPolicy = oauthPolicyFor(server.config, parsed);
    if ("refused" in oauthPolicy) return oauthPolicy;
    const oauthConfig = sanitizedOauthConfig(server.config.oauth);
    logMcp(options, { kind: "imported", scope: server.scope, agent: server.agent, name: server.name, detail: "transport=http auth=oauth" });
    return {
      agent: server.agent,
      auth: "oauth",
      name: server.name,
      source: server.scope,
      transport: "http",
      tokenBindings: [],
      endpoint: {
        host: parsed.host,
        path: parsed.pathPrefix,
      },
      oauthPolicy,
      claudeConfig: server.agent === "claude"
        ? {
          type: "http",
          url: parsed.url,
          ...(oauthConfig !== undefined ? { oauth: oauthConfig } : {}),
          ...(typeof server.config.authServerMetadataUrl === "string" ? { authServerMetadataUrl: server.config.authServerMetadataUrl } : {}),
        }
        : undefined,
      codexConfig: server.agent === "codex"
        ? {
          ...codexGeneratedOptions(server.config, parsed.url),
          oauth: true,
        }
        : undefined,
    };
  }

  const bindings: HeaderTokenBinding[] = [];
  if (server.agent === "codex") {
    const bearerEnv = typeof server.config.bearer_token_env_var === "string" ? server.config.bearer_token_env_var : undefined;
    if (bearerEnv) {
      if (!ENV_NAME_RE.test(bearerEnv)) {
        return { refused: "invalid bearer token env var" };
      }
      bindings.push(bindingFor(server.agent, server.name, parsed.host, parsed.pathPrefix, "Authorization", bearerEnv, "bearer"));
    }
    const envHeaders = stringRecord(server.config.env_http_headers);
    if (envHeaders) {
      for (const [header, envName] of Object.entries(envHeaders)) {
        if (!ENV_NAME_RE.test(envName)) {
          return { refused: "invalid env header source" };
        }
        bindings.push(bindingFor(server.agent, server.name, parsed.host, parsed.pathPrefix, header, envName, "raw"));
      }
    }
    if (isRecord(server.config.http_headers) && Object.keys(server.config.http_headers).length > 0) {
      const headers = stringRecord(server.config.http_headers);
      if (!headers) {
        return { refused: "invalid static HTTP headers" };
      }
      if (server.scope !== "project") {
        return { refused: "literal static HTTP headers require host-owned credential source reconfiguration" };
      }
      for (const [header, value] of Object.entries(headers)) {
        bindings.push(bindingFor(server.agent, server.name, parsed.host, parsed.pathPrefix, header, undefined, literalHeaderScheme(value)));
      }
    }
  } else {
    if (typeof server.config.headersHelper === "string") {
      return { refused: "headersHelper would execute a host command" };
    }
    const headers = stringRecord(server.config.headers);
    if (headers) {
      for (const [header, value] of Object.entries(headers)) {
        const reference = headerEnvReference(value);
        if (!reference) {
          if (server.scope !== "project") {
            return { refused: "literal static HTTP headers require host-owned credential source reconfiguration" };
          }
          bindings.push(bindingFor(server.agent, server.name, parsed.host, parsed.pathPrefix, header, undefined, literalHeaderScheme(value)));
          continue;
        }
        bindings.push(bindingFor(server.agent, server.name, parsed.host, parsed.pathPrefix, header, reference.env, reference.scheme));
      }
    }
  }

  const auth = bindings.length === 0 ? "public" : "static";
  const publicOauthPolicy = auth === "public" ? oauthPolicyFor(server.config, parsed) : undefined;
  if (publicOauthPolicy !== undefined && "refused" in publicOauthPolicy) return publicOauthPolicy;
  logMcp(options, { kind: "imported", scope: server.scope, agent: server.agent, name: server.name, detail: `transport=http auth=${auth}` });
  return {
    agent: server.agent,
    auth,
    name: server.name,
    source: server.scope,
    transport: "http",
    tokenBindings: bindings,
    endpoint: {
      host: parsed.host,
      path: parsed.pathPrefix,
    },
    // Public remote HTTP MCP servers commonly advertise OAuth dynamically at
    // runtime (HTTP 401 + WWW-Authenticate), so register the resource binding
    // for the proxy mediator and start the callback bridge. This adds no egress:
    // only the already-allowlisted resource host is recorded, and the proxy
    // mediates tokens lazily behind the firewall. Static-header servers carry a
    // credential and never run OAuth, so they get no resource binding.
    ...(publicOauthPolicy ? { oauthPolicy: publicOauthPolicy } : {}),
    claudeConfig: server.agent === "claude" ? { type: "http", url: parsed.url } : undefined,
    codexConfig: server.agent === "codex" ? codexGeneratedOptions(server.config, parsed.url) : undefined,
  };
}

// L2: credential and OAuth keys of either agent. Loopback traffic never
// passes the proxy, so a credential would have to live in the agent config.
const LOOPBACK_CREDENTIAL_KEYS = new Set([
  "authServerMetadataUrl",
  "bearer_token_env_var",
  "env_http_headers",
  "headers",
  "headersHelper",
  "http_headers",
  "http_headers_helper",
  "mcp_oauth_callback_port",
  "oauth",
  "oauth_resource",
  "scopes",
]);

// S3: the only keys a loopback entry may carry, per agent.
const LOOPBACK_ALLOWED_KEYS: Record<McpAgent, ReadonlySet<string>> = {
  claude: new Set(["type", "url"]),
  codex: new Set(["url", "enabled", "required", "enabled_tools", "disabled_tools", "startup_timeout_sec", "tool_timeout_sec"]),
};

function pickCodexLoopbackOptions(config: Record<string, unknown>): CodexGeneratedServer {
  return {
    ...(stringArray(config.enabled_tools) ? { enabled_tools: stringArray(config.enabled_tools) } : {}),
    ...(stringArray(config.disabled_tools) ? { disabled_tools: stringArray(config.disabled_tools) } : {}),
    ...(boolValue(config.enabled) === undefined ? {} : { enabled: boolValue(config.enabled) }),
    ...(boolValue(config.required) === undefined ? {} : { required: boolValue(config.required) }),
    ...(numberValue(config.startup_timeout_sec) === undefined ? {} : { startup_timeout_sec: numberValue(config.startup_timeout_sec) }),
    ...(numberValue(config.tool_timeout_sec) === undefined ? {} : { tool_timeout_sec: numberValue(config.tool_timeout_sec) }),
  };
}

// F7: the type each allowlisted Codex option must have. A wrongly typed option
// is refused, never dropped: a dropped `enabled_tools` would widen the tool set
// to every tool the server offers. Loopback only; HTTPS keeps
// `codexGeneratedOptions`, which drops it.
const LOOPBACK_CODEX_OPTION_TYPES: Record<string, { expected: string; valid: (value: unknown) => boolean }> = {
  enabled: { expected: "a boolean", valid: (value) => typeof value === "boolean" },
  required: { expected: "a boolean", valid: (value) => typeof value === "boolean" },
  enabled_tools: { expected: "an array of strings", valid: (value) => stringArray(value) !== undefined },
  disabled_tools: { expected: "an array of strings", valid: (value) => stringArray(value) !== undefined },
  startup_timeout_sec: { expected: "a finite number of at least 0", valid: (value) => (numberValue(value) ?? -1) >= 0 },
  tool_timeout_sec: { expected: "a finite number of at least 0", valid: (value) => (numberValue(value) ?? -1) >= 0 },
};

function loopbackKeyRefusal(server: NativeMcpServer): McpRefusal | undefined {
  const keys = Object.keys(server.config);
  if (hasOAuthConfig(server) || keys.some((key) => LOOPBACK_CREDENTIAL_KEYS.has(key))) {
    return { refused: LOOPBACK_REASONS.credentials };
  }
  const unknown = keys.find((key) => !LOOPBACK_ALLOWED_KEYS[server.agent].has(key));
  if (unknown !== undefined) return { refused: LOOPBACK_REASONS.key(printable(unknown)) };
  if (server.agent !== "codex") return undefined;
  for (const key of keys) {
    const type = LOOPBACK_CODEX_OPTION_TYPES[key];
    if (type && !type.valid(server.config[key])) return { refused: LOOPBACK_REASONS.keyType(key, type.expected) };
  }
  return undefined;
}

// An `http-loopback` server: auth `none`, no endpoint, no OAuth policy, no
// token bindings, so it projects nothing into any proxy policy (B1). Its
// config carries the normalized `href`, so the approved digest and the running
// config name the same target (S4).
function prepareLoopbackHttpServer(server: NativeMcpServer, options: PrepareServerOptions = {}): PreparedMcpServer | McpRefusal | undefined {
  if (server.scope === "project" && !options.allowProject) return undefined;
  const raw = typeof server.config.url === "string" ? server.config.url : "";
  const parsed = loopbackUrl(raw);
  if (!parsed) return { refused: "invalid URL" };
  if (raw.includes("$")) return { refused: LOOPBACK_REASONS.dollar };
  if (parsed.username !== "" || parsed.password !== "") return { refused: LOOPBACK_REASONS.userinfo };
  if (parsed.hash !== "" || parsed.href.endsWith("#")) return { refused: LOOPBACK_REASONS.fragment };
  const port = parsed.port === "" ? 80 : Number(parsed.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { refused: LOOPBACK_REASONS.portZero };
  const reserved = refusedHostServicePortReason(port);
  if (reserved !== undefined) return { refused: LOOPBACK_REASONS.reserved(port, reserved) };
  if (server.agent === "claude" && server.config.type !== undefined && server.config.type !== "http") {
    return { refused: LOOPBACK_REASONS.claudeType(printable(String(server.config.type))) };
  }
  const keyRefusal = loopbackKeyRefusal(server);
  if (keyRefusal) return keyRefusal;
  logMcp(options, { kind: "imported", scope: server.scope, agent: server.agent, name: server.name, detail: "transport=http-loopback auth=none" });
  return {
    agent: server.agent,
    auth: "none",
    name: server.name,
    source: server.scope,
    transport: "http-loopback",
    tokenBindings: [],
    loopbackPort: port,
    claudeConfig: server.agent === "claude" ? { type: "http", url: parsed.href } : undefined,
    codexConfig: server.agent === "codex" ? { url: parsed.href, ...pickCodexLoopbackOptions(server.config) } : undefined,
  };
}

function looksLikeHostPath(value: string, projectRoot: string): boolean {
  if (value.startsWith(projectRoot)) return true;
  if (/^\/(?:Users|Volumes|private|var\/folders)\//.test(value)) return true;
  if (/^[A-Za-z]:\\/.test(value)) return true;
  if (value.startsWith("file://")) return true;
  return false;
}

function containerLocalStdioRefusal(server: NativeMcpServer, projectRoot: string): McpRefusal | undefined {
  const command = typeof server.config.command === "string" ? server.config.command : "";
  if (command.trim() === "" || command.includes("/") || command.includes("\\") || path.isAbsolute(command)) {
    return { refused: "local stdio command must be installed in the container PATH" };
  }
  const args = stringArray(server.config.args) ?? [];
  for (const arg of args) {
    if (looksLikeHostPath(arg, projectRoot)) {
      return { refused: "local stdio args contain a host path" };
    }
  }
  const cwd = typeof server.config.cwd === "string" ? server.config.cwd : undefined;
  if (cwd && looksLikeHostPath(cwd, projectRoot)) {
    return { refused: "local stdio cwd is a host path" };
  }
  return undefined;
}

function prepareStdioServer(server: NativeMcpServer, projectRoot: string, options: PrepareServerOptions = {}): PreparedMcpServer | McpRefusal | undefined {
  if (server.scope === "project" && !options.allowProject) return undefined;
  const refusal = containerLocalStdioRefusal(server, projectRoot);
  if (refusal) return refusal;
  const command = server.config.command as string;
  const args = stringArray(server.config.args);
  const env = stringRecord(server.config.env);
  if (env && Object.keys(env).length > 0) {
    return { refused: "local stdio env would expose host config values to the agent" };
  }
  const cwd = typeof server.config.cwd === "string" ? server.config.cwd : undefined;
  logMcp(options, { kind: "imported", scope: server.scope, agent: server.agent, name: server.name, detail: "transport=stdio auth=none" });
  return {
    agent: server.agent,
    auth: "none",
    name: server.name,
    source: server.scope,
    transport: "stdio",
    tokenBindings: [],
    claudeConfig: server.agent === "claude"
      ? {
        type: "stdio",
        command,
        ...(args ? { args } : {}),
      }
      : undefined,
    codexConfig: server.agent === "codex"
      ? {
        ...codexGeneratedOptions(server.config, undefined),
        command,
        ...(args ? { args } : {}),
        ...(cwd ? { cwd } : {}),
      }
      : undefined,
  };
}

function isDesktopBuiltIn(server: NativeMcpServer): boolean {
  return nativeTransport(server) === "stdio" && isCodexDesktopBuiltIn({ agent: server.agent, name: server.name, config: server.config });
}

function prepareServer(server: NativeMcpServer, projectRoot: string, options: PrepareServerOptions = {}): PreparedMcpServer | McpRefusal | undefined {
  const transport = nativeTransport(server);
  if (transport === "http-loopback") return prepareLoopbackHttpServer(server, options);
  if (transport === "http") return prepareHttpServer(server, options);
  if (transport === "stdio") {
    // A Codex Desktop built-in is skipped before the generic STDIO rules, so
    // it neither warns nor reaches the generated config.
    if (isDesktopBuiltIn(server)) return undefined;
    return prepareStdioServer(server, projectRoot, options);
  }
  if (server.scope !== "project") logMcp(options, { kind: "skipped", scope: server.scope, agent: server.agent, name: server.name, detail: "reason=unsupported MCP transport" });
  return undefined;
}

export function discoverMcpServers(projectRoot: string, env: NodeJS.ProcessEnv): NativeMcpServer[] {
  return [
    ...collectClaudeServers(projectRoot, env),
    ...collectCodexServers(projectRoot, env),
  ];
}

export function mcpApprovalPath(stateDir: string): string {
  return path.join(stateDir, MCP_APPROVAL_FILE);
}

export function mcpRulesPath(stateDir: string): string {
  return path.join(stateDir, MCP_RULES_FILE);
}

function emptyMcpApprovals(projectRoot: string): McpApprovalFile {
  return {
    approvals: {},
    projectHash: projectHash(projectRoot),
    schemaVersion: 1,
  };
}

function isMcpApprovalRecord(value: unknown): value is McpApprovalRecord {
  if (!isRecord(value)) return false;
  return value.schemaVersion === 1
    && value.source === "project"
    && isMcpAgentId(typeof value.agent === "string" ? value.agent : undefined)
    && typeof value.approvedAt === "string"
    && typeof value.digest === "string"
    && typeof value.server === "string"
    && typeof value.summary === "string"
    && (value.auth === "public" || value.auth === "static" || value.auth === "oauth" || value.auth === "none")
    && (value.transport === "http" || value.transport === "http-loopback" || value.transport === "stdio");
}

export function readMcpApprovals(projectRoot: string, filePath?: string): McpApprovalFile {
  const empty = emptyMcpApprovals(projectRoot);
  if (!filePath) return empty;
  if (isPathInsideByRealpath(projectRoot, filePath)) {
    warn("mcp: ignored project-controlled approval file; MCP approvals must live outside the project");
    return empty;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, "utf8")) as unknown;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return empty;
    warn(`mcp: ignored malformed approval file ${filePath}: ${printable(error instanceof Error ? error.message : String(error))}`);
    return empty;
  }
  if (!isRecord(parsed) || parsed.schemaVersion !== 1 || parsed.projectHash !== projectHash(projectRoot) || !isRecord(parsed.approvals)) {
    return empty;
  }
  const approvals: Record<string, McpApprovalRecord> = {};
  for (const [key, record] of Object.entries(parsed.approvals)) {
    if (isMcpApprovalRecord(record)) approvals[key] = record;
  }
  return {
    approvals,
    projectHash: projectHash(projectRoot),
    schemaVersion: 1,
  };
}

function writeMcpApprovals(projectRoot: string, filePath: string, approvals: McpApprovalFile): void {
  if (isPathInsideByRealpath(projectRoot, filePath)) {
    throw new Error("MCP approval file must be outside the project");
  }
  atomicReplaceFile(filePath, `${JSON.stringify(approvals, null, 2)}\n`, 0o600);
}

function emptyMcpRules(projectRoot: string): McpRulesFile {
  return {
    projectHash: projectHash(projectRoot),
    rules: {},
    schemaVersion: 1,
  };
}

function isMcpWriteAction(value: unknown): value is McpWriteAction {
  return value === "allow" || value === "ask" || value === "deny";
}

function isMcpToolPolicy(value: unknown): value is McpToolOperationPolicyJson {
  return isRecord(value) && isMcpWriteAction(value.writeAction);
}

function isMcpRuleRecord(value: unknown): value is McpRuleRecord {
  if (!isRecord(value)) return false;
  if (value.schemaVersion !== 1) return false;
  if (value.agent !== "claude" && value.agent !== "codex") return false;
  if (value.source !== "user" && value.source !== "local" && value.source !== "project") return false;
  if (typeof value.server !== "string" || value.server === "") return false;
  if (typeof value.identity !== "string" || value.identity === "") return false;
  if (typeof value.updatedAt !== "string") return false;
  if (value.defaultToolWriteAction !== undefined && !isMcpWriteAction(value.defaultToolWriteAction)) return false;
  if (value.tools !== undefined) {
    if (!isRecord(value.tools)) return false;
    for (const [tool, policy] of Object.entries(value.tools)) {
      if (tool === "" || !isMcpToolPolicy(policy)) return false;
    }
  }
  return true;
}

export function readMcpRules(projectRoot: string, filePath?: string): McpRulesFile {
  const empty = emptyMcpRules(projectRoot);
  if (!filePath) return empty;
  if (isPathInsideByRealpath(projectRoot, filePath)) {
    warn("mcp: ignored project-controlled rules file; MCP rules must live outside the project");
    return empty;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, "utf8")) as unknown;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return empty;
    warn(`mcp: ignored malformed rules file ${filePath}: ${printable(error instanceof Error ? error.message : String(error))}`);
    return empty;
  }
  if (!isRecord(parsed) || parsed.schemaVersion !== 1 || parsed.projectHash !== projectHash(projectRoot) || !isRecord(parsed.rules)) {
    return empty;
  }
  const rules: Record<string, McpRuleRecord> = {};
  for (const [key, record] of Object.entries(parsed.rules)) {
    if (isMcpRuleRecord(record)) rules[key] = record;
  }
  return {
    projectHash: projectHash(projectRoot),
    rules,
    schemaVersion: 1,
  };
}

export function writeMcpRules(projectRoot: string, filePath: string, rules: McpRulesFile): void {
  if (isPathInsideByRealpath(projectRoot, filePath)) {
    throw new Error("MCP rules file must be outside the project");
  }
  atomicReplaceFile(filePath, `${JSON.stringify(rules, null, 2)}\n`, 0o600);
}

function approvalKey(agent: McpAgent, serverName: string, digest: string): string {
  return `${agent}:${encodeURIComponent(serverName)}:${digest}`;
}

function approvalFor(approvals: McpApprovalFile, agent: McpAgent, serverName: string, digest: string): McpApprovalRecord | undefined {
  return approvals.approvals[approvalKey(agent, serverName, digest)];
}

function hasApprovalForServer(approvals: McpApprovalFile, agent: McpAgent, serverName: string): boolean {
  return Object.values(approvals.approvals).some((approval) => approval.agent === agent && approval.server === serverName);
}

function mcpDescriptor(projectRoot: string, server: NativeMcpServer, prepared: PreparedMcpServer): Record<string, unknown> {
  const tokenBindings = prepared.tokenBindings
    .map((binding) => ({
      credential: binding.credential,
      tokenName: binding.tokenName,
    }))
    .sort((left, right) => `${left.credential.host}\0${left.credential.header}\0${left.tokenName}`.localeCompare(`${right.credential.host}\0${right.credential.header}\0${right.tokenName}`));
  return {
    schemaVersion: 1,
    projectHash: projectHash(projectRoot),
    agent: server.agent,
    source: server.scope,
    server: server.name,
    transport: prepared.transport,
    auth: prepared.auth,
    ...(prepared.claudeConfig ? { claudeConfig: prepared.claudeConfig } : {}),
    ...(prepared.codexConfig ? { codexConfig: prepared.codexConfig } : {}),
    ...(prepared.oauthPolicy ? { oauthPolicy: prepared.oauthPolicy } : {}),
    ...(tokenBindings.length > 0 ? { tokenBindings } : {}),
  };
}

function descriptorDigest(projectRoot: string, server: NativeMcpServer, prepared: PreparedMcpServer): string {
  return sha256Hex(canonicalJson(mcpDescriptor(projectRoot, server, prepared)));
}

function mcpRuleKey(input: {
  agent: McpAgent;
  descriptorDigest?: string;
  endpoint?: { host: string; path: string };
  server: string;
  source: McpSourceScope;
}): string | undefined {
  const serverName = encodeURIComponent(input.server);
  if (input.source === "project") {
    if (!input.descriptorDigest) return undefined;
    return `project:${input.agent}:${serverName}:${input.descriptorDigest}`;
  }
  if (!input.endpoint) return undefined;
  const endpointHash = sha256Hex(`${input.endpoint.host}\n${input.endpoint.path}`);
  return `configured:${input.agent}:${input.source}:${serverName}:${endpointHash}`;
}

export function mcpRuleKeyForEntry(entry: Pick<McpInventoryEntry, "agent" | "descriptorDigest" | "endpoint" | "name" | "source">): string | undefined {
  return mcpRuleKey({
    agent: entry.agent,
    descriptorDigest: entry.descriptorDigest,
    endpoint: entry.endpoint,
    server: entry.name,
    source: entry.source,
  });
}

export function saveMcpApproval(projectRoot: string, filePath: string, entry: McpInventoryEntry): McpApprovalRecord {
  if (entry.source !== "project") throw new Error("only project MCP entries can be approved");
  if (!entry.descriptorDigest) throw new Error("unsupported project MCP entry cannot be approved");
  if (entry.auth === "unknown" || entry.transport === "unknown") throw new Error("unsupported project MCP entry cannot be approved");
  const approvals = readMcpApprovals(projectRoot, filePath);
  for (const [key, approval] of Object.entries(approvals.approvals)) {
    if (approval.agent === entry.agent && approval.server === entry.name) delete approvals.approvals[key];
  }
  const record: McpApprovalRecord = {
    agent: entry.agent,
    approvedAt: new Date().toISOString(),
    auth: entry.auth,
    digest: entry.descriptorDigest,
    schemaVersion: 1,
    server: entry.name,
    source: "project",
    summary: `${entry.agent} ${entry.name} ${entry.transport}/${entry.auth}`,
    transport: entry.transport,
  };
  approvals.approvals[approvalKey(entry.agent, entry.name, entry.descriptorDigest)] = record;
  writeMcpApprovals(projectRoot, filePath, approvals);
  return record;
}

export function revokeMcpApproval(projectRoot: string, filePath: string, agent: McpAgent, serverName: string): { changed: boolean; remainingTokenNames: string[] } {
  const approvals = readMcpApprovals(projectRoot, filePath);
  let changed = false;
  for (const [key, approval] of Object.entries(approvals.approvals)) {
    if (approval.agent === agent && approval.server === serverName) {
      delete approvals.approvals[key];
      changed = true;
    }
  }
  if (changed) writeMcpApprovals(projectRoot, filePath, approvals);
  return { changed, remainingTokenNames: [] };
}

function mcpPolicySummary(rule: McpRuleRecord | undefined): string {
  const defaultAction = rule?.defaultToolWriteAction ?? "ask";
  const tools = Object.keys(rule?.tools ?? {}).length;
  return tools > 0 ? `tools=${defaultAction} (${tools} overrides)` : `tools=${defaultAction}`;
}

type McpNameRefusal = { status: "unsupported" | "conflict"; reason: string };

// Name checks, run before anything derives an ID or a key from a name. Two
// different names that map to one OAuth provider ID or one MCP operation
// server ID would make the generated policy invalid, so every entry of such a
// group is skipped. When user or local servers hold one name of the group,
// they keep it and the colliding project entries are the ones skipped, as for
// an exact-name conflict: project config cannot take a configured server away.
function mcpNameRefusals(servers: NativeMcpServer[]): Map<NativeMcpServer, McpNameRefusal> {
  const refusals = new Map<NativeMcpServer, McpNameRefusal>();
  const groups = new Map<string, NativeMcpServer[]>();
  for (const server of servers) {
    const reason = mcpServerNameRefusal(server.agent, server.name);
    if (reason) {
      refusals.set(server, { status: "unsupported", reason });
      continue;
    }
    if (isDesktopBuiltIn(server)) continue;
    const ids = [
      `oauth\0${mcpOAuthProviderId(server.agent, server.name)}`,
      `operation\0${mcpOperationServerId({ agent: server.agent, name: server.name, source: server.scope })}`,
    ];
    for (const id of ids) groups.set(id, [...(groups.get(id) ?? []), server]);
  }
  for (const group of groups.values()) {
    const names = new Set(group.map((server) => server.name));
    if (names.size < 2) continue;
    const importedNames = new Set(group.filter((server) => server.scope !== "project").map((server) => server.name));
    for (const server of group) {
      if (refusals.has(server)) continue;
      const others = [...names].filter((name) => name !== server.name).map(printable).join(", ");
      if (importedNames.size === 1) {
        // The imported name stays; an exact-name project entry is a conflict later.
        if (importedNames.has(server.name)) continue;
        refusals.set(server, { status: "conflict", reason: `server name collides with imported MCP server ${others}` });
      } else {
        refusals.set(server, { status: "unsupported", reason: `server name collides with MCP server ${others}` });
      }
    }
  }
  for (const [server, refusal] of refusals) {
    warn(`mcp: skipped ${server.agent} server ${printable(server.name)} reason=${refusal.reason}`);
  }
  return refusals;
}

function loopbackConfigUrl(prepared: PreparedMcpServer): string {
  const url = prepared.claudeConfig?.url ?? prepared.codexConfig?.url;
  if (typeof url !== "string") throw new Error(`loopback MCP server ${prepared.name} has no URL`);
  return url;
}

type McpInventoryOptions = {
  approvalPath?: string;
  env: NodeJS.ProcessEnv;
  // The selected effective policy's host services. When given, loopback
  // entries carry `loopback.reach`; when absent, no `reach` key.
  hostServices?: HostServicesJson;
  projectRoot: string;
  rulesPath?: string;
};

// L5: reach is shown, never granted. A loopback port is reached on the host
// only when the selected effective policy already has a host service on it;
// otherwise the server works only if a process in the session listens there.
export type McpLoopbackReach =
  | { kind: "host-service"; name: string; port: number }
  | { kind: "container-local"; port: number };

// What an admin surface shows: the reach, or `unknown` with the reason when
// the selected effective policy generation cannot be read. Never a fallback to
// container-local.
export type McpLoopbackShownReach = McpLoopbackReach | { kind: "unknown"; port: number; reason: string };

export function mcpLoopbackReach(port: number, hostServices: HostServicesJson): McpLoopbackReach {
  const match = Object.entries(hostServices).find(([, service]) => service.port === port);
  return match ? { kind: "host-service", name: match[0], port } : { kind: "container-local", port };
}

// The host-service name suggested for a container-local loopback server: the
// server name when it is a valid host-service name that no host service on
// another port already uses (so the printed `host-service add` can run), else
// `mcp-<port>`.
export function loopbackHostServiceName(serverName: string, port: number, hostServices: HostServicesJson): string {
  const taken = Object.hasOwn(hostServices, serverName) && hostServices[serverName].port !== port;
  return HOST_SERVICE_NAME_RE.test(serverName) && !taken ? serverName : `mcp-${port}`;
}

function mcpInventoryRecords(options: McpInventoryOptions): McpInventoryRecord[] {
  const approvals = readMcpApprovals(options.projectRoot, options.approvalPath);
  const rules = readMcpRules(options.projectRoot, options.rulesPath);
  const importedByName = new Map<string, McpSourceScope>();
  const servers = discoverMcpServers(options.projectRoot, options.env);
  const refusals = mcpNameRefusals(servers);
  return servers.map((server): McpInventoryRecord => {
    const transport = nativeTransport(server) ?? "unknown";
    const refusal = refusals.get(server);
    if (refusal) {
      return {
        agent: server.agent,
        auth: "unknown",
        decision: refusal,
        name: server.name,
        server,
        source: server.scope,
        ...(server.sourcePath ? { sourcePath: server.sourcePath } : {}),
        target: "excluded",
        transport,
      };
    }
    const desktopBuiltIn = isDesktopBuiltIn(server);
    const outcome = prepareServer(server, options.projectRoot, { allowProject: true, log: false });
    const refused = isMcpRefusal(outcome) ? outcome.refused : undefined;
    if (refused !== undefined) warn(`mcp: skipped ${server.agent} server ${printable(server.name)} reason=${printable(refused)}`);
    const prepared = isMcpRefusal(outcome) ? undefined : outcome;
    const supported = prepared !== undefined;
    const digest = prepared ? descriptorDigest(options.projectRoot, server, prepared) : undefined;
    const descriptor = prepared ? mcpDescriptor(options.projectRoot, server, prepared) : undefined;
    if (prepared && digest) prepared.descriptorDigest = digest;
    const nameKey = `${server.agent}:${server.name}`;
    let status: McpDecisionStatus;
    let reason: string | undefined;
    let approval: McpApprovalRecord | undefined;
    if (desktopBuiltIn) {
      status = "skipped";
      reason = CODEX_DESKTOP_BUILTIN_REASON;
    } else if (refused !== undefined) {
      status = "unsupported";
      reason = refused;
    } else if (!supported) {
      status = "unsupported";
      reason = "unsupported MCP transport or unsafe MCP configuration";
    } else if (server.scope !== "project") {
      status = "imported";
      importedByName.set(nameKey, server.scope);
    } else if (importedByName.has(nameKey)) {
      const winner = importedByName.get(nameKey);
      status = "conflict";
      reason = `conflicts with an imported ${winner} MCP server`;
    } else {
      approval = approvalFor(approvals, server.agent, server.name, digest as string);
      if (approval) {
        status = "approved";
      } else if (hasApprovalForServer(approvals, server.agent, server.name)) {
        status = "changed";
        reason = "approval changed";
      } else {
        status = "unapproved";
        reason = "project MCP requires approval";
      }
    }
    const ruleKey = prepared
      ? mcpRuleKey({
        agent: server.agent,
        descriptorDigest: digest,
        endpoint: prepared.endpoint,
        server: server.name,
        source: server.scope,
      })
      : undefined;
    const rule = ruleKey ? rules.rules[ruleKey] : undefined;
    const operationServerId = prepared?.endpoint ? mcpOperationServerId(prepared) : undefined;
    return {
      agent: server.agent,
      auth: prepared?.auth ?? "unknown",
      ...(descriptor ? { descriptor } : {}),
      ...(digest ? { descriptorDigest: digest } : {}),
      decision: {
        status,
        ...(reason ? { reason } : {}),
      },
      ...(prepared?.endpoint ? { endpoint: prepared.endpoint } : {}),
      ...(prepared?.transport === "http-loopback" && prepared.loopbackPort !== undefined
        ? {
          loopback: {
            url: loopbackConfigUrl(prepared),
            port: prepared.loopbackPort,
            ...(options.hostServices ? { reach: mcpLoopbackReach(prepared.loopbackPort, options.hostServices) } : {}),
          },
        }
        : {}),
      ...(operationServerId
        ? {
          mcpPolicy: {
            ...(rule?.defaultToolWriteAction !== undefined ? { defaultToolWriteAction: rule.defaultToolWriteAction } : {}),
            operationServerId,
            summary: mcpPolicySummary(rule),
            tools: rule?.tools ?? {},
          },
        }
        : {}),
      name: server.name,
      prepared,
      server,
      source: server.scope,
      ...(server.sourcePath ? { sourcePath: server.sourcePath } : {}),
      target: desktopBuiltIn || status === "unsupported" || (server.scope === "project" && status !== "approved") ? "excluded" : "generated",
      ...(prepared && prepared.tokenBindings.length > 0 ? { tokenBindings: prepared.tokenBindings } : {}),
      transport,
    };
  });
}

export function mcpInventory(options: McpInventoryOptions): McpInventory {
  const entries = mcpInventoryRecords(options).map((record): McpInventoryEntry => {
    const {
      prepared: _prepared,
      server: _server,
      ...entry
    } = record;
    return entry;
  });
  return { entries };
}

function loadClaudeRuntimeConfig(filePath: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8")) as unknown;
    return isRecord(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function writeHostMountFile(filePath: string, contents: string): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filePath, contents, { mode: 0o644 });
  fs.chmodSync(filePath, 0o644);
}

export function ensureClaudeMcpConfigFile(filePath: string): void {
  if (fs.existsSync(filePath)) return;
  writeHostMountFile(filePath, `${JSON.stringify({ mcpServers: {} }, null, 2)}\n`);
}

function writeClaudeRuntimeConfig(
  filePath: string,
  mcpConfigPath: string,
  servers: PreparedMcpServer[],
): void {
  const current = loadClaudeRuntimeConfig(filePath);
  const mcpServers: Record<string, unknown> = {};
  for (const server of servers) {
    if (server.agent !== "claude" || !server.claudeConfig) continue;
    // No `oauth.callbackPort` (session MCP OAuth callback decisions,
    // 2026-09-30): each eligible session owns its callback port, which the
    // session's `claude` adapter exports as MCP_OAUTH_CALLBACK_PORT. The pinned
    // Claude Code prefers a configured `oauth.callbackPort` over that variable,
    // so one here would send every session's login to a single port only one
    // session can own. Import already drops a source-configured callbackPort
    // (it is not a safe OAuth key), so the prepared config carries none.
    mcpServers[server.name] = server.claudeConfig;
  }
  writeHostMountFile(mcpConfigPath, `${JSON.stringify({ mcpServers }, null, 2)}\n`);

  if (current.mcpServers === undefined) return;
  const { mcpServers: _mcpServers, ...next } = current;
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filePath, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
}

function tomlString(value: string): string {
  return JSON.stringify(value);
}

function tomlArray(values: string[]): string {
  return `[${values.map(tomlString).join(", ")}]`;
}

function tomlKey(value: string): string {
  return /^[A-Za-z0-9_-]+$/.test(value) ? value : tomlString(value);
}

function renderCodexServer(name: string, server: CodexGeneratedServer): string {
  const serverKey = tomlKey(name);
  const lines = [`[mcp_servers.${serverKey}]`];
  if (server.url) lines.push(`url = ${tomlString(server.url)}`);
  if (server.command) lines.push(`command = ${tomlString(server.command)}`);
  if (server.args) lines.push(`args = ${tomlArray(server.args)}`);
  if (server.cwd) lines.push(`cwd = ${tomlString(server.cwd)}`);
  if (server.enabled_tools) lines.push(`enabled_tools = ${tomlArray(server.enabled_tools)}`);
  if (server.disabled_tools) lines.push(`disabled_tools = ${tomlArray(server.disabled_tools)}`);
  if (server.scopes) lines.push(`scopes = ${tomlArray(server.scopes)}`);
  if (server.enabled !== undefined) lines.push(`enabled = ${server.enabled ? "true" : "false"}`);
  if (server.oauth !== undefined) lines.push(`oauth = ${server.oauth ? "true" : "false"}`);
  if (server.oauth_resource) lines.push(`oauth_resource = ${tomlString(server.oauth_resource)}`);
  if (server.required !== undefined) lines.push(`required = ${server.required ? "true" : "false"}`);
  if (server.startup_timeout_sec !== undefined) lines.push(`startup_timeout_sec = ${server.startup_timeout_sec}`);
  if (server.tool_timeout_sec !== undefined) lines.push(`tool_timeout_sec = ${server.tool_timeout_sec}`);
  if (server.env && Object.keys(server.env).length > 0) {
    lines.push(`[mcp_servers.${serverKey}.env]`);
    for (const [key, value] of Object.entries(server.env).sort(([left], [right]) => left.localeCompare(right))) {
      lines.push(`${tomlKey(key)} = ${tomlString(value)}`);
    }
  }
  return lines.join("\n");
}

function firstTomlTableIndex(source: string): number {
  const match = /^[ \t]*\[\[?[^\]\r\n]+\]\]?[ \t]*(?:#.*)?$/m.exec(source);
  return match?.index ?? -1;
}

function stripGeneratedCodexBlock(current: string): string {
  const lines = current.split(/\r?\n/);
  const output: string[] = [];
  let insideGeneratedBlock = false;
  let removedBlock = false;

  for (const line of lines) {
    const marker = line.trim();
    if (!insideGeneratedBlock && marker === GENERATED_CODEX_BEGIN) {
      insideGeneratedBlock = true;
      removedBlock = true;
      continue;
    }
    if (insideGeneratedBlock) {
      if (marker === GENERATED_CODEX_END) insideGeneratedBlock = false;
      continue;
    }
    output.push(line);
  }

  return removedBlock && !insideGeneratedBlock ? output.join("\n") : current;
}

function replaceGeneratedCodexBlock(current: string, block: string): string {
  const stripped = stripGeneratedCodexBlock(current).trimEnd();
  if (block === "") return stripped === "" ? "" : `${stripped}\n`;
  const generated = `${GENERATED_CODEX_BEGIN}\n${block}\n${GENERATED_CODEX_END}`;
  if (stripped === "") return `${generated}\n`;
  const tableIndex = firstTomlTableIndex(stripped);
  if (tableIndex < 0) return `${stripped}\n\n${generated}\n`;
  const beforeTables = stripped.slice(0, tableIndex).trimEnd();
  const fromFirstTable = stripped.slice(tableIndex).trimStart();
  return `${[
    beforeTables,
    generated,
    fromFirstTable,
  ].filter(Boolean).join("\n\n")}\n`;
}

function writeCodexRuntimeConfig(codexDir: string, servers: PreparedMcpServer[]): void {
  const codexServers = servers.filter((server) => server.agent === "codex" && server.codexConfig);
  // No callback settings (session MCP OAuth callback decisions, 2026-09-30).
  // The session's `codex` adapter supplies the session's own port
  // (`-c mcp_oauth_callback_port=<port>`). A shared fallback port here would
  // send a login run outside the adapter to a port another session — or,
  // with a colliding project hash, another project — owns; without one, such
  // a login listens on an unforwarded ephemeral port and fails closed. No
  // `mcp_oauth_callback_url` either: the pinned Codex advertises that URL's
  // port while it listens on the override.
  // A loopback server has auth "none", so it never asks for a callback.
  const hasCodexCallback = codexServers.some(
    (server) => (server.auth === "oauth" || server.auth === "public") && typeof server.codexConfig?.url === "string",
  );
  const block = codexServers
    .map((server) => renderCodexServer(server.name, server.codexConfig as CodexGeneratedServer))
    .join("\n\n");
  updateCodexConfig(codexDir, (current) => {
    if (hasCodexCallback) warnOnOperatorCodexCallbackUrl(stripGeneratedCodexBlock(current ?? ""));
    return replaceGeneratedCodexBlock(current ?? "", block);
  });
}

/**
 * Names an operator-written top-level `mcp_oauth_callback_url`, which Runfree
 * preserves but cannot serve: Codex would advertise that URL's port instead of
 * the session's forwarded one, so the login could not return.
 */
function warnOnOperatorCodexCallbackUrl(operatorConfig: string): void {
  const tableIndex = firstTomlTableIndex(operatorConfig);
  const topLevel = tableIndex < 0 ? operatorConfig : operatorConfig.slice(0, tableIndex);
  if (!/^[ \t]*mcp_oauth_callback_url[ \t]*=/m.test(topLevel)) return;
  warn("mcp: the Codex config sets mcp_oauth_callback_url; Runfree forwards only the session's own callback port, "
    + "so Codex MCP OAuth logins in this project cannot complete until that setting is removed");
}

function ensureDomain(policy: PolicyJson, host: string): void {
  policy.hosts ??= [];
  if (!policy.hosts.includes(host)) {
    policy.hosts.push(host);
    policy.hosts.sort((left, right) => left.localeCompare(right));
  }
}

function credentialOwner(policy: PolicyJson, credential: CredentialPolicyJson): string | undefined {
  for (const [tokenName, tokenPolicy] of Object.entries(policy.tokens ?? {})) {
    for (const existing of tokenPolicy.credentials) {
      if (existing.host === credential.host && existing.header.toLowerCase() === credential.header.toLowerCase()) {
        return tokenName;
      }
    }
  }
  return undefined;
}

function sameCredential(left: CredentialPolicyJson, right: CredentialPolicyJson): boolean {
  return left.host === right.host
    && left.header.toLowerCase() === right.header.toLowerCase()
    && left.scheme === right.scheme
    && (left.pathPrefix ?? "") === (right.pathPrefix ?? "");
}

function applyTokenBinding(policy: PolicyJson, tokenConfig: TokenSourceConfig, binding: HeaderTokenBinding, options: { autoTokenSource: boolean }): void {
  policy.tokens ??= {};
  ensureDomain(policy, binding.credential.host);
  const owner = credentialOwner(policy, binding.credential);
  if (owner && owner !== binding.tokenName) {
    warn(`mcp: ${binding.credential.host} ${binding.credential.header} already uses proxy token ${owner}; generated MCP config will reuse existing proxy injection`);
    return;
  }
  policy.tokens[binding.tokenName] ??= {
    description: `MCP ${binding.credential.host} credential`,
    credentials: [],
  };
  const credentials = policy.tokens[binding.tokenName].credentials;
  if (!credentials.some((credential) => sameCredential(credential, binding.credential))) {
    credentials.push(binding.credential);
    credentials.sort((left, right) => `${left.host}\0${left.header}`.localeCompare(`${right.host}\0${right.header}`));
  }
  const existingSource = tokenConfig[binding.tokenName];
  if (!existingSource) {
    if (options.autoTokenSource && binding.env) {
      tokenConfig[binding.tokenName] = { source: "env", env: binding.env };
    } else {
      warn(`mcp: ${binding.tokenName} credential source is unconfigured; run runfree credential set-source ${binding.tokenName} --from-env ${binding.tokenName.toUpperCase().replace(/[^A-Z0-9_]+/g, "_")}_TOKEN`);
    }
  } else if (options.autoTokenSource && binding.env && (existingSource.source !== "env" || existingSource.env !== binding.env)) {
    warn(`mcp: ${binding.tokenName} credential source already exists; keeping ${existingSource.source} source`);
  }
}

function applyPolicyAndTokens(policy: PolicyJson, tokenConfig: TokenSourceConfig, servers: PreparedMcpServer[]): void {
  for (const server of servers) {
    // Only the prepared endpoint names an egress host. A generated config URL
    // (a loopback server's `http://127.0.0.1:<port>`) never reaches the policy.
    if (server.endpoint) ensureDomain(policy, server.endpoint.host);
    if (server.oauthPolicy?.oauth?.authServerMetadataUrl) {
      ensureDomain(policy, new URL(server.oauthPolicy.oauth.authServerMetadataUrl).hostname.toLowerCase());
    }
    for (const endpoint of server.oauthPolicy?.tokenEndpoints ?? []) {
      ensureDomain(policy, typeof endpoint === "string" ? new URL(endpoint).hostname.toLowerCase() : endpoint.host);
    }
    for (const binding of server.tokenBindings) {
      applyTokenBinding(policy, tokenConfig, binding, { autoTokenSource: server.source !== "project" });
    }
  }
}

export const applyPolicyAndTokensForTest = applyPolicyAndTokens;

export function mcpOAuthProviderId(agent: McpAgent, serverName: string): string {
  const key = `${agent}-${serverName}`.toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
  return `mcp:${key}`;
}

export function mcpOAuthPolicyJson(
  servers: PreparedMcpServer[],
  callbackPort: number,
  serviceProviders: Record<string, OAuthProviderPolicyForWrite> = {},
): OAuthMediationPolicyForWrite {
  const providers: Record<string, OAuthProviderPolicyJson> = {};
  for (const [providerId, provider] of Object.entries(serviceProviders)) {
    if (providers[providerId]) throw new Error(`duplicate OAuth provider id: ${providerId}`);
    providers[providerId] = provider;
  }
  for (const server of servers) {
    if (!server.oauthPolicy) continue;
    const providerId = mcpOAuthProviderId(server.agent, server.name);
    if (providers[providerId]) throw new Error(`duplicate OAuth provider id: ${providerId}`);
    providers[providerId] = { ...server.oauthPolicy, kind: "mcp" };
  }
  const policy = {
    callback: {
      port: callbackPort,
      url: `http://localhost:${callbackPort}/callback`,
    },
    providers,
  };
  validateOAuthMediationPolicy(policy);
  return policy;
}

export function writeOAuthMediationPolicy(filePath: string, policy: OAuthMediationPolicyForWrite): void {
  validateOAuthMediationPolicy(policy, filePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const tmpPath = `${filePath}.${process.pid}.${Date.now().toString(36)}.tmp`;
  fs.writeFileSync(tmpPath, `${JSON.stringify(policy, null, 2)}\n`, { mode: 0o644 });
  fs.renameSync(tmpPath, filePath);
  fs.chmodSync(filePath, 0o644);
}

function writeMcpOAuthPolicy(filePath: string, servers: PreparedMcpServer[], callbackPort: number): void {
  writeOAuthMediationPolicy(filePath, mcpOAuthPolicyJson(servers, callbackPort));
}

function mcpOperationServerId(server: Pick<PreparedMcpServer, "agent" | "name" | "source">): string {
  const slug = server.name.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  const safeName = slug === "" ? sha256Hex(server.name).slice(0, 12) : slug.slice(0, 96);
  return `${server.agent}:${server.source}:${safeName}`;
}

export function mcpOperationPolicyJson(
  servers: PreparedMcpServer[],
  rules: Record<string, { defaultToolWriteAction?: McpOperationServerPolicyJson["defaultToolWriteAction"]; tools?: Record<string, McpToolOperationPolicyJson> }> = {},
): McpOperationPolicyJson {
  const operationServers: McpOperationServerPolicyJson[] = [];
  for (const server of servers) {
    // A loopback server is not proxy-mediated: no endpoint, no operation policy.
    if (server.transport !== "http" || !server.endpoint) continue;
    const id = mcpOperationServerId(server);
    const rule = rules[id];
    operationServers.push({
      id,
      agent: server.agent,
      name: server.name,
      source: server.source,
      host: server.endpoint.host,
      path: server.endpoint.path,
      ...(rule?.defaultToolWriteAction !== undefined ? { defaultToolWriteAction: rule.defaultToolWriteAction } : {}),
      ...(rule?.tools && Object.keys(rule.tools).length > 0 ? { tools: rule.tools } : {}),
    });
  }
  const policy = {
    schemaVersion: 1,
    servers: operationServers.sort((left, right) => left.id.localeCompare(right.id)),
  } satisfies McpOperationPolicyJson;
  validateMcpOperationPolicy(policy);
  return policy;
}

function mcpOperationRulesForServers(
  servers: PreparedMcpServer[],
  rulesFile: McpRulesFile,
): Record<string, { defaultToolWriteAction?: McpOperationServerPolicyJson["defaultToolWriteAction"]; tools?: Record<string, McpToolOperationPolicyJson> }> {
  const operationRules: Record<string, { defaultToolWriteAction?: McpOperationServerPolicyJson["defaultToolWriteAction"]; tools?: Record<string, McpToolOperationPolicyJson> }> = {};
  for (const server of servers) {
    if (!server.endpoint) continue;
    const key = mcpRuleKey({
      agent: server.agent,
      descriptorDigest: server.descriptorDigest,
      endpoint: server.endpoint,
      server: server.name,
      source: server.source,
    });
    const rule = key ? rulesFile.rules[key] : undefined;
    if (!rule) continue;
    operationRules[mcpOperationServerId(server)] = {
      ...(rule.defaultToolWriteAction !== undefined ? { defaultToolWriteAction: rule.defaultToolWriteAction } : {}),
      ...(rule.tools && Object.keys(rule.tools).length > 0 ? { tools: rule.tools } : {}),
    };
  }
  return operationRules;
}

export function mcpOperationPolicyPath(stateDir: string): string {
  return path.join(stateDir, MCP_OPERATION_POLICY_FILE);
}

export function writeMcpOperationPolicy(filePath: string, policy: McpOperationPolicyJson): void {
  validateMcpOperationPolicy(policy, filePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const tmpPath = `${filePath}.${process.pid}.${Date.now().toString(36)}.tmp`;
  fs.writeFileSync(tmpPath, `${JSON.stringify(policy, null, 2)}\n`, { mode: 0o644 });
  fs.renameSync(tmpPath, filePath);
  fs.chmodSync(filePath, 0o644);
}

export function mcpOAuthPolicyHasServers(filePath: string): boolean {
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8")) as unknown;
    if (isRecord(parsed) && isRecord(parsed.providers)) {
      return Object.values(parsed.providers).some((provider) => isRecord(provider) && (provider.kind === undefined || provider.kind === "mcp"));
    }
    return isRecord(parsed) && isRecord(parsed.servers) && Object.keys(parsed.servers).length > 0;
  } catch {
    return false;
  }
}

export function runtimeMcpOAuthPolicyPath(project: ProjectInfo): string {
  if (project.config.version !== 4) return project.paths.mcpOAuthPolicyPath;
  const effective = readActiveEffectiveControl(project);
  if (!effective) throw new Error("selected effective controls are required before MCP OAuth topology inspection");
  return effective.oauthPolicyPath;
}

export function runtimeMcpOAuthPolicyHasServers(project: ProjectInfo): boolean {
  return mcpOAuthPolicyHasServers(runtimeMcpOAuthPolicyPath(project));
}

export function ensureMcpOAuthPolicyFile(filePath: string, projectRoot: string): void {
  if (fs.existsSync(filePath)) return;
  writeMcpOAuthPolicy(filePath, [], mcpOAuthCallbackPort(projectRoot));
}

export function ensureMcpOperationPolicyFile(filePath: string): void {
  if (fs.existsSync(filePath)) return;
  writeMcpOperationPolicy(filePath, { schemaVersion: 1, servers: [] });
}

export function ensureMcpProjectMasks(paths: McpMaskPaths): void {
  replaceEmptyDirectory(paths.projectCodexDirMaskPath, 0o555);
}

function replaceEmptyDirectory(dirPath: string, mode: number): void {
  fs.mkdirSync(path.dirname(dirPath), { recursive: true, mode: 0o700 });
  try {
    const stat = fs.lstatSync(dirPath);
    if (stat.isDirectory() && !stat.isSymbolicLink()) {
      fs.chmodSync(dirPath, 0o700);
      for (const entry of fs.readdirSync(dirPath)) {
        removeMaskPath(path.join(dirPath, entry));
      }
      fs.chmodSync(dirPath, mode);
      return;
    }
    removeMaskPath(dirPath);
  } catch (error) {
    if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw error;
  }
  fs.mkdirSync(dirPath, { recursive: true, mode });
  fs.chmodSync(dirPath, mode);
}

function removeMaskPath(targetPath: string): void {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(targetPath);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return;
    throw error;
  }

  if (stat.isDirectory() && !stat.isSymbolicLink()) {
    fs.chmodSync(targetPath, 0o700);
    for (const entry of fs.readdirSync(targetPath)) {
      removeMaskPath(path.join(targetPath, entry));
    }
    fs.rmdirSync(targetPath);
    return;
  }

  fs.unlinkSync(targetPath);
}

export function mcpProjectMaskMounts(
  _projectRoot: string,
  project: McpAgentMaskProject,
  projectContainerRoot = "/workspace",
): Array<{ type: "bind"; source: string; target: string; readOnly: true }> {
  return [{
    type: "bind",
    source: project.paths.projectCodexDirMaskPath,
    target: workspaceMetadataTarget(projectContainerRoot, "codex"),
    readOnly: true,
  }];
}

export function claudeMcpConfigMount(
  project: ClaudeMcpConfigProject,
): { type: "bind"; source: string; target: string; readOnly: true } {
  return {
    type: "bind",
    source: project.paths.claudeMcpConfigPath,
    target: RUNFREE_RUNTIME_TARGETS.claudeMcpConfig,
    readOnly: true,
  };
}

export function prepareMcpRuntime(options: McpPrepareOptions): McpPrepareResult {
  const originalPolicy = stableJson(options.policy);
  const originalTokenConfig = stableJson(options.tokenConfig);
  const callbackPort = options.callbackPort ?? mcpOAuthCallbackPort(options.projectRoot);
  // L5 reach source: the approved base policy's host services. Validated
  // before any write, so an invalid base policy fails before side effects.
  const hostServices = validateNetworkPolicy(options.policy).hostServices;
  const servers: PreparedMcpServer[] = [];
  const events: McpLogEvent[] = [];
  const desktopBuiltIns: McpInventoryRecord[] = [];
  for (const entry of mcpInventoryRecords({
    approvalPath: options.approvalPath,
    env: options.env,
    projectRoot: options.projectRoot,
    rulesPath: options.mcpRulesPath,
  })) {
    if (!entry.prepared) {
      // A Codex Desktop built-in is not a problem to warn about: it gets one
      // line under --verbose and nothing otherwise.
      if (entry.decision.status === "skipped") desktopBuiltIns.push(entry);
      continue;
    }
    if (entry.source === "project" && entry.decision.status !== "approved") {
      const reason = entry.decision.reason ?? "project MCP requires approval";
      const suffix = entry.decision.status === "unapproved"
        ? `; run ${remedy.mcpEnableProject(entry.agent, entry.name)}`
        : "";
      events.push({ kind: "skipped", scope: "project", agent: entry.agent, name: entry.name, detail: `reason=${reason}${suffix}` });
      continue;
    }
    const prepared = prepareServer(entry.server, options.projectRoot, {
      allowProject: entry.source === "project",
      log: (event) => events.push(event),
    });
    // A refusal here was already reported by the inventory pass above.
    if (prepared && !isMcpRefusal(prepared)) {
      if (entry.descriptorDigest) prepared.descriptorDigest = entry.descriptorDigest;
      servers.push(prepared);
    }
  }

  writeClaudeRuntimeConfig(options.claudeConfigPath, options.claudeMcpConfigPath, servers);
  writeCodexRuntimeConfig(options.codexDir, servers);
  applyPolicyAndTokens(options.policy, options.tokenConfig, servers);
  // `runfree mcp enable` records join the servers prepared in this pass by the
  // MCP rules identity (descriptor digest for project servers, endpoint for
  // user/local servers): a changed or deleted server matches no record. Their
  // hosts are projected after the servers' own hosts, so only hosts nothing
  // else allows get narrowed request rules; their endpoints then join the
  // OAuth mediation policy written below.
  const enabled = options.mcpEnabledPath ? readMcpEnabled(options.projectRoot, options.mcpEnabledPath).file : undefined;
  const claimants = servers.map((server) => {
    // F5: a loopback server claims no record, so whatever a record keyed to
    // its identity names never reaches the policy ("adds nothing to policy"
    // by construction, not because `mcp enable` writes none).
    const identity = enabled && server.transport !== "http-loopback"
      ? mcpRuleKey({ agent: server.agent, descriptorDigest: server.descriptorDigest, endpoint: server.endpoint, server: server.name, source: server.source })
      : undefined;
    const record = identity ? enabled?.records[identity] : undefined;
    return {
      serverKey: `${server.agent}\0${server.source}\0${server.name}`,
      label: `${server.agent} server ${server.name}`,
      ...(server.oauthPolicy ? { policy: server.oauthPolicy } : {}),
      ...(record ? { record } : {}),
    };
  });
  const mediation = withoutSharedEnabledEndpoints(claimants);
  for (const message of mediation.dropped) warn(message);
  servers.forEach((server, index) => {
    const record = mediation.records[index];
    if (!record || !server.oauthPolicy) return;
    const applied = projectEnabledOAuthEndpoints(server.oauthPolicy, record);
    if (applied.length > 0) server.oauthPolicy.protocolReadEndpoints = applied;
  });
  const oauthCapable = servers.filter((server) => server.oauthPolicy !== undefined);
  if (options.mcpOAuthEpochsPath && oauthCapable.length > 0) {
    const epochs = updateMcpOAuthEpochs(options.projectRoot, options.mcpOAuthEpochsPath);
    if (epochs.reset === "reclaimed") {
      warn(`mcp: the MCP OAuth state epoch store ${options.mcpOAuthEpochsPath} was invalid; Runfree replaced it, so the proxy clears all MCP OAuth state and every MCP server needs a new OAuth login`);
    }
    for (const server of oauthCapable) {
      if (server.oauthPolicy) server.oauthPolicy.stateEpoch = mcpOAuthStateEpoch(epochs, mcpOAuthProviderId(server.agent, server.name));
    }
  }
  projectEnabledOAuthHosts(options.policy, claimants.flatMap((claimant) => claimant.record ? [claimant.record] : []));
  writeMcpOAuthPolicy(options.mcpOAuthPolicyPath, servers, callbackPort);
  writeMcpOperationPolicy(
    options.mcpOperationPolicyPath ?? mcpOperationPolicyPath(path.dirname(options.mcpOAuthPolicyPath)),
    mcpOperationPolicyJson(servers, mcpOperationRulesForServers(servers, readMcpRules(options.projectRoot, options.mcpRulesPath))),
  );

  // Import/skip lines: only the launched agent's servers, and one line per
  // server when both agents import it with the same outcome.
  const grouped = new Map<string, { event: McpLogEvent; agents: string[] }>();
  for (const event of events) {
    if (mcpLogContext.agent !== undefined && event.agent !== mcpLogContext.agent) continue;
    const key = [event.kind, event.scope, event.name, event.detail].join("\0");
    const group = grouped.get(key);
    if (group) group.agents.push(event.agent);
    else grouped.set(key, { event, agents: [event.agent] });
  }
  for (const { event, agents } of grouped.values()) warn(renderMcpLogEvent(event, agents));
  if (mcpLogContext.verbose) {
    for (const entry of desktopBuiltIns) {
      if (mcpLogContext.agent !== undefined && entry.agent !== mcpLogContext.agent) continue;
      runfreeLog(`mcp: skipped Codex Desktop built-in ${entry.name}; not used in Runfree`);
    }
  }

  // L5: one warning per generated loopback server of the launched agent that
  // no approved host service backs. Reach is shown here, never granted.
  for (const server of servers) {
    if (server.transport !== "http-loopback" || server.loopbackPort === undefined) continue;
    if (mcpLogContext.agent !== undefined && server.agent !== mcpLogContext.agent) continue;
    const port = server.loopbackPort;
    if (mcpLoopbackReach(port, hostServices).kind !== "container-local") continue;
    warn(`mcp: ${server.agent} server ${printable(server.name)} targets 127.0.0.1:${port}, which is not an approved host service;\n`
      + `it works only if a process in the session listens there. To reach the host, and only if you trust the host process listening on port ${port}: ${remedy.hostServiceAdd(loopbackHostServiceName(server.name, port, hostServices), port)}`);
  }

  // The OAuth callback guidance is verbose-only: the host cannot see whether
  // the proxy already holds a live OAuth token for a server, and the agent
  // prints the authorization URL itself when a login is actually needed.
  const oauthServers = servers.filter((server) => server.oauthPolicy && (mcpLogContext.agent === undefined || server.agent === mcpLogContext.agent));
  if (mcpLogContext.verbose && oauthServers.length > 0) {
    warn(`mcp: OAuth login for ${[...new Set(oauthServers.map((server) => server.name))].sort().join(", ")} returns through the session's own loopback callback port; open the authorization URL the agent prints to complete it`);
  }

  return {
    policy: options.policy,
    tokenConfig: options.tokenConfig,
    policyChanged: stableJson(options.policy) !== originalPolicy,
    tokenConfigChanged: stableJson(options.tokenConfig) !== originalTokenConfig,
  };
}
