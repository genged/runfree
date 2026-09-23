

import {
  DEFAULT_WRITE_ACTION,
  isWriteAction,
  normalizeHostname,
  normalizePathPrefix,
  type WriteAction,
} from "./network-policy.js";
import { isRecord, sha256Digest } from "./primitives.js";

const INLINE_POLICY_LABEL = "<inline MCP operation policy>";
const MCP_SERVER_ID_RE = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$/;
const MCP_NAME_MAX = 128;
const MCP_TOOL_NAME_MAX = 128;

export type McpOperationPolicyJson = {
  schemaVersion: 1;
  servers: McpOperationServerPolicyJson[];
};

export type McpOperationServerPolicyJson = {
  id: string;
  agent: "claude" | "codex";
  name: string;
  source: "user" | "local" | "project";
  host: string;
  path: string;
  defaultToolWriteAction?: WriteAction;
  tools?: Record<string, McpToolOperationPolicyJson>;
};

export type McpToolOperationPolicyJson = {
  writeAction: WriteAction;
};

export type LoadedMcpOperationServer = McpOperationServerPolicyJson & {
  tools: Record<string, McpToolOperationPolicyJson>;
};

export type McpEndpointOverlap = {
  host: string;
  path: string;
  serverIds: string[];
};

export type LoadedMcpOperationPolicy = {
  policyPath: string;
  generation: string;
  raw: McpOperationPolicyJson;
  servers: LoadedMcpOperationServer[];
  endpointMap: Map<string, LoadedMcpOperationServer[]>;
  overlaps: McpEndpointOverlap[];
};

export class McpOperationPolicyValidationError extends Error {
  readonly issues: string[];

  constructor(issues: string[]) {
    super(`invalid MCP operation policy:\n${issues.map((issue) => `- ${issue}`).join("\n")}`);
    this.name = "McpOperationPolicyValidationError";
    this.issues = issues;
  }
}


function compareStableText(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function validateStoredName(label: string, value: unknown, issues: string[]): string | undefined {
  if (typeof value !== "string" || value.trim() === "" || value.length > MCP_NAME_MAX) {
    issues.push(`${label} must be a non-empty string up to ${MCP_NAME_MAX} characters`);
    return undefined;
  }
  if (/[\u0000-\u001f\u007f]/.test(value)) {
    issues.push(`${label} must not contain control characters`);
    return undefined;
  }
  return value;
}

function validateToolName(label: string, value: string, issues: string[]): boolean {
  if (value.trim() === "" || value.length > MCP_TOOL_NAME_MAX) {
    issues.push(`${label} must be a non-empty string up to ${MCP_TOOL_NAME_MAX} characters`);
    return false;
  }
  if (/[\u0000-\u001f\u007f]/.test(value)) {
    issues.push(`${label} must not contain control characters`);
    return false;
  }
  return true;
}

function validateStoredHost(label: string, value: unknown, issues: string[]): string | undefined {
  if (typeof value !== "string") {
    issues.push(`${label} must be a string`);
    return undefined;
  }
  if (value !== value.toLowerCase()) {
    issues.push(`${label} must be stored lowercase`);
  }
  let host: string;
  try {
    host = normalizeHostname(value);
  } catch (error) {
    issues.push(`${label} ${value}: ${error instanceof Error ? error.message : String(error)}`);
    return undefined;
  }
  if (host !== value) {
    issues.push(`${label} must be stored as exact normalized hostname ${host}`);
    return undefined;
  }
  return host;
}

function validateEndpointPath(label: string, value: unknown, issues: string[]): string | undefined {
  if (typeof value !== "string") {
    issues.push(`${label} must be a string`);
    return undefined;
  }
  let normalized: string;
  try {
    normalized = normalizePathPrefix(value);
  } catch (error) {
    issues.push(`${label} ${value}: ${error instanceof Error ? error.message : String(error)}`);
    return undefined;
  }
  if (normalized !== value) {
    issues.push(`${label} must be stored as exact normalized path ${normalized}`);
    return undefined;
  }
  if (normalized.includes("*")) {
    issues.push(`${label} must be an exact path without wildcards`);
    return undefined;
  }
  return normalized;
}

function validateWriteAction(label: string, value: unknown, issues: string[]): WriteAction | undefined {
  if (typeof value !== "string" || !isWriteAction(value)) {
    issues.push(`${label} must be one of: allow, ask, deny`);
    return undefined;
  }
  return value;
}

function normalizeTools(label: string, value: unknown, issues: string[]): Record<string, McpToolOperationPolicyJson> {
  if (value === undefined) return {};
  const tools: Record<string, McpToolOperationPolicyJson> = {};
  if (!isRecord(value)) {
    issues.push(`${label} must be an object when present`);
    return tools;
  }
  for (const [toolName, rawRule] of Object.entries(value)) {
    const toolLabel = `${label}.${toolName}`;
    if (!validateToolName(toolLabel, toolName, issues)) continue;
    if (!isRecord(rawRule)) {
      issues.push(`${toolLabel} must be an object`);
      continue;
    }
    for (const key of Object.keys(rawRule)) {
      if (key !== "writeAction") {
        issues.push(`${toolLabel}.${key} is not a known tool policy field (known: writeAction)`);
      }
    }
    const writeAction = validateWriteAction(`${toolLabel}.writeAction`, rawRule.writeAction, issues);
    if (writeAction) tools[toolName] = { writeAction };
  }
  return Object.fromEntries(Object.entries(tools).sort(([left], [right]) => compareStableText(left, right)));
}

export function mcpEndpointKey(host: string, path: string): string {
  return `${host}\0${path}`;
}

export function mcpMostRestrictiveWriteAction(actions: readonly WriteAction[]): WriteAction {
  if (actions.includes("deny")) return "deny";
  if (actions.includes("ask")) return "ask";
  return "allow";
}

export function effectiveMcpToolAction(
  server: Pick<LoadedMcpOperationServer, "defaultToolWriteAction" | "tools">,
  tool: string,
  fallback: WriteAction = DEFAULT_WRITE_ACTION,
): WriteAction {
  return server.tools[tool]?.writeAction ?? server.defaultToolWriteAction ?? fallback;
}

export function mcpOperationPolicyGeneration(servers: readonly LoadedMcpOperationServer[]): string {
  const normalized = servers
    .map((server) => ({
      id: server.id,
      agent: server.agent,
      name: server.name,
      source: server.source,
      host: server.host,
      path: server.path,
      ...(server.defaultToolWriteAction !== undefined ? { defaultToolWriteAction: server.defaultToolWriteAction } : {}),
      ...(Object.keys(server.tools).length > 0
        ? {
          tools: Object.fromEntries(Object.entries(server.tools)
            .sort(([left], [right]) => compareStableText(left, right))
            .map(([tool, rule]) => [tool, { writeAction: rule.writeAction }])),
        }
        : {}),
    }))
    .sort((left, right) => compareStableText(left.id, right.id));
  return sha256Digest(JSON.stringify({ schemaVersion: 1, servers: normalized }));
}

export function validateMcpOperationPolicy(raw: unknown, policyPath = INLINE_POLICY_LABEL): LoadedMcpOperationPolicy {
  const issues: string[] = [];
  if (!isRecord(raw)) {
    throw new McpOperationPolicyValidationError(["policy must be a JSON object"]);
  }
  if (raw.schemaVersion !== 1) {
    issues.push("schemaVersion must be 1");
  }
  if (!Array.isArray(raw.servers)) {
    issues.push("servers must be an array");
  }

  const servers: LoadedMcpOperationServer[] = [];
  const seenIds = new Set<string>();
  for (const [index, rawServer] of (Array.isArray(raw.servers) ? raw.servers : []).entries()) {
    const prefix = `servers[${index}]`;
    if (!isRecord(rawServer)) {
      issues.push(`${prefix} must be an object`);
      continue;
    }
    for (const key of Object.keys(rawServer)) {
      if (!["id", "agent", "name", "source", "host", "path", "defaultToolWriteAction", "tools"].includes(key)) {
        issues.push(`${prefix}.${key} is not a known server policy field`);
      }
    }
    const id = typeof rawServer.id === "string" && MCP_SERVER_ID_RE.test(rawServer.id) ? rawServer.id : undefined;
    if (!id) {
      issues.push(`${prefix}.id must match ${MCP_SERVER_ID_RE.source}`);
    } else if (seenIds.has(id)) {
      issues.push(`${prefix}.id duplicates ${id}`);
    } else {
      seenIds.add(id);
    }
    const agent = rawServer.agent === "claude" || rawServer.agent === "codex" ? rawServer.agent : undefined;
    if (!agent) issues.push(`${prefix}.agent must be claude or codex`);
    const source = rawServer.source === "user" || rawServer.source === "local" || rawServer.source === "project" ? rawServer.source : undefined;
    if (!source) issues.push(`${prefix}.source must be user, local, or project`);
    const name = validateStoredName(`${prefix}.name`, rawServer.name, issues);
    const host = validateStoredHost(`${prefix}.host`, rawServer.host, issues);
    const endpointPath = validateEndpointPath(`${prefix}.path`, rawServer.path, issues);
    const defaultToolWriteAction = rawServer.defaultToolWriteAction === undefined
      ? undefined
      : validateWriteAction(`${prefix}.defaultToolWriteAction`, rawServer.defaultToolWriteAction, issues);
    const tools = normalizeTools(`${prefix}.tools`, rawServer.tools, issues);
    if (!id || !agent || !source || !name || !host || !endpointPath) continue;
    servers.push({
      id,
      agent,
      name,
      source,
      host,
      path: endpointPath,
      ...(defaultToolWriteAction !== undefined ? { defaultToolWriteAction } : {}),
      tools,
    });
  }

  if (issues.length > 0) throw new McpOperationPolicyValidationError(issues);

  const endpointMap = new Map<string, LoadedMcpOperationServer[]>();
  for (const server of servers) {
    const key = mcpEndpointKey(server.host, server.path);
    endpointMap.set(key, [...(endpointMap.get(key) ?? []), server]);
  }
  const overlaps = Array.from(endpointMap.entries())
    .filter(([, entries]) => entries.length > 1)
    .map(([key, entries]) => {
      const [host, endpointPath] = key.split("\0");
      return {
        host,
        path: endpointPath,
        serverIds: entries.map((server) => server.id).sort(compareStableText),
      };
    })
    .sort((left, right) => compareStableText(`${left.host}\0${left.path}`, `${right.host}\0${right.path}`));

  const rawPolicy: McpOperationPolicyJson = {
    schemaVersion: 1,
    servers: servers.map((server) => ({
      id: server.id,
      agent: server.agent,
      name: server.name,
      source: server.source,
      host: server.host,
      path: server.path,
      ...(server.defaultToolWriteAction !== undefined ? { defaultToolWriteAction: server.defaultToolWriteAction } : {}),
      ...(Object.keys(server.tools).length > 0 ? { tools: server.tools } : {}),
    })),
  };

  return {
    policyPath,
    generation: mcpOperationPolicyGeneration(servers),
    raw: rawPolicy,
    servers,
    endpointMap,
    overlaps,
  };
}
