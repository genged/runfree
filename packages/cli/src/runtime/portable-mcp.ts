// Portable compute MCP catalog and descriptor classification.
//
// A host MCP descriptor that names a known compute tool (Codex Desktop's
// `node_repl`) is translated to a fixed Runfree-owned command inside the agent
// container. The host command is only a compatibility hint: its path, args,
// env values, and cwd are discarded and never executed or copied.
//
// Classification runs before the generic STDIO rules, so a known descriptor is
// never judged by its host path, and a look-alike descriptor is skipped with a
// precise reason instead of falling through to the generic path.
//
// The descriptor shapes come from public issue reports (see the portable
// compute MCP section of docs/architecture.md); they were not captured from a
// maintainer machine.

import path from "node:path";

import { isRecord } from "../strict-primitives.ts";

export const PORTABLE_MCP_DISPATCHER = "/usr/local/bin/runfree-mcp";

export type PortableMcpCapabilityId = "node-repl";

export type PortableMcpCapability = Readonly<{
  id: PortableMcpCapabilityId;
  // Names the tool surface; bound into project approvals. Must equal the agent
  // image's compiled contract version (asserted by scripts/agent-mcp-bundle.test.ts).
  contractVersion: number;
  compatibleAgents: readonly ("claude" | "codex")[];
  launcher: Readonly<{ command: string; args: readonly string[] }>;
  // Runfree-owned bundle version shipped in the base agent image.
  bundleVersion: string;
  requirements: readonly ("node" | "virtual-display" | "browser")[];
  workspaceAccess: "read-write" | "read-only" | "none";
  networkAccess: "agent-policy";
}>;

export const PORTABLE_MCP_CATALOG: Readonly<Record<PortableMcpCapabilityId, PortableMcpCapability>> = Object.freeze({
  "node-repl": Object.freeze({
    id: "node-repl",
    contractVersion: 1,
    compatibleAgents: Object.freeze(["codex"] as const),
    launcher: Object.freeze({ command: PORTABLE_MCP_DISPATCHER, args: Object.freeze(["node-repl"]) }),
    bundleVersion: "1.0.0",
    requirements: Object.freeze(["node"] as const),
    workspaceAccess: "read-write",
    networkAccess: "agent-policy",
  }),
});

// Options copied from a matched descriptor into the generated entry. Every
// value is a scalar or a list of tool names; none can name a host path or
// command. `required` is deliberately absent: until the selected agent image
// is checked at session time, a portable server that fails to start must not
// stop the agent session.
export type PortableSafeOptions = {
  disabled_tools?: string[];
  enabled?: boolean;
  enabled_tools?: string[];
  startup_timeout_sec?: number;
  tool_timeout_sec?: number;
};

export const PORTABLE_MESSAGES = Object.freeze({
  changed: "portable descriptor changed and is not supported by this Runfree version",
  hostDesktop: "computer-use controls host desktop apps; Runfree has no host desktop control (isolated-display computer-use is not supported yet)",
  notPortable: "local STDIO command is not a portable capability; install it in the agent image",
});

export type PortableClassification =
  | { kind: "none" }
  | { kind: "portable"; capability: PortableMcpCapability; options: PortableSafeOptions }
  | { kind: "changed"; capabilityId: PortableMcpCapabilityId; reason: string }
  | { kind: "host-desktop"; reason: string };

const NODE_REPL_SERVER_NAME = "node_repl";

// Env keys Codex Desktop writes for node_repl. Their values are host paths and
// are always discarded.
const NODE_REPL_ENV_KEYS: ReadonlySet<string> = new Set([
  "BROWSER_USE_AVAILABLE_BACKENDS",
  "CODEX_CLI_PATH",
  "CODEX_HOME",
  "NODE_REPL_NATIVE_PIPE_CONNECT_TIMEOUT_MS",
  "NODE_REPL_NODE_PATH",
  "NODE_REPL_TRUSTED_CODE_PATHS",
  "SKY_CUA_SERVICE_PATH",
]);

// Accepted argument lists, compared exactly.
const NODE_REPL_ARGS: readonly (readonly string[])[] = [[], ["--disable-sandbox"]];

// Path tails under the app bundle, as segments.
const NODE_REPL_COMMAND_TAILS: readonly (readonly string[])[] = [
  ["Codex.app", "Contents", "Resources", "node_repl"],
  ["Codex.app", "Contents", "Resources", "cua_node", "bin", "node_repl"],
];

const NODE_REPL_KEYS: ReadonlySet<string> = new Set([
  "args",
  "command",
  "disabled_tools",
  "enabled",
  "enabled_tools",
  "env",
  "env_vars",
  "required",
  "startup_timeout_sec",
  "tool_timeout_sec",
  "type",
]);

const COMPUTER_USE_SERVER_NAMES: ReadonlySet<string> = new Set(["computer-use", "unified-computer-use"]);
const COMPUTER_USE_CACHE_SEGMENT = "/plugins/cache/openai-bundled/computer-use/";

// Printable ASCII only: a command outside this set is never a Codex Desktop
// path, and exact byte matching avoids any Unicode normalization widening.
const PRINTABLE_ASCII = /^[\x20-\x7e]+$/;

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function commandSegments(command: string): string[] | undefined {
  if (!PRINTABLE_ASCII.test(command) || command.includes("\\") || !command.startsWith("/")) return undefined;
  const segments = command.slice(1).split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) return undefined;
  return segments;
}

function endsWithSegments(segments: readonly string[], tail: readonly string[]): boolean {
  if (segments.length < tail.length) return false;
  const offset = segments.length - tail.length;
  return tail.every((segment, index) => segments[offset + index] === segment);
}

function isExactNodeReplCommand(command: string): boolean {
  const segments = commandSegments(command);
  if (!segments) return false;
  // At least one directory must hold Codex.app: `/Codex.app/...` alone is not
  // an installed app location.
  return NODE_REPL_COMMAND_TAILS.some((tail) => segments.length > tail.length && endsWithSegments(segments, tail));
}

function hostCommandLooksLikeNodeRepl(command: string): boolean {
  const normalized = command.replaceAll("\\", "/");
  const base = path.posix.basename(normalized);
  return (base === "node_repl" || base === "node_repl.exe") && normalized.includes("/");
}

function sameArgs(value: unknown): boolean {
  if (value === undefined) return true;
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) return false;
  return NODE_REPL_ARGS.some((accepted) => accepted.length === value.length && accepted.every((item, index) => item === value[index]));
}

function envKeysAccepted(value: unknown): boolean {
  if (value === undefined) return true;
  if (!isRecord(value)) return false;
  return Object.entries(value).every(([key, item]) => NODE_REPL_ENV_KEYS.has(key) && typeof item === "string");
}

function stringList(value: unknown): string[] | undefined {
  return Array.isArray(value) && value.every((item) => typeof item === "string" && PRINTABLE_ASCII.test(item)) ? [...value] : undefined;
}

function positiveNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : undefined;
}

/**
 * The safe options of a matched descriptor, or undefined when an option has a
 * shape Runfree does not accept (which makes the descriptor `changed`).
 */
function nodeReplSafeOptions(config: Record<string, unknown>): PortableSafeOptions | undefined {
  const options: PortableSafeOptions = {};
  for (const key of ["enabled_tools", "disabled_tools"] as const) {
    if (config[key] === undefined) continue;
    const list = stringList(config[key]);
    if (!list) return undefined;
    options[key] = list;
  }
  for (const key of ["startup_timeout_sec", "tool_timeout_sec"] as const) {
    if (config[key] === undefined) continue;
    const value = positiveNumber(config[key]);
    if (value === undefined) return undefined;
    options[key] = value;
  }
  if (config.enabled !== undefined) {
    if (typeof config.enabled !== "boolean") return undefined;
    options.enabled = config.enabled;
  }
  if (config.required !== undefined && typeof config.required !== "boolean") return undefined;
  return options;
}

function classifyNodeRepl(name: string, config: Record<string, unknown>): PortableClassification {
  const command = stringValue(config.command);
  const nameMatches = name === NODE_REPL_SERVER_NAME;
  const commandLooksLike = command !== undefined && hostCommandLooksLikeNodeRepl(command);
  // A container-local `node_repl` (a bare command name with no path) keeps the
  // generic STDIO rules: it may be a project's own tool on the image PATH.
  if (!nameMatches && !commandLooksLike) return { kind: "none" };
  if (nameMatches && command !== undefined && !command.includes("/") && !command.includes("\\")) return { kind: "none" };
  const changed = (): PortableClassification => ({ kind: "changed", capabilityId: "node-repl", reason: PORTABLE_MESSAGES.changed });
  if (!nameMatches || command === undefined || !isExactNodeReplCommand(command)) return changed();
  if (config.type !== undefined && config.type !== "stdio") return changed();
  if (config.url !== undefined || config.cwd !== undefined) return changed();
  if (Object.keys(config).some((key) => !NODE_REPL_KEYS.has(key))) return changed();
  if (!sameArgs(config.args)) return changed();
  if (!envKeysAccepted(config.env)) return changed();
  if (config.env_vars !== undefined && !(Array.isArray(config.env_vars) && config.env_vars.length === 0)) return changed();
  const options = nodeReplSafeOptions(config);
  if (!options) return changed();
  return { kind: "portable", capability: PORTABLE_MCP_CATALOG["node-repl"], options };
}

function looksLikeComputerUse(name: string, config: Record<string, unknown>): boolean {
  if (COMPUTER_USE_SERVER_NAMES.has(name)) return true;
  const command = stringValue(config.command)?.replaceAll("\\", "/");
  const cwd = stringValue(config.cwd)?.replaceAll("\\", "/");
  if (command !== undefined && path.posix.basename(command) === "SkyComputerUseClient") return true;
  return [command, cwd].some((value) => value !== undefined && `${value}/`.includes(COMPUTER_USE_CACHE_SEGMENT));
}

/** Classifies one native MCP descriptor before the generic STDIO rules. */
export function classifyPortableMcp(input: { agent: string; name: string; config: Record<string, unknown> }): PortableClassification {
  if (input.agent !== "codex") return { kind: "none" };
  if (looksLikeComputerUse(input.name, input.config)) return { kind: "host-desktop", reason: PORTABLE_MESSAGES.hostDesktop };
  return classifyNodeRepl(input.name, input.config);
}

/** The fixed generated Codex entry for a portable capability. */
export function portableCodexConfig(capability: PortableMcpCapability, options: PortableSafeOptions): {
  args: string[];
  command: string;
} & PortableSafeOptions {
  return {
    ...options,
    command: capability.launcher.command,
    args: [...capability.launcher.args],
  };
}
