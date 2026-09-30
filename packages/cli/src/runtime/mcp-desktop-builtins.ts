// Codex Desktop built-in MCP servers.
//
// The Codex Desktop app writes `node_repl` and Computer Use entries into the
// shared `~/.codex/config.toml`. They run host app binaries and only work
// inside that app, so Runfree skips them without a warning: they are never
// written into the generated agent config and never approved. Nothing here
// runs or reads the host command.
//
// The match is exact on purpose. Any other entry, including a `node_repl`
// with a bare command name or a different path, keeps the generic STDIO rules
// and their warning.

import path from "node:path";

export const CODEX_DESKTOP_BUILTIN_REASON = "Codex Desktop built-in; not used in Runfree";

// Path tails under the app bundle, as segments.
const NODE_REPL_COMMAND_TAILS: readonly (readonly string[])[] = [
  ["Codex.app", "Contents", "Resources", "node_repl"],
  ["Codex.app", "Contents", "Resources", "cua_node", "bin", "node_repl"],
];

const COMPUTER_USE_SERVER_NAMES: ReadonlySet<string> = new Set(["computer-use", "unified-computer-use"]);
const COMPUTER_USE_CACHE_SEGMENT = "/plugins/cache/openai-bundled/computer-use/";
const COMPUTER_USE_CLIENT = "SkyComputerUseClient";

// Printable ASCII only: a command outside this set is never a Codex Desktop
// path, and exact byte matching avoids any Unicode normalization widening.
const PRINTABLE_ASCII = /^[\x20-\x7e]+$/;

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function absoluteSegments(command: string): string[] | undefined {
  if (!PRINTABLE_ASCII.test(command) || command.includes("\\") || !command.startsWith("/")) return undefined;
  const segments = command.slice(1).split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) return undefined;
  return segments;
}

function isDesktopNodeReplCommand(command: string): boolean {
  const segments = absoluteSegments(command);
  if (!segments) return false;
  // At least one directory must hold Codex.app: `/Codex.app/...` alone is not
  // an installed app location.
  return NODE_REPL_COMMAND_TAILS.some((tail) => {
    if (segments.length <= tail.length) return false;
    const offset = segments.length - tail.length;
    return tail.every((segment, index) => segments[offset + index] === segment);
  });
}

function isComputerUse(name: string, config: Record<string, unknown>): boolean {
  const command = stringValue(config.command)?.replaceAll("\\", "/");
  const cwd = stringValue(config.cwd)?.replaceAll("\\", "/");
  if (command !== undefined && path.posix.basename(command) === COMPUTER_USE_CLIENT) return true;
  if ([command, cwd].some((value) => value !== undefined && `${value}/`.includes(COMPUTER_USE_CACHE_SEGMENT))) return true;
  // A bare command under one of these names may be a project's own tool on
  // the image PATH, so only a path command counts.
  return COMPUTER_USE_SERVER_NAMES.has(name) && command !== undefined && command.includes("/");
}

/** True when a native STDIO MCP entry is a Codex Desktop built-in. */
export function isCodexDesktopBuiltIn(input: { agent: string; name: string; config: Record<string, unknown> }): boolean {
  if (input.agent !== "codex") return false;
  if (isComputerUse(input.name, input.config)) return true;
  const command = stringValue(input.config.command);
  return input.name === "node_repl" && command !== undefined && isDesktopNodeReplCommand(command);
}
