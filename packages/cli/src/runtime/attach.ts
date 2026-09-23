import { projectIdentity } from "../project-identity.ts";
import { AGENT_UID_GID, PROXY_SERVER_UID_GID, ROOT_UID_GID } from "./constants.ts";
import { dockerClientEnvOptions } from "./docker.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";

export const INTERACTIVE_TERMINAL_RESTORE_SEQUENCE = [
  "\x1b[?9l",
  "\x1b[?1000l",
  "\x1b[?1002l",
  "\x1b[?1003l",
  "\x1b[?1004l",
  "\x1b[?1005l",
  "\x1b[?1006l",
  "\x1b[?1015l",
  "\x1b[?1049l",
  "\x1b[?2004l",
  "\x1b[?25h",
  "\x1b[0m",
].join("");

type TerminalWriteStream = {
  isTTY?: boolean;
  write: (chunk: string) => unknown;
};

export function restoreInteractiveTerminalControlModes(stream: TerminalWriteStream = process.stdout): void {
  if (!stream.isTTY) return;
  try {
    stream.write(INTERACTIVE_TERMINAL_RESTORE_SEQUENCE);
  } catch {
    // Terminal cleanup is best-effort; never change the session exit status.
  }
}

export function runDockerExec(
  context: RuntimeContext,
  io: RuntimeIO,
  containerId: string,
  args: string[],
): CaptureResult {
  return io.capture("docker", ["exec", containerId, ...args], dockerClientEnvOptions(context));
}

export function runDockerExecAgent(
  context: RuntimeContext,
  io: RuntimeIO,
  containerId: string,
  args: string[],
): CaptureResult {
  return io.capture("docker", ["exec", "--user", AGENT_UID_GID, containerId, ...args], dockerClientEnvOptions(context));
}

export function runDockerExecRoot(
  context: RuntimeContext,
  io: RuntimeIO,
  containerId: string,
  args: string[],
): CaptureResult {
  return io.capture("docker", ["exec", "--user", ROOT_UID_GID, containerId, ...args], dockerClientEnvOptions(context));
}

export function runDockerExecProxyServer(
  context: RuntimeContext,
  io: RuntimeIO,
  containerId: string,
  args: string[],
): CaptureResult {
  return io.capture("docker", ["exec", "--user", PROXY_SERVER_UID_GID, containerId, ...args], dockerClientEnvOptions(context));
}

export function projectPhysicalRoot(context: RuntimeContext): string {
  return context.gitLayoutPlan?.containerProjectRoot
    ?? projectIdentity(context.projectRoot, context.project.config).compatRoot;
}
