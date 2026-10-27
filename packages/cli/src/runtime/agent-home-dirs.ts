import path from "node:path";

import { composeAgentStateMounts } from "../agents.ts";
import { runtimeToolStoreTargets } from "./dependency-stores.ts";
import { AGENT_HOME_TARGETS } from "./mount-target-policy.ts";

export const AGENT_HOME = "/home/agent";

// Every session mount target under the agent home. Docker creates a missing
// parent of a mount target as root, so the agent image must create each
// parent this list implies (see agentHomeMountParents).
export function agentHomeMountTargets(): string[] {
  return [...new Set([
    ...runtimeToolStoreTargets(),
    ...composeAgentStateMounts().map((mount) => mount.target),
    AGENT_HOME_TARGETS.gitConfig,
  ])].sort();
}

export function agentHomeMountParents(): string[] {
  const parents = new Set<string>();
  for (const target of agentHomeMountTargets()) {
    for (let dir = path.posix.dirname(target); dir.startsWith(`${AGENT_HOME}/`); dir = path.posix.dirname(dir)) {
      parents.add(dir);
    }
  }
  return [...parents].sort();
}

export const AGENT_HOME_DIRS_BEGIN = "# runfree:agent-home-dirs:begin";
export const AGENT_HOME_DIRS_END = "# runfree:agent-home-dirs:end";

function markerLine(lines: readonly string[], marker: string): number {
  const hits = lines.flatMap((line, index) => (line.trim() === marker ? [index] : []));
  if (hits.length !== 1) {
    throw new Error(`agent Dockerfile must contain "${marker}" exactly once; found ${hits.length}`);
  }
  return hits[0] as number;
}

// Reads the agent-home install block of the agent Dockerfile: one quoted
// path per line between the markers, with ${USERNAME} expanded to the ARG
// default. The static gate holds the result equal to agentHomeMountParents().
export function parseAgentHomeDirsBlock(dockerfile: string): { username: string; dirs: string[] } {
  const lines = dockerfile.split("\n");
  const arg = lines.map((line) => /^ARG USERNAME=(\S+)\s*$/u.exec(line.trim())).find(Boolean);
  if (!arg?.[1]) throw new Error("agent Dockerfile has no ARG USERNAME default");
  const username = arg[1];
  const begin = markerLine(lines, AGENT_HOME_DIRS_BEGIN);
  const end = markerLine(lines, AGENT_HOME_DIRS_END);
  if (end <= begin) throw new Error(`agent Dockerfile "${AGENT_HOME_DIRS_END}" must follow "${AGENT_HOME_DIRS_BEGIN}"`);
  const blockLines = lines.slice(begin + 1, end);
  const dirs = blockLines.map((line, index) => {
    const trimmed = line.trim();
    const match = /^"([^"]+)"\s*(\\)?$/u.exec(trimmed);
    if (!match?.[1]) throw new Error(`agent Dockerfile agent-home block line ${index + 1} is unparsable: ${trimmed}`);
    const isLast = index === blockLines.length - 1;
    const hasContinuation = match[2] !== undefined;
    // Every line but the last must continue the install -d instruction, and
    // the last line must end it: a misplaced "\" here does not fail the
    // build (install -d still gets a list of quoted paths), it just hands
    // BuildKit the wrong one — either swallowing the end marker and the next
    // instruction into this one, or splitting the block mid-continuation.
    if (!isLast && !hasContinuation) {
      throw new Error(`agent Dockerfile agent-home block line ${index + 1} is missing its trailing "\\" to continue the install -d instruction: ${trimmed}`);
    }
    if (isLast && hasContinuation) {
      throw new Error(`agent Dockerfile agent-home block line ${index + 1} must not end with "\\": it is the last entry and ends the install -d instruction: ${trimmed}`);
    }
    return match[1].replaceAll("${USERNAME}", username);
  });
  return { username, dirs: dirs.sort() };
}
