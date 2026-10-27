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
