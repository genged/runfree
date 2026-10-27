import path from "node:path";
import { describe, expect, test } from "vitest";

import { composeAgentStateMounts } from "../agents.ts";
import {
  AGENT_HOME,
  agentHomeMountParents,
  agentHomeMountTargets,
} from "./agent-home-dirs.ts";
import {
  RUNTIME_TOOL_STORE_DEFINITIONS,
  runtimeToolStoreTargets,
  runtimeToolStoreVolumes,
  type RuntimeToolStoreName,
} from "./dependency-stores.ts";
import { AGENT_HOME_TARGETS } from "./mount-target-policy.ts";
import {
  SESSION_TEST_PROJECT,
  sessionContainerTemplateFixture,
  sessionTestDependencies,
} from "./session-container.test-harness.ts";

function homeAncestors(target: string): string[] {
  const out: string[] = [];
  for (let dir = path.posix.dirname(target); dir.startsWith(`${AGENT_HOME}/`); dir = path.posix.dirname(dir)) {
    out.push(dir);
  }
  return out;
}

describe("agent home mount parents", () => {
  test("covers the tool stores, agent state mounts, and the Git identity bind", () => {
    const targets = agentHomeMountTargets();
    for (const target of runtimeToolStoreTargets()) expect(targets).toContain(target);
    for (const mount of composeAgentStateMounts()) expect(targets).toContain(mount.target);
    expect(targets).toContain(AGENT_HOME_TARGETS.gitConfig);
  });

  test("lists every proper ancestor below /home/agent, sorted and unique", () => {
    const parents = agentHomeMountParents();
    expect(parents).toEqual([...new Set(parents)].sort());
    for (const target of agentHomeMountTargets()) {
      for (const ancestor of homeAncestors(target)) expect(parents, target).toContain(ancestor);
    }
    for (const parent of parents) {
      expect(parent.startsWith(`${AGENT_HOME}/`), parent).toBe(true);
    }
    expect(parents).toEqual(expect.arrayContaining([
      "/home/agent/.local",
      "/home/agent/.local/share",
      "/home/agent/.local/share/pnpm",
      "/home/agent/.pi",
    ]));
  });

  test("no mount target is an ancestor of another, and no parent is a mount target", () => {
    const targets = agentHomeMountTargets();
    for (const outer of targets) {
      for (const inner of targets) {
        if (outer !== inner) expect(inner.startsWith(`${outer}/`), `${outer} contains ${inner}`).toBe(false);
      }
    }
    for (const parent of agentHomeMountParents()) expect(targets).not.toContain(parent);
  });

  test("agent state mount targets are a subset of AGENT_HOME_TARGETS", () => {
    const known = Object.values(AGENT_HOME_TARGETS) as string[];
    for (const mount of composeAgentStateMounts()) expect(known).toContain(mount.target);
  });

  test("every /home/agent ancestor of every rendered session mount is listed", () => {
    const storeNames = Object.keys(RUNTIME_TOOL_STORE_DEFINITIONS) as RuntimeToolStoreName[];
    const template = sessionContainerTemplateFixture({
      dependencyOverlays: {
        ...sessionTestDependencies(),
        storeVolumes: runtimeToolStoreVolumes(SESSION_TEST_PROJECT.projectId, storeNames),
      },
    });
    const rendered = template.mounts.map((mount) => mount.target);
    for (const target of runtimeToolStoreTargets()) expect(rendered).toContain(target);
    const parents = agentHomeMountParents();
    for (const target of rendered) {
      expect(parents, `${target} is a mount target`).not.toContain(target);
      for (const ancestor of homeAncestors(target)) expect(parents, target).toContain(ancestor);
    }
  });
});
