import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import { composeAgentStateMounts } from "../agents.ts";
import {
  AGENT_HOME,
  AGENT_HOME_DIRS_BEGIN,
  AGENT_HOME_DIRS_END,
  agentHomeMountParents,
  agentHomeMountTargets,
  parseAgentHomeDirsBlock,
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

const DOCKERFILE = fileURLToPath(new URL("../../../agent-runtime/agent/Dockerfile", import.meta.url));

function expectedDirs(): string[] {
  return [...agentHomeMountParents(), `${AGENT_HOME}/.local/bin`].sort();
}

function fixtureDockerfile(dirs: readonly string[], options: { begin?: boolean; end?: boolean } = {}): string {
  return [
    "ARG USERNAME=agent",
    'RUN install -d -m 0755 -o "${USERNAME}" -g "${USERNAME}" \\',
    ...(options.begin === false ? [] : [`      ${AGENT_HOME_DIRS_BEGIN}`]),
    ...dirs.map((dir, index) => `      "${dir.replace(AGENT_HOME, "/home/${USERNAME}")}"${index < dirs.length - 1 ? " \\" : ""}`),
    ...(options.end === false ? [] : [AGENT_HOME_DIRS_END]),
  ].join("\n");
}

describe("agent Dockerfile agent-home block", () => {
  test("the marked block equals the derived parents plus ~/.local/bin", () => {
    const parsed = parseAgentHomeDirsBlock(fs.readFileSync(DOCKERFILE, "utf8"));
    expect(parsed.username).toBe("agent");
    expect(parsed.dirs).toEqual(expectedDirs());
  });

  test("a fixture with the exact list parses", () => {
    expect(parseAgentHomeDirsBlock(fixtureDockerfile(expectedDirs())).dirs).toEqual(expectedDirs());
  });

  test("a block that omits ~/.local/share does not equal the list", () => {
    const dirs = expectedDirs().filter((dir) => dir !== `${AGENT_HOME}/.local/share`);
    const parsed = parseAgentHomeDirsBlock(fixtureDockerfile(dirs));
    expect(parsed.dirs).not.toContain(`${AGENT_HOME}/.local/share`);
    expect(parsed.dirs).not.toEqual(expectedDirs());
  });

  test("a block with an extra path does not equal the list", () => {
    const parsed = parseAgentHomeDirsBlock(fixtureDockerfile([...expectedDirs(), `${AGENT_HOME}/.stale`]));
    expect(parsed.dirs).toContain(`${AGENT_HOME}/.stale`);
    expect(parsed.dirs).not.toEqual(expectedDirs());
  });

  test("missing or duplicated markers are refused by name", () => {
    expect(() => parseAgentHomeDirsBlock(fixtureDockerfile(expectedDirs(), { begin: false })))
      .toThrow(/runfree:agent-home-dirs:begin/);
    expect(() => parseAgentHomeDirsBlock(fixtureDockerfile(expectedDirs(), { end: false })))
      .toThrow(/runfree:agent-home-dirs:end/);
    const doubled = `${fixtureDockerfile(expectedDirs())}\n# runfree:agent-home-dirs:begin\n`;
    expect(() => parseAgentHomeDirsBlock(doubled)).toThrow(/exactly once/);
  });

  test("a non-agent USERNAME default is reported", () => {
    const parsed = parseAgentHomeDirsBlock(fixtureDockerfile(expectedDirs()).replace("ARG USERNAME=agent", "ARG USERNAME=dev"));
    expect(parsed.username).toBe("dev");
  });

  test("a missing ARG USERNAME is refused", () => {
    expect(() => parseAgentHomeDirsBlock(fixtureDockerfile(expectedDirs()).replace("ARG USERNAME=agent\n", "")))
      .toThrow(/ARG USERNAME/);
  });
});
