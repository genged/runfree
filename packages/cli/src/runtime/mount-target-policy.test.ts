import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { composeAgentStateMounts } from "../agents.ts";
import { inboxMount } from "../inbox.ts";
import type { RuntimeComposeMount } from "./compose.ts";
import { dependencyStoreVolumes, runtimeToolStoreVolumes } from "./dependency-stores.ts";
import {
  AGENT_HOME_TARGETS,
  RUNFREE_RUNTIME_TARGETS,
  createAgentMountTargetPolicy,
  dependencyArtifactTarget,
  dependencyStoreTarget,
  classifyAgentMountTarget,
  workspaceMetadataTarget,
} from "./mount-target-policy.ts";
import { claudeMcpConfigMount, mcpProjectMaskMounts } from "./mcp.ts";

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mount-policy-"));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function workspacePolicy(projectMounts: RuntimeComposeMount[] = [
  { type: "bind", source: "/host/project", target: "/workspace" },
  { type: "bind", source: "/host/project/.runfree", target: "/workspace/.runfree", readOnly: true },
]) {
  return createAgentMountTargetPolicy(projectMounts);
}

function decision(target: string, policy = workspacePolicy()): string {
  return classifyAgentMountTarget(target, policy).decision;
}

describe("agent mount target policy", () => {
  test("allows built-in state, the exact inbox, dependency stores, workspace metadata, and dependency artifacts", () => {
    for (const target of Object.values(AGENT_HOME_TARGETS)) {
      expect(decision(target), target).toBe("allowed");
    }
    expect(decision(dependencyStoreTarget("pnpm"))).toBe("allowed");
    expect(decision(workspaceMetadataTarget("/workspace", "codex"))).toBe("allowed");
    expect(decision(RUNFREE_RUNTIME_TARGETS.claudeMcpConfig)).toBe("allowed");
    expect(classifyAgentMountTarget(RUNFREE_RUNTIME_TARGETS.inbox, workspacePolicy())).toMatchObject({
      decision: "allowed",
      kind: "runfree-inbox",
      target: RUNFREE_RUNTIME_TARGETS.inbox,
    });
    expect(decision(dependencyArtifactTarget("/workspace", "packages/app/node_modules"))).toBe("allowed");
    expect(decision(dependencyArtifactTarget("/workspace", "tools/scripts/.venv"))).toBe("allowed");
    expect(decision(dependencyArtifactTarget("/workspace", "tools/scripts/__pypackages__"))).toBe("allowed");
    expect(decision("/home/agent/.cache/uv")).toBe("allowed");
    expect(decision("/home/agent/.local/share/hatch")).toBe("allowed");
  });

  test("allows Git-layout metadata and dependency targets only under rendered project roots", () => {
    const policy = workspacePolicy([
      { type: "bind", source: "/host/project", target: "/runfree/git-layout/abc123abc123/.worktrees/feature" },
      { type: "bind", source: "/host/common.git", target: "/runfree/git-layout/abc123abc123/.git" },
      {
        type: "bind",
        source: "/host/project/.runfree",
        target: "/runfree/git-layout/abc123abc123/.worktrees/feature/.runfree",
        readOnly: true,
      },
    ]);

    expect(decision("/runfree/git-layout/abc123abc123/.worktrees/feature/.mcp.json", policy)).toBe("denied");
    expect(decision("/runfree/git-layout/abc123abc123/.worktrees/feature/.runfree-images", policy)).toBe("denied");
    expect(decision("/runfree/git-layout/abc123abc123/.worktrees/feature/packages/app/node_modules", policy)).toBe("allowed");
    expect(decision("/runfree/git-layout/abc123abc123/.worktrees/feature/tools/scripts/.venv", policy)).toBe("allowed");
    expect(decision("/runfree/git-layout/abc123abc123/.worktrees/feature/tools/scripts/__pypackages__", policy)).toBe("allowed");
    expect(decision("/runfree/git-layout/abc123abc123/other/node_modules", policy)).toBe("denied");
    expect(decision("/runfree/git-layout/abc123abc123/other/.venv", policy)).toBe("denied");
    expect(decision("/runfree/git-layout/abc123abc123/other/__pypackages__", policy)).toBe("denied");
  });

  test("rejects reserved targets before dependency allowlist classification", () => {
    const reserved = classifyAgentMountTarget("/workspace", workspacePolicy());
    expect(reserved).toMatchObject({ decision: "reserved" });
    expect(reserved).not.toHaveProperty("target");
    expect(classifyAgentMountTarget("/workspace/.runfree", workspacePolicy())).toMatchObject({ decision: "reserved" });
    expect(classifyAgentMountTarget("/workspace/.runfree/node_modules", workspacePolicy())).toMatchObject({ decision: "reserved" });
    expect(classifyAgentMountTarget("/workspace/.runfree/.venv", workspacePolicy())).toMatchObject({ decision: "reserved" });
    expect(classifyAgentMountTarget("/etc/proxy-ca", workspacePolicy())).toMatchObject({ decision: "reserved" });
    expect(classifyAgentMountTarget("/ca/private", workspacePolicy())).toMatchObject({ decision: "reserved" });
    for (const target of ["/runfree", "/runfree/other", "/runfree/inbox/sub"]) {
      expect(classifyAgentMountTarget(target, workspacePolicy()), target).toMatchObject({
        decision: "reserved",
        kind: "runfree-namespace",
      });
    }
    expect(decision("/workspace/.runfree-images")).toBe("denied");
  });

  test("resolves '.' and '..' segments before reserved and allowlist classification", () => {
    // "." must not let a dependency-looking target slip past the .runfree guard.
    expect(classifyAgentMountTarget("/workspace/./.runfree/node_modules", workspacePolicy())).toMatchObject({ decision: "reserved" });
    // ".." that escapes the workspace must resolve to its real (reserved) target.
    expect(classifyAgentMountTarget("/workspace/../../etc/node_modules", workspacePolicy())).toMatchObject({ decision: "reserved" });
    expect(classifyAgentMountTarget("/workspace/../ca/node_modules", workspacePolicy())).toMatchObject({ decision: "reserved" });
    // ".." that resolves back inside the workspace is classified by its real path.
    expect(classifyAgentMountTarget("/workspace/foo/../node_modules", workspacePolicy())).toMatchObject({
      decision: "allowed",
      target: "/workspace/node_modules",
    });
  });

  test("denies dependency-looking targets outside the rendered project roots", () => {
    expect(decision("/tmp/node_modules")).toBe("denied");
    expect(decision("/tmp/.venv")).toBe("denied");
    expect(decision("/runfree/git-layout/abc123abc123/other/.venv")).toBe("denied");
  });

  test("accepts targets produced by runtime mount producers", () => {
    fs.mkdirSync(path.join(tmp, ".codex"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".codex", "config.toml"), "\n");
    const project = {
      paths: {
        claudeMcpConfigPath: path.join(tmp, "claude-mcp.json"),
        projectCodexDirMaskPath: path.join(tmp, "mask-codex"),
      },
    };
    const producedTargets = [
      ...composeAgentStateMounts().map((mount) => mount.target),
      inboxMount().target,
      claudeMcpConfigMount(project).target,
      ...mcpProjectMaskMounts(tmp, project, "/workspace").map((mount) => mount.target),
      ...dependencyStoreVolumes("abc123abc123", ["pnpm", "npm", "yarn", "bun"]).map((mount) => mount.target),
      ...runtimeToolStoreVolumes("abc123abc123", ["pip", "uv", "poetry", "pipenv", "pdm", "hatch-cache", "hatch-data"]).map((mount) => mount.target),
    ];

    for (const target of producedTargets) {
      expect(decision(target), target).toBe("allowed");
    }
  });

  test("denies legacy Claude project-file mask targets", () => {
    const denied = classifyAgentMountTarget("/workspace/.mcp.json", workspacePolicy());
    expect(denied).toMatchObject({ decision: "denied" });
    expect(denied).not.toHaveProperty("target");
    expect(decision("/runfree/mcp/claude.json/extra")).toBe("reserved");
  });
});
