// F1: the command-layer wiring of the loopback reach source. `mcp list`,
// `explain`, `configure`, and `enable` get `mcpLoopbackDeps`; the admin layer
// calls `hostServices()` only when an entry is loopback. These tests pin what
// the command layer hands it: a lazy read of the selected effective policy
// generation that reports "none selected" as undefined and a corrupt selection
// as a throw, never as an empty host-service set.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { projectInfo, type ProjectInfo } from "../../config.ts";
import { approveNetworkCandidate, approveRuntimeIsolationControl } from "../../control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../../control/candidates.ts";
import { publishEffectivePolicyGeneration } from "../../control/effective.ts";
import { mcpLoopbackDeps } from "./mcp.ts";

describe("mcpLoopbackDeps", () => {
  let root: string;
  let stateHome: string;
  let env: NodeJS.ProcessEnv;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-loopback-deps-"));
    stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-loopback-deps-state-"));
    fs.mkdirSync(path.join(root, ".runfree"));
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), '{"version":2,"hosts":["example.com"]}\n');
    env = { XDG_STATE_HOME: stateHome, XDG_CONFIG_HOME: path.join(stateHome, "config") };
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(stateHome, { recursive: true, force: true });
  });

  function context(onProjectInfo?: () => void) {
    return {
      env,
      projectRoot: root,
      projectInfo: (): ProjectInfo => {
        onProjectInfo?.();
        return projectInfo(root, env);
      },
    };
  }

  test("building the deps reads no project state", () => {
    let reads = 0;
    mcpLoopbackDeps(context(() => {
      reads += 1;
    }));
    expect(reads).toBe(0);
  });

  test("no selected effective policy generation is undefined, not an empty host-service set", () => {
    expect(mcpLoopbackDeps(context()).hostServices()).toBeUndefined();
  });

  test("a corrupt active selection throws instead of reading as no host services", () => {
    const project = projectInfo(root, env);
    fs.mkdirSync(project.paths.controlProxyDir, { recursive: true });
    fs.writeFileSync(path.join(project.paths.controlProxyDir, "active.json"), '{"schemaVersion":1}\n');
    expect(() => mcpLoopbackDeps(context()).hostServices()).toThrow(/active control selection/);
  });

  test("a selected effective policy generation yields its host services", () => {
    const project = projectInfo(root, env);
    const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, project, candidate, "network-project", "interactive");
    approveNetworkCandidate(root, project, candidate, "network-local", "interactive");
    approveRuntimeIsolationControl(root, project, "interactive");
    publishEffectivePolicyGeneration(root, project);
    expect(mcpLoopbackDeps(context()).hostServices()).toEqual({});
  });
});
