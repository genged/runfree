import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { defaultConfig, projectControlPaths, type ProjectInfo } from "./config.ts";
import { projectHash } from "./project-identity.ts";
import { networkFromSubnet, resolveRuntimeNetwork, subnetOverlaps } from "./network.ts";
import { SESSION_SOURCE_IP_FIRST_HOST } from "./runtime/session-container-reconciliation.ts";

let tmp: string;

function projectInfo(projectRoot: string): ProjectInfo {
  const runfreeDir = path.join(projectRoot, ".runfree");
  const stateDir = path.join(runfreeDir, "state");
  return {
    config: defaultConfig(),
    paths: {
      runfreeDir,
      agentEnvPath: path.join(runfreeDir, "config", "agent.env"),
      claudeConfigPath: path.join(runfreeDir, "state", "claude.json"),
      claudeMcpConfigPath: path.join(runfreeDir, "state", "mounts", "claude-mcp.json"),
      claudeDir: path.join(runfreeDir, "state", "claude"),
      codexDir: path.join(runfreeDir, "state", "codex"),
      configPath: path.join(runfreeDir, "runfree.json"),
      ...projectControlPaths(stateDir),
      gitConfigPath: path.join(runfreeDir, "state", "gitconfig"),
      inboxDir: path.join(runfreeDir, "state", "inbox"),
      projectCodexDirMaskPath: path.join(runfreeDir, "state", "mounts", "project-codex-mask"),
      mcpOAuthPolicyPath: path.join(runfreeDir, "state", "oauth-mediation-policy.json"),
      proxyCaCertDir: path.join(runfreeDir, "state", "proxy-ca", "public"),
      proxyCaKeyDir: path.join(runfreeDir, "state", "proxy-ca", "private"),
      policyPath: path.join(runfreeDir, "network-policy.json"),
      sessionsDir: path.join(runfreeDir, "state", "sessions"),
      stateDir,
      tokenConfigPath: path.join(path.dirname(projectRoot), "config", "runfree", "projects", projectHash(projectRoot), "tokens.json"),
    },
  };
}

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-network-tests-")));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("runtime network allocation", () => {
  test("detects cidr overlap", () => {
    expect(subnetOverlaps("172.30.10.0/24", "172.30.10.0/24")).toBe(true);
    expect(subnetOverlaps("172.30.10.0/24", "172.30.0.0/16")).toBe(true);
    expect(subnetOverlaps("172.30.10.0/24", "172.30.11.0/24")).toBe(false);
  });

  test("persists a deterministic project network outside user config", () => {
    const projectRoot = path.join(tmp, "project");
    const project = projectInfo(projectRoot);

    const network = resolveRuntimeNetwork(projectRoot, project, []);

    expect(network.subnet).toMatch(/^172\.(30|31|28|29)\.\d+\.0\/24$/);
    expect(network.proxyIp).toMatch(/\.\d+\.10$/);
    expect(network.agentIp).toMatch(/\.\d+\.11$/);
    expect(network.callbackSidecarIp).toMatch(/\.\d+\.12$/);
    expect(network.proxyEgressSubnet).toMatch(/^172\.(30|31|28|29)\.\d+\.0\/24$/);
    expect(network.proxyEgressSubnet).not.toBe(network.subnet);
    expect(network.proxyEgressGateway).toMatch(/\.\d+\.1$/);
    expect(network.proxyEgressIp).toMatch(/\.\d+\.10$/);
    expect(fs.existsSync(path.join(project.paths.stateDir, "runtime-network.json"))).toBe(true);
    expect(fs.existsSync(project.paths.configPath)).toBe(false);
  });

  test("chooses another candidate when the first subnet overlaps", () => {
    const projectRoot = path.join(tmp, "project");
    const project = projectInfo(projectRoot);
    const first = resolveRuntimeNetwork(projectRoot, project, []);
    fs.rmSync(path.join(project.paths.stateDir, "runtime-network.json"), { force: true });

    const next = resolveRuntimeNetwork(projectRoot, project, [first.subnet]);

    expect(next.subnet).not.toBe(first.subnet);
    expect(subnetOverlaps(next.subnet, first.subnet)).toBe(false);
    expect(subnetOverlaps(next.proxyEgressSubnet, first.subnet)).toBe(false);
  });

  test("manual runtime network override is authoritative", () => {
    const projectRoot = path.join(tmp, "project");
    const project = projectInfo(projectRoot);
    project.config.runtime = {
      subnet: "172.31.44.0/24",
      proxyIp: "172.31.44.10",
      agentIp: "172.31.44.11",
    };

    expect(resolveRuntimeNetwork(projectRoot, project, [])).toMatchObject({
      ...project.config.runtime,
      callbackSidecarIp: "172.31.44.12",
    });
    expect(() => resolveRuntimeNetwork(projectRoot, project, ["172.31.44.0/24"]))
      .toThrow(/overlaps existing Docker network/);
  });

  test("generated control-plane addresses stay below the session source-IP pool", () => {
    // `.11` (retired agent position) and `.12` (retired Compose callback relay)
    // are reservations no container occupies post-cutover. They are safe to keep
    // only because sessions are allocated from SESSION_SOURCE_IP_FIRST_HOST
    // upward; lowering that start would hand a session an address the
    // control-plane contract still names.
    const network = networkFromSubnet("172.30.7.0/24");
    const hostOctet = (ip: string): number => Number(ip.split(".")[3]);

    for (const [label, ip] of [
      ["proxyIp", network.proxyIp],
      ["agentIp", network.agentIp],
      ["callbackSidecarIp", network.callbackSidecarIp],
    ] as const) {
      expect(hostOctet(ip), `${label} must stay outside the session pool`).toBeLessThan(SESSION_SOURCE_IP_FIRST_HOST);
    }
  });

  test("manual runtime network override must leave room for callback sidecar", () => {
    const projectRoot = path.join(tmp, "project");
    const project = projectInfo(projectRoot);
    project.config.runtime = {
      subnet: "172.31.44.0/24",
      proxyIp: "172.31.44.10",
      agentIp: "172.31.44.12",
    };

    expect(() => resolveRuntimeNetwork(projectRoot, project, []))
      .toThrow(/callbackSidecarIp must be distinct from agentIp/);
  });
});
