import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { evaluateRequestWriteAsk, type ProxyRequest } from "@runfree/proxy/policy";
import { validateMcpOperationPolicy, type McpOperationPolicyJson } from "@runfree/runtime-contracts/mcp-operation-policy";
import { validateNetworkPolicy, type PolicyJson, type WriteAction } from "@runfree/runtime-contracts/network-policy";
import { validateOAuthMediationPolicy } from "@runfree/runtime-contracts/oauth-mediation-policy";
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "vitest";

import { defaultConfig, projectControlPaths, type ProjectInfo } from "../config.ts";
import { approveNetworkCandidate, approveRuntimeIsolationControl } from "../control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../control/candidates.ts";
import { publishEffectivePolicyGeneration, readActiveEffectiveControl } from "../control/effective.ts";
import type { McpInventoryEntry } from "./mcp.ts";
import {
  askExposureOf,
  headlessAskExposure,
  headlessWritePosturePreflight,
  uncheckedAuthority,
  uncheckedAuthorityOf,
  type HeadlessAskExposure,
} from "./headless-write-posture.ts";
import type { RuntimeContext } from "./types.ts";

function policy(raw: PolicyJson) {
  return validateNetworkPolicy(raw);
}

function mcpPolicy(servers: McpOperationPolicyJson["servers"]) {
  return validateMcpOperationPolicy({ schemaVersion: 1, servers });
}

function server(
  id: string,
  extra: Partial<McpOperationPolicyJson["servers"][number]> = {},
): McpOperationPolicyJson["servers"][number] {
  return { id, agent: "claude", name: id, source: "user", host: "mcp.example.com", path: "/mcp", ...extra };
}

const NONE: HeadlessAskExposure = { askHosts: [], askMcp: [], globalAskWithMcp: false, unreadable: [] };

describe("askExposureOf", () => {
  test("every host allow or deny and no MCP: no exposure, and the preflight passes", () => {
    const exposure = askExposureOf({
      policy: policy({
        hosts: ["a.example.com", "b.example.com"],
        requests: { "a.example.com": { writeAction: "allow" }, "b.example.com": { writeAction: "deny" } },
      }),
    });
    expect(exposure).toEqual(NONE);
    expect(headlessWritePosturePreflight(exposure, { acceptDeniedWrites: false })).toMatchObject({ kind: "pass", accepted: false });
  });

  test("a host without writeAction and no writeApproval resolves to the default ask (plan C7)", () => {
    const exposure = askExposureOf({
      policy: policy({ hosts: ["a.example.com", "b.example.com"], requests: { "a.example.com": { writeAction: "allow" } } }),
    });
    expect(exposure.askHosts).toEqual(["b.example.com"]);
    const preflight = headlessWritePosturePreflight(exposure, { acceptDeniedWrites: false });
    expect(preflight.kind).toBe("refuse");
    if (preflight.kind !== "refuse") throw new Error("unreachable");
    expect(preflight.status).toBe(65);
    expect(preflight.message).toContain("b.example.com");
    expect(preflight.message).toContain("--accept-denied-writes");
  });

  test("--accept-denied-writes skips the refusal but keeps the exposure", () => {
    const exposure = askExposureOf({ policy: policy({ hosts: ["b.example.com"] }) });
    expect(headlessWritePosturePreflight(exposure, { acceptDeniedWrites: true })).toEqual({ kind: "pass", accepted: true, exposure });
  });

  test("host allow with an MCP tool override of ask is exposure, even under writeApproval deny", () => {
    const exposure = askExposureOf({
      policy: policy({ hosts: ["mcp.example.com"], requests: { "mcp.example.com": { writeAction: "allow" } }, writeApproval: "deny" }),
      mcp: mcpPolicy([server("srv", { tools: { create_issue: { writeAction: "ask" }, search: { writeAction: "allow" } } })]),
    });
    expect(exposure.askHosts).toEqual([]);
    expect(exposure.globalAskWithMcp).toBe(false);
    expect(exposure.askMcp).toEqual([{ serverId: "srv", agent: "claude", name: "srv", defaultAsk: false, askTools: ["create_issue"] }]);
    expect(headlessWritePosturePreflight(exposure, { acceptDeniedWrites: false }).kind).toBe("refuse");
  });

  test("an MCP server default of ask is exposure for every unlisted tool", () => {
    const exposure = askExposureOf({
      policy: policy({ hosts: [], writeApproval: "allow" }),
      mcp: mcpPolicy([server("srv", { defaultToolWriteAction: "ask", tools: { search: { writeAction: "allow" } } })]),
    });
    expect(exposure.askMcp).toEqual([{ serverId: "srv", agent: "claude", name: "srv", defaultAsk: true, askTools: [] }]);
  });

  test("an MCP server with no default inherits the global action for unlisted tools", () => {
    const allowGlobal = askExposureOf({
      policy: policy({ hosts: [], writeApproval: "allow" }),
      mcp: mcpPolicy([server("srv")]),
    });
    expect(allowGlobal).toEqual(NONE);
  });

  test("MCP configured and the global action ask: unclassified MCP methods ask", () => {
    const exposure = askExposureOf({
      policy: policy({ hosts: ["mcp.example.com"], requests: { "mcp.example.com": { writeAction: "allow" } } }),
      mcp: mcpPolicy([server("srv", { defaultToolWriteAction: "allow" })]),
    });
    expect(exposure.globalAskWithMcp).toBe(true);
    expect(exposure.askMcp).toEqual([]);
    expect(headlessWritePosturePreflight(exposure, { acceptDeniedWrites: false }).kind).toBe("refuse");
  });

  test("no MCP and the global action ask, but every host overridden: no exposure", () => {
    const exposure = askExposureOf({
      policy: policy({ hosts: ["a.example.com"], requests: { "a.example.com": { writeAction: "deny" } }, writeApproval: "ask" }),
      mcp: mcpPolicy([]),
    });
    expect(exposure).toEqual(NONE);
  });

  // The "does not copy them" proof: the hosts the preflight names are exactly
  // the hosts where the proxy's own pre-credential evaluation holds a POST.
  test("askHosts equals the hosts where the proxy's evaluateRequestWriteAsk asks for a POST", () => {
    let seed = 0x2545f491;
    const next = (bound: number): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % bound;
    };
    const actions: Array<WriteAction | undefined> = ["allow", "ask", "deny", undefined];
    for (let round = 0; round < 200; round += 1) {
      const hosts = Array.from({ length: 1 + next(5) }, (_, index) => `h${index}.example.com`);
      const requests: NonNullable<PolicyJson["requests"]> = {};
      for (const host of hosts) {
        const action = actions[next(actions.length)];
        if (action !== undefined) requests[host] = { writeAction: action };
      }
      const writeApproval = actions[next(actions.length)];
      const loaded = policy({ hosts, requests, ...(writeApproval !== undefined ? { writeApproval } : {}) });
      const proxyAsks = loaded.allowedHosts.filter((host) => {
        const admission = {
          v: 1, host, port: 443, policyGeneration: loaded.generation, admittedAtMs: 0, connectionSerial: 1, stage: "request",
        } as unknown as Parameters<typeof evaluateRequestWriteAsk>[0];
        const req = { method: "POST", url: `https://${host}/x`, headers: { host } } as unknown as ProxyRequest;
        return evaluateRequestWriteAsk(admission, req, {
          allowedHosts: loaded.allowedHosts,
          requests: loaded.requests,
          writeApproval: loaded.writeApproval,
        }) === "ask";
      });
      expect(askExposureOf({ policy: loaded }).askHosts).toEqual(proxyAsks);
    }
  });
});

describe("uncheckedAuthorityOf", () => {
  test("names host services, mediated OAuth providers, and local MCP servers of the run's agent", () => {
    const loaded = policy({ hosts: [], hostServices: { "dev-db": { target: "host-loopback", port: 5432 } } });
    const oauth = validateOAuthMediationPolicy({
      providers: { "mcp-claude-linear": { kind: "mcp", resourceHost: "mcp.linear.app", tokenEndpoints: ["https://mcp.linear.app/token"] } },
    });
    const entries = [
      { agent: "claude", name: "fs", source: "user", target: "generated", transport: "stdio" },
      { agent: "claude", name: "local-api", source: "local", target: "generated", transport: "http-loopback" },
      { agent: "claude", name: "remote", source: "user", target: "generated", transport: "http" },
      { agent: "claude", name: "unapproved", source: "project", target: "excluded", transport: "stdio" },
      { agent: "codex", name: "codex-fs", source: "user", target: "generated", transport: "stdio" },
    ] as unknown as McpInventoryEntry[];

    expect(uncheckedAuthorityOf("claude", { policy: loaded, oauth, mcpEntries: entries })).toEqual({
      hostServices: ["dev-db"],
      oauthExchanges: ["mcp-claude-linear"],
      localMcpServers: ["fs (stdio)", "local-api (http-loopback)"],
      unreadable: [],
    });
    expect(uncheckedAuthorityOf("pi", { policy: loaded, oauth, mcpEntries: entries }).localMcpServers).toEqual([]);
  });

  test("an unreadable source is named, never shown as empty", () => {
    expect(uncheckedAuthorityOf("claude", {})).toEqual({
      hostServices: [],
      oauthExchanges: [],
      localMcpServers: [],
      unreadable: ["hostServices", "oauthExchanges", "localMcpServers"],
    });
  });
});

// The readers, over a real published effective policy generation.
describe("readers", () => {
  let base: string;
  let tmp: string;

  beforeAll(() => {
    base = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-headless-posture-"));
    tmp = path.join(base, "work");
  });

  afterAll(() => {
    fs.rmSync(base, { recursive: true, force: true });
  });

  beforeEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
    fs.mkdirSync(tmp);
  });

  function projectInfo(): { projectRoot: string; project: ProjectInfo } {
    const projectRoot = path.join(tmp, "project");
    const runfreeDir = path.join(projectRoot, ".runfree");
    const stateDir = path.join(tmp, "state");
    const project: ProjectInfo = {
      config: defaultConfig(),
      paths: {
        runfreeDir,
        agentEnvPath: path.join(runfreeDir, "config", "agent.env"),
        claudeConfigPath: path.join(stateDir, "claude.json"),
        claudeMcpConfigPath: path.join(stateDir, "mounts", "claude-mcp.json"),
        claudeDir: path.join(stateDir, "claude"),
        codexDir: path.join(stateDir, "codex"),
        configPath: path.join(runfreeDir, "runfree.json"),
        ...projectControlPaths(stateDir),
        gitConfigPath: path.join(stateDir, "gitconfig"),
        inboxDir: path.join(stateDir, "inbox"),
        projectCodexDirMaskPath: path.join(stateDir, "mounts", "project-codex-mask"),
        mcpOperationPolicyPath: path.join(stateDir, "mcp-operation-policy.json"),
        mcpOAuthPolicyPath: path.join(stateDir, "oauth-mediation-policy.json"),
        proxyCaCertDir: path.join(stateDir, "proxy-ca", "public"),
        proxyCaKeyDir: path.join(stateDir, "proxy-ca", "private"),
        policyPath: path.join(runfreeDir, "network-policy.json"),
        sessionsDir: path.join(stateDir, "sessions"),
        stateDir,
        tokenConfigPath: path.join(stateDir, "tokens.json"),
      },
    };
    // Approved per test: approvals bind the project directory's identity, so
    // a copied snapshot reads as a replaced directory.
    fs.mkdirSync(path.dirname(project.paths.policyPath), { recursive: true });
    fs.writeFileSync(project.paths.policyPath, '{"version":2,"hosts":[]}\n');
    const candidate = captureDesiredPolicyCandidate(projectRoot, project.paths.controlCandidatesDir);
    approveNetworkCandidate(projectRoot, project, candidate, "network-project", "interactive");
    approveNetworkCandidate(projectRoot, project, candidate, "network-local", "interactive");
    approveRuntimeIsolationControl(projectRoot, project, "interactive");
    return { projectRoot, project };
  }

  function context(projectRoot: string, project: ProjectInfo, env: NodeJS.ProcessEnv = {}): RuntimeContext {
    return { projectRoot, project, env, runtimeRoot: path.join(tmp, "runtime") } as unknown as RuntimeContext;
  }

  test("reads the enforced policy and MCP operation policy from the active generation", () => {
    const { projectRoot, project } = projectInfo();
    publishEffectivePolicyGeneration(projectRoot, project, {
      effectiveNetworkPolicy: { hosts: ["mcp.example.com", "api.example.com"], requests: { "mcp.example.com": { writeAction: "allow" } }, writeApproval: "deny" },
      mcpOperationPolicy: { schemaVersion: 1, servers: [server("srv", { tools: { create_issue: { writeAction: "ask" } } })] },
    });

    expect(headlessAskExposure(context(projectRoot, project))).toEqual({
      askHosts: [],
      askMcp: [{ serverId: "srv", agent: "claude", name: "srv", defaultAsk: false, askTools: ["create_issue"] }],
      globalAskWithMcp: false,
      unreadable: [],
    });
  });

  test("no published generation is unreadable exposure, so the preflight refuses", () => {
    const { projectRoot, project } = projectInfo();
    const exposure = headlessAskExposure(context(projectRoot, project));
    expect(exposure.unreadable).toHaveLength(1);
    expect(headlessWritePosturePreflight(exposure, { acceptDeniedWrites: false }).kind).toBe("refuse");
  });

  test("a corrupt MCP operation policy payload is unreadable exposure", () => {
    const { projectRoot, project } = projectInfo();
    const generation = publishEffectivePolicyGeneration(projectRoot, project, {
      effectiveNetworkPolicy: { hosts: [], writeApproval: "allow" },
      mcpOperationPolicy: { schemaVersion: 1, servers: [server("srv", { defaultToolWriteAction: "allow" })] },
    });
    expect(headlessAskExposure(context(projectRoot, project))).toEqual(NONE);
    const payload = path.join(generation.proxyDirectory, "mcp-operation-policy.json");
    fs.chmodSync(payload, 0o600);
    fs.writeFileSync(payload, "{}\n");

    const exposure = headlessAskExposure(context(projectRoot, project));
    expect(exposure.unreadable).toHaveLength(1);
    expect(headlessWritePosturePreflight(exposure, { acceptDeniedWrites: false }).kind).toBe("refuse");
  });

  test("lists the generation's host services and a user stdio MCP server", () => {
    const { projectRoot, project } = projectInfo();
    publishEffectivePolicyGeneration(projectRoot, project, {
      effectiveNetworkPolicy: { hosts: [], hostServices: { "dev-db": { target: "host-loopback", port: 5432 } } },
    });
    expect(readActiveEffectiveControl(project)).toBeDefined();
    const home = path.join(tmp, "home");
    fs.mkdirSync(home);
    fs.writeFileSync(path.join(home, ".claude.json"), JSON.stringify({ mcpServers: { fs: { command: "mcp-fs", args: ["serve"] } } }));

    expect(uncheckedAuthority(context(projectRoot, project, { HOME: home }), "claude")).toEqual({
      hostServices: ["dev-db"],
      oauthExchanges: [],
      localMcpServers: ["fs (stdio)"],
      unreadable: [],
    });
  });
});
