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
  headlessWritePostureWarning,
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

const NONE: HeadlessAskExposure = { defaultAskHosts: [], ruleAskHosts: [], askMcp: [], globalAskWithMcp: false, unreadable: [] };

describe("askExposureOf", () => {
  test("every host allow or deny and no MCP: no exposure, and no warning", () => {
    const exposure = askExposureOf({
      policy: policy({
        hosts: ["a.example.com", "b.example.com"],
        requests: { "a.example.com": { writeAction: "allow" }, "b.example.com": { writeAction: "deny" } },
      }),
    });
    expect(exposure).toEqual(NONE);
    expect(headlessWritePostureWarning(exposure, { acceptDeniedWrites: false })).toBeUndefined();
  });

  test("a host without writeAction and no writeApproval resolves to the default ask (plan C7)", () => {
    const exposure = askExposureOf({
      policy: policy({ hosts: ["a.example.com", "b.example.com"], requests: { "a.example.com": { writeAction: "allow" } } }),
    });
    expect(exposure).toMatchObject({ defaultAskHosts: ["b.example.com"], ruleAskHosts: [] });
    expect(headlessWritePostureWarning(exposure, { acceptDeniedWrites: false })).toBe(
      "headless run: writes that would ask for approval are denied (1 host); run.json lists them",
    );
  });

  test("--accept-denied-writes silences the warning; the exposure is unchanged", () => {
    const exposure = askExposureOf({ policy: policy({ hosts: ["b.example.com"] }) });
    expect(exposure.defaultAskHosts).toEqual(["b.example.com"]);
    expect(headlessWritePostureWarning(exposure, { acceptDeniedWrites: true })).toBeUndefined();
  });

  test("a host with its own ask rule is listed apart from hosts that follow the default", () => {
    const exposure = askExposureOf({
      policy: policy({ hosts: ["a.example.com", "b.example.com"], requests: { "a.example.com": { writeAction: "ask" } } }),
    });
    expect(exposure).toMatchObject({ defaultAskHosts: ["b.example.com"], ruleAskHosts: ["a.example.com"] });
  });

  test("an MCP server of another agent is still exposure: the proxy matches rules by endpoint, not agent", () => {
    const exposure = askExposureOf({
      policy: policy({ hosts: ["mcp.context7.com"], requests: { "mcp.context7.com": { writeAction: "allow" } } }),
      mcp: mcpPolicy([server("ctx", { agent: "codex", name: "context7", host: "mcp.context7.com", path: "/mcp" })]),
    });
    expect(exposure.askMcp).toEqual([{
      serverId: "ctx", agent: "codex", name: "context7", host: "mcp.context7.com", path: "/mcp", defaultAsk: true, askTools: [],
    }]);
  });

  test("the warning is one line with counts, never a host list", () => {
    const hosts = Array.from({ length: 47 }, (_, index) => `h${String(index).padStart(2, "0")}.example.com`);
    const exposure = askExposureOf({
      policy: policy({ hosts: [...hosts, "mcp.context7.com"], requests: { "mcp.context7.com": { writeAction: "allow" } } }),
      mcp: mcpPolicy([
        server("a", { host: "mcp.context7.com", path: "/mcp" }),
        server("b", { agent: "codex", host: "mcp.context7.com", path: "/mcp" }),
        server("c", { host: "mcp.context7.com", path: "/other" }),
      ]),
    });
    // Counts servers: two of the three share one endpoint, and each entry names its endpoint.
    expect(headlessWritePostureWarning(exposure, { acceptDeniedWrites: false })).toBe(
      "headless run: writes that would ask for approval are denied (47 hosts, 3 MCP endpoints, unclassified MCP methods); run.json lists them",
    );
  });

  test("an unreadable policy warns that it could not be read; it does not refuse", () => {
    const exposure: HeadlessAskExposure = { ...NONE, unreadable: ["the effective policy could not be read: no effective policy generation is selected"] };
    expect(headlessWritePostureWarning(exposure, { acceptDeniedWrites: false })).toBe(
      "headless run: the write posture could not be read (the effective policy could not be read: no effective policy generation is selected); writes that would ask for approval are denied",
    );
  });

  test("host allow with an MCP tool override of ask is exposure, even under writeApproval deny", () => {
    const exposure = askExposureOf({
      policy: policy({ hosts: ["mcp.example.com"], requests: { "mcp.example.com": { writeAction: "allow" } }, writeApproval: "deny" }),
      mcp: mcpPolicy([server("srv", { tools: { create_issue: { writeAction: "ask" }, search: { writeAction: "allow" } } })]),
    });
    expect(exposure).toMatchObject({ defaultAskHosts: [], ruleAskHosts: [] });
    expect(exposure.globalAskWithMcp).toBe(false);
    expect(exposure.askMcp).toEqual([{
      serverId: "srv", agent: "claude", name: "srv", host: "mcp.example.com", path: "/mcp", defaultAsk: false, askTools: ["create_issue"],
    }]);
    expect(headlessWritePostureWarning(exposure, { acceptDeniedWrites: false })).toBe(
      "headless run: writes that would ask for approval are denied (1 MCP endpoint); run.json lists them",
    );
  });

  test("an MCP server default of ask is exposure for every unlisted tool", () => {
    const exposure = askExposureOf({
      policy: policy({ hosts: [], writeApproval: "allow" }),
      mcp: mcpPolicy([server("srv", { defaultToolWriteAction: "ask", tools: { search: { writeAction: "allow" } } })]),
    });
    expect(exposure.askMcp).toEqual([{
      serverId: "srv", agent: "claude", name: "srv", host: "mcp.example.com", path: "/mcp", defaultAsk: true, askTools: [],
    }]);
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
    expect(headlessWritePostureWarning(exposure, { acceptDeniedWrites: false })).toBe(
      "headless run: writes that would ask for approval are denied (unclassified MCP methods); run.json lists them",
    );
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
  test("default and rule ask hosts together equal the hosts where the proxy's evaluateRequestWriteAsk asks for a POST", () => {
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
      const exposure = askExposureOf({ policy: loaded });
      expect(new Set([...exposure.defaultAskHosts, ...exposure.ruleAskHosts])).toEqual(new Set(proxyAsks));
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
      defaultAskHosts: [],
      ruleAskHosts: [],
      askMcp: [{
        serverId: "srv", agent: "claude", name: "srv", host: "mcp.example.com", path: "/mcp", defaultAsk: false, askTools: ["create_issue"],
      }],
      globalAskWithMcp: false,
      unreadable: [],
    });
  });

  test("no published generation is unreadable exposure, and the warning names it", () => {
    const { projectRoot, project } = projectInfo();
    const exposure = headlessAskExposure(context(projectRoot, project));
    expect(exposure.unreadable).toHaveLength(1);
    expect(headlessWritePostureWarning(exposure, { acceptDeniedWrites: false })).toMatch(/^headless run: the write posture could not be read \(/);
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
    expect(headlessWritePostureWarning(exposure, { acceptDeniedWrites: false })).toMatch(/^headless run: the write posture could not be read \(/);
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
