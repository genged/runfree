import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { beforeAllowedRequest, type ProxyRequest } from "@runfree/proxy/policy";
import { type PolicyJson, validateNetworkPolicy } from "@runfree/runtime-contracts/network-policy";

import { SERVICES } from "../../../../scripts/services.ts";
import { flushWarnings, setOutputWriterForTest } from "../warnings.ts";
import { prepareMcpRuntime } from "./mcp.ts";

const MCP_TOKEN = "mcp-real-token";
const GITHUB_TOKEN = "github-real-token";

// The effective github token as the service compiles it: Bearer on the API
// hosts, and Basic on github.com scoped to git smart-HTTP and Git LFS only.
function githubServicePolicy(): PolicyJson {
  const credential = SERVICES.github?.credential;
  if (!credential) throw new Error("github service has no credential");
  return {
    hosts: SERVICES.github.hosts.map((entry) => entry.host).sort(),
    tokens: {
      github: {
        description: credential.tokenDescription,
        allowAnonymous: true,
        credentials: structuredClone(credential.credentials),
      },
    },
  };
}

function injectedAuthorization(policy: PolicyJson, tokens: Record<string, string>, method: string, url: string) {
  const loaded = validateNetworkPolicy(policy);
  const req: ProxyRequest = { method, url, headers: { Authorization: "Bearer agent-placeholder" } };
  const mutation = beforeAllowedRequest({
    v: 1,
    host: new URL(url).hostname,
    port: 443,
    policyGeneration: "sha256:test-policy",
    admittedAtMs: Date.now(),
    connectionSerial: 1,
    stage: "request",
  }, req, {
    allowedHosts: loaded.allowedHosts,
    credentials: loaded.credentials,
    writeApproval: "allow",
    tokenReader: (name) => tokens[name] ?? null,
    log: () => {},
  });
  return mutation.headers?.authorization;
}

function scopedPolicy(pathPrefix?: string): PolicyJson {
  return {
    hosts: ["mcp.example.com"],
    tokens: {
      existing: {
        description: "existing token",
        credentials: [{ host: "mcp.example.com", header: "Authorization", scheme: "bearer", ...(pathPrefix ? { pathPrefix } : {}) }],
      },
    },
  };
}

describe("MCP header-token ownership with protocol-scoped mappings", () => {
  let tmp: string;
  let projectRoot: string;
  let hostHome: string;
  let output: string[];

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-owner-"));
    projectRoot = path.join(tmp, "project");
    hostHome = path.join(tmp, "host-home");
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.mkdirSync(path.join(hostHome, ".codex"), { recursive: true });
    flushWarnings();
    output = [];
    setOutputWriterForTest((line) => output.push(line));
  });

  afterEach(() => {
    flushWarnings();
    setOutputWriterForTest(undefined);
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function prepare(url: string, policy: PolicyJson) {
    fs.writeFileSync(path.join(hostHome, ".claude.json"), JSON.stringify({
      mcpServers: { ghmcp: { type: "http", url, headers: { Authorization: "Bearer ${GH_MCP_TOKEN}" } } },
    }));
    const runDir = path.join(tmp, "run");
    const result = prepareMcpRuntime({
      callbackPort: 47638,
      claudeConfigPath: path.join(runDir, "claude.json"),
      claudeMcpConfigPath: path.join(runDir, "claude-mcp.json"),
      codexDir: path.join(runDir, "codex"),
      env: { HOME: hostHome, CODEX_HOME: path.join(hostHome, ".codex") },
      mcpOAuthPolicyPath: path.join(runDir, "mcp-oauth-policy.json"),
      policy,
      projectRoot,
      tokenConfig: {},
    });
    flushWarnings();
    return { ...result, warnings: output.join("\n") };
  }

  function mcpTokenName(policy: PolicyJson): string {
    const name = Object.keys(policy.tokens ?? {}).find((tokenName) => tokenName.startsWith("mcp-claude-ghmcp"));
    if (!name) throw new Error("MCP token binding missing");
    return name;
  }

  test("a git-http/git-lfs mapping on the same host and header does not own the MCP credential", () => {
    const result = prepare("https://github.com/mcp", githubServicePolicy());

    expect(result.warnings).not.toContain("already uses proxy token");
    const tokenName = mcpTokenName(result.policy);
    expect(result.policy.tokens?.[tokenName]?.credentials).toEqual([
      { host: "github.com", header: "Authorization", scheme: "bearer", pathPrefix: "/mcp" },
    ]);
    expect(result.tokenConfig[tokenName]).toEqual({ source: "env", env: "GH_MCP_TOKEN" });

    // The combined policy validates and the proxy picks the MCP token for MCP
    // traffic and the git Basic credential for git traffic.
    const loaded = validateNetworkPolicy(result.policy);
    const tokens: Record<string, string> = { github: GITHUB_TOKEN, [tokenName]: MCP_TOKEN };
    const send = (method: string, url: string) => {
      const req: ProxyRequest = { method, url, headers: { Authorization: "Bearer agent-placeholder" } };
      const mutation = beforeAllowedRequest({
        v: 1,
        host: "github.com",
        port: 443,
        policyGeneration: "sha256:test-policy",
        admittedAtMs: Date.now(),
        connectionSerial: 1,
        stage: "request",
      }, req, {
        allowedHosts: loaded.allowedHosts,
        credentials: loaded.credentials,
        writeApproval: "allow",
        tokenReader: (name) => tokens[name] ?? null,
        log: () => {},
      });
      return mutation.headers?.authorization;
    };
    expect(send("POST", "https://github.com/mcp")).toBe(`Bearer ${MCP_TOKEN}`);
    expect(send("GET", "https://github.com/owner/repo.git/info/refs?service=git-upload-pack"))
      .toBe(`Basic ${Buffer.from(`x-access-token:${GITHUB_TOKEN}`).toString("base64")}`);
    expect(send("POST", "https://github.com/owner/repo.git/info/lfs/objects/batch"))
      .toBe(`Basic ${Buffer.from(`x-access-token:${GITHUB_TOKEN}`).toString("base64")}`);
  });

  test("an unscoped mapping on the same host and header still owns the MCP credential", () => {
    const policy: PolicyJson = {
      hosts: ["mcp.example.com"],
      tokens: {
        existing: {
          description: "existing token",
          credentials: [{ host: "mcp.example.com", header: "Authorization", scheme: "bearer" }],
        },
      },
    };
    const result = prepare("https://mcp.example.com/mcp", policy);

    expect(result.warnings).toContain("mcp.example.com Authorization already uses proxy token existing");
    expect(Object.keys(result.policy.tokens ?? {})).toEqual(["existing"]);
    expect(result.tokenConfig).toEqual({});
  });

  // An existing mapping owns the MCP credential only when the proxy would
  // select it for the MCP endpoint's path.
  test("an existing mapping scoped to a disjoint path does not own the MCP credential", () => {
    const result = prepare("https://mcp.example.com/mcp", scopedPolicy("/api"));

    expect(result.warnings).not.toContain("already uses proxy token");
    const tokenName = mcpTokenName(result.policy);
    expect(result.policy.tokens?.[tokenName]?.credentials).toEqual([
      { host: "mcp.example.com", header: "Authorization", scheme: "bearer", pathPrefix: "/mcp" },
    ]);
    const tokens = { existing: "existing-real-token", [tokenName]: MCP_TOKEN };
    expect(injectedAuthorization(result.policy, tokens, "POST", "https://mcp.example.com/mcp")).toBe(`Bearer ${MCP_TOKEN}`);
    expect(injectedAuthorization(result.policy, tokens, "GET", "https://mcp.example.com/api/items")).toBe("Bearer existing-real-token");
  });

  test("a prefix that only shares leading characters is disjoint, not covering", () => {
    const result = prepare("https://mcp.example.com/apix/mcp", scopedPolicy("/api"));
    expect(result.warnings).not.toContain("already uses proxy token");
    expect(result.policy.tokens?.[mcpTokenName(result.policy)]?.credentials)
      .toEqual([{ host: "mcp.example.com", header: "Authorization", scheme: "bearer", pathPrefix: "/apix/mcp" }]);
  });

  test("an existing mapping scoped to a covering path still owns the MCP credential", () => {
    const policy = scopedPolicy("/api");
    const result = prepare("https://mcp.example.com/api/v4/mcp", policy);

    expect(result.warnings).toContain("mcp.example.com Authorization already uses proxy token existing");
    expect(result.policy).toEqual(policy);
    expect(result.tokenConfig).toEqual({});
    expect(injectedAuthorization(result.policy, { existing: "existing-real-token" }, "POST", "https://mcp.example.com/api/v4/mcp"))
      .toBe("Bearer existing-real-token");
  });
});
