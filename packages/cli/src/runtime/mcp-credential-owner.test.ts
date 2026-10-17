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

  function prepare(url: string, policy: PolicyJson, headers: Record<string, string> = { Authorization: "Bearer ${GH_MCP_TOKEN}" }) {
    fs.writeFileSync(path.join(hostHome, ".claude.json"), JSON.stringify({
      mcpServers: { ghmcp: { type: "http", url, headers } },
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

  // A root endpoint's binding has no pathPrefix, so it has the exact scope of
  // an unscoped mapping. The owner is the token the proxy selects at `/`, not
  // that exact-scope mapping.
  test("a root endpoint reuses the `/` mapping that shadows an unscoped one, as the proxy selects", () => {
    const policy: PolicyJson = {
      hosts: ["mcp.example.com"],
      tokens: {
        existing: {
          description: "existing token",
          credentials: [{ host: "mcp.example.com", header: "Authorization", scheme: "bearer" }],
        },
        root: {
          description: "root-scoped token",
          credentials: [{ host: "mcp.example.com", header: "Authorization", scheme: "bearer", pathPrefix: "/" }],
        },
      },
    };
    const tokens = { existing: "existing-real-token", root: "root-real-token" };
    expect(injectedAuthorization(policy, tokens, "POST", "https://mcp.example.com/")).toBe("Bearer root-real-token");

    const result = prepare("https://mcp.example.com/", policy);
    expect(result.warnings).toContain("mcp.example.com Authorization already uses proxy token root");
    expect(result.policy).toEqual(policy);
  });

  // Selection is host-wide: a `/` mapping on another header shadows every
  // unscoped mapping on the host, so a root endpoint's (unscoped) binding
  // could never be injected. Refuse instead of claiming the unscoped token is
  // reused or adding a mapping the proxy never selects.
  test("a root endpoint shadowed by a path-scoped mapping refuses the MCP credential", () => {
    const policy: PolicyJson = {
      hosts: ["mcp.example.com"],
      tokens: {
        existing: {
          description: "existing token",
          credentials: [{ host: "mcp.example.com", header: "Authorization", scheme: "bearer" }],
        },
        apikey: {
          description: "api key",
          credentials: [{ host: "mcp.example.com", header: "X-Api-Key", scheme: "raw", pathPrefix: "/" }],
        },
      },
    };
    const before = structuredClone(policy);
    expect(injectedAuthorization(policy, { existing: "existing-real-token", apikey: "key" }, "POST", "https://mcp.example.com/"))
      .toBeUndefined();

    expect(() => prepare("https://mcp.example.com/", policy))
      .toThrow(/mcp\.example\.com Authorization cannot be injected .*proxy token apikey .*remove that path-scoped mapping/);
    expect(policy).toEqual(before);

    // Recovery, as the refusal names it: with the path-scoped mapping
    // removed, the unscoped mapping is selected at the endpoint and owns it.
    delete policy.tokens?.apikey;
    const result = prepare("https://mcp.example.com/", policy);
    expect(result.warnings).toContain("mcp.example.com Authorization already uses proxy token existing");
    expect(injectedAuthorization(result.policy, { existing: "existing-real-token" }, "POST", "https://mcp.example.com/"))
      .toBe("Bearer existing-real-token");
  });

  test("a root endpoint with no matching path-scoped mapping adds an unscoped MCP credential the proxy injects", () => {
    const policy: PolicyJson = {
      hosts: ["mcp.example.com"],
      tokens: {
        apikey: {
          description: "api key",
          credentials: [{ host: "mcp.example.com", header: "X-Api-Key", scheme: "raw", pathPrefix: "/api" }],
        },
      },
    };
    const result = prepare("https://mcp.example.com/", policy);
    const tokenName = mcpTokenName(result.policy);
    expect(result.policy.tokens?.[tokenName]?.credentials)
      .toEqual([{ host: "mcp.example.com", header: "Authorization", scheme: "bearer" }]);
    expect(injectedAuthorization(result.policy, { apikey: "key", [tokenName]: MCP_TOKEN }, "POST", "https://mcp.example.com/"))
      .toBe(`Bearer ${MCP_TOKEN}`);
  });

  // Selection is host-wide: adding Authorization at the endpoint's prefix
  // moves the selected tier past the covering `/api` X-Api-Key mapping that an
  // earlier binding reused. Both header orders end with both headers injected.
  for (const order of ["X-Api-Key first", "Authorization first"] as const) {
    test(`a multi-header MCP server gets every header injected whatever the header order (${order})`, () => {
      const policy: PolicyJson = {
        hosts: ["mcp.example.com"],
        tokens: {
          apikey: {
            description: "api key",
            credentials: [{ host: "mcp.example.com", header: "X-Api-Key", scheme: "raw", pathPrefix: "/api" }],
          },
        },
      };
      const apiKey = { "X-Api-Key": "${MCP_KEY}" };
      const authorization = { Authorization: "Bearer ${GH_MCP_TOKEN}" };
      const headers = order === "X-Api-Key first" ? { ...apiKey, ...authorization } : { ...authorization, ...apiKey };
      const result = prepare("https://mcp.example.com/api/mcp", policy, headers);

      const loaded = validateNetworkPolicy(result.policy);
      const tokens: Record<string, string> = {
        apikey: "existing-key",
        "mcp-claude-ghmcp-auth": MCP_TOKEN,
        "mcp-claude-ghmcp-x-api-key": "mcp-key",
      };
      const req: ProxyRequest = { method: "POST", url: "https://mcp.example.com/api/mcp", headers: { Authorization: "Bearer x", "X-Api-Key": "x" } };
      const mutation = beforeAllowedRequest({
        v: 1, host: "mcp.example.com", port: 443, policyGeneration: "sha256:test-policy",
        admittedAtMs: Date.now(), connectionSerial: 1, stage: "request",
      }, req, {
        allowedHosts: loaded.allowedHosts,
        credentials: loaded.credentials,
        writeApproval: "allow",
        tokenReader: (name) => tokens[name] ?? null,
        log: () => {},
      });
      expect(mutation.headers?.authorization).toBe(`Bearer ${MCP_TOKEN}`);
      expect(mutation.headers?.["x-api-key"]).toBe("mcp-key");
    });
  }

  // Reconciliation spans servers: a later server's binding at `/api` creates
  // a tier that shadows, at `/api/mcp`, the unscoped X-Api-Key mapping an
  // earlier server reused. Both server orders inject each server's header.
  for (const order of ["nested server first", "outer server first"] as const) {
    test(`MCP servers on one host get their headers injected whatever the server order (${order})`, () => {
      const policy: PolicyJson = {
        hosts: ["mcp.example.com"],
        tokens: {
          apikey: {
            description: "api key",
            credentials: [{ host: "mcp.example.com", header: "X-Api-Key", scheme: "raw" }],
          },
        },
      };
      const nested = { nested: { type: "http", url: "https://mcp.example.com/api/mcp", headers: { "X-Api-Key": "${NESTED_KEY}" } } };
      const outer = { outer: { type: "http", url: "https://mcp.example.com/api", headers: { Authorization: "Bearer ${OUTER_TOKEN}" } } };
      fs.writeFileSync(path.join(hostHome, ".claude.json"), JSON.stringify({
        mcpServers: order === "nested server first" ? { ...nested, ...outer } : { ...outer, ...nested },
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

      const loaded = validateNetworkPolicy(result.policy);
      const tokens: Record<string, string> = {
        apikey: "existing-key",
        "mcp-claude-nested-x-api-key": "nested-key",
        "mcp-claude-outer-auth": "outer-token",
      };
      const send = (url: string) => beforeAllowedRequest({
        v: 1, host: "mcp.example.com", port: 443, policyGeneration: "sha256:test-policy",
        admittedAtMs: Date.now(), connectionSerial: 1, stage: "request",
      }, { method: "POST", url, headers: { Authorization: "Bearer x", "X-Api-Key": "x" } }, {
        allowedHosts: loaded.allowedHosts,
        credentials: loaded.credentials,
        writeApproval: "allow",
        tokenReader: (name) => tokens[name] ?? null,
        log: () => {},
      }).headers;
      expect(send("https://mcp.example.com/api/mcp")?.["x-api-key"]).toBeDefined();
      expect(send("https://mcp.example.com/api")?.authorization).toBe("Bearer outer-token");
    });
  }

  // Two servers at one endpoint both reuse the unscoped Authorization mapping
  // until a third header binding there shadows it. Reconciliation must add
  // one Authorization mapping at the endpoint and let the other server reuse
  // it, not add both (a duplicate scope that validation refuses).
  for (const order of ["bearer server first", "raw server first"] as const) {
    test(`two MCP servers at one endpoint share a reconciled Authorization mapping (${order})`, () => {
      const policy: PolicyJson = {
        hosts: ["mcp.example.com"],
        tokens: {
          existing: {
            description: "existing token",
            credentials: [{ host: "mcp.example.com", header: "Authorization", scheme: "bearer" }],
          },
        },
      };
      const url = "https://mcp.example.com/api/mcp";
      const bearer = { bearer: { type: "http", url, headers: { Authorization: "Bearer ${BEARER_TOKEN}", "X-Api-Key": "${API_KEY}" } } };
      const raw = { raw: { type: "http", url, headers: { Authorization: "${RAW_TOKEN}" } } };
      fs.writeFileSync(path.join(hostHome, ".claude.json"), JSON.stringify({
        mcpServers: order === "bearer server first" ? { ...bearer, ...raw } : { ...raw, ...bearer },
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

      const loaded = validateNetworkPolicy(result.policy);
      const authorizationMappings = Object.values(result.policy.tokens ?? {})
        .flatMap((token) => token.credentials)
        .filter((credential) => credential.header === "Authorization" && credential.pathPrefix === "/api/mcp");
      expect(authorizationMappings).toHaveLength(1);
      // Token-name order, not config order, picks the shared mapping's token,
      // so both server orders produce the same one.
      expect(Object.keys(result.policy.tokens ?? {}).filter((name) => name.endsWith("-auth"))).toEqual(["mcp-claude-raw-auth"]);
      const headers = beforeAllowedRequest({
        v: 1, host: "mcp.example.com", port: 443, policyGeneration: "sha256:test-policy",
        admittedAtMs: Date.now(), connectionSerial: 1, stage: "request",
      }, { method: "POST", url, headers: { Authorization: "Bearer x", "X-Api-Key": "x" } }, {
        allowedHosts: loaded.allowedHosts,
        credentials: loaded.credentials,
        writeApproval: "allow",
        tokenReader: (name) => `value-of-${name}`,
        log: () => {},
      }).headers;
      expect(headers?.authorization).toBeDefined();
      expect(headers?.["x-api-key"]).toBe("value-of-mcp-claude-bearer-x-api-key");
    });
  }

  // A mapping generated in this pass for one MCP server never owns another
  // server's binding at a different endpoint: each nested endpoint gets its
  // own token, whatever the server order.
  for (const order of ["outer server first", "nested server first"] as const) {
    test(`nested MCP servers on one header each get their own token (${order})`, () => {
      const outer = { outer: { type: "http", url: "https://mcp.example.com/api", headers: { Authorization: "Bearer ${OUTER}" } } };
      const nested = { nested: { type: "http", url: "https://mcp.example.com/api/mcp", headers: { Authorization: "Bearer ${NESTED}" } } };
      fs.writeFileSync(path.join(hostHome, ".claude.json"), JSON.stringify({
        mcpServers: order === "outer server first" ? { ...outer, ...nested } : { ...nested, ...outer },
      }));
      const runDir = path.join(tmp, "run");
      const result = prepareMcpRuntime({
        callbackPort: 47638,
        claudeConfigPath: path.join(runDir, "claude.json"),
        claudeMcpConfigPath: path.join(runDir, "claude-mcp.json"),
        codexDir: path.join(runDir, "codex"),
        env: { HOME: hostHome, CODEX_HOME: path.join(hostHome, ".codex") },
        mcpOAuthPolicyPath: path.join(runDir, "mcp-oauth-policy.json"),
        policy: { hosts: ["mcp.example.com"] },
        projectRoot,
        tokenConfig: {},
      });
      flushWarnings();

      expect(result.tokenConfig["mcp-claude-outer-auth"]).toEqual({ source: "env", env: "OUTER" });
      expect(result.tokenConfig["mcp-claude-nested-auth"]).toEqual({ source: "env", env: "NESTED" });
      const tokens: Record<string, string> = { "mcp-claude-outer-auth": "outer-token", "mcp-claude-nested-auth": "nested-token" };
      expect(injectedAuthorization(result.policy, tokens, "POST", "https://mcp.example.com/api")).toBe("Bearer outer-token");
      expect(injectedAuthorization(result.policy, tokens, "POST", "https://mcp.example.com/api/mcp")).toBe("Bearer nested-token");
    });
  }
});

