import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { refusedHostServicePortReason } from "@runfree/runtime-contracts/host-services";
import type { PolicyJson } from "@runfree/runtime-contracts/network-policy";

import { projectHash } from "../project-identity.ts";
import { flushWarnings, setOutputWriterForTest } from "../warnings.ts";
import {
  applyPolicyAndTokensForTest,
  mcpApprovalPath,
  mcpInventory,
  mcpOAuthCallbackPort,
  prepareMcpRuntime,
  readMcpApprovals,
} from "./mcp.ts";
import { sessionCallbackPortCandidates } from "./session-mcp-callback.ts";

type PreparedServer = Parameters<typeof applyPolicyAndTokensForTest>[2][number];

// S8: every MCP preparation refusal carries its specific reason into the
// inventory decision, and the inventory prints exactly one warning line for it.
const REFUSED: Record<string, { config: Record<string, unknown>; reason: string }> = {
  badUrl: { config: { type: "http", url: "not a url" }, reason: "invalid URL" },
  plainHttp: { config: { type: "http", url: "http://insecure.example.com/mcp" }, reason: "remote HTTP MCP must use https" },
  ipLiteral: { config: { type: "http", url: "https://127.0.0.1/mcp" }, reason: "HTTPS MCP endpoint must be a hostname, not an IP address" },
  helper: { config: { type: "http", url: "https://x.example.com/mcp", headersHelper: "x" }, reason: "headersHelper would execute a host command" },
  hostCommand: { config: { command: "/usr/bin/tool" }, reason: "local stdio command must be installed in the container PATH" },
};

describe("structured MCP refusal reasons", () => {
  let tmp: string;
  let projectRoot: string;
  let hostHome: string;
  let stateDir: string;
  let output: string[];

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-loopback-"));
    projectRoot = path.join(tmp, "project");
    hostHome = path.join(tmp, "host-home");
    stateDir = path.join(tmp, "state");
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.mkdirSync(path.join(hostHome, ".codex"), { recursive: true });
    fs.mkdirSync(stateDir, { recursive: true });
    const mcpServers = Object.fromEntries(Object.entries(REFUSED).map(([name, { config }]) => [name, config]));
    fs.writeFileSync(path.join(hostHome, ".claude.json"), `${JSON.stringify({ mcpServers }, null, 2)}\n`);
    flushWarnings();
    output = [];
    setOutputWriterForTest((line) => output.push(line));
  });

  afterEach(() => {
    flushWarnings();
    setOutputWriterForTest(undefined);
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const env = () => ({ HOME: hostHome, CODEX_HOME: path.join(hostHome, ".codex") });

  function warnings(): string[] {
    flushWarnings();
    const lines = output;
    output = [];
    return lines;
  }

  function inventory() {
    return mcpInventory({ projectRoot, env: env(), approvalPath: mcpApprovalPath(stateDir) });
  }

  test("each refusal reports its specific reason and is excluded from generated config", () => {
    const entries = inventory().entries.filter((entry) => entry.agent === "claude");
    warnings();
    const byName = new Map(entries.map((entry) => [entry.name, entry]));
    for (const [name, { reason }] of Object.entries(REFUSED)) {
      const entry = byName.get(name);
      expect(entry?.decision, name).toEqual({ status: "unsupported", reason });
      expect(entry?.target, name).toBe("excluded");
    }
  });

  test("each refusal prints exactly one warning line per inventory call", () => {
    for (let call = 0; call < 2; call += 1) {
      inventory();
      const lines = warnings();
      for (const [name, { reason }] of Object.entries(REFUSED)) {
        const matching = lines.filter((line) => line.includes(`server ${name} `));
        expect(matching, `${name} call ${call}`).toHaveLength(1);
        expect(matching[0]?.endsWith(` runfree warning: mcp: skipped claude server ${name} reason=${reason}`), `${name} call ${call}`).toBe(true);
      }
    }
  });

  test("inventory JSON carries the reason", () => {
    const json = JSON.stringify(inventory().entries);
    warnings();
    for (const { reason } of Object.values(REFUSED)) expect(json).toContain(reason);
  });
});

// B1: MCP policy hosts are projected only from the prepared server's
// `endpoint`, never from a generated client config URL. A loopback server's
// generated config points at `127.0.0.1` and has no endpoint, so nothing it
// carries can reach the egress allowlist.
describe("MCP policy host projection", () => {
  let tmp: string;
  let projectRoot: string;
  let hostHome: string;
  let stateDir: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-projection-"));
    projectRoot = path.join(tmp, "project");
    hostHome = path.join(tmp, "host-home");
    stateDir = path.join(tmp, "state");
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.mkdirSync(path.join(hostHome, ".codex"), { recursive: true });
    fs.mkdirSync(stateDir, { recursive: true });
    flushWarnings();
    setOutputWriterForTest(() => undefined);
  });

  afterEach(() => {
    flushWarnings();
    setOutputWriterForTest(undefined);
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  test("user-scope HTTPS, OAuth, Codex bearer, and STDIO servers project exactly their endpoint hosts", () => {
    fs.writeFileSync(path.join(hostHome, ".claude.json"), `${JSON.stringify({
      mcpServers: {
        publicMcp: { type: "http", url: "https://mcp.example.com/mcp" },
        oauthMcp: { type: "http", url: "https://oauth.example.com/mcp", oauth: true },
        stdioMcp: { command: "node", args: ["server.js"] },
      },
    }, null, 2)}\n`);
    fs.writeFileSync(path.join(hostHome, ".codex", "config.toml"), [
      "[mcp_servers.bearer_mcp]",
      'url = "https://bearer.example.com/mcp"',
      'bearer_token_env_var = "BEARER_MCP_TOKEN"',
      "",
    ].join("\n"));
    const runDir = path.join(tmp, "run");
    fs.mkdirSync(runDir, { recursive: true });
    const result = prepareMcpRuntime({
      approvalPath: mcpApprovalPath(stateDir),
      callbackPort: 47638,
      claudeConfigPath: path.join(runDir, "claude.json"),
      claudeMcpConfigPath: path.join(runDir, "claude-mcp.json"),
      codexDir: path.join(runDir, "codex"),
      env: { HOME: hostHome, CODEX_HOME: path.join(hostHome, ".codex") },
      mcpOAuthPolicyPath: path.join(runDir, "mcp-oauth-policy.json"),
      mcpOperationPolicyPath: path.join(runDir, "mcp-operation-policy.json"),
      policy: { hosts: [], tokens: {} },
      projectRoot,
      tokenConfig: {},
    });
    // Characterization: identical before and after the endpoint-only change,
    // since every accepted HTTPS URL's endpoint host is its normalized hostname.
    expect(result.policy.hosts).toEqual(["bearer.example.com", "mcp.example.com", "oauth.example.com"]);
  });

  function server(overrides: Partial<PreparedServer>): PreparedServer {
    return { agent: "claude", auth: "none", name: "local", source: "user", tokenBindings: [], transport: "http", ...overrides };
  }

  test("an http-loopback server without an endpoint adds no policy host", () => {
    const policy: PolicyJson = { hosts: ["existing.example.com"], tokens: {} };
    applyPolicyAndTokensForTest(policy, {}, [server({
      transport: "http-loopback",
      claudeConfig: { type: "http", url: "http://127.0.0.1:8089/mcp" },
    })]);
    expect(policy.hosts).toEqual(["existing.example.com"]);
    expect(policy.hosts).not.toContain("127.0.0.1");
  });

  test("an http server's config URL without an endpoint adds no policy host", () => {
    const policy: PolicyJson = { hosts: ["existing.example.com"], tokens: {} };
    applyPolicyAndTokensForTest(policy, {}, [server({
      claudeConfig: { type: "http", url: "https://config-only.example.com/mcp" },
      codexConfig: { url: "https://codex-config-only.example.com/mcp" },
    })]);
    expect(policy.hosts).toEqual(["existing.example.com"]);
  });

  test("an http server projects its endpoint host, not its config URL host", () => {
    const policy: PolicyJson = { hosts: [], tokens: {} };
    applyPolicyAndTokensForTest(policy, {}, [server({
      claudeConfig: { type: "http", url: "https://config.example.com/mcp" },
      endpoint: { host: "endpoint.example.com", path: "/mcp" },
    })]);
    expect(policy.hosts).toEqual(["endpoint.example.com"]);
  });
});

describe("MCP approval record transports", () => {
  let tmp: string;
  let projectRoot: string;
  let approvalFile: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-approval-"));
    projectRoot = path.join(tmp, "project");
    fs.mkdirSync(projectRoot, { recursive: true });
    approvalFile = mcpApprovalPath(path.join(tmp, "state"));
    fs.mkdirSync(path.dirname(approvalFile), { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const record = (transport: string) => ({
    agent: "claude",
    approvedAt: "2026-10-15T00:00:00.000Z",
    auth: "none",
    digest: "sha256:abc",
    schemaVersion: 1,
    server: "local",
    source: "project",
    summary: `claude local ${transport}/none`,
    transport,
  });

  test("keeps an http-loopback record and drops an unknown transport", () => {
    fs.writeFileSync(approvalFile, `${JSON.stringify({
      approvals: { loopback: record("http-loopback"), ftp: record("ftp") },
      projectHash: projectHash(projectRoot),
      schemaVersion: 1,
    })}\n`);
    const approvals = readMcpApprovals(projectRoot, approvalFile).approvals;
    expect(Object.keys(approvals)).toEqual(["loopback"]);
    expect(approvals.loopback?.transport).toBe("http-loopback");
  });
});

// N2 (T5 half): every MCP OAuth callback port Runfree picks lies inside the
// block host-service policy refuses, so a host service can never claim one.
describe("MCP callback ports stay inside the refused host-service block", () => {
  test("the refused block is exactly 47100-48099", () => {
    expect(refusedHostServicePortReason(47100)).toBeTypeOf("string");
    expect(refusedHostServicePortReason(48099)).toBeTypeOf("string");
    expect(refusedHostServicePortReason(47099)).toBeUndefined();
    expect(refusedHostServicePortReason(48100)).toBeUndefined();
  });

  test("project and session callback ports fall inside the block", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-ports-"));
    try {
      const inBlock = (port: number) => port >= 47100 && port <= 48099;
      for (let index = 0; index < 200; index += 1) {
        const root = path.join(tmp, `project-${index}`);
        const port = mcpOAuthCallbackPort(root);
        expect(inBlock(port), `${root} -> ${port}`).toBe(true);
        if (index < 20) {
          const sessionId = crypto.randomUUID();
          for (const candidate of sessionCallbackPortCandidates(root, sessionId)) {
            expect(inBlock(candidate), `${root} ${sessionId} -> ${candidate}`).toBe(true);
          }
        }
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
