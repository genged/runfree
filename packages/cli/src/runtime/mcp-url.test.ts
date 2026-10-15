import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { isIpLiteralHostname } from "@runfree/runtime-contracts/network-policy";

import { flushWarnings, setOutputWriterForTest } from "../warnings.ts";
import { mcpApprovalPath, mcpInventory, prepareMcpRuntime } from "./mcp.ts";

// A remote HTTPS MCP endpoint must name a host. An IP literal would skip the
// exact-hostname policy (desired-policy validation refuses IP-literal hosts),
// so import refuses it in every form a resolver or dialer accepts.
const IP_LITERAL_REASON = "reason=HTTPS MCP endpoint must be a hostname, not an IP address";

const REFUSED: Record<string, string> = {
  loopback4: "https://127.0.0.1/mcp",
  private4port: "https://192.168.1.5:8443/mcp",
  decimal4: "https://2130706433/mcp",
  loopback6: "https://[::1]/mcp",
  private10: "https://10.0.0.1/mcp",
};
const ACCEPTED: Record<string, string> = {
  named: "https://mcp.example.com/mcp",
};

describe("IP-literal HTTPS MCP endpoints", () => {
  let tmp: string;
  let projectRoot: string;
  let hostHome: string;
  let stateDir: string;
  let output: string[];

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-url-"));
    projectRoot = path.join(tmp, "project");
    hostHome = path.join(tmp, "host-home");
    stateDir = path.join(tmp, "state");
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.mkdirSync(path.join(hostHome, ".codex"), { recursive: true });
    fs.mkdirSync(stateDir, { recursive: true });
    const mcpServers = Object.fromEntries(
      Object.entries({ ...REFUSED, ...ACCEPTED }).map(([name, url]) => [name, { type: "http", url }]),
    );
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

  test("user-scope entries with an IP-literal URL are unsupported and warn", () => {
    const inventory = mcpInventory({ projectRoot, env: env(), approvalPath: mcpApprovalPath(stateDir) });
    const lines = warnings();
    const byName = new Map(inventory.entries.filter((entry) => entry.agent === "claude").map((entry) => [entry.name, entry]));
    for (const name of Object.keys(REFUSED)) {
      const entry = byName.get(name);
      expect(entry?.decision.status, name).toBe("unsupported");
      expect(entry?.decision.reason, name).toBe(IP_LITERAL_REASON.slice("reason=".length));
      expect(entry?.target, name).toBe("excluded");
      expect(lines.some((line) => line.includes(`server ${name} `) && line.includes(IP_LITERAL_REASON)), name).toBe(true);
    }
    for (const name of Object.keys(ACCEPTED)) {
      expect(byName.get(name)?.decision.status, name).toBe("imported");
      expect(lines.some((line) => line.includes(`server ${name} `)), name).toBe(false);
    }
  });

  test("launch generates no IP-literal server or policy host", () => {
    const runDir = path.join(tmp, "run");
    fs.mkdirSync(runDir, { recursive: true });
    const result = prepareMcpRuntime({
      approvalPath: mcpApprovalPath(stateDir),
      callbackPort: 47638,
      claudeConfigPath: path.join(runDir, "claude.json"),
      claudeMcpConfigPath: path.join(runDir, "claude-mcp.json"),
      codexDir: path.join(runDir, "codex"),
      env: env(),
      mcpOAuthPolicyPath: path.join(runDir, "mcp-oauth-policy.json"),
      mcpOperationPolicyPath: path.join(runDir, "mcp-operation-policy.json"),
      policy: { hosts: [], tokens: {} },
      projectRoot,
      tokenConfig: {},
    });
    warnings();
    const generated = JSON.parse(fs.readFileSync(path.join(runDir, "claude-mcp.json"), "utf8")) as { mcpServers?: Record<string, unknown> };
    const names = Object.keys(generated.mcpServers ?? {});
    for (const name of Object.keys(REFUSED)) expect(names, name).not.toContain(name);
    expect(names).toContain("named");
    expect(result.policy.hosts).toContain("mcp.example.com");
    for (const host of ["127.0.0.1", "192.168.1.5", "2130706433", "::1", "[::1]", "10.0.0.1"]) {
      expect(result.policy.hosts, host).not.toContain(host);
    }
  });
});

// The OAuth metadata URL and token endpoints of an HTTPS entry also become
// effective policy hosts, so an IP literal there is refused the same way.
const METADATA_REASON = "OAuth metadata URL must be a hostname, not an IP address";
const TOKEN_REASON = "OAuth token endpoint must be a hostname, not an IP address";
const IP_FORMS: Record<string, string> = {
  v4: "https://10.0.0.2",
  v6: "https://[fd00::2]",
  decimal: "https://2130706433",
};

describe("IP-literal OAuth metadata and token endpoint hosts", () => {
  let tmp: string;
  let projectRoot: string;
  let hostHome: string;
  let stateDir: string;
  let output: string[];
  const expected = new Map<string, { agent: "claude" | "codex"; reason: string }>();

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-oauth-ip-"));
    projectRoot = path.join(tmp, "project");
    hostHome = path.join(tmp, "host-home");
    stateDir = path.join(tmp, "state");
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.mkdirSync(path.join(hostHome, ".codex"), { recursive: true });
    fs.mkdirSync(stateDir, { recursive: true });
    expected.clear();
    const mcpServers: Record<string, unknown> = {
      okclaude: {
        type: "http",
        url: "https://ok.example.com/mcp",
        authServerMetadataUrl: "https://auth.ok.example.com/.well-known/oauth-authorization-server",
        oauth: { tokenEndpoint: "https://token.ok.example.com/token" },
      },
    };
    const toml: string[] = [
      "[mcp_servers.okcodex]",
      'url = "https://okc.example.com/mcp"',
      'token_url = "https://token.okc.example.com/token"',
      "",
    ];
    for (const [form, base] of Object.entries(IP_FORMS)) {
      mcpServers[`meta-${form}`] = { type: "http", url: `https://meta-${form}.example.com/mcp`, authServerMetadataUrl: `${base}/.well-known/oauth-authorization-server` };
      expected.set(`meta-${form}`, { agent: "claude", reason: METADATA_REASON });
      mcpServers[`oauthmeta-${form}`] = { type: "http", url: `https://om-${form}.example.com/mcp`, oauth: { authServerMetadataUrl: `${base}/.well-known/oauth-authorization-server` } };
      expected.set(`oauthmeta-${form}`, { agent: "claude", reason: METADATA_REASON });
      mcpServers[`ctoken-${form}`] = { type: "http", url: `https://ct-${form}.example.com/mcp`, oauth: { tokenEndpoint: `${base}/token` } };
      expected.set(`ctoken-${form}`, { agent: "claude", reason: TOKEN_REASON });
      mcpServers[`cpublic-${form}`] = { type: "http", url: `https://cp-${form}.example.com/mcp`, token_url: `${base}/token` };
      expected.set(`cpublic-${form}`, { agent: "claude", reason: TOKEN_REASON });
      toml.push(`[mcp_servers.xtoken-${form}]`, `url = "https://xt-${form}.example.com/mcp"`, `token_url = "${base}/token"`, "");
      expected.set(`xtoken-${form}`, { agent: "codex", reason: TOKEN_REASON });
      toml.push(`[mcp_servers.xoauth-${form}]`, `url = "https://xo-${form}.example.com/mcp"`, 'oauth_resource = "https://xo.example.com"', `token_endpoint = "${base}/token"`, "");
      expected.set(`xoauth-${form}`, { agent: "codex", reason: TOKEN_REASON });
    }
    fs.writeFileSync(path.join(hostHome, ".claude.json"), `${JSON.stringify({ mcpServers }, null, 2)}\n`);
    fs.writeFileSync(path.join(hostHome, ".codex", "config.toml"), toml.join("\n"));
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

  test("entries are unsupported, excluded, and carry the specific reason", () => {
    const inventory = mcpInventory({ projectRoot, env: env(), approvalPath: mcpApprovalPath(stateDir) });
    flushWarnings();
    const byKey = new Map(inventory.entries.map((entry) => [`${entry.agent}:${entry.name}`, entry]));
    for (const [name, { agent, reason }] of expected) {
      const entry = byKey.get(`${agent}:${name}`);
      expect(entry, name).toBeDefined();
      expect(entry?.decision.status, name).toBe("unsupported");
      expect(entry?.decision.reason, name).toBe(reason);
      expect(entry?.target, name).toBe("excluded");
      expect(output.some((line) => line.includes(`server ${name} `) && line.includes(`reason=${reason}`)), name).toBe(true);
    }
    expect(byKey.get("claude:okclaude")?.decision.status).toBe("imported");
    expect(byKey.get("codex:okcodex")?.decision.status).toBe("imported");
  });

  test("launch projects no IP-literal policy host", () => {
    const runDir = path.join(tmp, "run");
    fs.mkdirSync(runDir, { recursive: true });
    const result = prepareMcpRuntime({
      approvalPath: mcpApprovalPath(stateDir),
      callbackPort: 47638,
      claudeConfigPath: path.join(runDir, "claude.json"),
      claudeMcpConfigPath: path.join(runDir, "claude-mcp.json"),
      codexDir: path.join(runDir, "codex"),
      env: env(),
      mcpOAuthPolicyPath: path.join(runDir, "mcp-oauth-policy.json"),
      mcpOperationPolicyPath: path.join(runDir, "mcp-operation-policy.json"),
      policy: { hosts: [], tokens: {} },
      projectRoot,
      tokenConfig: {},
    });
    flushWarnings();
    expect(result.policy.hosts).toEqual(expect.arrayContaining([
      "ok.example.com", "auth.ok.example.com", "token.ok.example.com", "okc.example.com", "token.okc.example.com",
    ]));
    for (const host of result.policy.hosts) {
      const bare = host.startsWith("[") ? host.slice(1, -1) : host;
      expect(isIpLiteralHostname(bare), host).toBe(false);
    }
    const generated = JSON.parse(fs.readFileSync(path.join(runDir, "claude-mcp.json"), "utf8")) as { mcpServers?: Record<string, unknown> };
    for (const [name, { agent }] of expected) {
      if (agent === "claude") expect(Object.keys(generated.mcpServers ?? {}), name).not.toContain(name);
    }
    const codexToml = fs.readFileSync(path.join(runDir, "codex", "config.toml"), "utf8");
    for (const [name, { agent }] of expected) {
      if (agent === "codex") expect(codexToml, name).not.toContain(name);
    }
  });
});
