import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { refusedHostServicePortReason } from "@runfree/runtime-contracts/host-services";
import type { HostServicesJson } from "@runfree/runtime-contracts/host-services";
import type { PolicyJson } from "@runfree/runtime-contracts/network-policy";
import { stableJson } from "@runfree/runtime-contracts/primitives";

import { projectHash } from "../project-identity.ts";
import { remedy } from "../remedies.ts";
import { flushWarnings, pendingWarningsForTest, setOutputWriterForTest } from "../warnings.ts";
import {
  applyPolicyAndTokensForTest,
  loopbackHostServiceName,
  mcpApprovalPath,
  mcpInventory,
  mcpLoopbackReach,
  mcpOAuthCallbackPort,
  mcpOAuthPolicyHasServers,
  mcpOAuthProviderId,
  prepareMcpRuntime,
  readMcpApprovals,
  saveMcpApproval,
  setMcpLogContext,
} from "./mcp.ts";
import { isMcpApprovalRecordV052 } from "./mcp-approval-reader-v0.5.2.fixture.ts";
import { sessionCallbackPortCandidates } from "./session-mcp-callback.ts";

type PreparedServer = Parameters<typeof applyPolicyAndTokensForTest>[2][number];

// S8: every MCP preparation refusal carries its specific reason into the
// inventory decision, and the inventory prints exactly one warning line for it.
const REFUSED: Record<string, { config: Record<string, unknown>; reason: string }> = {
  badUrl: { config: { type: "http", url: "not a url" }, reason: "invalid URL" },
  plainHttp: { config: { type: "http", url: "http://insecure.example.com/mcp" }, reason: "remote HTTP MCP must use https; plain HTTP is allowed only to 127.0.0.1" },
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

// L1, L2, S3, S4, N1, N5, T2, T3, T5, T7: classification and preparation of
// `http-loopback` MCP servers.
const LOOPBACK_REASONS = {
  userinfo: "loopback MCP URL must not contain a username or password",
  fragment: "loopback MCP URL must not contain a fragment",
  dollar: "loopback MCP URL must not contain $; the agent would expand it",
  portZero: "loopback MCP port must be between 1 and 65535",
  reserved: (port: number, why: string) => `loopback MCP port ${port} is reserved: ${why}`,
  claudeType: (type: string) => `loopback MCP supports only Claude type "http", not ${type}`,
  credentials: "loopback MCP cannot carry credentials or OAuth: its traffic does not pass the proxy",
  key: (key: string) => `loopback MCP does not support config key ${key}`,
  keyType: (key: string, expected: string) => `loopback MCP config key ${key} must be ${expected}`,
  localhost: "loopback MCP must use 127.0.0.1, not localhost: localhost may resolve to ::1, which the session relay does not bind",
  otherLoopback: "loopback MCP must use 127.0.0.1",
  ipv6: "loopback MCP must use 127.0.0.1: the session relay binds IPv4 loopback only",
  plainHttp: "remote HTTP MCP must use https; plain HTTP is allowed only to 127.0.0.1",
} as const;

function reservedReason(port: number): string {
  const why = refusedHostServicePortReason(port);
  if (why === undefined) throw new Error(`port ${port} is not reserved`);
  return LOOPBACK_REASONS.reserved(port, why);
}

type RefusedVector = { config: Record<string, unknown>; reason: string; transport: "http" | "http-loopback" };

const CLAUDE_REFUSED: Record<string, RefusedVector> = {
  // T2: not loopback class; refused by normalizeMcpUrl.
  localhost: { config: { type: "http", url: "http://localhost:8089/mcp" }, reason: LOOPBACK_REASONS.localhost, transport: "http" },
  localhostUpper: { config: { type: "http", url: "http://LOCALHOST/" }, reason: LOOPBACK_REASONS.localhost, transport: "http" },
  other127: { config: { type: "http", url: "http://127.0.0.2:8089/" }, reason: LOOPBACK_REASONS.otherLoopback, transport: "http" },
  ipv6Loopback: { config: { type: "http", url: "http://[::1]:8089/" }, reason: LOOPBACK_REASONS.ipv6, transport: "http" },
  ipv6Mapped: { config: { type: "http", url: "http://[::ffff:127.0.0.1]/" }, reason: LOOPBACK_REASONS.ipv6, transport: "http" },
  anyAddress: { config: { type: "http", url: "http://0.0.0.0:8089/" }, reason: LOOPBACK_REASONS.plainHttp, transport: "http" },
  rfc1918: { config: { type: "http", url: "http://192.168.1.5:8089/" }, reason: LOOPBACK_REASONS.plainHttp, transport: "http" },
  linkLocal: { config: { type: "http", url: "http://169.254.1.1/" }, reason: LOOPBACK_REASONS.plainHttp, transport: "http" },
  dockerHost: { config: { type: "http", url: "http://host.docker.internal:8089/" }, reason: LOOPBACK_REASONS.plainHttp, transport: "http" },
  runfreeInternal: { config: { type: "http", url: "http://echo.runfree.internal:8089/" }, reason: LOOPBACK_REASONS.plainHttp, transport: "http" },
  plainName: { config: { type: "http", url: "http://example.com/" }, reason: LOOPBACK_REASONS.plainHttp, transport: "http" },
  // N1
  user: { config: { type: "http", url: "http://u@127.0.0.1:8089/" }, reason: LOOPBACK_REASONS.userinfo, transport: "http-loopback" },
  userPass: { config: { type: "http", url: "http://u:p@127.0.0.1:8089/" }, reason: LOOPBACK_REASONS.userinfo, transport: "http-loopback" },
  emptyFragment: { config: { type: "http", url: "http://127.0.0.1:8089/mcp#" }, reason: LOOPBACK_REASONS.fragment, transport: "http-loopback" },
  fragment: { config: { type: "http", url: "http://127.0.0.1:8089/mcp#x" }, reason: LOOPBACK_REASONS.fragment, transport: "http-loopback" },
  dollarPath: { config: { type: "http", url: "http://127.0.0.1:8089/${PORT}" }, reason: LOOPBACK_REASONS.dollar, transport: "http-loopback" },
  dollarQuery: { config: { type: "http", url: "http://127.0.0.1:8089/mcp?t=$TOKEN" }, reason: LOOPBACK_REASONS.dollar, transport: "http-loopback" },
  portZero: { config: { type: "http", url: "http://127.0.0.1:0/mcp" }, reason: LOOPBACK_REASONS.portZero, transport: "http-loopback" },
  // T5
  ...Object.fromEntries([2375, 2376, 3128, 5901, 47100, 47638, 48099].map((port) => [
    `reserved${port}`,
    { config: { type: "http", url: `http://127.0.0.1:${port}/mcp` }, reason: reservedReason(port), transport: "http-loopback" as const },
  ])),
  // N5
  sse: { config: { type: "sse", url: "http://127.0.0.1:8089/mcp" }, reason: LOOPBACK_REASONS.claudeType("sse"), transport: "http-loopback" },
  streamable: { config: { type: "streamable-http", url: "http://127.0.0.1:8089/mcp" }, reason: LOOPBACK_REASONS.claudeType("streamable-http"), transport: "http-loopback" },
  // T3
  emptyHeaders: { config: { type: "http", url: "http://127.0.0.1:8089/mcp", headers: {} }, reason: LOOPBACK_REASONS.credentials, transport: "http-loopback" },
  authHeader: { config: { type: "http", url: "http://127.0.0.1:8089/mcp", headers: { Authorization: "Bearer ${T}" } }, reason: LOOPBACK_REASONS.credentials, transport: "http-loopback" },
  headersHelper: { config: { type: "http", url: "http://127.0.0.1:8089/mcp", headersHelper: "x" }, reason: LOOPBACK_REASONS.credentials, transport: "http-loopback" },
  oauthFalse: { config: { type: "http", url: "http://127.0.0.1:8089/mcp", oauth: false }, reason: LOOPBACK_REASONS.credentials, transport: "http-loopback" },
  oauthObject: { config: { type: "http", url: "http://127.0.0.1:8089/mcp", oauth: { clientId: "x" } }, reason: LOOPBACK_REASONS.credentials, transport: "http-loopback" },
  metadataUrl: { config: { type: "http", url: "http://127.0.0.1:8089/mcp", authServerMetadataUrl: "https://a.example.com/x" }, reason: LOOPBACK_REASONS.credentials, transport: "http-loopback" },
  // S3
  fooKey: { config: { type: "http", url: "http://127.0.0.1:8089/mcp", foo: 1 }, reason: LOOPBACK_REASONS.key("foo"), transport: "http-loopback" },
  codexOnlyKey: { config: { type: "http", url: "http://127.0.0.1:8089/mcp", enabled: true }, reason: LOOPBACK_REASONS.key("enabled"), transport: "http-loopback" },
  controlKey: { config: { type: "http", url: "http://127.0.0.1:8089/mcp", "f\u0007o": 1 }, reason: LOOPBACK_REASONS.key("f\\u{7}o"), transport: "http-loopback" },
  // Credentials are reported before an unknown key, whatever the key order.
  unknownThenCredential: { config: { type: "http", url: "http://127.0.0.1:8089/mcp", foo: 1, headersHelper: "x" }, reason: LOOPBACK_REASONS.credentials, transport: "http-loopback" },
};

const CODEX_REFUSED: Record<string, { toml: string[]; reason: string }> = {
  bearer: { toml: ['bearer_token_env_var = "T"'], reason: LOOPBACK_REASONS.credentials },
  envHeaders: { toml: ['env_http_headers = { Authorization = "T" }'], reason: LOOPBACK_REASONS.credentials },
  httpHeaders: { toml: ['http_headers = { "X-Key" = "v" }'], reason: LOOPBACK_REASONS.credentials },
  headersHelper: { toml: ['http_headers_helper = "x"'], reason: LOOPBACK_REASONS.credentials },
  oauthFalse: { toml: ["oauth = false"], reason: LOOPBACK_REASONS.credentials },
  oauthTrue: { toml: ["oauth = true"], reason: LOOPBACK_REASONS.credentials },
  oauthResource: { toml: ['oauth_resource = "x"'], reason: LOOPBACK_REASONS.credentials },
  scopes: { toml: ['scopes = ["a"]'], reason: LOOPBACK_REASONS.credentials },
  callbackPort: { toml: ["mcp_oauth_callback_port = 1"], reason: LOOPBACK_REASONS.credentials },
  cwd: { toml: ['cwd = "/x"'], reason: LOOPBACK_REASONS.key("cwd") },
  command: { toml: ['command = "x"'], reason: LOOPBACK_REASONS.key("command") },
  env: { toml: ['env = { A = "b" }'], reason: LOOPBACK_REASONS.key("env") },
  // F7: an allowlisted key with the wrong type is refused, not dropped: a
  // dropped `enabled_tools` would widen the tool set to every tool.
  enabledString: { toml: ['enabled = "no"'], reason: LOOPBACK_REASONS.keyType("enabled", "a boolean") },
  requiredNumber: { toml: ["required = 1"], reason: LOOPBACK_REASONS.keyType("required", "a boolean") },
  enabledToolsString: { toml: ['enabled_tools = "a"'], reason: LOOPBACK_REASONS.keyType("enabled_tools", "an array of strings") },
  disabledToolsTable: { toml: ["disabled_tools = { a = 1 }"], reason: LOOPBACK_REASONS.keyType("disabled_tools", "an array of strings") },
  startupNegative: { toml: ["startup_timeout_sec = -1"], reason: LOOPBACK_REASONS.keyType("startup_timeout_sec", "a finite number of at least 0") },
  toolTimeoutString: { toml: ['tool_timeout_sec = "5"'], reason: LOOPBACK_REASONS.keyType("tool_timeout_sec", "a finite number of at least 0") },
};

function codexTable(name: string, url: string, lines: string[]): string {
  return [`[mcp_servers.${name}]`, `url = ${JSON.stringify(url)}`, ...lines, ""].join("\n");
}

describe("http-loopback MCP classification and preparation", () => {
  let tmp: string;
  let projectRoot: string;
  let hostHome: string;
  let stateDir: string;
  let runDir: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-loopback-class-"));
    projectRoot = path.join(tmp, "project");
    hostHome = path.join(tmp, "host-home");
    stateDir = path.join(tmp, "state");
    runDir = path.join(tmp, "run");
    for (const dir of [projectRoot, path.join(hostHome, ".codex"), stateDir, runDir]) fs.mkdirSync(dir, { recursive: true });
    flushWarnings();
    setOutputWriterForTest(() => undefined);
  });

  afterEach(() => {
    flushWarnings();
    setOutputWriterForTest(undefined);
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const env = () => ({ HOME: hostHome, CODEX_HOME: path.join(hostHome, ".codex") });
  const approvalFile = () => mcpApprovalPath(stateDir);

  function writeUserClaude(mcpServers: Record<string, unknown>): void {
    fs.writeFileSync(path.join(hostHome, ".claude.json"), `${JSON.stringify({ mcpServers }, null, 2)}\n`);
  }

  function writeProjectClaude(mcpServers: Record<string, unknown>): void {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), `${JSON.stringify({ mcpServers }, null, 2)}\n`);
  }

  function writeUserCodex(source: string): void {
    fs.writeFileSync(path.join(hostHome, ".codex", "config.toml"), source);
  }

  function writeProjectCodex(source: string): void {
    fs.mkdirSync(path.join(projectRoot, ".codex"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".codex", "config.toml"), source);
  }

  function inventory() {
    return mcpInventory({ projectRoot, env: env(), approvalPath: approvalFile() });
  }

  function entry(agent: "claude" | "codex", name: string) {
    const found = inventory().entries.find((candidate) => candidate.agent === agent && candidate.name === name);
    if (!found) throw new Error(`no inventory entry ${agent} ${name}`);
    return found;
  }

  function prepare(): { claude: Record<string, Record<string, unknown>>; codex: string; hosts: string[] } {
    const result = prepareMcpRuntime({
      approvalPath: approvalFile(),
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
    const codexPath = path.join(runDir, "codex", "config.toml");
    return {
      claude: (JSON.parse(fs.readFileSync(path.join(runDir, "claude-mcp.json"), "utf8")) as { mcpServers: Record<string, Record<string, unknown>> }).mcpServers,
      codex: fs.existsSync(codexPath) ? fs.readFileSync(codexPath, "utf8") : "",
      hosts: result.policy.hosts,
    };
  }

  test("T2: accepted loopback URLs import as http-loopback/none and emit the normalized href", () => {
    const accepted: Array<[string, string, number]> = [
      ["http://127.0.0.1:8089/mcp", "http://127.0.0.1:8089/mcp", 8089],
      ["http://127.1:8089/mcp", "http://127.0.0.1:8089/mcp", 8089],
      ["http://2130706433/mcp", "http://127.0.0.1/mcp", 80],
      ["http://0x7f.0.0.1:8089/mcp", "http://127.0.0.1:8089/mcp", 8089],
      ["http://127.0.0.1.:8089/", "http://127.0.0.1:8089/", 8089],
      ["http://127.0.0.1:8089", "http://127.0.0.1:8089/", 8089],
      ["http://127.0.0.1:/mcp", "http://127.0.0.1/mcp", 80],
      ["http://127.0.0.1:8089/mcp?x=1", "http://127.0.0.1:8089/mcp?x=1", 8089],
      // T5 boundaries: the ports just outside the refused callback block.
      ["http://127.0.0.1:47099/mcp", "http://127.0.0.1:47099/mcp", 47099],
      ["http://127.0.0.1:48100/mcp", "http://127.0.0.1:48100/mcp", 48100],
    ];
    // N5: the first entry has no `type`; it is accepted and emitted as `http`.
    writeUserClaude(Object.fromEntries(accepted.map(([raw], index) => [`a${index}`, index === 0 ? { url: raw } : { type: "http", url: raw }])));
    const entries = inventory().entries;
    const generated = prepare();
    accepted.forEach(([raw, href, port], index) => {
      const name = `a${index}`;
      const found = entries.find((candidate) => candidate.name === name);
      expect(found?.decision, raw).toEqual({ status: "imported" });
      expect(found?.transport, raw).toBe("http-loopback");
      expect(found?.auth, raw).toBe("none");
      expect(found?.target, raw).toBe("generated");
      expect(found?.endpoint, raw).toBeUndefined();
      expect(found?.tokenBindings, raw).toBeUndefined();
      expect(found?.loopback, raw).toEqual({ url: href, port });
      expect(generated.claude[name], raw).toEqual({ type: "http", url: href });
    });
    expect(generated.hosts).toEqual([]);
  });

  test("T2: a Codex loopback entry imports with the normalized href", () => {
    writeUserCodex(codexTable("loop", "http://127.1:8089/mcp", []));
    const found = entry("codex", "loop");
    expect(found.decision).toEqual({ status: "imported" });
    expect(found.transport).toBe("http-loopback");
    expect(found.loopback).toEqual({ url: "http://127.0.0.1:8089/mcp", port: 8089 });
    expect(prepare().codex).toContain('[mcp_servers.loop]\nurl = "http://127.0.0.1:8089/mcp"\n');
  });

  test("a stdio-typed entry with a loopback url stays stdio", () => {
    writeUserClaude({ tool: { type: "stdio", command: "node", url: "http://127.0.0.1:8089/mcp" } });
    expect(entry("claude", "tool").transport).toBe("stdio");
  });

  test("refused Claude vectors are unsupported, excluded, and absent from generated config", () => {
    writeUserClaude(Object.fromEntries(Object.entries(CLAUDE_REFUSED).map(([name, { config }]) => [name, config])));
    const entries = inventory().entries;
    const generated = prepare();
    for (const [name, { reason, transport }] of Object.entries(CLAUDE_REFUSED)) {
      const found = entries.find((candidate) => candidate.name === name);
      expect(found?.decision, name).toEqual({ status: "unsupported", reason });
      expect(found?.target, name).toBe("excluded");
      expect(found?.transport, name).toBe(transport);
      expect(found?.loopback, name).toBeUndefined();
      expect(generated.claude[name], name).toBeUndefined();
    }
    expect(Object.keys(generated.claude)).toEqual([]);
    expect(generated.hosts).toEqual([]);
  });

  test("refused project Claude vectors cannot be approved and write no approval file", () => {
    writeProjectClaude(Object.fromEntries(Object.entries(CLAUDE_REFUSED).map(([name, { config }]) => [name, config])));
    const entries = inventory().entries;
    for (const [name, { reason }] of Object.entries(CLAUDE_REFUSED)) {
      const found = entries.find((candidate) => candidate.name === name);
      if (!found) throw new Error(name);
      expect(found.decision, name).toEqual({ status: "unsupported", reason });
      expect(found.target, name).toBe("excluded");
      expect(() => saveMcpApproval(projectRoot, approvalFile(), found), name).toThrow("unsupported project MCP entry cannot be approved");
    }
    expect(fs.existsSync(approvalFile())).toBe(false);
    expect(Object.keys(prepare().claude)).toEqual([]);
  });

  test("refused project Codex vectors cannot be approved and are absent from generated TOML", () => {
    writeProjectCodex(Object.entries(CODEX_REFUSED).map(([name, { toml }]) => codexTable(name, "http://127.0.0.1:8089/mcp", toml)).join("\n"));
    const entries = inventory().entries;
    for (const [name, { reason }] of Object.entries(CODEX_REFUSED)) {
      const found = entries.find((candidate) => candidate.agent === "codex" && candidate.name === name);
      if (!found) throw new Error(name);
      expect(found.decision, name).toEqual({ status: "unsupported", reason });
      expect(found.target, name).toBe("excluded");
      expect(found.transport, name).toBe("http-loopback");
      expect(() => saveMcpApproval(projectRoot, approvalFile(), found), name).toThrow("unsupported project MCP entry cannot be approved");
    }
    expect(fs.existsSync(approvalFile())).toBe(false);
    expect(prepare().codex).not.toContain("mcp_servers");
  });

  test("refused user Codex vectors are absent from generated TOML", () => {
    writeUserCodex(Object.entries(CODEX_REFUSED).map(([name, { toml }]) => codexTable(name, "http://127.0.0.1:8089/mcp", toml)).join("\n"));
    for (const [name, { reason }] of Object.entries(CODEX_REFUSED)) {
      expect(entry("codex", name).decision, name).toEqual({ status: "unsupported", reason });
    }
    expect(prepare().codex).not.toContain("mcp_servers");
  });

  test("F7: zero and fractional timeouts and empty tool lists are well-typed loopback options", () => {
    writeUserCodex(codexTable("loop", "http://127.0.0.1:8089/mcp", [
      "enabled_tools = []",
      "startup_timeout_sec = 0",
      "tool_timeout_sec = 1.5",
    ]));
    expect(entry("codex", "loop").decision).toEqual({ status: "imported" });
    const codex = prepare().codex;
    for (const line of ["enabled_tools = []", "startup_timeout_sec = 0", "tool_timeout_sec = 1.5"]) {
      expect(codex).toContain(`\n${line}\n`);
    }
  });

  test("F7: the type check is loopback-only; an HTTPS Codex entry still drops a wrongly typed option", () => {
    writeUserCodex(codexTable("remote", "https://mcp.example.com/mcp", ['enabled = "no"', "tool_timeout_sec = -1"]));
    expect(entry("codex", "remote").decision).toEqual({ status: "imported" });
    const codex = prepare().codex;
    expect(codex).toContain('[mcp_servers.remote]\nurl = "https://mcp.example.com/mcp"\n');
    expect(codex).not.toMatch(/^enabled\s*=/m);
  });

  test("S3: allowed Codex keys survive into the generated TOML; no OAuth lines are emitted", () => {
    writeUserCodex(codexTable("loop", "http://127.0.0.1:8089/mcp", [
      "enabled = false",
      "required = true",
      'enabled_tools = ["a"]',
      'disabled_tools = ["b"]',
      "startup_timeout_sec = 5",
      "tool_timeout_sec = 7",
    ]));
    expect(entry("codex", "loop").decision).toEqual({ status: "imported" });
    const codex = prepare().codex;
    for (const line of [
      'url = "http://127.0.0.1:8089/mcp"',
      "enabled = false",
      "required = true",
      'enabled_tools = ["a"]',
      'disabled_tools = ["b"]',
      "startup_timeout_sec = 5",
      "tool_timeout_sec = 7",
    ]) {
      expect(codex).toContain(`\n${line}\n`);
    }
    expect(codex).not.toMatch(/^(?:oauth|scopes|oauth_resource)\s*=/m);
  });

  test("project scope: a loopback entry needs approval, records http-loopback, then generates", () => {
    writeProjectClaude({ astro: { type: "http", url: "http://127.1:8089/mcp" } });
    const before = entry("claude", "astro");
    expect(before.decision).toEqual({ status: "unapproved", reason: "project MCP requires approval" });
    expect(before.target).toBe("excluded");
    expect(prepare().claude.astro).toBeUndefined();
    const record = saveMcpApproval(projectRoot, approvalFile(), before);
    expect(record.transport).toBe("http-loopback");
    expect(record.auth).toBe("none");
    expect(record.summary).toBe("claude astro http-loopback/none");
    const after = entry("claude", "astro");
    expect(after.decision).toEqual({ status: "approved" });
    expect(after.target).toBe("generated");
    const generated = prepare();
    expect(generated.claude.astro).toEqual({ type: "http", url: "http://127.0.0.1:8089/mcp" });
    expect(generated.hosts).toEqual([]);
  });

  test("T7: a v0.5.2 reader drops the loopback approval; re-approval reclaims it", () => {
    writeProjectClaude({ astro: { type: "http", url: "http://127.0.0.1:8089/mcp" } });
    const record = saveMcpApproval(projectRoot, approvalFile(), entry("claude", "astro"));
    expect(isMcpApprovalRecordV052(record)).toBe(false);
    expect(Object.values(readMcpApprovals(projectRoot, approvalFile()).approvals)).toEqual([record]);

    // Simulate the v0.5.2 writer: it keeps only records its predicate accepts.
    const file = JSON.parse(fs.readFileSync(approvalFile(), "utf8")) as { approvals: Record<string, unknown> };
    file.approvals = Object.fromEntries(Object.entries(file.approvals).filter(([, value]) => isMcpApprovalRecordV052(value)));
    fs.writeFileSync(approvalFile(), `${JSON.stringify(file, null, 2)}\n`);
    const dropped = entry("claude", "astro");
    expect(dropped.decision).toEqual({ status: "unapproved", reason: "project MCP requires approval" });

    // Reclaim: `runfree mcp enable` saves the approval again.
    saveMcpApproval(projectRoot, approvalFile(), dropped);
    expect(entry("claude", "astro").decision).toEqual({ status: "approved" });
  });
});

// S4: emitting `href` is loopback-only. A project HTTPS entry's digest and
// generated URL are unchanged, so no existing approval turns `changed`.
describe("HTTPS MCP digest stability", () => {
  // descriptorDigest of the entry below, computed with `mcpInventory` from
  // `main` at 91404d9 (before loopback support). The digest covers
  // `projectHash(projectRoot)`, so the project root is a fixed path.
  const PINNED_DIGEST_91404D9 = "22aba3ecad3b9f7a31bc1a7cb848ab35cb124120f5f57cef608854284e0868c6";
  const root = "/tmp/runfree-mcp-s4-digest-pin";
  const projectRoot = path.join(root, "project");
  const hostHome = path.join(root, "home");

  beforeEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.mkdirSync(path.join(hostHome, ".codex"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({ mcpServers: { astro: { type: "http", url: "https://MCP.Example.com/mcp" } } }));
    flushWarnings();
    setOutputWriterForTest(() => undefined);
  });

  afterEach(() => {
    flushWarnings();
    setOutputWriterForTest(undefined);
    fs.rmSync(root, { recursive: true, force: true });
  });

  test("the HTTPS descriptor digest matches 91404d9 and keeps the raw URL", () => {
    const env = { HOME: hostHome, CODEX_HOME: path.join(hostHome, ".codex") };
    const approvalPath = mcpApprovalPath(path.join(root, "state"));
    const astro = () => {
      const found = mcpInventory({ projectRoot, env, approvalPath }).entries.find((candidate) => candidate.name === "astro");
      if (!found) throw new Error("no astro entry");
      return found;
    };
    const before = astro();
    expect(before.transport).toBe("http");
    expect(before.descriptorDigest).toBe(PINNED_DIGEST_91404D9);
    expect(before.loopback).toBeUndefined();
    saveMcpApproval(projectRoot, approvalPath, before);
    const after = astro();
    expect(after.decision).toEqual({ status: "approved" });
    expect(after.descriptorDigest).toBe(PINNED_DIGEST_91404D9);
    const runDir = path.join(root, "run");
    prepareMcpRuntime({
      approvalPath,
      callbackPort: 47638,
      claudeConfigPath: path.join(runDir, "claude.json"),
      claudeMcpConfigPath: path.join(runDir, "claude-mcp.json"),
      codexDir: path.join(runDir, "codex"),
      env,
      mcpOAuthPolicyPath: path.join(runDir, "mcp-oauth-policy.json"),
      mcpOperationPolicyPath: path.join(runDir, "mcp-operation-policy.json"),
      policy: { hosts: [], tokens: {} },
      projectRoot,
      tokenConfig: {},
    });
    const generated = JSON.parse(fs.readFileSync(path.join(runDir, "claude-mcp.json"), "utf8")) as { mcpServers: Record<string, unknown> };
    expect(generated.mcpServers.astro).toEqual({ type: "http", url: "https://MCP.Example.com/mcp" });
  });
});

const ASTRO_HOST_SERVICES: HostServicesJson = { astro: { target: "host-loopback", port: 8089 } };

// L5: reach is shown, never granted. The suggested host-service name is the
// server name when valid, else `mcp-<port>`.
describe("loopback MCP reach", () => {
  test("a port with an approved host service reaches it; any other port is container-local", () => {
    expect(mcpLoopbackReach(8089, ASTRO_HOST_SERVICES)).toEqual({ kind: "host-service", name: "astro", port: 8089 });
    expect(mcpLoopbackReach(3000, ASTRO_HOST_SERVICES)).toEqual({ kind: "container-local", port: 3000 });
    expect(mcpLoopbackReach(8089, {})).toEqual({ kind: "container-local", port: 8089 });
  });

  test("the suggested host-service name is the server name only when it is a valid host-service name", () => {
    expect(loopbackHostServiceName("astro", 8089, {})).toBe("astro");
    expect(loopbackHostServiceName("Astro_MCP", 8089, {})).toBe("mcp-8089");
    expect(loopbackHostServiceName("a".repeat(64), 8089, {})).toBe("mcp-8089");
    expect(loopbackHostServiceName("a".repeat(63), 8089, {})).toBe("a".repeat(63));
  });

  test("the suggested name falls back to mcp-<port> when the server name is a host service on another port", () => {
    // `runfree host-service add astro --port 3000` would fail: astro is taken.
    expect(loopbackHostServiceName("astro", 3000, ASTRO_HOST_SERVICES)).toBe("mcp-3000");
    expect(loopbackHostServiceName("devtools", 3000, ASTRO_HOST_SERVICES)).toBe("devtools");
  });
});

// T6/S6, T10, and the L5 launch warning.
describe("loopback MCP launch: policy invariance, OAuth isolation, and reach warning", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-loopback-launch-"));
    flushWarnings();
    setOutputWriterForTest(() => undefined);
  });

  afterEach(() => {
    setMcpLogContext({});
    flushWarnings();
    setOutputWriterForTest(undefined);
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  type Fixture = {
    env: NodeJS.ProcessEnv;
    approvalPath: string;
    projectRoot: string;
    runDir: string;
  };

  function fixture(label: string, options: { projectClaude?: Record<string, unknown>; userClaude?: Record<string, unknown>; userCodex?: string }): Fixture {
    const root = path.join(tmp, label);
    const projectRoot = path.join(root, "project");
    const hostHome = path.join(root, "host-home");
    const stateDir = path.join(root, "state");
    const runDir = path.join(root, "run");
    for (const dir of [projectRoot, path.join(hostHome, ".codex"), stateDir, runDir]) fs.mkdirSync(dir, { recursive: true });
    const env = { HOME: hostHome, CODEX_HOME: path.join(hostHome, ".codex") };
    const approvalPath = mcpApprovalPath(stateDir);
    if (options.userClaude) fs.writeFileSync(path.join(hostHome, ".claude.json"), `${JSON.stringify({ mcpServers: options.userClaude }, null, 2)}\n`);
    if (options.userCodex) fs.writeFileSync(path.join(hostHome, ".codex", "config.toml"), options.userCodex);
    if (options.projectClaude) {
      fs.writeFileSync(path.join(projectRoot, ".mcp.json"), `${JSON.stringify({ mcpServers: options.projectClaude }, null, 2)}\n`);
      for (const entry of mcpInventory({ projectRoot, env, approvalPath }).entries) {
        if (entry.source === "project") saveMcpApproval(projectRoot, approvalPath, entry);
      }
    }
    return { env, approvalPath, projectRoot, runDir };
  }

  function basePolicy(): PolicyJson {
    return { hosts: ["api.example.com"], tokens: {}, hostServices: { ...ASTRO_HOST_SERVICES } };
  }

  function launch(f: Fixture) {
    const oauthPolicyPath = path.join(f.runDir, "mcp-oauth-policy.json");
    const operationPolicyPath = path.join(f.runDir, "mcp-operation-policy.json");
    const result = prepareMcpRuntime({
      approvalPath: f.approvalPath,
      callbackPort: 47638,
      claudeConfigPath: path.join(f.runDir, "claude.json"),
      claudeMcpConfigPath: path.join(f.runDir, "claude-mcp.json"),
      codexDir: path.join(f.runDir, "codex"),
      env: f.env,
      mcpOAuthPolicyPath: oauthPolicyPath,
      mcpOperationPolicyPath: operationPolicyPath,
      policy: basePolicy(),
      projectRoot: f.projectRoot,
      tokenConfig: {},
    });
    return {
      result,
      oauthPolicyPath,
      oauthPolicy: fs.readFileSync(oauthPolicyPath, "utf8"),
      operationPolicy: fs.readFileSync(operationPolicyPath, "utf8"),
      claude: (JSON.parse(fs.readFileSync(path.join(f.runDir, "claude-mcp.json"), "utf8")) as { mcpServers: Record<string, unknown> }).mcpServers,
    };
  }

  function warningMessages(): string[] {
    const messages = pendingWarningsForTest().map((event) => event.message);
    flushWarnings();
    return messages;
  }

  function containerLocalWarning(agent: string, name: string, port: number): string {
    return `mcp: ${agent} server ${name} targets 127.0.0.1:${port}, which is not an approved host service;\n`
      + `it works only if a process in the session listens there. To reach the host: ${remedy.hostServiceAdd(loopbackHostServiceName(name, port, ASTRO_HOST_SERVICES), port)}`;
  }

  test("T6/S6: an approved project loopback entry and a user loopback entry leave every policy byte-identical", () => {
    const plain = launch(fixture("plain", {}));
    const loopback = launch(fixture("loopback", {
      projectClaude: { astro: { type: "http", url: "http://127.0.0.1:8089/mcp" } },
      userClaude: { devtools: { type: "http", url: "http://127.0.0.1:3000/mcp" } },
    }));
    // The loopback servers were generated, so the comparison is not vacuous.
    expect(loopback.claude.astro).toEqual({ type: "http", url: "http://127.0.0.1:8089/mcp" });
    expect(loopback.claude.devtools).toEqual({ type: "http", url: "http://127.0.0.1:3000/mcp" });
    expect(stableJson(loopback.result.policy)).toBe(stableJson(plain.result.policy));
    expect(loopback.operationPolicy).toBe(plain.operationPolicy);
    expect(loopback.oauthPolicy).toBe(plain.oauthPolicy);
    expect(loopback.result.policyChanged).toBe(false);
    expect(loopback.result.tokenConfigChanged).toBe(false);
    expect(loopback.result.policy.hosts).toEqual(["api.example.com"]);
    expect(loopback.result.policy.hosts).not.toContain("127.0.0.1");
    expect(loopback.result.policy.hostServices).toEqual(ASTRO_HOST_SERVICES);
    // No MCP OAuth provider, so no callback bridge or ingress forwarder starts.
    expect(mcpOAuthPolicyHasServers(loopback.oauthPolicyPath)).toBe(false);
  });

  test("T10: an HTTPS server gets the only OAuth provider; the loopback server gets none", () => {
    const launched = launch(fixture("t10", {
      projectClaude: {
        astro: { type: "http", url: "http://127.0.0.1:8089/mcp" },
        publicMcp: { type: "http", url: "https://mcp.example.com/mcp" },
      },
    }));
    expect(launched.claude.astro).toEqual({ type: "http", url: "http://127.0.0.1:8089/mcp" });
    const providers = (JSON.parse(launched.oauthPolicy) as { providers: Record<string, unknown> }).providers;
    expect(Object.keys(providers)).toEqual([mcpOAuthProviderId("claude", "publicMcp")]);
    expect(providers).not.toHaveProperty(mcpOAuthProviderId("claude", "astro"));
    expect(mcpOAuthPolicyHasServers(launched.oauthPolicyPath)).toBe(true);
  });

  test("inventory reports loopback reach only when given host services", () => {
    const f = fixture("inventory", {
      userClaude: {
        astro: { type: "http", url: "http://127.0.0.1:8089/mcp" },
        devtools: { type: "http", url: "http://127.0.0.1:3000/mcp" },
      },
    });
    const withReach = mcpInventory({ projectRoot: f.projectRoot, env: f.env, approvalPath: f.approvalPath, hostServices: ASTRO_HOST_SERVICES }).entries;
    expect(withReach.find((entry) => entry.name === "astro")?.loopback).toEqual({
      url: "http://127.0.0.1:8089/mcp",
      port: 8089,
      reach: { kind: "host-service", name: "astro", port: 8089 },
    });
    expect(withReach.find((entry) => entry.name === "devtools")?.loopback?.reach).toEqual({ kind: "container-local", port: 3000 });
    const without = mcpInventory({ projectRoot: f.projectRoot, env: f.env, approvalPath: f.approvalPath }).entries;
    for (const entry of without) expect(entry.loopback && "reach" in entry.loopback, entry.name).toBe(false);
  });

  test("L5: launch warns once per container-local server of the launched agent only", () => {
    const f = fixture("warn", {
      userClaude: {
        astro: { type: "http", url: "http://127.0.0.1:3000/mcp" },
        hosted: { type: "http", url: "http://127.0.0.1:8089/mcp" },
        Odd_Name: { type: "http", url: "http://127.0.0.1:4000/mcp" },
      },
      userCodex: codexTable("codexlocal", "http://127.0.0.1:5000/mcp", []),
    });
    setMcpLogContext({ agent: "claude" });
    launch(f);
    const reachLines = warningMessages().filter((message) => message.includes("not an approved host service"));
    expect(reachLines.sort()).toEqual([
      containerLocalWarning("claude", "Odd_Name", 4000),
      containerLocalWarning("claude", "astro", 3000),
    ].sort());
    // The policy already has host service astro on 8089, so the suggestion
    // for server astro on 3000 is mcp-3000: `host-service add astro` would fail.
    expect(containerLocalWarning("claude", "astro", 3000)).toBe(
      "mcp: claude server astro targets 127.0.0.1:3000, which is not an approved host service;\n"
        + "it works only if a process in the session listens there. To reach the host: runfree host-service add mcp-3000 --port 3000",
    );
    expect(reachLines.some((line) => line.includes("Odd_Name") && line.endsWith("runfree host-service add mcp-4000 --port 4000"))).toBe(true);

    // Each call warns again, once.
    launch(f);
    expect(warningMessages().filter((message) => message.includes("not an approved host service"))).toHaveLength(2);

    setMcpLogContext({ agent: "codex" });
    launch(f);
    expect(warningMessages().filter((message) => message.includes("not an approved host service"))).toEqual([
      containerLocalWarning("codex", "codexlocal", 5000),
    ]);
  });

  test("L5: an unapproved project loopback server is skipped, not reach-warned", () => {
    const f = fixture("unapproved", {});
    fs.writeFileSync(path.join(f.projectRoot, ".mcp.json"), `${JSON.stringify({ mcpServers: { astro: { type: "http", url: "http://127.0.0.1:3000/mcp" } } }, null, 2)}\n`);
    setMcpLogContext({ agent: "claude" });
    launch(f);
    expect(warningMessages().filter((message) => message.includes("not an approved host service"))).toEqual([]);
  });
});
