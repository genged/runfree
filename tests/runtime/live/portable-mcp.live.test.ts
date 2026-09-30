// Portable compute MCP tranche (extended tier).
//
// Proves, in a real per-session agent container built from the Runfree base
// image, that a host Codex Desktop `node_repl` descriptor becomes the fixed
// container dispatcher and that the shipped node-repl server:
// - is present and passes its self-check in the selected session image;
// - is what the generated Codex config names, with no host path or env value;
// - runs as the agent user, reads and writes only agent-visible workspace
//   state, and keeps its state across calls;
// - cannot open a direct outbound connection (the agent firewall refuses it
//   before any upstream handshake);
// - never sees a proxy-managed credential value in its environment.
//
// The host descriptor uses canary host paths; none may reach the container.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { docker } from "./docker.ts";
import {
  describeOutput,
  destroyLiveFixture,
  type LiveFixture,
  provisionSandboxFixture,
  startStandingSession,
  type StandingSessionHandle,
} from "./fixture.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 5 * 60_000;
// The sandbox fixture's proxy-managed strip credential (see fixture.ts).
const PROXY_CREDENTIAL_VALUE = "sandbox-not-a-real-token";
const CANARY = "runfree-portable-canary";

const HOST_CODEX_CONFIG = [
  "[mcp_servers.node_repl]",
  `command = "/Users/${CANARY}/Applications/Codex.app/Contents/Resources/node_repl"`,
  "args = []",
  "startup_timeout_sec = 120",
  "",
  "[mcp_servers.node_repl.env]",
  `NODE_REPL_NODE_PATH = "/Users/${CANARY}/node"`,
  `CODEX_HOME = "/Users/${CANARY}/.codex"`,
  "",
].join("\n");

// A minimal MCP stdio client run inside the container with the container's own
// Node. It prints one JSON object with every tool result.
const IN_CONTAINER_CLIENT = String.raw`
const { spawn } = require("node:child_process");
const child = spawn("/usr/local/bin/runfree-mcp", ["node-repl"], { stdio: ["pipe", "pipe", "inherit"] });
let buffer = ""; const waiting = new Map(); let nextId = 1;
child.stdout.setEncoding("utf8");
child.stdout.on("data", (chunk) => {
  buffer += chunk;
  for (let i = buffer.indexOf("\n"); i >= 0; i = buffer.indexOf("\n")) {
    const line = buffer.slice(0, i); buffer = buffer.slice(i + 1);
    const message = JSON.parse(line);
    if (typeof message.id === "number") waiting.get(message.id)?.(message);
  }
});
const request = (method, params) => new Promise((resolve) => {
  const id = nextId++; waiting.set(id, resolve);
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
});
const js = async (code) => {
  const response = await request("tools/call", { name: "js", arguments: { code, timeout_ms: 20000 } });
  return { text: response.result.content.map((entry) => entry.text).join(""), isError: response.result.isError === true };
};
(async () => {
  await request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "live", version: "0" } });
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
  const results = {
    uid: await js("String(process.getuid())"),
    cwd: await js("nodeRepl.cwd"),
    write: await js("require('node:fs').writeFileSync('portable-mcp-live.txt', 'from-kernel'); 'ok'"),
    persist1: await js("globalThis.kept = 41; 'set'"),
    persist2: await js("String(kept + 1)"),
    env: await js("JSON.stringify(process.env) + require('node:fs').readFileSync('/proc/self/environ', 'latin1')"),
    egress: await js("await new Promise((resolve) => { const socket = require('node:net').connect({ host: '1.1.1.1', port: 443, timeout: 5000 }); socket.once('connect', () => { socket.destroy(); resolve('connected'); }); socket.once('timeout', () => { socket.destroy(); resolve('refused:timeout'); }); socket.once('error', (error) => resolve('refused:' + error.code)); }).then((value) => { nodeRepl.write(value); })"),
  };
  process.stdout.write(JSON.stringify(results));
  child.kill("SIGTERM");
  process.exit(0);
})().catch((error) => { process.stderr.write(String(error && error.stack || error)); process.exit(1); });
`;

describe("portable compute MCP", () => {
  let fixture: LiveFixture;
  let standing: StandingSessionHandle;
  let containerId: string;
  let hostCodexHome: string;
  const previousCodexHome = process.env.CODEX_HOME;

  beforeAll(async () => {
    // The host Codex config the CLI imports from. provisionLiveFixture
    // snapshots process.env, so set it before provisioning.
    hostCodexHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-live-codex-home-"));
    fs.writeFileSync(path.join(hostCodexHome, "config.toml"), HOST_CODEX_CONFIG);
    process.env.CODEX_HOME = hostCodexHome;
    fixture = provisionSandboxFixture(REPO_ROOT);
    standing = await startStandingSession(fixture);
    containerId = standing.session.containerId;
  }, PROVISION_TIMEOUT_MS);

  afterAll(async () => {
    try {
      if (standing) await standing.release();
    } finally {
      if (fixture) destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
      if (previousCodexHome === undefined) delete process.env.CODEX_HOME;
      else process.env.CODEX_HOME = previousCodexHome;
      if (hostCodexHome) fs.rmSync(hostCodexHome, { recursive: true, force: true });
    }
  }, PROVISION_TIMEOUT_MS);

  test("the session image ships the bundle and passes its self-check as the agent user", () => {
    const result = docker([
      "exec", containerId,
      "/usr/bin/node", "/usr/local/libexec/runfree/mcp/self-check.mjs", "--dispatcher", "/usr/local/bin/runfree-mcp",
    ]);
    expect(result.status, describeOutput(result.output)).toBe(0);
    expect(result.stdout).toContain("runfree-mcp self-check: ok");
    const owner = docker(["exec", containerId, "stat", "-c", "%U %a", "/usr/local/libexec/runfree/mcp/runfree-mcp.mjs", "/usr/local/bin/runfree-mcp"]);
    expect(owner.stdout.trim().split("\n"), describeOutput(owner.output)).toEqual(["root 644", "root 755"]);
  }, TEST_TIMEOUT_MS);

  test("the generated Codex config names the fixed dispatcher and carries no host value", () => {
    const config = docker(["exec", containerId, "cat", "/home/agent/.codex/config.toml"]);
    expect(config.status, describeOutput(config.output)).toBe(0);
    expect(config.stdout).toContain("[mcp_servers.node_repl]");
    expect(config.stdout).toContain('command = "/usr/local/bin/runfree-mcp"');
    expect(config.stdout).toContain('args = ["node-repl"]');
    expect(config.stdout).not.toContain(CANARY);
    expect(config.stdout).not.toContain("Codex.app");
    const explain = fixture.runfree(["mcp", "explain", "codex", "node_repl", "--source", "user"]);
    expect(explain.status, describeOutput(explain.output)).toBe(0);
    expect(explain.stdout).toContain("execution: portable container capability node-repl");
  }, TEST_TIMEOUT_MS);

  test("node-repl runs as the agent user in the workspace, without egress or proxy credentials", () => {
    const run = docker(["exec", containerId, "/usr/bin/node", "-e", IN_CONTAINER_CLIENT]);
    expect(run.status, describeOutput(run.output)).toBe(0);
    const results = JSON.parse(run.stdout) as Record<string, { isError: boolean; text: string }>;
    expect(results.uid.text).toBe("1000");
    expect(results.write).toEqual({ text: "ok", isError: false });
    expect(fs.readFileSync(path.join(fixture.projectRoot, "portable-mcp-live.txt"), "utf8")).toBe("from-kernel");
    expect(results.persist2.text).toBe("42");
    expect(results.env.isError).toBe(false);
    expect(results.env.text).not.toContain(PROXY_CREDENTIAL_VALUE);
    expect(results.env.text).not.toContain(CANARY);
    expect(results.egress.text).toMatch(/^refused:/);
  }, TEST_TIMEOUT_MS);
});
