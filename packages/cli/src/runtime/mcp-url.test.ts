import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

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
