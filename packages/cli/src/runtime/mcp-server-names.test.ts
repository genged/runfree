import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { flushWarnings, setOutputWriterForTest } from "../warnings.ts";
import { mcpApprovalPath, mcpInventory, mcpServerNameRefusal, prepareMcpRuntime, saveMcpApproval } from "./mcp.ts";

const HTTP = { type: "http", url: "https://mcp.example.com/mcp" };

describe("mcpServerNameRefusal", () => {
  test("accepts what each agent's own mcp add accepts", () => {
    for (const name of ["posthog", "ok_name-1", "A", "x".repeat(128)]) {
      expect(mcpServerNameRefusal("claude", name), name).toBeUndefined();
      expect(mcpServerNameRefusal("codex", name), name).toBeUndefined();
    }
    for (const name of ["with.dot", "a:b", "user@host", "scope/name"]) {
      expect(mcpServerNameRefusal("codex", name), name).toBeUndefined();
      expect(mcpServerNameRefusal("claude", name), name).toMatch(/^server name must use only letters, numbers, '-', '_'$/);
    }
  });

  test("refuses the reserved name, empty and over-long names, and characters neither agent accepts", () => {
    expect(mcpServerNameRefusal("claude", "__proto__")).toBe("server name __proto__ is reserved");
    expect(mcpServerNameRefusal("codex", "__proto__")).toBe("server name __proto__ is reserved");
    for (const agent of ["claude", "codex"] as const) {
      expect(mcpServerNameRefusal(agent, "")).toBe("server name must be 1-128 characters");
      expect(mcpServerNameRefusal(agent, "x".repeat(129))).toBe("server name must be 1-128 characters");
      for (const name of ["with space", "ünï", "\ud800", "a\u001bb", "a‮b", "a\nb"]) {
        expect(mcpServerNameRefusal(agent, name), JSON.stringify(name)).toMatch(/^server name must use only /);
      }
    }
  });
});

describe("MCP server names in the inventory and at launch", () => {
  let tmp: string;
  let projectRoot: string;
  let hostHome: string;
  let stateDir: string;
  let output: string[];

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-names-"));
    projectRoot = path.join(tmp, "project");
    hostHome = path.join(tmp, "host-home");
    stateDir = path.join(tmp, "state");
    fs.mkdirSync(path.join(projectRoot, ".codex"), { recursive: true });
    fs.mkdirSync(path.join(hostHome, ".codex"), { recursive: true });
    fs.mkdirSync(stateDir, { recursive: true });
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
  const writeProject = (servers: string) => fs.writeFileSync(path.join(projectRoot, ".mcp.json"), `{"mcpServers": ${servers}}`);
  const writeHostClaude = (config: unknown) => fs.writeFileSync(path.join(hostHome, ".claude.json"), JSON.stringify(config));
  const inventory = () => mcpInventory({ projectRoot, env: env(), approvalPath: mcpApprovalPath(stateDir) });
  const decisions = () => inventory().entries.map((entry) => [entry.source, entry.agent, entry.name, entry.decision.status, entry.decision.reason ?? ""]);
  const warnings = () => {
    flushWarnings();
    const lines = output;
    output = [];
    return lines;
  };

  function prepare(): Record<string, unknown> {
    const runDir = path.join(tmp, "run");
    prepareMcpRuntime({
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
    return (JSON.parse(fs.readFileSync(path.join(runDir, "claude-mcp.json"), "utf8")) as { mcpServers: Record<string, unknown> }).mcpServers;
  }

  function approveAllProject(): void {
    for (const entry of inventory().entries) {
      if (entry.source === "project" && entry.decision.status === "unapproved") saveMcpApproval(projectRoot, mcpApprovalPath(stateDir), entry);
    }
  }

  test("a __proto__ server is listed as unsupported, not dropped", () => {
    writeProject(`{"__proto__": ${JSON.stringify(HTTP)}, "posthog": ${JSON.stringify(HTTP)}}`);
    expect(decisions()).toEqual([
      ["project", "claude", "__proto__", "unsupported", "server name __proto__ is reserved"],
      ["project", "claude", "posthog", "unapproved", "project MCP requires approval"],
    ]);
    expect(warnings()).toContainEqual(expect.stringContaining("mcp: skipped claude server __proto__ reason=server name __proto__ is reserved"));
  });

  test("a lone-surrogate name is listed as unsupported and launch still prepares the other servers", () => {
    writeProject(`{"\\ud800": ${JSON.stringify(HTTP)}, "posthog": ${JSON.stringify(HTTP)}}`);
    expect(decisions()[0]?.slice(3)).toEqual(["unsupported", "server name must use only letters, numbers, '-', '_'"]);
    approveAllProject();
    expect(Object.keys(prepare())).toEqual(["posthog"]);
  });

  test("a name with terminal escapes is printed escaped, never raw", () => {
    writeProject(`{"a\\u001b]52;c;eA==\\u0007b": ${JSON.stringify(HTTP)}}`);
    inventory();
    const lines = warnings();
    expect(lines).toContainEqual(expect.stringContaining("mcp: skipped claude server a\\u{1b}]52;c;eA==\\u{7}b reason="));
    expect(lines.join("\n")).not.toMatch(/[\u001b\u0007]/);
  });

  test("an invalid .mcp.json warning escapes the file text the parse error quotes", () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), '{"mcpServers": {"a": \u001b[2J}}');
    inventory();
    const lines = warnings();
    expect(lines.some((line) => line.includes("skipped project claude config .mcp.json"))).toBe(true);
    expect(lines.join("\n")).not.toContain("\u001b");
  });

  test("a dotted name is refused for Claude and accepted for Codex", () => {
    writeProject(`{"with.dot": ${JSON.stringify(HTTP)}}`);
    fs.writeFileSync(path.join(projectRoot, ".codex", "config.toml"), '[mcp_servers."with.dot"]\nurl = "https://mcp.example.com/mcp"\n');
    expect(decisions().map((row) => row.slice(1, 4))).toEqual([
      ["claude", "with.dot", "unsupported"],
      ["codex", "with.dot", "unapproved"],
    ]);
  });

  test("project names that differ only by case are all skipped, and launch does not throw", () => {
    // Before the check, approving both crashed launch: duplicate OAuth provider id mcp:claude-foo.
    writeProject(`{"Foo": ${JSON.stringify(HTTP)}, "foo": ${JSON.stringify(HTTP)}, "bar": ${JSON.stringify(HTTP)}}`);
    expect(decisions().map((row) => row.slice(2))).toEqual([
      ["Foo", "unsupported", "server name collides with MCP server foo"],
      ["foo", "unsupported", "server name collides with MCP server Foo"],
      ["bar", "unapproved", "project MCP requires approval"],
    ]);
    approveAllProject();
    expect(Object.keys(prepare())).toEqual(["bar"]);
  });

  test("names that differ only past the 96-character operation ID cut collide", () => {
    const [left, right] = [`${"x".repeat(96)}a`, `${"x".repeat(96)}b`];
    writeProject(`{"${left}": ${JSON.stringify(HTTP)}, "${right}": ${JSON.stringify(HTTP)}}`);
    expect(decisions().map((row) => row[3])).toEqual(["unsupported", "unsupported"]);
  });

  test("a project name colliding with a user server is the one skipped; the user server stays", () => {
    writeHostClaude({ mcpServers: { Sentry: HTTP } });
    writeProject(`{"sentry": ${JSON.stringify(HTTP)}}`);
    expect(decisions()).toEqual([
      ["user", "claude", "Sentry", "imported", ""],
      ["project", "claude", "sentry", "conflict", "server name collides with imported MCP server Sentry"],
    ]);
    expect(Object.keys(prepare())).toEqual(["Sentry"]);
  });

  test("user and local names that collide are both skipped", () => {
    writeHostClaude({ mcpServers: { Sentry: HTTP }, projects: { [projectRoot]: { mcpServers: { sentry: HTTP } } } });
    expect(decisions().map((row) => row.slice(0, 4))).toEqual([
      ["user", "claude", "Sentry", "unsupported"],
      ["local", "claude", "sentry", "unsupported"],
    ]);
    expect(prepare()).toEqual({});
  });

  test("the same exact name in user and project config keeps the existing imported-wins conflict", () => {
    writeHostClaude({ mcpServers: { sentry: HTTP } });
    writeProject(`{"sentry": ${JSON.stringify(HTTP)}}`);
    expect(decisions().map((row) => row.slice(0, 4))).toEqual([
      ["user", "claude", "sentry", "imported"],
      ["project", "claude", "sentry", "conflict"],
    ]);
  });
});
