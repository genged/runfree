import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { parse as parseToml } from "smol-toml";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { flushWarnings, setOutputWriterForTest } from "../warnings.ts";
import { mcpApprovalPath, mcpInventory, prepareMcpRuntime, saveMcpApproval, setMcpLogContext } from "./mcp.ts";
import { CODEX_DESKTOP_BUILTIN_REASON, isCodexDesktopBuiltIn } from "./mcp-desktop-builtins.ts";

// Entry shapes the Codex Desktop app writes into ~/.codex/config.toml (public
// Codex issue reports openai/codex#26262, #26560, #29219, #28479).
const DESKTOP_NODE_REPL = "/Applications/Codex.app/Contents/Resources/node_repl";
const DESKTOP_CUA_NODE_REPL = "/Applications/Codex.app/Contents/Resources/cua_node/bin/node_repl";
const COMPUTER_USE = {
  command: "./Codex Computer Use.app/Contents/SharedSupport/SkyComputerUseClient.app/Contents/MacOS/SkyComputerUseClient",
  args: ["mcp"],
  cwd: "/Users/someone/.codex/plugins/cache/openai-bundled/computer-use/1.0.809/.",
};

const builtIn = (name: string, config: Record<string, unknown>, agent = "codex") => isCodexDesktopBuiltIn({ agent, name, config });

describe("isCodexDesktopBuiltIn", () => {
  test("matches the Codex Desktop node_repl and computer-use entries", () => {
    expect(builtIn("node_repl", { command: DESKTOP_NODE_REPL, args: [] })).toBe(true);
    expect(builtIn("node_repl", { command: DESKTOP_CUA_NODE_REPL, args: ["--disable-sandbox"], env: { CODEX_HOME: "/Users/x/.codex" } })).toBe(true);
    expect(builtIn("node_repl", { command: "/Users/someone/Applications/Codex.app/Contents/Resources/node_repl" })).toBe(true);
    expect(builtIn("computer-use", COMPUTER_USE)).toBe(true);
    expect(builtIn("cua", COMPUTER_USE)).toBe(true);
    expect(builtIn("unified-computer-use", { command: "/somewhere/else" })).toBe(true);
    expect(builtIn("cua", { command: "/Users/someone/.codex/plugins/cache/openai-bundled/computer-use/2.0.0/bin/tool" })).toBe(true);
  });

  test("does not match look-alikes, which keep the generic STDIO rules", () => {
    for (const command of [
      "node_repl",
      "/opt/tools/node_repl",
      "/Applications/Codex.app/Contents/MacOS/node_repl",
      "/Applications/Codex.app/Contents/Resources/../Resources/node_repl",
      "/Applications//Codex.app/Contents/Resources/node_repl",
      "/Codex.app/Contents/Resources/node_repl",
      "Applications/Codex.app/Contents/Resources/node_repl",
      "/Applications/Codéx.app/Contents/Resources/node_repl",
      "C:\\Users\\x\\AppData\\Local\\OpenAI\\Codex\\bin\\abc\\node_repl.exe",
    ]) {
      expect(builtIn("node_repl", { command }), command).toBe(false);
    }
    // The Desktop command under another name, or for another agent.
    expect(builtIn("repl", { command: DESKTOP_NODE_REPL })).toBe(false);
    expect(builtIn("node_repl", { command: DESKTOP_NODE_REPL }, "claude")).toBe(false);
    expect(builtIn("node_repl ", { command: DESKTOP_NODE_REPL })).toBe(false);
    expect(builtIn("nоde_repl", { command: DESKTOP_NODE_REPL })).toBe(false);
    // A bare command under a computer-use name may be the project's own tool.
    expect(builtIn("computer-use", { command: "computer-use-mcp" })).toBe(false);
    expect(builtIn("docs", { command: "/opt/bin/docs-mcp" })).toBe(false);
  });
});

describe("Codex Desktop built-ins at launch", () => {
  let tmp: string;
  let projectRoot: string;
  let hostHome: string;
  let hostCodexDir: string;
  let stateDir: string;
  let codexDir: string;
  let claudeMcpConfigPath: string;
  let output: string[];

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-desktop-builtins-"));
    projectRoot = path.join(tmp, "project");
    hostHome = path.join(tmp, "host-home");
    hostCodexDir = path.join(hostHome, ".codex");
    stateDir = path.join(tmp, "state");
    codexDir = path.join(stateDir, "codex");
    claudeMcpConfigPath = path.join(stateDir, "mounts", "claude-mcp.json");
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.mkdirSync(hostCodexDir, { recursive: true });
    flushWarnings();
    output = [];
    setOutputWriterForTest((line) => output.push(line));
    setMcpLogContext({});
  });

  afterEach(() => {
    flushWarnings();
    setOutputWriterForTest(undefined);
    setMcpLogContext({});
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const env = () => ({ HOME: hostHome, CODEX_HOME: hostCodexDir });

  // Everything the launch printed, warnings flushed.
  function prepare(approvalPath?: string): string[] {
    prepareMcpRuntime({
      ...(approvalPath ? { approvalPath } : {}),
      callbackPort: 47638,
      claudeConfigPath: path.join(stateDir, "claude", "claude.json"),
      claudeMcpConfigPath,
      codexDir,
      env: env(),
      mcpOAuthPolicyPath: path.join(stateDir, "mcp-oauth-policy.json"),
      mcpOperationPolicyPath: path.join(stateDir, "mcp-operation-policy.json"),
      policy: { hosts: [], tokens: {} },
      projectRoot,
      tokenConfig: {},
    });
    flushWarnings();
    const lines = output;
    output = [];
    return lines;
  }

  const generatedServers = () => Object.keys((parseToml(fs.readFileSync(path.join(codexDir, "config.toml"), "utf8")) as { mcp_servers?: Record<string, unknown> }).mcp_servers ?? {});

  // Canary values that must never leave the host entry.
  const hostToml = [
    "[mcp_servers.node_repl]",
    'command = "/Users/canary/Applications/Codex.app/Contents/Resources/cua_node/bin/node_repl"',
    'args = ["--disable-sandbox"]',
    "startup_timeout_sec = 120",
    "",
    "[mcp_servers.node_repl.env]",
    'NODE_REPL_NODE_PATH = "/Users/canary/node"',
    "",
    '[mcp_servers."computer-use"]',
    `command = "${COMPUTER_USE.command}"`,
    'args = ["mcp"]',
    `cwd = "${COMPUTER_USE.cwd.replace("someone", "canary")}"`,
    "",
    "[mcp_servers.posthog]",
    'url = "https://mcp.posthog.com/mcp"',
    "",
  ].join("\n");

  test("are skipped with no output on a normal launch and never reach the generated config", () => {
    fs.writeFileSync(path.join(hostCodexDir, "config.toml"), hostToml);
    setMcpLogContext({ agent: "codex" });

    const lines = prepare();

    expect(lines).toEqual([expect.stringContaining("mcp: imported user codex server posthog transport=http auth=public")]);
    expect(generatedServers()).toEqual(["posthog"]);
    const generated = fs.readFileSync(path.join(codexDir, "config.toml"), "utf8") + fs.readFileSync(claudeMcpConfigPath, "utf8");
    expect(generated).not.toContain("canary");
    expect(generated).not.toContain("node_repl");
    expect(generated).not.toContain("computer-use");
  });

  test("get one line each under --verbose", () => {
    fs.writeFileSync(path.join(hostCodexDir, "config.toml"), hostToml);
    setMcpLogContext({ agent: "codex", verbose: true });

    const lines = prepare();

    expect(lines.filter((line) => line.includes("Codex Desktop built-in"))).toEqual([
      expect.stringMatching(/^(\S+ )?runfree: mcp: skipped Codex Desktop built-in node_repl; not used in Runfree$/),
      expect.stringMatching(/^(\S+ )?runfree: mcp: skipped Codex Desktop built-in computer-use; not used in Runfree$/),
    ]);
    expect(lines.join("\n")).not.toContain("warning: mcp: skipped");
    expect(generatedServers()).toEqual(["posthog"]);
  });

  test("are not reported to a Claude launch, even with --verbose", () => {
    fs.writeFileSync(path.join(hostCodexDir, "config.toml"), hostToml);
    setMcpLogContext({ agent: "claude", verbose: true });
    expect(prepare().join("\n")).not.toContain("Codex Desktop built-in");
  });

  test("appear in the inventory as skipped and excluded", () => {
    fs.writeFileSync(path.join(hostCodexDir, "config.toml"), hostToml);
    const entries = mcpInventory({ projectRoot, env: env() }).entries;
    for (const name of ["node_repl", "computer-use"]) {
      const entry = entries.find((candidate) => candidate.name === name);
      expect(entry).toMatchObject({
        agent: "codex",
        decision: { status: "skipped", reason: CODEX_DESKTOP_BUILTIN_REASON },
        target: "excluded",
        transport: "stdio",
      });
      expect(entry?.descriptor).toBeUndefined();
      expect(JSON.stringify(entry)).not.toContain("canary");
    }
    flushWarnings();
    expect(output).toEqual([]);
  });

  test("a project copy cannot be approved and nothing is written", () => {
    fs.mkdirSync(path.join(projectRoot, ".codex"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".codex", "config.toml"), `[mcp_servers.node_repl]\ncommand = "${DESKTOP_NODE_REPL}"\n`);
    const approvalPath = mcpApprovalPath(stateDir);
    const entry = mcpInventory({ projectRoot, env: env(), approvalPath }).entries.find((candidate) => candidate.name === "node_repl");
    if (!entry) throw new Error("project node_repl entry missing");
    expect(entry).toMatchObject({ source: "project", decision: { status: "skipped" }, target: "excluded" });
    expect(() => saveMcpApproval(projectRoot, approvalPath, entry)).toThrow("unsupported project MCP entry cannot be approved");
    expect(fs.existsSync(approvalPath)).toBe(false);
    expect(prepare(approvalPath).join("\n")).not.toContain("node_repl");
  });

  test("a look-alike node_repl keeps the host-path warning and is not generated", () => {
    fs.writeFileSync(path.join(hostCodexDir, "config.toml"), [
      "[mcp_servers.node_repl]",
      'command = "/opt/tools/node_repl"',
      "",
      "[mcp_servers.repl]",
      `command = "${DESKTOP_NODE_REPL}"`,
      "",
    ].join("\n"));
    setMcpLogContext({ agent: "codex" });

    const lines = prepare();

    for (const name of ["node_repl", "repl"]) {
      expect(lines).toContainEqual(expect.stringMatching(new RegExp(`runfree warning: mcp: skipped codex server ${name} reason=local stdio command must be installed in the container PATH$`)));
    }
    expect(lines.join("\n")).not.toContain("Codex Desktop built-in");
    expect(generatedServers()).toEqual([]);
    const entries = mcpInventory({ projectRoot, env: env() }).entries;
    expect(entries.find((entry) => entry.name === "node_repl")?.decision.status).toBe("unsupported");
  });

  test("a bare-command node_repl keeps the generic STDIO rules and is imported", () => {
    fs.writeFileSync(path.join(hostCodexDir, "config.toml"), '[mcp_servers.node_repl]\ncommand = "node_repl"\n');
    setMcpLogContext({ agent: "codex" });

    const lines = prepare();

    expect(lines).toContainEqual(expect.stringContaining("mcp: imported user codex server node_repl transport=stdio auth=none"));
    expect((parseToml(fs.readFileSync(path.join(codexDir, "config.toml"), "utf8")) as { mcp_servers: Record<string, unknown> }).mcp_servers.node_repl)
      .toMatchObject({ command: "node_repl" });
  });
});
