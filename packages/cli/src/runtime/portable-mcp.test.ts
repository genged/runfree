import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { parse as parseToml } from "smol-toml";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { flushWarnings, pendingWarningsForTest } from "../warnings.ts";
import { mcpApprovalPath, mcpInventory, prepareMcpRuntime, saveMcpApproval, setMcpLogContext } from "./mcp.ts";
import { classifyPortableMcp, PORTABLE_MCP_CATALOG, PORTABLE_MCP_DISPATCHER, PORTABLE_MESSAGES } from "./portable-mcp.ts";

// Descriptor shapes from public Codex issue reports (openai/codex#26262,
// #26560, #29219, #28479).
const DESKTOP_NODE_REPL = "/Applications/Codex.app/Contents/Resources/node_repl";
const DESKTOP_CUA_NODE_REPL = "/Applications/Codex.app/Contents/Resources/cua_node/bin/node_repl";

function nodeRepl(config: Record<string, unknown> = {}): Record<string, unknown> {
  return { command: DESKTOP_NODE_REPL, args: [], startup_timeout_sec: 120, ...config };
}

describe("classifyPortableMcp", () => {
  test("maps exact Codex Desktop node_repl descriptors to the node-repl capability", () => {
    for (const config of [
      nodeRepl(),
      nodeRepl({ command: DESKTOP_CUA_NODE_REPL, args: ["--disable-sandbox"] }),
      nodeRepl({ command: "/Users/someone/Applications/Codex.app/Contents/Resources/node_repl" }),
      nodeRepl({ args: undefined, type: "stdio" }),
      nodeRepl({
        env: {
          BROWSER_USE_AVAILABLE_BACKENDS: "iab",
          CODEX_CLI_PATH: "/Applications/Codex.app/Contents/Resources/codex",
          CODEX_HOME: "/Users/someone/.codex",
          NODE_REPL_NATIVE_PIPE_CONNECT_TIMEOUT_MS: "10000",
          NODE_REPL_NODE_PATH: "/Applications/Codex.app/Contents/Resources/node",
          NODE_REPL_TRUSTED_CODE_PATHS: "/Users/someone/.codex",
          SKY_CUA_SERVICE_PATH: "/Users/someone/.codex/plugins/cache/x",
        },
        env_vars: [],
      }),
    ]) {
      const result = classifyPortableMcp({ agent: "codex", name: "node_repl", config });
      expect(result.kind).toBe("portable");
      if (result.kind === "portable") expect(result.capability.id).toBe("node-repl");
    }
  });

  test("keeps only safe scalar options and never keeps required", () => {
    const result = classifyPortableMcp({
      agent: "codex",
      name: "node_repl",
      config: nodeRepl({ required: true, enabled: true, tool_timeout_sec: 60, enabled_tools: ["js"], disabled_tools: ["js_reset"] }),
    });
    expect(result).toEqual({
      kind: "portable",
      capability: PORTABLE_MCP_CATALOG["node-repl"],
      options: { startup_timeout_sec: 120, tool_timeout_sec: 60, enabled: true, enabled_tools: ["js"], disabled_tools: ["js_reset"] },
    });
  });

  test("classifies look-alike node_repl descriptors as changed", () => {
    const changed = [
      nodeRepl({ args: ["--disable-sandbox=1"] }),
      nodeRepl({ args: ["--eval", "x"] }),
      nodeRepl({ env: { NODE_OPTIONS: "--require /tmp/x.js" } }),
      nodeRepl({ env: { CODEX_HOME: 1 } }),
      nodeRepl({ env_vars: ["OPENAI_API_KEY"] }),
      nodeRepl({ cwd: "/Users/someone" }),
      nodeRepl({ unknown_key: true }),
      nodeRepl({ type: "http" }),
      nodeRepl({ startup_timeout_sec: -1 }),
      nodeRepl({ enabled_tools: [1] }),
      nodeRepl({ command: "/Applications/Codex.app/Contents/Resources/../Resources/node_repl" }),
      nodeRepl({ command: "/Applications//Codex.app/Contents/Resources/node_repl" }),
      nodeRepl({ command: "/Codex.app/Contents/Resources/node_repl" }),
      nodeRepl({ command: "Applications/Codex.app/Contents/Resources/node_repl" }),
      nodeRepl({ command: "/Applications/Codex.app/Contents/MacOS/node_repl" }),
      nodeRepl({ command: "/Applications/Codéx.app/Contents/Resources/node_repl" }),
      nodeRepl({ command: "/opt/tools/node_repl" }),
      nodeRepl({ command: "C:\\Users\\x\\AppData\\Local\\OpenAI\\Codex\\bin\\abc\\node_repl.exe" }),
    ];
    for (const config of changed) {
      expect(classifyPortableMcp({ agent: "codex", name: "node_repl", config })).toEqual({
        kind: "changed",
        capabilityId: "node-repl",
        reason: PORTABLE_MESSAGES.changed,
      });
    }
    // A Codex Desktop node_repl command under another server name is also a look-alike.
    expect(classifyPortableMcp({ agent: "codex", name: "repl", config: nodeRepl() }).kind).toBe("changed");
  });

  test("leaves other descriptors to the generic STDIO rules", () => {
    expect(classifyPortableMcp({ agent: "claude", name: "node_repl", config: nodeRepl() }).kind).toBe("none");
    expect(classifyPortableMcp({ agent: "codex", name: "node_repl", config: { command: "node_repl" } }).kind).toBe("none");
    expect(classifyPortableMcp({ agent: "codex", name: "node_repl ", config: { command: "npx" } }).kind).toBe("none");
    expect(classifyPortableMcp({ agent: "codex", name: "nоde_repl", config: { command: "npx" } }).kind).toBe("none");
    expect(classifyPortableMcp({ agent: "codex", name: "docs", config: { command: "/opt/bin/docs-mcp" } }).kind).toBe("none");
  });

  test("classifies Codex computer-use descriptors as host-desktop tools", () => {
    const computerUse = {
      command: "./Codex Computer Use.app/Contents/SharedSupport/SkyComputerUseClient.app/Contents/MacOS/SkyComputerUseClient",
      args: ["mcp"],
      cwd: "/Users/someone/.codex/plugins/cache/openai-bundled/computer-use/1.0.809/.",
    };
    for (const [name, config] of [
      ["computer-use", computerUse],
      ["unified-computer-use", { command: "/somewhere/else" }],
      ["cua", computerUse],
      ["cua", { command: "/Users/someone/.codex/plugins/cache/openai-bundled/computer-use/2.0.0/bin/tool" }],
    ] as const) {
      expect(classifyPortableMcp({ agent: "codex", name, config: { ...config } })).toEqual({
        kind: "host-desktop",
        reason: PORTABLE_MESSAGES.hostDesktop,
      });
    }
  });
});

describe("portable MCP import", () => {
  let tmp: string;
  let projectRoot: string;
  let hostHome: string;
  let hostCodexDir: string;
  let paths: { claudeConfigPath: string; claudeMcpConfigPath: string; codexDir: string; mcpOAuthPolicyPath: string; mcpOperationPolicyPath: string; stateDir: string };

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-portable-mcp-"));
    projectRoot = path.join(tmp, "project");
    hostHome = path.join(tmp, "host-home");
    hostCodexDir = path.join(hostHome, ".codex");
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.mkdirSync(hostCodexDir, { recursive: true });
    const stateDir = path.join(tmp, "state");
    paths = {
      claudeConfigPath: path.join(stateDir, "claude", "claude.json"),
      claudeMcpConfigPath: path.join(stateDir, "mounts", "claude-mcp.json"),
      codexDir: path.join(stateDir, "codex"),
      mcpOAuthPolicyPath: path.join(stateDir, "mcp-oauth-policy.json"),
      mcpOperationPolicyPath: path.join(stateDir, "mcp-operation-policy.json"),
      stateDir,
    };
    flushWarnings();
    setMcpLogContext({});
  });

  afterEach(() => {
    flushWarnings();
    setMcpLogContext({});
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const env = () => ({ HOME: hostHome, CODEX_HOME: hostCodexDir });

  function prepare(approvalPath?: string): void {
    prepareMcpRuntime({
      ...(approvalPath ? { approvalPath } : {}),
      callbackPort: 47638,
      claudeConfigPath: paths.claudeConfigPath,
      claudeMcpConfigPath: paths.claudeMcpConfigPath,
      codexDir: paths.codexDir,
      env: env(),
      mcpOAuthPolicyPath: paths.mcpOAuthPolicyPath,
      mcpOperationPolicyPath: paths.mcpOperationPolicyPath,
      policy: { hosts: [], tokens: {} },
      projectRoot,
      tokenConfig: {},
    });
  }

  function generatedCodexToml(): string {
    return fs.readFileSync(path.join(paths.codexDir, "config.toml"), "utf8");
  }

  function warnings(): string[] {
    const lines = pendingWarningsForTest().map((event) => event.message);
    flushWarnings();
    return lines;
  }

  // Canary values that must never leave the host descriptor.
  const CANARY_HOME = "/Users/canary-host-user";
  const hostNodeReplToml = [
    "[mcp_servers.node_repl]",
    `command = "${CANARY_HOME}/Applications/Codex.app/Contents/Resources/cua_node/bin/node_repl"`,
    'args = ["--disable-sandbox"]',
    "startup_timeout_sec = 120",
    "required = true",
    "",
    "[mcp_servers.node_repl.env]",
    `NODE_REPL_NODE_PATH = "${CANARY_HOME}/canary-node-path"`,
    `CODEX_HOME = "${CANARY_HOME}/.codex-canary"`,
    'CODEX_CLI_PATH = "/Applications/Codex.app/Contents/Resources/canary-codex"',
    "",
  ].join("\n");

  test("a user Codex node_repl becomes the fixed container dispatcher with no host values", () => {
    fs.writeFileSync(path.join(hostCodexDir, "config.toml"), hostNodeReplToml);

    setMcpLogContext({ agent: "codex" });
    prepare();

    const toml = generatedCodexToml();
    const parsed = parseToml(toml) as { mcp_servers: Record<string, Record<string, unknown>> };
    expect(parsed.mcp_servers.node_repl).toEqual({
      command: PORTABLE_MCP_DISPATCHER,
      args: ["node-repl"],
      startup_timeout_sec: 120,
    });
    for (const text of [toml, fs.readFileSync(paths.claudeMcpConfigPath, "utf8"), ...warnings()]) {
      expect(text).not.toContain("canary");
      expect(text).not.toContain("disable-sandbox");
      expect(text).not.toContain("Codex.app");
    }

    const entry = mcpInventory({ projectRoot, env: env() }).entries.find((candidate) => candidate.name === "node_repl");
    expect(entry).toMatchObject({
      agent: "codex",
      decision: { status: "imported" },
      portable: { capability: "node-repl", contractVersion: 1, bundleVersion: PORTABLE_MCP_CATALOG["node-repl"].bundleVersion },
      target: "generated",
      transport: "stdio",
    });
    expect(JSON.stringify(entry?.descriptor)).not.toContain("canary");
    expect(entry?.descriptor).toMatchObject({ portable: { capability: "node-repl", contractVersion: 1 } });
  });

  test("the import line names the portable capability and ignores the host command", () => {
    fs.writeFileSync(path.join(hostCodexDir, "config.toml"), hostNodeReplToml);
    setMcpLogContext({ agent: "codex" });
    prepare();
    expect(warnings().filter((line) => line.startsWith("mcp: "))).toEqual([
      "mcp: imported user codex server node_repl transport=stdio portable=node-repl; host command ignored",
    ]);
  });

  test("changed and host-desktop descriptors are skipped with precise reasons while other servers import", () => {
    fs.writeFileSync(path.join(hostCodexDir, "config.toml"), [
      "[mcp_servers.node_repl]",
      `command = "${DESKTOP_NODE_REPL}"`,
      'args = ["--eval", "canary-arg"]',
      "",
      '[mcp_servers."computer-use"]',
      'command = "./Codex Computer Use.app/Contents/SharedSupport/SkyComputerUseClient.app/Contents/MacOS/SkyComputerUseClient"',
      'args = ["mcp"]',
      'cwd = "/Users/canary/.codex/plugins/cache/openai-bundled/computer-use/1.0.809/."',
      "",
      "[mcp_servers.posthog]",
      'url = "https://mcp.posthog.com/mcp"',
      "",
    ].join("\n"));

    setMcpLogContext({ agent: "codex" });
    prepare();

    const lines = warnings().filter((line) => line.startsWith("mcp: "));
    expect(lines).toContain(`mcp: skipped user codex server node_repl reason=${PORTABLE_MESSAGES.changed}`);
    expect(lines).toContain(`mcp: skipped user codex server computer-use reason=${PORTABLE_MESSAGES.hostDesktop}`);
    expect(lines).toContain("mcp: imported user codex server posthog transport=http auth=public");
    const parsed = parseToml(generatedCodexToml()) as { mcp_servers: Record<string, unknown> };
    expect(Object.keys(parsed.mcp_servers)).toEqual(["posthog"]);
    expect(generatedCodexToml()).not.toContain("canary");

    const entries = mcpInventory({ projectRoot, env: env() }).entries;
    expect(entries.find((entry) => entry.name === "node_repl")?.decision).toEqual({ status: "unsupported", reason: PORTABLE_MESSAGES.changed });
    expect(entries.find((entry) => entry.name === "computer-use")?.decision).toEqual({ status: "unsupported", reason: PORTABLE_MESSAGES.hostDesktop });
  });

  test("a host-path STDIO command that is not portable gets the precise generic reason", () => {
    fs.writeFileSync(path.join(hostCodexDir, "config.toml"), [
      "[mcp_servers.docs]",
      'command = "/opt/homebrew/bin/docs-mcp"',
      "",
    ].join("\n"));
    prepare();
    expect(warnings()).toContain(`mcp: skipped codex server docs reason=${PORTABLE_MESSAGES.notPortable}`);
  });

  test("a project node_repl needs approval bound to the capability and contract, not the host path", () => {
    const projectCodex = path.join(projectRoot, ".codex");
    fs.mkdirSync(projectCodex, { recursive: true });
    const writeProject = (command: string, extra: string[] = []) => fs.writeFileSync(path.join(projectCodex, "config.toml"), [
      "[mcp_servers.node_repl]",
      `command = "${command}"`,
      "args = []",
      ...extra,
      "",
    ].join("\n"));
    const approvalPath = mcpApprovalPath(paths.stateDir);
    const projectEntry = () => {
      const entry = mcpInventory({ projectRoot, env: env(), approvalPath }).entries.find((candidate) => candidate.source === "project" && candidate.name === "node_repl");
      if (!entry) throw new Error("project node_repl entry missing");
      return entry;
    };

    writeProject(DESKTOP_NODE_REPL);
    expect(projectEntry()).toMatchObject({ decision: { status: "unapproved" }, target: "excluded" });
    setMcpLogContext({ agent: "codex" });
    prepare(approvalPath);
    expect(generatedCodexToml()).not.toContain("node_repl");
    flushWarnings();

    const approval = saveMcpApproval(projectRoot, approvalPath, projectEntry());
    expect(approval.summary).toBe("codex node_repl stdio/none portable:node-repl@1");
    expect(projectEntry()).toMatchObject({ decision: { status: "approved" }, target: "generated" });
    prepare(approvalPath);
    expect((parseToml(generatedCodexToml()) as { mcp_servers: Record<string, unknown> }).mcp_servers.node_repl).toEqual({
      command: PORTABLE_MCP_DISPATCHER,
      args: ["node-repl"],
    });

    // Moving the host app does not change the approved behavior.
    writeProject("/Users/someone/Applications/Codex.app/Contents/Resources/node_repl");
    expect(projectEntry().decision.status).toBe("approved");

    // A changed safe option changes the approved behavior.
    writeProject(DESKTOP_NODE_REPL, ["tool_timeout_sec = 5"]);
    expect(projectEntry().decision).toEqual({ status: "changed", reason: "approval changed" });
  });

  test("a look-alike project node_repl cannot be approved and nothing is written", () => {
    const projectCodex = path.join(projectRoot, ".codex");
    fs.mkdirSync(projectCodex, { recursive: true });
    fs.writeFileSync(path.join(projectCodex, "config.toml"), [
      "[mcp_servers.node_repl]",
      `command = "${DESKTOP_NODE_REPL}"`,
      'args = ["--inspect"]',
      "",
    ].join("\n"));
    const approvalPath = mcpApprovalPath(paths.stateDir);
    const entry = mcpInventory({ projectRoot, env: env(), approvalPath }).entries.find((candidate) => candidate.name === "node_repl");
    if (!entry) throw new Error("project node_repl entry missing");
    expect(entry.decision).toEqual({ status: "unsupported", reason: PORTABLE_MESSAGES.changed });
    expect(entry.descriptorDigest).toBeUndefined();
    expect(() => saveMcpApproval(projectRoot, approvalPath, entry)).toThrow("unsupported project MCP entry cannot be approved");
    expect(fs.existsSync(approvalPath)).toBe(false);
  });

  test("a Claude node_repl descriptor keeps the generic STDIO rules", () => {
    fs.writeFileSync(path.join(hostHome, ".claude.json"), JSON.stringify({
      mcpServers: { node_repl: { type: "stdio", command: DESKTOP_NODE_REPL, args: [] } },
    }));
    prepare();
    expect(warnings()).toContain(`mcp: skipped claude server node_repl reason=${PORTABLE_MESSAGES.notPortable}`);
    expect(JSON.parse(fs.readFileSync(paths.claudeMcpConfigPath, "utf8"))).toEqual({ mcpServers: {} });
  });
});
