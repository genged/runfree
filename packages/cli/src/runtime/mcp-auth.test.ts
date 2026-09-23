import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("./prepared-runtime.ts", () => ({
  preparedRuntimeContext: (prepared: { context: unknown }) => prepared.context,
}));

import { projectInfo } from "../config.ts";
import { mcpApprovalPath, mcpInventory, saveMcpApproval } from "./mcp.ts";
import { mcpAuthAdapterPlan, mcpAuthRuntime } from "./mcp-auth.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

const tempDirs: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function tempContext(configToml: string): RuntimeContext {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-auth-"));
  tempDirs.push(tmp);
  const projectRoot = path.join(tmp, "project");
  const home = path.join(tmp, "home");
  const codexHome = path.join(home, ".codex");
  fs.mkdirSync(codexHome, { recursive: true });
  fs.mkdirSync(projectRoot, { recursive: true });
  fs.writeFileSync(path.join(codexHome, "config.toml"), configToml);
  const env = {
    HOME: home,
    CODEX_HOME: codexHome,
    XDG_CONFIG_HOME: path.join(tmp, "config"),
    XDG_STATE_HOME: path.join(tmp, "state"),
  };
  const project = projectInfo(projectRoot, env);
  expect(project.paths.stateDir).toContain(tmp);
  return {
    projectRoot,
    project,
    runtimeRoot: path.join(tmp, "runtime"),
    env,
  };
}

function fakeIo(): RuntimeIO {
  return {
    admin: vi.fn(async () => 0),
    capture: vi.fn((_command: string, args: string[]) => {
      if (args[0] === "container" && args[1] === "inspect") {
        return {
          status: 1,
          stdout: "",
          stderr: `Error response from daemon: No such container: ${args[2]}`,
        };
      }
      if (args[0] === "network" && args[1] === "inspect") {
        return {
          status: 1,
          stdout: "",
          stderr: `Error response from daemon: network ${args[2]} not found`,
        };
      }
      return { status: 0, stdout: "", stderr: "" };
    }),
    commandExists: vi.fn(() => true),
    confirm: vi.fn(() => false),
    run: vi.fn(() => 0),
  };
}

function writeProjectCodexServer(context: RuntimeContext, server = "repo_tools", url = "https://repo-tools.example.com/mcp"): void {
  fs.mkdirSync(path.join(context.projectRoot, ".codex"), { recursive: true });
  fs.writeFileSync(path.join(context.projectRoot, ".codex", "config.toml"), [
    `[mcp_servers.${server}]`,
    `url = ${JSON.stringify(url)}`,
    "",
  ].join("\n"));
}

function approveProjectServer(context: RuntimeContext, server = "repo_tools"): void {
  const inventory = mcpInventory({
    approvalPath: mcpApprovalPath(context.project.paths.stateDir),
    env: context.env ?? process.env,
    projectRoot: context.projectRoot,
  });
  const entry = inventory.entries.find((candidate) =>
    candidate.agent === "codex" && candidate.source === "project" && candidate.name === server);
  if (!entry) throw new Error(`missing project MCP server: ${server}`);
  saveMcpApproval(context.projectRoot, mcpApprovalPath(context.project.paths.stateDir), entry);
}

describe("MCP auth runtime", () => {
  test("plans Codex and Claude agent-native auth adapters without OAuth URL handling", () => {
    const context = tempContext("");

    expect(mcpAuthAdapterPlan(context, { agent: "codex", server: "posthog" })).toMatchObject({
      command: ["codex", "mcp", "login", "posthog"],
      extraOptions: [],
      session: { command: "mcp auth codex/posthog" },
    });

    const claude = mcpAuthAdapterPlan(context, { agent: "claude", server: "sentry" });
    expect(claude.command.join(" ")).toContain("/mcp reconnect sentry");
    expect(claude.extraOptions).toContain(
      "RUNFREE_AGENT_COMMAND=claude --dangerously-skip-permissions --add-dir /runfree/inbox",
    );
    expect(claude.session).toMatchObject({
      agentCommand: "claude --dangerously-skip-permissions --add-dir /runfree/inbox",
      command: "mcp auth claude/sentry",
    });
  });

  test("rejects static-header targets before runtime startup", async () => {
    const context = tempContext([
      "[mcp_servers.static_mcp]",
      'url = "https://static.example.com/mcp"',
      'bearer_token_env_var = "STATIC_MCP_TOKEN"',
      "",
    ].join("\n"));
    const start = vi.fn();

    await expect(mcpAuthRuntime({ agent: "codex", server: "static_mcp" }, context, fakeIo(), { start })).rejects.toThrow(
      "static-header MCP server codex static_mcp uses a credential source, not OAuth login",
    );
    expect(start).not.toHaveBeenCalled();
  });

  test("rejects unapproved project targets before runtime startup", async () => {
    const context = tempContext("");
    writeProjectCodexServer(context);
    const start = vi.fn();

    await expect(mcpAuthRuntime({ agent: "codex", server: "repo_tools", source: "project" }, context, fakeIo(), { start })).rejects.toThrow(
      "project MCP server must be approved before auth: runfree mcp approve codex repo_tools",
    );
    expect(start).not.toHaveBeenCalled();
  });

  test("auth starts only for currently approved project targets", async () => {
    const context = tempContext("");
    writeProjectCodexServer(context);
    approveProjectServer(context);
    const io = fakeIo();
    const preparedRuntime = Object.freeze({ version: 1, context }) as never;
    const start = vi.fn(async () => ({
      kind: "ready" as const,
      preparedRuntime,
      fastPath: true,
      status: 0 as const,
      tokenResolutionReceipts: [],
    }));
    // Post-cutover the agent launches through per-session admission and the
    // operator authenticates interactively; there is no auto-typed login exec.
    const launch = vi.fn(async () => 0);
    const log = vi.spyOn(console, "log").mockImplementation(() => {});

    await expect(mcpAuthRuntime({ agent: "codex", server: "repo_tools", source: "project" }, context, io, {
      adaptersFor: () => ({ admin: vi.fn(async () => 0), docker: {} as never }),
      launch,
      start,
    })).resolves.toBe(0);

    expect(start).toHaveBeenCalled();
    expect(launch).toHaveBeenCalledWith(expect.objectContaining({ preparedRuntime, io, agentName: "codex" }));
    // Codex has no /mcp auth menu; the instruction names its login command.
    expect(log).toHaveBeenCalledWith(expect.stringContaining("codex mcp login repo_tools"));
    expect(log).not.toHaveBeenCalledWith(expect.stringContaining("type /mcp"));
  });

  test("rejects changed project targets before runtime startup", async () => {
    const context = tempContext("");
    writeProjectCodexServer(context, "repo_tools", "https://repo-tools.example.com/mcp");
    approveProjectServer(context);
    writeProjectCodexServer(context, "repo_tools", "https://changed.example.com/mcp");
    const start = vi.fn();

    await expect(mcpAuthRuntime({ agent: "codex", server: "repo_tools", source: "project" }, context, fakeIo(), { start })).rejects.toThrow(
      "project MCP server must be approved before auth: runfree mcp approve codex repo_tools",
    );
    expect(start).not.toHaveBeenCalled();
  });

  test("starts validated runtime and launches the agent for public HTTP targets", async () => {
    const context = tempContext([
      "[mcp_servers.posthog]",
      'url = "https://mcp.posthog.com/mcp"',
      "",
    ].join("\n"));
    const io = fakeIo();
    const preparedRuntime = Object.freeze({ version: 1, context }) as never;
    const start = vi.fn(async () => ({
      kind: "ready" as const,
      preparedRuntime,
      fastPath: true,
      status: 0 as const,
      tokenResolutionReceipts: [],
    }));
    const launch = vi.fn(async () => 0);
    const log = vi.spyOn(console, "log").mockImplementation(() => {});

    await expect(mcpAuthRuntime({ agent: "codex", server: "posthog" }, context, io, {
      adaptersFor: () => ({ admin: vi.fn(async () => 0), docker: {} as never }),
      launch,
      start,
    })).resolves.toBe(0);

    expect(start).toHaveBeenCalled();
    expect(launch).toHaveBeenCalledWith(expect.objectContaining({ preparedRuntime, io, agentName: "codex" }));
    expect(log).toHaveBeenCalledWith(expect.stringContaining("codex mcp login posthog"));
  });
});
