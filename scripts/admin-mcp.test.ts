import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import util from "node:util";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

// `runfree mcp configure` drives clack prompts on a TTY. A test that sets
// `clack.select`/`clack.confirm` answers them; every other test gets clack.
const clack = vi.hoisted(() => ({
  select: undefined as undefined | ((options: { message: string; options: Array<{ value: string; label: string }> }) => Promise<unknown>),
  confirm: undefined as undefined | ((options: { message: string }) => Promise<unknown>),
}));
vi.mock("@clack/prompts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@clack/prompts")>();
  return {
    ...actual,
    select: ((options: Parameters<typeof actual.select>[0]) => clack.select
      ? clack.select(options as never)
      : actual.select(options)) as typeof actual.select,
    confirm: ((options: Parameters<typeof actual.confirm>[0]) => clack.confirm
      ? clack.confirm(options)
      : actual.confirm(options)) as typeof actual.confirm,
  };
});

import type { HostServicesJson } from "@runfree/runtime-contracts/host-services";
import type { PolicyJson } from "@runfree/runtime-contracts/network-policy";
import { createAdminState } from "../packages/cli/src/admin/context.ts";
import type { McpEnableInput } from "../packages/cli/src/admin/admin-core.ts";
import { type McpLoopbackDeps, printable } from "../packages/cli/src/admin/mcp-admin.ts";
import type { HostPortOwner } from "../packages/cli/src/host-service-port-owner.ts";
import type { DiscoveryDeps } from "../packages/cli/src/admin/mcp-discovery.ts";
import {
  mcpConfigureIntent,
  mcpEnableIntent,
  mcpExplainIntent,
  mcpListIntent,
  mcpRulesIntent,
  mcpRevokeIntent,
  parseMcpAgent,
  parseMcpSource,
  prepareEffectiveRuntimeIntent,
  runAdminAction,
} from "../packages/cli/src/admin/options.ts";
import { projectHash } from "../packages/cli/src/project-identity.ts";
import { flushWarnings } from "../packages/cli/src/warnings.ts";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);

let tmpBase: string;
let projectRoot: string;
let home: string;
let stateDir: string;
let claudeJsonPath: string;
let claudeMcpConfigPath: string;
let codexHome: string;

type AdminRunResult = {
  status: number;
  stderr: string;
  stdout: string;
};

function writeFixtureRepo(policy: unknown): void {
  fs.mkdirSync(path.join(projectRoot, ".runfree"), { recursive: true });
  fs.mkdirSync(path.join(projectRoot, ".runfree/config"), { recursive: true });
  fs.writeFileSync(path.join(projectRoot, ".runfree/network-policy.json"), `${JSON.stringify(policy, null, 2)}\n`);
}

function writeClaudeNative(config: unknown): void {
  fs.mkdirSync(home, { recursive: true });
  fs.writeFileSync(path.join(home, ".claude.json"), `${JSON.stringify(config, null, 2)}\n`);
}

function writeCodexNative(source: string): void {
  const codexDir = path.join(home, ".codex");
  fs.mkdirSync(codexDir, { recursive: true });
  fs.writeFileSync(path.join(codexDir, "config.toml"), source);
}

async function runAdmin(action: () => void | Promise<void>, extraEnv: NodeJS.ProcessEnv = {}): Promise<AdminRunResult> {
  fs.mkdirSync(path.dirname(claudeJsonPath), { recursive: true });
  fs.mkdirSync(codexHome, { recursive: true });
  if (!fs.existsSync(claudeJsonPath)) fs.writeFileSync(claudeJsonPath, "{}\n");
  if (!fs.existsSync(path.join(codexHome, "config.toml"))) {
    fs.writeFileSync(path.join(codexHome, "config.toml"), 'cli_auth_credentials_store = "file"\n');
  }
  const env = {
    ...process.env,
    HOME: home,
    RUNFREE_CLAUDE_JSON: claudeJsonPath,
    RUNFREE_CLAUDE_MCP_CONFIG_HOST_PATH: claudeMcpConfigPath,
    RUNFREE_CODEX_HOME: codexHome,
    RUNFREE_PACKAGE_ROOT: repoRoot,
    RUNFREE_PROJECT_ROOT: projectRoot,
    RUNFREE_STATE_DIR: stateDir,
    RUNFREE_TEST_FAKE_DOCKER: "1",
    XDG_CONFIG_HOME: path.join(home, ".config"),
    XDG_DATA_HOME: path.join(home, ".local/share"),
    XDG_STATE_HOME: path.join(home, ".local/state"),
    // Match the hostHome/.codex fallback explicitly so a host CODEX_HOME
    // can't redirect the codex MCP import to the developer's real config.
    CODEX_HOME: path.join(home, ".codex"),
    ...extraEnv,
  };
  let stderr = "";
  let stdout = "";
  const originalConsoleError = console.error;
  const originalConsoleLog = console.log;
  const originalStdoutWrite = process.stdout.write.bind(process.stdout);
  const originalStderrWrite = process.stderr.write.bind(process.stderr);
  const capture = (append: (text: string) => void) =>
    (chunk: string | Uint8Array, encoding?: BufferEncoding | ((error?: Error | null) => void), callback?: (error?: Error | null) => void): boolean => {
      append(Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk));
      const cb = typeof encoding === "function" ? encoding : callback;
      if (cb) queueMicrotask(() => cb(null));
      return true;
    };
  process.stdout.write = capture((text) => { stdout += text; }) as typeof process.stdout.write;
  process.stderr.write = capture((text) => { stderr += text; }) as typeof process.stderr.write;
  console.log = (...values: unknown[]) => {
    stdout += `${util.format(...values)}\n`;
  };
  console.error = (...values: unknown[]) => {
    stderr += `${util.format(...values)}\n`;
  };
  try {
    let status: number;
    try {
      status = await runAdminAction(createAdminState({
        env,
        packageRoot: repoRoot,
        projectRoot,
        stateDir,
      }), action);
    } catch (error) {
      status = typeof (error as { status?: unknown }).status === "number"
        ? (error as { status: number }).status
        : 1;
      console.error(error instanceof Error ? error.message : String(error));
    }
    flushWarnings();
    return { status, stderr, stdout };
  } finally {
    console.log = originalConsoleLog;
    console.error = originalConsoleError;
    process.stdout.write = originalStdoutWrite as typeof process.stdout.write;
    process.stderr.write = originalStderrWrite as typeof process.stderr.write;
  }
}

// The effective prepare entry point never writes the project policy file: the
// MCP-extended policy lands in the generation projection at `outputPath`.
function effectivePolicyOutputPath(): string {
  return path.join(stateDir, "control", "mcp-network-policy.json");
}

function prepareRuntime(): void {
  const base = JSON.parse(
    fs.readFileSync(path.join(projectRoot, ".runfree/network-policy.json"), "utf8"),
  ) as PolicyJson;
  prepareEffectiveRuntimeIntent({ basePolicy: base, outputPath: effectivePolicyOutputPath() });
}

function readPolicy(): PolicyJson {
  return (JSON.parse(fs.readFileSync(effectivePolicyOutputPath(), "utf8")) as { policy: PolicyJson }).policy;
}

function readTokenConfig(): unknown {
  const filePath = path.join(home, ".config/runfree/projects", projectHash(projectRoot), "tokens.json");
  return JSON.parse(fs.readFileSync(filePath, "utf8")) as unknown;
}

function readClaudeGenerated(): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(claudeMcpConfigPath, "utf8")) as Record<string, unknown>;
}

function readCodexGenerated(): string {
  return fs.readFileSync(path.join(codexHome, "config.toml"), "utf8");
}

function readMcpOAuthPolicy(): unknown {
  return JSON.parse(fs.readFileSync(path.join(stateDir, "oauth-mediation-policy.json"), "utf8")) as unknown;
}

function readMcpOperationPolicy(): {
  servers: Array<{
    id: string;
    defaultToolWriteAction?: string;
    tools?: Record<string, { writeAction: string }>;
  }>;
} {
  return JSON.parse(fs.readFileSync(path.join(stateDir, "mcp-operation-policy.json"), "utf8")) as {
    servers: Array<{
      id: string;
      defaultToolWriteAction?: string;
      tools?: Record<string, { writeAction: string }>;
    }>;
  };
}

beforeEach(() => {
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-admin-mcp-tests-"));
  projectRoot = path.join(tmpBase, "project");
  home = path.join(tmpBase, "home");
  stateDir = path.join(tmpBase, "state");
  claudeJsonPath = path.join(stateDir, "claude.json");
  claudeMcpConfigPath = path.join(stateDir, "mounts", "claude-mcp.json");
  codexHome = path.join(stateDir, "codex");
  fs.mkdirSync(projectRoot, { recursive: true });
  fs.mkdirSync(home, { recursive: true });
  writeFixtureRepo({ hosts: [], tokens: {} });
});

afterEach(() => {
  fs.rmSync(tmpBase, { recursive: true, force: true });
});

describe("admin MCP runtime preparation", () => {
  test("prepare always writes an empty dedicated config and removes stale MCP state", async () => {
    fs.mkdirSync(path.dirname(claudeJsonPath), { recursive: true });
    fs.writeFileSync(claudeJsonPath, `${JSON.stringify({ theme: "dark", mcpServers: { stale: { command: "false" } } }, null, 2)}\n`);

    const result = await runAdmin(() => prepareRuntime());

    expect(result.status, result.stderr).toBe(0);
    expect(readClaudeGenerated()).toEqual({ mcpServers: {} });
    expect(JSON.parse(fs.readFileSync(claudeJsonPath, "utf8"))).toEqual({ theme: "dark" });
  });

  test("blank project Claude MCP config is treated as no servers without a warning", async () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), " \n\t\n");

    const result = await runAdmin(() => prepareRuntime());

    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).not.toContain("skipped project claude config");
    expect(readClaudeGenerated()).toEqual({ mcpServers: {} });
  });

  test("malformed non-empty project Claude MCP config still warns and renders no servers", async () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), "{not-json}\n");

    const result = await runAdmin(() => prepareRuntime());

    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toContain("mcp: skipped project claude config .mcp.json");
    expect(readClaudeGenerated()).toEqual({ mcpServers: {} });
  });

  test("prepare imports user and local public HTTP MCP servers into sanitized agent configs and policy", async () => {
    writeClaudeNative({
      mcpServers: {
        openaiDocs: { type: "http", url: "https://developers.openai.com/mcp" },
      },
      projects: {
        [projectRoot]: {
          mcpServers: {
            sentry: { type: "http", url: "https://mcp.sentry.dev/mcp" },
          },
        },
      },
    });
    writeCodexNative([
      "[mcp_servers.openaiDeveloperDocs]",
      'url = "https://developers.openai.com/mcp"',
      'enabled_tools = ["search", "fetch"]',
      'disabled_tools = ["fetch"]',
      "",
    ].join("\n"));

    const result = await runAdmin(() => prepareRuntime());

    expect(result.status, result.stderr).toBe(0);
    expect(readPolicy().hosts).toEqual(["developers.openai.com", "mcp.sentry.dev"]);
    expect(readPolicy().tokens).toEqual({});
    expect(readClaudeGenerated().mcpServers).toMatchObject({
      openaiDocs: { type: "http", url: "https://developers.openai.com/mcp" },
      sentry: { type: "http", url: "https://mcp.sentry.dev/mcp" },
    });
    const codex = readCodexGenerated();
    expect(codex).toContain("[mcp_servers.openaiDeveloperDocs]");
    expect(codex).toContain('url = "https://developers.openai.com/mcp"');
    expect(codex).toContain('enabled_tools = ["search", "fetch"]');
    expect(codex).toContain('disabled_tools = ["fetch"]');
  });

  test("mcp list --json inventories user local and project MCP sources", async () => {
    writeClaudeNative({
      mcpServers: {
        userDocs: { type: "http", url: "https://user.example.com/mcp" },
      },
      projects: {
        [projectRoot]: {
          mcpServers: {
            localTools: { type: "stdio", command: "npx", args: ["-y", "@example/local"] },
          },
        },
      },
    });
    writeCodexNative([
      "[mcp_servers.codex_docs]",
      'url = "https://codex.example.com/mcp"',
      "",
    ].join("\n"));
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoTools: { type: "http", url: "https://repo.example.com/mcp" },
      },
    }));
    fs.mkdirSync(path.join(projectRoot, ".codex"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".codex/config.toml"), [
      "[mcp_servers.repo_stdio]",
      'command = "npx"',
      'args = ["-y", "@example/repo"]',
      "",
    ].join("\n"));

    const result = await runAdmin(() => mcpListIntent({ json: true }));

    expect(result.status, result.stderr).toBe(0);
    const inventory = JSON.parse(result.stdout) as {
      entries: Array<{
        agent: string;
        decision: { status: string };
        name: string;
        source: string;
      }>;
    };
    expect(inventory.entries).toEqual(expect.arrayContaining([
      expect.objectContaining({ source: "user", agent: "claude", name: "userDocs", decision: expect.objectContaining({ status: "imported" }) }),
      expect.objectContaining({ source: "local", agent: "claude", name: "localTools", decision: expect.objectContaining({ status: "imported" }) }),
      expect.objectContaining({ source: "user", agent: "codex", name: "codex_docs", decision: expect.objectContaining({ status: "imported" }) }),
      expect.objectContaining({ source: "project", agent: "claude", name: "repoTools", decision: expect.objectContaining({ status: "unapproved" }) }),
      expect.objectContaining({ source: "project", agent: "codex", name: "repo_stdio", decision: expect.objectContaining({ status: "unapproved" }) }),
    ]));
  });

  test("mcp list aligns human output without tabs", async () => {
    writeClaudeNative({
      mcpServers: {
        posthog: { type: "http", url: "https://mcp.posthog.com/mcp" },
      },
    });
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        git: { type: "stdio", command: "npx", args: ["-y", "@modelcontextprotocol/server-git"] },
        "sequential-thinking": { type: "stdio", command: "npx", args: ["-y", "@modelcontextprotocol/server-sequential-thinking"] },
      },
    }));

    const result = await runAdmin(() => mcpListIntent({ json: false }));

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).not.toContain("\t");
    expect(result.stdout).toBe([
      "SOURCE   AGENT   SERVER               TRANSPORT  AUTH    STATUS      MCP POLICY  TARGET",
      "user     claude  posthog              http       public  imported    tools=ask   generated",
      "project  claude  git                  stdio      none    unapproved  -           excluded",
      "project  claude  sequential-thinking  stdio      none    unapproved  -           excluded",
      "",
    ].join("\n"));
  });

  test("mcp enable stores project approval outside the project and prepare imports approved public HTTP MCP", async () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoTools: { type: "http", url: "https://repo.example.com/mcp" },
      },
    }));

    const approve = await runAdmin(() => enableProjectNoTty("repoTools"));
    expect(approve.status, approve.stderr).toBe(0);
    expect(approve.stdout).toContain("approved project MCP server: claude repoTools");
    expect(fs.existsSync(path.join(projectRoot, ".runfree/approved-mcp.json"))).toBe(false);

    const prepare = await runAdmin(() => prepareRuntime());

    expect(prepare.status, prepare.stderr).toBe(0);
    expect(readPolicy().hosts).toContain("repo.example.com");
    expect(JSON.stringify(readClaudeGenerated())).toContain("repo.example.com");
  });

  test("mcp rules stores host-owned server and tool rules and prepare merges them into the MCP operation policy", async () => {
    writeClaudeNative({
      mcpServers: {
        posthog: { type: "http", url: "https://mcp.posthog.com/mcp" },
      },
    });

    const serverRule = await runAdmin(() =>
      mcpRulesIntent({ agent: parseMcpAgent("claude"), server: "posthog", source: parseMcpSource("user"), write: "ask" }));
    const toolRule = await runAdmin(() =>
      mcpRulesIntent({ agent: parseMcpAgent("claude"), server: "posthog", source: parseMcpSource("user"), tool: "query", write: "allow" }));
    const prepare = await runAdmin(() => prepareRuntime());

    expect(serverRule.status, serverRule.stderr).toBe(0);
    expect(serverRule.stdout).toContain("MCP tool default: ask");
    expect(toolRule.status, toolRule.stderr).toBe(0);
    expect(toolRule.stdout).toContain("MCP tool rule: query allow");
    expect(fs.existsSync(path.join(projectRoot, ".runfree/mcp-rules.json"))).toBe(false);
    expect(prepare.status, prepare.stderr).toBe(0);
    expect(readMcpOperationPolicy().servers).toEqual([
      expect.objectContaining({
        id: "claude:user:posthog",
        defaultToolWriteAction: "ask",
        tools: { query: { writeAction: "allow" } },
      }),
    ]);
  });

  test("mcp configure requires a TTY and does not write policy in non-interactive use", async () => {
    writeCodexNative([
      "[mcp_servers.posthog]",
      'url = "https://mcp.posthog.com/mcp"',
      "",
    ].join("\n"));
    const before = fs.readFileSync(path.join(projectRoot, ".runfree/network-policy.json"), "utf8");

    const result = await runAdmin(async () => {
      await mcpConfigureIntent({ agents: [parseMcpAgent("codex")], server: "posthog" });
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("runfree mcp configure requires a TTY; for scripts use mcp list, mcp enable, and mcp rules");
    expect(fs.readFileSync(path.join(projectRoot, ".runfree/network-policy.json"), "utf8")).toBe(before);
  });

  test("mcp rules stop applying when a user MCP server name is repointed to another endpoint", async () => {
    writeClaudeNative({
      mcpServers: {
        posthog: { type: "http", url: "https://mcp.posthog.com/mcp" },
      },
    });
    expect((await runAdmin(() =>
      mcpRulesIntent({ agent: parseMcpAgent("claude"), server: "posthog", source: parseMcpSource("user"), tool: "query", write: "allow" }))).status).toBe(0);
    writeClaudeNative({
      mcpServers: {
        posthog: { type: "http", url: "https://changed.posthog.example/mcp" },
      },
    });

    const prepare = await runAdmin(() => prepareRuntime());

    expect(prepare.status, prepare.stderr).toBe(0);
    expect(readMcpOperationPolicy().servers).toEqual([
      expect.objectContaining({
        id: "claude:user:posthog",
        host: "changed.posthog.example",
      }),
    ]);
    expect(JSON.stringify(readMcpOperationPolicy())).not.toContain("query");
  });

  test("mcp list and explain show effective MCP operation policy state", async () => {
    writeClaudeNative({
      mcpServers: {
        posthog: { type: "http", url: "https://mcp.posthog.com/mcp" },
      },
    });
    expect((await runAdmin(() =>
      mcpRulesIntent({ agent: parseMcpAgent("claude"), server: "posthog", source: parseMcpSource("user"), write: "ask" }))).status).toBe(0);

    const list = await runAdmin(() => mcpListIntent({ json: false }));
    const explain = await runAdmin(() => mcpExplainIntent({
      agent: parseMcpAgent("claude"),
      server: "posthog",
      source: parseMcpSource("user"),
      json: false,
    }));

    expect(list.status, list.stderr).toBe(0);
    expect(list.stdout).toContain("MCP POLICY");
    expect(list.stdout).toContain("tools=ask");
    expect(explain.status, explain.stderr).toBe(0);
    expect(explain.stdout).toContain("endpoint: mcp.posthog.com/mcp");
    expect(explain.stdout).toContain("server id: claude:user:posthog");
    expect(explain.stdout).toContain("MCP tool default: ask");
    expect(explain.stdout).toContain("change: runfree mcp rules claude posthog --source user --write ask");
  });

  test("changed project MCP approval is not reused", async () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoTools: { type: "http", url: "https://repo.example.com/mcp" },
      },
    }));
    expect((await runAdmin(() => enableProjectNoTty("repoTools"))).status).toBe(0);
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoTools: { type: "http", url: "https://changed.example.com/mcp" },
      },
    }));

    const prepare = await runAdmin(() => prepareRuntime());

    expect(prepare.status, prepare.stderr).toBe(0);
    expect(prepare.stderr).toContain("mcp: skipped project claude server repoTools reason=approval changed");
    expect(JSON.stringify(readClaudeGenerated())).not.toContain("changed.example.com");
  });

  test("project-controlled MCP approval files are ignored during prepare", async () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoTools: { type: "http", url: "https://repo.example.com/mcp" },
      },
    }));
    expect((await runAdmin(() => enableProjectNoTty("repoTools"))).status).toBe(0);
    const projectStateDir = path.join(projectRoot, ".runfree");
    fs.mkdirSync(projectStateDir, { recursive: true });
    fs.copyFileSync(path.join(stateDir, "approved-mcp.json"), path.join(projectStateDir, "approved-mcp.json"));
    fs.rmSync(path.join(stateDir, "approved-mcp.json"));

    const prepare = await runAdmin(() => prepareRuntime(), {
      RUNFREE_STATE_DIR: projectStateDir,
    });

    expect(prepare.status, prepare.stderr).toBe(0);
    expect(prepare.stderr).toContain("mcp: skipped project claude server repoTools reason=project MCP requires approval");
    expect(JSON.stringify(readClaudeGenerated())).not.toContain("repo.example.com");
  });

  test("project static-header MCP approval requires an explicit host-owned source", async () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoTools: {
          type: "http",
          url: "https://repo.example.com/mcp",
          headers: { Authorization: "Bearer ${REPO_MCP_TOKEN}" },
        },
      },
    }));

    const result = await runAdmin(() => enableProjectNoTty("repoTools"));

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("static project MCP credentials require --from-env, --from-1password, or --from-source");
    // Refused before any write: no approval and no credential source.
    expect(fs.existsSync(path.join(stateDir, "approved-mcp.json"))).toBe(false);
    const tokensFile = path.join(home, ".config/runfree/projects", projectHash(projectRoot), "tokens.json");
    expect(fs.existsSync(tokensFile) ? readTokenConfig() : {}).toEqual({});
  });

  test("project static-header MCP approval binds credential source and prepare omits header from generated config", async () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoTools: {
          type: "http",
          url: "https://repo.example.com/mcp",
          headers: { Authorization: "Bearer ${REPO_MCP_TOKEN}" },
        },
      },
    }));

    const approve = await runAdmin(() => enableProjectNoTty("repoTools", { kind: "env", env: "REPO_MCP_TOKEN" }), {
      REPO_MCP_TOKEN: "host-secret",
    });
    expect(approve.status, approve.stderr).toBe(0);
    const prepare = await runAdmin(() => prepareRuntime());
    expect(prepare.status, prepare.stderr).toBe(0);
    const policy = readPolicy();
    const tokenName = Object.keys(policy.tokens ?? {}).find((name) => name.startsWith("mcp-claude-repotools"));
    expect(tokenName).toBeDefined();
    expect(readTokenConfig()).toMatchObject({
      [tokenName as string]: { source: "env", env: "REPO_MCP_TOKEN" },
    });
    expect(JSON.stringify(readClaudeGenerated())).toContain("repo.example.com");
    expect(JSON.stringify(readClaudeGenerated())).not.toContain("Authorization");
    expect(JSON.stringify(readClaudeGenerated())).not.toContain("REPO_MCP_TOKEN");
  });

  test("project literal static-header MCP approval binds host source without trusting literal", async () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoTools: {
          type: "http",
          url: "https://repo.example.com/mcp",
          headers: { Authorization: "Bearer literal-project-secret" },
        },
      },
    }));

    const approve = await runAdmin(() => enableProjectNoTty("repoTools", { kind: "env", env: "REPO_MCP_TOKEN" }), {
      REPO_MCP_TOKEN: "host-secret",
    });
    expect(approve.status, approve.stderr).toBe(0);
    const prepare = await runAdmin(() => prepareRuntime());
    expect(prepare.status, prepare.stderr).toBe(0);
    expect(JSON.stringify(readPolicy())).not.toContain("literal-project-secret");
    expect(JSON.stringify(readClaudeGenerated())).not.toContain("Authorization");
    expect(JSON.stringify(readClaudeGenerated())).not.toContain("literal-project-secret");
  });

  test("approved project OAuth MCP imports with sanitized OAuth policy", async () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoOauth: {
          type: "http",
          url: "https://repo-oauth.example.com/mcp",
          oauth: {
            authServerMetadataUrl: "https://auth.repo-oauth.example.com/.well-known/oauth-authorization-server",
            client_id: "public-client-id",
            client_secret: "project-secret",
          },
        },
      },
    }));

    const approve = await runAdmin(() => enableProjectNoTty("repoOauth"));
    expect(approve.status, approve.stderr).toBe(0);
    const prepare = await runAdmin(() => prepareRuntime());

    expect(prepare.status, prepare.stderr).toBe(0);
    expect(readPolicy().hosts).toEqual(["auth.repo-oauth.example.com", "repo-oauth.example.com"]);
    const generated = JSON.stringify(readClaudeGenerated());
    expect(generated).toContain("repo-oauth.example.com/mcp");
    expect(generated).toContain("public-client-id");
    expect(generated).not.toContain("project-secret");
    expect(readMcpOAuthPolicy()).toMatchObject({
      providers: {
        "mcp:claude-repooauth": {
          kind: "mcp",
          resourceHost: "repo-oauth.example.com",
          resourcePathPrefix: "/mcp",
          oauth: {
            authServerMetadataUrl: "https://auth.repo-oauth.example.com/.well-known/oauth-authorization-server",
          },
        },
      },
    });
  });

  test("approved project container stdio MCP imports without host execution", async () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoTools: { type: "stdio", command: "npx", args: ["-y", "@example/repo-tools"] },
      },
    }));

    const approve = await runAdmin(() => enableProjectNoTty("repoTools"));
    expect(approve.status, approve.stderr).toBe(0);
    const prepare = await runAdmin(() => prepareRuntime());

    expect(prepare.status, prepare.stderr).toBe(0);
    expect(readPolicy().hosts).toEqual([]);
    expect(readClaudeGenerated().mcpServers).toMatchObject({
      repoTools: {
        type: "stdio",
        command: "npx",
        args: ["-y", "@example/repo-tools"],
      },
    });
  });

  test("project public MCP approval rejects credential source options", async () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoTools: { type: "http", url: "https://repo.example.com/mcp" },
      },
    }));

    const result = await runAdmin(() => enableProjectNoTty("repoTools", { kind: "env", env: "REPO_MCP_TOKEN" }));

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("--from-* is only valid for static-header project MCP servers");
    expect(fs.existsSync(path.join(stateDir, "approved-mcp.json"))).toBe(false);
  });

  test("mcp explain shows project approval decision and descriptor digest", async () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoTools: { type: "http", url: "https://repo.example.com/mcp" },
      },
    }));

    const result = await runAdmin(() => mcpExplainIntent({ agent: parseMcpAgent("claude"), server: "repoTools", source: parseMcpSource("project"), json: false }));

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("source: project");
    expect(result.stdout).toContain("status: unapproved");
    expect(result.stdout).toContain("digest:");
    expect(result.stdout).toContain("enable: runfree mcp enable claude repoTools --source project");
    expect(result.stdout).toContain("repo.example.com");
  });

  test("mcp list and explain show a Codex Desktop built-in as skipped, and no admin action accepts it", async () => {
    writeCodexNative([
      "[mcp_servers.node_repl]",
      'command = "/Applications/Codex.app/Contents/Resources/node_repl"',
      "args = []",
      "",
      "[mcp_servers.node_repl.env]",
      'NODE_REPL_NODE_PATH = "/Applications/Codex.app/Contents/Resources/node"',
      "",
    ].join("\n"));

    const list = await runAdmin(() => mcpListIntent({ json: false }));
    expect(list.status, list.stderr).toBe(0);
    expect(list.stdout).toMatch(/node_repl\s+stdio\s+unknown\s+skipped\s+-\s+excluded/);
    expect(list.stderr).not.toContain("node_repl");

    const explain = await runAdmin(() => mcpExplainIntent({ agent: parseMcpAgent("codex"), server: "node_repl", source: parseMcpSource("user"), json: false }));
    expect(explain.status, explain.stderr).toBe(0);
    expect(explain.stdout).toContain("status: skipped");
    expect(explain.stdout).toContain("reason: Codex Desktop built-in; not used in Runfree");

    const rules = await runAdmin(() => mcpRulesIntent({ agent: parseMcpAgent("codex"), server: "node_repl", source: parseMcpSource("user"), write: "allow" }));
    expect(rules.status).toBe(1);
    expect(rules.stderr).toContain("cannot set MCP rules for codex node_repl: Codex Desktop built-in; not used in Runfree");
    expect(fs.existsSync(path.join(stateDir, "mcp-rules.json"))).toBe(false);
  });

  test("mcp revoke removes project approval", async () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoTools: { type: "http", url: "https://repo.example.com/mcp" },
      },
    }));
    expect((await runAdmin(() => enableProjectNoTty("repoTools"))).status).toBe(0);
    const revoke = await runAdmin(() => { mcpRevokeIntent({ agent: parseMcpAgent("claude"), server: "repoTools" }); });
    expect(revoke.status, revoke.stderr).toBe(0);
    expect(revoke.stdout).toContain("revoked project MCP server: claude repoTools");

    const prepare = await runAdmin(() => prepareRuntime());

    expect(prepare.status, prepare.stderr).toBe(0);
    expect(JSON.stringify(readClaudeGenerated())).not.toContain("repo.example.com");
  });

  test("mcp revoke removes stale approval after project entry is deleted", async () => {
    const mcpPath = path.join(projectRoot, ".mcp.json");
    fs.writeFileSync(mcpPath, JSON.stringify({
      mcpServers: {
        repoTools: { type: "http", url: "https://repo.example.com/mcp" },
      },
    }));
    expect((await runAdmin(() => enableProjectNoTty("repoTools"))).status).toBe(0);
    fs.rmSync(mcpPath);

    const revoke = await runAdmin(() => { mcpRevokeIntent({ agent: parseMcpAgent("claude"), server: "repoTools" }); });

    expect(revoke.status, revoke.stderr).toBe(0);
    expect(revoke.stdout).toContain("revoked project MCP server: claude repoTools");
  });

  test("project MCP conflicts with user server name and cannot be approved", async () => {
    writeClaudeNative({
      mcpServers: {
        repoTools: { type: "http", url: "https://user.example.com/mcp" },
      },
    });
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoTools: { type: "http", url: "https://repo.example.com/mcp" },
      },
    }));

    const approve = await runAdmin(() => enableProjectNoTty("repoTools"));

    expect(approve.status).toBe(1);
    expect(approve.stderr).toContain("conflicts with an imported user MCP server");
    expect(fs.existsSync(path.join(stateDir, "approved-mcp.json"))).toBe(false);
  });

  test("prepare leaves the callback port to the session for OAuth-capable Claude servers and registers public servers as OAuth resources", async () => {
    writeClaudeNative({
      mcpServers: {
        // Public remote HTTP server that advertises OAuth dynamically at runtime.
        posthog: { type: "http", url: "https://mcp.posthog.example/mcp" },
        // Statically declared OAuth server.
        sentryClaude: {
          type: "http",
          url: "https://mcp.sentry.dev/mcp",
          oauth: { authServerMetadataUrl: "https://sentry.io/.well-known/oauth-authorization-server" },
        },
        // Static-header credentialed server: never runs OAuth.
        staticMcp: {
          type: "http",
          url: "https://static.example/mcp",
          headers: { Authorization: "Bearer ${STATIC_MCP_TOKEN}" },
        },
      },
    });

    const result = await runAdmin(() => prepareRuntime());
    expect(result.status, result.stderr).toBe(0);

    const generated = readClaudeGenerated().mcpServers as Record<string, {
      oauth?: { callbackPort?: number; authServerMetadataUrl?: string };
    }>;

    // No shared callback port: the pinned Claude prefers `oauth.callbackPort`
    // over the session adapter's MCP_OAUTH_CALLBACK_PORT, and each session owns
    // its own forwarded port, so a projected port would route every session's
    // login to one port.
    expect(generated.posthog.oauth?.callbackPort).toBeUndefined();
    expect(generated.sentryClaude.oauth?.callbackPort).toBeUndefined();
    // Declared OAuth metadata is preserved.
    expect(generated.sentryClaude.oauth?.authServerMetadataUrl).toBe("https://sentry.io/.well-known/oauth-authorization-server");
    // Static-header servers never run OAuth: no callback port, no leaked token.
    expect(generated.staticMcp.oauth).toBeUndefined();
    expect(JSON.stringify(generated.staticMcp)).not.toContain("STATIC_MCP_TOKEN");

    // Public and OAuth servers register as OAuth resources so the bridge starts
    // and the proxy mediates tokens; the credentialed static-header server does not.
    const oauthPolicy = readMcpOAuthPolicy() as { providers: Record<string, { kind?: string; resourceHost: string }> };
    const resourceHosts = Object.values(oauthPolicy.providers)
      .filter((provider) => provider.kind === "mcp")
      .map((provider) => provider.resourceHost);
    expect(resourceHosts).toContain("mcp.posthog.example");
    expect(resourceHosts).toContain("mcp.sentry.dev");
    expect(resourceHosts).not.toContain("static.example");

    // No egress is broadened beyond the resource hosts already added by import:
    // a bare public server contributes only its own resource host.
    expect(readPolicy().hosts).toContain("mcp.posthog.example");
  });

  test("prepare imports Codex MCP servers with multiline tool filter TOML", async () => {
    writeCodexNative([
      "[mcp_servers.openaiDeveloperDocs]",
      'url = "https://developers.openai.com/mcp"',
      "enabled_tools = [",
      '  "search",',
      '  "fetch"',
      "]",
      "",
    ].join("\n"));

    const result = await runAdmin(() => prepareRuntime());

    expect(result.status, result.stderr).toBe(0);
    const codex = readCodexGenerated();
    expect(codex).toContain("[mcp_servers.openaiDeveloperDocs]");
    expect(codex).toContain('enabled_tools = ["search", "fetch"]');
  });

  test("prepare skips Codex MCP servers with unsupported tool filter values", async () => {
    writeCodexNative([
      "[mcp_servers.openaiDeveloperDocs]",
      'url = "https://developers.openai.com/mcp"',
      'enabled_tools = ["search", 1]',
      "",
    ].join("\n"));

    const result = await runAdmin(() => prepareRuntime());

    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toContain("mcp: skipped codex server openaiDeveloperDocs reason=unsupported TOML value for enabled_tools");
    const codex = readCodexGenerated();
    expect(codex).not.toContain("[mcp_servers.openaiDeveloperDocs]");
    expect(codex).not.toContain("enabled_tools");
  });

  test("prepare preserves Codex env_http_headers subtables", async () => {
    writeCodexNative([
      "[mcp_servers.github]",
      'url = "https://api.githubcopilot.com/mcp/"',
      'enabled_tools = ["search"]',
      "[mcp_servers.github.env_http_headers]",
      'X-GitHub-Api-Version = "GITHUB_MCP_VERSION"',
      "",
    ].join("\n"));

    const result = await runAdmin(() => prepareRuntime());

    expect(result.status, result.stderr).toBe(0);
    const policy = readPolicy();
    const tokenName = Object.keys(policy.tokens ?? {}).find((name) => name.includes("github"));
    expect(tokenName).toBeDefined();
    expect(policy.tokens?.[tokenName as string].credentials).toEqual([
      {
        host: "api.githubcopilot.com",
        header: "X-GitHub-Api-Version",
        scheme: "raw",
        pathPrefix: "/mcp/",
      },
    ]);
    expect(readTokenConfig()).toMatchObject({
      [tokenName as string]: { source: "env", env: "GITHUB_MCP_VERSION" },
    });
    const codex = readCodexGenerated();
    expect(codex).toContain("[mcp_servers.github]");
    expect(codex).toContain('enabled_tools = ["search"]');
    expect(codex).not.toContain("env_http_headers");
  });

  test("prepare converts env-backed HTTP credentials into proxy credential policy without leaking them to generated config", async () => {
    writeClaudeNative({
      mcpServers: {
        claudeStatic: {
          type: "http",
          url: "https://mcp.example.com/mcp",
          headers: { Authorization: "Bearer ${CLAUDE_MCP_TOKEN}" },
        },
      },
    });
    writeCodexNative([
      "[mcp_servers.github]",
      'url = "https://api.githubcopilot.com/mcp/"',
      'bearer_token_env_var = "GITHUB_MCP_TOKEN"',
      'enabled_tools = ["search"]',
      "",
    ].join("\n"));

    const result = await runAdmin(() => prepareRuntime());

    expect(result.status, result.stderr).toBe(0);
    const policy = readPolicy();
    const codexTokenName = Object.keys(policy.tokens ?? {}).find((name) => name.startsWith("mcp-codex-github"));
    const claudeTokenName = Object.keys(policy.tokens ?? {}).find((name) => name.startsWith("mcp-claude-claudestatic"));
    expect(codexTokenName).toBeTruthy();
    expect(claudeTokenName).toBeTruthy();
    expect(policy.hosts).toEqual(["api.githubcopilot.com", "mcp.example.com"]);
    expect(policy.tokens?.[codexTokenName as string]).toMatchObject({
      credentials: [
        { host: "api.githubcopilot.com", header: "Authorization", scheme: "bearer", pathPrefix: "/mcp/" },
      ],
    });
    expect(policy.tokens?.[claudeTokenName as string]).toMatchObject({
      credentials: [
        { host: "mcp.example.com", header: "Authorization", scheme: "bearer", pathPrefix: "/mcp" },
      ],
    });
    expect(readTokenConfig()).toMatchObject({
      [codexTokenName as string]: { source: "env", env: "GITHUB_MCP_TOKEN" },
      [claudeTokenName as string]: { source: "env", env: "CLAUDE_MCP_TOKEN" },
    });
    expect(JSON.stringify(readClaudeGenerated())).toContain("mcp.example.com");
    expect(JSON.stringify(readClaudeGenerated())).not.toContain("CLAUDE_MCP_TOKEN");
    expect(JSON.stringify(readClaudeGenerated())).not.toContain("Authorization");
    const codex = readCodexGenerated();
    expect(codex).toContain("[mcp_servers.github]");
    expect(codex).toContain('url = "https://api.githubcopilot.com/mcp/"');
    expect(codex).toContain('enabled_tools = ["search"]');
    expect(codex).not.toContain("GITHUB_MCP_TOKEN");
    expect(codex).not.toContain("bearer_token_env_var");
  });

  test("prepare imports only container-compatible local stdio MCP and skips project-scoped entries", async () => {
    writeClaudeNative({
      projects: {
        [projectRoot]: {
          mcpServers: {
            context7: { type: "stdio", command: "npx", args: ["-y", "@upstash/context7-mcp"] },
            envLeak: { type: "stdio", command: "node", env: { API_TOKEN: "literal-secret" } },
            hostPath: { type: "stdio", command: "/Users/me/bin/server" },
          },
        },
      },
    });
    writeCodexNative([
      "[mcp_servers.context7]",
      'command = "npx"',
      'args = ["-y", "@upstash/context7-mcp"]',
      "",
      "[mcp_servers.env_leak]",
      'command = "node"',
      "[mcp_servers.env_leak.env]",
      'API_TOKEN = "literal-secret"',
      "",
    ].join("\n"));
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoTools: { type: "http", url: "https://repo-tools.example.com/mcp" },
      },
    }));
    fs.mkdirSync(path.join(projectRoot, ".codex"), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".codex/config.toml"), [
      "[mcp_servers.repo_tools]",
      'url = "https://repo-tools.example.com/mcp"',
      "",
    ].join("\n"));

    const result = await runAdmin(() => prepareRuntime());

    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toContain("mcp: skipped project claude server repoTools");
    expect(result.stderr).toContain("mcp: skipped project codex server repo_tools");
    expect(result.stderr).toContain("mcp: skipped claude server envLeak");
    expect(result.stderr).toContain("mcp: skipped codex server env_leak");
    expect(result.stderr).toContain("mcp: skipped claude server hostPath");
    expect(JSON.stringify(readClaudeGenerated())).toContain("@upstash/context7-mcp");
    expect(JSON.stringify(readClaudeGenerated())).not.toContain("literal-secret");
    expect(JSON.stringify(readClaudeGenerated())).not.toContain("repo-tools.example.com");
    expect(JSON.stringify(readClaudeGenerated())).not.toContain("/Users/me/bin/server");
    const codex = readCodexGenerated();
    expect(codex).toContain("[mcp_servers.context7]");
    expect(codex).toContain('command = "npx"');
    expect(codex).not.toContain("literal-secret");
    expect(codex).not.toContain("repo-tools.example.com");
  });

  test("prepare rejects literal static HTTP secrets instead of copying them into agent-visible config", async () => {
    writeClaudeNative({
      mcpServers: {
        literal: {
          type: "http",
          url: "https://literal.example.com/mcp",
          headers: { Authorization: "Bearer literal-secret" },
        },
      },
    });
    writeCodexNative([
      "[mcp_servers.literal]",
      'url = "https://literal.example.com/mcp"',
      'http_headers = { "Authorization" = "Bearer literal-secret" }',
      "",
    ].join("\n"));

    const result = await runAdmin(() => prepareRuntime());

    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toContain("mcp: skipped claude server literal");
    expect(result.stderr).toContain("mcp: skipped codex server literal");
    expect(JSON.stringify(readPolicy())).not.toContain("literal-secret");
    expect(JSON.stringify(readClaudeGenerated())).not.toContain("literal-secret");
    expect(readCodexGenerated()).not.toContain("literal-secret");
  });

  test("prepare imports OAuth HTTP MCP servers with callback config and proxy mediation policy", async () => {
    writeClaudeNative({
      mcpServers: {
        sentryClaude: {
          type: "http",
          url: "https://mcp.sentry.dev/mcp",
          oauth: { authServerMetadataUrl: "https://sentry.io/.well-known/oauth-authorization-server" },
        },
      },
    });
    writeCodexNative([
      "[mcp_servers.sentry]",
      'url = "https://mcp.sentry.dev/mcp"',
      "oauth = true",
      'oauth_resource = "https://mcp.sentry.dev/mcp"',
      'scopes = ["org:read"]',
      "",
    ].join("\n"));

    const result = await runAdmin(() => prepareRuntime());

    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toContain("mcp: imported user claude server sentryClaude transport=http auth=oauth");
    expect(result.stderr).toContain("mcp: imported user codex server sentry transport=http auth=oauth");
    expect(readPolicy().hosts).toEqual(["mcp.sentry.dev", "sentry.io"]);
    expect(readClaudeGenerated().mcpServers).toMatchObject({
      sentryClaude: {
        type: "http",
        url: "https://mcp.sentry.dev/mcp",
        oauth: { authServerMetadataUrl: "https://sentry.io/.well-known/oauth-authorization-server" },
      },
    });
    const codex = readCodexGenerated();
    expect(codex).not.toContain("mcp_oauth_callback_port");
    expect(codex).not.toContain("mcp_oauth_callback_url");
    expect(codex).toContain("[mcp_servers.sentry]");
    expect(codex).toContain("oauth = true");
    expect(codex).toContain('oauth_resource = "https://mcp.sentry.dev/mcp"');
    expect(codex).toContain('scopes = ["org:read"]');
    expect(readMcpOAuthPolicy()).toMatchObject({
      callback: {
        url: expect.stringMatching(/^http:\/\/localhost:\d+\/callback$/),
      },
      providers: {
        "mcp:claude-sentryclaude": {
          kind: "mcp",
          resourceHost: "mcp.sentry.dev",
          resourcePathPrefix: "/mcp",
          oauth: { authServerMetadataUrl: "https://sentry.io/.well-known/oauth-authorization-server" },
        },
        "mcp:codex-sentry": {
          kind: "mcp",
          resourceHost: "mcp.sentry.dev",
          resourcePathPrefix: "/mcp",
        },
      },
    });
    expect(fs.statSync(path.join(stateDir, "oauth-mediation-policy.json")).mode & 0o777).toBe(0o644);
  });

  test("prepare strips OAuth secrets from generated MCP agent config", async () => {
    writeClaudeNative({
      mcpServers: {
        sentryClaude: {
          type: "http",
          url: "https://mcp.sentry.dev/mcp",
          oauth: {
            authServerMetadataUrl: "https://sentry.io/.well-known/oauth-authorization-server",
            client_id: "public-client-id",
            access_token: "real-access-token",
            refresh_token: "real-refresh-token",
            id_token: "real-id-token",
            client_secret: "real-client-secret",
            registration_access_token: "real-registration-token",
          },
        },
      },
    });

    const result = await runAdmin(() => prepareRuntime());

    expect(result.status, result.stderr).toBe(0);
    const generated = JSON.stringify(readClaudeGenerated());
    expect(generated).toContain("public-client-id");
    expect(generated).toContain("https://sentry.io/.well-known/oauth-authorization-server");
    expect(generated).not.toContain("real-access-token");
    expect(generated).not.toContain("real-refresh-token");
    expect(generated).not.toContain("real-id-token");
    expect(generated).not.toContain("real-client-secret");
    expect(generated).not.toContain("real-registration-token");
    expect(JSON.stringify(readMcpOAuthPolicy())).not.toContain("real-client-secret");
  });
});

// --- runfree mcp enable -------------------------------------------------------

type FakeNetwork = { deps: DiscoveryDeps; calls: string[] };

// Discovery against a fake network: every resolve and request is recorded, so a
// test can prove that no lookup or connection happened.
function fakeDiscovery(routes: Record<string, Record<string, unknown>>): FakeNetwork {
  const calls: string[] = [];
  return {
    calls,
    deps: {
      resolve: async (host) => {
        calls.push(`resolve ${host}`);
        return [{ address: "93.184.216.34", family: 4 }];
      },
      request: async (url) => {
        calls.push(`GET ${url.href}`);
        const route = routes[url.href];
        return route
          ? { kind: "response", status: 200, contentType: "application/json", body: Buffer.from(JSON.stringify(route)) }
          : { kind: "response", status: 404, contentType: "text/plain", body: Buffer.alloc(0) };
      },
    },
  };
}

const NO_NETWORK: DiscoveryDeps = {
  resolve: async (host) => {
    throw new Error(`unexpected DNS lookup of ${host}`);
  },
  request: async (url) => {
    throw new Error(`unexpected request to ${url.href}`);
  },
};

function oauthRoutes(resource = "https://repo-oauth.example.com/mcp"): Record<string, Record<string, unknown>> {
  return {
    "https://repo-oauth.example.com/.well-known/oauth-protected-resource/mcp": {
      resource,
      authorization_servers: ["https://auth.oauth-idp.example"],
    },
    "https://auth.oauth-idp.example/.well-known/oauth-authorization-server": {
      issuer: "https://auth.oauth-idp.example",
      authorization_endpoint: "https://auth.oauth-idp.example/authorize",
      token_endpoint: "https://auth.oauth-idp.example/oauth/token",
      registration_endpoint: "https://auth.oauth-idp.example/oauth/register",
    },
  };
}

function writeProjectOauthServer(name = "repoOauth", url = "https://repo-oauth.example.com/mcp"): void {
  const mcpPath = path.join(projectRoot, ".mcp.json");
  const existing = fs.existsSync(mcpPath)
    ? JSON.parse(fs.readFileSync(mcpPath, "utf8")) as { mcpServers: Record<string, unknown> }
    : { mcpServers: {} };
  existing.mcpServers[name] = { type: "http", url };
  fs.writeFileSync(mcpPath, JSON.stringify(existing));
}

function enableInput(overrides: Partial<McpEnableInput> = {}): McpEnableInput {
  return {
    agent: parseMcpAgent("claude"),
    server: "repoOauth",
    tokenSource: { kind: "none" },
    replaceSource: false,
    oauthHosts: [],
    discover: true,
    interactive: true,
    ...overrides,
  };
}

// `runfree mcp enable <agent> <server> --source project --no-discover` without a
// terminal: the command line names every change, so it applies without a
// prompt and makes no network call.
async function enableProjectNoTty(server: string, tokenSource: McpEnableInput["tokenSource"] = { kind: "none" }): Promise<void> {
  await mcpEnableIntent({
    agent: parseMcpAgent("claude"),
    server,
    source: "project",
    tokenSource,
    replaceSource: false,
    oauthHosts: [],
    discover: false,
    interactive: false,
  });
}

function answers(...values: boolean[]): { confirm: (message: string) => Promise<boolean>; asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    confirm: async (message) => {
      asked.push(message);
      const next = values.shift();
      if (next === undefined) throw new Error(`unexpected prompt: ${message}`);
      return next;
    },
  };
}

function enabledFilePath(): string {
  return path.join(stateDir, "mcp-enabled.json");
}

function approvalFilePath(): string {
  return path.join(stateDir, "approved-mcp.json");
}

describe("runfree mcp enable", () => {
  test("one review enables a project OAuth server: approval, discovered hosts, mediated endpoints", async () => {
    writeProjectOauthServer();
    const network = fakeDiscovery(oauthRoutes());
    const prompts = answers(true, true);

    const result = await runAdmin(async () => {
      const outcome = await mcpEnableIntent(enableInput(), { discovery: network.deps, confirm: prompts.confirm });
      expect(outcome).toEqual({
        applied: true,
        login: { agent: "claude", server: "repoOauth", source: "project" },
        loginCommand: "runfree mcp auth claude repoOauth --source project",
      });
    });

    expect(result.status, result.stderr).toBe(0);
    // One consent to contact the untrusted endpoint, then one approval.
    expect(prompts.asked).toEqual(["Contact repo-oauth.example.com to discover OAuth hosts?", "Enable this MCP server?"]);
    expect(result.stdout).toContain("allow host repo-oauth.example.com  [MCP endpoint]");
    expect(result.stdout).toContain("allow host auth.oauth-idp.example  [OAuth, discovered]");
    expect(result.stdout).toContain("limited to GET, HEAD, OPTIONS, and POST on paths starting with /.well-known, /.well-known/oauth-authorization-server, /oauth/register, /oauth/token");
    expect(result.stdout).toContain("browser sign-in at https://auth.oauth-idp.example (opened on this computer; not allowlisted)");
    expect(result.stdout).toContain("approved project MCP server: claude repoOauth");

    const prepare = await runAdmin(() => prepareRuntime());
    expect(prepare.status, prepare.stderr).toBe(0);
    const policy = readPolicy();
    expect(policy.hosts).toEqual(["auth.oauth-idp.example", "repo-oauth.example.com"]);
    expect(policy.requests?.["auth.oauth-idp.example"]).toEqual({
      methods: ["GET", "HEAD", "OPTIONS", "POST"],
      pathPrefixes: ["/.well-known", "/.well-known/oauth-authorization-server", "/oauth/register", "/oauth/token"],
    });
    // The proxy mediates the validated endpoints statically, and a POST to
    // exactly those recorded, mediated endpoints is an OAuth protocol read.
    expect(readMcpOAuthPolicy()).toMatchObject({
      providers: {
        "mcp:claude-repooauth": {
          resourceHost: "repo-oauth.example.com",
          tokenEndpoints: [{ host: "auth.oauth-idp.example", path: "/oauth/token" }],
          registrationEndpoints: [{ host: "auth.oauth-idp.example", path: "/oauth/register" }],
          protocolReadEndpoints: [
            { host: "auth.oauth-idp.example", path: "/oauth/register" },
            { host: "auth.oauth-idp.example", path: "/oauth/token" },
          ],
          stateEpoch: expect.stringMatching(/^[a-f0-9]{32}$/),
        },
      },
    });
  });

  test("revoke publishes a new OAuth state epoch for the server and leaves other servers' epochs", async () => {
    writeProjectOauthServer("serverA", "https://a.example.com/mcp");
    writeClaudeNative({ mcpServers: { linear: { type: "http", url: "https://mcp.linear.example/mcp" } } });
    expect((await runAdmin(() => mcpEnableIntent(enableInput({ server: "serverA", interactive: false, discover: false, oauthHosts: [] }), { discovery: NO_NETWORK }).then(() => {}))).status).toBe(0);
    expect((await runAdmin(() => prepareRuntime())).status).toBe(0);
    type Providers = { providers: Record<string, { stateEpoch?: string }> };
    const before = (readMcpOAuthPolicy() as Providers).providers;
    expect(before["mcp:claude-linear"]?.stateEpoch).toBe(before["mcp:claude-servera"]?.stateEpoch);

    // A user server has no project approval, but revoke still clears its
    // proxy OAuth state.
    const revokeUser = await runAdmin(() => { mcpRevokeIntent({ agent: parseMcpAgent("claude"), server: "linear" }); });
    expect(revokeUser.status, revokeUser.stderr).toBe(0);
    expect(revokeUser.stdout).toContain("proxy OAuth state for claude linear: clear requested");
    expect((await runAdmin(() => prepareRuntime())).status).toBe(0);
    const afterUser = (readMcpOAuthPolicy() as Providers).providers;
    expect(afterUser["mcp:claude-linear"]?.stateEpoch).not.toBe(before["mcp:claude-linear"]?.stateEpoch);
    expect(afterUser["mcp:claude-servera"]?.stateEpoch).toBe(before["mcp:claude-servera"]?.stateEpoch);

    // Revoking the project server and enabling it again starts a new epoch,
    // so the proxy state from before the revoke never applies again.
    expect((await runAdmin(() => { mcpRevokeIntent({ agent: parseMcpAgent("claude"), server: "serverA" }); })).status).toBe(0);
    expect((await runAdmin(() => mcpEnableIntent(enableInput({ server: "serverA", interactive: false, discover: false, oauthHosts: [] }), { discovery: NO_NETWORK }).then(() => {}))).status).toBe(0);
    expect((await runAdmin(() => prepareRuntime())).status).toBe(0);
    const again = (readMcpOAuthPolicy() as Providers).providers;
    expect(again["mcp:claude-servera"]?.stateEpoch).toMatch(/^[a-f0-9]{32}$/);
    expect(again["mcp:claude-servera"]?.stateEpoch).not.toBe(before["mcp:claude-servera"]?.stateEpoch);
  });

  test("an invalid OAuth epoch store fails closed: every MCP server gets a new epoch, with a warning", async () => {
    writeClaudeNative({ mcpServers: { linear: { type: "http", url: "https://mcp.linear.example/mcp" } } });
    expect((await runAdmin(() => prepareRuntime())).status).toBe(0);
    type Providers = { providers: Record<string, { stateEpoch?: string }> };
    const before = (readMcpOAuthPolicy() as Providers).providers["mcp:claude-linear"]?.stateEpoch;
    fs.writeFileSync(path.join(stateDir, "mcp-oauth-epochs.json"), "{ corrupt");
    const prepare = await runAdmin(() => prepareRuntime());
    expect(prepare.status, prepare.stderr).toBe(0);
    expect(prepare.stderr).toContain("every MCP server needs a new OAuth login");
    expect((readMcpOAuthPolicy() as Providers).providers["mcp:claude-linear"]?.stateEpoch).not.toBe(before);
    // Reclaimed: the next preparation is quiet and stable.
    const next = await runAdmin(() => prepareRuntime());
    expect(next.stderr).not.toContain("new OAuth login");
  });

  test("no DNS lookup or request happens for an unknown, unsupported, static, or stdio entry", async () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoStatic: { type: "http", url: "https://static.example.com/mcp", headers: { Authorization: "Bearer ${STATIC_TOKEN}" } },
        repoStdio: { command: "repo-mcp", args: [] },
        repoBad: { type: "http", url: "http://insecure.example.com/mcp" },
      },
    }));

    const unknown = await runAdmin(() => mcpEnableIntent(enableInput({ server: "missing" }), { discovery: NO_NETWORK }).then(() => {}));
    expect(unknown.status).not.toBe(0);
    expect(unknown.stderr).toContain("unknown MCP server: claude missing");

    const bad = await runAdmin(() => mcpEnableIntent(enableInput({ server: "repoBad" }), { discovery: NO_NETWORK }).then(() => {}));
    expect(bad.status).not.toBe(0);
    expect(bad.stderr).toContain("cannot enable MCP server claude repoBad");

    const stdio = await runAdmin(() => mcpEnableIntent(enableInput({ server: "repoStdio" }), { discovery: NO_NETWORK, confirm: answers(true).confirm }).then(() => {}));
    expect(stdio.status, stdio.stderr).toBe(0);

    const staticMissing = await runAdmin(() => mcpEnableIntent(enableInput({ server: "repoStatic" }), { discovery: NO_NETWORK }).then(() => {}));
    expect(staticMissing.status).not.toBe(0);
    expect(staticMissing.stderr).toContain("static project MCP credentials require --from-env");
    expect(fs.existsSync(enabledFilePath())).toBe(false);
  });

  test("a refused loopback MCP entry dies in enable before any approval write or lookup", async () => {
    const refused: Record<string, { config: Record<string, unknown>; reason: string }> = {
      repoLocalhost: {
        config: { type: "http", url: "http://localhost:8089/mcp" },
        reason: "loopback MCP must use 127.0.0.1, not localhost: localhost may resolve to ::1, which the session relay does not bind",
      },
      repoHeaders: {
        config: { type: "http", url: "http://127.0.0.1:8089/mcp", headers: { Authorization: "Bearer ${T}" } },
        reason: "loopback MCP cannot carry credentials or OAuth: its traffic does not pass the proxy",
      },
      repoSse: {
        config: { type: "sse", url: "http://127.0.0.1:8089/mcp" },
        reason: 'loopback MCP supports only Claude type "http", not sse',
      },
      repoReserved: {
        config: { type: "http", url: "http://127.0.0.1:2375/mcp" },
        reason: "loopback MCP port 2375 is reserved: ",
      },
    };
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: Object.fromEntries(Object.entries(refused).map(([name, { config }]) => [name, config])),
    }));
    for (const [server, { reason }] of Object.entries(refused)) {
      const result = await runAdmin(() => mcpEnableIntent(enableInput({ server }), { discovery: NO_NETWORK, confirm: answers().confirm }).then(() => {}));
      expect(result.status, server).not.toBe(0);
      expect(result.stderr, server).toContain(`cannot enable MCP server claude ${server}`);
      expect(result.stderr, server).toContain(reason);
      expect(fs.existsSync(approvalFilePath()), server).toBe(false);
      expect(fs.existsSync(enabledFilePath()), server).toBe(false);
    }
  });

  test("a refused or colliding server name is refused by enable before any write or lookup", async () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        "with.dot": { type: "http", url: "https://dot.example.com/mcp" },
        Foo: { type: "http", url: "https://foo.example.com/mcp" },
        foo: { type: "http", url: "https://foo2.example.com/mcp" },
      },
    }));
    const cases: Array<[string, string]> = [
      ["with.dot", "server name must use only letters, numbers, '-', '_'"],
      ["Foo", "server name collides with MCP server foo"],
    ];
    for (const [server, reason] of cases) {
      const enable = await runAdmin(() => mcpEnableIntent(enableInput({ server }), { discovery: NO_NETWORK }).then(() => {}));
      expect(enable.status, server).not.toBe(0);
      expect(enable.stderr).toContain(`cannot enable MCP server claude ${server}: ${reason}`);
    }
    expect(fs.existsSync(approvalFilePath())).toBe(false);
    expect(fs.existsSync(enabledFilePath())).toBe(false);
  });

  test("declining to contact the endpoint makes no lookup and writes nothing", async () => {
    writeProjectOauthServer();
    const prompts = answers(false);
    const result = await runAdmin(async () => {
      expect(await mcpEnableIntent(enableInput(), { discovery: NO_NETWORK, confirm: prompts.confirm })).toEqual({ applied: false });
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("No hosts contacted and no changes saved.");
    expect(fs.existsSync(approvalFilePath())).toBe(false);
    expect(fs.existsSync(enabledFilePath())).toBe(false);
  });

  test("without a terminal, discovery is refused before any lookup and nothing is written", async () => {
    writeProjectOauthServer();
    const result = await runAdmin(() => mcpEnableIntent(enableInput({ interactive: false }), { discovery: NO_NETWORK }).then(() => {}));
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("mcp enable discovers OAuth hosts only on a terminal");
    expect(result.stderr).toContain("runfree mcp enable claude repoOauth --source project --no-discover --oauth-host <host>");
    expect(fs.existsSync(approvalFilePath())).toBe(false);
    expect(fs.existsSync(enabledFilePath())).toBe(false);
  });

  test("declining the review writes nothing even after discovery", async () => {
    writeProjectOauthServer();
    const network = fakeDiscovery(oauthRoutes());
    const result = await runAdmin(async () => {
      expect(await mcpEnableIntent(enableInput(), { discovery: network.deps, confirm: answers(true, false).confirm })).toEqual({ applied: false });
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("No changes saved.");
    expect(fs.existsSync(approvalFilePath())).toBe(false);
    expect(fs.existsSync(enabledFilePath())).toBe(false);
  });

  test("--no-discover without a terminal applies exactly the named hosts and makes no network call", async () => {
    writeProjectOauthServer();
    const result = await runAdmin(async () => {
      const outcome = await mcpEnableIntent(enableInput({ interactive: false, discover: false, oauthHosts: ["SSO.Example.org", "repo-oauth.example.com"] }), { discovery: NO_NETWORK });
      expect(outcome.applied).toBe(true);
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("allow host sso.example.org  [OAuth, --oauth-host]");
    expect(result.stdout).toContain("note: repo-oauth.example.com is the MCP endpoint host");

    const prepare = await runAdmin(() => prepareRuntime());
    expect(prepare.status, prepare.stderr).toBe(0);
    expect(readPolicy().hosts).toEqual(["repo-oauth.example.com", "sso.example.org"]);
    // A user-named host is allowed as given, like `runfree host add`.
    expect(readPolicy().requests?.["sso.example.org"]).toBeUndefined();
    // No recorded endpoint, so no POST on it is ever an OAuth protocol read.
    const provider = (readMcpOAuthPolicy() as { providers: Record<string, { protocolReadEndpoints?: unknown }> }).providers["mcp:claude-repooauth"];
    expect(provider?.protocolReadEndpoints).toBeUndefined();
  });

  test("invalid --oauth-host values are refused before any write", async () => {
    writeProjectOauthServer();
    for (const bad of ["10.0.0.1", "*.example.com", "https://auth.example.com/", "auth.example.com:444", "1.2.3.0x4", "localhost"]) {
      const result = await runAdmin(() => mcpEnableIntent(enableInput({ discover: false, oauthHosts: [bad] }), { discovery: NO_NETWORK, confirm: answers().confirm }).then(() => {}));
      expect(result.status, bad).not.toBe(0);
      expect(result.stderr).toContain("--oauth-host");
    }
    expect(fs.existsSync(approvalFilePath())).toBe(false);
    expect(fs.existsSync(enabledFilePath())).toBe(false);
  });

  test("an unbound token endpoint in discovery output adds no host and no endpoint", async () => {
    writeProjectOauthServer();
    const routes = oauthRoutes();
    routes["https://auth.oauth-idp.example/.well-known/oauth-authorization-server"] = {
      issuer: "https://auth.oauth-idp.example",
      token_endpoint: "https://tokens.elsewhere.example/token",
    };
    const result = await runAdmin(() => mcpEnableIntent(enableInput(), { discovery: fakeDiscovery(routes).deps, confirm: answers(true, true).confirm }).then(() => {}));
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("not added: token_endpoint https://tokens.elsewhere.example/token");
    expect(fs.existsSync(enabledFilePath())).toBe(false);
    const prepare = await runAdmin(() => prepareRuntime());
    expect(prepare.status, prepare.stderr).toBe(0);
    expect(readPolicy().hosts).toEqual(["repo-oauth.example.com"]);
  });

  test("revoke removes exactly the hosts enable added; desired and shared hosts stay", async () => {
    writeFixtureRepo({ hosts: ["sso.example.org"], tokens: {} });
    writeProjectOauthServer("serverA", "https://a.example.com/mcp");
    writeProjectOauthServer("serverB", "https://b.example.com/mcp");
    for (const server of ["serverA", "serverB"]) {
      const result = await runAdmin(() => mcpEnableIntent(enableInput({
        server,
        interactive: false,
        discover: false,
        oauthHosts: ["shared-idp.example.com", "sso.example.org", `only-${server.toLowerCase()}.example.com`],
      }), { discovery: NO_NETWORK }).then(() => {}));
      expect(result.status, result.stderr).toBe(0);
    }
    expect((await runAdmin(() => prepareRuntime())).status).toBe(0);
    expect(readPolicy().hosts).toEqual([
      "a.example.com", "b.example.com", "only-servera.example.com", "only-serverb.example.com", "shared-idp.example.com", "sso.example.org",
    ]);

    const revoke = await runAdmin(() => { mcpRevokeIntent({ agent: parseMcpAgent("claude"), server: "serverA" }); });
    expect(revoke.status, revoke.stderr).toBe(0);
    expect(revoke.stdout).toContain("OAuth hosts no longer allowed for this server: only-servera.example.com, shared-idp.example.com, sso.example.org");

    expect((await runAdmin(() => prepareRuntime())).status).toBe(0);
    // serverA's endpoint and its only host are gone; the desired-policy host and
    // the host serverB also named stay.
    expect(readPolicy().hosts).toEqual(["b.example.com", "only-serverb.example.com", "shared-idp.example.com", "sso.example.org"]);
  });

  test("a changed project descriptor stops projecting the hosts enable added", async () => {
    writeProjectOauthServer();
    expect((await runAdmin(() => mcpEnableIntent(enableInput({ interactive: false, discover: false, oauthHosts: ["sso.example.org"] }), { discovery: NO_NETWORK }).then(() => {}))).status).toBe(0);
    writeProjectOauthServer("repoOauth", "https://repo-oauth.example.com/mcp/v2");

    const prepare = await runAdmin(() => prepareRuntime());
    expect(prepare.status, prepare.stderr).toBe(0);
    expect(readPolicy().hosts).toEqual([]);
  });

  test("a user server enabled for OAuth hosts stops projecting when it is deleted", async () => {
    writeClaudeNative({ mcpServers: { linear: { type: "http", url: "https://mcp.linear.example/mcp" } } });
    const enable = await runAdmin(() => mcpEnableIntent(enableInput({ server: "linear", interactive: false, discover: false, oauthHosts: ["auth.linear.example"] }), { discovery: NO_NETWORK }).then(() => {}));
    expect(enable.status, enable.stderr).toBe(0);
    expect(enable.stdout).not.toContain("approve project MCP server");
    expect((await runAdmin(() => prepareRuntime())).status).toBe(0);
    expect(readPolicy().hosts).toEqual(["auth.linear.example", "mcp.linear.example"]);

    writeClaudeNative({ mcpServers: {} });
    expect((await runAdmin(() => prepareRuntime())).status).toBe(0);
    expect(readPolicy().hosts).toEqual([]);
  });

  test("an invalid enable record grants nothing, and the next revoke reclaims the file", async () => {
    writeProjectOauthServer();
    expect((await runAdmin(() => mcpEnableIntent(enableInput({ interactive: false, discover: false, oauthHosts: ["sso.example.org"] }), { discovery: NO_NETWORK }).then(() => {}))).status).toBe(0);
    const file = JSON.parse(fs.readFileSync(enabledFilePath(), "utf8")) as { records: Record<string, { oauthHosts: Array<{ host: string }> }> };
    const [identity] = Object.keys(file.records);
    if (!identity) throw new Error("expected a record");
    const record = file.records[identity];
    if (!record) throw new Error("expected a record");
    record.oauthHosts.push({ host: "10.0.0.1" });
    fs.writeFileSync(enabledFilePath(), JSON.stringify(file));

    const prepare = await runAdmin(() => prepareRuntime());
    expect(prepare.status, prepare.stderr).toBe(0);
    expect(prepare.stderr).toContain("mcp: ignored an invalid MCP enable record (claude repoOauth)");
    expect(readPolicy().hosts).toEqual(["repo-oauth.example.com"]);

    const revoke = await runAdmin(() => { mcpRevokeIntent({ agent: parseMcpAgent("claude"), server: "other" }); });
    expect(revoke.status, revoke.stderr).toBe(0);
    expect(revoke.stdout).toContain("dropped 1 invalid MCP enable record(s)");
    expect((JSON.parse(fs.readFileSync(enabledFilePath(), "utf8")) as { records: object }).records).toEqual({});
  });

  test("a malformed enable file grants nothing, and the next enable rewrites it", async () => {
    writeProjectOauthServer();
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(enabledFilePath(), "{not json");
    const prepare = await runAdmin(() => prepareRuntime());
    expect(prepare.status, prepare.stderr).toBe(0);
    expect(prepare.stderr).toContain("mcp: ignored malformed MCP enable file");

    const enable = await runAdmin(() => mcpEnableIntent(enableInput({ interactive: false, discover: false, oauthHosts: ["sso.example.org"] }), { discovery: NO_NETWORK }).then(() => {}));
    expect(enable.status, enable.stderr).toBe(0);
    expect((await runAdmin(() => prepareRuntime())).status).toBe(0);
    expect(readPolicy().hosts).toEqual(["repo-oauth.example.com", "sso.example.org"]);
  });

  test("re-enabling with fewer hosts stops projecting the dropped ones", async () => {
    writeProjectOauthServer();
    expect((await runAdmin(() => mcpEnableIntent(enableInput({ interactive: false, discover: false, oauthHosts: ["a-idp.example.com", "b-idp.example.com"] }), { discovery: NO_NETWORK }).then(() => {}))).status).toBe(0);
    const again = await runAdmin(() => mcpEnableIntent(enableInput({ interactive: false, discover: false, oauthHosts: ["a-idp.example.com"] }), { discovery: NO_NETWORK }).then(() => {}));
    expect(again.status, again.stderr).toBe(0);
    expect(again.stdout).toContain("stop allowing host b-idp.example.com");
    expect((await runAdmin(() => prepareRuntime())).status).toBe(0);
    expect(readPolicy().hosts).toEqual(["a-idp.example.com", "repo-oauth.example.com"]);
  });

  test("mcp explain shows the hosts and endpoints enable recorded", async () => {
    writeProjectOauthServer();
    const network = fakeDiscovery(oauthRoutes());
    expect((await runAdmin(() => mcpEnableIntent(enableInput(), { discovery: network.deps, confirm: answers(true, true).confirm }).then(() => {}))).status).toBe(0);
    const explain = await runAdmin(() => mcpExplainIntent({ agent: parseMcpAgent("claude"), server: "repoOauth", json: false }));
    expect(explain.status, explain.stderr).toBe(0);
    expect(explain.stdout).toContain("OAuth host: auth.oauth-idp.example (discovered; added by mcp enable)");
    expect(explain.stdout).toContain("OAuth token endpoint: https://auth.oauth-idp.example/oauth/token");
  });

  test("an authorization server on the endpoint host adds no host but its endpoints are still mediated", async () => {
    writeProjectOauthServer();
    const network = fakeDiscovery({
      "https://repo-oauth.example.com/.well-known/oauth-protected-resource/mcp": {
        resource: "https://repo-oauth.example.com/mcp",
        authorization_servers: ["https://repo-oauth.example.com"],
      },
      "https://repo-oauth.example.com/.well-known/oauth-authorization-server": {
        issuer: "https://repo-oauth.example.com",
        token_endpoint: "https://repo-oauth.example.com/token",
      },
    });
    const result = await runAdmin(() => mcpEnableIntent(enableInput(), { discovery: network.deps, confirm: answers(true, true).confirm }).then(() => {}));
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("proxy mediates token endpoint https://repo-oauth.example.com/token");
    expect(result.stdout).toContain("OAuth hosts: none");

    expect((await runAdmin(() => prepareRuntime())).status).toBe(0);
    expect(readPolicy().hosts).toEqual(["repo-oauth.example.com"]);
    expect(readPolicy().requests).toBeUndefined();
    expect(readMcpOAuthPolicy()).toMatchObject({
      providers: { "mcp:claude-repooauth": { tokenEndpoints: [{ host: "repo-oauth.example.com", path: "/token" }] } },
    });
  });

  test("the review says when a discovered host is already allowed and keeps its rules", async () => {
    writeFixtureRepo({ hosts: ["auth.oauth-idp.example"], tokens: {} });
    writeProjectOauthServer();
    const result = await runAdmin(() => mcpEnableIntent(enableInput(), { discovery: fakeDiscovery(oauthRoutes()).deps, confirm: answers(true, true).confirm }).then(() => {}));
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("already allowed by the current policy; its existing rules stay");
    expect(result.stdout).not.toContain("limited to GET");
    expect((await runAdmin(() => prepareRuntime())).status).toBe(0);
    expect(readPolicy().requests).toBeUndefined();
  });

  test("a token endpoint two enabled servers share is not mediated statically for either", async () => {
    writeProjectOauthServer("serverA", "https://a.example.com/mcp");
    writeProjectOauthServer("serverB", "https://b.example.com/mcp");
    for (const [server, host] of [["serverA", "a.example.com"], ["serverB", "b.example.com"]] as const) {
      const routes = {
        [`https://${host}/.well-known/oauth-protected-resource/mcp`]: { resource: `https://${host}/mcp`, authorization_servers: ["https://shared-idp.example.com"] },
        "https://shared-idp.example.com/.well-known/oauth-authorization-server": {
          issuer: "https://shared-idp.example.com",
          token_endpoint: "https://shared-idp.example.com/oauth/token",
        },
      };
      const result = await runAdmin(() => mcpEnableIntent(enableInput({ server }), { discovery: fakeDiscovery(routes).deps, confirm: answers(true, true).confirm }).then(() => {}));
      expect(result.status, result.stderr).toBe(0);
    }
    const prepare = await runAdmin(() => prepareRuntime());
    expect(prepare.status, prepare.stderr).toBe(0);
    expect(prepare.stderr).toContain("token endpoint https://shared-idp.example.com/oauth/token is also used by another MCP server");
    const providers = (readMcpOAuthPolicy() as { providers: Record<string, { protocolReadEndpoints?: unknown[]; tokenEndpoints?: unknown[] }> }).providers;
    expect(providers["mcp:claude-servera"]?.tokenEndpoints ?? []).toEqual([]);
    expect(providers["mcp:claude-serverb"]?.tokenEndpoints ?? []).toEqual([]);
    // A shared endpoint is never an OAuth protocol read for either server.
    expect(providers["mcp:claude-servera"]?.protocolReadEndpoints).toBeUndefined();
    expect(providers["mcp:claude-serverb"]?.protocolReadEndpoints).toBeUndefined();
    // The path stays reachable for the login, as with `host add`.
    expect(readPolicy().requests?.["shared-idp.example.com"]?.pathPrefixes).toContain("/oauth/token");
  });

  test("printable escapes control, C1, and bidi characters from MCP config and metadata", () => {
    expect(printable("repo\u001b[2Jname‮\u0085")).toBe("repo\\u{1b}[2Jname\\u{202e}\\u{85}");
    expect(printable("plain-name_1")).toBe("plain-name_1");
  });
});

// L3-L6, S7, T4: the admin surfaces for an `http-loopback` MCP server.
const ASTRO_URL = "http://127.0.0.1:8089/mcp";
const ASTRO_HOST_SERVICES: HostServicesJson = { astro: { target: "host-loopback", port: 8089 } };
const NODE_LISTENER: HostPortOwner = {
  kind: "listener",
  command: "node",
  pid: 42,
  count: 1,
  commands: ["node"],
  listeners: [{ command: "node", pid: 42, addresses: ["127.0.0.1:8089"] }],
};
const L6_LINE = "tool calls to this server do not pass the proxy; write approval and runfree mcp rules do not apply";
const HOSTED_REACH = "  reach=host-service astro:8089";
const LISTENER_LINE = "      tools run in a host process (node, pid 42), outside the sandbox";
const UNKNOWN_OWNER_LINE = "      tools run in a host process (owner unknown), outside the sandbox";
const CONTAINER_LOCAL_REACH = "  reach=container-local 127.0.0.1:8089: works only if a process in the session listens there; to reach the host: runfree host-service add astro --port 8089";

type OwnerProbe = { deps: McpLoopbackDeps; probed: number[] };

function loopbackDeps(hostServices: HostServicesJson, owner: HostPortOwner = NODE_LISTENER): OwnerProbe {
  const probed: number[] = [];
  return {
    probed,
    deps: {
      hostServices: () => hostServices,
      owner: (port) => {
        probed.push(port);
        return owner;
      },
    },
  };
}

function writeProjectLoopbackServer(name = "astro", url = ASTRO_URL): void {
  fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({ mcpServers: { [name]: { type: "http", url } } }));
}

function rulesFilePath(): string {
  return path.join(stateDir, "mcp-rules.json");
}

async function withTty<T>(action: () => Promise<T>): Promise<T> {
  const stdinTty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
  const stdoutTty = Object.getOwnPropertyDescriptor(process.stdout, "isTTY");
  Object.defineProperty(process.stdin, "isTTY", { value: true, configurable: true });
  Object.defineProperty(process.stdout, "isTTY", { value: true, configurable: true });
  try {
    return await action();
  } finally {
    if (stdinTty) Object.defineProperty(process.stdin, "isTTY", stdinTty);
    else delete (process.stdin as { isTTY?: boolean }).isTTY;
    if (stdoutTty) Object.defineProperty(process.stdout, "isTTY", stdoutTty);
    else delete (process.stdout as { isTTY?: boolean }).isTTY;
  }
}

describe("loopback MCP admin surfaces", () => {
  afterEach(() => {
    clack.select = undefined;
    clack.confirm = undefined;
  });

  test("T4: enable of a loopback entry makes no network call, asks only for the approval, and offers no login", async () => {
    writeProjectLoopbackServer();
    const prompts = answers(true);
    const probe = loopbackDeps(ASTRO_HOST_SERVICES);

    const result = await runAdmin(async () => {
      const outcome = await mcpEnableIntent(enableInput({ server: "astro", interactive: true, discover: true }), {
        discovery: NO_NETWORK,
        confirm: prompts.confirm,
        loopback: probe.deps,
      });
      expect(outcome).toEqual({ applied: true });
    });

    expect(result.status, result.stderr).toBe(0);
    expect(prompts.asked).toEqual(["Enable this MCP server?"]);
    expect(result.stdout).toContain("Enable MCP server: claude astro (project, http-loopback/none)");
    expect(result.stdout).toContain(`  endpoint: ${ASTRO_URL} (loopback)\n`);
    expect(result.stdout).toContain(`${HOSTED_REACH}\n${LISTENER_LINE}\n`);
    expect(result.stdout).toContain(`  ${L6_LINE}\n`);
    expect(result.stdout).not.toContain("allow host 127.0.0.1");
    expect(result.stdout).not.toContain("Discover");
    expect(result.stdout).not.toContain("mcp auth");
    expect(result.stdout).toContain("approved project MCP server: claude astro");
    expect(probe.probed).toEqual([8089]);
    expect(fs.existsSync(approvalFilePath())).toBe(true);
    expect(fs.existsSync(enabledFilePath())).toBe(false);
  });

  test("T4: --oauth-host is refused for a loopback entry before any write", async () => {
    writeProjectLoopbackServer();
    const probe = loopbackDeps(ASTRO_HOST_SERVICES);
    const result = await runAdmin(() => mcpEnableIntent(enableInput({ server: "astro", oauthHosts: ["auth.example.com"] }), {
      discovery: NO_NETWORK,
      confirm: answers().confirm,
      loopback: probe.deps,
    }).then(() => {}));

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("--oauth-host does not apply to loopback MCP servers: their traffic does not pass the proxy");
    expect(probe.probed).toEqual([]);
    expect(fs.existsSync(approvalFilePath())).toBe(false);
    expect(fs.existsSync(enabledFilePath())).toBe(false);
  });

  test("T4: enable without a terminal approves a loopback entry; there is no discovery to refuse", async () => {
    writeProjectLoopbackServer();
    const result = await runAdmin(() => mcpEnableIntent(enableInput({ server: "astro", interactive: false, discover: true }), {
      discovery: NO_NETWORK,
      loopback: loopbackDeps({}).deps,
    }).then(() => {}));

    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).not.toContain("discovers OAuth hosts only on a terminal");
    expect(result.stdout).toContain(`${CONTAINER_LOCAL_REACH}\n`);
    expect(fs.existsSync(approvalFilePath())).toBe(true);
    expect(fs.existsSync(enabledFilePath())).toBe(false);
  });

  test("L5: the review names an unknown owner when the listener check cannot read it", async () => {
    writeProjectLoopbackServer();
    const result = await runAdmin(() => mcpEnableIntent(enableInput({ server: "astro", interactive: false, discover: false }), {
      discovery: NO_NETWORK,
      loopback: loopbackDeps(ASTRO_HOST_SERVICES, { kind: "unavailable", reason: "x" }).deps,
    }).then(() => {}));

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(`${HOSTED_REACH}\n${UNKNOWN_OWNER_LINE}\n`);
  });

  test("L5: a server name taken by a host service on another port suggests mcp-<port>", async () => {
    writeProjectLoopbackServer();
    const result = await runAdmin(() => mcpEnableIntent(enableInput({ server: "astro", interactive: false, discover: false }), {
      discovery: NO_NETWORK,
      loopback: loopbackDeps({ astro: { target: "host-loopback", port: 9000 } }).deps,
    }).then(() => {}));

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("to reach the host: runfree host-service add mcp-8089 --port 8089\n");
  });

  test("S7: configure shows the loopback review before the save prompt and offers no OAuth login", async () => {
    writeProjectLoopbackServer();
    const selects: string[] = [];
    clack.select = async ({ message, options }) => {
      selects.push(message);
      expect(options.map((option) => option.value)).toEqual(["keep", "approve"]);
      return "approve";
    };
    clack.confirm = async ({ message }) => {
      console.log(`<<prompt: ${message}>>`);
      return true;
    };

    const result = await withTty(() => runAdmin(async () => {
      expect(await mcpConfigureIntent({ agents: [parseMcpAgent("claude")], server: "astro" }, { loopback: loopbackDeps(ASTRO_HOST_SERVICES).deps })).toEqual({});
    }));

    expect(result.status, result.stderr).toBe(0);
    // One select: the approval. No tool-call rules choice, no OAuth login choice.
    expect(selects).toHaveLength(1);
    expect(selects[0]).toMatch(/^Project approval for .+ \/ astro$/);
    expect(result.stdout).toContain("loopback server claude/astro has no OAuth login\n");
    const promptAt = result.stdout.indexOf("<<prompt: Save these changes?>>");
    expect(promptAt).toBeGreaterThan(0);
    const reviewAt = result.stdout.indexOf(`${HOSTED_REACH}\n${LISTENER_LINE}\n`);
    expect(reviewAt).toBeGreaterThanOrEqual(0);
    expect(reviewAt).toBeLessThan(promptAt);
    expect(result.stdout.indexOf(L6_LINE)).toBeLessThan(promptAt);
    expect(result.stdout).not.toContain("OAuth login with");
    expect(fs.existsSync(approvalFilePath())).toBe(true);
  });

  test("explain shows the loopback transport, reach, and the L6 line; --json carries loopback.reach", async () => {
    writeClaudeNative({ mcpServers: { astro: { type: "http", url: ASTRO_URL }, devtools: { type: "http", url: "http://127.0.0.1:3000/mcp" } } });
    const probe = loopbackDeps(ASTRO_HOST_SERVICES);

    const hosted = await runAdmin(() => mcpExplainIntent({ agent: "claude", server: "astro", json: false }, { loopback: probe.deps }));
    expect(hosted.status, hosted.stderr).toBe(0);
    expect(hosted.stdout).toContain("transport: http-loopback\n");
    expect(hosted.stdout).toContain(`endpoint: ${ASTRO_URL} (loopback)\n`);
    expect(hosted.stdout).toContain("reach: host-service astro:8089\n");
    expect(hosted.stdout).toContain(`${L6_LINE}\n`);

    const local = await runAdmin(() => mcpExplainIntent({ agent: "claude", server: "devtools", json: false }, { loopback: probe.deps }));
    expect(local.status, local.stderr).toBe(0);
    expect(local.stdout).toContain("reach: container-local");
    expect(local.stdout).toContain("runfree host-service add devtools --port 3000");

    const json = await runAdmin(() => mcpExplainIntent({ agent: "claude", server: "astro", json: true }, { loopback: probe.deps }));
    expect(json.status, json.stderr).toBe(0);
    expect(json.stdout).toContain('"transport": "http-loopback"');
    const parsed = JSON.parse(json.stdout) as { loopback?: { reach?: unknown } };
    expect(parsed.loopback?.reach).toEqual({ kind: "host-service", name: "astro", port: 8089 });
    // Explain never runs the host listener check.
    expect(probe.probed).toEqual([]);
  });

  test("list shows http-loopback in TRANSPORT and the reach in --json", async () => {
    writeClaudeNative({ mcpServers: { astro: { type: "http", url: ASTRO_URL } } });
    const probe = loopbackDeps(ASTRO_HOST_SERVICES);

    const table = await runAdmin(() => mcpListIntent({ json: false }, { loopback: probe.deps }));
    expect(table.status, table.stderr).toBe(0);
    const row = table.stdout.split("\n").find((line) => line.includes("astro"));
    expect(row).toMatch(/\bhttp-loopback\b/);

    const json = await runAdmin(() => mcpListIntent({ json: true }, { loopback: probe.deps }));
    const entry = (JSON.parse(json.stdout) as { entries: Array<{ name: string; loopback?: { reach?: unknown } }> }).entries.find((candidate) => candidate.name === "astro");
    expect(entry?.loopback?.reach).toEqual({ kind: "host-service", name: "astro", port: 8089 });
    expect(probe.probed).toEqual([]);
  });

  test("F1: list, explain, and configure read no host services when no entry is loopback", async () => {
    writeClaudeNative({ mcpServers: { remote: { type: "http", url: "https://mcp.example.com/mcp" }, tool: { command: "node", args: ["server.js"] } } });
    let reads = 0;
    const deps: McpLoopbackDeps = {
      hostServices: () => {
        reads += 1;
        throw new Error("active control selection is malformed");
      },
      owner: () => {
        throw new Error("the owner check must not run");
      },
    };

    for (const json of [false, true]) {
      const listed = await runAdmin(() => mcpListIntent({ json }, { loopback: deps }));
      expect(listed.status, listed.stderr).toBe(0);
    }
    const explained = await runAdmin(() => mcpExplainIntent({ agent: "claude", server: "remote", json: false }, { loopback: deps }));
    expect(explained.status, explained.stderr).toBe(0);
    clack.confirm = async () => false;
    const configured = await withTty(() => runAdmin(async () => {
      expect(await mcpConfigureIntent({ agents: [parseMcpAgent("claude")], server: "tool" }, { loopback: deps })).toEqual({});
    }));
    expect(configured.status, configured.stderr).toBe(0);
    expect(reads).toBe(0);
  });

  test("F1: an unreadable effective policy shows reach unknown with the error, never container-local", async () => {
    writeClaudeNative({ mcpServers: { astro: { type: "http", url: ASTRO_URL } } });
    const probe = loopbackDeps({});
    const deps: McpLoopbackDeps = {
      ...probe.deps,
      hostServices: () => {
        throw new Error("active control selection is malformed\u001b[2J");
      },
    };
    const reason = "cannot read the selected effective policy generation: active control selection is malformed\\u{1b}[2J";

    const json = await runAdmin(() => mcpListIntent({ json: true }, { loopback: deps }));
    expect(json.status, json.stderr).toBe(0);
    const entry = (JSON.parse(json.stdout) as { entries: Array<{ name: string; loopback?: { reach?: unknown } }> }).entries.find((candidate) => candidate.name === "astro");
    expect(entry?.loopback?.reach).toEqual({ kind: "unknown", port: 8089, reason });

    const explained = await runAdmin(() => mcpExplainIntent({ agent: "claude", server: "astro", json: false }, { loopback: deps }));
    expect(explained.status, explained.stderr).toBe(0);
    expect(explained.stdout).toContain(`reach: unknown (${reason})\n`);
    expect(explained.stdout).not.toContain("container-local");

    const enabled = await runAdmin(() => mcpEnableIntent(enableInput({ server: "astro", source: "user", interactive: false, discover: false }), {
      discovery: NO_NETWORK,
      loopback: deps,
    }).then(() => {}));
    expect(enabled.status, enabled.stderr).toBe(0);
    expect(enabled.stdout).toContain(`  reach=unknown (${reason})\n  ${L6_LINE}\n`);
    expect(enabled.stdout).not.toContain("container-local");
    expect(probe.probed).toEqual([]);
  });

  test("F1: with no selected effective policy generation, reach is unknown", async () => {
    writeClaudeNative({ mcpServers: { astro: { type: "http", url: ASTRO_URL } } });
    const deps: McpLoopbackDeps = { ...loopbackDeps({}).deps, hostServices: () => undefined };
    const explained = await runAdmin(() => mcpExplainIntent({ agent: "claude", server: "astro", json: false }, { loopback: deps }));
    expect(explained.status, explained.stderr).toBe(0);
    expect(explained.stdout).toContain("reach: unknown (no effective policy generation is selected)\n");
    expect(explained.stdout).not.toContain("container-local");
  });

  test("F4: the review names the listener the gateway reaches, not the first one", async () => {
    writeProjectLoopbackServer();
    const owner: HostPortOwner = {
      kind: "listener",
      command: "v6only",
      pid: 7,
      count: 2,
      commands: ["v6only", "node"],
      listeners: [
        { command: "v6only", pid: 7, addresses: ["[::1]:8089"] },
        { command: "node", pid: 42, addresses: ["127.0.0.1:8089"] },
      ],
    };
    const reached = await runAdmin(() => mcpEnableIntent(enableInput({ server: "astro", interactive: false, discover: false }), {
      discovery: NO_NETWORK,
      loopback: loopbackDeps(ASTRO_HOST_SERVICES, owner).deps,
    }).then(() => {}));
    expect(reached.status, reached.stderr).toBe(0);
    expect(reached.stdout).toContain(`${HOSTED_REACH}\n${LISTENER_LINE}\n`);
    expect(reached.stdout).not.toContain("v6only");
  });

  test("F4: a listener only on [::1] is not named as the owner", async () => {
    writeProjectLoopbackServer();
    const owner: HostPortOwner = {
      kind: "listener",
      command: "v6only",
      pid: 7,
      count: 1,
      commands: ["v6only"],
      listeners: [{ command: "v6only", pid: 7, addresses: ["[::1]:8089"] }],
    };
    const result = await runAdmin(() => mcpEnableIntent(enableInput({ server: "astro", interactive: false, discover: false }), {
      discovery: NO_NETWORK,
      loopback: loopbackDeps(ASTRO_HOST_SERVICES, owner).deps,
    }).then(() => {}));
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(`${HOSTED_REACH}\n${UNKNOWN_OWNER_LINE}\n`);
  });

  test("F2: configure refuses when .mcp.json changes during the review and writes no approval", async () => {
    writeProjectLoopbackServer();
    clack.select = async () => "approve";
    clack.confirm = async () => {
      // The agent rewrites the project config while the person reads the review.
      writeProjectLoopbackServer("astro", "http://127.0.0.1:9999/mcp");
      return true;
    };

    const result = await withTty(() => runAdmin(async () => {
      await mcpConfigureIntent({ agents: [parseMcpAgent("claude")], server: "astro" }, { loopback: loopbackDeps(ASTRO_HOST_SERVICES).deps });
    }));

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("project MCP server claude astro changed after the review; nothing was approved; review it again with: runfree mcp configure");
    expect(result.stdout).not.toContain("approved project MCP server");
    expect(fs.existsSync(approvalFilePath())).toBe(false);
  });

  test("L6: mcp rules refuses a loopback server and writes no rules file", async () => {
    writeClaudeNative({ mcpServers: { astro: { type: "http", url: ASTRO_URL } } });
    const result = await runAdmin(() => mcpRulesIntent({ agent: "claude", server: "astro", write: "allow" }));
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("MCP rules apply only to HTTP MCP servers imported through the proxy");
    expect(fs.existsSync(rulesFilePath())).toBe(false);
  });
});
