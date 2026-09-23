import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import util from "node:util";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import type { PolicyJson } from "@runfree/runtime-contracts/network-policy";
import { createAdminState } from "../packages/cli/src/admin/context.ts";
import {
  mcpApproveIntent,
  mcpConfigureIntent,
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
import { mcpOAuthCallbackPort } from "../packages/cli/src/runtime/mcp.ts";
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

  test("mcp approve stores project approval outside the project and prepare imports approved public HTTP MCP", async () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoTools: { type: "http", url: "https://repo.example.com/mcp" },
      },
    }));

    const approve = await runAdmin(() => mcpApproveIntent({ agent: parseMcpAgent("claude"), server: "repoTools", tokenSource: { kind: "none" }, replaceSource: false }));
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
    expect(result.stderr).toContain("runfree mcp configure requires a TTY; use runfree mcp list/approve/rules for scripts");
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
    expect((await runAdmin(() => mcpApproveIntent({ agent: parseMcpAgent("claude"), server: "repoTools", tokenSource: { kind: "none" }, replaceSource: false }))).status).toBe(0);
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
    expect((await runAdmin(() => mcpApproveIntent({ agent: parseMcpAgent("claude"), server: "repoTools", tokenSource: { kind: "none" }, replaceSource: false }))).status).toBe(0);
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

    const result = await runAdmin(() => mcpApproveIntent({ agent: parseMcpAgent("claude"), server: "repoTools", tokenSource: { kind: "none" }, replaceSource: false }));

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("static project MCP credentials require --from-env, --from-1password, or --from-source");
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

    const approve = await runAdmin(() => mcpApproveIntent({ agent: parseMcpAgent("claude"), server: "repoTools", tokenSource: { kind: "env", env: "REPO_MCP_TOKEN" }, replaceSource: false }), {
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

    const approve = await runAdmin(() => mcpApproveIntent({ agent: parseMcpAgent("claude"), server: "repoTools", tokenSource: { kind: "env", env: "REPO_MCP_TOKEN" }, replaceSource: false }), {
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

    const approve = await runAdmin(() => mcpApproveIntent({ agent: parseMcpAgent("claude"), server: "repoOauth", tokenSource: { kind: "none" }, replaceSource: false }));
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

    const approve = await runAdmin(() => mcpApproveIntent({ agent: parseMcpAgent("claude"), server: "repoTools", tokenSource: { kind: "none" }, replaceSource: false }));
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

    const result = await runAdmin(() => mcpApproveIntent({ agent: parseMcpAgent("claude"), server: "repoTools", tokenSource: { kind: "env", env: "REPO_MCP_TOKEN" }, replaceSource: false }));

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("--from-* is only valid for static-header project MCP servers");
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
    expect(result.stdout).toContain("approve: runfree mcp approve claude repoTools");
    expect(result.stdout).toContain("repo.example.com");
  });

  test("mcp revoke removes project approval", async () => {
    fs.writeFileSync(path.join(projectRoot, ".mcp.json"), JSON.stringify({
      mcpServers: {
        repoTools: { type: "http", url: "https://repo.example.com/mcp" },
      },
    }));
    expect((await runAdmin(() => mcpApproveIntent({ agent: parseMcpAgent("claude"), server: "repoTools", tokenSource: { kind: "none" }, replaceSource: false }))).status).toBe(0);
    const revoke = await runAdmin(() => mcpRevokeIntent({ agent: parseMcpAgent("claude"), server: "repoTools" }));
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
    expect((await runAdmin(() => mcpApproveIntent({ agent: parseMcpAgent("claude"), server: "repoTools", tokenSource: { kind: "none" }, replaceSource: false }))).status).toBe(0);
    fs.rmSync(mcpPath);

    const revoke = await runAdmin(() => mcpRevokeIntent({ agent: parseMcpAgent("claude"), server: "repoTools" }));

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

    const approve = await runAdmin(() => mcpApproveIntent({ agent: parseMcpAgent("claude"), server: "repoTools", tokenSource: { kind: "none" }, replaceSource: false }));

    expect(approve.status).toBe(1);
    expect(approve.stderr).toContain("conflicts with an imported user MCP server");
  });

  test("prepare pins the deterministic callback port for OAuth-capable Claude servers and registers public servers as OAuth resources", async () => {
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

    const port = mcpOAuthCallbackPort(projectRoot);
    const generated = readClaudeGenerated().mcpServers as Record<string, {
      oauth?: { callbackPort?: number; authServerMetadataUrl?: string };
    }>;

    // Public + declared-OAuth servers pin the Runfree-computed callback port so
    // Claude does not fall back to a random loopback port the bridge can't reach.
    expect(generated.posthog.oauth?.callbackPort).toBe(port);
    expect(generated.sentryClaude.oauth?.callbackPort).toBe(port);
    // Declared OAuth metadata is preserved alongside the pinned port.
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
    expect(codex).toContain("mcp_oauth_callback_port = ");
    expect(codex).toContain('mcp_oauth_callback_url = "http://localhost:');
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
