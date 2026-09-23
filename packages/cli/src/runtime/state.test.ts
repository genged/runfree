import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { defaultConfig, projectControlPaths, type ProjectInfo } from "../config.ts";
import { projectHash } from "./env.ts";
import { BASE_AGENT_ENVIRONMENT } from "./agent-env.ts";
import { mcpOAuthCallbackPort } from "./mcp.ts";
import { ensureSandboxGitConfig, ensureAgentState, runtimeValidationMarkerStatus } from "./state.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";
import { flushWarnings } from "../warnings.ts";
import { createRuntimeComponentState, sha256Digest } from "./component-state.ts";
import {
  createControlPlaneGenerationV2,
  createRuntimeTopologyGenerationV2,
  createSessionAgentGenerationInputsV2,
} from "./component-state-v2.ts";

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-runtime-state-"));
});

afterEach(() => {
  flushWarnings();
  vi.restoreAllMocks();
  fs.rmSync(tmp, { recursive: true, force: true });
});

function projectInfo(projectRoot: string): ProjectInfo {
  const runfreeDir = path.join(projectRoot, ".runfree");
  const stateDir = path.join(tmp, "state");
  return {
    config: { ...defaultConfig(), version: 3 },
    paths: {
      runfreeDir,
      agentEnvPath: path.join(runfreeDir, "config", "agent.env"),
      claudeConfigPath: path.join(stateDir, "claude.json"),
      claudeMcpConfigPath: path.join(stateDir, "mounts", "claude-mcp.json"),
      claudeDir: path.join(stateDir, "claude"),
      codexDir: path.join(stateDir, "codex"),
      configPath: path.join(runfreeDir, "runfree.json"),
      ...projectControlPaths(stateDir),
      gitConfigPath: path.join(stateDir, "gitconfig"),
      inboxDir: path.join(stateDir, "inbox"),
      projectCodexDirMaskPath: path.join(stateDir, "mounts", "project-codex-mask"),
      mcpOAuthPolicyPath: path.join(stateDir, "oauth-mediation-policy.json"),
      proxyCaCertDir: path.join(stateDir, "proxy-ca", "public"),
      proxyCaKeyDir: path.join(stateDir, "proxy-ca", "private"),
      policyPath: path.join(runfreeDir, "network-policy.json"),
      sessionsDir: path.join(stateDir, "sessions"),
      stateDir,
      tokenConfigPath: path.join(stateDir, "tokens.json"),
    },
  };
}

test("ensureAgentState creates agent state directories, an empty Claude MCP config, and the Codex mask", () => {
  const projectRoot = path.join(tmp, "project");
  fs.mkdirSync(projectRoot, { recursive: true });
  const context = { projectRoot, project: projectInfo(projectRoot), runtimeRoot: "/runtime" } as RuntimeContext;
  ensureAgentState(context);
  expect(fs.statSync(context.project.paths.claudeDir).isDirectory()).toBe(true);
  expect(fs.statSync(context.project.paths.codexDir).isDirectory()).toBe(true);
  expect(fs.readFileSync(path.join(context.project.paths.codexDir, "config.toml"), "utf8"))
    .toBe('cli_auth_credentials_store = "file"\n');
  expect(fs.statSync(path.join(context.project.paths.codexDir, "config.toml")).mode & 0o777).toBe(0o600);
  expect(JSON.parse(fs.readFileSync(context.project.paths.claudeMcpConfigPath, "utf8"))).toEqual({ mcpServers: {} });
  expect(fs.statSync(context.project.paths.claudeMcpConfigPath).mode & 0o777).toBe(0o644);
  expect(fs.statSync(context.project.paths.projectCodexDirMaskPath).isDirectory()).toBe(true);
  expect(fs.statSync(context.project.paths.inboxDir).isDirectory()).toBe(true);
});

test("ensureAgentState skips an unsafe Codex config and continues other state setup", () => {
  const projectRoot = path.join(tmp, "project");
  fs.mkdirSync(projectRoot, { recursive: true });
  const context = { projectRoot, project: projectInfo(projectRoot), runtimeRoot: "/runtime" } as RuntimeContext;
  const outside = path.join(tmp, "outside.toml");
  const configPath = path.join(context.project.paths.codexDir, "config.toml");
  fs.mkdirSync(context.project.paths.codexDir, { recursive: true });
  fs.writeFileSync(outside, "outside = true\n");
  fs.symlinkSync(outside, configPath);
  const error = vi.spyOn(console, "error").mockImplementation(() => {});

  ensureAgentState(context);
  flushWarnings();

  expect(fs.readFileSync(outside, "utf8")).toBe("outside = true\n");
  expect(fs.lstatSync(configPath).isSymbolicLink()).toBe(true);
  expect(fs.statSync(context.project.paths.claudeDir).isDirectory()).toBe(true);
  expect(fs.statSync(path.join(context.project.paths.stateDir, "pi")).isDirectory()).toBe(true);
  expect(error).toHaveBeenCalledWith(expect.stringContaining("Codex config update skipped"));
  expect(error).toHaveBeenCalledWith(expect.stringContaining("remove only this config.toml entry"));
});

test("ensureAgentState removes only an empty legacy project inbox mountpoint", () => {
  const projectRoot = path.join(tmp, "project");
  fs.mkdirSync(path.join(projectRoot, ".runfree-images"), { recursive: true });
  const context = { projectRoot, project: projectInfo(projectRoot), runtimeRoot: "/runtime" } as RuntimeContext;

  ensureAgentState(context);

  expect(fs.existsSync(path.join(projectRoot, ".runfree-images"))).toBe(false);
});

test("ensureAgentState keeps unsafe legacy project inbox paths and warns", () => {
  const projectRoot = path.join(tmp, "project");
  const legacyInbox = path.join(projectRoot, ".runfree-images");
  fs.mkdirSync(legacyInbox, { recursive: true });
  fs.writeFileSync(path.join(legacyInbox, "keep"), "data");
  const context = { projectRoot, project: projectInfo(projectRoot), runtimeRoot: "/runtime" } as RuntimeContext;
  const error = vi.spyOn(console, "error").mockImplementation(() => {});

  ensureAgentState(context);
  flushWarnings();

  expect(fs.readFileSync(path.join(legacyInbox, "keep"), "utf8")).toBe("data");
  expect(error).toHaveBeenCalledWith(expect.stringContaining("delete it by hand"));

  fs.rmSync(legacyInbox, { recursive: true });
  const outside = path.join(tmp, "outside");
  fs.mkdirSync(outside);
  fs.symlinkSync(outside, legacyInbox, "dir");
  ensureAgentState(context);
  flushWarnings();
  expect(fs.lstatSync(legacyInbox).isSymbolicLink()).toBe(true);
  expect(fs.existsSync(outside)).toBe(true);
});

test("ensureSandboxGitConfig writes generated identity", () => {
  const projectRoot = path.join(tmp, "project");
  const context = { projectRoot, project: projectInfo(projectRoot), runtimeRoot: "/runtime" } as RuntimeContext;
  const io = {
    run: () => 0,
    capture: (_command: string, args: string[]) => args[0] === "worktree" ? ({ status: 129, stdout: "--relative-paths", stderr: "" }) : ({
      status: 0,
      stdout: args.at(-1) === "user.name" ? "Runfree User\n" : "runfree@example.test\n",
      stderr: "",
    }),
    commandExists: () => true,
    confirm: () => true,
    admin: () => Promise.resolve(0),
  } satisfies RuntimeIO;
  ensureSandboxGitConfig(context, io);
  expect(fs.readFileSync(context.project.paths.gitConfigPath, "utf8")).toContain("Runfree User");
  expect(fs.readFileSync(context.project.paths.gitConfigPath, "utf8")).toContain("runfree@example.test");
});

test("generated Git config declares the sandbox repository roots safe by path", () => {
  // Docker maps a bind-mount root's owner independently of its contents, so the
  // agent's Git refuses `/workspace` with "detected dubious ownership" whenever
  // that mapping does not match the container user. The mapping has changed
  // between Docker Desktop versions, so the config must not encode a uid.
  const projectRoot = path.join(tmp, "project");
  const context = { projectRoot, project: projectInfo(projectRoot), runtimeRoot: "/runtime" } as RuntimeContext;
  const io = {
    run: () => 0,
    // `init` is the relative-worktree support probe; `config --get` failing
    // leaves the identity out, keeping this test to the safe.directory entries.
    capture: (_command: string, args: string[]) => args[0] === "init"
      ? ({ status: 0, stdout: "", stderr: "" })
      : args[0] === "worktree"
        ? ({ status: 129, stdout: "--relative-paths", stderr: "" })
        : ({ status: 1, stdout: "", stderr: "" }),
    commandExists: () => true,
    confirm: () => true,
    admin: () => Promise.resolve(0),
  } satisfies RuntimeIO;
  ensureSandboxGitConfig(context, io);
  const generated = context.project.paths.gitConfigPath;

  // Read the values back through Git itself rather than matching the text, so
  // the assertion is about what Git will honour.
  const configured = childProcess.spawnSync(
    "git",
    ["config", "--file", generated, "--get-all", "safe.directory"],
    { encoding: "utf8" },
  );
  expect(configured.status).toBe(0);
  const declared = configured.stdout.trim().split("\n");

  // Both forms per root: Git matches a bare path exactly, and only a trailing
  // `/*` covers everything below it — including a mount nested inside a mount.
  expect(declared).toEqual([
    "/workspace",
    "/workspace/*",
    "/runfree/git-layout",
    "/runfree/git-layout/*",
  ]);
  // No uid, and not the blanket wildcard.
  expect(declared).not.toContain("*");
});

test.each([true, false])("generated Git config creates portable worktrees, identity present: %s", (hasIdentity) => {
  const projectRoot = path.join(tmp, "project");
  fs.mkdirSync(projectRoot);
  const context = { projectRoot, project: projectInfo(projectRoot), runtimeRoot: "/runtime" } as RuntimeContext;
  const io = {
    run: () => 0,
    capture: (_command, args) => args[0] === "init" ? ({ status: 0, stdout: "", stderr: "" }) : args[0] === "worktree"
      ? ({ status: 129, stdout: "--relative-paths", stderr: "" })
      : ({ status: hasIdentity ? 0 : 1, stdout: hasIdentity ? "Test" : "", stderr: "" }),
    commandExists: () => true,
    confirm: () => true,
    admin: async () => 0,
  } satisfies RuntimeIO;
  ensureSandboxGitConfig(context, io);
  const env = { ...process.env, GIT_CONFIG_GLOBAL: context.project.paths.gitConfigPath, GIT_CONFIG_NOSYSTEM: "1" };
  const git = (cwd: string, args: string[], globalConfig = env.GIT_CONFIG_GLOBAL) => childProcess.spawnSync("git", ["-C", cwd, ...args], {
    encoding: "utf8", env: { ...env, GIT_CONFIG_GLOBAL: globalConfig },
  });
  for (const args of [
    ["init", "-q"],
    ["-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "--allow-empty", "-qm", "initial"],
    ["worktree", "add", "-qb", "feature", ".worktrees/feature"],
  ]) expect(git(projectRoot, args).status).toBe(0);
  const relocated = path.join(tmp, "relocated");
  fs.renameSync(projectRoot, relocated);
  // A second environment has no generated config and a different root path.
  // Both link directions must still resolve; a source-string check misses it.
  expect(git(path.join(relocated, ".worktrees", "feature"), ["status", "--porcelain"], "/dev/null").status).toBe(0);
  const worktrees = git(relocated, ["worktree", "list", "--porcelain"], "/dev/null");
  expect(worktrees.status).toBe(0);
  expect(worktrees.stdout).not.toContain("prunable");
});

test("unsupported host Git refuses the sandbox default before writing config, then recovers after an upgrade", () => {
  const projectRoot = path.join(tmp, "project");
  const context = { projectRoot, project: projectInfo(projectRoot), runtimeRoot: "/runtime" } as RuntimeContext;
  let supportsRelativeLinks = false;
  const io = {
    run: () => 0,
    capture: (_command, args) => args[0] === "init" ? ({ status: 0, stdout: "", stderr: "" }) : ({ status: 129, stdout: supportsRelativeLinks ? "--relative-paths" : "usage: git worktree", stderr: "" }),
    commandExists: () => true,
    confirm: () => true,
    admin: async () => 0,
  } satisfies RuntimeIO;
  expect(() => ensureSandboxGitConfig(context, io)).toThrow("host Git does not support relative worktree links");
  expect(fs.existsSync(context.project.paths.gitConfigPath)).toBe(false);
  supportsRelativeLinks = true;
  ensureSandboxGitConfig(context, io);
  expect(fs.existsSync(context.project.paths.gitConfigPath)).toBe(true);
});

test.each(["include", "worktree", "conditional-include"])("sandbox Git keeps relative links despite a false %s override", (override) => {
  const projectRoot = path.join(tmp, "project");
  fs.mkdirSync(projectRoot);
  const git = (args: string[], sandbox = false) => childProcess.spawnSync("git", ["-C", projectRoot, ...args], {
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_COUNT: sandbox ? BASE_AGENT_ENVIRONMENT.GIT_CONFIG_COUNT : "0",
      GIT_CONFIG_KEY_0: BASE_AGENT_ENVIRONMENT.GIT_CONFIG_KEY_0,
      GIT_CONFIG_VALUE_0: BASE_AGENT_ENVIRONMENT.GIT_CONFIG_VALUE_0,
    },
  });
  expect(git(["init", "-q"]).status).toBe(0);
  expect(git(["-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "--allow-empty", "-qm", "initial"]).status).toBe(0);
  if (override === "worktree") {
    expect(git(["config", "extensions.worktreeConfig", "true"]).status).toBe(0);
    expect(git(["config", "--worktree", "worktree.useRelativePaths", "false"]).status).toBe(0);
  } else {
    fs.writeFileSync(path.join(projectRoot, ".git", "relative-override"), "[worktree]\nuseRelativePaths = false\n");
    const section = override === "include" ? "include" : 'includeIf "gitdir:**/project/.git"';
    fs.appendFileSync(path.join(projectRoot, ".git", "config"), `\n[${section}]\npath = relative-override\n`);
  }
  expect(git(["config", "--get", "worktree.useRelativePaths"]).stdout.trim()).toBe("false");
  expect(git(["worktree", "add", "-qb", "feature", ".worktrees/feature"], true).status).toBe(0);
  expect(fs.readFileSync(path.join(projectRoot, ".worktrees", "feature", ".git"), "utf8"))
    .toBe("gitdir: ../../.git/worktrees/feature\n");
  expect(git(["worktree", "repair"], true).status).toBe(0);
  expect(fs.readFileSync(path.join(projectRoot, ".worktrees", "feature", ".git"), "utf8"))
    .toBe("gitdir: ../../.git/worktrees/feature\n");
});

test("runtime validation marker rejects stale proof version and contract hash", () => {
  const projectRoot = path.join(tmp, "project");
  const runtimeComponents = createRuntimeComponentState({
    embeddedAgentImageInputDigest: sha256Digest("embedded"),
    selectedAgentImageInputDigest: sha256Digest("agent"),
    selectedAgentImageKind: "embedded",
    proxyImageInputDigest: sha256Digest("proxy"),
    topologyDigest: sha256Digest("topology"),
    hostHelperDigest: sha256Digest("helper"),
  });
  const projectId = projectHash(projectRoot);
  const generationV2 = {
    topology: createRuntimeTopologyGenerationV2({
      controlPlaneTopologyDigest: sha256Digest("control-plane-topology"),
      sessionTemplateDigest: sha256Digest("session-template"),
    }),
    controlPlane: createControlPlaneGenerationV2({
      projectId,
      composeProject: `runfree-${projectId}`,
      proxyImageInputDigest: sha256Digest("proxy"),
      controlPlaneTopologyDigest: sha256Digest("control-plane-topology"),
      admissionContractEpoch: 1,
    }),
    sessionAgent: createSessionAgentGenerationInputsV2({
      selectedAgentImageInputDigest: sha256Digest("agent"),
      sessionTemplateDigest: sha256Digest("session-template"),
      admissionContractEpoch: 1,
    }),
  };
  const context = {
    projectRoot,
    project: projectInfo(projectRoot),
    runtimeComponents,
    runtimeGenerationV2: generationV2,
    runtimeRoot: "/runtime",
  } as RuntimeContext;
  const marker = {
    components: { ...generationV2.controlPlane },
    contractHash: "sha256:old",
    mcpOAuthCallbackPort: mcpOAuthCallbackPort(projectRoot),
    mcpOAuthCallbackTopologyVersion: 2,
    projectId: projectHash(projectRoot),
    proofVersion: 4,
    proxyId: "proxy-id",
  };
  const io = {
    run: () => 0,
    capture: (_command: string, args: string[]) => {
      const text = args.join(" ");
      // Per-session runtime: no shared agent container exists.
      if (text.includes("com.docker.compose.service=agent")) return { status: 0, stdout: "", stderr: "" };
      if (text.includes("com.docker.compose.service=proxy")) return { status: 0, stdout: "proxy-id\n", stderr: "" };
      if (text.includes("com.docker.compose.service=mcp_callback")) return { status: 0, stdout: "", stderr: "" };
      if (text.includes("cat /run/runfree-runtime-validation.json")) {
        return { status: 0, stdout: JSON.stringify(marker), stderr: "" };
      }
      if (text.includes("findmnt")) return { status: 0, stdout: "", stderr: "" };
      return { status: 0, stdout: "", stderr: "" };
    },
    commandExists: () => true,
    confirm: () => true,
    admin: () => Promise.resolve(0),
  } satisfies RuntimeIO;

  expect(runtimeValidationMarkerStatus(context, io, { contractHash: "sha256:new" }).issue)
    .toBe("runtime validation marker is stale for runtime security contract");

  marker.proofVersion = 2 as never;
  expect(runtimeValidationMarkerStatus(context, io, { contractHash: "sha256:old" }).issue)
    .toBe("runtime validation marker has stale proof version");
});
