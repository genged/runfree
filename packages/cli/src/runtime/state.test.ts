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
import { flushWarnings, pendingWarningsForTest } from "../warnings.ts";
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

const GITHUB_SSH_PREFIXES = ["git@github.com:", "ssh://git@github.com/", "ssh://git@github.com:22/", "ssh://git@ssh.github.com:443/"];
const GITLAB_SSH_PREFIXES = ["git@gitlab.com:", "ssh://git@gitlab.com/", "ssh://git@gitlab.com:22/"];

// Generates the sandbox gitconfig with no host identity (every `config --get`
// fails), so only the static sections are rendered.
function generatedSandboxGitConfig(): string {
  const projectRoot = path.join(tmp, "project");
  const context = { projectRoot, project: projectInfo(projectRoot), runtimeRoot: "/runtime" } as RuntimeContext;
  const io = {
    run: () => 0,
    capture: () => ({ status: 1, stdout: "", stderr: "" }),
    commandExists: () => true,
    confirm: () => true,
    admin: async () => 0,
  } satisfies RuntimeIO;
  ensureSandboxGitConfig(context, io, { supported: true, version: "2.53.0", found: true });
  return context.project.paths.gitConfigPath;
}

// Real host Git reading the generated file as its only global config: no
// system config, no proxy variables, no prompts, and SSH that cannot run, so
// nothing here can reach the network or block.
function sandboxGit(globalConfig: string) {
  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!/^(?:https?|all|no)_proxy$|^GIT_|^NODE_USE_ENV_PROXY$/i.test(key)) env[key] = value;
  }
  Object.assign(env, {
    GIT_CONFIG_GLOBAL: globalConfig,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
    GIT_SSH_COMMAND: "false",
  });
  return (cwd: string, args: string[]) => childProcess.spawnSync("git", ["-C", cwd, ...args], { encoding: "utf8", env });
}

test("generated Git config rewrites the GitHub and GitLab SSH remote forms to HTTPS", () => {
  const generated = generatedSandboxGitConfig();
  const values = (key: string) => {
    const result = childProcess.spawnSync("git", ["config", "--file", generated, "--get-all", key], { encoding: "utf8" });
    expect(result.status).toBe(0);
    return result.stdout.trim().split("\n");
  };
  expect(values("url.https://github.com/.insteadof")).toEqual(GITHUB_SSH_PREFIXES);
  expect(values("url.https://gitlab.com/.insteadof")).toEqual(GITLAB_SSH_PREFIXES);
  // The existing sections are unchanged by the rewrite blocks.
  expect(values("worktree.userelativepaths")).toEqual(["true"]);
  expect(values("safe.directory")).toEqual(["/workspace", "/workspace/*", "/runfree/git-layout", "/runfree/git-layout/*"]);
});

test("real Git resolves every supported SSH remote form to HTTPS through the generated config", () => {
  const git = sandboxGit(generatedSandboxGitConfig());
  const repo = path.join(tmp, "repo");
  fs.mkdirSync(repo);
  expect(git(repo, ["init", "-q"]).status).toBe(0);
  const getUrl = (url: string) => {
    const result = git(repo, ["ls-remote", "--get-url", url]);
    expect(result.status).toBe(0);
    return result.stdout.trim();
  };

  for (const prefix of GITHUB_SSH_PREFIXES) expect(getUrl(`${prefix}o/r.git`)).toBe("https://github.com/o/r.git");
  for (const prefix of GITLAB_SSH_PREFIXES) expect(getUrl(`${prefix}g/r.git`)).toBe("https://gitlab.com/g/r.git");
  // SSH host aliases are not supported forms and stay as written.
  expect(getUrl("git@github.com-work:o/r.git")).toBe("git@github.com-work:o/r.git");

  // Push resolves through the same rewrite, with and without an explicit pushurl.
  expect(git(repo, ["remote", "add", "origin", "git@github.com:o/r.git"]).status).toBe(0);
  const pushUrl = () => {
    const result = git(repo, ["remote", "get-url", "--push", "origin"]);
    expect(result.status).toBe(0);
    return result.stdout.trim();
  };
  expect(pushUrl()).toBe("https://github.com/o/r.git");
  expect(git(repo, ["config", "remote.origin.pushurl", "ssh://git@gitlab.com:22/g/p.git"]).status).toBe(0);
  expect(pushUrl()).toBe("https://gitlab.com/g/p.git");
  // Repository config keeps the SSH URL; only resolution is rewritten.
  expect(git(repo, ["config", "remote.origin.url"]).stdout.trim()).toBe("git@github.com:o/r.git");
});

test("repository-level insteadOf can override the generated rewrite (recorded Git 2.53.0 behavior)", () => {
  // Recorded behavior, not a requirement: the rewrite is routing, and the agent
  // may override it freely because SSH egress is blocked either way. Git picks
  // the longest matching insteadOf prefix across all config levels; on an
  // equal-length tie the first one read wins, and global is read before the
  // repository. So a longer repository prefix wins, and an identical one loses.
  const git = sandboxGit(generatedSandboxGitConfig());
  const repo = path.join(tmp, "repo");
  fs.mkdirSync(repo);
  expect(git(repo, ["init", "-q"]).status).toBe(0);
  const getUrl = () => git(repo, ["ls-remote", "--get-url", "git@github.com:o/r.git"]).stdout.trim();

  expect(git(repo, ["config", "url.https://tie.test/.insteadOf", "git@github.com:"]).status).toBe(0);
  expect(getUrl()).toBe("https://github.com/o/r.git");
  expect(git(repo, ["config", "url.https://longer.test/.insteadOf", "git@github.com:o/"]).status).toBe(0);
  expect(getUrl()).toBe("https://longer.test/r.git");
});

test("a submodule declared with an SSH URL is fetched over HTTPS through the generated config", () => {
  const git = sandboxGit(generatedSandboxGitConfig());
  const repo = path.join(tmp, "repo");
  fs.mkdirSync(repo);
  expect(git(repo, ["init", "-q"]).status).toBe(0);
  // The clone goes to a proxy port that refuses at once, so the attempt fails
  // offline and fast, and its error names the URL Git actually tried.
  const added = git(repo, ["-c", "http.proxy=http://127.0.0.1:1", "submodule", "add", "git@github.com:o/sub.git", "sub"]);
  expect(added.status).not.toBe(0);
  expect(added.stderr).toContain("'https://github.com/o/sub.git/'");
  // `GIT_SSH_COMMAND=false` would have produced this had SSH been attempted.
  expect(added.stderr).not.toContain("Could not read from remote repository");
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

test.each(["normal repository", "non-Git project"])("old host Git writes the same sandbox config with one versioned warning for a %s, and drops it after an upgrade", (kind) => {
  const projectRoot = path.join(tmp, "project");
  fs.mkdirSync(projectRoot);
  if (kind === "normal repository") {
    expect(childProcess.spawnSync("git", ["init", "-q", projectRoot], { env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" } }).status).toBe(0);
  }
  const context = { projectRoot, project: projectInfo(projectRoot), runtimeRoot: "/runtime" } as RuntimeContext;
  let supportsRelativeLinks = false;
  const io = {
    run: () => 0,
    capture: (_command, args) => args[0] === "--version"
      ? ({ status: 0, stdout: "git version 2.43.0\n", stderr: "" })
      : args[0] === "init"
        ? ({ status: 0, stdout: "", stderr: "" })
        : args[0] === "worktree"
          ? ({ status: 129, stdout: supportsRelativeLinks ? "--relative-paths" : "usage: git worktree", stderr: "" })
          : ({ status: 1, stdout: "", stderr: "" }),
    commandExists: () => true,
    confirm: () => true,
    admin: async () => 0,
  } satisfies RuntimeIO;
  flushWarnings();

  ensureSandboxGitConfig(context, io);
  const degraded = fs.readFileSync(context.project.paths.gitConfigPath, "utf8");
  expect(degraded).toContain("useRelativePaths = true");
  expect(pendingWarningsForTest().map((event) => event.message)).toEqual([
    "host Git 2.43.0 is older than 2.48: Git worktrees created inside the sandbox will make this repository unreadable to host Git; upgrade host Git (Ubuntu: sudo add-apt-repository ppa:git-core/ppa && sudo apt install git)",
  ]);
  flushWarnings();

  supportsRelativeLinks = true;
  fs.rmSync(context.project.paths.gitConfigPath);
  ensureSandboxGitConfig(context, io);
  expect(pendingWarningsForTest()).toEqual([]);
  expect(fs.readFileSync(context.project.paths.gitConfigPath, "utf8")).toBe(degraded);
});

test("a launch-supplied capability result is used without probing again", () => {
  const projectRoot = path.join(tmp, "project");
  const context = { projectRoot, project: projectInfo(projectRoot), runtimeRoot: "/runtime" } as RuntimeContext;
  const captured: string[][] = [];
  const io = {
    run: () => 0,
    capture: (_command, args) => {
      captured.push(args);
      return { status: 1, stdout: "", stderr: "" };
    },
    commandExists: () => true,
    confirm: () => true,
    admin: async () => 0,
  } satisfies RuntimeIO;
  flushWarnings();
  ensureSandboxGitConfig(context, io, { supported: false, version: "2.39.5", found: true });
  expect(captured.map((args) => args.slice(2, 4))).toEqual([["config", "--get"], ["config", "--get"]]);
  expect(pendingWarningsForTest().map((event) => event.message)).toEqual([
    expect.stringContaining("host Git 2.39.5 is older than 2.48"),
  ]);
  expect(fs.existsSync(context.project.paths.gitConfigPath)).toBe(true);
});

test("missing host Git on a non-Git project probes a genuinely failing git spawn and gets exactly the not-found warning", () => {
  const projectRoot = path.join(tmp, "project");
  fs.mkdirSync(projectRoot);
  // A real spawn with an empty PATH: `git` cannot be found, as on a host
  // without Git. No capability is supplied, so the real probe runs.
  const context = { projectRoot, project: projectInfo(projectRoot), runtimeRoot: "/runtime", env: { PATH: "" } } as RuntimeContext;
  const io = {
    run: () => 0,
    capture: (command, args, options) => {
      const result = childProcess.spawnSync(command, args, { ...options, encoding: "utf8" });
      return { status: result.error ? 127 : result.status ?? 1, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
    },
    commandExists: () => true,
    confirm: () => true,
    admin: async () => 0,
  } satisfies RuntimeIO;
  flushWarnings();
  ensureSandboxGitConfig(context, io);
  expect(pendingWarningsForTest().map((event) => event.message)).toEqual([
    "host Git not found: Git worktrees created inside the sandbox will make this repository unreadable to host Git older than 2.48; install Git 2.48 or newer",
  ]);
  expect(fs.readFileSync(context.project.paths.gitConfigPath, "utf8")).toContain("useRelativePaths = true");
});

test("old host Git on a repository that already uses relative worktree links gets exactly the already-unreadable warning", () => {
  const projectRoot = path.join(tmp, "project");
  fs.mkdirSync(projectRoot);
  const gitEnv = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
  expect(childProcess.spawnSync("git", ["init", "-q", projectRoot], { env: gitEnv }).status).toBe(0);
  expect(childProcess.spawnSync("git", ["-C", projectRoot, "config", "extensions.relativeWorktrees", "true"], { env: gitEnv }).status).toBe(0);
  const context = { projectRoot, project: projectInfo(projectRoot), runtimeRoot: "/runtime" } as RuntimeContext;
  const io = {
    run: () => 0,
    capture: () => ({ status: 1, stdout: "", stderr: "" }),
    commandExists: () => true,
    confirm: () => true,
    admin: async () => 0,
  } satisfies RuntimeIO;
  flushWarnings();
  ensureSandboxGitConfig(context, io, { supported: false, version: "2.43.0", found: true });
  expect(pendingWarningsForTest().map((event) => event.message)).toEqual([
    "host Git 2.43.0 is older than 2.48 and cannot read this repository, which uses relative worktree links; upgrade host Git (Ubuntu: sudo add-apt-repository ppa:git-core/ppa && sudo apt install git)",
  ]);
  expect(fs.readFileSync(context.project.paths.gitConfigPath, "utf8")).toContain("useRelativePaths = true");
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
