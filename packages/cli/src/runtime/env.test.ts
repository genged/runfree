import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { defaultConfig, projectControlPaths, type ProjectInfo } from "../config.ts";
import { approveNetworkCandidate, approveRuntimeIsolationControl } from "../control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../control/candidates.ts";
import { publishEffectivePolicyGeneration } from "../control/effective.ts";
import { projectHash } from "../project-identity.ts";
import { runtimeInputBuildEnvironment } from "../runtime-inputs.ts";
import { composeRuntimeEnvironment } from "./env.ts";

let tmp: string;

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-runtime-env-tests-")));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function projectInfo(projectRoot: string): ProjectInfo {
  const runfreeDir = path.join(projectRoot, ".runfree");
  const stateDir = path.join(path.dirname(projectRoot), "state");
  return {
    config: defaultConfig(),
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
      mcpOperationPolicyPath: path.join(stateDir, "mcp-operation-policy.json"),
      mcpOAuthPolicyPath: path.join(stateDir, "oauth-mediation-policy.json"),
      proxyCaCertDir: path.join(stateDir, "proxy-ca", "public"),
      proxyCaKeyDir: path.join(stateDir, "proxy-ca", "private"),
      policyPath: path.join(runfreeDir, "network-policy.json"),
      sessionsDir: path.join(stateDir, "sessions"),
      stateDir,
      tokenConfigPath: path.join(path.dirname(projectRoot), "config", "runfree", "projects", projectHash(projectRoot), "tokens.json"),
    },
  };
}

function prepareSelectedControls(projectRoot: string, project: ProjectInfo) {
  fs.mkdirSync(project.paths.runfreeDir, { recursive: true });
  fs.writeFileSync(project.paths.policyPath, '{"version":2,"hosts":[]}\n');
  const candidate = captureDesiredPolicyCandidate(projectRoot, project.paths.controlCandidatesDir);
  approveNetworkCandidate(projectRoot, project, candidate, "network-project", "interactive");
  approveNetworkCandidate(projectRoot, project, candidate, "network-local", "interactive");
  approveRuntimeIsolationControl(projectRoot, project, "interactive");
  return publishEffectivePolicyGeneration(projectRoot, project);
}

describe("runtime environment", () => {
  test("includes descriptor-derived agent state paths", () => {
    const projectRoot = path.join(tmp, "project");
    const project = projectInfo(projectRoot);
    const effective = prepareSelectedControls(projectRoot, project);

    const env = composeRuntimeEnvironment(projectRoot, project, path.join("/tmp", "runtime"), {});

    expect(env).toMatchObject({
      RUNFREE_PROJECT_NAME: "project",
      RUNFREE_PROJECT_CONTAINER_ROOT: "/workspaces/project",
      RUNFREE_PROJECT_COMPAT_ROOT: "/workspace",
      RUNFREE_PROJECT_PHYSICAL_ROOT: "/workspace",
      RUNFREE_AGENT_ENV_FILE: effective.agentEnvPath,
      RUNFREE_EFFECTIVE_PROXY_DIR: path.join(tmp, "state", "control", "effective", "proxy"),
      RUNFREE_GIT_LAYOUT_KIND: "workspace",
      RUNFREE_INBOX_DIR: path.join(tmp, "state", "inbox"),
      RUNFREE_INBOX_CONTAINER_DIR: "/runfree/inbox",
      RUNFREE_AGENT_STATE_CLAUDE_CONFIG_DIR: path.join(tmp, "state", "claude"),
      RUNFREE_AGENT_STATE_CLAUDE_CONFIG_JSON: path.join(tmp, "state", "claude.json"),
      RUNFREE_AGENT_STATE_CODEX_HOME: path.join(tmp, "state", "codex"),
      RUNFREE_AGENT_STATE_PI_AGENT_DIR: path.join(tmp, "state", "pi"),
      RUNFREE_MCP_OPERATION_POLICY_HOST_PATH: path.join(tmp, "state", "mcp-operation-policy.json"),
    });
    expect(env.RUNFREE_HOST_PROJECT_ROOT).toBeUndefined();
    expect(env.RUNFREE_PROJECT_RUNFREE_DIR).toBeUndefined();
    expect(env.RUNFREE_OAUTH_POLICY_HOST_PATH).toBeUndefined();
    expect(env.RUNFREE_POLICY_DIR).toBeUndefined();
    expect(env.RUNFREE_MCP_OAUTH_CALLBACK_URL).toMatch(/^http:\/\/localhost:\d+\/callback$/);
  });

  test("includes relative linked worktree layout paths when resolved for the runtime", () => {
    const projectRoot = path.join(tmp, "project");
    const project = projectInfo(projectRoot);
    prepareSelectedControls(projectRoot, project);

    const env = composeRuntimeEnvironment(projectRoot, project, path.join("/tmp", "runtime"), {}, undefined, {
      gitLayout: {
        version: 1,
        kind: "relative-linked",
        hostProjectRoot: projectRoot,
        hostGitDir: path.join(tmp, "main", ".git", "worktrees", "project"),
        hostGitCommonDir: path.join(tmp, "main", ".git"),
        hostBase: tmp,
        projectRel: "project",
        commonRel: "main/.git",
        relativeGitDir: "worktrees/project",
        containerBase: "/runfree/git-layout/abc123abc123",
        containerProjectRoot: "/runfree/git-layout/abc123abc123/project",
        containerCompatRoot: "/runfree/git-layout/abc123abc123/project",
        containerGitCommonDir: "/runfree/git-layout/abc123abc123/main/.git",
        containerGitDir: "/runfree/git-layout/abc123abc123/main/.git/worktrees/project",
      },
    });

    expect(env).toMatchObject({
      RUNFREE_GIT_COMMON_DIR: path.join(tmp, "main", ".git"),
      RUNFREE_GIT_LAYOUT_KIND: "relative-linked",
      RUNFREE_PROJECT_COMPAT_ROOT: "/runfree/git-layout/abc123abc123/project",
      RUNFREE_PROJECT_PHYSICAL_ROOT: "/runfree/git-layout/abc123abc123/project",
      RUNFREE_INBOX_CONTAINER_DIR: "/runfree/inbox",
    });
  });

  test("loads lock-derived build args from the materialized runtime root", () => {
    const runtimeRoot = path.join(tmp, "runtime");
    fs.mkdirSync(path.join(runtimeRoot, "agent", "agent-tools"), { recursive: true });
    fs.mkdirSync(path.join(runtimeRoot, "proxy"), { recursive: true });
    fs.copyFileSync("packages/agent-runtime/runtime-inputs.lock.json", path.join(runtimeRoot, "runtime-inputs.lock.json"));
    fs.copyFileSync(
      "packages/agent-runtime/agent/agent-tools/package-lock.json",
      path.join(runtimeRoot, "agent", "agent-tools", "package-lock.json"),
    );
    fs.copyFileSync("packages/proxy/package-lock.json", path.join(runtimeRoot, "proxy", "package-lock.json"));

    expect(runtimeInputBuildEnvironment(runtimeRoot)).toMatchObject({
      RUNFREE_AGENT_BASE_IMAGE: expect.stringMatching(/^.+@sha256:[a-f0-9]{64}$/),
      RUNFREE_UV_IMAGE: expect.stringMatching(/^.+@sha256:[a-f0-9]{64}$/),
      RUNFREE_PROXY_BASE_IMAGE: expect.stringMatching(/^.+@sha256:[a-f0-9]{64}$/),
      RUNFREE_APT_SOURCE_UBUNTU_URL: "http://archive.ubuntu.com/ubuntu",
      RUNFREE_APT_SOURCE_UBUNTU_SUITES: "resolute resolute-updates",
      RUNFREE_APT_SOURCE_UBUNTU_SECURITY_URL: "http://security.ubuntu.com/ubuntu",
      RUNFREE_APT_SOURCE_UBUNTU_SECURITY_SUITES: "resolute-security",
      RUNFREE_APT_SIGNED_BY: "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
      RUNFREE_GH_VERSION: expect.stringMatching(/^\d+\.\d+\.\d+$/),
    });
  });
});
