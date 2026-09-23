import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";

import { afterEach, expect, test, vi } from "vitest";

import { defaultConfig, projectControlPaths, type ProjectInfo } from "../config.ts";
import { approveNetworkCandidate, approveRuntimeIsolationControl } from "../control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../control/candidates.ts";
import { publishEffectivePolicyGeneration } from "../control/effective.ts";
import { activeRuntimePlanFromContext } from "../runtime/plan.ts";
import { createRuntimeSecurityContract } from "../runtime/security-contract.ts";
import { createAdminState } from "./context.ts";
import { domainList, reloadProxy, runAdminAction, takeLastTokenSyncReceipts, credentialSyncIntent } from "./options.ts";
import { ensureClaudeMcpConfigFile, mcpOAuthCallbackPort } from "../runtime/mcp.ts";
import { projectHash } from "../project-identity.ts";

let consoleLogSpy: ReturnType<typeof vi.spyOn> | undefined;
let consoleErrorSpy: ReturnType<typeof vi.spyOn> | undefined;

afterEach(() => {
  consoleLogSpy?.mockRestore();
  consoleLogSpy = undefined;
  consoleErrorSpy?.mockRestore();
  consoleErrorSpy = undefined;
});

function writeExecutable(filePath: string, source: string): void {
  fs.writeFileSync(filePath, source, { mode: 0o755 });
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((entry) => stableJson(entry)).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([left], [right]) => left.localeCompare(right));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${stableJson(entry)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256Json(value: unknown): string {
  return crypto.createHash("sha256").update(stableJson(value)).digest("hex");
}

function adminTestProjectInfo(options: {
  mcpOperationPolicyPath?: string;
  mcpOAuthPolicyPath?: string;
  policyPath: string;
  projectRoot: string;
  stateDir: string;
  tokenConfigPath: string;
}): ProjectInfo {
  const runfreeDir = path.join(options.projectRoot, ".runfree");
  const mountsDir = path.join(options.stateDir, "mounts");
  return {
    config: defaultConfig(),
    paths: {
      runfreeDir,
      agentEnvPath: path.join(runfreeDir, "config", "agent.env"),
      claudeConfigPath: path.join(options.stateDir, "claude.json"),
      claudeMcpConfigPath: path.join(mountsDir, "claude-mcp.json"),
      claudeDir: path.join(options.stateDir, "claude"),
      codexDir: path.join(options.stateDir, "codex"),
      configPath: path.join(runfreeDir, "runfree.json"),
      ...projectControlPaths(options.stateDir),
      gitConfigPath: path.join(options.stateDir, "gitconfig"),
      inboxDir: path.join(options.stateDir, "inbox"),
      projectCodexDirMaskPath: path.join(mountsDir, "project-codex-mask"),
      mcpOperationPolicyPath: options.mcpOperationPolicyPath ?? path.join(options.stateDir, "mcp-operation-policy.json"),
      mcpOAuthPolicyPath: options.mcpOAuthPolicyPath ?? path.join(options.stateDir, "oauth-mediation-policy.json"),
      proxyCaCertDir: path.join(options.stateDir, "proxy-ca", "public"),
      proxyCaKeyDir: path.join(options.stateDir, "proxy-ca", "private"),
      policyPath: options.policyPath,
      sessionsDir: path.join(options.stateDir, "sessions"),
      stateDir: options.stateDir,
      tokenConfigPath: options.tokenConfigPath,
    },
  };
}

function prepareSelectedAdminControls(
  projectRoot: string,
  project: ProjectInfo,
  policyPath: string,
): void {
  const legacyPolicy = fs.readFileSync(policyPath, "utf8");
  const desiredPolicy = {
    ...(JSON.parse(legacyPolicy) as Record<string, unknown>),
    version: 2,
  };
  fs.writeFileSync(policyPath, `${JSON.stringify(desiredPolicy, null, 2)}\n`);
  try {
    const candidate = captureDesiredPolicyCandidate(projectRoot, project.paths.controlCandidatesDir);
    approveNetworkCandidate(projectRoot, project, candidate, "network-project", "interactive");
    approveNetworkCandidate(projectRoot, project, candidate, "network-local", "interactive");
    approveRuntimeIsolationControl(projectRoot, project, "interactive");
  } finally {
    fs.writeFileSync(policyPath, legacyPolicy);
  }
  publishEffectivePolicyGeneration(projectRoot, project);
}

function expectedAdminTarget(options: {
  mcpOAuthPolicyPath?: string;
  policyPath: string;
  projectRoot: string;
  runtimeDigest: string;
  stateDir: string;
  tokenConfigPath: string;
}) {
  fs.mkdirSync(options.projectRoot, { recursive: true });
  const project = adminTestProjectInfo(options);
  fs.mkdirSync(path.dirname(project.paths.claudeMcpConfigPath), { recursive: true });
  if (!fs.existsSync(project.paths.claudeMcpConfigPath)) {
    fs.writeFileSync(project.paths.claudeMcpConfigPath, '{\n  "mcpServers": {}\n}\n');
  }
  prepareSelectedAdminControls(options.projectRoot, project, options.policyPath);
  const plan = activeRuntimePlanFromContext({
    projectRoot: options.projectRoot,
    project,
    runtimeRoot: path.join(process.cwd(), "packages/agent-runtime"),
    env: {
      RUNFREE_RUNTIME_DIGEST: options.runtimeDigest,
    },
  });
  return { contract: createRuntimeSecurityContract(plan), plan };
}

function expectedAdminContract(options: Parameters<typeof expectedAdminTarget>[0]) {
  return expectedAdminTarget(options).contract;
}

function expectedAdminContractHash(options: Parameters<typeof expectedAdminContract>[0]): string {
  return expectedAdminContract(options).contractHash ?? "";
}

function expectedAdminContractComponents(options: Parameters<typeof expectedAdminContract>[0]) {
  return expectedAdminContract(options).components;
}

function dockerComponentEvidenceShell(options: Parameters<typeof expectedAdminTarget>[0]): string {
  const { plan } = expectedAdminTarget(options);
  const agentRow = [
    "agent-id",
    "agent",
    "1",
    plan.components.selectedAgentImageInputDigest,
    "<no value>",
    plan.components.topologyDigest,
    "<no value>",
    plan.activeRuntime.agentImage,
    "true",
    plan.projectId,
    plan.composeProjectName,
  ].join("\\t");
  const proxyRow = [
    "proxy-id",
    "proxy",
    "1",
    "<no value>",
    plan.components.proxyImageInputDigest,
    plan.components.topologyDigest,
    "<no value>",
    plan.activeRuntime.proxyImage,
    "true",
    plan.projectId,
    plan.composeProjectName,
  ].join("\\t");
  const callbackRow = [
    "callback-id",
    "mcp_callback",
    "1",
    "<no value>",
    plan.components.proxyImageInputDigest,
    plan.components.topologyDigest,
    "<no value>",
    plan.activeRuntime.proxyImage,
    "true",
    plan.projectId,
    plan.composeProjectName,
  ].join("\\t");
  return `
if [ "$1" = "inspect" ] && [ "$2" = "--format" ]; then
  case "$3" in
    *"io.runfree.agent-image-input-digest"*)
      shift 3
      for id in "$@"; do
        case "$id" in
          agent-id) printf '%b\\n' ${JSON.stringify(agentRow)} ;;
          proxy-id) printf '%b\\n' ${JSON.stringify(proxyRow)} ;;
          callback-id) printf '%b\\n' ${JSON.stringify(callbackRow)} ;;
        esac
      done
      exit 0
      ;;
  esac
fi
`;
}

function dockerInspectSecurityEvidence(options: {
  mcpOAuthPolicyPath?: string;
  policyPath: string;
  projectRoot: string;
  stateDir: string;
}): string {
  const mountsDir = path.join(options.stateDir, "mounts");
  const proxyCaCertDir = path.join(options.stateDir, "proxy-ca", "public");
  const proxyCaKeyDir = path.join(options.stateDir, "proxy-ca", "private");
  const mcpOperationPolicyPath = path.join(options.stateDir, "mcp-operation-policy.json");
  const bind = (Destination: string, Source: string, mode: "ro" | "rw") => ({
    Destination,
    Mode: mode,
    RW: mode === "rw",
    Source,
    Type: "bind",
  });
  return JSON.stringify([
    {
      Id: "agent-id",
      HostConfig: {},
      Mounts: [
        bind("/runfree/inbox", path.join(options.stateDir, "inbox"), "ro"),
        bind("/runfree/mcp/claude.json", path.join(mountsDir, "claude-mcp.json"), "ro"),
        bind("/workspace/.codex", path.join(mountsDir, "project-codex-mask"), "ro"),
        bind("/etc/proxy-ca", proxyCaCertDir, "ro"),
      ],
    },
    {
      Id: "proxy-id",
      HostConfig: {
        Tmpfs: {
          "/run/runfree-proxy-audit": "",
          "/run/runfree-proxy-audit-spool": "",
          "/run/runfree-proxy-secrets": "",
          "/run/runfree-proxy-status": "",
          "/run/runfree-sessions": "",
          "/run/runfree-approvals/pending": "",
          "/run/runfree-approvals/decisions": "",
        },
      },
      Mounts: [
        bind("/ca/private", proxyCaKeyDir, "rw"),
        bind("/ca/public", proxyCaCertDir, "rw"),
        bind("/app/runfree-effective", projectControlPaths(options.stateDir).controlProxyDir, "ro"),
        bind("/app/proxy/mcp-operation-policy.json", mcpOperationPolicyPath, "ro"),
      ],
    },
  ]);
}

function dockerSecurityContractProbeShell(): string {
  return `
  case "$*" in
    *runfree_security_contract_probe*)
      case "$*" in
        *agent-id*)
          printf '%s\\n' \
            'mount\t/workspace\t0\t/workspace\text4\trw,relatime' \
            'mount\t/runfree/inbox\t0\t/runfree/inbox\text4\tro,relatime' \
            'mount\t/runfree/mcp/claude.json\t0\t/runfree/mcp/claude.json\text4\tro,relatime' \
            'mount\t/workspace/.codex\t0\t/workspace/.codex\text4\tro,relatime' \
            'mount\t/etc/proxy-ca\t0\t/etc/proxy-ca\text4\tro,relatime' \
            'content\t/runfree/mcp/claude.json\t0\td8e397af03b5b032f21d0aa967086f0c78b33c87b76f2e9898ae0a144df7de02' \
            'directory\t/workspace/.codex\t0\t1' \
            'absence\t/ca/private/proxy-ca.key\t0'
          exit 0
          ;;
        *proxy-id*)
          printf '%s\\n' \
            'mount\t/ca/private\t0\t/ca/private\text4\trw,relatime' \
            'mount\t/ca/public\t0\t/ca/public\text4\trw,relatime' \
            'mount\t/app/runfree-effective\t0\t/app/runfree-effective\text4\tro,relatime' \
            'mount\t/app/proxy/mcp-operation-policy.json\t0\t/app/proxy/mcp-operation-policy.json\text4\tro,relatime' \
            'mount\t/run/runfree-proxy-secrets\t0\t/run/runfree-proxy-secrets\ttmpfs\trw,nosuid,nodev,noexec,relatime' \
            'mount\t/run/runfree-proxy-audit\t0\t/run/runfree-proxy-audit\ttmpfs\trw,nosuid,nodev,noexec,relatime' \
            'mount\t/run/runfree-proxy-audit-spool\t0\t/run/runfree-proxy-audit-spool\ttmpfs\trw,nosuid,nodev,noexec,relatime' \
            'mount\t/run/runfree-proxy-status\t0\t/run/runfree-proxy-status\ttmpfs\trw,nosuid,nodev,noexec,relatime' \
            'mount\t/run/runfree-sessions\t0\t/run/runfree-sessions\ttmpfs\trw,nosuid,nodev,noexec,relatime' \
            'mount\t/run/runfree-approvals/pending\t0\t/run/runfree-approvals/pending\ttmpfs\trw,nosuid,nodev,noexec,relatime' \
            'mount\t/run/runfree-approvals/decisions\t0\t/run/runfree-approvals/decisions\ttmpfs\trw,nosuid,nodev,noexec,relatime' \
            'stat\t/run/runfree-proxy-secrets\t0\t1001:1001:700' \
            'stat\t/run/runfree-proxy-audit\t0\t0:0:755' \
            'stat\t/run/runfree-proxy-audit-spool\t0\t1001:1001:755' \
            'stat\t/run/runfree-proxy-status\t0\t0:0:755' \
            'stat\t/run/runfree-proxy-status/request-proxy\t0\t1001:1001:755' \
            'stat\t/run/runfree-sessions\t0\t0:0:755' \
            'stat\t/run/runfree-sessions/sessions\t0\t0:0:755' \
            'stat\t/run/runfree-approvals/pending\t0\t1001:1001:700' \
            'stat\t/run/runfree-approvals/decisions\t0\t0:0:755'
          exit 0
          ;;
      esac
      ;;
  esac
`;
}

test("admin configured runs do not rely on mutable module globals", () => {
  const source = fs.readFileSync(new URL("./options.ts", import.meta.url), "utf8");

  expect(source).not.toMatch(/\blet (REPO_ROOT|PROJECT_ROOT|POLICY_PATH|PROJECT_ID|TOKEN_CONFIG_PATH|SOURCE_CONFIG_PATH|AGENT_ENV_PATH|STATE_DIR|SYNC_STATUS_PATH|COMPOSE_PROJECT_NAME|CONTAINER_LABEL|VALIDATED_RUNTIME|CHILD_ENV|DOCKER_CHILD_ENV|LAST_TOKEN_SYNC_RECEIPTS)\b/);
  expect(source).not.toContain("function configureState(");
  expect(source).not.toContain("function configureContext(");
});

test("runAdminWithState executes against a prebuilt admin state", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-admin-state-"));
  const projectRoot = path.join(root, "project");
  const home = path.join(root, "home");
  const stateDir = path.join(root, "state");
  const policyPath = path.join(projectRoot, ".runfree", "network-policy.json");
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  fs.writeFileSync(policyPath, `${JSON.stringify({ hosts: ["state.example"], tokens: {} }, null, 2)}\n`);

  const state = createAdminState({
    env: {
      HOME: home,
      PATH: process.env.PATH,
      XDG_CONFIG_HOME: path.join(home, ".config"),
      XDG_STATE_HOME: path.join(home, ".local", "state"),
    },
    policyPath,
    projectRoot,
    stateDir,
  });
  const output: string[] = [];
  consoleLogSpy = vi.spyOn(console, "log").mockImplementation((message) => {
    output.push(String(message));
  });

  const status = await runAdminAction(state, () => domainList());

  expect(status).toBe(0);
  expect(output).toContain("state.example");
});

test("token sync times out a stalled 1Password read with a clear failure", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-admin-op-timeout-"));
  const projectRoot = path.join(root, "project");
  const fakeBin = path.join(root, "fake-bin");
  const home = path.join(root, "home");
  const stateDir = path.join(root, "state");
  const policyPath = path.join(projectRoot, ".runfree", "network-policy.json");
  const tokenConfigPath = path.join(root, "config", "tokens.json");
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  fs.mkdirSync(path.dirname(tokenConfigPath), { recursive: true });
  fs.mkdirSync(fakeBin, { recursive: true });
  writeExecutable(path.join(fakeBin, "op"), "#!/bin/sh\n/bin/sleep 1\n");
  fs.writeFileSync(policyPath, `${JSON.stringify({
    hosts: ["api.github.com"],
    tokens: {
      github: {
        description: "GitHub token",
        credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }],
      },
    },
  }, null, 2)}\n`);
  fs.writeFileSync(tokenConfigPath, `${JSON.stringify({
    github: { source: "1password", ref: "op://Private/GitHub/token" },
  }, null, 2)}\n`);

  const state = createAdminState({
    env: {
      HOME: home,
      PATH: fakeBin,
      RUNFREE_TEST_FAKE_DOCKER: "1",
      RUNFREE_TEST_OP_READ_TIMEOUT_MS: "20",
      XDG_CONFIG_HOME: path.join(home, ".config"),
      XDG_STATE_HOME: path.join(home, ".local", "state"),
    },
    policyPath,
    projectRoot,
    stateDir,
    tokenConfigPath,
  });
  const errors: string[] = [];
  consoleErrorSpy = vi.spyOn(console, "error").mockImplementation((message) => {
    errors.push(String(message));
  });

  const startedAt = Date.now();
  const status = await runAdminAction(state, () => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }));

  expect(Date.now() - startedAt).toBeLessThan(900);
  expect(status).toBe(1);
  expect(errors.join("\n")).toContain("resolving 1Password credential source");
  expect(errors.join("\n")).toContain("op read timed out waiting for 1Password");
});

test("token sync can reuse a runtime validation proof from startup", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-admin-prevalidated-"));
  const projectRoot = path.join(root, "project");
  const home = path.join(root, "home");
  const stateDir = path.join(root, "state");
  const policyPath = path.join(projectRoot, ".runfree", "network-policy.json");
  const runtimeDigest = "sha256:prevalidated";
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  fs.writeFileSync(policyPath, `${JSON.stringify({ hosts: ["api.github.com"], tokens: {} }, null, 2)}\n`);
  const contractOptions = {
    policyPath,
    projectRoot,
    runtimeDigest,
    stateDir,
    tokenConfigPath: path.join(root, "config", "tokens.json"),
  };
  const contractHash = expectedAdminContractHash(contractOptions);
  const components = expectedAdminContractComponents(contractOptions);

  // The prevalidated proof skips the full evidence probes, but the live store
  // generation is still read from the container (validation marker +
  // StartedAt): a fabricated generation is exactly what the deterministic
  // store-generation rule forbids.
  const fakeBin = path.join(root, "fake-bin");
  const dockerLogPath = path.join(root, "docker-calls.log");
  const markerPath = path.join(root, "runtime-validation.json");
  fs.mkdirSync(fakeBin, { recursive: true });
  fs.writeFileSync(markerPath, `${JSON.stringify({ marker: "prevalidated" })}\n`);
  writeExecutable(path.join(fakeBin, "docker"), `#!/bin/sh
printf '%s\\n' "$*" >> ${JSON.stringify(dockerLogPath)}
${dockerComponentEvidenceShell(contractOptions)}
if [ "$1" = "exec" ] && [ "$5" = "cat" ]; then
  /bin/cat ${JSON.stringify(markerPath)}
  exit 0
fi
if [ "$1" = "inspect" ] && [ "$2" = "--format" ]; then
  case "$3" in
    *"State.StartedAt"*)
      printf '%s\\n' '2026-06-18T00:00:00.000000000Z'
      exit 0
      ;;
  esac
fi
if [ "$1" = "exec" ]; then
  /bin/cat >/dev/null
  exit 0
fi
exit 0
`);
  const state = createAdminState({
    env: {
      HOME: home,
      PATH: fakeBin,
      RUNFREE_PROJECT_ID: "0123456789ab",
      RUNFREE_RUNTIME_DIGEST: runtimeDigest,
      XDG_CONFIG_HOME: path.join(home, ".config"),
      XDG_STATE_HOME: path.join(home, ".local", "state"),
    },
    policyPath,
    projectRoot,
    stateDir,
    validatedRuntime: {
      components,
      contractHash,
      mcpOAuthCallbackPort: mcpOAuthCallbackPort(projectRoot),
      mcpOAuthCallbackTopologyVersion: 2,
      proofVersion: 4,
      projectId: "0123456789ab",
      proxyId: "proxy-id",
    },
  });
  const errors: string[] = [];
  consoleErrorSpy = vi.spyOn(console, "error").mockImplementation((message) => {
    errors.push(String(message));
  });
  consoleLogSpy = vi.spyOn(console, "log").mockImplementation(() => {});

  const status = await runAdminAction(state, () => credentialSyncIntent({ verbose: true, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }));

  expect(status).toBe(0);
  expect(errors.join("\n")).toContain("proxy runtime state is ready");
  // Proof reuse: no live security-contract probe ran.
  expect(fs.readFileSync(dockerLogPath, "utf8")).not.toContain("runfree_security_contract_probe");
});

test("startup token receipts use the marker generation imported by detached watch", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-admin-receipt-handoff-"));
  const projectRoot = path.join(root, "project");
  const fakeBin = path.join(root, "fake-bin");
  const home = path.join(root, "home");
  const stateDir = path.join(root, "state");
  const policyPath = path.join(projectRoot, ".runfree", "network-policy.json");
  const tokenConfigPath = path.join(root, "config", "tokens.json");
  const markerPath = path.join(root, "runtime-validation.json");
  const dockerLogPath = path.join(root, "docker-calls.log");
  const opLogPath = path.join(root, "op-calls.log");
  const receiptsPath = path.join(root, "startup-receipts.json");
  const secretsDir = path.join(root, "proxy-secrets");
  const runtimeDigest = "sha256:handoff";
  const composeProject = "runfree-test";
  const startedAt = "2026-06-18T00:00:00.000000000Z";
  const projectId = projectHash(projectRoot);
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  fs.mkdirSync(path.dirname(tokenConfigPath), { recursive: true });
  fs.mkdirSync(fakeBin, { recursive: true });
  fs.mkdirSync(secretsDir, { recursive: true });
  fs.writeFileSync(policyPath, `${JSON.stringify({
    hosts: ["api.github.com"],
    tokens: {
      github: {
        description: "GitHub token",
        credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }],
      },
    },
  }, null, 2)}\n`);
  fs.writeFileSync(tokenConfigPath, `${JSON.stringify({
    github: { source: "1password", ref: "op://Private/GitHub/token" },
  }, null, 2)}\n`);
  const contractOptions = { policyPath, projectRoot, runtimeDigest, stateDir, tokenConfigPath };
  const contractHash = expectedAdminContractHash(contractOptions);
  const components = expectedAdminContractComponents(contractOptions);
  const marker = {
    components,
    contractHash,
    mcpOAuthCallbackPort: mcpOAuthCallbackPort(projectRoot),
    mcpOAuthCallbackTopologyVersion: 2,
    projectId,
    proofVersion: 4,
    proxyId: "proxy-id",
    validatedAt: "2026-06-18T00:00:00.000Z",
  };
  fs.writeFileSync(markerPath, `${JSON.stringify(marker)}\n`);
  writeExecutable(path.join(fakeBin, "op"), `#!/bin/sh
printf '%s\\n' "$*" >> ${JSON.stringify(opLogPath)}
if [ -z "$OP_SERVICE_ACCOUNT_TOKEN" ]; then
  exit 3
fi
printf 'ghp_secret\\n'
`);
  writeExecutable(path.join(fakeBin, "docker"), `#!/bin/sh
printf '%s\\n' "$*" >> ${JSON.stringify(dockerLogPath)}
${dockerComponentEvidenceShell(contractOptions)}
if [ "$1" = "info" ]; then
  exit 0
fi
if [ "$1" = "ps" ]; then
  case " $* " in
    *"com.docker.compose.service=agent"*|*"io.runfree.project-id=${projectId}"*)
      printf '%s\\n' agent-id
      ;;
    *"com.docker.compose.service=proxy"*)
      printf '%s\\n' proxy-id
      ;;
  esac
  exit 0
fi
if [ "$1" = "inspect" ] && [ "$2" = "--format" ]; then
  case "$3" in
    *"State.StartedAt"*)
      printf '%s\\n' ${JSON.stringify(startedAt)}
      exit 0
      ;;
    *"State.Running"*)
      printf '%s\\n' true
      exit 0
      ;;
    *"com.docker.compose.project"*)
      printf '%s\\n' ${JSON.stringify(composeProject)}
      exit 0
      ;;
  esac
fi
if [ "$1" = "inspect" ] && [ "$2" = "agent-id" ]; then
  printf '%s\\n' ${JSON.stringify(dockerInspectSecurityEvidence({ policyPath, projectRoot, stateDir }))}
  exit 0
fi
if [ "$1" = "exec" ]; then
${dockerSecurityContractProbeShell()}
  case "$*" in
    *"ls -1 '/run/runfree-proxy-secrets'"*)
      /bin/ls -1 ${JSON.stringify(secretsDir)} 2>/dev/null
      exit 0
      ;;
  esac
  if [ "$2" = "--user" ] && [ "$3" = "0:0" ] && [ "$5" = "cat" ]; then
    /bin/cat ${JSON.stringify(markerPath)}
    exit 0
  fi
  if [ "$2" = "--user" ] && [ "$3" = "1001:1001" ] && [ "$4" = "-i" ]; then
    /bin/cat >/dev/null
    : > ${JSON.stringify(path.join(secretsDir, "github"))}
    exit 0
  fi
  /bin/cat >/dev/null
  exit 0
fi
exit 0
`);
  const commonState = {
    policyPath,
    projectRoot,
    stateDir,
    tokenConfigPath,
  };
  const commonEnv: NodeJS.ProcessEnv = {
    HOME: home,
    PATH: fakeBin,
    RUNFREE_COMPOSE_PROJECT_NAME: composeProject,
    RUNFREE_PROJECT_ID: projectId,
    RUNFREE_RUNTIME_DIGEST: runtimeDigest,
    RUNFREE_TEST_FAKE_DOCKER: "1",
    XDG_CONFIG_HOME: path.join(home, ".config"),
    XDG_STATE_HOME: path.join(home, ".local", "state"),
  };
  const startupState = createAdminState({
    ...commonState,
    env: {
      ...commonEnv,
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
    },
    validatedRuntime: {
      components,
      contractHash,
      mcpOAuthCallbackPort: mcpOAuthCallbackPort(projectRoot),
      mcpOAuthCallbackTopologyVersion: 2,
      projectId,
      proofVersion: 4,
      proxyId: "proxy-id",
    },
  });
  consoleLogSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

  const startupStatus = await runAdminAction(startupState, () => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }));
  const receipts = takeLastTokenSyncReceipts(startupState);
  fs.writeFileSync(receiptsPath, `${JSON.stringify(receipts)}\n`);
  const expectedGeneration = sha256Json({
    proxyId: "proxy-id",
    startedAt,
    validationIdentity: sha256Json(marker),
  });

  expect(startupStatus).toBe(0);
  expect(receipts).toHaveLength(1);
  expect(receipts[0].proxyStoreGeneration).toBe(expectedGeneration);

  const receiptFd = fs.openSync(receiptsPath, "r");
  try {
    const watchState = createAdminState({
      ...commonState,
      env: {
        ...commonEnv,
        RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "1",
        RUNFREE_TOKEN_SYNC_RECEIPT_FD: String(receiptFd),
      },
    });

    const watchStatus = await runAdminAction(watchState, () => credentialSyncIntent({ verbose: false, watch: true, quiet: true, delayFirstSync: false, cacheSourceSecrets: true }));

    expect(watchStatus).toBe(0);
    expect(fs.readFileSync(opLogPath, "utf8").trim().split(/\n+/)).toEqual([
      "read op://Private/GitHub/token",
    ]);
  } finally {
    fs.closeSync(receiptFd);
  }
});

test.each([false, true])("policy reload preserves receipts and rejects source drift before restart (drift: %s)", async (drift) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-admin-reload-receipts-"));
  const projectRoot = path.join(root, "project");
  const fakeBin = path.join(root, "fake-bin");
  const home = path.join(root, "home");
  const stateDir = path.join(root, "state");
  const policyPath = path.join(projectRoot, ".runfree", "network-policy.json");
  const tokenConfigPath = path.join(root, "config", "tokens.json");
  const markerPath = path.join(root, "runtime-validation.json");
  const dockerLogPath = path.join(root, "docker-calls.log");
  const driftTrigger = path.join(root, "change-source-while-queued");
  if (drift) fs.writeFileSync(driftTrigger, "enabled");
  const runtimeDigest = "sha256:reload-receipts";
  const composeProject = "runfree-test";
  const startedAt = "2026-06-18T00:01:00.000000000Z";
  const projectId = projectHash(projectRoot);
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  fs.mkdirSync(path.dirname(tokenConfigPath), { recursive: true });
  fs.mkdirSync(fakeBin, { recursive: true });
  fs.writeFileSync(policyPath, `${JSON.stringify({
    hosts: ["api.github.com"],
    tokens: {
      github: {
        description: "GitHub token",
        credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }],
      },
    },
  }, null, 2)}\n`);
  fs.writeFileSync(tokenConfigPath, `${JSON.stringify({
    github: { source: "env", env: "GITHUB_TOKEN" },
  }, null, 2)}\n`);
  const contractOptions = { policyPath, projectRoot, runtimeDigest, stateDir, tokenConfigPath };
  const contractHash = expectedAdminContractHash(contractOptions);
  const components = expectedAdminContractComponents(contractOptions);
  const marker = {
    components,
    contractHash,
    mcpOAuthCallbackPort: mcpOAuthCallbackPort(projectRoot),
    mcpOAuthCallbackTopologyVersion: 2,
    projectId,
    proofVersion: 4,
    proxyId: "proxy-id",
    validatedAt: "2026-06-18T00:00:00.000Z",
  };
  fs.writeFileSync(markerPath, `${JSON.stringify(marker)}\n`);
  writeExecutable(path.join(fakeBin, "docker"), `#!/bin/sh
printf '%s\\n' "$*" >> ${JSON.stringify(dockerLogPath)}
${dockerComponentEvidenceShell(contractOptions)}
if [ "$1" = "info" ]; then
  exit 0
fi
if [ "$1" = "ps" ]; then
  if [ -f ${JSON.stringify(driftTrigger)} ] && [ -d ${JSON.stringify(path.join(stateDir, "runtime-lifecycle.lock"))} ]; then
    printf '%s\\n' '{"github":{"source":"env","env":"CHANGED_TOKEN"}}' > ${JSON.stringify(tokenConfigPath)}
  fi
  case " $* " in
    *"com.docker.compose.service=proxy"*)
      printf '%s\\n' proxy-id
      ;;
    *)
      printf '%s\\n' agent-id
      ;;
  esac
  exit 0
fi
if [ "$1" = "inspect" ] && [ "$2" = "--format" ]; then
  case "$3" in
    *"State.StartedAt"*)
      printf '%s\\n' ${JSON.stringify(startedAt)}
      exit 0
      ;;
    *"State.Running"*)
      printf '%s\\n' true
      exit 0
      ;;
    *"com.docker.compose.project"*)
      printf '%s\\n' ${JSON.stringify(composeProject)}
      exit 0
      ;;
  esac
fi
if [ "$1" = "restart" ]; then
  exit 0
fi
if [ "$1" = "exec" ]; then
  case "$*" in
    *"request-proxy.json"*)
      printf '%s\\n' '{"generation":"sha256:test-generation","rulesetVerified":true,"appliedAt":"2026-06-18T00:01:01.000Z"}'
      printf '%s\\n' '{"generation":"sha256:test-generation","appliedAt":"2026-06-18T00:01:01.000Z"}'
      exit 0
      ;;
  esac
  if [ "$2" = "--user" ] && [ "$3" = "0:0" ] && [ "$5" = "cat" ]; then
    /bin/cat ${JSON.stringify(markerPath)}
    exit 0
  fi
  /bin/cat >/dev/null
  exit 0
fi
exit 0
`);
  const state = createAdminState({
    env: {
      GITHUB_TOKEN: "ghp_secret",
      HOME: home,
      PATH: fakeBin,
      RUNFREE_COMPOSE_PROJECT_NAME: composeProject,
      RUNFREE_PROJECT_ID: projectId,
      RUNFREE_RUNTIME_DIGEST: runtimeDigest,
      RUNFREE_TEST_FAKE_DOCKER: "1",
      XDG_CONFIG_HOME: path.join(home, ".config"),
      XDG_STATE_HOME: path.join(home, ".local", "state"),
    },
    policyPath,
    projectRoot,
    stateDir,
    tokenConfigPath,
    validatedRuntime: {
      components,
      contractHash,
      mcpOAuthCallbackPort: mcpOAuthCallbackPort(projectRoot),
      mcpOAuthCallbackTopologyVersion: 2,
      projectId,
      proofVersion: 4,
      proxyId: "proxy-id",
    },
  });
  consoleLogSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

  if (drift) {
    await expect(runAdminAction(state, () => reloadProxy())).rejects.toThrow("before disruption");
    expect(fs.readFileSync(dockerLogPath, "utf8").split("\n").some((line) => line.startsWith("restart ") || line.startsWith("start "))).toBe(false);
    fs.unlinkSync(driftTrigger);
    fs.writeFileSync(tokenConfigPath, JSON.stringify({ github: { source: "env", env: "GITHUB_TOKEN" } }));
  }
  const status = await runAdminAction(state, () => reloadProxy());
  const receipts = takeLastTokenSyncReceipts(state);

  expect(status).toBe(0);
  expect(receipts).toHaveLength(1);
  expect(receipts[0]).toMatchObject({
    tokenName: "github",
    proxyStoreGeneration: sha256Json({
      proxyId: "proxy-id",
      startedAt,
      validationIdentity: sha256Json(marker),
    }),
  });
});

test("direct token sync rejects a stale runtime security contract before writing proxy tokens", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-admin-stale-contract-"));
  const projectRoot = path.join(root, "project");
  const fakeBin = path.join(root, "fake-bin");
  const home = path.join(root, "home");
  const stateDir = path.join(root, "state");
  const policyPath = path.join(projectRoot, ".runfree", "network-policy.json");
  const tokenConfigPath = path.join(root, "config", "tokens.json");
  const markerPath = path.join(root, "runtime-validation.json");
  const dockerLogPath = path.join(root, "docker-calls.log");
  const runtimeDigest = "sha256:stale-contract";
  const composeProject = "runfree-test";
  const projectId = projectHash(projectRoot);
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  fs.mkdirSync(path.dirname(tokenConfigPath), { recursive: true });
  fs.mkdirSync(fakeBin, { recursive: true });
  ensureClaudeMcpConfigFile(path.join(stateDir, "mounts", "claude-mcp.json"));
  fs.writeFileSync(path.join(projectRoot, ".runfree", "runfree.json"), `${JSON.stringify({ version: 3, runtime: { dependencyOverlays: "off" } }, null, 2)}\n`);
  fs.writeFileSync(policyPath, `${JSON.stringify({
    hosts: ["api.github.com"],
    tokens: {
      github: {
        description: "GitHub token",
        credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }],
      },
    },
  }, null, 2)}\n`);
  fs.writeFileSync(tokenConfigPath, `${JSON.stringify({
    github: { source: "env", env: "GITHUB_TOKEN" },
  }, null, 2)}\n`);
  const components = expectedAdminContractComponents({ policyPath, projectRoot, runtimeDigest, stateDir, tokenConfigPath });
  fs.writeFileSync(markerPath, `${JSON.stringify({
    components,
    contractHash: "sha256:stale",
    mcpOAuthCallbackPort: mcpOAuthCallbackPort(projectRoot),
    mcpOAuthCallbackTopologyVersion: 2,
    projectId,
    proofVersion: 4,
    proxyId: "proxy-id",
    validatedAt: "2026-06-18T00:00:00.000Z",
  })}\n`);
  writeExecutable(path.join(fakeBin, "docker"), `#!/bin/sh
printf '%s\\n' "$*" >> ${JSON.stringify(dockerLogPath)}
if [ "$1" = "info" ]; then
  exit 0
fi
if [ "$1" = "ps" ]; then
  case " $* " in
    *"com.docker.compose.service=agent"*|*"io.runfree.project-id=${projectId}"*)
      printf '%s\\n' agent-id
      ;;
    *"com.docker.compose.service=proxy"*)
      printf '%s\\n' proxy-id
      ;;
  esac
  exit 0
fi
if [ "$1" = "inspect" ] && [ "$2" = "--format" ]; then
  case "$3" in
    *"State.StartedAt"*)
      printf '%s\\n' "2026-06-18T00:00:00.000000000Z"
      exit 0
      ;;
    *"State.Running"*)
      printf '%s\\n' true
      exit 0
      ;;
    *"com.docker.compose.project"*)
      printf '%s\\n' ${JSON.stringify(composeProject)}
      exit 0
      ;;
  esac
fi
if [ "$1" = "exec" ]; then
${dockerSecurityContractProbeShell()}
  if [ "$2" = "--user" ] && [ "$3" = "0:0" ] && [ "$5" = "cat" ]; then
    /bin/cat ${JSON.stringify(markerPath)}
    exit 0
  fi
  /bin/cat >/dev/null
  exit 0
fi
exit 0
`);
  const errors: string[] = [];
  consoleLogSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  consoleErrorSpy = vi.spyOn(console, "error").mockImplementation((message) => {
    errors.push(String(message));
  });

  const status = await runAdminAction(createAdminState({
    env: {
      GITHUB_TOKEN: "ghp_secret",
      HOME: home,
      PATH: fakeBin,
      RUNFREE_COMPOSE_PROJECT_NAME: composeProject,
      RUNFREE_PROJECT_ID: projectId,
      RUNFREE_RUNTIME_DIGEST: runtimeDigest,
      RUNFREE_RUNTIME_ROOT: path.join(process.cwd(), "packages/agent-runtime"),
      RUNFREE_TEST_FAKE_DOCKER: "1",
      XDG_CONFIG_HOME: path.join(home, ".config"),
      XDG_STATE_HOME: path.join(home, ".local", "state"),
    },
    policyPath,
    projectRoot,
    stateDir,
    tokenConfigPath,
  }), () => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }));

  expect(status).toBe(1);
  expect(errors.join("\n")).toContain("runtime validation marker is stale for runtime security contract");
  expect(fs.readFileSync(dockerLogPath, "utf8")).not.toContain("--user 1001:1001 -i proxy-id");
});

test("token sync watch quiet suppresses routine watch output", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-admin-watch-quiet-"));
  const projectRoot = path.join(root, "project");
  const fakeBin = path.join(root, "fake-bin");
  const home = path.join(root, "home");
  const stateDir = path.join(root, "state");
  const policyPath = path.join(projectRoot, ".runfree", "network-policy.json");
  const tokenConfigPath = path.join(root, "config", "tokens.json");
  const dockerLogPath = path.join(root, "docker-calls.log");
  const runtimeDigest = "sha256:quiet-watch";
  const projectId = projectHash(projectRoot);
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  fs.mkdirSync(path.dirname(tokenConfigPath), { recursive: true });
  fs.mkdirSync(fakeBin, { recursive: true });
  fs.writeFileSync(policyPath, `${JSON.stringify({
    hosts: ["api.github.com"],
    tokens: {
      github: {
        description: "GitHub token",
        credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }],
      },
    },
  }, null, 2)}\n`);
  fs.writeFileSync(tokenConfigPath, `${JSON.stringify({
    github: { source: "1password", ref: "op://Private/GitHub/token", refreshEverySeconds: 1 },
  }, null, 2)}\n`);
  const contractOptions = { policyPath, projectRoot, runtimeDigest, stateDir, tokenConfigPath };
  const contractHash = expectedAdminContractHash(contractOptions);
  const components = expectedAdminContractComponents(contractOptions);
  writeExecutable(path.join(fakeBin, "op"), `#!/bin/sh
if [ "$1" = "read" ]; then
  printf 'ghp_secret\\n'
  exit 0
fi
exit 1
`);
  writeExecutable(path.join(fakeBin, "docker"), `#!/bin/sh
stdin="$(/bin/cat)"
printf '%s\\t%s\\n' "$*" "$stdin" >> ${JSON.stringify(dockerLogPath)}
${dockerComponentEvidenceShell(contractOptions)}
case "$*" in
  *"State.StartedAt"*)
    printf '%s\\n' '2026-06-18T00:00:00.000000000Z'
    ;;
esac
exit 0
`);

  const state = createAdminState({
    env: {
      HOME: home,
      PATH: fakeBin,
      RUNFREE_PROJECT_ID: projectId,
      RUNFREE_RUNTIME_DIGEST: runtimeDigest,
      RUNFREE_TEST_FAKE_DOCKER: "1",
      RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "1",
      XDG_CONFIG_HOME: path.join(home, ".config"),
      XDG_STATE_HOME: path.join(home, ".local", "state"),
    },
    policyPath,
    projectRoot,
    stateDir,
    tokenConfigPath,
    validatedRuntime: {
      components,
      contractHash,
      mcpOAuthCallbackPort: mcpOAuthCallbackPort(projectRoot),
      mcpOAuthCallbackTopologyVersion: 2,
      proofVersion: 4,
      projectId,
      proxyId: "proxy-id",
    },
  });
  const output: string[] = [];
  const errors: string[] = [];
  consoleLogSpy = vi.spyOn(console, "log").mockImplementation((message) => {
    output.push(String(message));
  });
  consoleErrorSpy = vi.spyOn(console, "error").mockImplementation((message) => {
    errors.push(String(message));
  });

  const status = await runAdminAction(state, () => credentialSyncIntent({ verbose: false, watch: true, quiet: true, delayFirstSync: false, cacheSourceSecrets: true }));

  expect(status).toBe(0);
  expect(output.join("\n")).not.toContain("source secret cache");
  expect(output.join("\n")).not.toContain("next token sync");
  expect(output.join("\n")).not.toContain("github: synced");
  expect(errors.join("\n")).not.toContain("resolving 1Password token source");
  expect(fs.readFileSync(dockerLogPath, "utf8")).toContain("ghp_secret");
});

test("token sync watch delay-first-sync waits before reading token sources", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-admin-watch-delay-"));
  const projectRoot = path.join(root, "project");
  const fakeBin = path.join(root, "fake-bin");
  const home = path.join(root, "home");
  const stateDir = path.join(root, "state");
  const policyPath = path.join(projectRoot, ".runfree", "network-policy.json");
  const tokenConfigPath = path.join(root, "config", "tokens.json");
  const opLogPath = path.join(root, "op-calls.log");
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  fs.mkdirSync(path.dirname(tokenConfigPath), { recursive: true });
  fs.mkdirSync(fakeBin, { recursive: true });
  fs.writeFileSync(policyPath, `${JSON.stringify({
    hosts: ["api.github.com"],
    tokens: {
      github: {
        description: "GitHub token",
        credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }],
      },
    },
  }, null, 2)}\n`);
  fs.writeFileSync(tokenConfigPath, `${JSON.stringify({
    github: { source: "1password", ref: "op://Private/GitHub/token", refreshEverySeconds: 1 },
  }, null, 2)}\n`);
  writeExecutable(path.join(fakeBin, "op"), `#!/bin/sh
printf '%s\\n' "$*" >> ${JSON.stringify(opLogPath)}
printf 'ghp_secret\\n'
`);

  const state = createAdminState({
    env: {
      HOME: home,
      PATH: fakeBin,
      RUNFREE_TEST_FAKE_DOCKER: "1",
      RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "1",
      RUNFREE_TOKEN_SYNC_WATCH_PARENT_PID: "not-a-pid",
      XDG_CONFIG_HOME: path.join(home, ".config"),
      XDG_STATE_HOME: path.join(home, ".local", "state"),
    },
    policyPath,
    projectRoot,
    stateDir,
    tokenConfigPath,
  });

  const status = await runAdminAction(state, () => credentialSyncIntent({ verbose: false, watch: true, quiet: true, delayFirstSync: true, cacheSourceSecrets: true }));

  expect(status).toBe(0);
  expect(fs.existsSync(opLogPath)).toBe(false);
});

test("prepared credentials refuse stale admission, then bind one fresh operation without extending it on repeated checks", async () => {
  const { prepareRuntimeTokenSources, admitPreparedRuntimeTokenSources, clearPreparedRuntimeTokenSources } = await import("./admin-core.ts");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-prepared-credentials-"));
  const projectRoot = path.join(root, "project");
  const policyPath = path.join(projectRoot, ".runfree/network-policy.json");
  const stateDir = path.join(root, "state");
  const tokenConfigPath = path.join(root, "tokens.json");
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  fs.writeFileSync(policyPath, JSON.stringify({ hosts: [], tokens: {} }));
  fs.writeFileSync(tokenConfigPath, "{}");
  const project = adminTestProjectInfo({ projectRoot, policyPath, stateDir, tokenConfigPath });
  prepareSelectedAdminControls(projectRoot, project, policyPath);
  const state = createAdminState({ projectRoot, policyPath, stateDir, tokenConfigPath,
    env: { HOME: root, PATH: process.env.PATH }, runtimeContext: { projectRoot, project, runtimeRoot: "/runtime" } });
  const clock = vi.spyOn(Date, "now");
  let now = Date.now(); clock.mockImplementation(() => now);
  try {
    expect(await runAdminAction(state, () => prepareRuntimeTokenSources())).toBe(0);
    now += 120_000;
    expect(() => admitPreparedRuntimeTokenSources(project)).toThrow("before disruption");
    expect(await runAdminAction(state, () => prepareRuntimeTokenSources())).toBe(0);
    now += 119_000;
    admitPreparedRuntimeTokenSources(project);
    now += 119_000;
    expect(() => admitPreparedRuntimeTokenSources(project)).not.toThrow();
    now += 1001;
    expect(() => admitPreparedRuntimeTokenSources(project)).toThrow("before disruption");
  } finally { clock.mockRestore(); clearPreparedRuntimeTokenSources(project); fs.rmSync(root, { recursive: true, force: true }); }
});

test.each(["binding", "required-removal", "optional-addition", "named-change", "named-removal", "named-malformed", "malformed"] as const)(
  "prepared credential admission refuses %s before disruption and accepts restored metadata without another source read", async (change) => {
    const { prepareRuntimeTokenSources, admitPreparedRuntimeTokenSources, clearPreparedRuntimeTokenSources } = await import("./admin-core.ts");
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-prepared-source-drift-"));
    const projectRoot = path.join(root, "project");
    const policyPath = path.join(projectRoot, ".runfree/network-policy.json");
    const stateDir = path.join(root, "state");
    const tokenConfigPath = path.join(root, "tokens.json");
    const sourceConfigPath = path.join(root, "sources.json");
    fs.mkdirSync(path.dirname(policyPath), { recursive: true });
    const credentials = [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }];
    fs.writeFileSync(policyPath, JSON.stringify({ hosts: ["api.github.com"], tokens: {
      github: { description: "Required fixture", credentials }, optional: { description: "Optional fixture", allowAnonymous: true, credentials: [{ ...credentials[0], header: "X-Optional" }] },
    } }));
    const named = change.startsWith("named-");
    const config = { github: named ? { source: "named", name: "fixture" } : { source: "env", env: "GITHUB_TOKEN" } };
    const registry = { fixture: { type: "command", argv: [fs.realpathSync(process.execPath), "--version"],
      displayArgv: ["node", "--version"], createdAt: "2026-09-06T00:00:00.000Z" } };
    fs.writeFileSync(tokenConfigPath, JSON.stringify(config));
    fs.writeFileSync(sourceConfigPath, JSON.stringify(registry));
    const project = adminTestProjectInfo({ projectRoot, policyPath, stateDir, tokenConfigPath });
    prepareSelectedAdminControls(projectRoot, project, policyPath);
    const sourceReads = vi.fn(() => ({ status: 0, stdout: "fixture-token\n", stderr: "", pid: 1, signal: null, output: [] }));
    const state = createAdminState({ projectRoot, policyPath, stateDir, tokenConfigPath, sourceConfigPath,
      env: { HOME: root, PATH: process.env.PATH, GITHUB_TOKEN: "fixture-token" }, processRunner: sourceReads,
      runtimeContext: { projectRoot, project, runtimeRoot: "/runtime" } });
    try {
      expect(await runAdminAction(state, () => prepareRuntimeTokenSources())).toBe(0);
      const readsBeforeAdmission = sourceReads.mock.calls.length;
      expect(readsBeforeAdmission).toBe(named ? 1 : 0);
      if (change === "binding") fs.writeFileSync(tokenConfigPath, JSON.stringify({ github: { source: "env", env: "OTHER_TOKEN" } }));
      if (change === "required-removal") fs.writeFileSync(tokenConfigPath, "{}");
      if (change === "optional-addition") fs.writeFileSync(tokenConfigPath, JSON.stringify({ ...config, optional: { source: "env", env: "GITHUB_TOKEN" } }));
      if (change === "named-change") fs.writeFileSync(sourceConfigPath, JSON.stringify({ fixture: { ...registry.fixture, argv: [fs.realpathSync(process.execPath), "--help"] } }));
      if (change === "named-removal") fs.writeFileSync(sourceConfigPath, "{}");
      if (change === "named-malformed") fs.writeFileSync(sourceConfigPath, "[]");
      if (change === "malformed") fs.writeFileSync(tokenConfigPath, "not-json");
      expect(() => admitPreparedRuntimeTokenSources(project)).toThrow();
      expect(sourceReads).toHaveBeenCalledTimes(readsBeforeAdmission);
      fs.writeFileSync(tokenConfigPath, JSON.stringify(config));
      fs.writeFileSync(sourceConfigPath, JSON.stringify(registry));
      expect(() => admitPreparedRuntimeTokenSources(project)).not.toThrow();
      expect(sourceReads).toHaveBeenCalledTimes(readsBeforeAdmission);
    } finally { clearPreparedRuntimeTokenSources(project); fs.rmSync(root, { recursive: true, force: true }); }
  },
);
