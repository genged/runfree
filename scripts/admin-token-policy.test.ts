import childProcess from "node:child_process";
import type { SpawnSyncOptions, SpawnSyncReturns } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import util from "node:util";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { validateNetworkPolicy, type PolicyJson } from "@runfree/runtime-contracts/network-policy";
import { defaultConfig, projectControlPaths, type ProjectInfo } from "../packages/cli/src/config.ts";
import { approveNetworkCandidate, approveRuntimeIsolationControl } from "../packages/cli/src/control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../packages/cli/src/control/candidates.ts";
import {
  convergeEffectivePolicyGeneration,
  publishEffectivePolicyGeneration,
  readActiveEffectiveControl,
} from "../packages/cli/src/control/effective.ts";
import { RUNFREE_RUNTIME_DIGEST } from "../packages/cli/src/embedded-assets.generated.ts";
import { projectHash } from "../packages/cli/src/project-identity.ts";
import { sha256Digest } from "../packages/cli/src/runtime/component-state.ts";
import {
  CONTROL_PLANE_PROOF_SCHEMA_VERSION,
  RUNTIME_ADMISSION_CONTRACT_EPOCH,
  createControlPlaneGenerationV2,
  createControlPlaneMaterializationManifestV2,
  type ControlPlaneEffectiveSelectionV2,
} from "../packages/cli/src/runtime/component-state-v2.ts";
import {
  controlPlaneRebindTransactionPath,
  createControlPlaneRebindTransaction,
  serializeControlPlaneRebindTransaction,
  type ControlPlaneRebindTransaction,
} from "../packages/cli/src/runtime/control-plane-rebind.ts";
import { mcpOAuthCallbackPort } from "../packages/cli/src/runtime/mcp.ts";
import { activeRuntimePlanFromContext } from "../packages/cli/src/runtime/plan.ts";
import { createRuntimeSecurityContract } from "../packages/cli/src/runtime/security-contract.ts";
import { classifyOnePasswordFailure } from "../packages/cli/src/admin/admin-core.ts";
import { CREDENTIAL_OBSERVATION_BATCH_HEADER } from "../packages/cli/src/admin/credential-observation.ts";
import { createAdminState } from "../packages/cli/src/admin/context.ts";
import {
  convergeProxyPolicy,
  runAdminAction,
  sourceAddCommandIntent,
  sourceAddJwtIntent,
  sourceList,
  sourceRemoveIntent,
  sourceShowIntent,
  credentialSetSourceIntent,
  credentialStatus,
  credentialSyncIntent,
  credentialClearSourceIntent,
} from "../packages/cli/src/admin/options.ts";
import { tryAcquireControlLock } from "../packages/cli/src/control/lock.ts";
import {
  admitPreparedRuntimeTokenSources,
  clearPreparedRuntimeTokenSources,
  prepareRuntimeTokenSources,
  runCapture,
  TokenSyncDeferredError,
  withAdminCallTimeout,
} from "../packages/cli/src/admin/admin-core.ts";
import { TOKEN_SYNC_DEFERRED_STATUS, TOKEN_SYNC_REPREPARE_STATUS } from "../packages/cli/src/runtime/constants.ts";
import { flushWarnings } from "../packages/cli/src/warnings.ts";
import { cliEntryArgv, credentialWatchHarnessEntryArgv } from "../tests/support/prebuilt-entry.ts";
import type { CredentialWatchHarnessConfig } from "./credential-watch.test-harness.ts";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);

let tmpBase: string;
let tmp: string;
let home: string;

type AdminRunResult = {
  status: number;
  stderr: string;
  stdout: string;
};

type FakeCommandHandler = (
  args: string[],
  options: SpawnSyncOptions,
  commandPath: string,
) => SpawnSyncReturns<string>;

const fakeCommandHandlers = new Map<string, FakeCommandHandler>();

function spawnResult(options: {
  error?: Error;
  signal?: NodeJS.Signals;
  status?: number | null;
  stderr?: string;
  stdout?: string;
} = {}): SpawnSyncReturns<string> {
  const stdout = options.stdout ?? "";
  const stderr = options.stderr ?? "";
  return {
    error: options.error,
    output: [null, stdout, stderr],
    pid: 0,
    signal: options.signal ?? null,
    status: options.status === undefined ? 0 : options.status,
    stderr,
    stdout,
  };
}

function spawnTimeoutResult(command: string): SpawnSyncReturns<string> {
  const error = new Error(`spawnSync ${command} ETIMEDOUT`) as NodeJS.ErrnoException;
  error.code = "ETIMEDOUT";
  return spawnResult({ error, status: null });
}

function envFromSpawnOptions(options: SpawnSyncOptions): NodeJS.ProcessEnv {
  return (options.env ?? process.env) as NodeJS.ProcessEnv;
}

function spawnInputText(input: SpawnSyncOptions["input"]): string {
  if (input === undefined) return "";
  if (typeof input === "string") return input;
  if (Buffer.isBuffer(input)) return input.toString("utf8");
  if (input instanceof Uint8Array) return Buffer.from(input).toString("utf8");
  return String(input);
}

function realExecutableForRunner(command: string, env: NodeJS.ProcessEnv): string | undefined {
  const candidates = command.includes("/") || path.isAbsolute(command)
    ? [path.resolve(command)]
    : (env.PATH ?? "").split(path.delimiter)
      .filter((entry) => entry.trim() !== "")
      .map((entry) => path.join(entry, command));
  for (const candidate of candidates) {
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return fs.realpathSync(candidate);
    } catch {
    }
  }
  return undefined;
}

function fakeProcessRunner(command: string, args: string[], options: SpawnSyncOptions): SpawnSyncReturns<string> {
  const env = envFromSpawnOptions(options);
  if (command === "command" && args[0] === "-v" && typeof args[1] === "string") {
    return spawnResult({ status: realExecutableForRunner(args[1], env) ? 0 : 1 });
  }
  const realPath = realExecutableForRunner(command, env);
  const handler = realPath ? fakeCommandHandlers.get(realPath) : undefined;
  if (handler && realPath) return handler(args, options, realPath);
  return childProcess.spawnSync(command, args, options) as SpawnSyncReturns<string>;
}

function writeExecutableStub(filePath: string): string {
  fs.writeFileSync(filePath, "#!/bin/sh\nexit 127\n");
  fs.chmodSync(filePath, 0o755);
  return fs.realpathSync(filePath);
}

function registerFakeCommand(filePath: string, handler: FakeCommandHandler): void {
  fakeCommandHandlers.set(writeExecutableStub(filePath), handler);
}

function writeFixtureRepo(policy: unknown): void {
  fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
  fs.mkdirSync(path.join(tmp, "scripts"), { recursive: true });
  fs.symlinkSync(path.join(repoRoot, "node_modules"), path.join(tmp, "node_modules"), "dir");
  fs.writeFileSync(path.join(tmp, ".runfree/network-policy.json"), `${JSON.stringify(policy, null, 2)}\n`);
}

async function runAdmin(
  action: () => void | Promise<void>,
  extraEnv: NodeJS.ProcessEnv = {},
  stateOverrides: Readonly<{ policyAccess?: "effective-read-only"; validatedRuntime?: ReturnType<typeof tokenSyncValidatedRuntime> }> = {},
): Promise<AdminRunResult> {
  fs.mkdirSync(home, { recursive: true });
  const env = {
    ...process.env,
    HOME: home,
    // Isolate every host config/state/data root so a developer's real
    // XDG_CONFIG_HOME / CODEX_HOME does not redirect the admin config root
    // (sources.json, tokens.json) away from the test's <home>/.config.
    XDG_CONFIG_HOME: path.join(home, ".config"),
    XDG_DATA_HOME: path.join(home, ".local/share"),
    XDG_STATE_HOME: path.join(home, ".local/state"),
    CODEX_HOME: path.join(home, ".codex"),
    RUNFREE_PACKAGE_ROOT: tmp,
    RUNFREE_RUNTIME_ROOT: path.join(repoRoot, "packages/agent-runtime"),
    RUNFREE_PROJECT_ID: projectHash(tmp),
    RUNFREE_RUNTIME_DIGEST,
    RUNFREE_TEST_FAKE_DOCKER: "1",
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
      ensureSelectedEffectiveControls();
      status = await runAdminAction(createAdminState({
        env,
        packageRoot: tmp,
        projectRoot: tmp,
        processRunner: fakeProcessRunner,
        runtimeContext: tokenSyncRuntimeContext(env),
        stateDir: path.join(home, ".local/state/runfree"),
        ...stateOverrides,
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

// Subprocess driver for the typed `runfree` CLI (yargs grammar). Used only for
// tests that exercise parser-level behavior the typed intents do not model
// (e.g. rejecting a mistyped flag): those failures live in the yargs strict
// parser, not in any intent, so they cannot be reproduced by calling an intent
// in-process. Env isolation mirrors runAdmin's in-process state.
function runAdminCli(args: string[], options: { input?: string; extraEnv?: NodeJS.ProcessEnv } = {}): AdminRunResult {
  fs.mkdirSync(home, { recursive: true });
  const env = {
    ...process.env,
    HOME: home,
    XDG_CONFIG_HOME: path.join(home, ".config"),
    XDG_DATA_HOME: path.join(home, ".local/share"),
    XDG_STATE_HOME: path.join(home, ".local/state"),
    CODEX_HOME: path.join(home, ".codex"),
    RUNFREE_PACKAGE_ROOT: tmp,
    RUNFREE_RUNTIME_ROOT: path.join(repoRoot, "packages/agent-runtime"),
    RUNFREE_PROJECT_ID: projectHash(tmp),
    RUNFREE_RUNTIME_DIGEST,
    RUNFREE_TEST_FAKE_DOCKER: "1",
    ...options.extraEnv,
  };
  const result = childProcess.spawnSync(
    process.execPath,
    [...cliEntryArgv(), "--workspace", tmp, ...args],
    { cwd: repoRoot, encoding: "utf8", env, input: options.input },
  );
  return {
    status: result.status ?? 1,
    stderr: result.stderr ?? "",
    stdout: result.stdout ?? "",
  };
}

function readPolicy(): PolicyJson {
  return JSON.parse(fs.readFileSync(path.join(tmp, ".runfree/network-policy.json"), "utf8")) as PolicyJson;
}

function tokenConfigPath(): string {
  return path.join(home, ".config/runfree/projects", projectHash(tmp), "tokens.json");
}

function writeTokenConfig(value: unknown): void {
  const filePath = tokenConfigPath();
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function readTokenConfig(): unknown {
  return JSON.parse(fs.readFileSync(tokenConfigPath(), "utf8")) as unknown;
}

function readSourceRegistry(): unknown {
  return JSON.parse(fs.readFileSync(path.join(home, ".config/runfree/sources.json"), "utf8")) as unknown;
}

function readTokenStatus(): Record<string, { message: string; ok: boolean; source?: string; state?: string; heldValueResolvedAt?: string }> {
  return JSON.parse(fs.readFileSync(path.join(home, ".local/state/runfree/token-sync-status.json"), "utf8")) as Record<string, { message: string; ok: boolean; source?: string; state?: string; heldValueResolvedAt?: string }>;
}

function adminStateDir(): string {
  return path.join(home, ".local/state/runfree");
}

function adminProjectInfoForTokenSync(): ProjectInfo {
  const stateDir = adminStateDir();
  const runfreeDir = path.join(tmp, ".runfree");
  const mountsDir = path.join(stateDir, "mounts");
  return {
    config: defaultConfig(),
    paths: {
      runfreeDir,
      agentEnvPath: path.join(runfreeDir, "config", "agent.env"),
      claudeConfigPath: path.join(stateDir, "claude.json"),
      claudeMcpConfigPath: path.join(mountsDir, "claude-mcp.json"),
      claudeDir: path.join(stateDir, "claude"),
      codexDir: path.join(stateDir, "codex"),
      configPath: path.join(runfreeDir, "runfree.json"),
      ...projectControlPaths(stateDir),
      gitConfigPath: path.join(stateDir, "gitconfig"),
      inboxDir: path.join(stateDir, "inbox"),
      projectCodexDirMaskPath: path.join(mountsDir, "project-codex-mask"),
      mcpOperationPolicyPath: path.join(stateDir, "mcp-operation-policy.json"),
      mcpOAuthPolicyPath: path.join(stateDir, "oauth-mediation-policy.json"),
      proxyCaCertDir: path.join(stateDir, "proxy-ca", "public"),
      proxyCaKeyDir: path.join(stateDir, "proxy-ca", "private"),
      policyPath: path.join(runfreeDir, "network-policy.json"),
      sessionsDir: path.join(stateDir, "sessions"),
      stateDir,
      tokenConfigPath: tokenConfigPath(),
    },
  };
}

function tokenSyncRuntimeContext(env: NodeJS.ProcessEnv = {}) {
  return {
    projectRoot: tmp,
    project: adminProjectInfoForTokenSync(),
    runtimeRoot: path.join(repoRoot, "packages/agent-runtime"),
    env,
  };
}

// Runtime environment generation requires a selected effective control
// generation. The generation's compiled policy content is irrelevant to these
// token tests (the admin state reads the project policy file directly), so a
// minimal empty desired policy is captured, approved, and published once per
// test project — swapping the project policy file back afterwards so each
// test's own policy fixture is untouched.
function ensureSelectedEffectiveControls(): void {
  const project = adminProjectInfoForTokenSync();
  if (fs.existsSync(path.join(project.paths.controlProxyDir, "active.json"))) return;
  const policyPath = project.paths.policyPath;
  const original = fs.existsSync(policyPath) ? fs.readFileSync(policyPath, "utf8") : undefined;
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  fs.writeFileSync(policyPath, '{"version":2,"hosts":[]}\n');
  try {
    const candidate = captureDesiredPolicyCandidate(tmp, project.paths.controlCandidatesDir);
    approveNetworkCandidate(tmp, project, candidate, "network-project", "interactive");
    approveNetworkCandidate(tmp, project, candidate, "network-local", "interactive");
    approveRuntimeIsolationControl(tmp, project, "interactive");
    publishEffectivePolicyGeneration(tmp, project);
  } finally {
    if (original === undefined) fs.rmSync(policyPath, { force: true });
    else fs.writeFileSync(policyPath, original);
  }
}

// Launch preparation reads the *selected effective* policy (never the project
// file), so the D4 tests select one compiled from the test's own policy
// fixture, which the admin sync then agrees with.
function selectEffectiveControlsFromProjectPolicy(): void {
  const project = adminProjectInfoForTokenSync();
  const policyPath = project.paths.policyPath;
  const original = fs.readFileSync(policyPath, "utf8");
  // The admin fixtures predate desired-policy v2; the effective generation is
  // compiled from the same hosts and tokens with the version stamp added.
  fs.writeFileSync(policyPath, `${JSON.stringify({ version: 2, ...JSON.parse(original) }, null, 2)}\n`);
  try {
    const candidate = captureDesiredPolicyCandidate(tmp, project.paths.controlCandidatesDir);
    approveNetworkCandidate(tmp, project, candidate, "network-project", "interactive");
    approveNetworkCandidate(tmp, project, candidate, "network-local", "interactive");
    approveRuntimeIsolationControl(tmp, project, "interactive");
    publishEffectivePolicyGeneration(tmp, project);
  } finally {
    fs.writeFileSync(policyPath, original);
  }
}

function expectedTokenSyncActivePlan() {
  fs.mkdirSync(tmp, { recursive: true });
  const project = adminProjectInfoForTokenSync();
  fs.mkdirSync(path.dirname(project.paths.claudeMcpConfigPath), { recursive: true });
  if (!fs.existsSync(project.paths.claudeMcpConfigPath)) {
    fs.writeFileSync(project.paths.claudeMcpConfigPath, '{\n  "mcpServers": {}\n}\n');
  }
  ensureSelectedEffectiveControls();
  return activeRuntimePlanFromContext(tokenSyncRuntimeContext());
}

function expectedTokenSyncContract() {
  return createRuntimeSecurityContract(expectedTokenSyncActivePlan());
}

function expectedTokenSyncContractHash(): string {
  return expectedTokenSyncContract().contractHash ?? "";
}

function expectedTokenSyncComponents() {
  return expectedTokenSyncContract().components;
}

// The startup-provided validation proof a warm launch hands the admin state.
function tokenSyncValidatedRuntime(proxyId = "proxy-id") {
  return {
    components: expectedTokenSyncComponents(),
    contractHash: expectedTokenSyncContractHash(),
    mcpOAuthCallbackPort: mcpOAuthCallbackPort(tmp),
    mcpOAuthCallbackTopologyVersion: 2 as const,
    projectId: projectHash(tmp),
    proofVersion: 4 as const,
    proxyId,
  };
}

function expectedTokenSyncComponentRows(ids: readonly string[], proxyId = "proxy-id"): string {
  const plan = expectedTokenSyncActivePlan();
  return `${ids.map((id) => {
    const service = id === proxyId || id.includes("proxy") ? "proxy" : id.includes("callback") ? "mcp_callback" : "agent";
    return [
      id,
      service,
      "1",
      service === "agent" ? plan.components.selectedAgentImageInputDigest : "<no value>",
      service !== "agent" ? plan.components.proxyImageInputDigest : "<no value>",
      plan.components.topologyDigest,
      "<no value>",
      service === "agent" ? plan.activeRuntime.agentImage : plan.activeRuntime.proxyImage,
      "true",
      plan.projectId,
      plan.composeProjectName,
    ].join("\t");
  }).join("\n")}\n`;
}

function dockerInspectSecurityEvidence(ids?: readonly string[], proxyId = "proxy-id"): string {
  const project = adminProjectInfoForTokenSync();
  const bind = (Destination: string, Source: string, mode: "ro" | "rw") => ({
    Destination,
    Mode: mode,
    RW: mode === "rw",
    Source,
    Type: "bind",
  });
  const entries = [
    {
      Id: "agent-id",
      HostConfig: {},
      Mounts: [
        bind("/runfree/inbox", project.paths.inboxDir, "ro"),
        bind("/runfree/mcp/claude.json", project.paths.claudeMcpConfigPath, "ro"),
        bind("/workspace/.codex", project.paths.projectCodexDirMaskPath, "ro"),
        bind("/etc/proxy-ca", project.paths.proxyCaCertDir, "ro"),
      ],
    },
    {
      Id: proxyId,
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
        bind("/ca/private", project.paths.proxyCaKeyDir, "rw"),
        bind("/ca/public", project.paths.proxyCaCertDir, "rw"),
        bind("/app/runfree-effective", project.paths.controlProxyDir, "ro"),
        bind(
          "/app/proxy/mcp-operation-policy.json",
          project.paths.mcpOperationPolicyPath ?? path.join(project.paths.stateDir, "mcp-operation-policy.json"),
          "ro",
        ),
      ],
    },
  ];
  // Return only the requested containers: post-cutover the security contract is
  // proxy-only, so the token-sync evidence probe inspects just the proxy.
  const selected = ids ? entries.filter((entry) => ids.includes(entry.Id)) : entries;
  return JSON.stringify(selected);
}

function readJsonLines(filePath: string): Array<Record<string, unknown>> {
  if (!fs.existsSync(filePath)) return [];
  return fs.readFileSync(filePath, "utf8").trim().split(/\n+/).filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

function decodeJwtPart(part: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>;
}

function verifyEs256Jwt(jwt: string, publicKeyPem: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const parts = jwt.split(".");
  expect(parts).toHaveLength(3);
  const signature = Buffer.from(parts[2], "base64url");
  expect(signature).toHaveLength(64);
  const verified = crypto.verify(
    "sha256",
    Buffer.from(`${parts[0]}.${parts[1]}`),
    { key: publicKeyPem, dsaEncoding: "ieee-p1363" },
    signature,
  );
  expect(verified).toBe(true);
  return {
    header: decodeJwtPart(parts[0]),
    payload: decodeJwtPart(parts[1]),
  };
}

// `proxyId` and `composeProject` are parameterized for the tests that need the
// live proxy identity to be a real Docker object id (the control-plane rebind
// journal only records 64-hex container ids and `runfree-<projectId>` compose
// projects); every other caller keeps the short stand-ins.
function installTokenSyncDockerFake(options: { composeProject?: string; onMarkerSwap?: () => void; onTokenWrite?: (tokenName: string) => void; proxyId?: string } = {}): { dockerLog: string; fakeBin: string; heldTokens: Set<string> } {
  const proxyId = options.proxyId ?? "proxy-id";
  const onMarkerSwap = options.onMarkerSwap;
  const onTokenWrite = options.onTokenWrite;
  const composeProjectLabel = options.composeProject ?? "fake-project";
  const fakeBin = path.join(tmp, "fake-bin");
  const dockerLog = path.join(tmp, "docker-token-sync.jsonl");
  // Emulated proxy tmpfs token store: token writes/removes over docker exec
  // update this set, and the batched possession listing reads it, so
  // receipt-gated skips and keep-last-good behave like a real proxy.
  const fakeProxySecretStore = new Set<string>();
  // Tmpfs writes seen per token, for FAKE_DOCKER_MARKER_SWAP_ON_WRITE.
  const fakeProxyWriteCounts = new Map<string, number>();
  const validationMarkerJson = JSON.stringify({
    components: expectedTokenSyncComponents(),
    contractHash: expectedTokenSyncContractHash(),
    mcpOAuthCallbackPort: mcpOAuthCallbackPort(tmp),
    mcpOAuthCallbackTopologyVersion: 2,
    proofVersion: 4,
    projectId: projectHash(tmp),
    proxyId,
  });
  fs.mkdirSync(fakeBin, { recursive: true });
  // The credential observation batch runs for real: its script executes in
  // the host's POSIX shell against a scratch tree laid out like the proxy's
  // /run, materialized from this fake's state, so the parser reads exactly
  // the bytes a proxy would emit.
  const fakeCredentialObservationBatch = (script: string, env: NodeJS.ProcessEnv): SpawnSyncReturns<string> => {
    // A transient failure of the exec that lists the held tokens.
    if (env.FAKE_DOCKER_SECRET_LIST_STATUS && script.includes("held-token-names")) {
      return spawnResult({ status: Number(env.FAKE_DOCKER_SECRET_LIST_STATUS), stderr: "transient exec failure\n" });
    }
    if (script.includes("held-token-names") && env.FAKE_DOCKER_RESTART_ON_LISTING_ARM && fs.existsSync(env.FAKE_DOCKER_RESTART_ON_LISTING_ARM)) {
      fs.writeFileSync(`${env.FAKE_DOCKER_RESTART_ON_LISTING_ARM}.restarted`, "");
    }
    if (script.includes("held-token-names") && env.FAKE_DOCKER_REPLACE_ON_LISTING_ARM && fs.existsSync(env.FAKE_DOCKER_REPLACE_ON_LISTING_ARM)) {
      fs.writeFileSync(`${env.FAKE_DOCKER_REPLACE_ON_LISTING_ARM}.replaced`, "");
    }
    if (script.includes("request-proxy-status") && env.FAKE_DOCKER_RESTART_ON_STATUS_ARM && fs.existsSync(env.FAKE_DOCKER_RESTART_ON_STATUS_ARM)) {
      fs.writeFileSync(`${env.FAKE_DOCKER_RESTART_ON_STATUS_ARM}.restarted`, "");
    }
    const root = fs.mkdtempSync(path.join(tmpBase, "fake-proxy-run-"));
    try {
      const at = (absolute: string): string => {
        const file = path.join(root, absolute);
        fs.mkdirSync(path.dirname(file), { recursive: true });
        return file;
      };
      if (env.FAKE_DOCKER_VALIDATION_MARKER !== "missing") {
        // Simulates the proxy's token store being replaced once the trigger
        // file exists (the fake `op` creates its log on first resolution).
        const swapTrigger = env.FAKE_DOCKER_MARKER_SWAP_AFTER ?? env.FAKE_DOCKER_MARKER_SWAP_FLAG;
        fs.writeFileSync(at("/run/runfree-runtime-validation.json"), swapTrigger && fs.existsSync(swapTrigger)
          ? JSON.stringify({ ...JSON.parse(validationMarkerJson), proofVersion: 999 })
          : env.FAKE_DOCKER_VALIDATION_MARKER_JSON ?? validationMarkerJson);
      }
      const generation = env.FAKE_PROXY_STATUS_GENERATION ?? "";
      if (generation) {
        // Effective-control acknowledgement: both consumers name the selected
        // effective policy generation as well as the network policy generation.
        const control = env.FAKE_PROXY_STATUS_CONTROL_GENERATION
          ? { controlGeneration: env.FAKE_PROXY_STATUS_CONTROL_GENERATION, policyGeneration: generation }
          : {};
        fs.writeFileSync(at("/run/runfree-proxy-status/firewall.json"), `${JSON.stringify({ generation, ...control, rulesetVerified: true, appliedAt: "2026-06-18T00:00:00.000Z" })}\n`);
        fs.writeFileSync(at("/run/runfree-proxy-status/request-proxy/request-proxy.json"), `${JSON.stringify({ generation, ...control, appliedAt: "2026-06-18T00:00:00.000Z" })}\n`);
      }
      const secretDir = path.join(root, "run/runfree-proxy-secrets");
      fs.mkdirSync(secretDir, { recursive: true });
      for (const name of fakeProxySecretStore) fs.writeFileSync(path.join(secretDir, name), "fake-held-value");
      const result = childProcess.spawnSync("/bin/sh", ["-c", script.replaceAll("'/run/", `'${root}/run/`)], { encoding: "utf8" });
      // A proxy that answered with a damaged batch, while the arm exists.
      const corrupt = env.FAKE_DOCKER_OBSERVATION_CORRUPT_ARM && fs.existsSync(env.FAKE_DOCKER_OBSERVATION_CORRUPT_ARM)
        ? env.FAKE_DOCKER_OBSERVATION_CORRUPT
        : undefined;
      let stdout = result.stdout;
      if (corrupt === "truncated") stdout = stdout.slice(0, Math.max(0, stdout.length - 12));
      if (corrupt === "duplicate") stdout = stdout.replace(/\nend\n$/, `\n${stdout.split("\n").slice(1, 3).join("\n")}\nend\n`);
      if (corrupt === "missing") stdout = `${stdout.split("\n")[0]}\nend\n`;
      return spawnResult({ status: result.status ?? 1, stdout, stderr: result.stderr });
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  };
  registerFakeCommand(path.join(fakeBin, "docker"), (args, options) => {
    const env = envFromSpawnOptions(options);
    const stdin = spawnInputText(options.input);
    if (env.FAKE_DOCKER_LOG) {
      fs.appendFileSync(env.FAKE_DOCKER_LOG, `${JSON.stringify({
        args,
        env: {
          COMPOSE_PROJECT_NAME: env.COMPOSE_PROJECT_NAME,
          DOCKER_CLI_HINTS: env.DOCKER_CLI_HINTS,
          OP_SERVICE_ACCOUNT_TOKEN: env.OP_SERVICE_ACCOUNT_TOKEN,
          RUNFREE_PROJECT_ROOT: env.RUNFREE_PROJECT_ROOT,
        },
        stdin,
      })}\n`);
    }
    const text = args.join(" ");
    // A proxy replaced after an armed held-token listing: its exact ID no
    // longer names a container.
    if (env.FAKE_DOCKER_REPLACE_ON_LISTING_ARM && fs.existsSync(`${env.FAKE_DOCKER_REPLACE_ON_LISTING_ARM}.replaced`)
      && (args[0] === "exec" || args[0] === "inspect") && args.includes(proxyId)) {
      return spawnResult({ status: 1, stderr: `Error: No such container: ${proxyId}\n` });
    }
    // The proxy's incarnation as Docker reports it now: undefined models a
    // reading that fails (FAKE_DOCKER_STARTED_AT_STATUS).
    const startedAt = (): string | undefined => {
      if (env.FAKE_DOCKER_STARTED_AT_STATUS) return undefined;
      // A proxy restart that lands after an armed held-token listing, or
      // after an armed precheck status-file read.
      if ((env.FAKE_DOCKER_RESTART_ON_LISTING_ARM && fs.existsSync(`${env.FAKE_DOCKER_RESTART_ON_LISTING_ARM}.restarted`))
        || (env.FAKE_DOCKER_RESTART_ON_STATUS_ARM && fs.existsSync(`${env.FAKE_DOCKER_RESTART_ON_STATUS_ARM}.restarted`))) {
        return "2026-06-18T00:00:01.000000000Z";
      }
      return env.FAKE_DOCKER_STARTED_AT ?? "2026-06-18T00:00:00.000000000Z";
    };
    if (args[0] === "info") return spawnResult();
    if (args[0] === "ps") {
      // Per-session runtime: no shared agent or Compose mcp_callback container.
      if (text.includes("com.docker.compose.service=agent")) return spawnResult();
      if (text.includes("com.docker.compose.service=mcp_callback")) return spawnResult();
      // The proxy answers both its own service query and the project-wide
      // listing (composeProject / runtimeContainers): it is the only fixed
      // container after the cutover.
      return spawnResult({ stdout: `${proxyId}\n` });
    }
    if (args[0] === "inspect") {
      if (args[1] === "--format" && text.includes("io.runfree.agent-image-input-digest")) {
        let rows = expectedTokenSyncComponentRows(args.slice(3), proxyId);
        // The incarnation grouped into the component inspect.
        if (text.includes("{{.State.StartedAt}}") && env.FAKE_DOCKER_COMPONENT_ROW_SHAPE !== "without-started-at") {
          rows = rows.replace(/\n/g, `\t${startedAt() ?? ""}\n`);
        }
        return spawnResult({
          stdout: env.FAKE_RUNTIME_COMPONENT_TAMPER === "1"
            // Container labels carry the composite v1 digests; the contract
            // components are control-plane-scoped, so tamper the label digest.
            ? rows.replace(expectedTokenSyncActivePlan().components.topologyDigest, `sha256:${"0".repeat(64)}`)
            : rows,
        });
      }
      if (args[1] === proxyId || (args[1] === "agent-id" && args[2] === proxyId)) {
        return spawnResult({ stdout: dockerInspectSecurityEvidence(args.slice(1), proxyId) });
      }
      if (text.includes(".State.Running") && text.includes(".State.StartedAt")) {
        return spawnResult({ stdout: `true\t${startedAt() ?? ""}\n` });
      }
      if (text.includes(".State.Running")) return spawnResult({ stdout: "true\n" });
      if (text.includes(".State.StartedAt")) {
        const value = startedAt();
        if (value === undefined) {
          return spawnResult({ status: Number(env.FAKE_DOCKER_STARTED_AT_STATUS), stderr: "transient inspect failure\n" });
        }
        return spawnResult({ stdout: `${value}\n` });
      }
      if (text.includes("com.docker.compose.project")) return spawnResult({ stdout: `${composeProjectLabel}\n` });
      return spawnResult();
    }
    if (args[0] !== "exec") return spawnResult();
    if (text.includes(CREDENTIAL_OBSERVATION_BATCH_HEADER)) {
      return fakeCredentialObservationBatch(String(args.at(-1)), env);
    }
    if (text.includes("ls -1 '/run/runfree-proxy-secrets'")) {
      if (env.FAKE_DOCKER_SECRET_LIST_STATUS) {
        return spawnResult({ status: Number(env.FAKE_DOCKER_SECRET_LIST_STATUS), stderr: "transient exec failure\n" });
      }
      if (env.FAKE_DOCKER_RESTART_ON_LISTING_ARM && fs.existsSync(env.FAKE_DOCKER_RESTART_ON_LISTING_ARM)) {
        fs.writeFileSync(`${env.FAKE_DOCKER_RESTART_ON_LISTING_ARM}.restarted`, "");
      }
      const held = Array.from(fakeProxySecretStore).sort();
      return spawnResult({ stdout: held.length > 0 ? `${held.join("\n")}\n` : "" });
    }
    if (text.includes("request-proxy.json")) {
      // A proxy restart that lands after the precheck's policy-acknowledgement
      // status-file read, before the sync's own held-token listing runs.
      if (env.FAKE_DOCKER_RESTART_ON_STATUS_ARM && fs.existsSync(env.FAKE_DOCKER_RESTART_ON_STATUS_ARM)) {
        fs.writeFileSync(`${env.FAKE_DOCKER_RESTART_ON_STATUS_ARM}.restarted`, "");
      }
      const generation = env.FAKE_PROXY_STATUS_GENERATION ?? "";
      if (!generation) return spawnResult({ stdout: "{}\n{}\n" });
      // Effective-control acknowledgement: both consumers name the selected
      // effective policy generation as well as the network policy generation.
      const control = env.FAKE_PROXY_STATUS_CONTROL_GENERATION
        ? { controlGeneration: env.FAKE_PROXY_STATUS_CONTROL_GENERATION, policyGeneration: generation }
        : {};
      return spawnResult({ stdout: `${JSON.stringify({ generation, ...control, rulesetVerified: true, appliedAt: "2026-06-18T00:00:00.000Z" })}\n${JSON.stringify({ generation, ...control, appliedAt: "2026-06-18T00:00:00.000Z" })}\n` });
    }
    {
      const writeMatch = /mv '\/run\/runfree-proxy-secrets\/[^']*' '\/run\/runfree-proxy-secrets\/([^']+)'/.exec(text);
      if (writeMatch && env.FAKE_DOCKER_TOKEN_WRITE_STATUS
        && (!env.FAKE_DOCKER_TOKEN_WRITE_STATUS_TOKEN || env.FAKE_DOCKER_TOKEN_WRITE_STATUS_TOKEN === writeMatch[1])) {
        // A write whose client failed or was killed at its time bound.
        return spawnResult({ status: Number(env.FAKE_DOCKER_TOKEN_WRITE_STATUS), stderr: "token write timed out\n" });
      }
      if (writeMatch) {
        fakeProxySecretStore.add(writeMatch[1]);
        onTokenWrite?.(writeMatch[1]);
        // The remote write landed, but its client was killed (or timed out)
        // before it could report.
        if (env.FAKE_DOCKER_TOKEN_WRITE_KILL === "timeout") return spawnTimeoutResult("docker");
        if (env.FAKE_DOCKER_TOKEN_WRITE_KILL) return spawnResult({ signal: env.FAKE_DOCKER_TOKEN_WRITE_KILL as NodeJS.Signals, status: null });
        const writes = (fakeProxyWriteCounts.get(writeMatch[1]) ?? 0) + 1;
        fakeProxyWriteCounts.set(writeMatch[1], writes);
        // Simulates the proxy's token store being replaced right after the
        // Nth write of the named token (default: its first write).
        if (env.FAKE_DOCKER_MARKER_SWAP_FLAG && writeMatch[1] === env.FAKE_DOCKER_MARKER_SWAP_ON_WRITE
          && writes === Number(env.FAKE_DOCKER_MARKER_SWAP_ON_WRITE_COUNT ?? "1")) {
          onMarkerSwap?.();
          fs.writeFileSync(env.FAKE_DOCKER_MARKER_SWAP_FLAG, "");
        }
      }
      const removeMatch = /rm -f '\/run\/runfree-proxy-secrets\/([^']+)' '\/run\/runfree-proxy-secrets\/[^']*'/.exec(text);
      if (removeMatch) fakeProxySecretStore.delete(removeMatch[1]);
    }
    if (text.includes("runfree_security_contract_probe")) {
      if (args.includes("agent-id")) {
        return spawnResult({ stdout: `${[
          "mount\t/workspace\t0\t/workspace\text4\trw,relatime",
          "mount\t/runfree/inbox\t0\t/runfree/inbox\text4\tro,relatime",
          "mount\t/runfree/mcp/claude.json\t0\t/runfree/mcp/claude.json\text4\tro,relatime",
          "mount\t/workspace/.codex\t0\t/workspace/.codex\text4\tro,relatime",
          "mount\t/etc/proxy-ca\t0\t/etc/proxy-ca\text4\tro,relatime",
          "content\t/runfree/mcp/claude.json\t0\td8e397af03b5b032f21d0aa967086f0c78b33c87b76f2e9898ae0a144df7de02",
          "directory\t/workspace/.codex\t0\t1",
          "absence\t/ca/private/proxy-ca.key\t0",
        ].join("\n")}\n` });
      }
      if (args.includes(proxyId)) {
        return spawnResult({ stdout: `${[
          "mount\t/ca/private\t0\t/ca/private\text4\trw,relatime",
          "mount\t/ca/public\t0\t/ca/public\text4\trw,relatime",
          "mount\t/app/runfree-effective\t0\t/app/runfree-effective\text4\tro,relatime",
          "mount\t/app/proxy/mcp-operation-policy.json\t0\t/app/proxy/mcp-operation-policy.json\text4\tro,relatime",
          "mount\t/run/runfree-proxy-secrets\t0\t/run/runfree-proxy-secrets\ttmpfs\trw,nosuid,nodev,noexec,relatime",
          "mount\t/run/runfree-proxy-audit\t0\t/run/runfree-proxy-audit\ttmpfs\trw,nosuid,nodev,noexec,relatime",
          "mount\t/run/runfree-proxy-audit-spool\t0\t/run/runfree-proxy-audit-spool\ttmpfs\trw,nosuid,nodev,noexec,relatime",
          "mount\t/run/runfree-proxy-status\t0\t/run/runfree-proxy-status\ttmpfs\trw,nosuid,nodev,noexec,relatime",
          "mount\t/run/runfree-sessions\t0\t/run/runfree-sessions\ttmpfs\trw,nosuid,nodev,noexec,relatime",
          "mount\t/run/runfree-approvals/pending\t0\t/run/runfree-approvals/pending\ttmpfs\trw,nosuid,nodev,noexec,relatime",
          "mount\t/run/runfree-approvals/decisions\t0\t/run/runfree-approvals/decisions\ttmpfs\trw,nosuid,nodev,noexec,relatime",
          "stat\t/run/runfree-proxy-secrets\t0\t1001:1001:700",
          "stat\t/run/runfree-proxy-audit\t0\t0:0:755",
          "stat\t/run/runfree-proxy-audit-spool\t0\t1001:1001:755",
          "stat\t/run/runfree-proxy-status\t0\t0:0:755",
          "stat\t/run/runfree-proxy-status/request-proxy\t0\t1001:1001:755",
          "stat\t/run/runfree-sessions\t0\t0:0:755",
          "stat\t/run/runfree-sessions/sessions\t0\t0:0:755",
          "stat\t/run/runfree-approvals/pending\t0\t1001:1001:700",
          "stat\t/run/runfree-approvals/decisions\t0\t0:0:755",
        ].join("\n")}\n` });
      }
    }
    if (text.includes("cat /run/runfree-runtime-validation.json")) {
      if (env.FAKE_DOCKER_VALIDATION_MARKER === "missing") {
        return spawnResult({ status: 1, stderr: "missing runtime validation marker\n" });
      }
      // Simulates the proxy's token store being replaced once the trigger file
      // exists (the fake `op` creates its log on first resolution).
      const swapTrigger = env.FAKE_DOCKER_MARKER_SWAP_AFTER ?? env.FAKE_DOCKER_MARKER_SWAP_FLAG;
      if (swapTrigger && fs.existsSync(swapTrigger)) {
        return spawnResult({ stdout: JSON.stringify({ ...JSON.parse(validationMarkerJson), proofVersion: 999 }) });
      }
      return spawnResult({ stdout: env.FAKE_DOCKER_VALIDATION_MARKER_JSON ?? validationMarkerJson });
    }
    if (env.FAKE_DOCKER_EXEC_STATUS) {
      return spawnResult({
        status: Number(env.FAKE_DOCKER_EXEC_STATUS),
        stderr: env.FAKE_DOCKER_EXEC_STDERR ?? "",
      });
    }
    return spawnResult();
  });
  return { dockerLog, fakeBin, heldTokens: fakeProxySecretStore };
}

function installFakeOp(fakeBin: string, options: { exitCode?: number; logPath?: string; output?: string; stderr?: string } = {}): void {
  registerFakeCommand(path.join(fakeBin, "op"), (args, spawnOptions) => {
    if (options.logPath !== undefined) fs.appendFileSync(options.logPath, `${JSON.stringify({ args })}\n`);
    const env = envFromSpawnOptions(spawnOptions);
    if (args[0] !== "read") return spawnResult({ status: 2 });
    if (!env.HOME || !env.OP_SERVICE_ACCOUNT_TOKEN) return spawnResult({ status: 3 });
    if (options.exitCode !== undefined) {
      return spawnResult({ status: options.exitCode, stderr: options.stderr ?? "" });
    }
    return spawnResult({ stderr: options.stderr ?? "", stdout: options.output ?? "onepassword-secret\n" });
  });
}

function installFakeDocumentOp(fakeBin: string, options: { documentOutput: string; logPath: string }): void {
  registerFakeCommand(path.join(fakeBin, "op"), (args, spawnOptions) => {
    fs.appendFileSync(options.logPath, `${JSON.stringify({ args })}\n`);
    const env = envFromSpawnOptions(spawnOptions);
    if (!env.HOME || !env.OP_SERVICE_ACCOUNT_TOKEN) return spawnResult({ status: 3 });
    if (args[0] === "read") {
      return spawnResult({ status: 1, stderr: "not a field secret reference\n" });
    }
    if (args[0] === "document" && args[1] === "get" && args[2] === "AuthKey_KEY123" && args[3] === "--vault" && args[4] === "Private") {
      return spawnResult({ stdout: options.documentOutput });
    }
    return spawnResult({ status: 2, stderr: `unexpected op args: ${args.join(" ")}\n` });
  });
}

async function configureAppStoreJwtFixture(options: { refreshEvery?: string } = {}): Promise<{
  fakeDocker: { dockerLog: string; fakeBin: string };
  hostOpBin: string;
  opLogPath: string;
  privateKeyPem: string;
  publicKeyPem: string;
}> {
  writeFixtureRepo({
    hosts: ["api.appstoreconnect.apple.com"],
    tokens: {
      "appstore-connect": {
        description: "App Store Connect token",
        credentials: [
          { host: "api.appstoreconnect.apple.com", header: "Authorization", scheme: "bearer" },
        ],
      },
    },
  });
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const fakeDocker = installTokenSyncDockerFake();
  const hostOpBin = path.join(tmpBase, `appstore-op-${Math.random().toString(16).slice(2)}`);
  const opLogPath = path.join(tmpBase, `appstore-op-${Math.random().toString(16).slice(2)}.jsonl`);
  fs.mkdirSync(hostOpBin);
  installFakeDocumentOp(hostOpBin, {
    documentOutput: privateKeyPem,
    logPath: opLogPath,
  });

  const add = await runAdmin(() => sourceAddJwtIntent({
    name: "appstore-connect-jwt",
    replaceSource: false,
    alg: "ES256",
    privateKeyRef: "op://Private/AuthKey_KEY123",
    ttl: "19m",
    claims: ["iss=ISSUER123", "aud=appstoreconnect-v1"],
    headers: ["kid=KEY123"],
  }), {
    OP_SERVICE_ACCOUNT_TOKEN: "op-session",
    PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
  });
  expect(add.status, add.stderr).toBe(0);

  const bind = await runAdmin(() => credentialSetSourceIntent({
    name: "appstore-connect",
    tokenSource: { kind: "named", name: "appstore-connect-jwt" },
    refreshEvery: options.refreshEvery,
    replaceSource: false,
    sync: false,
  }));
  expect(bind.status, bind.stderr).toBe(0);

  return { fakeDocker, hostOpBin, opLogPath, privateKeyPem, publicKeyPem };
}

function installFakeCommandSource(options: {
  block?: boolean;
  exitCode?: number;
  name?: string;
  output?: string;
  stderr?: string;
  directory?: string;
} = {}): { commandPath: string; fakeBin: string; logPath: string } {
  const fakeBin = options.directory ?? path.join(tmpBase, "host-bin");
  const commandName = options.name ?? "gh";
  const commandPath = path.join(fakeBin, commandName);
  const logPath = path.join(tmpBase, `${commandName}-source-log.jsonl`);
  fs.mkdirSync(fakeBin, { recursive: true });
  registerFakeCommand(commandPath, (args, spawnOptions, realPath) => {
    const env = envFromSpawnOptions(spawnOptions);
    const cwd = typeof spawnOptions.cwd === "string" ? fs.realpathSync(spawnOptions.cwd) : String(spawnOptions.cwd ?? process.cwd());
    fs.appendFileSync(logPath, `${JSON.stringify({
      argv: [realPath, ...args],
      cwd,
      env: {
        BUN_OPTIONS: env.BUN_OPTIONS,
        HOME: env.HOME,
        HTTPS_PROXY: env.HTTPS_PROXY,
        INIT_CWD: env.INIT_CWD,
        NODE_OPTIONS: env.NODE_OPTIONS,
        OLDPWD: env.OLDPWD,
        PATH: env.PATH,
        PWD: env.PWD,
        RUNFREE_PACKAGE_ROOT: env.RUNFREE_PACKAGE_ROOT,
        RUNFREE_PROJECT_ROOT: env.RUNFREE_PROJECT_ROOT,
      },
    })}\n`);
    if (options.block) return spawnTimeoutResult(commandName);
    if (options.exitCode !== undefined) {
      return spawnResult({ status: options.exitCode, stderr: options.stderr ?? "" });
    }
    return spawnResult({ stderr: options.stderr ?? "", stdout: options.output ?? "command-secret\n" });
  });
  return { commandPath, fakeBin, logPath };
}

function sourceRegistryPath(): string {
  return path.join(home, ".config/runfree/sources.json");
}

function rewriteFakeCommandSource(commandPath: string, options: { block?: boolean; exitCode?: number; output?: string } = {}): void {
  registerFakeCommand(commandPath, () => {
    if (options.block) return spawnTimeoutResult(path.basename(commandPath));
    if (options.exitCode !== undefined) return spawnResult({ status: options.exitCode });
    return spawnResult({ stdout: options.output ?? "command-secret\n" });
  });
}

function readCommandSourceLog(logPath: string): Array<Record<string, unknown>> {
  return readJsonLines(logPath);
}

function dockerExecCalls(logPath: string): Array<Record<string, unknown>> {
  return readJsonLines(logPath)
    .filter((entry) => {
      if (!Array.isArray(entry.args) || entry.args[0] !== "exec") return false;
      const args = entry.args.join(" ");
      return !args.includes("/run/runfree-runtime-validation.json")
        && !args.includes("/ca/private/proxy-ca.key")
        && !args.includes("runfree_security_contract_probe")
        // Possession listing and generation status reads are sync bookkeeping,
        // not token traffic.
        && !args.includes(CREDENTIAL_OBSERVATION_BATCH_HEADER)
        && !args.includes("ls -1 '/run/runfree-proxy-secrets'")
        && !args.includes("request-proxy.json");
    });
}

function proxyTokenRemovalIndexes(logPath: string, tokenName?: string): number[] {
  return readJsonLines(logPath).flatMap((entry, index) => {
    if (!Array.isArray(entry.args) || entry.args[0] !== "exec") return [];
    const script = String(entry.args.at(-1));
    const removes = tokenName === undefined
      ? script.includes("rm -f '/run/runfree-proxy-secrets/")
      : script.includes(`rm -f '/run/runfree-proxy-secrets/${tokenName}'`);
    return removes ? [index] : [];
  });
}

function proxyTokenWriteIndexes(logPath: string, tokenName: string): number[] {
  return readJsonLines(logPath).flatMap((entry, index) => Array.isArray(entry.args) && entry.args[0] === "exec"
    && String(entry.args.at(-1)).includes(`'/run/runfree-proxy-secrets/${tokenName}'`)
    && String(entry.args.at(-1)).includes("mv '/run/runfree-proxy-secrets/") ? [index] : []);
}

function tokenReceiptsFilePath(): string {
  return path.join(adminStateDir(), `token-resolution-receipts-${projectHash(tmp)}.json`);
}

function tokenStatusFilePath(): string {
  return path.join(adminStateDir(), "token-sync-status.json");
}

function exampleTokenPolicy(names: string[]): { hosts: string[]; tokens: Record<string, unknown> } {
  return {
    hosts: names.map((name) => `${name}.example.com`),
    tokens: Object.fromEntries(names.map((name) => [name, {
      description: `${name} token`,
      credentials: [{ host: `${name}.example.com`, header: "Authorization", scheme: "bearer" }],
    }])),
  };
}

function expectProxyTokenRemoval(logPath: string, tokenName = "github"): void {
  expect(dockerExecCalls(logPath).some((entry) => {
    const args = entry.args as string[];
    return args.includes("sh")
      && args.includes("-c")
      && String(args.at(-1)).includes(`rm -f '/run/runfree-proxy-secrets/${tokenName}'`);
  })).toBe(true);
}

beforeEach(() => {
  fakeCommandHandlers.clear();
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "agent-admin-tests-"));
  tmp = path.join(tmpBase, "project");
  home = path.join(tmpBase, "home");
  fs.mkdirSync(tmp, { recursive: true });
  fs.mkdirSync(home, { recursive: true });
});

afterEach(() => {
  fs.rmSync(tmpBase, { recursive: true, force: true });
});

describe("admin credential policy commands", () => {

  test("admin mutating commands reject unknown flags before writing state", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    const initialPolicy = fs.readFileSync(path.join(tmp, ".runfree/network-policy.json"), "utf8");
    const fakeSource = installFakeCommandSource();

    // Parser-level rejection of mistyped flags lives in the yargs strict parser,
    // not in any typed intent, so these run through the typed CLI subprocess.
    const domainAdd = runAdminCli(["host", "add", "raw.githubusercontent.com", "--no-relod"]);
    const tokenSet = runAdminCli(["credential", "set-source", "github", "--from-soruce", "github-cli"]);
    const sourceAdd = runAdminCli(["credential", "source", "add", "github-cli", "--replcae-source", "--", "gh", "auth", "token"], {
      extraEnv: { PATH: fakeSource.fakeBin },
    });
    // Conflicting credential sources are a parser-level rejection too (not an unknown
    // flag); it must also fail before any service revision / policy / credential
    // write. Spec security-regression example: `service enable github --from-env A
    // --from-source B`.
    const serviceConflict = runAdminCli(["service", "enable", "github", "--from-env", "A", "--from-source", "B"]);

    expect(domainAdd.status).not.toBe(0);
    expect(domainAdd.stderr).toContain("Unknown argument: no-relod");
    expect(tokenSet.status).not.toBe(0);
    expect(tokenSet.stderr).toContain("Unknown argument: from-soruce");
    expect(sourceAdd.status).not.toBe(0);
    expect(sourceAdd.stderr).toContain("Unknown arguments: replcae-source, replcaeSource");
    expect(serviceConflict.status).not.toBe(0);
    expect(serviceConflict.stderr).toContain("choose only one credential source");
    expect(fs.readFileSync(path.join(tmp, ".runfree/network-policy.json"), "utf8")).toBe(initialPolicy);
    expect(fs.existsSync(tokenConfigPath())).toBe(false);
    expect(fs.existsSync(sourceRegistryPath())).toBe(false);
    expect(readCommandSourceLog(fakeSource.logPath)).toHaveLength(0);
  });

  test("policy convergence without docker reports it and applies on next runfree", async () => {
    writeFixtureRepo({
      hosts: ["registry.npmjs.org"],
      tokens: {},
    });
    const emptyPath = path.join(tmp, "empty-bin");
    fs.mkdirSync(emptyPath);

    const converge = await runAdmin(() => convergeProxyPolicy(), { PATH: emptyPath });
    expect(converge.status, converge.stderr).toBe(0);
    expect(converge.stdout).toContain("proxy not inspected: docker unavailable");
  });

  test("policy mutation converges the running proxy without restarting the container", async () => {
    writeFixtureRepo({
      hosts: ["registry.npmjs.org"],
      tokens: {},
    });
    fs.mkdirSync(path.join(tmp, "dist/runtime/agent"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "dist/runtime/agent/compose.yaml"), "services: {}\n");

    // The generation the mutated policy will hash to — the fake proxy reports
    // it from both level-triggered status files (firewall ruleset verified).
    const expectedGeneration = validateNetworkPolicy({ hosts: ["registry.npmjs.org"], tokens: {} }).generation;
    const fakeBin = path.join(tmp, "fake-bin");
    const envLog = path.join(tmp, "docker-env.log");
    fs.mkdirSync(fakeBin);
    fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/sh
printf '%s|%s|%s|%s\\n' "$1" "$RUNFREE_CLAUDE_DIR" "$RUNFREE_CLAUDE_JSON" "$DOCKER_CLI_HINTS" >> "${envLog}"
case "$1" in
  info) exit 0 ;;
  ps)
    if [ "$2" = "--all" ] && [ "$3" = "--quiet" ]; then
      case "$*" in
        *com.docker.compose.service=proxy*) echo proxy-id ;;
        *) echo agent-id ;;
      esac
    fi
    exit 0
    ;;
  inspect)
    case "$*" in
      *State.Running*) echo true ;;
      *com.docker.compose.project*) echo fake-project ;;
    esac
    exit 0
    ;;
  container)
    case "$2" in
      restart|start) exit 1 ;;
    esac
    exit 0
    ;;
  exec)
    case "$*" in
      *request-proxy.json*)
        printf '%s\\n' '{"generation":"${expectedGeneration}","rulesetVerified":true,"appliedAt":"2026-06-18T00:00:00.000Z"}'
        printf '%s\\n' '{"generation":"${expectedGeneration}","appliedAt":"2026-06-18T00:00:00.000Z"}'
        ;;
    esac
    exit 0
    ;;
esac
exit 0
`);
    fs.chmodSync(path.join(fakeBin, "docker"), 0o755);

    const result = await runAdmin(() => convergeProxyPolicy(), {
      PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_CLAUDE_DIR: path.join(tmp, "state/claude"),
      RUNFREE_CLAUDE_JSON: path.join(tmp, "state/claude.json"),
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("proxy policy converged (no restart)");
    const log = fs.readFileSync(envLog, "utf8");
    expect(log).not.toContain("restart|");
    expect(log).not.toContain("start|");
    expect(log).toContain("exec|||false");
    expect(log).not.toContain(path.join(tmp, "state/claude"));
    expect(log).not.toContain("compose|");
  });

  test("policy mutation falls back to a loud proxy restart when a validated proxy never acknowledges", async () => {
    writeFixtureRepo({
      hosts: ["registry.npmjs.org"],
      tokens: {},
    });
    fs.mkdirSync(path.join(tmp, "dist/runtime/agent"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "dist/runtime/agent/compose.yaml"), "services: {}\n");
    const fakeDocker = installTokenSyncDockerFake();

    // The status files answer with a generation that never matches the
    // mutation, so the ack times out; runtime validation itself passes, so
    // the loud restart fallback engages (and readiness still comes from the
    // parseable status file, not a log scrape).
    const result = await runAdmin(() => convergeProxyPolicy(), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      FAKE_PROXY_STATUS_GENERATION: "sha256:never-the-expected-generation",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_CONVERGE_ACK_TIMEOUT_MS: "50",
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toContain("falling back to a proxy restart");
    expect(result.stderr).toContain("source prompts (e.g. 1Password) may reappear");
    expect(result.stdout).toContain("proxy reload: done");
    expect(readJsonLines(fakeDocker.dockerLog).some((entry) => Array.isArray(entry.args) && entry.args[0] === "container" && entry.args[1] === "restart")).toBe(true);
  });

  test("policy mutation refuses the restart fallback when the runtime needs revalidation", async () => {
    writeFixtureRepo({
      hosts: ["registry.npmjs.org"],
      tokens: {},
    });
    fs.mkdirSync(path.join(tmp, "dist/runtime/agent"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "dist/runtime/agent/compose.yaml"), "services: {}\n");
    const fakeDocker = installTokenSyncDockerFake();

    // A runtime whose validation marker is unreadable (e.g. a proxy image
    // from before this CLI version, which also never writes the status
    // files): restarting it would wipe the token store and then fail
    // readiness for nothing — the command must point at `runfree up` instead.
    const result = await runAdmin(() => convergeProxyPolicy(), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      FAKE_DOCKER_VALIDATION_MARKER: "missing",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_CONVERGE_ACK_TIMEOUT_MS: "50",
    });

    expect(result.stderr).toContain("did not acknowledge policy generation");
    expect(result.stderr).toContain("run `runfree up`");
    expect(result.stderr).toContain("a proxy restart cannot revalidate this runtime");
    expect(readJsonLines(fakeDocker.dockerLog).some((entry) => Array.isArray(entry.args) && entry.args[0] === "container" && entry.args[1] === "restart")).toBe(false);
  });

  test("source add stores canonical command metadata outside the project without storing stdout", async () => {
    writeFixtureRepo({
      hosts: [],
      tokens: {},
    });
    const fakeSource = installFakeCommandSource();

    const add = await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["gh", "auth", "token"],
    }), {
      BUN_OPTIONS: "--inspect",
      HTTPS_PROXY: "http://attacker-proxy.invalid",
      INIT_CWD: tmp,
      NODE_OPTIONS: "--trace-warnings",
      OLDPWD: tmp,
      PATH: `${fakeSource.fakeBin}${path.delimiter}${path.join(tmp, "node_modules/.bin")}`,
      PWD: tmp,
      RUNFREE_PROJECT_ROOT: tmp,
    });

    expect(add.status, add.stderr).toBe(0);
    expect(add.stdout).toContain("github-cli source configured");
    expect(add.stdout).not.toContain("command-secret");
    expect(JSON.stringify(readSourceRegistry())).toEqual(expect.stringContaining(fs.realpathSync(fakeSource.commandPath)));
    expect(JSON.stringify(readSourceRegistry())).toContain("\"displayArgv\":[\"gh\",\"auth\",\"token\"]");
    expect(JSON.stringify(readSourceRegistry())).not.toContain("command-secret");
    expect(fs.existsSync(path.join(tmp, ".runfree/config/sources.json"))).toBe(false);

    const show = await runAdmin(() => sourceShowIntent({ name: "github-cli" }));
    const list = await runAdmin(() => sourceList());
    expect(show.status, show.stderr).toBe(0);
    expect(show.stdout).toContain("github-cli: configured");
    expect(show.stdout).toContain("command: gh auth token");
    expect(show.stdout).toContain("agent exposure: no");
    expect(show.stdout).not.toContain("command-secret");
    expect(list.status, list.stderr).toBe(0);
    expect(list.stdout.trim()).toBe("github-cli");
    expect(readCommandSourceLog(fakeSource.logPath)).toHaveLength(1);
  });

  test("source add refuses replacement unless explicitly requested", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    const firstSource = installFakeCommandSource({ name: "gh", output: "first-secret\n" });
    const first = await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["gh", "auth", "token"],
    }), {
      PATH: firstSource.fakeBin,
    });
    const bind = await runAdmin(() => credentialSetSourceIntent({
      name: "github",
      tokenSource: { kind: "named", name: "github-cli" },
      replaceSource: false,
      sync: false,
    }));
    const secondSource = installFakeCommandSource({ name: "gh2", output: "second-secret\n" });

    const refused = await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["gh2", "auth", "token"],
    }), {
      PATH: secondSource.fakeBin,
    });
    const unchanged = JSON.stringify(readSourceRegistry());
    const refusedLogLength = readCommandSourceLog(secondSource.logPath).length;
    const allowed = await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: true,
      command: ["gh2", "auth", "token"],
    }), {
      PATH: secondSource.fakeBin,
    });
    const identical = await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["gh2", "auth", "token"],
    }), {
      PATH: secondSource.fakeBin,
    });

    expect(first.status, first.stderr).toBe(0);
    expect(bind.status, bind.stderr).toBe(0);
    expect(refused.status).not.toBe(0);
    expect(refused.stderr).toContain("github-cli source is already configured");
    expect(refused.stderr).toContain("--replace-source");
    expect(refused.stderr).toContain("used by credential bindings: github");
    expect(unchanged).toContain(fs.realpathSync(firstSource.commandPath));
    expect(refusedLogLength).toBe(0);
    expect(allowed.status, allowed.stderr).toBe(0);
    expect(allowed.stdout).toContain("github-cli source replaced");
    expect(JSON.stringify(readSourceRegistry())).toContain(fs.realpathSync(secondSource.commandPath));
    expect(identical.status, identical.stderr).toBe(0);
    expect(identical.stdout).toContain("github-cli source unchanged");
  });

  test("source add rejects project-controlled executables without executing them", async () => {
    writeFixtureRepo({
      hosts: [],
      tokens: {},
    });
    const projectBin = path.join(tmp, "node_modules/.bin");
    const fakeSource = installFakeCommandSource({ directory: projectBin });

    const result = await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["gh", "auth", "token"],
    }), {
      PATH: projectBin,
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("gh executable was not found on the sanitized host PATH");
    expect(readCommandSourceLog(fakeSource.logPath)).toHaveLength(0);
    expect(fs.existsSync(path.join(home, ".config/runfree/sources.json"))).toBe(false);
  });

  test("source add rejects invalid syntax, timeout, and symlinked project executables", async () => {
    writeFixtureRepo({
      hosts: [],
      tokens: {},
    });
    const hostSource = installFakeCommandSource({ name: "slow-gh", block: true });
    // Missing name and missing `--` separator are yargs-grammar errors (the `--`
    // split assigns positionals); no typed intent models the argv shape, so these
    // two run through the typed CLI subprocess.
    const missingName = runAdminCli(["credential", "source", "add", "--", "gh"], {
      extraEnv: { PATH: hostSource.fakeBin },
    });
    expect(missingName.status).not.toBe(0);
    expect(missingName.stderr).toContain("runfree credential source add");

    const missingSeparator = runAdminCli(["credential", "source", "add", "github-cli", "gh"], {
      extraEnv: { PATH: hostSource.fakeBin },
    });
    expect(missingSeparator.status).not.toBe(0);
    expect(missingSeparator.stderr).toContain("unexpected credential source add argument before --: gh");

    const emptyArgv = await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: [],
    }), {
      PATH: hostSource.fakeBin,
    });
    expect(emptyArgv.status).not.toBe(0);
    expect(emptyArgv.stderr).toContain("credential source add requires a command");

    const timeout = await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["slow-gh"],
    }), {
      PATH: hostSource.fakeBin,
      RUNFREE_TEST_COMMAND_SOURCE_TIMEOUT_MS: "20",
    });
    expect(timeout.status).not.toBe(0);
    expect(timeout.stderr).toContain("command source timed out");

    const argSource = installFakeCommandSource({ name: "arg-gh" });
    const projectArg = await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["arg-gh", path.join(tmp, "script.js")],
    }), {
      PATH: argSource.fakeBin,
    });
    expect(projectArg.status).not.toBe(0);
    expect(projectArg.stderr).toContain("source command argument must not reference project-controlled path");
    expect(readCommandSourceLog(argSource.logPath)).toHaveLength(0);

    const runfreeBin = path.join(tmp, ".runfree/bin");
    const projectSource = installFakeCommandSource({ directory: runfreeBin, name: "gh" });
    const hostSymlinkDir = path.join(tmpBase, "host-symlinks");
    fs.mkdirSync(hostSymlinkDir);
    fs.symlinkSync(projectSource.commandPath, path.join(hostSymlinkDir, "gh"));

    const symlinkResult = await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["gh"],
    }), {
      PATH: hostSymlinkDir,
    });

    expect(symlinkResult.status).not.toBe(0);
    expect(symlinkResult.stderr).toContain("gh executable was not found on the sanitized host PATH");
    expect(readCommandSourceLog(projectSource.logPath)).toHaveLength(0);
    expect(fs.existsSync(sourceRegistryPath())).toBe(false);
  });

  test("source add rejects nonzero and empty command output without storing metadata", async () => {
    writeFixtureRepo({
      hosts: [],
      tokens: {},
    });
    const leakedToken = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
    const nonzero = installFakeCommandSource({ name: "bad-gh", exitCode: 7, stderr: `not logged in ${leakedToken}\nsecond line\n` });
    const nonzeroResult = await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["bad-gh", "auth", "token"],
    }), {
      PATH: nonzero.fakeBin,
    });
    expect(nonzeroResult.status).not.toBe(0);
    expect(nonzeroResult.stderr).toContain("command source exited nonzero: bad-gh status 7: not logged in [redacted]");
    expect(nonzeroResult.stderr).not.toContain(leakedToken);
    expect(nonzeroResult.stderr).not.toContain("command-secret");

    const empty = installFakeCommandSource({ name: "empty-gh", output: "\n" });
    const emptyResult = await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["empty-gh", "auth", "token"],
    }), {
      PATH: empty.fakeBin,
    });
    expect(emptyResult.status).not.toBe(0);
    expect(emptyResult.stderr).toContain("command source returned an empty value");
    expect(fs.existsSync(path.join(home, ".config/runfree/sources.json"))).toBe(false);
  });

  test("token set can bind a token to a host-owned named command source", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    const fakeSource = installFakeCommandSource();
    const add = await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["gh", "auth", "token"],
    }), {
      PATH: fakeSource.fakeBin,
    });
    expect(add.status, add.stderr).toBe(0);

    const missing = await runAdmin(() => credentialSetSourceIntent({
      name: "github",
      tokenSource: { kind: "named", name: "missing-cli" },
      replaceSource: false,
      sync: false,
    }));
    expect(missing.status).not.toBe(0);
    expect(missing.stderr).toContain("unknown source: missing-cli");
    expect(fs.existsSync(tokenConfigPath())).toBe(false);

    const configured = await runAdmin(() => credentialSetSourceIntent({
      name: "github",
      tokenSource: { kind: "named", name: "github-cli" },
      replaceSource: false,
      sync: false,
    }));
    expect(configured.status, configured.stderr).toBe(0);
    expect(configured.stdout).toContain("github credential configured");
    expect(configured.stdout).toContain("source: source github-cli");
    expect(readTokenConfig()).toEqual({
      github: { source: "named", name: "github-cli" },
    });
    expect(fs.existsSync(path.join(tmp, ".runfree/config/tokens.json"))).toBe(false);
  });

  test("jwt sources sign short-lived bearer tokens from a 1Password private key without storing the key", async () => {
    writeFixtureRepo({
      hosts: ["api.appstoreconnect.apple.com"],
      tokens: {
        "appstore-connect": {
          description: "App Store Connect token",
          credentials: [
            { host: "api.appstoreconnect.apple.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
    const fakeDocker = installTokenSyncDockerFake();
    const hostOpBin = path.join(tmpBase, "host-op-bin");
    fs.mkdirSync(hostOpBin);
    installFakeOp(hostOpBin, { output: privateKeyPem });

    const add = await runAdmin(() => sourceAddJwtIntent({
      name: "appstore-connect-jwt",
      replaceSource: false,
      alg: "ES256",
      privateKeyRef: "op://Private/AppStoreConnect/AuthKey",
      ttl: "19m",
      claims: ["iss=ISSUER123", "aud=appstoreconnect-v1"],
      headers: ["kid=KEY123"],
    }), {
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(add.status, add.stderr).toBe(0);
    expect(add.stdout).toContain("appstore-connect-jwt source configured");
    expect(add.stdout).toContain("type: jwt");
    expect(add.stdout).not.toContain(privateKeyPem.trim());
    expect(JSON.stringify(readSourceRegistry())).toEqual(expect.stringContaining("\"type\":\"jwt\""));
    expect(JSON.stringify(readSourceRegistry())).toContain("\"privateKey\":{\"source\":\"1password\",\"ref\":\"op://Private/AppStoreConnect/AuthKey\"}");
    expect(JSON.stringify(readSourceRegistry())).not.toContain(privateKeyPem.trim());

    const bind = await runAdmin(() => credentialSetSourceIntent({
      name: "appstore-connect",
      tokenSource: { kind: "named", name: "appstore-connect-jwt" },
      refreshEvery: "18m",
      replaceSource: false,
      sync: false,
    }));
    expect(bind.status, bind.stderr).toBe(0);
    expect(bind.stdout).toContain("refresh: every 18m");
    expect(readTokenConfig()).toEqual({
      "appstore-connect": {
        source: "named",
        name: "appstore-connect-jwt",
        refreshEverySeconds: 1080,
      },
    });

    const sync = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(sync.status, sync.stderr).toBe(0);
    expect(sync.stdout).toContain("appstore-connect: synced to proxy tmpfs from source appstore-connect-jwt");
    expect(sync.stdout).not.toContain(privateKeyPem.trim());
    expect(sync.stderr).not.toContain(privateKeyPem.trim());

    const execCalls = dockerExecCalls(fakeDocker.dockerLog);
    expect(execCalls).toHaveLength(1);
    const jwt = String(execCalls[0].stdin);
    const { header, payload } = verifyEs256Jwt(jwt, publicKeyPem);
    expect(header).toMatchObject({ alg: "ES256", kid: "KEY123", typ: "JWT" });
    expect(payload).toMatchObject({
      aud: "appstoreconnect-v1",
      iss: "ISSUER123",
    });
    expect(typeof payload.iat).toBe("number");
    expect(typeof payload.exp).toBe("number");
    expect((payload.exp as number) - (payload.iat as number)).toBe(19 * 60);
    expect(JSON.stringify(readTokenStatus())).not.toContain(jwt);
    expect(JSON.stringify(readTokenStatus())).not.toContain(privateKeyPem.trim());
  });

  test("jwt sources can read a 1Password document item private key", async () => {
    writeFixtureRepo({
      hosts: ["api.appstoreconnect.apple.com"],
      tokens: {
        "appstore-connect": {
          description: "App Store Connect token",
          credentials: [
            { host: "api.appstoreconnect.apple.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
    const fakeDocker = installTokenSyncDockerFake();
    const hostOpBin = path.join(tmpBase, "host-document-op-bin");
    const opLogPath = path.join(tmpBase, "document-op-log.jsonl");
    fs.mkdirSync(hostOpBin);
    installFakeDocumentOp(hostOpBin, {
      documentOutput: privateKeyPem,
      logPath: opLogPath,
    });

    const add = await runAdmin(() => sourceAddJwtIntent({
      name: "appstore-connect-jwt",
      replaceSource: false,
      alg: "ES256",
      privateKeyRef: "op://Private/AuthKey_KEY123",
      ttl: "19m",
      claims: ["iss=ISSUER123", "aud=appstoreconnect-v1"],
      headers: ["kid=KEY123"],
    }), {
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(add.status, add.stderr).toBe(0);
    expect(JSON.stringify(readSourceRegistry())).toContain("\"ref\":\"op://Private/AuthKey_KEY123\"");
    writeTokenConfig({
      "appstore-connect": { source: "named", name: "appstore-connect-jwt" },
    });

    const sync = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(sync.status, sync.stderr).toBe(0);
    const opCalls = readJsonLines(opLogPath);
    expect(opCalls).toEqual([
      { args: ["read", "op://Private/AuthKey_KEY123"] },
      { args: ["document", "get", "AuthKey_KEY123", "--vault", "Private"] },
      { args: ["read", "op://Private/AuthKey_KEY123"] },
      { args: ["document", "get", "AuthKey_KEY123", "--vault", "Private"] },
    ]);
    const execCalls = dockerExecCalls(fakeDocker.dockerLog);
    expect(execCalls).toHaveLength(1);
    const { header, payload } = verifyEs256Jwt(String(execCalls[0].stdin), publicKeyPem);
    expect(header).toMatchObject({ alg: "ES256", kid: "KEY123" });
    expect(payload).toMatchObject({ aud: "appstoreconnect-v1", iss: "ISSUER123" });
    expect(sync.stdout).not.toContain(privateKeyPem.trim());
    expect(sync.stderr).not.toContain(privateKeyPem.trim());
  });

  test("credential sync watch repeats at the shortest configured refresh interval", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({
      github: { source: "env", env: "GITHUB_TOKEN", refreshEverySeconds: 1 },
    });
    const fakeDocker = installTokenSyncDockerFake();

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: true, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      GITHUB_TOKEN: "ghp_secret",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "2",
      RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "1",
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("next credential sync in 1s");
    const execCalls = dockerExecCalls(fakeDocker.dockerLog);
    expect(execCalls).toHaveLength(2);
    expect(execCalls.map((entry) => entry.stdin)).toEqual(["ghp_secret", "ghp_secret"]);
  });

  test("credential sync watch ignores refresh intervals on unused local sources", async () => {
    writeFixtureRepo({
      hosts: [],
      tokens: {},
    });
    writeTokenConfig({
      unused: { source: "env", env: "UNUSED_TOKEN", refreshEverySeconds: 1 },
    });
    const fakeDocker = installTokenSyncDockerFake();

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: true, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "2",
      RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "1",
      UNUSED_TOKEN: "unused-secret",
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("credential sync watch stopped: no credential sources have refresh intervals");
    expect(result.stdout).not.toContain("unused-secret");
    const execCalls = dockerExecCalls(fakeDocker.dockerLog);
    expect(execCalls).toHaveLength(1);
    expect(String((execCalls[0].args as string[]).at(-1))).toContain("rm -f '/run/runfree-proxy-secrets/unused'");
    expect(execCalls[0].stdin).toBe("");
  });

  test("credential sync watch skips manual 1Password tokens after the current proxy generation is populated", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com", "registry.npmjs.org"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
        npm: {
          description: "npm token",
          credentials: [
            { host: "registry.npmjs.org", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({
      github: { source: "1password", ref: "op://Personal/GitHub/token" },
      npm: { source: "env", env: "NPM_TOKEN", refreshEverySeconds: 1 },
    });
    const fakeDocker = installTokenSyncDockerFake();
    const opLogPath = path.join(tmpBase, "manual-watch-op.jsonl");
    const hostOpBin = path.join(tmpBase, "manual-watch-op-bin");
    fs.mkdirSync(hostOpBin);
    installFakeOp(hostOpBin, { logPath: opLogPath });

    const result = await runAdmin(() => credentialSyncIntent({ verbose: true, watch: true, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      NPM_TOKEN: "npm_secret",
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "2",
      RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "1",
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toContain("github: skipped (manual current token-store generation already populated)");
    expect(readJsonLines(opLogPath)).toEqual([{ args: ["read", "op://Personal/GitHub/token"] }]);
    expect(dockerExecCalls(fakeDocker.dockerLog).map((entry) => entry.stdin)).toEqual([
      "onepassword-secret",
      "npm_secret",
      "npm_secret",
    ]);
  });

  test("credential sync refuses the proxy write when the token store changes during resolution", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: { github: { description: "GitHub token", credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }] } },
    });
    writeTokenConfig({ github: { source: "1password", ref: "op://Personal/GitHub/token" } });
    const fakeDocker = installTokenSyncDockerFake();
    const opLogPath = path.join(tmpBase, "swap-op.jsonl");
    const hostOpBin = path.join(tmpBase, "swap-op-bin");
    fs.mkdirSync(hostOpBin);
    installFakeOp(hostOpBin, { logPath: opLogPath });

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      FAKE_DOCKER_MARKER_SWAP_AFTER: opLogPath,
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(readJsonLines(opLogPath)).toHaveLength(1);
    expect(dockerExecCalls(fakeDocker.dockerLog).map((entry) => entry.stdin)).not.toContain("onepassword-secret");
    expect(result.status).not.toBe(0);
  });

  test("credential sync watch persists nothing after the token store changes behind trailing skipped tokens", async () => {
    // alpha is due every iteration; bravo and charlie are manual and skipped
    // once populated. delta is dropped (kept in the token config but absent
    // from the policy), so every iteration's post-loop cleanup tries to
    // remove it. The store is replaced right after alpha's iteration-2
    // write, so only the post-loop fence stands between the replaced store
    // and both the iteration-2 dropped-token removal and the status/receipt
    // persistence.
    writeFixtureRepo(exampleTokenPolicy(["alpha", "bravo", "charlie"]));
    writeTokenConfig({
      alpha: { source: "env", env: "ALPHA_TOKEN", refreshEverySeconds: 1 },
      bravo: { source: "1password", ref: "op://Personal/bravo/token" },
      charlie: { source: "1password", ref: "op://Personal/charlie/token" },
      delta: { source: "env", env: "DELTA_TOKEN" },
    });
    let atSwap: { receipts: string; status: string } | undefined;
    const fakeDocker = installTokenSyncDockerFake({
      onMarkerSwap: () => {
        atSwap = { receipts: fs.readFileSync(tokenReceiptsFilePath(), "utf8"), status: fs.readFileSync(tokenStatusFilePath(), "utf8") };
      },
    });
    const opLogPath = path.join(tmpBase, "trailing-op.jsonl");
    const hostOpBin = path.join(tmpBase, "trailing-op-bin");
    fs.mkdirSync(hostOpBin);
    installFakeOp(hostOpBin, { logPath: opLogPath });

    const result = await runAdmin(() => credentialSyncIntent({ verbose: true, watch: true, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      ALPHA_TOKEN: "alpha_secret",
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      FAKE_DOCKER_MARKER_SWAP_FLAG: path.join(tmpBase, "trailing-swap.flag"),
      FAKE_DOCKER_MARKER_SWAP_ON_WRITE: "alpha",
      FAKE_DOCKER_MARKER_SWAP_ON_WRITE_COUNT: "2",
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "2",
      RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "1",
    });

    expect(atSwap, result.stderr).toBeDefined();
    expect(result.stderr).toContain("credential sync watch iteration failed: exact proxy or token store changed during credential resolution");
    // bravo and charlie resolved once, in iteration 1 only.
    expect(readJsonLines(opLogPath)).toHaveLength(2);
    expect(fs.readFileSync(tokenStatusFilePath(), "utf8")).toBe(atSwap?.status);
    expect(fs.readFileSync(tokenReceiptsFilePath(), "utf8")).toBe(atSwap?.receipts);
    const swapWrite = proxyTokenWriteIndexes(fakeDocker.dockerLog, "alpha")[1];
    expect(swapWrite).toBeDefined();
    expect(proxyTokenRemovalIndexes(fakeDocker.dockerLog).filter((index) => index > swapWrite)).toEqual([]);
  });

  test("credential sync does not remove an unconfigured token after the token store changes", async () => {
    writeFixtureRepo(exampleTokenPolicy(["alpha", "bravo"]));
    writeTokenConfig({ alpha: { source: "env", env: "ALPHA_TOKEN" } });
    const fakeDocker = installTokenSyncDockerFake();

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      ALPHA_TOKEN: "alpha_secret",
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      FAKE_DOCKER_MARKER_SWAP_FLAG: path.join(tmpBase, "unconfigured-swap.flag"),
      FAKE_DOCKER_MARKER_SWAP_ON_WRITE: "alpha",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(proxyTokenWriteIndexes(fakeDocker.dockerLog, "alpha")).toHaveLength(1);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("exact proxy or token store changed during credential resolution");
    expect(proxyTokenRemovalIndexes(fakeDocker.dockerLog, "bravo")).toEqual([]);
  });

  test("credential sync does not remove a failed-source token after the token store changes", async () => {
    // bravo's named source fails on the source-registry error path, which
    // throws before the pre-resolution fence and lands in the per-token catch.
    writeFixtureRepo(exampleTokenPolicy(["alpha", "bravo"]));
    writeTokenConfig({
      alpha: { source: "env", env: "ALPHA_TOKEN" },
      bravo: { source: "named", name: "missing-cli" },
    });
    fs.mkdirSync(path.dirname(sourceRegistryPath()), { recursive: true });
    fs.writeFileSync(sourceRegistryPath(), `${JSON.stringify({ "missing-cli": { type: "command" } })}\n`);
    const fakeDocker = installTokenSyncDockerFake();

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      ALPHA_TOKEN: "alpha_secret",
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      FAKE_DOCKER_MARKER_SWAP_FLAG: path.join(tmpBase, "failed-source-swap.flag"),
      FAKE_DOCKER_MARKER_SWAP_ON_WRITE: "alpha",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(proxyTokenWriteIndexes(fakeDocker.dockerLog, "alpha")).toHaveLength(1);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("exact proxy or token store changed during credential resolution");
    expect(proxyTokenRemovalIndexes(fakeDocker.dockerLog, "bravo")).toEqual([]);
  });

  test("credential sync observes the proxy only before token side effects", async () => {
    writeFixtureRepo(exampleTokenPolicy(["one", "two", "three"]));
    // three keeps the watch running (an all-manual set stops after one
    // iteration); one and two are manual, so iteration 2 skips them.
    writeTokenConfig({
      one: { source: "1password", ref: "op://Personal/one/token" },
      two: { source: "1password", ref: "op://Personal/two/token" },
      three: { source: "env", env: "THREE_TOKEN", refreshEverySeconds: 1 },
    });
    const fakeDocker = installTokenSyncDockerFake();
    const hostOpBin = path.join(tmpBase, "fence-op-bin");
    fs.mkdirSync(hostOpBin);
    installFakeOp(hostOpBin, { logPath: path.join(tmpBase, "fence-op.jsonl") });

    const result = await runAdmin(() => credentialSyncIntent({ verbose: true, watch: true, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "2",
      RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "1",
      THREE_TOKEN: "three_secret",
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toContain("one: skipped (manual current token-store generation already populated)");
    expect(result.stderr).toContain("two: skipped (manual current token-store generation already populated)");
    expect(dockerExecCalls(fakeDocker.dockerLog).map((entry) => entry.stdin)).toEqual(["onepassword-secret", "onepassword-secret", "three_secret", "three_secret"]);
    // Iteration 1 resolves all three; iteration 2 resolves three and skips one
    // and two. A token that is not due takes no action, so it costs no proxy
    // re-observation; each iteration pays one post-loop fence. A value the
    // watcher read before its lock is taken from memory, so only its write
    // is fenced.
    const markerReads = readJsonLines(fakeDocker.dockerLog).filter((entry) => Array.isArray(entry.args)
      && entry.args[0] === "exec" && entry.args.join(" ").includes(CREDENTIAL_OBSERVATION_BATCH_HEADER)
      && entry.args.join(" ").includes("validation-marker")).length;
    expect(markerReads).toMatchInlineSnapshot(`8`);
  });

  test("credential sync watch schedules non-multiple token intervals by each token's own due time", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com", "registry.npmjs.org"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
        npm: {
          description: "npm token",
          credentials: [
            { host: "registry.npmjs.org", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({
      github: { source: "1password", ref: "op://Personal/GitHub/token", refreshEverySeconds: 3 },
      npm: { source: "env", env: "NPM_TOKEN", refreshEverySeconds: 2 },
    });
    const fakeDocker = installTokenSyncDockerFake();
    const opLogPath = path.join(tmpBase, "non-multiple-watch-op.jsonl");
    const hostOpBin = path.join(tmpBase, "non-multiple-watch-op-bin");
    fs.mkdirSync(hostOpBin);
    installFakeOp(hostOpBin, { logPath: opLogPath });

    const result = await runAdmin(() => credentialSyncIntent({ verbose: true, watch: true, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      NPM_TOKEN: "npm_secret",
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "3",
      RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "1",
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("next credential sync in 2s");
    expect(result.stdout).toContain("next credential sync in 1s");
    expect(readJsonLines(opLogPath)).toEqual([
      { args: ["read", "op://Personal/GitHub/token"] },
      { args: ["read", "op://Personal/GitHub/token"] },
    ]);
    expect(dockerExecCalls(fakeDocker.dockerLog).map((entry) => entry.stdin)).toEqual([
      "onepassword-secret",
      "npm_secret",
      "npm_secret",
      "onepassword-secret",
    ]);
  });

  test("credential sync watch caches 1Password JWT private keys in memory by default", async () => {
    const {
      fakeDocker,
      hostOpBin,
      opLogPath,
      privateKeyPem,
      publicKeyPem,
    } = await configureAppStoreJwtFixture({ refreshEvery: "18m" });

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: true, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "2",
      RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "1",
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("source secret cache: memory-only");
    expect(result.stdout).toContain("next credential sync in 18m");
    expect(result.stdout).not.toContain(privateKeyPem.trim());
    expect(result.stderr).not.toContain(privateKeyPem.trim());
    expect(readJsonLines(opLogPath)).toEqual([
      { args: ["read", "op://Private/AuthKey_KEY123"] },
      { args: ["document", "get", "AuthKey_KEY123", "--vault", "Private"] },
      { args: ["read", "op://Private/AuthKey_KEY123"] },
      { args: ["document", "get", "AuthKey_KEY123", "--vault", "Private"] },
    ]);
    const execCalls = dockerExecCalls(fakeDocker.dockerLog);
    expect(execCalls).toHaveLength(2);
    const firstJwt = String(execCalls[0].stdin);
    const secondJwt = String(execCalls[1].stdin);
    const first = verifyEs256Jwt(firstJwt, publicKeyPem);
    const second = verifyEs256Jwt(secondJwt, publicKeyPem);
    expect(first.header).toMatchObject({ alg: "ES256", kid: "KEY123", typ: "JWT" });
    expect(first.payload).toMatchObject({ aud: "appstoreconnect-v1", iss: "ISSUER123" });
    expect(second.payload.exp).toBeGreaterThan(first.payload.exp as number);
    expect(firstJwt).not.toBe(secondJwt);
    expect(JSON.stringify(readTokenStatus())).not.toContain(privateKeyPem.trim());
    expect(JSON.stringify(readTokenStatus())).not.toContain(firstJwt);
    expect(JSON.stringify(readTokenStatus())).not.toContain(secondJwt);
  });

  test("credential sync watch can disable source secret caching", async () => {
    const { fakeDocker, hostOpBin, opLogPath } = await configureAppStoreJwtFixture({ refreshEvery: "18m" });

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: true, quiet: false, delayFirstSync: false, cacheSourceSecrets: false }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "2",
      RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "1",
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("source secret cache: disabled");
    expect(readJsonLines(opLogPath)).toEqual([
      { args: ["read", "op://Private/AuthKey_KEY123"] },
      { args: ["document", "get", "AuthKey_KEY123", "--vault", "Private"] },
      { args: ["read", "op://Private/AuthKey_KEY123"] },
      { args: ["document", "get", "AuthKey_KEY123", "--vault", "Private"] },
      { args: ["read", "op://Private/AuthKey_KEY123"] },
      { args: ["document", "get", "AuthKey_KEY123", "--vault", "Private"] },
    ]);
    expect(dockerExecCalls(fakeDocker.dockerLog)).toHaveLength(2);
  });

  test("credential sync watch derives JWT refresh interval from ttl", async () => {
    const { fakeDocker, hostOpBin } = await configureAppStoreJwtFixture();

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: true, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "2",
      RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "1",
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("next credential sync in 18m");
    expect(dockerExecCalls(fakeDocker.dockerLog)).toHaveLength(2);
  });

  test("token set rejects refresh intervals at or beyond JWT ttl before reading secrets", async () => {
    writeFixtureRepo({
      hosts: ["api.appstoreconnect.apple.com"],
      tokens: {
        "appstore-connect": {
          description: "App Store Connect token",
          credentials: [
            { host: "api.appstoreconnect.apple.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    const fakeDocker = installTokenSyncDockerFake();
    const hostOpBin = path.join(tmpBase, "refresh-ttl-op-bin");
    const opLogPath = path.join(tmpBase, "refresh-ttl-op-log.jsonl");
    fs.mkdirSync(hostOpBin);
    installFakeDocumentOp(hostOpBin, {
      documentOutput: privateKeyPem,
      logPath: opLogPath,
    });
    const add = await runAdmin(() => sourceAddJwtIntent({
      name: "appstore-connect-jwt",
      replaceSource: false,
      alg: "ES256",
      privateKeyRef: "op://Private/AuthKey_KEY123",
      ttl: "19m",
      claims: ["iss=ISSUER123", "aud=appstoreconnect-v1"],
      headers: ["kid=KEY123"],
    }), {
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });
    expect(add.status, add.stderr).toBe(0);
    fs.writeFileSync(opLogPath, "");

    const bind = await runAdmin(() => credentialSetSourceIntent({
      name: "appstore-connect",
      tokenSource: { kind: "named", name: "appstore-connect-jwt" },
      refreshEvery: "19m",
      replaceSource: false,
      sync: false,
    }));

    expect(bind.status).toBe(1);
    expect(bind.stderr).toContain("--refresh-every must be shorter than source ttl 19m");
    expect(readJsonLines(opLogPath)).toEqual([]);
  });

  test("credential sync watch does not read source secrets when runtime validation is required", async () => {
    const { fakeDocker, hostOpBin, opLogPath } = await configureAppStoreJwtFixture({ refreshEvery: "18m" });
    fs.writeFileSync(opLogPath, "");

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: true, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      FAKE_DOCKER_VALIDATION_MARKER: "missing",
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "1",
      RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "1",
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toContain("runtime validation required before proxy token sync");
    expect(readJsonLines(opLogPath)).toEqual([]);
  });

  test("token status reports explicit derived and manual refresh modes", async () => {
    writeFixtureRepo({
      hosts: ["api.appstoreconnect.apple.com", "api.github.com"],
      tokens: {
        "appstore-explicit": {
          description: "Explicit App Store Connect token",
          credentials: [
            { host: "api.appstoreconnect.apple.com", header: "Authorization", scheme: "bearer" },
          ],
        },
        "appstore-derived": {
          description: "Derived App Store Connect token",
          credentials: [],
        },
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    const fakeDocker = installTokenSyncDockerFake();
    const hostOpBin = path.join(tmpBase, "status-refresh-op-bin");
    const opLogPath = path.join(tmpBase, "status-refresh-op-log.jsonl");
    fs.mkdirSync(hostOpBin);
    installFakeDocumentOp(hostOpBin, {
      documentOutput: privateKeyPem,
      logPath: opLogPath,
    });
    const add = await runAdmin(() => sourceAddJwtIntent({
      name: "appstore-connect-jwt",
      replaceSource: false,
      alg: "ES256",
      privateKeyRef: "op://Private/AuthKey_KEY123",
      ttl: "19m",
      claims: ["iss=ISSUER123", "aud=appstoreconnect-v1"],
      headers: ["kid=KEY123"],
    }), {
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });
    expect(add.status, add.stderr).toBe(0);
    writeTokenConfig({
      "appstore-explicit": { source: "named", name: "appstore-connect-jwt", refreshEverySeconds: 1080 },
      "appstore-derived": { source: "named", name: "appstore-connect-jwt" },
      github: { source: "env", env: "GITHUB_TOKEN" },
    });

    const status = await runAdmin(() => credentialStatus());

    expect(status.status, status.stderr).toBe(0);
    expect(status.stdout).toContain("appstore-explicit: configured");
    expect(status.stdout).toContain("refresh: every 18m (override)");
    expect(status.stdout).toContain("appstore-derived: configured");
    expect(status.stdout).toContain("refresh: every 18m (derived from source ttl 19m)");
    expect(status.stdout).toContain("github: configured");
    expect(status.stdout).toContain("refresh: manual");
    expect(status.stdout).not.toContain(privateKeyPem.trim());
  });

  test("source remove refuses sources still used by credential bindings", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    const fakeSource = installFakeCommandSource();
    expect((await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["gh", "auth", "token"],
    }), {
      PATH: fakeSource.fakeBin,
    })).status).toBe(0);
    writeTokenConfig({ github: { source: "named", name: "github-cli" } });

    const result = await runAdmin(() => sourceRemoveIntent({ name: "github-cli" }));

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("github-cli is used by credential bindings: github");
    expect(readSourceRegistry()).toHaveProperty("github-cli");
  });

  test("token sync resolves named command sources with sanitized host execution", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    const fakeSource = installFakeCommandSource();
    expect((await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["gh", "auth", "token"],
    }), {
      PATH: fakeSource.fakeBin,
    })).status).toBe(0);
    fs.writeFileSync(fakeSource.logPath, "");
    writeTokenConfig({ github: { source: "named", name: "github-cli" } });
    const fakeDocker = installTokenSyncDockerFake();

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      BUN_OPTIONS: "--inspect",
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      HTTPS_PROXY: "http://attacker-proxy.invalid",
      INIT_CWD: tmp,
      NODE_OPTIONS: "--trace-warnings",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${path.join(tmp, "node_modules/.bin")}${path.delimiter}${process.env.PATH ?? ""}`,
      PWD: tmp,
      RUNFREE_SECRET: "host-secret",
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("github: synced to proxy tmpfs from source github-cli");
    expect(result.stdout).not.toContain("command-secret");
    expect(result.stderr).not.toContain("command-secret");

    const sourceCalls = readCommandSourceLog(fakeSource.logPath);
    expect(sourceCalls).toHaveLength(1);
    expect(sourceCalls[0].argv).toEqual([fs.realpathSync(fakeSource.commandPath), "auth", "token"]);
    expect(sourceCalls[0].cwd).toBe(fs.realpathSync(path.dirname(path.join(home, ".config/runfree/sources.json"))));
    const sourceEnv = sourceCalls[0].env as Record<string, unknown>;
    for (const key of ["BUN_OPTIONS", "HTTPS_PROXY", "INIT_CWD", "NODE_OPTIONS", "PWD", "RUNFREE_PACKAGE_ROOT", "RUNFREE_PROJECT_ROOT"]) {
      expect(sourceEnv).not.toHaveProperty(key);
    }
    expect(String(sourceEnv.PATH)).not.toContain(tmp);

    const execCalls = dockerExecCalls(fakeDocker.dockerLog);
    expect(execCalls).toHaveLength(1);
    expect(execCalls[0].stdin).toBe("command-secret");
    expect(readTokenStatus().github).toMatchObject({
      source: "named",
      ok: true,
      message: "synced to proxy tmpfs",
    });
    expect(JSON.stringify(readTokenStatus())).not.toContain("command-secret");
  });

  test("token sync removes stale proxy tokens for missing named sources and malformed host configs", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({ github: { source: "named", name: "missing-cli" } });
    const missingDocker = installTokenSyncDockerFake();

    const missing = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: missingDocker.dockerLog,
      PATH: `${missingDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(missing.status).toBe(1);
    expect(missing.stderr).toContain("github: sync failed (unknown source: missing-cli)");
    expectProxyTokenRemoval(missingDocker.dockerLog);

    const malformedTokenSource = installFakeCommandSource();
    expect((await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["gh", "auth", "token"],
    }), {
      PATH: malformedTokenSource.fakeBin,
    })).status).toBe(0);
    fs.writeFileSync(malformedTokenSource.logPath, "");
    writeTokenConfig({ github: { source: "named", name: 7 } });
    const malformedTokenDocker = installTokenSyncDockerFake();

    const malformedToken = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: malformedTokenDocker.dockerLog,
      PATH: `${malformedTokenDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(malformedToken.status).toBe(1);
    expect(malformedToken.stderr).toContain("github: github: named credential source requires a valid source name");
    expect(readCommandSourceLog(malformedTokenSource.logPath)).toHaveLength(0);
    expectProxyTokenRemoval(malformedTokenDocker.dockerLog);

    writeTokenConfig({ github: { source: "named", name: "github-cli" } });
    fs.mkdirSync(path.dirname(sourceRegistryPath()), { recursive: true });
    fs.writeFileSync(
      sourceRegistryPath(),
      `${JSON.stringify({
        "github-cli": {
          type: "command",
          argv: [fs.realpathSync(malformedTokenSource.commandPath), "auth", "token"],
          displayArgv: [],
          createdAt: "",
        },
      }, null, 2)}\n`,
    );
    const malformedRegistryDocker = installTokenSyncDockerFake();

    const malformedRegistry = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: malformedRegistryDocker.dockerLog,
      PATH: `${malformedRegistryDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(malformedRegistry.status).toBe(1);
    expect(malformedRegistry.stderr).toContain("github: sync failed (github-cli: displayArgv must be a non-empty string array)");
    expect(readCommandSourceLog(malformedTokenSource.logPath)).toHaveLength(0);
    expectProxyTokenRemoval(malformedRegistryDocker.dockerLog);
  });

  test("token sync rejects hand-edited jwt sources with reserved header or claim fields before reading secrets", async () => {
    writeFixtureRepo({
      hosts: ["api.appstoreconnect.apple.com"],
      tokens: {
        "appstore-connect": {
          description: "App Store Connect token",
          credentials: [
            { host: "api.appstoreconnect.apple.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({ "appstore-connect": { source: "named", name: "appstore-connect-jwt" } });
    fs.mkdirSync(path.dirname(sourceRegistryPath()), { recursive: true });
    fs.writeFileSync(
      sourceRegistryPath(),
      `${JSON.stringify({
        "appstore-connect-jwt": {
          type: "jwt",
          alg: "ES256",
          privateKey: { source: "1password", ref: "op://Private/AppStoreConnect/AuthKey" },
          headers: { alg: "none", kid: "KEY123" },
          claims: { aud: "appstoreconnect-v1", exp: "9999999999", iss: "ISSUER123" },
          ttlSeconds: 1140,
          createdAt: new Date().toISOString(),
        },
      }, null, 2)}\n`,
    );
    const fakeDocker = installTokenSyncDockerFake();

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("appstore-connect: sync failed (appstore-connect-jwt: jwt header alg is reserved)");
    expect(result.stderr).not.toContain("op CLI not found");
    expectProxyTokenRemoval(fakeDocker.dockerLog, "appstore-connect");
  });

  test("token sync removes stale proxy tokens when named command execution fails", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });

    const fakeSource = installFakeCommandSource();
    expect((await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["gh", "auth", "token"],
    }), {
      PATH: fakeSource.fakeBin,
    })).status).toBe(0);
    writeTokenConfig({ github: { source: "named", name: "github-cli" } });

    fs.rmSync(fakeSource.commandPath);
    let fakeDocker = installTokenSyncDockerFake();
    const missingExecutable = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });
    expect(missingExecutable.status).toBe(1);
    expect(missingExecutable.stderr).toContain("executable is missing or no longer canonical");
    expectProxyTokenRemoval(fakeDocker.dockerLog);

    rewriteFakeCommandSource(fakeSource.commandPath, { exitCode: 7 });
    fakeDocker = installTokenSyncDockerFake();
    const nonzero = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });
    expect(nonzero.status).toBe(1);
    expect(nonzero.stderr).toContain("command source exited nonzero");
    expectProxyTokenRemoval(fakeDocker.dockerLog);

    rewriteFakeCommandSource(fakeSource.commandPath, { output: "\n" });
    fakeDocker = installTokenSyncDockerFake();
    const empty = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });
    expect(empty.status).toBe(1);
    expect(empty.stderr).toContain("command source returned an empty value");
    expectProxyTokenRemoval(fakeDocker.dockerLog);

    rewriteFakeCommandSource(fakeSource.commandPath, { block: true });
    fakeDocker = installTokenSyncDockerFake();
    const timeout = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_COMMAND_SOURCE_TIMEOUT_MS: "20",
    });
    expect(timeout.status).toBe(1);
    expect(timeout.stderr).toContain("command source timed out");
    expectProxyTokenRemoval(fakeDocker.dockerLog);
  });

  test("project-local token metadata is inert while the host-owned source resolves", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    const fakeSource = installFakeCommandSource();
    expect((await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["gh", "auth", "token"],
    }), {
      PATH: fakeSource.fakeBin,
    })).status).toBe(0);
    fs.writeFileSync(fakeSource.logPath, "");
    writeTokenConfig({ github: { source: "named", name: "github-cli" } });
    fs.mkdirSync(path.join(tmp, ".runfree/config"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, ".runfree/config/tokens.json"),
      `${JSON.stringify({ github: { source: "cmd", command: "malicious-project-command" } }, null, 2)}\n`,
    );
    const fakeDocker = installTokenSyncDockerFake();

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${fakeSource.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("github: synced to proxy tmpfs from source github-cli");
    expect(result.stderr).not.toContain("project-local");
    expect(readCommandSourceLog(fakeSource.logPath)).toHaveLength(1);
    const execCalls = dockerExecCalls(fakeDocker.dockerLog);
    expect(execCalls).toHaveLength(1);
    expect(execCalls[0].stdin).toBe("command-secret");
  });

  test("project-local token metadata cannot supply a missing host-owned source", async () => {
    writeFixtureRepo({
      hosts: ["api.example.com"],
      tokens: {
        acme: {
          description: "Acme token",
          credentials: [
            { host: "api.example.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    fs.mkdirSync(path.join(tmp, ".runfree/config"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, ".runfree/config/tokens.json"),
      `${JSON.stringify({ acme: { source: "cmd", command: "malicious" } }, null, 2)}\n`,
    );
    const fakeDocker = installTokenSyncDockerFake();

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("acme: missing required credential source");
    expect(result.stderr).not.toContain("malicious");
    expect(result.stderr).not.toContain("project-local");
    expectProxyTokenRemoval(fakeDocker.dockerLog, "acme");
  });

  test("a project-local token-config symlink is inert", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    fs.mkdirSync(path.join(tmp, ".runfree/config"), { recursive: true });
    fs.symlinkSync(path.join(tmp, "attacker-controlled-token-config.json"), path.join(tmp, ".runfree/config/tokens.json"));
    writeTokenConfig({ github: { source: "env", env: "HOST_GITHUB_TOKEN" } });
    const fakeDocker = installTokenSyncDockerFake();

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      HOST_GITHUB_TOKEN: "host-owned-secret",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).not.toContain("project-local");
    const execCalls = dockerExecCalls(fakeDocker.dockerLog);
    expect(execCalls).toHaveLength(1);
    expect(execCalls[0].stdin).toBe("host-owned-secret");
  });

  test("host-owned credential source paths reject XDG config symlinks into the project", async () => {
    writeFixtureRepo({
      hosts: [],
      tokens: {},
    });
    const projectOwnedConfig = path.join(tmp, "project-owned-config");
    const hostConfigLink = path.join(tmpBase, "host-config-link");
    const projectLink = path.join(tmpBase, "project-link");
    fs.mkdirSync(projectOwnedConfig);
    fs.symlinkSync(tmp, projectLink, "dir");
    fs.symlinkSync(projectOwnedConfig, hostConfigLink, "dir");

    const result = await runAdmin(() => sourceList(), {
      RUNFREE_PROJECT_ROOT: projectLink,
      XDG_CONFIG_HOME: hostConfigLink,
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("must be outside the project");
  });

  test("production token-source path overrides cannot move metadata into the project", () => {
    // The host-owned token/source config paths are managed by Runfree. The env
    // overrides are test-only (gated on RUNFREE_TEST_FAKE_DOCKER); createAdminState
    // rejects them otherwise. Without the marker in the env, construction throws.
    expect(() =>
      createAdminState({
        projectRoot: tmp,
        packageRoot: tmp,
        env: { HOME: home, RUNFREE_TOKEN_CONFIG_PATH: path.join(tmp, ".runfree/config/tokens.json") },
      }),
    ).toThrow("RUNFREE_TOKEN_CONFIG_PATH is test-only");

    expect(() =>
      createAdminState({
        projectRoot: tmp,
        packageRoot: tmp,
        env: { HOME: home, RUNFREE_SOURCE_CONFIG_PATH: path.join(tmp, ".runfree/config/sources.json") },
      }),
    ).toThrow("RUNFREE_SOURCE_CONFIG_PATH is test-only");
  });

  test("token set for an unknown token points to credential policy creation", async () => {
    writeFixtureRepo({
      hosts: ["platform.claude.com"],
      tokens: {},
    });

    const result = await runAdmin(() => credentialSetSourceIntent({
      name: "claude",
      tokenSource: { kind: "1password", ref: "op://Personal/ClaudeCode_setup-token/password" },
      replaceSource: false,
      sync: true,
    }));

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("unknown credential: claude");
    expect(result.stderr).toContain("runfree credential add claude --host <host>");
    expect(result.stderr).toContain("Claude Code login uses Runfree-managed Claude state");
  });

  test("token set reports unrelated required token sync failures", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com", "api.firecrawl.dev"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
        firecrawl: {
          description: "Firecrawl token",
          credentials: [
            { host: "api.firecrawl.dev", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });

    const result = await runAdmin(() => credentialSetSourceIntent({
      name: "github",
      tokenSource: { kind: "env", env: "GITHUB_TOKEN" },
      replaceSource: false,
      sync: true,
    }), {
      GITHUB_TOKEN: "real-github-token",
    });

    expect(result.status).toBe(1);
    expect(result.stdout).toContain("github credential configured");
    expect(result.stdout).toContain("proxy sync: failed");
    expect(result.stderr).toContain("firecrawl: missing required credential source");
    expect(result.stderr).toContain("runfree credential set-source firecrawl --from-env FIRECRAWL_TOKEN");
    expect(result.stderr).not.toContain("real-github-token");
  });

  test("token status shows stale local sources and token unset can remove them", async () => {
    writeFixtureRepo({
      hosts: [],
      tokens: {},
    });

    writeTokenConfig({ claude: { source: "env", env: "CLAUDE_TOKEN" } });

    const status = await runAdmin(() => credentialStatus());
    expect(status.status, status.stderr).toBe(0);
    expect(status.stdout).toContain("claude: configured (unused local source)");
    expect(status.stdout).toContain("cleanup: runfree credential clear-source claude");

    const fakeDocker = installTokenSyncDockerFake();
    const unset = await runAdmin(() => credentialClearSourceIntent({ name: "claude" }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });
    expect(unset.status, unset.stderr).toBe(0);
    expect(readTokenConfig()).toEqual({});
  });

  test("credential clear-source preserves recovery metadata when live proxy revocation cannot be verified", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }],
        },
      },
    });
    writeTokenConfig({ github: { source: "env", env: "GITHUB_TOKEN" } });
    const fakeDocker = installTokenSyncDockerFake();

    const result = await runAdmin(() => credentialClearSourceIntent({ name: "github" }), {
      FAKE_DOCKER_EXEC_STATUS: "1",
      FAKE_DOCKER_EXEC_STDERR: "proxy exec unavailable\n",
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("proxy exec unavailable");
    expect(result.stdout).not.toContain("credential source cleared");
    expect(readTokenConfig()).toEqual({ github: { source: "env", env: "GITHUB_TOKEN" } });
  });

  test("token sync writes configured env tokens into proxy tmpfs through stdin and records non-secret status", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({ github: { source: "env", env: "GITHUB_TOKEN" } });
    const fakeDocker = installTokenSyncDockerFake();

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      GITHUB_TOKEN: "real-secret-value",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("github: synced to proxy tmpfs from env GITHUB_TOKEN");
    expect(result.stdout).toContain("credential sync complete");
    expect(result.stdout).not.toContain("real-secret-value");
    expect(result.stderr).not.toContain("real-secret-value");

    const execCalls = dockerExecCalls(fakeDocker.dockerLog);
    expect(execCalls).toHaveLength(1);
    expect(execCalls[0].args).toEqual([
      "exec",
      "--interactive",
      "--user",
      "1001:1001",
      "proxy-id",
      "sh",
      "-c",
      expect.stringContaining("cat > '/run/runfree-proxy-secrets/github.tmp'"),
    ]);
    const command = String((execCalls[0].args as string[])[7]);
    expect(command).toContain("umask 077");
    expect(command).toContain("chmod 600 '/run/runfree-proxy-secrets/github.tmp'");
    expect(command).toContain("mv '/run/runfree-proxy-secrets/github.tmp' '/run/runfree-proxy-secrets/github'");
    expect(execCalls[0].stdin).toBe("real-secret-value");

    const status = readTokenStatus();
    expect(status.github).toMatchObject({
      source: "env",
      ok: true,
      message: "synced to proxy tmpfs",
    });
    expect(JSON.stringify(status)).not.toContain("real-secret-value");
  });

  // Pins the token-write property independent of the exact argv shape above:
  // the proxy write (packages/cli/src/admin/admin-core.ts's
  // `writeProxyRuntimeToken`, built through `adminDockerClient()`) must
  // deliver the secret only on the spawned call's stdin, never in argv. A
  // future argv change (quoting, flag order, a shell helper) must not let
  // the value leak into argv. This does not check env: the fake docker log
  // only ever records four fixed, unrelated keys
  // (COMPOSE_PROJECT_NAME/DOCKER_CLI_HINTS/OP_SERVICE_ACCOUNT_TOKEN/
  // RUNFREE_PROJECT_ROOT), so an env assertion against that log could never
  // fail and would prove nothing.
  test("the proxy token write carries the secret only on stdin, never in argv", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({ github: { source: "env", env: "GITHUB_TOKEN" } });
    const fakeDocker = installTokenSyncDockerFake();
    const secretValue = "pinned-secret-9f3a1c";

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      GITHUB_TOKEN: secretValue,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status, result.stderr).toBe(0);

    const execCalls = dockerExecCalls(fakeDocker.dockerLog);
    const writeCall = execCalls.find((entry) => String(entry.stdin) === secretValue);
    expect(writeCall, "no exec call carried the secret on stdin").toBeDefined();
    expect(JSON.stringify(writeCall?.args)).not.toContain(secretValue);
    // And nowhere else in the whole exchange with the proxy container.
    for (const entry of execCalls) {
      expect(JSON.stringify(entry.args)).not.toContain(secretValue);
    }
  });

  test("token sync accepts the startup-provided current validation proof without reading the marker", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({ github: { source: "env", env: "GITHUB_TOKEN" } });
    const fakeDocker = installTokenSyncDockerFake();
    const env = {
      ...process.env,
      HOME: home,
      XDG_CONFIG_HOME: path.join(home, ".config"),
      XDG_DATA_HOME: path.join(home, ".local/share"),
      XDG_STATE_HOME: path.join(home, ".local/state"),
      CODEX_HOME: path.join(home, ".codex"),
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      GITHUB_TOKEN: "real-secret-value",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_PACKAGE_ROOT: tmp,
      RUNFREE_PROJECT_ID: projectHash(tmp),
      RUNFREE_RUNTIME_DIGEST,
      RUNFREE_RUNTIME_ROOT: path.join(repoRoot, "packages/agent-runtime"),
      RUNFREE_TEST_FAKE_DOCKER: "1",
    };
    const state = createAdminState({
      env,
      packageRoot: tmp,
      policyPath: path.join(tmp, ".runfree/network-policy.json"),
      projectRoot: tmp,
      processRunner: fakeProcessRunner,
      runtimeContext: tokenSyncRuntimeContext(env),
      stateDir: adminStateDir(),
      tokenConfigPath: tokenConfigPath(),
      validatedRuntime: {
        components: expectedTokenSyncComponents(),
        contractHash: expectedTokenSyncContractHash(),
        mcpOAuthCallbackPort: mcpOAuthCallbackPort(tmp),
        mcpOAuthCallbackTopologyVersion: 2,
        projectId: projectHash(tmp),
        proofVersion: 4,
        proxyId: "proxy-id",
      },
    });

    const status = await runAdminAction(state, () => credentialSyncIntent({
      verbose: false,
      watch: false,
      quiet: false,
      delayFirstSync: false,
      cacheSourceSecrets: true,
    }));

    expect(status).toBe(0);
    const execCalls = dockerExecCalls(fakeDocker.dockerLog);
    expect(execCalls.some((entry) => String(entry.stdin).includes("real-secret-value"))).toBe(true);
  });

  test("token sync rejects contradictory live component labels before resolving credential sources", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({ github: { source: "1password", ref: "op://Private/GitHub/token" } });
    const fakeDocker = installTokenSyncDockerFake();
    const opLogPath = path.join(tmpBase, "component-mismatch-op.jsonl");
    installFakeOp(fakeDocker.fakeBin, { logPath: opLogPath, output: "must-not-resolve\n" });

    const result = await runAdmin(() => credentialSyncIntent({
      verbose: false,
      watch: false,
      quiet: false,
      delayFirstSync: false,
      cacheSourceSecrets: true,
    }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      FAKE_RUNTIME_COMPONENT_TAMPER: "1",
      OP_SERVICE_ACCOUNT_TOKEN: "host-session-token",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("runtime component evidence contradicts the active control plane generation");
    expect(fs.existsSync(opLogPath)).toBe(false);
    expect(fs.readFileSync(fakeDocker.dockerLog, "utf8")).not.toContain("must-not-resolve");
    expect(dockerExecCalls(fakeDocker.dockerLog).some((entry) =>
      Array.isArray(entry.args) && entry.args.join(" ").includes(" mv ")
    )).toBe(false);
  });

  test("token sync refuses a running proxy before runtime validation without writing secrets", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({ github: { source: "env", env: "GITHUB_TOKEN" } });
    const fakeDocker = installTokenSyncDockerFake();

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      FAKE_DOCKER_VALIDATION_MARKER: "missing",
      GITHUB_TOKEN: "real-secret-value",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("runtime validation required before proxy token sync");
    expect(result.stdout).not.toContain("credential sync complete");
    expect(result.stdout).not.toContain("real-secret-value");
    expect(result.stderr).not.toContain("real-secret-value");
    const execCalls = dockerExecCalls(fakeDocker.dockerLog);
    expect(execCalls.some((entry) => String(entry.stdin).includes("real-secret-value"))).toBe(false);
    expectProxyTokenRemoval(fakeDocker.dockerLog);
  });

  test("token sync reports stale runtime validation markers without writing secrets", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({ github: { source: "env", env: "GITHUB_TOKEN" } });
    const fakeDocker = installTokenSyncDockerFake();

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      FAKE_DOCKER_VALIDATION_MARKER_JSON: JSON.stringify({
        // A leftover shared-agent id: post-cutover any agent id in the marker
        // means it was written for the pre-flip runtime shape.
        agentId: "stale-agent-id",
        components: expectedTokenSyncComponents(),
        mcpOAuthCallbackPort: mcpOAuthCallbackPort(tmp),
        mcpOAuthCallbackTopologyVersion: 2,
    proofVersion: 4,
        projectId: projectHash(tmp),
        proxyId: "proxy-id",
      }),
      GITHUB_TOKEN: "real-secret-value",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("runtime validation marker is stale for the per-session runtime shape");
    expect(result.stdout).not.toContain("credential sync complete");
    expect(result.stdout).not.toContain("real-secret-value");
    expect(result.stderr).not.toContain("real-secret-value");
    const execCalls = dockerExecCalls(fakeDocker.dockerLog);
    expect(execCalls.some((entry) => String(entry.stdin).includes("real-secret-value"))).toBe(false);
    expectProxyTokenRemoval(fakeDocker.dockerLog);
  });

  test("token sync rejects stale runtime component markers before writing secrets", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({ github: { source: "env", env: "GITHUB_TOKEN" } });
    const fakeDocker = installTokenSyncDockerFake();

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      FAKE_DOCKER_VALIDATION_MARKER_JSON: JSON.stringify({
        components: {
          ...expectedTokenSyncComponents(),
          controlPlaneTopologyDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        },
        mcpOAuthCallbackPort: mcpOAuthCallbackPort(tmp),
        mcpOAuthCallbackTopologyVersion: 2,
    proofVersion: 4,
        projectId: projectHash(tmp),
        proxyId: "proxy-id",
      }),
      GITHUB_TOKEN: "real-secret-value",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("runtime validation marker is stale for runtime components");
    expect(result.stdout).not.toContain("credential sync complete");
    expect(result.stdout).not.toContain("real-secret-value");
    expect(result.stderr).not.toContain("real-secret-value");
    const execCalls = dockerExecCalls(fakeDocker.dockerLog);
    expect(execCalls.some((entry) => String(entry.stdin).includes("real-secret-value"))).toBe(false);
    expectProxyTokenRemoval(fakeDocker.dockerLog);
  });

  test("token unset removes stale proxy tokens even when runtime validation is required", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({ github: { source: "env", env: "GITHUB_TOKEN" } });
    const fakeDocker = installTokenSyncDockerFake();

    const result = await runAdmin(() => credentialClearSourceIntent({ name: "github" }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      FAKE_DOCKER_VALIDATION_MARKER: "missing",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("github credential source cleared");
    expectProxyTokenRemoval(fakeDocker.dockerLog);
  });

  test("token sync fails when policy declares a required token without a local source", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }));

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("github: missing required credential source");
    expect(result.stderr).toContain("tokens.json has no github entry");
    expect(result.stderr).toContain("runfree credential set-source github --from-env GITHUB_TOKEN");
    expect(result.stderr).toContain("tokens.github.allowAnonymous=true");
    expect(result.stdout).not.toContain("credential sync complete");

    const status = readTokenStatus();
    expect(status.github.ok).toBe(false);
    expect(status.github.message).toContain("missing required credential source");
  });

  test("token sync allows a policy token without a local source only when anonymous fallback is explicit", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          allowAnonymous: true,
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }));

    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).not.toContain("missing required credential source");

    const status = readTokenStatus();
    expect(status.github).toMatchObject({
      ok: true,
      message: "unconfigured; anonymous fallback enabled",
    });
  });

  test("token sync treats the legacy generated GitHub policy as anonymous fallback", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com", "raw.githubusercontent.com"],
      tokens: {
        github: {
          description: "Read-only GitHub API token for rate limit and public metadata",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
            { host: "raw.githubusercontent.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }));

    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).not.toContain("missing required credential source");
    // The validator normalizes the legacy generated GitHub shape to anonymous
    // fallback at read time; nothing rewrites the stored file any more.
    expect(validateNetworkPolicy(readPolicy()).tokens.github.allowAnonymous).toBe(true);

    const status = readTokenStatus();
    expect(status.github).toMatchObject({
      ok: true,
      message: "unconfigured; anonymous fallback enabled",
    });
  });

  test("token sync resolves 1Password sources with host env while keeping credential env out of Docker", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({ github: { source: "1password", ref: "op://Personal/GitHub/token" } });
    const fakeDocker = installTokenSyncDockerFake();
    const hostOpBin = path.join(tmpBase, "host-op-bin");
    fs.mkdirSync(hostOpBin);
    installFakeOp(hostOpBin);

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      COMPOSE_PROJECT_NAME: "attacker-compose",
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_FAKE_DOCKER: "1",
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("github: synced to proxy tmpfs from 1password");
    expect(result.stdout).not.toContain("onepassword-secret");

    const dockerCalls = readJsonLines(fakeDocker.dockerLog);
    expect(dockerCalls.length).toBeGreaterThan(0);
    for (const call of dockerCalls) {
      expect(call.env).toMatchObject({ DOCKER_CLI_HINTS: "false" });
      expect(call.env).not.toHaveProperty("COMPOSE_PROJECT_NAME");
      expect(call.env).not.toHaveProperty("OP_SERVICE_ACCOUNT_TOKEN");
    }
    const execCalls = dockerExecCalls(fakeDocker.dockerLog);
    expect(execCalls).toHaveLength(1);
    expect(execCalls[0].stdin).toBe("onepassword-secret");
  });

  test("token sync includes sanitized 1Password stderr on read failures", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({ github: { source: "1password", ref: "op://Personal/GitHub/token" } });
    const fakeDocker = installTokenSyncDockerFake();
    const hostOpBin = path.join(tmpBase, "host-op-bin");
    fs.mkdirSync(hostOpBin);
    installFakeOp(hostOpBin, {
      exitCode: 1,
      stderr: "authentication failed for sk-abcdefghijklmnopqrstuvwxyz1234567890TOKEN\nsecond line\n",
    });

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_FAKE_DOCKER: "1",
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("github: sync failed (op read failed: authentication failed for [redacted])");
    expect(result.stderr).not.toContain("sk-abcdefghijklmnopqrstuvwxyz1234567890TOKEN");
    expectProxyTokenRemoval(fakeDocker.dockerLog);
  });

  test("token sync removes stale proxy tmpfs tokens when source resolution fails", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({ github: { source: "env", env: "MISSING_GITHUB_TOKEN" } });
    const fakeDocker = installTokenSyncDockerFake();

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("github: sync failed (MISSING_GITHUB_TOKEN is unset or empty)");
    expect(result.stdout).not.toContain("credential sync complete");

    const execCalls = dockerExecCalls(fakeDocker.dockerLog);
    expect(execCalls).toHaveLength(1);
    expect(execCalls[0].args).toEqual([
      "exec",
      "proxy-id",
      "sh",
      "-c",
      "rm -f '/run/runfree-proxy-secrets/github' '/run/runfree-proxy-secrets/github.tmp'",
    ]);
    expect(execCalls[0].stdin).toBe("");

    expect(readTokenStatus().github).toMatchObject({
      source: "env",
      ok: false,
      message: "MISSING_GITHUB_TOKEN is unset or empty",
    });
  });

  test("1Password sources do not resolve project-controlled op executables", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({ github: { source: "1password", ref: "op://Personal/GitHub/token" } });
    const fakeDocker = installTokenSyncDockerFake();
    installFakeOp(fakeDocker.fakeBin);

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: fakeDocker.fakeBin,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("github: sync failed (op CLI not found on sanitized host PATH)");
    expectProxyTokenRemoval(fakeDocker.dockerLog);
  });

  test("token sync cleans unused local credential sources out of proxy tmpfs", async () => {
    writeFixtureRepo({
      hosts: [],
      tokens: {},
    });
    writeTokenConfig({ stale: { source: "env", env: "STALE_TOKEN" } });
    const fakeDocker = installTokenSyncDockerFake();

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
      STALE_TOKEN: "unused-secret",
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("credential sync complete");
    expect(result.stdout).not.toContain("unused-secret");

    const execCalls = dockerExecCalls(fakeDocker.dockerLog);
    expect(execCalls).toHaveLength(1);
    expect(execCalls[0].args).toEqual([
      "exec",
      "proxy-id",
      "sh",
      "-c",
      "rm -f '/run/runfree-proxy-secrets/stale' '/run/runfree-proxy-secrets/stale.tmp'",
    ]);
    expect(readTokenStatus().stale).toMatchObject({
      source: "env",
      ok: true,
      message: "unused local source; proxy tmpfs token removed",
    });
    expect(JSON.stringify(readTokenStatus())).not.toContain("unused-secret");
  });

  // A receipt-gated warm-launch sync with nothing it could
  // write, delete, or prune returns before any Docker call.
  test("a startup-convergence sync with no tokens, no token config, and no receipts asks Docker nothing", async () => {
    writeFixtureRepo({ hosts: [], tokens: {} });
    writeTokenConfig({});
    const fakeDocker = installTokenSyncDockerFake();
    const result = await runAdmin(() => credentialSyncIntent({
      verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true, mode: "startup-convergence",
    }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });
    expect(result.status, result.stderr).toBe(0);
    expect(fs.existsSync(fakeDocker.dockerLog) ? readJsonLines(fakeDocker.dockerLog) : []).toEqual([]);
  });

  test("a startup-convergence sync still runs when the host token config holds an entry the policy dropped", async () => {
    writeFixtureRepo({ hosts: [], tokens: {} });
    writeTokenConfig({ dropped: { source: "env", env: "DROPPED_TOKEN" } });
    const fakeDocker = installTokenSyncDockerFake();
    await runAdmin(() => credentialSyncIntent({
      verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true, mode: "startup-convergence",
    }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });
    // The dropped-token cleanup must still get its chance: the sync observed the proxy.
    expect(readJsonLines(fakeDocker.dockerLog).length).toBeGreaterThan(0);
  });

  test("a startup-convergence sync still runs when a persisted receipt awaits pruning", async () => {
    // Arrange a persisted receipt the way an earlier successful sync leaves
    // one: run a source-truth sync with a real token so it resolves and
    // writes a receipt, then drop the token from both the policy and the
    // token config, so only the receipt remains as evidence of something a
    // sync could still prune.
    writeFixtureRepo(exampleTokenPolicy(["alpha"]));
    writeTokenConfig({ alpha: { source: "env", env: "ALPHA_TOKEN" } });
    const fakeDocker = installTokenSyncDockerFake();

    const populated = await runAdmin(() => credentialSyncIntent({
      verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true,
    }), {
      ALPHA_TOKEN: "alpha_secret",
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });
    expect(populated.status, populated.stderr).toBe(0);
    expect(fs.existsSync(tokenReceiptsFilePath())).toBe(true);
    const receiptsBefore = JSON.parse(fs.readFileSync(tokenReceiptsFilePath(), "utf8")) as { receipts: Array<{ tokenName: string }> };
    expect(receiptsBefore.receipts.map((receipt) => receipt.tokenName)).toEqual(["alpha"]);

    // Drop the token everywhere but the receipt file. (Not writeFixtureRepo:
    // it unconditionally symlinks node_modules into the project and would
    // fail with EEXIST on this second call.)
    fs.writeFileSync(path.join(tmp, ".runfree/network-policy.json"), `${JSON.stringify({ hosts: [], tokens: {} }, null, 2)}\n`);
    writeTokenConfig({});
    const linesBeforeWarmSync = readJsonLines(fakeDocker.dockerLog).length;

    await runAdmin(() => credentialSyncIntent({
      verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true, mode: "startup-convergence",
    }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    // The receipt alone must be enough to force the sync to run and observe
    // the proxy: new Docker log entries past the populate run.
    expect(readJsonLines(fakeDocker.dockerLog).slice(linesBeforeWarmSync)).not.toEqual([]);
  });
});

describe("convergent proxy token store", () => {
  const syncInput = { verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true } as const;

  function writeGithubOnePasswordFixture(): void {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    writeTokenConfig({ github: { source: "1password", ref: "op://Private/GitHub/token" } });
  }

  function receiptsFilePath(): string {
    return path.join(adminStateDir(), `token-resolution-receipts-${projectHash(tmp)}.json`);
  }

  function readReceiptsFile(): Array<{ tokenName: string; sourceFingerprint: string; proxyStoreGeneration: string; resolvedAt: number }> {
    if (!fs.existsSync(receiptsFilePath())) return [];
    const raw = JSON.parse(fs.readFileSync(receiptsFilePath(), "utf8")) as { receipts: Array<{ tokenName: string; sourceFingerprint: string; proxyStoreGeneration: string; resolvedAt: number }> };
    return raw.receipts ?? [];
  }

  function tokenRemovalCount(logPath: string, tokenName = "github"): number {
    return dockerExecCalls(logPath).filter((entry) => {
      const args = entry.args as string[];
      return String(args.at(-1)).includes(`rm -f '/run/runfree-proxy-secrets/${tokenName}'`);
    }).length;
  }

  // The op stub must live outside the project root: sanitized host PATH
  // rejects project-controlled executables.
  function makeHostOpBin(): string {
    const hostOpBin = path.join(tmpBase, `host-op-${Math.random().toString(16).slice(2)}`);
    fs.mkdirSync(hostOpBin, { recursive: true });
    return hostOpBin;
  }

  function opEnv(fakeDocker: { dockerLog: string; fakeBin: string }, hostOpBin: string): NodeJS.ProcessEnv {
    return {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${hostOpBin}${path.delimiter}${process.env.PATH ?? ""}`,
    };
  }

  test("classified-transient 1Password failures keep a receipt-proven token as stale and heal on success", async () => {
    writeGithubOnePasswordFixture();
    const fakeDocker = installTokenSyncDockerFake();
    const hostOpBin = makeHostOpBin();
    installFakeOp(hostOpBin, { output: "ghp_secret\n" });

    const populate = await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin));
    expect(populate.status, populate.stderr).toBe(0);
    expect(readReceiptsFile().map((receipt) => receipt.tokenName)).toEqual(["github"]);

    // Locked vault: transient, receipt-proven, held → keep, mark stale, no removal exec.
    installFakeOp(hostOpBin, { exitCode: 1, stderr: "1Password is locked\n" });
    const stale = await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin));
    expect(stale.status).toBe(1);
    expect(stale.stderr).toContain("keeping last-good proxy value resolved at");
    expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
    expect(readTokenStatus().github).toMatchObject({ ok: false, state: "stale" });
    expect(readTokenStatus().github.heldValueResolvedAt).toBeTruthy();
    expect(readReceiptsFile()).toHaveLength(1);

    // A later successful source-truth resolution returns to ok with a fresh receipt.
    installFakeOp(hostOpBin, { output: "ghp_rotated\n" });
    const healed = await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin));
    expect(healed.status, healed.stderr).toBe(0);
    expect(readTokenStatus().github).toMatchObject({ ok: true, state: "ok" });
  });

  test("definitive failure deletes and retracts the receipt even with a matching receipt (host-side revocation)", async () => {
    writeGithubOnePasswordFixture();
    const fakeDocker = installTokenSyncDockerFake();
    const hostOpBin = makeHostOpBin();
    installFakeOp(hostOpBin, { output: "ghp_secret\n" });
    expect((await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin))).status).toBe(0);

    // Deleting the vault item surfaces as item-not-found: fail closed within one sync.
    installFakeOp(hostOpBin, { exitCode: 1, stderr: 'could not read secret "op://Private/GitHub/token": item not found in vault\n' });
    const revoked = await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin));
    expect(revoked.status).toBe(1);
    expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(1);
    expect(readTokenStatus().github).toMatchObject({ ok: false, state: "failed" });
    expect(readReceiptsFile()).toHaveLength(0);

    // With the receipt retracted, a following transient failure records failed, never stale.
    installFakeOp(hostOpBin, { exitCode: 1, stderr: "1Password is locked\n" });
    const afterRetract = await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin));
    expect(afterRetract.status).toBe(1);
    expect(readTokenStatus().github).toMatchObject({ ok: false, state: "failed" });
  });

  test("transient failure with no receipt (or past the staleness bound) deletes", async () => {
    writeGithubOnePasswordFixture();
    const fakeDocker = installTokenSyncDockerFake();
    const hostOpBin = makeHostOpBin();
    installFakeOp(hostOpBin, { exitCode: 1, stderr: "1Password is locked\n" });

    // No receipt: even a transient failure cannot prove the tmpfs value.
    const noReceipt = await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin));
    expect(noReceipt.status).toBe(1);
    expect(readTokenStatus().github).toMatchObject({ ok: false, state: "failed" });

    // Populate, then age the receipt past the 24h staleness bound.
    installFakeOp(hostOpBin, { output: "ghp_secret\n" });
    expect((await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin))).status).toBe(0);
    const receipts = readReceiptsFile();
    expect(receipts).toHaveLength(1);
    fs.writeFileSync(receiptsFilePath(), `${JSON.stringify({
      schemaVersion: 1,
      receipts: [{ ...receipts[0], resolvedAt: Date.now() - 25 * 60 * 60 * 1000 }],
    })}\n`);
    const before = tokenRemovalCount(fakeDocker.dockerLog);
    installFakeOp(hostOpBin, { exitCode: 1, stderr: "1Password is locked\n" });
    const expired = await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin));
    expect(expired.status).toBe(1);
    expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(before + 1);
    expect(readTokenStatus().github).toMatchObject({ ok: false, state: "failed" });
  });

  test("receipt-gated convergence skips held tokens without reading sources; explicit sync stays source-truth", async () => {
    writeGithubOnePasswordFixture();
    const fakeDocker = installTokenSyncDockerFake();
    const hostOpBin = makeHostOpBin();
    const opLogPath = path.join(tmpBase, `converge-op-${Math.random().toString(16).slice(2)}.jsonl`);
    installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_secret\n" });
    expect((await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin))).status).toBe(0);
    expect(readJsonLines(opLogPath)).toHaveLength(1);

    // Unrelated policy mutation with reload: the convergence sync must not
    // re-resolve the held 1Password token (zero op spawns).
    const widened = { ...readPolicy(), hosts: ["api.github.com", "unrelated.example"] };
    const expectedGeneration = validateNetworkPolicy(widened).generation;
    fs.writeFileSync(path.join(tmp, ".runfree/network-policy.json"), `${JSON.stringify(widened, null, 2)}\n`);
    const converge = await runAdmin(() => convergeProxyPolicy(), {
      ...opEnv(fakeDocker, hostOpBin),
      FAKE_PROXY_STATUS_GENERATION: expectedGeneration,
    });
    expect(converge.status, converge.stderr).toBe(0);
    expect(converge.stdout).toContain("proxy policy converged (no restart)");
    expect(readJsonLines(opLogPath)).toHaveLength(1);

    // Explicit `runfree credential sync` ignores receipts for resolution: it
    // re-reads the source and observes host-side revocation immediately.
    installFakeOp(hostOpBin, { logPath: opLogPath, exitCode: 1, stderr: "item not found in vault\n" });
    const explicit = await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin));
    expect(explicit.status).toBe(1);
    expect(readJsonLines(opLogPath)).toHaveLength(2);
    expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(1);
  });

  describe("receipt-gated warm launch (launch plan D4, sub-second launch plan Task 5)", () => {
    // Verbose, so a deferral names its reason and each test can prove which
    // step deferred.
    const warmSync = { ...syncInput, verbose: true, mode: "startup-convergence" as const };

    function tokenWrites(logPath: string): number {
      return dockerExecCalls(logPath).filter((entry) => entry.stdin === "ghp_secret" || entry.stdin === "ghp_rotated").length;
    }

    async function populate(fakeDocker: { dockerLog: string; fakeBin: string }, hostOpBin: string): Promise<void> {
      selectEffectiveControlsFromProjectPolicy();
      const populated = await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin));
      expect(populated.status, populated.stderr).toBe(0);
      expect(readReceiptsFile().map((receipt) => receipt.tokenName)).toEqual(["github"]);
    }

    test("a current receipt for a held value: no source read and no token write", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      const opLogPath = path.join(tmpBase, `warm-op-${Math.random().toString(16).slice(2)}.jsonl`);
      installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      const writesBefore = tokenWrites(fakeDocker.dockerLog);

      const warm = await runAdmin(async () => {
        prepareRuntimeTokenSources({ mode: "convergence" });
        await credentialSyncIntent(warmSync);
      }, opEnv(fakeDocker, hostOpBin));

      expect(warm.status, warm.stderr).toBe(0);
      expect(readJsonLines(opLogPath)).toHaveLength(1);
      expect(tokenWrites(fakeDocker.dockerLog)).toBe(writesBefore);
      expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
    });

    test("a source read older than the warm bound is re-read before the lock and written", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      const opLogPath = path.join(tmpBase, `warm-old-op-${Math.random().toString(16).slice(2)}.jsonl`);
      installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      const [receipt] = readReceiptsFile();
      fs.writeFileSync(receiptsFilePath(), `${JSON.stringify({
        schemaVersion: 1,
        receipts: [{ ...receipt, resolvedAt: Date.now() - 16 * 60 * 1000 }],
      })}\n`);
      installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_rotated\n" });
      const writesBefore = tokenWrites(fakeDocker.dockerLog);

      const warm = await runAdmin(async () => {
        prepareRuntimeTokenSources({ mode: "convergence" });
        await credentialSyncIntent(warmSync);
      }, opEnv(fakeDocker, hostOpBin));

      expect(warm.status, warm.stderr).toBe(0);
      expect(readJsonLines(opLogPath)).toHaveLength(2);
      // The re-read value is written even though the ledger would call a
      // manual token populated: the warm bound is why it was re-read.
      expect(tokenWrites(fakeDocker.dockerLog)).toBe(writesBefore + 1);
      expect(dockerExecCalls(fakeDocker.dockerLog).map((entry) => entry.stdin)).toContain("ghp_rotated");
    });

    test("a changed source fingerprint is re-read before the lock and written", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      const opLogPath = path.join(tmpBase, `warm-fp-op-${Math.random().toString(16).slice(2)}.jsonl`);
      installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      writeTokenConfig({ github: { source: "1password", ref: "op://Private/GitHub/rotated" } });
      const writesBefore = tokenWrites(fakeDocker.dockerLog);

      const warm = await runAdmin(async () => {
        prepareRuntimeTokenSources({ mode: "convergence" });
        await credentialSyncIntent(warmSync);
      }, opEnv(fakeDocker, hostOpBin));

      expect(warm.status, warm.stderr).toBe(0);
      expect(readJsonLines(opLogPath).at(-1)).toEqual({ args: ["read", "op://Private/GitHub/rotated"] });
      expect(tokenWrites(fakeDocker.dockerLog)).toBe(writesBefore + 1);
    });

    test("a due token the preparation skipped defers before any source read, write, or removal", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      const opLogPath = path.join(tmpBase, `warm-defer-op-${Math.random().toString(16).slice(2)}.jsonl`);
      installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      const execsBefore = dockerExecCalls(fakeDocker.dockerLog).length;

      const deferred = await runAdmin(async () => {
        prepareRuntimeTokenSources({ mode: "convergence" });
        // Between preparation and the locked sync the receipt disappears, so
        // the sync finds the token due with no value it may write.
        fs.rmSync(receiptsFilePath());
        await credentialSyncIntent(warmSync);
      }, opEnv(fakeDocker, hostOpBin));

      expect(deferred.status).toBe(TOKEN_SYNC_DEFERRED_STATUS);
      expect(deferred.stdout).toContain("credential sync deferred to a source-truth sync: github is due and its source was not read before the lock");
      expect(readJsonLines(opLogPath)).toHaveLength(1);
      const execsAfter = dockerExecCalls(fakeDocker.dockerLog).slice(execsBefore);
      expect(execsAfter.filter((entry) => entry.stdin !== "")).toEqual([]);
      expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
    });

    test("a preparation whose inputs changed before the locked sync defers instead of failing the launch", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      const opLogPath = path.join(tmpBase, `warm-rebind-op-${Math.random().toString(16).slice(2)}.jsonl`);
      installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      const execsBefore = dockerExecCalls(fakeDocker.dockerLog).length;

      const deferred = await runAdmin(async () => {
        prepareRuntimeTokenSources({ mode: "convergence" });
        // The source config changes between preparation and the lock. The new
        // fingerprint makes the token due, and the due check runs before the
        // prepared-binding check, so the deferral names the unread source.
        writeTokenConfig({ github: { source: "1password", ref: "op://Private/GitHub/rotated" } });
        await credentialSyncIntent(warmSync);
      }, opEnv(fakeDocker, hostOpBin));

      expect(deferred.status).toBe(TOKEN_SYNC_DEFERRED_STATUS);
      expect(deferred.stdout).toContain("credential sync deferred to a source-truth sync: github is due and its source was not read before the lock");
      expect(readJsonLines(opLogPath)).toHaveLength(1);
      const execsAfter = dockerExecCalls(fakeDocker.dockerLog).slice(execsBefore);
      expect(execsAfter.filter((entry) => entry.stdin !== "")).toEqual([]);
      expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
    });

    test("a source changed after a re-read preparation defers instead of refusing, and a fresh preparation reclaims", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      const opLogPath = path.join(tmpBase, `warm-reread-fp-op-${Math.random().toString(16).slice(2)}.jsonl`);
      installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      const [receipt] = readReceiptsFile();
      // An old read: the preparation re-reads it, so its entry is resolved.
      fs.writeFileSync(receiptsFilePath(), `${JSON.stringify({ schemaVersion: 1, receipts: [{ ...receipt, resolvedAt: Date.now() - 16 * 60 * 1000 }] })}\n`);
      const writesBefore = tokenWrites(fakeDocker.dockerLog);
      let readsBeforeSync = -1;

      const deferred = await runAdmin(async () => {
        prepareRuntimeTokenSources({ mode: "convergence" });
        readsBeforeSync = readJsonLines(opLogPath).length;
        // The resolved entry no longer names the current source.
        writeTokenConfig({ github: { source: "1password", ref: "op://Private/GitHub/rotated" } });
        await credentialSyncIntent(warmSync);
      }, opEnv(fakeDocker, hostOpBin));

      expect(deferred.status).toBe(TOKEN_SYNC_DEFERRED_STATUS);
      expect(deferred.stdout).toContain("the prepared credential set no longer applies: prepared credential source changed");
      expect(readJsonLines(opLogPath)).toHaveLength(readsBeforeSync);
      expect(tokenWrites(fakeDocker.dockerLog)).toBe(writesBefore);
      expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);

      const reclaimed = await runAdmin(async () => {
        prepareRuntimeTokenSources({ mode: "convergence" });
        await credentialSyncIntent(warmSync);
      }, opEnv(fakeDocker, hostOpBin));
      expect(reclaimed.status, reclaimed.stderr).toBe(0);
      expect(readJsonLines(opLogPath).at(-1)).toEqual({ args: ["read", "op://Private/GitHub/rotated"] });
    });

    test("a preparation that expired before the locked sync defers instead of failing the launch", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      installFakeOp(hostOpBin, { output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);

      const realNow = Date.now;
      let deferred: Awaited<ReturnType<typeof runAdmin>>;
      try {
        deferred = await runAdmin(async () => {
          prepareRuntimeTokenSources({ mode: "convergence" });
          const preparedAt = realNow();
          Date.now = () => preparedAt + 121_000;
          await credentialSyncIntent(warmSync);
        }, opEnv(fakeDocker, hostOpBin));
      } finally {
        Date.now = realNow;
      }

      expect(deferred.status).toBe(TOKEN_SYNC_DEFERRED_STATUS);
      expect(deferred.stdout).toContain("credential sync deferred to a source-truth sync: the prepared credential set no longer applies: prepared credential inputs changed or expired");
      expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
    });

    test("a locked sync past its total time budget starts no further child process and defers", () => {
      const marker = path.join(tmpBase, `budget-${Math.random().toString(16).slice(2)}`);
      // A spent total: the call is refused before its process starts.
      expect(() => withAdminCallTimeout(20_000, () => runCapture("touch", [marker]), 0)).toThrow(TokenSyncDeferredError);
      expect(fs.existsSync(marker)).toBe(false);
      // Inside the total, the call runs.
      withAdminCallTimeout(20_000, () => runCapture("touch", [marker]), 30_000);
      expect(fs.existsSync(marker)).toBe(true);
    });

    test("a locked write that fails or times out defers and removes nothing", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      installFakeOp(hostOpBin, { output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      const [receipt] = readReceiptsFile();
      // An old read: the preparation re-reads it, so the locked sync writes.
      fs.writeFileSync(receiptsFilePath(), `${JSON.stringify({
        schemaVersion: 1,
        receipts: [{ ...receipt, resolvedAt: Date.now() - 16 * 60 * 1000 }],
      })}\n`);
      const writesBefore = tokenWrites(fakeDocker.dockerLog);

      const deferred = await runAdmin(async () => {
        prepareRuntimeTokenSources({ mode: "convergence" });
        await credentialSyncIntent(warmSync);
      }, { ...opEnv(fakeDocker, hostOpBin), FAKE_DOCKER_TOKEN_WRITE_STATUS: "124" });

      // A killed client may still land its write; removing after it could
      // race the late write, so the source-truth order retries instead.
      expect(deferred.status).toBe(TOKEN_SYNC_DEFERRED_STATUS);
      expect(deferred.stdout).toContain("credential sync deferred to a source-truth sync: github: proxy token write failed");
      // The deferral came from the failed write, not from an earlier step.
      expect(tokenWrites(fakeDocker.dockerLog)).toBe(writesBefore + 1);
      expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
    });

    test("a prepared-only sync with no preparation defers instead of resolving", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      const opLogPath = path.join(tmpBase, `warm-noprep-op-${Math.random().toString(16).slice(2)}.jsonl`);
      installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_secret\n" });
      selectEffectiveControlsFromProjectPolicy();

      const deferred = await runAdmin(() => credentialSyncIntent(warmSync), opEnv(fakeDocker, hostOpBin));

      expect(deferred.status).toBe(TOKEN_SYNC_DEFERRED_STATUS);
      expect(deferred.stdout).toContain("credential sync deferred to a source-truth sync: no prepared credential set for a prepared-only sync");
      expect(readJsonLines(opLogPath)).toHaveLength(0);
      expect(tokenWrites(fakeDocker.dockerLog)).toBe(0);
    });

    test("a busy token-store lock defers at once instead of waiting under the lifecycle lock", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      installFakeOp(hostOpBin, { output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      const lockPath = path.join(adminStateDir(), `token-store-sync-${projectHash(tmp)}.lock`);
      const holder = childProcess.spawn(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], { stdio: "ignore" });
      try {
        fs.mkdirSync(lockPath, { recursive: true });
        fs.writeFileSync(path.join(lockPath, "pid"), `${holder.pid}\n`);
        const startedAt = Date.now();
        const deferred = await runAdmin(async () => {
          prepareRuntimeTokenSources({ mode: "convergence" });
          await credentialSyncIntent(warmSync);
        }, { ...opEnv(fakeDocker, hostOpBin), RUNFREE_TEST_TOKEN_STORE_LOCK_WAIT_MS: "5000" });
        expect(deferred.status).toBe(TOKEN_SYNC_DEFERRED_STATUS);
        expect(deferred.stdout).toContain("credential sync deferred to a source-truth sync: another runfree command holds the token store lock");
        expect(Date.now() - startedAt).toBeLessThan(4_000);
        expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
      } finally {
        holder.kill("SIGKILL");
        fs.rmSync(lockPath, { recursive: true, force: true });
      }
    });

    test("a busy control lock defers instead of failing the launch and leaves no lock behind", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      installFakeOp(hostOpBin, { output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      const held = tryAcquireControlLock(adminProjectInfoForTokenSync());
      expect(held).toBeDefined();
      try {
        const deferred = await runAdmin(async () => {
          prepareRuntimeTokenSources({ mode: "convergence" });
          await credentialSyncIntent(warmSync);
        }, opEnv(fakeDocker, hostOpBin), { policyAccess: "effective-read-only" });
        expect(deferred.status).toBe(TOKEN_SYNC_DEFERRED_STATUS);
        expect(deferred.stdout).toContain("credential sync deferred to a source-truth sync: another control operation holds the control lock");
        expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
      } finally {
        held?.release();
      }
      // Reclaim: the deferral took and left no lock (startup's source-truth
      // fallback after a deferral is proved in runtime.test.ts).
      const free = tryAcquireControlLock(adminProjectInfoForTokenSync());
      expect(free).toBeDefined();
      free?.release();
    });

    // Record the selected effective policy generation as converged, the state
    // a warm launch reaches before its credential sync, and return the fake
    // proxy env that acknowledges that generation from both consumers.
    async function convergeSelectedGeneration(): Promise<NodeJS.ProcessEnv> {
      const project = adminProjectInfoForTokenSync();
      const active = readActiveEffectiveControl(project);
      if (!active) throw new Error("test setup: no selected effective policy generation");
      const ids = { controlGeneration: active.controlGeneration, policyGeneration: active.policyGeneration };
      await convergeEffectivePolicyGeneration(project, {
        probe: async () => ({
          firewall: { generation: ids.policyGeneration, ...ids, rulesetVerified: true },
          requestProxy: { generation: ids.policyGeneration, ...ids },
        }),
        stopRuntime: async () => {},
      });
      return { FAKE_PROXY_STATUS_CONTROL_GENERATION: ids.controlGeneration, FAKE_PROXY_STATUS_GENERATION: ids.policyGeneration };
    }

    // Docker round trips per launch scenario, counted at the fake (call
    // counts, not latency): preparation before the lock, then the locked
    // receipt-gated sync, in the state a warm launch reaches (validated
    // runtime proof, effective policy converged and acknowledged).
    async function launchDockerCalls(
      fakeDocker: { dockerLog: string; fakeBin: string },
      hostOpBin: string,
      env: NodeJS.ProcessEnv,
    ): Promise<Readonly<{ status: number; stderr: string; prepare: number; sync: number }>> {
      let start = 0;
      let prepared = 0;
      const result = await runAdmin(async () => {
        start = readJsonLines(fakeDocker.dockerLog).length;
        prepareRuntimeTokenSources({ mode: "convergence" });
        prepared = readJsonLines(fakeDocker.dockerLog).length;
        await credentialSyncIntent(warmSync);
      }, { ...opEnv(fakeDocker, hostOpBin), ...env }, { policyAccess: "effective-read-only", validatedRuntime: tokenSyncValidatedRuntime() });
      return { status: result.status, stderr: result.stderr, prepare: prepared - start, sync: readJsonLines(fakeDocker.dockerLog).length - prepared };
    }

    test("launch Docker call counts: clean zero-source launch", async () => {
      writeFixtureRepo({ hosts: ["api.example.com"], tokens: {} });
      selectEffectiveControlsFromProjectPolicy();
      const fakeDocker = installTokenSyncDockerFake();
      const launch = await launchDockerCalls(fakeDocker, makeHostOpBin(), await convergeSelectedGeneration());
      expect(launch.status, launch.stderr).toBe(0);
      // The shipped zero-token skip: nothing to spare, nothing to sync.
      expect({ prepare: launch.prepare, sync: launch.sync }).toEqual({ prepare: 0, sync: 0 });
    });

    test("launch Docker call counts: fresh credential-bearing launch that reads no source", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      installFakeOp(hostOpBin, { output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      const launch = await launchDockerCalls(fakeDocker, hostOpBin, await convergeSelectedGeneration());
      expect(launch.status, launch.stderr).toBe(0);
      // Preparation: one component inspect that also reads the incarnation, one
      // root exec for the marker and the held names, one incarnation reading
      // after it. Sync: the precheck's observation (marker and both
      // acknowledgements in one exec), the held-token listing under the
      // token-store lock, and the fence before persistence.
      expect({ prepare: launch.prepare, sync: launch.sync }).toEqual({ prepare: 3, sync: 6 });
    });

    test("launch Docker call counts: due source re-read before the lock and written", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      installFakeOp(hostOpBin, { output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      const [receipt] = readReceiptsFile();
      fs.writeFileSync(receiptsFilePath(), `${JSON.stringify({ schemaVersion: 1, receipts: [{ ...receipt, resolvedAt: Date.now() - 16 * 60 * 1000 }] })}\n`);
      const launch = await launchDockerCalls(fakeDocker, hostOpBin, await convergeSelectedGeneration());
      expect(launch.status, launch.stderr).toBe(0);
      // The written token adds only its write fence and the write: the value
      // was read before the lock, so no fence precedes taking it from memory.
      expect({ prepare: launch.prepare, sync: launch.sync }).toEqual({ prepare: 3, sync: 9 });
    });

    test("launch Docker call counts: proxy restarted since the receipt", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      installFakeOp(hostOpBin, { output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      const launch = await launchDockerCalls(fakeDocker, hostOpBin, {
        ...await convergeSelectedGeneration(),
        FAKE_DOCKER_STARTED_AT: "2026-06-18T00:05:00.000000000Z",
      });
      expect(launch.status, launch.stderr).toBe(0);
      // The receipt names the previous incarnation, so the source is re-read
      // before the lock and written: the same calls as a due source.
      expect({ prepare: launch.prepare, sync: launch.sync }).toEqual({ prepare: 3, sync: 9 });
    });

    describe("batched credential observations", () => {
      const launchState = () => ({ policyAccess: "effective-read-only" as const, validatedRuntime: tokenSyncValidatedRuntime() });
      const opLog = () => path.join(tmpBase, `batch-op-${Math.random().toString(16).slice(2)}.jsonl`);

      async function populatedLaunch(): Promise<{ fakeDocker: ReturnType<typeof installTokenSyncDockerFake>; hostOpBin: string; opLogPath: string; ackEnv: NodeJS.ProcessEnv }> {
        writeGithubOnePasswordFixture();
        const fakeDocker = installTokenSyncDockerFake();
        const hostOpBin = makeHostOpBin();
        const opLogPath = opLog();
        installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_secret\n" });
        await populate(fakeDocker, hostOpBin);
        return { fakeDocker, hostOpBin, opLogPath, ackEnv: await convergeSelectedGeneration() };
      }

      function heldListings(logPath: string, from = 0): number {
        return readJsonLines(logPath).slice(from).filter((entry) => Array.isArray(entry.args)
          && entry.args.join(" ").includes(CREDENTIAL_OBSERVATION_BATCH_HEADER) && entry.args.join(" ").includes("held-token-names")).length;
      }

      test.each(["truncated", "duplicate", "missing"])("a %s batch section in preparation skips no source read", async (corrupt) => {
        const { fakeDocker, hostOpBin, opLogPath, ackEnv } = await populatedLaunch();
        const arm = path.join(tmpBase, `corrupt-${corrupt}.arm`);
        const readsBefore = readJsonLines(opLogPath).length;

        const launch = await runAdmin(async () => {
          fs.writeFileSync(arm, "");
          prepareRuntimeTokenSources({ mode: "convergence" });
          fs.rmSync(arm);
          await credentialSyncIntent(warmSync);
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv, FAKE_DOCKER_OBSERVATION_CORRUPT: corrupt, FAKE_DOCKER_OBSERVATION_CORRUPT_ARM: arm }, launchState());

        expect(launch.status, launch.stderr).toBe(0);
        // The held value would have been spared; an unusable observation spares nothing.
        expect(readJsonLines(opLogPath)).toHaveLength(readsBefore + 1);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(2);
      });

      test.each(["truncated", "duplicate", "missing"])("a %s batch section in the locked sync refuses before any write, removal or persistence", async (corrupt) => {
        const { fakeDocker, hostOpBin, ackEnv } = await populatedLaunch();
        const [receipt] = readReceiptsFile();
        fs.writeFileSync(receiptsFilePath(), `${JSON.stringify({ schemaVersion: 1, receipts: [{ ...receipt, resolvedAt: Date.now() - 16 * 60 * 1000 }] })}\n`);
        const receiptsBefore = fs.readFileSync(receiptsFilePath(), "utf8");
        const arm = path.join(tmpBase, `corrupt-locked-${corrupt}.arm`);

        const launch = await runAdmin(async () => {
          prepareRuntimeTokenSources({ mode: "convergence" });
          fs.writeFileSync(arm, "");
          await credentialSyncIntent(warmSync);
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv, FAKE_DOCKER_OBSERVATION_CORRUPT: corrupt, FAKE_DOCKER_OBSERVATION_CORRUPT_ARM: arm }, launchState());

        expect(launch.status).not.toBe(0);
        expect(launch.stderr).toContain("runtime is proxy-unreachable");
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(1);
        expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
        expect(fs.readFileSync(receiptsFilePath(), "utf8")).toBe(receiptsBefore);
      });

      test("a component inspect without the incarnation field refuses the runtime before any source read or write", async () => {
        const { fakeDocker, hostOpBin, opLogPath, ackEnv } = await populatedLaunch();
        const readsBefore = readJsonLines(opLogPath).length;

        const launch = await runAdmin(async () => {
          prepareRuntimeTokenSources({ mode: "convergence" });
          await credentialSyncIntent(warmSync);
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv, FAKE_DOCKER_COMPONENT_ROW_SHAPE: "without-started-at" }, launchState());

        expect(launch.status).not.toBe(0);
        expect(launch.stderr).toContain("runtime component container identities changed");
        // Preparation skipped nothing (one read); the locked sync refused before writing it.
        expect(readJsonLines(opLogPath)).toHaveLength(readsBefore + 1);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(1);
        expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
      });

      test("a same-ID restart inside the preparation observation spares no read, and the locked sync writes to the new incarnation", async () => {
        const { fakeDocker, hostOpBin, opLogPath, ackEnv } = await populatedLaunch();
        const arm = path.join(tmpBase, "prepare-restart.arm");
        fs.writeFileSync(arm, "");
        const readsBefore = readJsonLines(opLogPath).length;
        const result = await runAdmin(async () => {
          prepareRuntimeTokenSources({ mode: "convergence" });
          // The restart wiped the proxy tmpfs.
          fakeDocker.heldTokens.clear();
          await credentialSyncIntent(warmSync);
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv, FAKE_DOCKER_RESTART_ON_LISTING_ARM: arm }, launchState());

        expect(fs.existsSync(`${arm}.restarted`)).toBe(true);
        expect(result.status, result.stderr).toBe(0);
        expect(readJsonLines(opLogPath)).toHaveLength(readsBefore + 1);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(2);
        // The receipt binds the new incarnation: the next launch against it
        // spares the read again.
        const next = await launchDockerCalls(fakeDocker, hostOpBin, { ...ackEnv, FAKE_DOCKER_RESTART_ON_LISTING_ARM: arm });
        expect(next.status, next.stderr).toBe(0);
        expect(readJsonLines(opLogPath)).toHaveLength(readsBefore + 1);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(2);
      });

      test("a proxy replaced after the locked listing refuses the write; a retry against the live proxy succeeds", async () => {
        const { fakeDocker, hostOpBin, ackEnv } = await populatedLaunch();
        const [receipt] = readReceiptsFile();
        fs.writeFileSync(receiptsFilePath(), `${JSON.stringify({ schemaVersion: 1, receipts: [{ ...receipt, resolvedAt: Date.now() - 16 * 60 * 1000 }] })}\n`);
        const arm = path.join(tmpBase, "replace.arm");

        const refused = await runAdmin(async () => {
          prepareRuntimeTokenSources({ mode: "convergence" });
          fs.writeFileSync(arm, "");
          await credentialSyncIntent(warmSync);
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv, FAKE_DOCKER_REPLACE_ON_LISTING_ARM: arm }, launchState());

        expect(fs.existsSync(`${arm}.replaced`)).toBe(true);
        expect(refused.status).not.toBe(0);
        expect(`${refused.stdout}${refused.stderr}`).toContain("exact proxy or token store changed during credential resolution");
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(1);
        expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);

        const retried = await launchDockerCalls(fakeDocker, hostOpBin, ackEnv);
        expect(retried.status, retried.stderr).toBe(0);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(2);
      });

      test("a held file deleted after preparation makes the token due, and the locked sync defers before any write", async () => {
        const { fakeDocker, hostOpBin, opLogPath, ackEnv } = await populatedLaunch();
        const readsBefore = readJsonLines(opLogPath).length;

        const deferred = await runAdmin(async () => {
          prepareRuntimeTokenSources({ mode: "convergence" });
          fakeDocker.heldTokens.delete("github");
          await credentialSyncIntent(warmSync);
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv }, launchState());

        expect(deferred.status).toBe(TOKEN_SYNC_DEFERRED_STATUS);
        expect(deferred.stdout).toContain("github is due and its source was not read before the lock");
        // The preparation's held set spared the read; the locked listing, not
        // the preparation's evidence, decided the write.
        expect(readJsonLines(opLogPath)).toHaveLength(readsBefore);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(1);
        expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
      });

      test("a changed consumer acknowledgement refuses the locked sync before any write; matching acknowledgements reclaim it", async () => {
        const { fakeDocker, hostOpBin, ackEnv } = await populatedLaunch();
        const [receipt] = readReceiptsFile();
        fs.writeFileSync(receiptsFilePath(), `${JSON.stringify({ schemaVersion: 1, receipts: [{ ...receipt, resolvedAt: Date.now() - 16 * 60 * 1000 }] })}\n`);

        const refused = await runAdmin(async () => {
          prepareRuntimeTokenSources({ mode: "convergence" });
          await credentialSyncIntent(warmSync);
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv, FAKE_PROXY_STATUS_GENERATION: "sha256:another-generation" }, launchState());

        expect(refused.status).not.toBe(0);
        expect(refused.stderr).toContain("credential resolution requires request-proxy and firewall acknowledgement of the selected effective policy generation");
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(1);
        expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);

        const reclaimed = await launchDockerCalls(fakeDocker, hostOpBin, ackEnv);
        expect(reclaimed.status, reclaimed.stderr).toBe(0);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(2);
      });

      test("an effective policy selected after preparation refuses the locked sync before any write; converging it reclaims", async () => {
        const { fakeDocker, hostOpBin } = await populatedLaunch();
        const [receipt] = readReceiptsFile();
        fs.writeFileSync(receiptsFilePath(), `${JSON.stringify({ schemaVersion: 1, receipts: [{ ...receipt, resolvedAt: Date.now() - 16 * 60 * 1000 }] })}\n`);
        const staleAckEnv = await convergeSelectedGeneration();

        const refused = await runAdmin(async () => {
          prepareRuntimeTokenSources({ mode: "convergence" });
          // Another host reselects a policy generation between preparation and the lock.
          const policy = readPolicy();
          fs.writeFileSync(path.join(tmp, ".runfree/network-policy.json"), `${JSON.stringify({ ...policy, hosts: [...policy.hosts ?? [], "drift.example.com"] }, null, 2)}\n`);
          selectEffectiveControlsFromProjectPolicy();
          await credentialSyncIntent(warmSync);
        }, { ...opEnv(fakeDocker, hostOpBin), ...staleAckEnv }, launchState());

        expect(refused.status).not.toBe(0);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(1);
        expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);

        const reclaimed = await launchDockerCalls(fakeDocker, hostOpBin, await convergeSelectedGeneration());
        expect(reclaimed.status, reclaimed.stderr).toBe(0);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(2);
      });

      test("token-store lock contention defers the locked sync before it lists held tokens", async () => {
        const { fakeDocker, hostOpBin, ackEnv } = await populatedLaunch();
        const lockPath = path.join(adminStateDir(), `token-store-sync-${projectHash(tmp)}.lock`);
        const holder = childProcess.spawn(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], { stdio: "ignore" });
        let prepared = 0;
        try {
          fs.mkdirSync(lockPath, { recursive: true });
          fs.writeFileSync(path.join(lockPath, "pid"), `${holder.pid}\n`);
          const deferred = await runAdmin(async () => {
            prepareRuntimeTokenSources({ mode: "convergence" });
            prepared = readJsonLines(fakeDocker.dockerLog).length;
            await credentialSyncIntent(warmSync);
          }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv }, launchState());
          expect(deferred.status).toBe(TOKEN_SYNC_DEFERRED_STATUS);
          expect(heldListings(fakeDocker.dockerLog, prepared)).toBe(0);
          expect(tokenWrites(fakeDocker.dockerLog)).toBe(1);
        } finally {
          holder.kill("SIGKILL");
          fs.rmSync(lockPath, { recursive: true, force: true });
        }
        // Reclaim: once the holder is gone the same launch completes.
        const free = await launchDockerCalls(fakeDocker, hostOpBin, ackEnv);
        expect(free.status, free.stderr).toBe(0);
      });

      test("a receipt reused without a read keeps its age; past the warm bound it is read again", async () => {
        const { fakeDocker, hostOpBin, opLogPath, ackEnv } = await populatedLaunch();
        const [receipt] = readReceiptsFile();
        const readsBefore = readJsonLines(opLogPath).length;

        const reused = await launchDockerCalls(fakeDocker, hostOpBin, ackEnv);
        expect(reused.status, reused.stderr).toBe(0);
        expect(readJsonLines(opLogPath)).toHaveLength(readsBefore);
        expect(readReceiptsFile()).toEqual([receipt]);

        fs.writeFileSync(receiptsFilePath(), `${JSON.stringify({ schemaVersion: 1, receipts: [{ ...receipt, resolvedAt: Date.now() - 16 * 60 * 1000 }] })}\n`);
        const expired = await launchDockerCalls(fakeDocker, hostOpBin, ackEnv);
        expect(expired.status, expired.stderr).toBe(0);
        expect(readJsonLines(opLogPath)).toHaveLength(readsBefore + 1);
        expect(readReceiptsFile()[0].resolvedAt).toBeGreaterThan(receipt.resolvedAt);
      });
    });

    // A cold launch prepares every source before it takes the lifecycle lock;
    // the prepared source-truth sync then publishes that set under the held
    // lock and reads nothing. Anything it cannot publish from the prepared set
    // alone defers before an effect, and startup takes the unlocked order.
    describe("prepared source-truth sync under a held lifecycle lock", () => {
      const launchState = () => ({ policyAccess: "effective-read-only" as const, validatedRuntime: tokenSyncValidatedRuntime() });
      let restoreClock: () => void = () => {};
      afterEach(() => {
        restoreClock();
        restoreClock = () => {};
      });
      const coldSync = (holdDeadlineMonotonicMs = performance.now() + 8_000) => ({
        ...syncInput,
        verbose: true,
        mode: "prepared-source-truth" as const,
        holdDeadlineMonotonicMs,
      });

      async function coldLaunch(): Promise<{ fakeDocker: ReturnType<typeof installTokenSyncDockerFake>; hostOpBin: string; opLogPath: string; ackEnv: NodeJS.ProcessEnv }> {
        writeGithubOnePasswordFixture();
        selectEffectiveControlsFromProjectPolicy();
        const fakeDocker = installTokenSyncDockerFake();
        const hostOpBin = makeHostOpBin();
        const opLogPath = path.join(tmpBase, `cold-op-${Math.random().toString(16).slice(2)}.jsonl`);
        installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_secret\n" });
        return { fakeDocker, hostOpBin, opLogPath, ackEnv: await convergeSelectedGeneration() };
      }

      test("no provider runs under lock", async () => {
        const { fakeDocker, hostOpBin, opLogPath, ackEnv } = await coldLaunch();
        let readsBeforeSync = -1;
        let preparedBefore = 0;
        let preparedAfter = 0;
        let syncStartedAt = 0;
        const realNow = Date.now;
        const published = await runAdmin(async () => {
          preparedBefore = Date.now();
          prepareRuntimeTokenSources();
          preparedAfter = Date.now();
          readsBeforeSync = readJsonLines(opLogPath).length;
          // The lock is taken a while after the preparation finished.
          Date.now = () => realNow() + 30_000;
          restoreClock = () => { Date.now = realNow; };
          syncStartedAt = Date.now();
          await credentialSyncIntent(coldSync());
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv }, launchState());
        restoreClock();

        expect(published.status, published.stderr).toBe(0);
        expect(readsBeforeSync).toBe(1);
        // The locked sync read nothing: the one read is the preparation's.
        expect(readJsonLines(opLogPath)).toHaveLength(1);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(1);
        // The receipt keeps the age of the read before the lock; reusing the
        // value under the lock does not make it younger.
        const [receipt] = readReceiptsFile();
        expect(receipt.tokenName).toBe("github");
        expect(receipt.resolvedAt).toBeGreaterThanOrEqual(preparedBefore);
        expect(receipt.resolvedAt).toBeLessThanOrEqual(preparedAfter);
        expect(preparedAfter).toBeLessThan(syncStartedAt);
        expect(published.stdout).not.toContain("credential sync deferred");
      });

      test("many credentials publish from one preparation with no source read under the lock", async () => {
        const names = Array.from({ length: 12 }, (_, index) => `svc-${String(index).padStart(2, "0")}`);
        writeFixtureRepo({
          hosts: names.map((name) => `${name}.example.com`),
          tokens: Object.fromEntries(names.map((name) => [name, {
            description: `${name} token`,
            credentials: [{ host: `${name}.example.com`, header: "Authorization", scheme: "bearer" }],
          }])),
        });
        writeTokenConfig(Object.fromEntries(names.map((name) => [name, { source: "1password", ref: `op://Private/${name}/token` }])));
        selectEffectiveControlsFromProjectPolicy();
        const fakeDocker = installTokenSyncDockerFake();
        const hostOpBin = makeHostOpBin();
        const opLogPath = path.join(tmpBase, `cold-many-op-${Math.random().toString(16).slice(2)}.jsonl`);
        installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_secret\n" });
        const ackEnv = await convergeSelectedGeneration();

        let readsBeforeSync = -1;
        const published = await runAdmin(async () => {
          prepareRuntimeTokenSources();
          readsBeforeSync = readJsonLines(opLogPath).length;
          await credentialSyncIntent(coldSync());
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv }, launchState());

        expect(published.status, published.stderr).toBe(0);
        expect(readsBeforeSync).toBe(names.length);
        expect(readJsonLines(opLogPath)).toHaveLength(names.length);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(names.length);
        expect(readReceiptsFile().map((receipt) => receipt.tokenName).sort()).toEqual(names);
      });

      test.each([
        ["no preparation", "no prepared credential set", (_hostOpBin: string) => {}],
        ["an incomplete (receipt-gated) preparation", "github is due and its source was not read before the lock", (_hostOpBin: string) => {
          prepareRuntimeTokenSources({ mode: "convergence" });
        }],
        ["an expired preparation", "prepared credential inputs changed or expired", (_hostOpBin: string) => {
          prepareRuntimeTokenSources();
          const preparedAt = Date.now();
          const realNow = Date.now;
          Date.now = () => preparedAt + 121_000;
          restoreClock = () => { Date.now = realNow; };
        }],
        ["a source changed while waiting for the lock", "prepared credential source changed", (_hostOpBin: string) => {
          prepareRuntimeTokenSources();
          writeTokenConfig({ github: { source: "1password", ref: "op://Private/GitHub/rotated" } });
        }],
      ] as const)("expired or incomplete prepared set defers before effects: %s", async (_label, reason, arrange) => {
        const { fakeDocker, hostOpBin, opLogPath, ackEnv } = await coldLaunch();
        // A held value from an earlier launch, which a deferral must not touch.
        const populated = await runAdmin(() => credentialSyncIntent(syncInput), { ...opEnv(fakeDocker, hostOpBin), ...ackEnv });
        expect(populated.status, populated.stderr).toBe(0);
        const receiptsBefore = fs.readFileSync(receiptsFilePath(), "utf8");
        const writesBefore = tokenWrites(fakeDocker.dockerLog);
        let readsBeforeSync = -1;
        try {
          const deferred = await runAdmin(async () => {
            arrange(hostOpBin);
            readsBeforeSync = readJsonLines(opLogPath).length;
            await credentialSyncIntent(coldSync());
          }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv }, launchState());
          // The preparation itself is the reason: the caller reads it again.
          expect(deferred.status, deferred.stderr).toBe(TOKEN_SYNC_REPREPARE_STATUS);
          expect(deferred.stdout).toContain("credential sync deferred to a source-truth sync that reads every source again");
          expect(deferred.stdout).toContain(reason);
        } finally {
          restoreClock();
          restoreClock = () => {};
        }
        expect(readJsonLines(opLogPath)).toHaveLength(readsBeforeSync);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(writesBefore);
        expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
        expect(fs.readFileSync(receiptsFilePath(), "utf8")).toBe(receiptsBefore);

        // Reclaim: a fresh, complete preparation publishes.
        const reclaimed = await runAdmin(async () => {
          prepareRuntimeTokenSources();
          await credentialSyncIntent(coldSync());
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv }, launchState());
        expect(reclaimed.status, reclaimed.stderr).toBe(0);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(writesBefore + 1);
      });

      test("an effective policy selected while waiting refuses before any write; converging it reclaims", async () => {
        const { fakeDocker, hostOpBin } = await coldLaunch();
        const staleAckEnv = await convergeSelectedGeneration();
        const refused = await runAdmin(async () => {
          prepareRuntimeTokenSources();
          const policy = readPolicy();
          fs.writeFileSync(path.join(tmp, ".runfree/network-policy.json"), `${JSON.stringify({ ...policy, hosts: [...policy.hosts ?? [], "drift.example.com"] }, null, 2)}\n`);
          selectEffectiveControlsFromProjectPolicy();
          await credentialSyncIntent(coldSync());
        }, { ...opEnv(fakeDocker, hostOpBin), ...staleAckEnv }, launchState());
        expect(refused.status).not.toBe(0);
        expect(refused.status).not.toBe(TOKEN_SYNC_DEFERRED_STATUS);
        expect(refused.status).not.toBe(TOKEN_SYNC_REPREPARE_STATUS);
        expect(refused.stderr).toContain("credential resolution requires");
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(0);
        expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);

        const reclaimed = await runAdmin(async () => {
          prepareRuntimeTokenSources();
          await credentialSyncIntent(coldSync());
        }, { ...opEnv(fakeDocker, hostOpBin), ...await convergeSelectedGeneration() }, launchState());
        expect(reclaimed.status, reclaimed.stderr).toBe(0);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(1);
      });

      test("a named source changed while waiting for the lock defers before any read or write, and a fresh preparation reclaims", async () => {
        writeGithubOnePasswordFixture();
        selectEffectiveControlsFromProjectPolicy();
        const fakeSource = installFakeCommandSource();
        expect((await runAdmin(() => sourceAddCommandIntent({ name: "github-cli", replaceSource: false, command: ["gh", "auth", "token"] }), {
          PATH: fakeSource.fakeBin,
        })).status).toBe(0);
        writeTokenConfig({ github: { source: "named", name: "github-cli" } });
        const fakeDocker = installTokenSyncDockerFake();
        const ackEnv = await convergeSelectedGeneration();
        const env = { FAKE_DOCKER_LOG: fakeDocker.dockerLog, PATH: `${fakeDocker.fakeBin}${path.delimiter}${fakeSource.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`, ...ackEnv };
        const secretWrites = (): number => dockerExecCalls(fakeDocker.dockerLog).filter((entry) => entry.stdin === "command-secret").length;
        let readsBeforeSync = -1;

        const deferred = await runAdmin(async () => {
          prepareRuntimeTokenSources();
          readsBeforeSync = readCommandSourceLog(fakeSource.logPath).length;
          // The named source is redefined between the preparation and the lock.
          const registry = JSON.parse(fs.readFileSync(sourceRegistryPath(), "utf8")) as Record<string, Record<string, unknown>>;
          const entry = registry["github-cli"] as Record<string, unknown>;
          fs.writeFileSync(sourceRegistryPath(), `${JSON.stringify({ ...registry, "github-cli": { ...entry, argv: [...entry.argv as string[], "--hostname", "other.example"] } }, null, 2)}\n`);
          await credentialSyncIntent(coldSync());
        }, env, launchState());

        expect(deferred.status, `${deferred.stdout}${deferred.stderr}`).toBe(TOKEN_SYNC_REPREPARE_STATUS);
        expect(readCommandSourceLog(fakeSource.logPath)).toHaveLength(readsBeforeSync);
        expect(secretWrites()).toBe(0);
        expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);

        const reclaimed = await runAdmin(async () => {
          prepareRuntimeTokenSources();
          await credentialSyncIntent(coldSync());
        }, env, launchState());
        expect(reclaimed.status, reclaimed.stderr).toBe(0);
        expect(secretWrites()).toBe(1);
      });

      test("a preparation that expires between two writes defers for a re-read; the first write stands without a receipt and the fallback rewrites both", async () => {
        writeFixtureRepo({
          hosts: ["api.github.com", "api.example.com"],
          tokens: {
            github: { description: "GitHub token", credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }] },
            other: { description: "Other token", credentials: [{ host: "api.example.com", header: "Authorization", scheme: "bearer" }] },
          },
        });
        writeTokenConfig({
          github: { source: "1password", ref: "op://Private/GitHub/token" },
          other: { source: "1password", ref: "op://Private/Other/token" },
        });
        selectEffectiveControlsFromProjectPolicy();
        const realNow = Date.now;
        let expireOnWrite = false;
        const fakeDocker = installTokenSyncDockerFake({
          onTokenWrite: () => {
            if (!expireOnWrite) return;
            expireOnWrite = false;
            const at = realNow() + 121_000;
            Date.now = () => at;
            restoreClock = () => { Date.now = realNow; };
          },
        });
        const hostOpBin = makeHostOpBin();
        installFakeOp(hostOpBin, { output: "ghp_secret\n" });
        const ackEnv = await convergeSelectedGeneration();

        const deferred = await runAdmin(async () => {
          prepareRuntimeTokenSources();
          expireOnWrite = true;
          await credentialSyncIntent(coldSync());
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv }, launchState());
        restoreClock();
        restoreClock = () => {};

        expect(deferred.status, deferred.stderr).toBe(TOKEN_SYNC_REPREPARE_STATUS);
        expect(deferred.stdout).toContain("prepared credential inputs changed or expired");
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(1);
        expect(tokenRemovalCount(fakeDocker.dockerLog, "github")).toBe(0);
        expect(tokenRemovalCount(fakeDocker.dockerLog, "other")).toBe(0);
        expect(readReceiptsFile()).toEqual([]);

        // The unlocked fallback: read again, then the ordinary source-truth sync.
        const fallback = await runAdmin(async () => {
          prepareRuntimeTokenSources();
          await credentialSyncIntent(syncInput);
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv }, launchState());
        expect(fallback.status, fallback.stderr).toBe(0);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(3);
        expect(readReceiptsFile().map((receipt) => receipt.tokenName).sort()).toEqual(["github", "other"]);
      });

      test("a partial publication (one write landed, the next failed) records no receipt, and the fallback reuses the preparation", async () => {
        writeFixtureRepo({
          hosts: ["api.github.com", "api.example.com"],
          tokens: {
            github: { description: "GitHub token", credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }] },
            other: { description: "Other token", credentials: [{ host: "api.example.com", header: "Authorization", scheme: "bearer" }] },
          },
        });
        writeTokenConfig({
          github: { source: "1password", ref: "op://Private/GitHub/token" },
          other: { source: "1password", ref: "op://Private/Other/token" },
        });
        selectEffectiveControlsFromProjectPolicy();
        const fakeDocker = installTokenSyncDockerFake();
        const hostOpBin = makeHostOpBin();
        const opLogPath = path.join(tmpBase, `cold-partial-op-${Math.random().toString(16).slice(2)}.jsonl`);
        installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_secret\n" });
        const ackEnv = await convergeSelectedGeneration();

        const deferred = await runAdmin(async () => {
          prepareRuntimeTokenSources();
          await credentialSyncIntent(coldSync());
          // The fallback after a write failure: the same preparation, the
          // ordinary source-truth sync, no second read.
          await credentialSyncIntent(syncInput);
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv, FAKE_DOCKER_TOKEN_WRITE_STATUS: "124", FAKE_DOCKER_TOKEN_WRITE_STATUS_TOKEN: "other" }, launchState());

        expect(deferred.stdout).toContain("other: proxy token write failed");
        // The first write landed; the held-lock pass persisted nothing.
        expect(readJsonLines(opLogPath)).toHaveLength(2);
        expect(tokenRemovalCount(fakeDocker.dockerLog, "github")).toBe(0);
        // The fallback rewrote github and failed other again (the fake still fails it): receipts name only what it wrote.
        expect(readReceiptsFile().map((receipt) => receipt.tokenName)).toEqual(["github"]);
      });

      test.each(["SIGTERM", "SIGKILL", "timeout"])("a write client ended by %s under the lock defers without a removal or receipt change, and the fallback writes again", async (kill) => {
        const { fakeDocker, hostOpBin, ackEnv } = await coldLaunch();
        const deferred = await runAdmin(async () => {
          prepareRuntimeTokenSources();
          await credentialSyncIntent(coldSync());
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv, FAKE_DOCKER_TOKEN_WRITE_KILL: kill }, launchState());
        expect(deferred.status, deferred.stderr).toBe(TOKEN_SYNC_DEFERRED_STATUS);
        expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
        expect(readReceiptsFile()).toEqual([]);
        const writesAfterKill = tokenWrites(fakeDocker.dockerLog);

        const fallback = await runAdmin(async () => {
          prepareRuntimeTokenSources();
          await credentialSyncIntent(syncInput);
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv }, launchState());
        expect(fallback.status, fallback.stderr).toBe(0);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(writesAfterKill + 1);
        expect(readReceiptsFile().map((receipt) => receipt.tokenName)).toEqual(["github"]);
      });

      test("8s boundary uses original clock", async () => {
        const { fakeDocker, hostOpBin, opLogPath, ackEnv } = await coldLaunch();
        let logBefore = 0;
        const deferred = await runAdmin(async () => {
          prepareRuntimeTokenSources();
          logBefore = readJsonLines(fakeDocker.dockerLog).length;
          // The allowance ends 8 s after the lock was taken, not after this
          // sync started: an allowance already spent dispatches nothing.
          await credentialSyncIntent(coldSync(performance.now() - 1));
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv }, launchState());

        expect(deferred.status).toBe(TOKEN_SYNC_DEFERRED_STATUS);
        expect(deferred.stdout).toContain("the startup lock-hold allowance is spent");
        expect(readJsonLines(fakeDocker.dockerLog).slice(logBefore)).toEqual([]);
        expect(readJsonLines(opLogPath)).toHaveLength(1);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(0);
      });

      test("a missing deadline is refused rather than read as an unbounded hold", async () => {
        const { fakeDocker, hostOpBin, ackEnv } = await coldLaunch();
        const refused = await runAdmin(async () => {
          prepareRuntimeTokenSources();
          await credentialSyncIntent({ ...syncInput, mode: "prepared-source-truth" });
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv }, launchState());
        expect(refused.status).toBe(TOKEN_SYNC_DEFERRED_STATUS);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(0);
      });

      test("a write that fails under the lock defers, removes nothing, and persists no receipt", async () => {
        const { fakeDocker, hostOpBin, ackEnv } = await coldLaunch();
        const deferred = await runAdmin(async () => {
          prepareRuntimeTokenSources();
          await credentialSyncIntent(coldSync());
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv, FAKE_DOCKER_TOKEN_WRITE_STATUS: "124" }, launchState());
        expect(deferred.status).toBe(TOKEN_SYNC_DEFERRED_STATUS);
        expect(deferred.stdout).toContain("github: proxy token write failed");
        expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
        // A partial publication manufactures no receipt.
        expect(readReceiptsFile()).toEqual([]);
      });

      test("same-ID restart refuses", async () => {
        const { fakeDocker, hostOpBin, ackEnv } = await coldLaunch();
        const arm = path.join(tmpBase, `cold-restart-${Math.random().toString(16).slice(2)}.arm`);
        const refused = await runAdmin(async () => {
          prepareRuntimeTokenSources();
          // The proxy restarts in place right after the locked held-token
          // listing: same container ID, a new token store.
          fs.writeFileSync(arm, "");
          await credentialSyncIntent(coldSync());
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv, FAKE_DOCKER_RESTART_ON_LISTING_ARM: arm }, launchState());

        expect(fs.existsSync(`${arm}.restarted`)).toBe(true);
        expect(refused.status).not.toBe(0);
        expect(refused.status).not.toBe(TOKEN_SYNC_DEFERRED_STATUS);
        expect(`${refused.stdout}${refused.stderr}`).toContain("exact proxy or token store changed during credential resolution");
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(0);
        expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
        expect(readReceiptsFile()).toEqual([]);

        // Retry against the new incarnation publishes.
        fs.rmSync(arm);
        const retried = await runAdmin(async () => {
          prepareRuntimeTokenSources();
          await credentialSyncIntent(coldSync());
        }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv, FAKE_DOCKER_RESTART_ON_LISTING_ARM: arm }, launchState());
        expect(retried.status, retried.stderr).toBe(0);
        expect(tokenWrites(fakeDocker.dockerLog)).toBe(1);
        expect(readReceiptsFile().map((receipt) => receipt.tokenName)).toEqual(["github"]);
      });
    });

    test("a warm sync with nothing to write observes the proxy once more for the write fence and never lists compose containers", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      installFakeOp(hostOpBin, { output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      const ackEnv = await convergeSelectedGeneration();
      const writesBefore = tokenWrites(fakeDocker.dockerLog);
      // Count only the sync: preparation's own observation happens before the
      // control lock and is not part of this sync's proof.
      let logBefore = 0;

      const warm = await runAdmin(async () => {
        prepareRuntimeTokenSources({ mode: "convergence" });
        logBefore = readJsonLines(fakeDocker.dockerLog).length;
        await credentialSyncIntent(warmSync);
      }, { ...opEnv(fakeDocker, hostOpBin), ...ackEnv }, { policyAccess: "effective-read-only", validatedRuntime: tokenSyncValidatedRuntime() });

      expect(warm.status, warm.stderr).toBe(0);
      expect(tokenWrites(fakeDocker.dockerLog)).toBe(writesBefore);
      const log = readJsonLines(fakeDocker.dockerLog).slice(logBefore).filter((entry) => Array.isArray(entry.args));
      const joined = log.map((entry) => (entry.args as string[]).join(" "));
      const markerReads = joined.filter((args) => args.startsWith("exec") && args.includes(CREDENTIAL_OBSERVATION_BATCH_HEADER) && args.includes("validation-marker")).length;
      const startedAtReads = joined.filter((args) => args.includes("{{.State.StartedAt}}")).length;
      const composeLookups = joined.filter((args) => args.startsWith("ps") || args.startsWith("container ls")).length;
      // The precheck reads its incarnation before (grouped into the component
      // inspect) and after its batch; the write fence reads it once more.
      expect({ markerReads, startedAtReads, composeLookups }).toEqual({ markerReads: 2, startedAtReads: 3, composeLookups: 0 });
    });

    test("an effective-policy watcher reads no source while another control operation holds the control lock, and reads it once the lock is free", async () => {
      // The watcher reads sources before its lock; the same precheck the
      // locked pass runs still comes first.
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      const opLogPath = path.join(tmpBase, `watch-busy-op-${Math.random().toString(16).slice(2)}.jsonl`);
      installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      const ackEnv = await convergeSelectedGeneration();
      const watchInput = { ...syncInput, watch: true, initialSourceTruth: true };
      const watchEnv = { ...opEnv(fakeDocker, hostOpBin), ...ackEnv, RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "1", RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "1" };
      const stateOverrides = { policyAccess: "effective-read-only" as const, validatedRuntime: tokenSyncValidatedRuntime() };
      const readsBefore = readJsonLines(opLogPath).length;
      const held = tryAcquireControlLock(adminProjectInfoForTokenSync());
      expect(held).toBeDefined();
      try {
        const busy = await runAdmin(() => credentialSyncIntent(watchInput), watchEnv, stateOverrides);
        expect(busy.stderr).toContain("credential resolution cannot start while another control operation is in progress");
        expect(readJsonLines(opLogPath)).toHaveLength(readsBefore);
        expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
      } finally {
        held?.release();
      }
      const free = await runAdmin(() => credentialSyncIntent(watchInput), watchEnv, stateOverrides);
      expect(free.status, free.stderr).toBe(0);
      expect(readJsonLines(opLogPath)).toHaveLength(readsBefore + 1);
      expect(readTokenStatus().github).toMatchObject({ ok: true, state: "ok" });
    });

    test("a warm sync refuses the token write when the proxy restarts after the precheck observed it", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      installFakeOp(hostOpBin, { output: "ghp_secret\n" });
      // No populate: with no receipt the token is due, so the sync reaches a write.
      selectEffectiveControlsFromProjectPolicy();
      const ackEnv = await convergeSelectedGeneration();
      const restartArm = path.join(tmpBase, `warm-restart-${Math.random().toString(16).slice(2)}.arm`);

      const result = await runAdmin(async () => {
        prepareRuntimeTokenSources({ mode: "convergence" });
        // Arm after preparation, so the restart lands after the sync's own
        // held-token listing, which runs after the precheck observed the proxy.
        fs.writeFileSync(restartArm, "");
        await credentialSyncIntent(warmSync);
      }, {
        ...opEnv(fakeDocker, hostOpBin),
        ...ackEnv,
        FAKE_DOCKER_RESTART_ON_LISTING_ARM: restartArm,
      }, { policyAccess: "effective-read-only", validatedRuntime: tokenSyncValidatedRuntime() });

      // The restart happened: the held-token listing ran under the precheck's
      // observation, and the write fence then saw a new store generation.
      expect(fs.existsSync(`${restartArm}.restarted`)).toBe(true);
      expect(result.status).not.toBe(0);
      expect(`${result.stdout}${result.stderr}`).toContain("exact proxy or token store changed during credential resolution");
      expect(tokenWrites(fakeDocker.dockerLog)).toBe(0);
      expect(readReceiptsFile()).toHaveLength(0);
    });

    test("a warm sync refuses before any write when the proxy restarts during the precheck's own observation, and a retry then succeeds", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      installFakeOp(hostOpBin, { output: "ghp_secret\n" });
      // No populate: with no receipt the token is due, so the sync reaches a write.
      selectEffectiveControlsFromProjectPolicy();
      const ackEnv = await convergeSelectedGeneration();
      const restartArm = path.join(tmpBase, `warm-restart-status-${Math.random().toString(16).slice(2)}.arm`);

      const refused = await runAdmin(async () => {
        prepareRuntimeTokenSources({ mode: "convergence" });
        // Arm after preparation, so the restart lands on the precheck's own
        // policy-acknowledgement status read -- before the sync's own
        // held-token listing runs, let alone any write.
        fs.writeFileSync(restartArm, "");
        await credentialSyncIntent(warmSync);
      }, {
        ...opEnv(fakeDocker, hostOpBin),
        ...ackEnv,
        FAKE_DOCKER_RESTART_ON_STATUS_ARM: restartArm,
      }, { policyAccess: "effective-read-only", validatedRuntime: tokenSyncValidatedRuntime() });

      // The restart happened inside the precheck's own batched observation
      // (marker and acknowledgements in one exec): the incarnation read after
      // it differs from the one read before, so nothing of that batch is
      // evidence and the sync stops before its own work starts.
      expect(fs.existsSync(`${restartArm}.restarted`)).toBe(true);
      expect(refused.status).not.toBe(0);
      expect(`${refused.stdout}${refused.stderr}`).toContain("credential resolution requires a validated running proxy; runtime is proxy-unreachable");
      expect(tokenWrites(fakeDocker.dockerLog)).toBe(0);
      expect(dockerExecCalls(fakeDocker.dockerLog).some((entry) => String((entry.args as string[]).at(-1)).includes("mv '/run/runfree-proxy-secrets/"))).toBe(false);
      expect(readReceiptsFile()).toHaveLength(0);

      // Reclaim: a retry that observes no restart succeeds and writes once.
      const retried = await runAdmin(async () => {
        prepareRuntimeTokenSources({ mode: "convergence" });
        await credentialSyncIntent(warmSync);
      }, {
        ...opEnv(fakeDocker, hostOpBin),
        ...ackEnv,
      }, { policyAccess: "effective-read-only", validatedRuntime: tokenSyncValidatedRuntime() });

      expect(retried.status, retried.stderr).toBe(0);
      expect(tokenWrites(fakeDocker.dockerLog)).toBe(1);
      expect(readReceiptsFile().map((receipt) => receipt.tokenName)).toEqual(["github"]);
    });

    test("the watcher's first pass after a receipt-gated launch re-reads every source, even with no refresh interval", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      const opLogPath = path.join(tmpBase, `warm-watch-op-${Math.random().toString(16).slice(2)}.jsonl`);
      installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_rotated\n" });

      const watch = await runAdmin(() => credentialSyncIntent({
        verbose: false,
        watch: true,
        quiet: true,
        delayFirstSync: false,
        initialSourceTruth: true,
        cacheSourceSecrets: true,
      }), {
        ...opEnv(fakeDocker, hostOpBin),
        RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "1",
        RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "1",
      });

      expect(watch.status, watch.stderr).toBe(0);
      // A manual source whose receipt is current is still re-read once, and
      // the rotated value reaches the proxy.
      expect(readJsonLines(opLogPath)).toHaveLength(2);
      expect(dockerExecCalls(fakeDocker.dockerLog).map((entry) => entry.stdin)).toContain("ghp_rotated");
    });

    test("the watcher's first pass keeps the held value when a source cannot be read without a prompt", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      installFakeOp(hostOpBin, { output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      // A detached, non-interactive read of a locked vault: no revocation
      // information, so the session keeps the value it is using.
      installFakeOp(hostOpBin, { exitCode: 1, stderr: "1Password is locked\n" });

      const watch = await runAdmin(() => credentialSyncIntent({
        verbose: false,
        watch: true,
        quiet: true,
        delayFirstSync: false,
        initialSourceTruth: true,
        cacheSourceSecrets: true,
      }), {
        ...opEnv(fakeDocker, hostOpBin),
        RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "1",
        RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "1",
      });

      expect(watch.status, watch.stderr).toBe(0);
      expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
      expect(readTokenStatus().github).toMatchObject({ ok: false, state: "stale" });
      expect(readReceiptsFile()).toHaveLength(1);
    });

    test("the watcher's first pass deletes the held value when its source was revoked", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      installFakeOp(hostOpBin, { output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      // A definitive failure is how a revocation at the source shows: the
      // value the warm launch reused must not outlive it for the session.
      installFakeOp(hostOpBin, { exitCode: 1, stderr: 'could not read secret "op://Private/GitHub/token": item not found in vault\n' });

      const watch = await runAdmin(() => credentialSyncIntent({
        verbose: false,
        watch: true,
        quiet: true,
        delayFirstSync: false,
        initialSourceTruth: true,
        cacheSourceSecrets: true,
      }), {
        ...opEnv(fakeDocker, hostOpBin),
        RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "1",
        RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "1",
      });

      expect(watch.status).toBe(0);
      expect(tokenRemovalCount(fakeDocker.dockerLog)).toBeGreaterThanOrEqual(1);
      expect(readTokenStatus().github).toMatchObject({ ok: false, state: "failed" });
      expect(readReceiptsFile()).toHaveLength(0);
    });

    test("an explicit source-truth credential sync still deletes on a definitive failure", async () => {
      writeGithubOnePasswordFixture();
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      installFakeOp(hostOpBin, { output: "ghp_secret\n" });
      await populate(fakeDocker, hostOpBin);
      installFakeOp(hostOpBin, { exitCode: 1, stderr: 'could not read secret "op://Private/GitHub/token": item not found in vault\n' });
      const explicit = await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin));
      expect(explicit.status).toBe(1);
      expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(1);
    });
  });

  // F01: launch preparation shares a successful exact 1Password read across
  // every destination in the same preparation pass that uses the identical
  // reference. Only the resolved value is shared; each destination keeps its
  // own fingerprint, policy, receipt and error.
  describe("shared 1Password reads within one preparation (F01)", () => {
    function writeSharedOnePasswordFixture(tokenNames: readonly string[], ref = "op://Private/GitHub/token"): void {
      writeFixtureRepo({
        hosts: tokenNames.map((name) => `${name}.example.com`),
        tokens: Object.fromEntries(tokenNames.map((name) => [name, {
          description: `${name} token`,
          credentials: [{ host: `${name}.example.com`, header: "Authorization", scheme: "bearer" }],
        }])),
      });
      writeTokenConfig(Object.fromEntries(tokenNames.map((name) => [name, { source: "1password", ref }])));
    }

    test("six destinations one exact ref make one read", async () => {
      const names = ["dest1", "dest2", "dest3", "dest4", "dest5", "dest6"];
      writeSharedOnePasswordFixture(names);
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      const opLogPath = path.join(tmpBase, `shared-op-${Math.random().toString(16).slice(2)}.jsonl`);
      installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_shared\n" });
      selectEffectiveControlsFromProjectPolicy();

      const prepared = await runAdmin(() => prepareRuntimeTokenSources(), opEnv(fakeDocker, hostOpBin));

      expect(prepared.status, prepared.stderr).toBe(0);
      expect(readJsonLines(opLogPath)).toHaveLength(1);
      clearPreparedRuntimeTokenSources(adminProjectInfoForTokenSync());
    });

    test("distinct refs stay distinct", async () => {
      const names = ["dest1", "dest2"];
      writeFixtureRepo({
        hosts: names.map((name) => `${name}.example.com`),
        tokens: Object.fromEntries(names.map((name) => [name, {
          description: `${name} token`,
          credentials: [{ host: `${name}.example.com`, header: "Authorization", scheme: "bearer" }],
        }])),
      });
      writeTokenConfig({
        dest1: { source: "1password", ref: "op://Private/GitHub/token" },
        dest2: { source: "1password", ref: "op://Private/GitHub/other" },
      });
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      const opLogPath = path.join(tmpBase, `distinct-op-${Math.random().toString(16).slice(2)}.jsonl`);
      installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_distinct\n" });
      selectEffectiveControlsFromProjectPolicy();

      const prepared = await runAdmin(() => prepareRuntimeTokenSources(), opEnv(fakeDocker, hostOpBin));

      expect(prepared.status, prepared.stderr).toBe(0);
      expect(readJsonLines(opLogPath)).toHaveLength(2);
      clearPreparedRuntimeTokenSources(adminProjectInfoForTokenSync());
    });

    test("next pass reads again", async () => {
      const names = ["dest1", "dest2", "dest3"];
      writeSharedOnePasswordFixture(names);
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      const opLogPath = path.join(tmpBase, `nextpass-op-${Math.random().toString(16).slice(2)}.jsonl`);
      installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_next\n" });
      selectEffectiveControlsFromProjectPolicy();

      const first = await runAdmin(() => prepareRuntimeTokenSources(), opEnv(fakeDocker, hostOpBin));
      expect(first.status, first.stderr).toBe(0);
      expect(readJsonLines(opLogPath)).toHaveLength(1);
      clearPreparedRuntimeTokenSources(adminProjectInfoForTokenSync());

      // A later preparation pass gets its own fresh scope: it reads again
      // rather than reusing the first pass's shared value.
      const second = await runAdmin(() => prepareRuntimeTokenSources(), opEnv(fakeDocker, hostOpBin));
      expect(second.status, second.stderr).toBe(0);
      expect(readJsonLines(opLogPath)).toHaveLength(2);
      clearPreparedRuntimeTokenSources(adminProjectInfoForTokenSync());
    });

    // Launch preparation is fail-fast: the first resolution failure aborts
    // the whole pass without visiting later destinations, so a shared
    // failing read's "not cached" guarantee (every destination still makes
    // its own attempt) is proved at the scope level instead, in
    // credential-source-reader.test.ts ("failed read is not cached"). The
    // watcher continues after a failure, so it is proved here instead, below.

    test("a config fingerprint drift refuses admission before publication, even for a shared read", async () => {
      const names = ["dest1", "dest2"];
      writeSharedOnePasswordFixture(names);
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      const opLogPath = path.join(tmpBase, `drift-op-${Math.random().toString(16).slice(2)}.jsonl`);
      installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_drift\n" });
      selectEffectiveControlsFromProjectPolicy();

      const prepared = await runAdmin(() => prepareRuntimeTokenSources(), opEnv(fakeDocker, hostOpBin));
      expect(prepared.status, prepared.stderr).toBe(0);
      expect(readJsonLines(opLogPath)).toHaveLength(1);

      // One of the two destinations sharing the read gets a new reference
      // before publication: its own fingerprint no longer matches what was
      // prepared, so admission refuses, even though the shared value it
      // reused was legitimately resolved. Preparation and admission touch no
      // Docker/proxy state at all, so nothing was (or could have been)
      // published before the refusal.
      writeTokenConfig({
        dest1: { source: "1password", ref: "op://Private/GitHub/token" },
        dest2: { source: "1password", ref: "op://Private/GitHub/rotated" },
      });
      expect(() => admitPreparedRuntimeTokenSources(adminProjectInfoForTokenSync())).toThrow("prepared credential source changed");
      expect(dockerExecCalls(fakeDocker.dockerLog)).toHaveLength(0);
      clearPreparedRuntimeTokenSources(adminProjectInfoForTokenSync());
    });

    test("a receipt that disappears before the locked sync defers every shared destination before any write", async () => {
      const names = ["dest1", "dest2", "dest3"];
      writeSharedOnePasswordFixture(names);
      const fakeDocker = installTokenSyncDockerFake();
      const hostOpBin = makeHostOpBin();
      const opLogPath = path.join(tmpBase, `drift-receipt-op-${Math.random().toString(16).slice(2)}.jsonl`);
      installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_drift_receipt\n" });
      selectEffectiveControlsFromProjectPolicy();
      // Seed a current receipt for every shared destination with a plain
      // explicit sync (not shared: nothing is prepared yet).
      const seeded = await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin));
      expect(seeded.status, seeded.stderr).toBe(0);
      expect(readReceiptsFile().map((receipt) => receipt.tokenName).sort()).toEqual(names);
      const execsBefore = dockerExecCalls(fakeDocker.dockerLog).length;
      const warmSync = { ...syncInput, verbose: true, mode: "startup-convergence" as const };

      const deferred = await runAdmin(async () => {
        // Every receipt is current, so this warm preparation shares nothing
        // (it skips every destination without reading). Between it and the
        // locked sync every receipt disappears, so the sync finds every
        // destination that would have shared the read due with nothing
        // prepared for it.
        prepareRuntimeTokenSources({ mode: "convergence" });
        fs.rmSync(receiptsFilePath());
        await credentialSyncIntent(warmSync);
      }, opEnv(fakeDocker, hostOpBin));

      expect(deferred.status).toBe(TOKEN_SYNC_DEFERRED_STATUS);
      // Nothing published: no op read beyond the seeded baseline, no further
      // docker exec, no removal, no resurrected receipt.
      expect(readJsonLines(opLogPath)).toHaveLength(names.length);
      const execsAfter = dockerExecCalls(fakeDocker.dockerLog).slice(execsBefore);
      expect(execsAfter.filter((entry) => entry.stdin !== "")).toEqual([]);
      for (const name of names) expect(tokenRemovalCount(fakeDocker.dockerLog, name)).toBe(0);
      expect(readReceiptsFile()).toHaveLength(0);
      clearPreparedRuntimeTokenSources(adminProjectInfoForTokenSync());
    });

    // The watcher continues after a failure (unlike launch preparation,
    // which is fail-fast), so both the sharing and the not-cached-on-failure
    // guarantees are observable through it.
    describe("the watcher pass shares reads the same way", () => {
      // No `initialSourceTruth`: that option runs an extra, uncounted
      // source-truth pass before the one counted by
      // RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS, which would attempt every
      // never-resolved shared destination a second time regardless of F01
      // (each pass gets its own fresh scope by design — see "next pass
      // reads again"). Omitting it keeps this at exactly one pass.
      function runOneWatchPass(fakeDocker: { dockerLog: string; fakeBin: string }, hostOpBin: string): Promise<AdminRunResult> {
        return runAdmin(() => credentialSyncIntent({
          verbose: false,
          watch: true,
          quiet: true,
          delayFirstSync: false,
          cacheSourceSecrets: true,
        }), {
          ...opEnv(fakeDocker, hostOpBin),
          RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "1",
          RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "1",
        });
      }

      test("several due tokens with one ref make one read", async () => {
        const names = ["dest1", "dest2", "dest3"];
        writeSharedOnePasswordFixture(names);
        const fakeDocker = installTokenSyncDockerFake();
        const hostOpBin = makeHostOpBin();
        const opLogPath = path.join(tmpBase, `watch-shared-op-${Math.random().toString(16).slice(2)}.jsonl`);
        installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_watch_shared\n" });

        const watch = await runOneWatchPass(fakeDocker, hostOpBin);

        expect(watch.status, watch.stderr).toBe(0);
        expect(readJsonLines(opLogPath)).toHaveLength(1);
      });

      test("a failing shared ref is attempted once per token", async () => {
        const names = ["dest1", "dest2", "dest3"];
        writeSharedOnePasswordFixture(names);
        const fakeDocker = installTokenSyncDockerFake();
        const hostOpBin = makeHostOpBin();
        const opLogPath = path.join(tmpBase, `watch-shared-fail-op-${Math.random().toString(16).slice(2)}.jsonl`);
        installFakeOp(hostOpBin, { logPath: opLogPath, exitCode: 1, stderr: "connection reset by peer\n" });

        const watch = await runOneWatchPass(fakeDocker, hostOpBin);

        expect(watch.status, watch.stderr).toBe(0);
        // The watcher continues after a failure: every destination sharing
        // the failing reference still makes its own attempt, never cached.
        expect(readJsonLines(opLogPath)).toHaveLength(names.length);
        for (const name of names) expect(readTokenStatus()[name]).toMatchObject({ ok: false });
      });
    });
  });

  test("a resurrected receipt for a value the proxy does not hold is ignored and re-resolved", async () => {
    writeGithubOnePasswordFixture();
    const fakeDocker = installTokenSyncDockerFake();
    const hostOpBin = makeHostOpBin();
    installFakeOp(hostOpBin, { output: "ghp_secret\n" });
    expect((await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin))).status).toBe(0);
    const receipts = readReceiptsFile();
    expect(receipts).toHaveLength(1);

    // Simulate a concurrent delete after the receipt was written: the tmpfs
    // file is gone but the receipt file says otherwise.
    const removal = await runAdmin(() => credentialClearSourceIntent({ name: "github" }), opEnv(fakeDocker, hostOpBin));
    expect(removal.status).toBe(0);
    expect(readReceiptsFile()).toHaveLength(0);
    writeTokenConfig({ github: { source: "1password", ref: "op://Private/GitHub/token" } });
    fs.writeFileSync(receiptsFilePath(), `${JSON.stringify({ schemaVersion: 1, receipts })}\n`);

    // Transient failure with the resurrected receipt but no held value: failed, not stale.
    installFakeOp(hostOpBin, { exitCode: 1, stderr: "1Password is locked\n" });
    const failed = await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin));
    expect(failed.status).toBe(1);
    expect(readTokenStatus().github).toMatchObject({ ok: false, state: "failed" });
    expect(readReceiptsFile()).toHaveLength(0);
  });

  test("project-local token metadata cannot retract a matching host-owned receipt", async () => {
    writeGithubOnePasswordFixture();
    const fakeDocker = installTokenSyncDockerFake();
    const hostOpBin = makeHostOpBin();
    installFakeOp(hostOpBin, { output: "ghp_secret\n" });
    expect((await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin))).status).toBe(0);
    expect(readReceiptsFile()).toHaveLength(1);

    // Compromised-.runfree negative test: project-local credential metadata is
    // inert and cannot delete a held token or its host-owned receipt.
    fs.mkdirSync(path.join(tmp, ".runfree/config"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".runfree/config/tokens.json"), `${JSON.stringify({
      github: { source: "env", env: "EVIL" },
    })}\n`);
    const projectLocal = await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin));
    expect(projectLocal.status, projectLocal.stderr).toBe(0);
    expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(0);
    expect(readReceiptsFile()).toHaveLength(1);
    fs.rmSync(path.join(tmp, ".runfree/config/tokens.json"));

    // Malformed host token config: unconditional delete despite receipts.
    installFakeOp(hostOpBin, { output: "ghp_secret\n" });
    expect((await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin))).status).toBe(0);
    expect(readReceiptsFile()).toHaveLength(1);
    writeTokenConfig({ github: { source: "unsupported-kind" } });
    const malformed = await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin));
    expect(malformed.status).toBe(1);
    expect(readReceiptsFile()).toHaveLength(0);
  });

  test("a transient store-generation read failure fails the run without deleting or writing receipts", async () => {
    writeGithubOnePasswordFixture();
    const fakeDocker = installTokenSyncDockerFake();
    const hostOpBin = makeHostOpBin();
    installFakeOp(hostOpBin, { output: "ghp_secret\n" });
    expect((await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin))).status).toBe(0);
    const receiptsBefore = fs.readFileSync(receiptsFilePath(), "utf8");
    const statusPath = path.join(home, ".local/state/runfree/token-sync-status.json");
    const statusBefore = fs.readFileSync(statusPath, "utf8");
    const removalsBefore = tokenRemovalCount(fakeDocker.dockerLog);

    const opLogPath = path.join(tmpBase, `unreachable-op-${Math.random().toString(16).slice(2)}.jsonl`);
    installFakeOp(hostOpBin, { logPath: opLogPath, output: "ghp_secret\n" });
    const unreachable = await runAdmin(() => credentialSyncIntent(syncInput), {
      ...opEnv(fakeDocker, hostOpBin),
      FAKE_DOCKER_STARTED_AT_STATUS: "1",
    });
    expect(unreachable.status).toBe(1);
    expect(unreachable.stderr).toContain("proxy runtime could not be inspected");
    expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(removalsBefore);
    expect(fs.existsSync(opLogPath)).toBe(false);
    expect(fs.readFileSync(receiptsFilePath(), "utf8")).toBe(receiptsBefore);
    // "Report, change nothing": the healthy per-token records (ok/stale)
    // must not be rewritten to failed while the proxy still injects values.
    expect(fs.readFileSync(statusPath, "utf8")).toBe(statusBefore);

    // Same fail-closed treatment when the batched possession listing fails.
    const listingFailure = await runAdmin(() => credentialSyncIntent(syncInput), {
      ...opEnv(fakeDocker, hostOpBin),
      FAKE_DOCKER_SECRET_LIST_STATUS: "1",
    });
    expect(listingFailure.status).toBe(1);
    expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(removalsBefore);
    expect(fs.readFileSync(receiptsFilePath(), "utf8")).toBe(receiptsBefore);
    expect(fs.readFileSync(statusPath, "utf8")).toBe(statusBefore);
  });

  test("possession is one batched listing per sync run and a corrupted receipts file degrades to re-resolution", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com", "api.example.com"],
      tokens: {
        github: { description: "GitHub token", credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }] },
        example: { description: "Example token", credentials: [{ host: "api.example.com", header: "Authorization", scheme: "bearer" }] },
      },
    });
    writeTokenConfig({
      github: { source: "env", env: "GITHUB_TOKEN" },
      example: { source: "env", env: "EXAMPLE_TOKEN" },
    });
    const fakeDocker = installTokenSyncDockerFake();
    const env = {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      GITHUB_TOKEN: "ghp_secret",
      EXAMPLE_TOKEN: "ex_secret",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    };
    expect((await runAdmin(() => credentialSyncIntent(syncInput), env)).status).toBe(0);
    const listings = readJsonLines(fakeDocker.dockerLog).filter((entry) =>
      Array.isArray(entry.args) && entry.args.join(" ").includes(CREDENTIAL_OBSERVATION_BATCH_HEADER)
      && entry.args.join(" ").includes("held-token-names"));
    expect(listings).toHaveLength(1);

    // Corrupted receipts file: no receipts (fail-open to re-resolution), never a crash.
    fs.writeFileSync(receiptsFilePath(), "not-json{{{\n");
    expect((await runAdmin(() => credentialSyncIntent(syncInput), env)).status).toBe(0);
    expect(readReceiptsFile().map((receipt) => receipt.tokenName).sort()).toEqual(["example", "github"]);
  });

  test("dropping a token from policy removes its tmpfs value and retracts its receipt", async () => {
    writeGithubOnePasswordFixture();
    const fakeDocker = installTokenSyncDockerFake();
    const hostOpBin = makeHostOpBin();
    installFakeOp(hostOpBin, { output: "ghp_secret\n" });
    expect((await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin))).status).toBe(0);
    expect(readReceiptsFile()).toHaveLength(1);

    fs.writeFileSync(path.join(tmp, ".runfree/network-policy.json"), `${JSON.stringify({ hosts: ["api.github.com"], tokens: {} }, null, 2)}\n`);
    const dropped = await runAdmin(() => credentialSyncIntent(syncInput), opEnv(fakeDocker, hostOpBin));
    expect(dropped.status, dropped.stderr).toBe(0);
    expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(1);
    expect(readReceiptsFile()).toHaveLength(0);
  });

  test("the per-project token-store lock serializes concurrent syncs and clears stale locks", async () => {
    writeGithubOnePasswordFixture();
    writeTokenConfig({ github: { source: "env", env: "GITHUB_TOKEN" } });
    const fakeDocker = installTokenSyncDockerFake();
    const env = {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      GITHUB_TOKEN: "ghp_secret",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_TOKEN_STORE_LOCK_WAIT_MS: "150",
    };
    const lockPath = path.join(adminStateDir(), `token-store-sync-${projectHash(tmp)}.lock`);

    // Held by a live foreign process: the sync must wait and then fail loudly.
    const holder = childProcess.spawn(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], { stdio: "ignore" });
    try {
      fs.mkdirSync(lockPath, { recursive: true });
      fs.writeFileSync(path.join(lockPath, "pid"), `${holder.pid}\n`);
      const blocked = await runAdmin(() => credentialSyncIntent(syncInput), env);
      expect(blocked.status).toBe(1);
      expect(blocked.stderr).toContain("timed out waiting for the token store lock");
    } finally {
      holder.kill("SIGKILL");
    }

    // Stale lock (dead PID): removed and the sync proceeds.
    fs.writeFileSync(path.join(lockPath, "pid"), "999999999\n");
    const recovered = await runAdmin(() => credentialSyncIntent(syncInput), env);
    expect(recovered.status, recovered.stderr).toBe(0);
    expect(fs.existsSync(lockPath)).toBe(false);
  });

  test("the token-store lock is reclaimed across a reboot but never stolen on an unprovable stamp", async () => {
    writeGithubOnePasswordFixture();
    writeTokenConfig({ github: { source: "env", env: "GITHUB_TOKEN" } });
    const fakeDocker = installTokenSyncDockerFake();
    const previousBoot = "linux:11111111-2222-3333-4444-555555555555";
    const currentBoot = "linux:66666666-7777-8888-9999-aaaaaaaaaaaa";
    const bootEnv = (bootId: string): NodeJS.ProcessEnv => ({
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      GITHUB_TOKEN: "ghp_secret",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_HOST_BOOT_ID: bootId,
      RUNFREE_TEST_TOKEN_STORE_LOCK_WAIT_MS: "150",
    });
    const lockPath = path.join(adminStateDir(), `token-store-sync-${projectHash(tmp)}.lock`);

    const holder = childProcess.spawn(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], { stdio: "ignore" });
    try {
      // Negative first: a live holder whose boot stamp was truncated by a torn
      // write. It compares unequal to the current boot but proves nothing, and
      // the boot check short-circuits the PID check entirely — so reading it as
      // "previous boot" would delete a live holder's lock and admit two writers
      // to the token store. The rejection has to happen before the removal, so
      // the lock directory and its owner PID must survive untouched.
      fs.mkdirSync(lockPath, { recursive: true });
      fs.writeFileSync(path.join(lockPath, "pid"), `${holder.pid}\n`);
      fs.writeFileSync(path.join(lockPath, "boot"), "linux:11111111\n");
      const blocked = await runAdmin(() => credentialSyncIntent(syncInput), bootEnv(currentBoot));
      expect(blocked.status).toBe(1);
      expect(blocked.stderr).toContain("timed out waiting for the token store lock");
      expect(fs.existsSync(lockPath)).toBe(true);
      expect(fs.readFileSync(path.join(lockPath, "pid"), "utf8").trim()).toBe(String(holder.pid));

      // Positive: the same live PID, now stamped with a provably different
      // boot. After a reboot PIDs are reissued from low numbers, so PID
      // liveness alone matches an unrelated process and wedges every token sync
      // for this project until someone deletes the directory by hand.
      fs.writeFileSync(path.join(lockPath, "boot"), `${previousBoot}\n`);
      const recovered = await runAdmin(() => credentialSyncIntent(syncInput), bootEnv(currentBoot));
      expect(recovered.status, recovered.stderr).toBe(0);
      expect(fs.existsSync(lockPath)).toBe(false);
    } finally {
      holder.kill("SIGKILL");
      fs.rmSync(lockPath, { recursive: true, force: true });
    }
  });

  test("1Password diagnostics map to typed transient/definitive classifications", () => {
    const transient = [
      "[ERROR] you are not currently signed in, run `op signin` to continue",
      "error initializing client: authorization prompt dismissed, please try again",
      "connecting to desktop app: timed out",
      "1Password is locked",
      "biometric unlock failed",
      "session expired",
      "dial tcp: i/o timeout",
    ];
    const definitive = [
      'could not read secret "op://Private/GitHub/token": item not found in vault',
      "more than one item matches",
      '"op://x" is not an item reference',
      "authorization denied: access denied",
      "vault not found",
      "unauthorized",
      "",
      "some brand-new unknown diagnostic",
    ];
    for (const line of transient) expect(classifyOnePasswordFailure(line), line).toBe("transient");
    for (const line of definitive) expect(classifyOnePasswordFailure(line), line).toBe("definitive");
  });

  test("the watch loop survives a token-store lock timeout and keeps iterating", async () => {
    writeGithubOnePasswordFixture();
    writeTokenConfig({ github: { source: "env", env: "GITHUB_TOKEN", refreshEverySeconds: 60 } });
    const fakeDocker = installTokenSyncDockerFake();
    const lockPath = path.join(adminStateDir(), `token-store-sync-${projectHash(tmp)}.lock`);

    // A live foreign process holds the lock for the whole watch run (the
    // real-world shape: another command mid-1Password prompt). Every watch
    // iteration's sync must fail loudly and retry — never crash the watcher.
    const holder = childProcess.spawn(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], { stdio: "ignore" });
    try {
      fs.mkdirSync(lockPath, { recursive: true });
      fs.writeFileSync(path.join(lockPath, "pid"), `${holder.pid}\n`);
      const watch = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: true, quiet: true, delayFirstSync: false, cacheSourceSecrets: true }), {
        FAKE_DOCKER_LOG: fakeDocker.dockerLog,
        GITHUB_TOKEN: "ghp_secret",
        PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
        RUNFREE_TEST_TOKEN_STORE_LOCK_WAIT_MS: "100",
        RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "2",
        RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "0",
      });
      expect(watch.status, watch.stderr).toBe(0);
      const iterationFailures = watch.stderr.split("credential sync watch iteration failed").length - 1;
      expect(iterationFailures).toBe(2);
      expect(watch.stderr).toContain("timed out waiting for the token store lock");
    } finally {
      holder.kill("SIGKILL");
      fs.rmSync(lockPath, { recursive: true, force: true });
    }
  });

  test("a transient store-generation read failure keeps the watch scheduled instead of stopping it", async () => {
    writeGithubOnePasswordFixture();
    writeTokenConfig({ github: { source: "env", env: "GITHUB_TOKEN" } });
    const fakeDocker = installTokenSyncDockerFake();

    // Manual-source token + proxy-unreachable: the delay computation must
    // schedule a bounded re-probe, not conclude "no credential sources have
    // refresh intervals" and end the watch (the spec keeps stale manual
    // tokens under watcher retry).
    const watch = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: true, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      FAKE_DOCKER_STARTED_AT_STATUS: "1",
      GITHUB_TOKEN: "ghp_secret",
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "2",
      RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "0",
    });

    expect(watch.status, watch.stderr).toBe(0);
    expect(watch.stdout).not.toContain("credential sync watch stopped: no credential sources have refresh intervals");
    const unreachableReports = watch.stderr.split("proxy runtime could not be inspected").length - 1;
    expect(unreachableReports).toBeGreaterThanOrEqual(2);
  });

  test("watcher exits when the parent lifetime pipe closes even though the parent PID is alive", async () => {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: { description: "GitHub token", credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }] },
      },
    });
    writeTokenConfig({ github: { source: "env", env: "GITHUB_TOKEN", refreshEverySeconds: 3600 } });
    fs.mkdirSync(home, { recursive: true });
    const env = {
      ...process.env,
      HOME: home,
      XDG_CONFIG_HOME: path.join(home, ".config"),
      XDG_DATA_HOME: path.join(home, ".local/share"),
      XDG_STATE_HOME: path.join(home, ".local/state"),
      CODEX_HOME: path.join(home, ".codex"),
      GITHUB_TOKEN: "ghp_secret",
      RUNFREE_PACKAGE_ROOT: tmp,
      RUNFREE_PROJECT_ID: projectHash(tmp),
      RUNFREE_RUNTIME_DIGEST,
      RUNFREE_TEST_FAKE_DOCKER: "1",
      // PID-reuse stand-in: this test process is alive, so the PID probe
      // alone would keep the watcher running forever.
      RUNFREE_TOKEN_SYNC_WATCH_PARENT_PID: String(process.pid),
      RUNFREE_TOKEN_SYNC_LIFETIME_FD: "3",
      // Short sleeps instead of the hourly refresh's 5 s ticks: the exit still
      // depends only on the pipe, since nothing else ends this watch, and the
      // test no longer waits out a whole tick.
      RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "200",
    };
    const child = childProcess.spawn(
      process.execPath,
      [...cliEntryArgv(), "--workspace", tmp, "credential", "sync", "--watch"],
      { cwd: repoRoot, env, stdio: ["ignore", "pipe", "pipe", "pipe"] },
    );
    let stderr = "";
    child.stderr?.on("data", (chunk) => {
      stderr += String(chunk);
    });
    const exited = new Promise<number | null>((resolve) => {
      child.on("exit", (code) => resolve(code));
    });
    // Deterministic readiness: the non-quiet watch announces its start on
    // stdout; waiting for that (instead of a fixed sleep) proves the watcher
    // is running before the pipe closes and removes dead time from the test.
    await new Promise<void>((resolve, reject) => {
      let stdout = "";
      const timeout = setTimeout(() => reject(new Error(`watcher did not report readiness: ${stdout} ${stderr}`)), 20_000);
      child.stdout?.on("data", (chunk) => {
        stdout += String(chunk);
        if (stdout.includes("source secret cache:")) {
          clearTimeout(timeout);
          resolve();
        }
      });
    });
    // Close the parent's write end: the watcher must stop at its next sleep
    // check even though the "parent" PID is still alive.
    (child.stdio[3] as { destroy: () => void }).destroy();
    const timeout = new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), 20_000));
    const result = await Promise.race([exited, timeout]);
    if (result === "timeout") child.kill("SIGKILL");
    expect(result, stderr).not.toBe("timeout");
  }, 30_000);
});

// A proxy replacement in flight is a moving credential destination. The
// coordinator checks the rebind journal when it hands the credential path its
// go-ahead; that check is point-in-time, so it cannot see a journal that moves
// afterwards. `syncTokensUnderLock` re-reads the serialized journal at every
// step of the sync and refuses before the write, which is the only thing
// standing between a proxy-managed token and a container that is being
// replaced out from under it.
describe("credential writes against a moving proxy replacement", () => {
  // The journal only records real Docker object ids and `runfree-<projectId>`
  // compose projects, so the fake proxy runtime carries both here.
  const LIVE_PROXY_ID = "a".repeat(64);
  const RETIRED_PROXY_ID = "7".repeat(64);

  function rebindProject(): { projectId: string; composeProject: string } {
    const projectId = projectHash(tmp);
    return { projectId, composeProject: `runfree-${projectId}` };
  }

  /**
   * A journal parked at `control-selected` — the phase that owes the credential
   * write — with the candidate control plane bound to the live proxy and a
   * healthy recovery allowance. Everything the gate looks at is satisfied, so a
   * test that changes exactly one input isolates exactly one disjunct.
   */
  function rebindJournalAtControlSelected(input: {
    allowance?: { exhausted?: boolean };
    updatedAtOffsetMs?: number;
  } = {}): ControlPlaneRebindTransaction {
    const project = rebindProject();
    const preparedAt = new Date();
    const topologyDigest = sha256Digest("rebind-control-plane-topology");
    const generationFor = (proxyImageInputDigest: string) => createControlPlaneGenerationV2({
      ...project,
      proxyImageInputDigest: sha256Digest(proxyImageInputDigest),
      controlPlaneTopologyDigest: topologyDigest,
      admissionContractEpoch: RUNTIME_ADMISSION_CONTRACT_EPOCH,
    });
    const materializationFor = (generation: ReturnType<typeof generationFor>, proxyImageId: string) =>
      createControlPlaneMaterializationManifestV2({
        ...project,
        generation,
        proxyImageRef: "runfree/proxy:test",
        proxyImageId: sha256Digest(proxyImageId),
        renderedControlPlaneSha256: topologyDigest,
        sessionAdmissionSource: "files",
      });
    const selectionFor = (
      generation: ReturnType<typeof generationFor>,
      materialization: ReturnType<typeof materializationFor>,
      proxyContainerId: string,
    ): ControlPlaneEffectiveSelectionV2 => ({
      schemaVersion: 2,
      ...project,
      controlPlaneGenerationDigest: generation.controlPlaneGenerationDigest,
      controlPlaneMaterializationDigest: materialization.controlPlaneMaterializationDigest,
      proxyContainerId,
      proxyImageId: materialization.proxyImageId,
      sidecarContainerIds: [],
      networkIds: { agentInternal: "8".repeat(64), proxyEgress: "9".repeat(64) },
      securityContractHash: sha256Digest("security-contract"),
      proofSchemaVersion: CONTROL_PLANE_PROOF_SCHEMA_VERSION,
      admissionContractEpoch: generation.admissionContractEpoch,
      denyByDefaultBaseProofHash: sha256Digest("deny-by-default-base-proof"),
      selectedAt: preparedAt.toISOString(),
      runfreeVersion: "0.3.0",
    });
    const oldGeneration = generationFor("retired-proxy-image-input");
    const candidateGeneration = generationFor("candidate-proxy-image-input");
    const oldMaterialization = materializationFor(oldGeneration, "retired-proxy-image-id");
    const candidateMaterialization = materializationFor(candidateGeneration, "candidate-proxy-image-id");
    const prepared = createControlPlaneRebindTransaction({
      expectedProject: project,
      lockOwnerToken: "e".repeat(64),
      oldControlPlane: selectionFor(oldGeneration, oldMaterialization, RETIRED_PROXY_ID),
      oldMaterialization,
      candidateMaterialization,
      oldRecords: [],
      now: () => preparedAt,
      randomBytes: () => new Uint8Array(32).fill(0xab),
    });
    const recovery = prepared.recovery as NonNullable<ControlPlaneRebindTransaction["recovery"]>;
    return {
      ...prepared,
      phase: "control-selected",
      candidateControlPlane: selectionFor(candidateGeneration, candidateMaterialization, LIVE_PROXY_ID),
      recovery: {
        ...recovery,
        outstandingEffect: "credentials",
        allowance: { ...recovery.allowance, exhausted: input.allowance?.exhausted ?? false },
      },
      updatedAt: new Date(preparedAt.getTime() + (input.updatedAtOffsetMs ?? 0)).toISOString(),
    };
  }

  function writeRebindJournal(transaction: ControlPlaneRebindTransaction): void {
    const journalPath = controlPlaneRebindTransactionPath(adminStateDir());
    fs.mkdirSync(path.dirname(journalPath), { recursive: true });
    fs.writeFileSync(journalPath, serializeControlPlaneRebindTransaction(transaction));
  }

  async function configureGithubCommandSource(): Promise<{ commandPath: string; fakeBin: string }> {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    const fakeSource = installFakeCommandSource();
    expect((await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["gh", "auth", "token"],
    }), { PATH: fakeSource.fakeBin })).status).toBe(0);
    writeTokenConfig({ github: { source: "named", name: "github-cli" } });
    return { commandPath: fakeSource.commandPath, fakeBin: fakeSource.fakeBin };
  }

  test("a rebind journal that moves while the credential is being resolved refuses the write", async () => {
    const fakeSource = await configureGithubCommandSource();
    const fakeDocker = installTokenSyncDockerFake({
      composeProject: rebindProject().composeProject,
      proxyId: LIVE_PROXY_ID,
    });
    writeRebindJournal(rebindJournalAtControlSelected());
    // The host source resolves inside the sync window, between the journal read
    // that opened the sync and the write. A rebind step landing here is exactly
    // what a point-in-time admission check upstream cannot observe.
    let resolved = 0;
    registerFakeCommand(fakeSource.commandPath, () => {
      resolved += 1;
      writeRebindJournal(rebindJournalAtControlSelected({ updatedAtOffsetMs: 1_000 }));
      return spawnResult({ stdout: "command-secret\n" });
    });

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${fakeSource.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("proxy replacement receipt or recovery allowance changed before credential write; resume runtime recover");
    // The secret was in hand and still never reached the proxy: the refusal is
    // between resolution and the tmpfs write, not before resolution.
    expect(resolved).toBe(1);
    expect(dockerExecCalls(fakeDocker.dockerLog)).toHaveLength(0);
  });

  test("an exhausted recovery allowance refuses the write before the source is read", async () => {
    const fakeSource = await configureGithubCommandSource();
    const fakeDocker = installTokenSyncDockerFake({
      composeProject: rebindProject().composeProject,
      proxyId: LIVE_PROXY_ID,
    });
    // Unchanged across the whole sync: the journal never moves, so the refusal
    // can only come from the spent allowance.
    writeRebindJournal(rebindJournalAtControlSelected({ allowance: { exhausted: true } }));
    let resolved = 0;
    registerFakeCommand(fakeSource.commandPath, () => {
      resolved += 1;
      return spawnResult({ stdout: "command-secret\n" });
    });

    const result = await runAdmin(() => credentialSyncIntent({ verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true }), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      PATH: `${fakeDocker.fakeBin}${path.delimiter}${fakeSource.fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("proxy replacement receipt or recovery allowance changed before credential write; resume runtime recover");
    expect(resolved).toBe(0);
    expect(dockerExecCalls(fakeDocker.dockerLog)).toHaveLength(0);
  });
});

// F08: cancelling a credential watch — the session exits (its parent closes
// the lifetime pipe and signals the watcher), a Ctrl-C, a vanished parent, a
// signal — must never read as a definitive provider failure that deletes a
// valid shared credential.
//
// These are real-subprocess reproductions. The session parent is
// scripts/credential-watch.test-harness.ts, which starts and stops the watcher
// through the production `nodeRuntimeIO` (or, for the crash and recycled-PID
// cases, through the production spawn plan). The watcher installs the CLI's
// own signal handlers and runs the production `credentialSyncIntent`. The
// providers (`op`, and a `gh` command source) are real shell scripts on the
// sanitized host PATH, so the watcher's `spawnSync` sees real exits and real
// signals. Docker is the same in-process fake as the rest of this file, reached
// from the watcher through a small executable bridge on a Unix socket.
//
// `reproduction` marks a test that reproduced the defect before the fix (as
// an expected failure). Each marks the point where its effect assertion
// runs, and the last test of the block fails if a reproduction that started
// never got there, so a harness failure can never pass for evidence. The
// other tests pin behavior that must not change: genuine failures while the
// parent is alive.
describe("credential watcher cancellation (F08)", () => {
  // Measured from the cancelling event: the watcher and every provider
  // process it started are gone, and nothing it does afterwards reaches the
  // proxy. Covers a TERM grace, a KILL, and the join (design addendum).
  const CANCELLATION_BOUND_MS = 8_000;
  const harnessArgv = credentialWatchHarnessEntryArgv();
  const syncInput = { verbose: false, watch: false, quiet: false, delayFirstSync: false, cacheSourceSecrets: true } as const;

  type ProviderEvent = { kind: "start" | "end"; pid: number; ppid?: number; sub: string; item: string; status?: number };
  type Provider = { dir: string; bin: string; setMode: (sub: "read" | "document" | "command", mode: string, item?: string) => void; events: () => ProviderEvent[] };
  type WatchParent = { child: childProcess.ChildProcess; configPath: string; watcherPid: number; send: (command: string) => void };

  let bridge: net.Server | undefined;
  let releaseHeldWrites: (() => void) | undefined;
  // Reproduction name -> whether it reached its effect assertion.
  const reproductionProgress = new Map<string, boolean>();

  function reproduction(name: string, body: () => Promise<void>): void {
    test(name, async () => {
      reproductionProgress.set(expect.getState().currentTestName ?? name, false);
      await body();
    }, 60_000);
  }

  function reached(): void {
    const name = expect.getState().currentTestName;
    if (name !== undefined) reproductionProgress.set(name, true);
  }

  // Kills only processes this test can prove it owns, from a fresh listing:
  // every harness, provider and bridge process carries this test's unique
  // temporary directory in its argv, and their descendants (a provider's
  // `sleep`) are found through the parent links of that same listing. A PID
  // remembered from earlier is never signalled: it may have been reused.
  function killOwnedProcesses(): void {
    const listing = childProcess.spawnSync("ps", ["-A", "-ww", "-o", "pid=", "-o", "ppid=", "-o", "args="], { encoding: "utf8" });
    if (listing.status !== 0) return;
    const rows = listing.stdout.split("\n").flatMap((line) => {
      const match = /^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(line);
      return match ? [{ pid: Number(match[1]), ppid: Number(match[2]), args: match[3] }] : [];
    }).filter((row) => row.pid !== process.pid && row.pid !== listing.pid);
    const owned = new Set(rows.filter((row) => row.args.includes(tmpBase)).map((row) => row.pid));
    for (let grew = true; grew;) {
      grew = false;
      for (const row of rows) {
        if (!owned.has(row.pid) && owned.has(row.ppid)) {
          owned.add(row.pid);
          grew = true;
        }
      }
    }
    for (const pid of owned) {
      try {
        process.kill(pid, "SIGKILL");
      } catch {
        // Exited since the listing.
      }
    }
  }

  afterEach(async () => {
    releaseHeldWrites?.();
    releaseHeldWrites = undefined;
    killOwnedProcesses();
    await new Promise<void>((resolve) => {
      if (!bridge) return resolve();
      bridge.close(() => resolve());
    });
    bridge = undefined;
  });

  function readProviderEvents(dir: string): ProviderEvent[] {
    const logPath = path.join(dir, "provider.log");
    if (!fs.existsSync(logPath)) return [];
    return fs.readFileSync(logPath, "utf8").split("\n").filter(Boolean).map((line) => {
      const [kind, pid, third, fourth, fifth] = line.split(" ");
      return kind === "start"
        ? { kind: "start", pid: Number(pid), ppid: Number(third), sub: fourth, item: fifth }
        : { kind: "end", pid: Number(pid), sub: third, item: fourth, status: Number(fifth) };
    });
  }

  // A scripted provider: `op` (read, document get) or a `gh` command source.
  // Its behavior per subcommand (and optionally per vault item) comes from a
  // mode file, so one executable serves the seed sync and the watcher. It logs
  // `start` before acting and `end` only when it ran to completion, so a
  // missing `end` proves the process was killed. It never prints a real value.
  function installScriptedProvider(name: "op" | "gh"): Provider {
    const dir = fs.mkdtempSync(path.join(tmpBase, `${name}-provider-`));
    const bin = path.join(dir, "bin");
    fs.mkdirSync(bin);
    const script = [
      "#!/bin/sh",
      `dir='${dir}'`,
      `case "${name}:$1" in`,
      "  op:read) sub=read; rest=\"${2#op://}\"; rest=\"${rest#*/}\"; item=\"${rest%%/*}\" ;;",
      "  op:document) sub=document; item=\"$3\" ;;",
      `  *) sub=command; item=${name} ;;`,
      "esac",
      "mode=ok",
      "if [ -f \"$dir/mode-$sub-$item\" ]; then read -r mode < \"$dir/mode-$sub-$item\"; elif [ -f \"$dir/mode-$sub\" ]; then read -r mode < \"$dir/mode-$sub\"; fi",
      "echo \"start $$ $PPID $sub $item\" >> \"$dir/provider.log\"",
      "status=0",
      "case \"$mode\" in",
      "  ok) echo \"dummy-$item-value\" ;;",
      // Dies with the process group's SIGTERM, or with spawnSync's timeout kill
      // (an orphaned `sleep 1` holds the output pipe for at most a second).
      "  hang) while :; do sleep 1; done ;;",
      // A provider that ignores SIGTERM (inherited by its `sleep`), then fails
      // with empty stderr: the shape the classifier calls definitive.
      // Outlives the cancellation bound by a margin.
      "  ignore-term-fail) trap '' TERM; sleep 10; status=1 ;;",
      // Not signaled (a crashed parent signals nobody): fails later.
      "  slow-fail) sleep 2; status=1 ;;",
      "  fail-empty) status=1 ;;",
      "  fail-unmatched) echo 'not a field secret reference' >&2; status=1 ;;",
      // How a revocation at the source shows: a classified definitive failure.
      "  fail-not-found) echo \"\\\"$item\\\" isn't an item in the \\\"Private\\\" vault\" >&2; status=1 ;;",
      // A private key the test wrote next to the script (a JWT source's key).
      "  pem) cat \"$dir/pem\" ;;",
      // The provider's own signal, with the parent alive.
      "  self-term) kill -TERM $$; sleep 5 ;;",
      "esac",
      "echo \"end $$ $sub $item $status\" >> \"$dir/provider.log\"",
      "exit $status",
      "",
    ].join("\n");
    fs.writeFileSync(path.join(bin, name), script, { mode: 0o755 });
    return {
      dir,
      bin,
      setMode: (sub, mode, item) => fs.writeFileSync(path.join(dir, item ? `mode-${sub}-${item}` : `mode-${sub}`), `${mode}\n`),
      events: () => readProviderEvents(dir),
    };
  }

  // Replaces the fake docker stub with an executable that forwards argv, env
  // and stdin to this process, which answers from the same in-process handler
  // the in-process tests use (one emulated proxy token store for both). A
  // held write is applied to the store at once (the remote side completed)
  // but its answer waits until released: an in-flight `docker exec`.
  async function startDockerBridge(fakeBin: string, options: { holdTokenWrites?: boolean } = {}): Promise<{ socketPath: string; heldWrite: Promise<void> }> {
    const dockerPath = path.join(fakeBin, "docker");
    const dockerRealPath = fs.realpathSync(dockerPath);
    const handler = fakeCommandHandlers.get(dockerRealPath);
    if (!handler) throw new Error("test setup: the docker fake must be installed before its bridge");
    const socketPath = path.join(tmpBase, "docker-bridge.sock");
    fs.writeFileSync(dockerPath, [
      `#!${process.execPath}`,
      "const net = require('node:net');",
      "const chunks = [];",
      "process.stdin.on('data', (chunk) => chunks.push(chunk));",
      "process.stdin.on('end', () => {",
      "  const socket = net.connect(process.env.FAKE_DOCKER_BRIDGE_SOCKET);",
      "  let response = '';",
      "  socket.setEncoding('utf8');",
      "  socket.on('data', (chunk) => { response += chunk; });",
      "  socket.on('end', () => {",
      "    const result = JSON.parse(response);",
      "    process.stdout.write(result.stdout);",
      "    process.stderr.write(result.stderr);",
      "    process.exitCode = result.status;",
      "  });",
      "  socket.end(JSON.stringify({ args: process.argv.slice(2), env: process.env, input: Buffer.concat(chunks).toString('utf8') }));",
      "});",
      "",
    ].join("\n"), { mode: 0o755 });
    let markWriteHeld: () => void = () => {};
    const heldWrite = new Promise<void>((resolve) => {
      markWriteHeld = resolve;
    });
    const released = new Promise<void>((resolve) => {
      releaseHeldWrites = resolve;
    });
    bridge = net.createServer({ allowHalfOpen: true }, (socket) => {
      let raw = "";
      socket.setEncoding("utf8");
      socket.on("error", () => {});
      socket.on("data", (chunk) => {
        raw += chunk;
      });
      socket.on("end", async () => {
        const request = JSON.parse(raw) as { args: string[]; env: NodeJS.ProcessEnv; input: string };
        const result = handler(request.args, { env: request.env, input: request.input }, dockerRealPath);
        const isTokenWrite = request.args[0] === "exec" && /mv '\/run\/runfree-proxy-secrets\//.test(String(request.args.at(-1)));
        if (options.holdTokenWrites && isTokenWrite) {
          markWriteHeld();
          await released;
        }
        if (!socket.destroyed) {
          socket.end(JSON.stringify({ status: result.status ?? 1, stdout: String(result.stdout ?? ""), stderr: String(result.stderr ?? "") }));
        }
      });
    });
    await new Promise<void>((resolve) => bridge?.listen(socketPath, resolve));
    return { socketPath, heldWrite };
  }

  function harnessEnv(fakeDocker: { dockerLog: string; fakeBin: string }, socketPath: string, providerBins: string[], extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
    return {
      ...process.env,
      HOME: home,
      XDG_CONFIG_HOME: path.join(home, ".config"),
      XDG_DATA_HOME: path.join(home, ".local/share"),
      XDG_STATE_HOME: path.join(home, ".local/state"),
      CODEX_HOME: path.join(home, ".codex"),
      RUNFREE_PACKAGE_ROOT: tmp,
      RUNFREE_RUNTIME_ROOT: path.join(repoRoot, "packages/agent-runtime"),
      RUNFREE_PROJECT_ID: projectHash(tmp),
      RUNFREE_RUNTIME_DIGEST,
      RUNFREE_TEST_FAKE_DOCKER: "1",
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      FAKE_DOCKER_BRIDGE_SOCKET: socketPath,
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: [fakeDocker.fakeBin, ...providerBins, process.env.PATH ?? ""].join(path.delimiter),
      // Short real sleeps (the simulated clock still advances by the full
      // interval). Not 0: a zero sleep never yields to the event loop, so the
      // watcher could never observe its pipe or run a signal handler between
      // passes, which production's 5 s ticks do. Plus a bounded watch for the
      // cases where nothing cancels it.
      RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "50",
      RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "1",
      ...extra,
    };
  }

  function writeHarnessConfig(config: Omit<CredentialWatchHarnessConfig, "projectRoot" | "stateDir" | "runtimeRoot" | "project">): string {
    const configPath = path.join(tmpBase, `watch-harness-${Math.random().toString(16).slice(2)}.json`);
    const full: CredentialWatchHarnessConfig = {
      projectRoot: tmp,
      stateDir: adminStateDir(),
      runtimeRoot: path.join(repoRoot, "packages/agent-runtime"),
      project: adminProjectInfoForTokenSync(),
      ...config,
    };
    fs.writeFileSync(configPath, JSON.stringify(full));
    return configPath;
  }

  async function startWatchParent(
    config: Omit<CredentialWatchHarnessConfig, "projectRoot" | "stateDir" | "runtimeRoot" | "project">,
    env: NodeJS.ProcessEnv,
  ): Promise<WatchParent> {
    const configPath = writeHarnessConfig(config);
    const child = childProcess.spawn(process.execPath, [...harnessArgv, "parent", configPath], {
      cwd: repoRoot,
      env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr?.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.on("error", () => {});
    const watcherPid = await waitForWatcherPid(configPath, () => `watch parent: ${stderr}`);
    return { child, configPath, watcherPid, send: (command) => child.stdin?.write(`${command}\n`) };
  }

  // The harness writes the watcher's own PID before it does anything else.
  async function waitForWatcherPid(configPath: string, diagnostics: () => string): Promise<number> {
    const pidPath = `${configPath}.pid`;
    if (!(await waitUntil(() => fs.existsSync(pidPath) && /^\d+\n$/.test(fs.readFileSync(pidPath, "utf8")), 30_000))) {
      throw new Error(`harness watcher never started: ${diagnostics()}`);
    }
    return Number(fs.readFileSync(pidPath, "utf8"));
  }

  // A foreground `runfree credential sync` run, as typed at a terminal: no
  // parent, no lifetime pipe, a process group of its own (the terminal's
  // foreground job). `--watch` makes it the manual watch.
  async function startForegroundSync(env: NodeJS.ProcessEnv, options: { watch: boolean }): Promise<number> {
    const configPath = writeHarnessConfig({ launch: "plan", initialSourceTruth: false });
    const syncEnv: NodeJS.ProcessEnv = { ...env, RUNFREE_CREDENTIAL_WATCH_HARNESS_CONFIG: configPath };
    delete syncEnv.RUNFREE_TOKEN_SYNC_LIFETIME_FD;
    delete syncEnv.RUNFREE_TOKEN_SYNC_WATCH_PARENT_PID;
    const child = childProcess.spawn(process.execPath, [
      ...harnessArgv, "--workspace", tmp, "credential", "sync", ...(options.watch ? ["--watch"] : []),
    ], { cwd: repoRoot, env: syncEnv, detached: true, stdio: "ignore" });
    child.on("error", () => {});
    return waitForWatcherPid(configPath, () => "foreground sync");
  }

  // Gone, or a zombie nobody has reaped yet: either way it runs nothing more.
  function processGone(pid: number): boolean {
    try {
      process.kill(pid, 0);
    } catch {
      return true;
    }
    const stat = childProcess.spawnSync("ps", ["-o", "stat=", "-p", String(pid)], { encoding: "utf8" }).stdout.trim();
    return stat === "" || stat.startsWith("Z");
  }

  async function waitUntil(predicate: () => boolean, timeoutMs: number): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (predicate()) return true;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    return predicate();
  }

  // A provider start by the given watcher (its parent), not by the seed sync.
  async function waitForProviderStart(provider: Provider, watcherPid: number, sub: string, item: string, timeoutMs = 30_000): Promise<ProviderEvent> {
    let found: ProviderEvent | undefined;
    await waitUntil(() => {
      found = provider.events().find((event) => event.kind === "start" && event.ppid === watcherPid && event.sub === sub && event.item === item);
      return found !== undefined;
    }, timeoutMs);
    if (!found) throw new Error(`provider ${sub} ${item} never started: ${JSON.stringify(provider.events())}`);
    return found;
  }

  function tokenWriteCount(logPath: string, tokenName: string): number {
    return proxyTokenWriteIndexes(logPath, tokenName).length;
  }

  function tokenRemovalCount(logPath: string, tokenName: string): number {
    return proxyTokenRemovalIndexes(logPath, tokenName).length;
  }

  function readReceiptNames(): string[] {
    if (!fs.existsSync(tokenReceiptsFilePath())) return [];
    const raw = JSON.parse(fs.readFileSync(tokenReceiptsFilePath(), "utf8")) as { receipts: Array<{ tokenName: string }> };
    return raw.receipts.map((receipt) => receipt.tokenName).sort();
  }

  // What a cancellation must leave exactly as it found it.
  function credentialSnapshot() {
    return {
      receipts: fs.existsSync(tokenReceiptsFilePath()) ? fs.readFileSync(tokenReceiptsFilePath(), "utf8") : undefined,
      status: fs.existsSync(tokenStatusFilePath()) ? fs.readFileSync(tokenStatusFilePath(), "utf8") : undefined,
    };
  }

  function githubOnePasswordPolicy(): void {
    writeFixtureRepo({
      hosts: ["api.github.com"],
      tokens: {
        github: { description: "GitHub token", credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }] },
      },
    });
  }

  // Seeds a held value, its receipt and an `ok` status through an ordinary
  // in-process sync against the same scripted provider.
  async function seed(fakeDocker: { dockerLog: string; fakeBin: string }, providerBins: string[], extra: NodeJS.ProcessEnv = {}): Promise<void> {
    const seeded = await runAdmin(() => credentialSyncIntent(syncInput), {
      FAKE_DOCKER_LOG: fakeDocker.dockerLog,
      OP_SERVICE_ACCOUNT_TOKEN: "op-session",
      PATH: [fakeDocker.fakeBin, ...providerBins, process.env.PATH ?? ""].join(path.delimiter),
      ...extra,
    });
    expect(seeded.status, seeded.stderr).toBe(0);
  }

  // Waits out the cancellation bound and reports what is still running, so
  // one assertion shows cleanup and credential effects side by side.
  async function settleAfterCancellation(watcherPid: number, providerPids: number[]): Promise<{ watcherGone: boolean; providersRunning: number[] }> {
    await waitUntil(() => processGone(watcherPid) && providerPids.every(processGone), CANCELLATION_BOUND_MS);
    return { watcherGone: processGone(watcherPid), providersRunning: providerPids.filter((pid) => !processGone(pid)) };
  }

  async function oneTokenFixture(options: { ref?: string; refreshEverySeconds?: number } = {}) {
    githubOnePasswordPolicy();
    writeTokenConfig({ github: { source: "1password", ref: options.ref ?? "op://Private/GitHub/token", ...(options.refreshEverySeconds ? { refreshEverySeconds: options.refreshEverySeconds } : {}) } });
    const fakeDocker = installTokenSyncDockerFake();
    const op = installScriptedProvider("op");
    return { fakeDocker, op };
  }

  reproduction("ordinary session exit during an op read keeps the held credential, its receipt and its status", async () => {
    const { fakeDocker, op } = await oneTokenFixture();
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    const before = credentialSnapshot();
    const writesBefore = tokenWriteCount(fakeDocker.dockerLog, "github");
    op.setMode("read", "hang");

    const parent = await startWatchParent({ launch: "runtime", initialSourceTruth: true }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    const read = await waitForProviderStart(op, parent.watcherPid, "read", "GitHub");
    parent.send("stop");
    const cleanup = await settleAfterCancellation(parent.watcherPid, [read.pid]);

    reached();
    expect({
      ...cleanup,
      reads: op.events().filter((event) => event.kind === "start").length,
      removals: tokenRemovalCount(fakeDocker.dockerLog, "github"),
      writes: tokenWriteCount(fakeDocker.dockerLog, "github") - writesBefore,
      ...credentialSnapshot(),
    }).toEqual({ watcherGone: true, providersRunning: [], reads: 2, removals: 0, writes: 0, ...before });
  });

  reproduction("ordinary session exit during the op document get fallback keeps the held credential", async () => {
    const { fakeDocker, op } = await oneTokenFixture({ ref: "op://Private/AuthKey" });
    op.setMode("read", "fail-unmatched");
    op.setMode("document", "ok");
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    const before = credentialSnapshot();
    op.setMode("document", "hang");

    const parent = await startWatchParent({ launch: "runtime", initialSourceTruth: true }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    await waitForProviderStart(op, parent.watcherPid, "read", "AuthKey");
    const fallback = await waitForProviderStart(op, parent.watcherPid, "document", "AuthKey");
    parent.send("stop");
    const cleanup = await settleAfterCancellation(parent.watcherPid, [fallback.pid]);

    reached();
    expect({ ...cleanup, removals: tokenRemovalCount(fakeDocker.dockerLog, "github"), ...credentialSnapshot() })
      .toEqual({ watcherGone: true, providersRunning: [], removals: 0, ...before });
  });

  reproduction("ordinary session exit during an op read of a document reference starts no document fallback", async () => {
    const { fakeDocker, op } = await oneTokenFixture({ ref: "op://Private/AuthKey" });
    op.setMode("read", "fail-unmatched");
    op.setMode("document", "ok");
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    const before = credentialSnapshot();
    const writesBefore = tokenWriteCount(fakeDocker.dockerLog, "github");
    op.setMode("read", "hang");

    const parent = await startWatchParent({ launch: "runtime", initialSourceTruth: true }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    const read = await waitForProviderStart(op, parent.watcherPid, "read", "AuthKey");
    parent.send("stop");
    const cleanup = await settleAfterCancellation(parent.watcherPid, [read.pid]);

    reached();
    expect({
      ...cleanup,
      fallbacks: op.events().filter((event) => event.kind === "start" && event.ppid === parent.watcherPid && event.sub === "document").length,
      removals: tokenRemovalCount(fakeDocker.dockerLog, "github"),
      writes: tokenWriteCount(fakeDocker.dockerLog, "github") - writesBefore,
      ...credentialSnapshot(),
    }).toEqual({ watcherGone: true, providersRunning: [], fallbacks: 0, removals: 0, writes: 0, ...before });
  });

  reproduction("ordinary session exit during a later token's read leaves every token held", async () => {
    writeFixtureRepo(exampleTokenPolicy(["alpha", "beta"]));
    writeTokenConfig({
      alpha: { source: "1password", ref: "op://Private/Alpha/token" },
      beta: { source: "1password", ref: "op://Private/Beta/token" },
    });
    const fakeDocker = installTokenSyncDockerFake();
    const op = installScriptedProvider("op");
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    const statusBefore = JSON.parse(credentialSnapshot().status ?? "{}") as Record<string, unknown>;
    const betaWritesBefore = tokenWriteCount(fakeDocker.dockerLog, "beta");
    op.setMode("read", "hang", "Beta");

    const parent = await startWatchParent({ launch: "runtime", initialSourceTruth: true }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    const alpha = await waitForProviderStart(op, parent.watcherPid, "read", "Alpha");
    const beta = await waitForProviderStart(op, parent.watcherPid, "read", "Beta");
    parent.send("stop");
    const cleanup = await settleAfterCancellation(parent.watcherPid, [alpha.pid, beta.pid]);

    // The earlier token's completed write precedes the cancellation; nothing
    // after it may touch either token.
    reached();
    expect({
      ...cleanup,
      removals: tokenRemovalCount(fakeDocker.dockerLog, "alpha") + tokenRemovalCount(fakeDocker.dockerLog, "beta"),
      betaWrites: tokenWriteCount(fakeDocker.dockerLog, "beta") - betaWritesBefore,
      receipts: readReceiptNames(),
      betaStatus: (JSON.parse(credentialSnapshot().status ?? "{}") as Record<string, unknown>).beta,
    }).toEqual({ watcherGone: true, providersRunning: [], removals: 0, betaWrites: 0, receipts: ["alpha", "beta"], betaStatus: statusBefore.beta });
  });

  reproduction("EOF while provider ignores SIGTERM causes no revocation and bounded child cleanup", async () => {
    const { fakeDocker, op } = await oneTokenFixture();
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    const before = credentialSnapshot();
    op.setMode("read", "ignore-term-fail");

    const parent = await startWatchParent({ launch: "runtime", initialSourceTruth: true }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    const read = await waitForProviderStart(op, parent.watcherPid, "read", "GitHub");
    parent.send("stop");
    // The provider outlives SIGTERM by design; only the watcher's own bounded
    // KILL ends it inside the bound, before it can report a failure.
    const cleanup = await settleAfterCancellation(parent.watcherPid, [read.pid]);

    reached();
    expect({
      ...cleanup,
      completed: op.events().some((event) => event.kind === "end" && event.pid === read.pid),
      removals: tokenRemovalCount(fakeDocker.dockerLog, "github"),
      ...credentialSnapshot(),
    }).toEqual({ watcherGone: true, providersRunning: [], completed: false, removals: 0, ...before });
  });

  reproduction("a parent crash (lifetime EOF, no signal) during an op read stops the provider and changes nothing", async () => {
    const { fakeDocker, op } = await oneTokenFixture();
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    const before = credentialSnapshot();
    op.setMode("read", "slow-fail");

    const parent = await startWatchParent({ launch: "runtime", initialSourceTruth: true }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    const read = await waitForProviderStart(op, parent.watcherPid, "read", "GitHub");
    parent.send("crash");
    const cleanup = await settleAfterCancellation(parent.watcherPid, [read.pid]);

    reached();
    expect({
      ...cleanup,
      completed: op.events().some((event) => event.kind === "end" && event.pid === read.pid),
      removals: tokenRemovalCount(fakeDocker.dockerLog, "github"),
      ...credentialSnapshot(),
    }).toEqual({ watcherGone: true, providersRunning: [], completed: false, removals: 0, ...before });
  });

  reproduction("lifetime EOF while the parent PID still answers (a recycled PID) during an op read changes nothing", async () => {
    const { fakeDocker, op } = await oneTokenFixture();
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    const before = credentialSnapshot();
    op.setMode("read", "slow-fail");

    // This test process is alive and is not the watcher's parent: the PID
    // probe alone would keep the watch going.
    const parent = await startWatchParent({ launch: "plan", initialSourceTruth: true, parentPid: process.pid }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    const read = await waitForProviderStart(op, parent.watcherPid, "read", "GitHub");
    parent.send("close-pipe");
    const cleanup = await settleAfterCancellation(parent.watcherPid, [read.pid]);

    reached();
    expect({
      ...cleanup,
      completed: op.events().some((event) => event.kind === "end" && event.pid === read.pid),
      removals: tokenRemovalCount(fakeDocker.dockerLog, "github"),
      ...credentialSnapshot(),
    }).toEqual({ watcherGone: true, providersRunning: [], completed: false, removals: 0, ...before });
  });

  reproduction("a process-group SIGTERM without lifetime EOF during an op read changes nothing", async () => {
    const { fakeDocker, op } = await oneTokenFixture();
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    const before = credentialSnapshot();
    op.setMode("read", "hang");

    const parent = await startWatchParent({ launch: "runtime", initialSourceTruth: true }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    const read = await waitForProviderStart(op, parent.watcherPid, "read", "GitHub");
    // The parent stays alive and keeps the pipe open (a host shutdown or a
    // user signalling the group).
    process.kill(-parent.watcherPid, "SIGTERM");
    const cleanup = await settleAfterCancellation(parent.watcherPid, [read.pid]);
    parent.send("exit");

    reached();
    expect({ ...cleanup, removals: tokenRemovalCount(fakeDocker.dockerLog, "github"), ...credentialSnapshot() })
      .toEqual({ watcherGone: true, providersRunning: [], removals: 0, ...before });
  });

  reproduction("an interrupted manual credential sync --watch (no lifetime pipe) during an op read changes nothing", async () => {
    const { fakeDocker, op } = await oneTokenFixture({ refreshEverySeconds: 60 });
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    const before = credentialSnapshot();
    op.setMode("read", "hang");

    // The first iteration finds the token current; the next one, a simulated
    // minute later, reads it.
    const watcherPid = await startForegroundSync(harnessEnv(fakeDocker, socketPath, [op.bin], { RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "3" }), { watch: true });
    const read = await waitForProviderStart(op, watcherPid, "read", "GitHub");
    // Ctrl-C at the terminal: SIGINT to the foreground process group.
    process.kill(-watcherPid, "SIGINT");
    const cleanup = await settleAfterCancellation(watcherPid, [read.pid]);

    reached();
    expect({ ...cleanup, removals: tokenRemovalCount(fakeDocker.dockerLog, "github"), ...credentialSnapshot() })
      .toEqual({ watcherGone: true, providersRunning: [], removals: 0, ...before });
  });

  reproduction("a lifetime already closed when the watcher starts reads no source", async () => {
    const { fakeDocker, op } = await oneTokenFixture();
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    const before = credentialSnapshot();
    const writesBefore = tokenWriteCount(fakeDocker.dockerLog, "github");

    // The pipe is closed before the watcher has even booted. Its first,
    // source-truth pass must observe that, not a flag no stream event has set.
    const parent = await startWatchParent({ launch: "plan", initialSourceTruth: true, parentPid: process.pid, closePipeAtSpawn: true }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    await waitUntil(() => processGone(parent.watcherPid), 30_000);

    reached();
    expect({
      watcherGone: processGone(parent.watcherPid),
      reads: op.events().filter((event) => event.kind === "start" && event.ppid === parent.watcherPid).length,
      writes: tokenWriteCount(fakeDocker.dockerLog, "github") - writesBefore,
      ...credentialSnapshot(),
    }).toEqual({ watcherGone: true, reads: 0, writes: 0, ...before });
  });

  reproduction("ordinary session exit during a command source run keeps the held credential", async () => {
    githubOnePasswordPolicy();
    const fakeDocker = installTokenSyncDockerFake();
    const gh = installScriptedProvider("gh");
    expect((await runAdmin(() => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["gh", "auth", "token"],
    }), { PATH: gh.bin })).status).toBe(0);
    writeTokenConfig({ github: { source: "named", name: "github-cli" } });
    await seed(fakeDocker, [gh.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    const before = credentialSnapshot();
    gh.setMode("command", "hang");

    const parent = await startWatchParent({ launch: "runtime", initialSourceTruth: true }, harnessEnv(fakeDocker, socketPath, [gh.bin]));
    const run = await waitForProviderStart(gh, parent.watcherPid, "command", "gh");
    parent.send("stop");
    const cleanup = await settleAfterCancellation(parent.watcherPid, [run.pid]);

    reached();
    expect({ ...cleanup, removals: tokenRemovalCount(fakeDocker.dockerLog, "github"), ...credentialSnapshot() })
      .toEqual({ watcherGone: true, providersRunning: [], removals: 0, ...before });
  });

  reproduction("an in-flight token write cut off by session exit is not compensated by a deletion", async () => {
    const { fakeDocker, op } = await oneTokenFixture({ refreshEverySeconds: 60 });
    await seed(fakeDocker, [op.bin]);
    const { socketPath, heldWrite } = await startDockerBridge(fakeDocker.fakeBin, { holdTokenWrites: true });
    const writesBefore = tokenWriteCount(fakeDocker.dockerLog, "github");

    // A refresh pass (not the first source-truth pass): the read succeeds and
    // the write reaches the proxy, but its client has not returned yet.
    const parent = await startWatchParent({ launch: "runtime", initialSourceTruth: false }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    await heldWrite;
    expect(tokenWriteCount(fakeDocker.dockerLog, "github")).toBe(writesBefore + 1);
    parent.send("stop");
    // The remote write completes and its client may still be waiting; a stop
    // that lets the client return sees success, one that killed it sees an
    // unknown outcome. Neither is a provider failure.
    await new Promise((resolve) => setTimeout(resolve, 500));
    releaseHeldWrites?.();
    const cleanup = await settleAfterCancellation(parent.watcherPid, []);

    reached();
    expect({ ...cleanup, removals: tokenRemovalCount(fakeDocker.dockerLog, "github"), receipts: readReceiptNames() })
      .toEqual({ watcherGone: true, providersRunning: [], removals: 0, receipts: ["github"] });
  });

  reproduction("Ctrl-C during a foreground one-shot credential sync's op read keeps the held credential", async () => {
    const { fakeDocker, op } = await oneTokenFixture();
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    const before = credentialSnapshot();
    op.setMode("read", "hang");

    // `runfree credential sync` at a terminal: the same F08 path without any
    // watcher. The CLI's own SIGINT handler cannot run while `spawnSync`
    // blocks, so the deletion lands before it does.
    const syncPid = await startForegroundSync(harnessEnv(fakeDocker, socketPath, [op.bin]), { watch: false });
    const read = await waitForProviderStart(op, syncPid, "read", "GitHub");
    process.kill(-syncPid, "SIGINT");
    const cleanup = await settleAfterCancellation(syncPid, [read.pid]);

    reached();
    expect({ ...cleanup, removals: tokenRemovalCount(fakeDocker.dockerLog, "github"), ...credentialSnapshot() })
      .toEqual({ watcherGone: true, providersRunning: [], removals: 0, ...before });
  });

  reproduction("Ctrl-C at a manual credential sync --watch during an in-flight token write is not compensated by a deletion", async () => {
    const { fakeDocker, op } = await oneTokenFixture({ refreshEverySeconds: 60 });
    await seed(fakeDocker, [op.bin]);
    const { socketPath, heldWrite } = await startDockerBridge(fakeDocker.fakeBin, { holdTokenWrites: true });
    const writesBefore = tokenWriteCount(fakeDocker.dockerLog, "github");

    // The terminal's SIGINT reaches the whole foreground group, the Docker
    // client of the in-flight write included, whatever the session stop
    // protocol does. Its failure is an unknown outcome, never a removal.
    const watcherPid = await startForegroundSync(harnessEnv(fakeDocker, socketPath, [op.bin], { RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS: "3" }), { watch: true });
    await heldWrite;
    expect(tokenWriteCount(fakeDocker.dockerLog, "github")).toBe(writesBefore + 1);
    process.kill(-watcherPid, "SIGINT");
    await new Promise((resolve) => setTimeout(resolve, 500));
    releaseHeldWrites?.();
    const cleanup = await settleAfterCancellation(watcherPid, []);

    reached();
    expect({ ...cleanup, removals: tokenRemovalCount(fakeDocker.dockerLog, "github"), receipts: readReceiptNames() })
      .toEqual({ watcherGone: true, providersRunning: [], removals: 0, receipts: ["github"] });
  });

  // Behavior that must not change: genuine provider failures while the
  // parent is alive, through the same subprocess harness.

  test("a genuine nonzero exit with empty stderr while the parent is alive still revokes", async () => {
    const { fakeDocker, op } = await oneTokenFixture();
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    op.setMode("read", "fail-empty");

    const parent = await startWatchParent({ launch: "runtime", initialSourceTruth: true }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    expect(await waitUntil(() => fs.existsSync(`${parent.configPath}.done`), 30_000)).toBe(true);
    parent.send("stop");

    expect(tokenRemovalCount(fakeDocker.dockerLog, "github")).toBeGreaterThanOrEqual(1);
    expect(readReceiptNames()).toEqual([]);
    expect(readTokenStatus().github).toMatchObject({ ok: false, state: "failed", message: "op read failed" });
  }, 60_000);

  test("an op read timeout while the parent is alive keeps the receipt-proven value as stale", async () => {
    const { fakeDocker, op } = await oneTokenFixture({ refreshEverySeconds: 60 });
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    op.setMode("read", "hang");

    // Long enough for a loaded host to start the script, far short of its 30 s hang.
    const parent = await startWatchParent(
      { launch: "runtime", initialSourceTruth: false },
      harnessEnv(fakeDocker, socketPath, [op.bin], { RUNFREE_TEST_OP_READ_TIMEOUT_MS: "3000" }),
    );
    const read = await waitForProviderStart(op, parent.watcherPid, "read", "GitHub");
    expect(await waitUntil(() => fs.existsSync(`${parent.configPath}.done`), 30_000)).toBe(true);
    expect(await waitUntil(() => processGone(read.pid), 5_000)).toBe(true);
    parent.send("stop");

    expect(tokenRemovalCount(fakeDocker.dockerLog, "github")).toBe(0);
    expect(readReceiptNames()).toEqual(["github"]);
    expect(readTokenStatus().github).toMatchObject({ ok: false, state: "stale" });
    expect(readTokenStatus().github.message).toContain("op read timed out");
  }, 60_000);

  test("a provider killed by its own signal while the parent is alive keeps its definitive classification", async () => {
    const { fakeDocker, op } = await oneTokenFixture();
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    op.setMode("read", "self-term");

    const parent = await startWatchParent({ launch: "runtime", initialSourceTruth: true }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    expect(await waitUntil(() => fs.existsSync(`${parent.configPath}.done`), 30_000)).toBe(true);
    parent.send("stop");

    // The provider died of its own signal (no `end`); the watcher's lifetime
    // never ended, so this is a provider failure, not host cancellation.
    const reads = op.events().filter((event) => event.kind === "start" && event.ppid === parent.watcherPid);
    expect(reads.length).toBeGreaterThanOrEqual(1);
    expect(op.events().some((event) => event.kind === "end" && reads.some((read) => read.pid === event.pid))).toBe(false);
    expect(tokenRemovalCount(fakeDocker.dockerLog, "github")).toBeGreaterThanOrEqual(1);
    expect(readReceiptNames()).toEqual([]);
    expect(readTokenStatus().github).toMatchObject({ ok: false, state: "failed", message: "op read failed" });
  }, 60_000);

  test("definitive revocation still deletes", async () => {
    const { fakeDocker, op } = await oneTokenFixture();
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    op.setMode("read", "fail-not-found");

    // The watcher's detached first pass keeps a value it merely cannot read,
    // but a classified definitive failure is how a revocation shows.
    const parent = await startWatchParent({ launch: "runtime", initialSourceTruth: true }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    expect(await waitUntil(() => fs.existsSync(`${parent.configPath}.done`), 30_000)).toBe(true);
    parent.send("stop");

    // The first pass removes it; the watch's retry of the failed source may
    // remove the already absent file once more.
    expect(tokenRemovalCount(fakeDocker.dockerLog, "github")).toBeGreaterThanOrEqual(1);
    expect(readReceiptNames()).toEqual([]);
    expect(readTokenStatus().github).toMatchObject({ ok: false, state: "failed" });
    expect(readTokenStatus().github.message).toContain("isn't an item");
  }, 60_000);

  test("cancelled source preserves byte-identical receipt", async () => {
    // A JWT source: the watcher's cancellation reaches the private key's read.
    writeFixtureRepo({
      hosts: ["api.appstoreconnect.apple.com"],
      tokens: {
        "appstore-connect": {
          description: "App Store Connect token",
          credentials: [{ host: "api.appstoreconnect.apple.com", header: "Authorization", scheme: "bearer" }],
        },
      },
    });
    const fakeDocker = installTokenSyncDockerFake();
    const op = installScriptedProvider("op");
    const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    fs.writeFileSync(path.join(op.dir, "pem"), privateKey.export({ format: "pem", type: "pkcs8" }).toString());
    op.setMode("read", "pem");
    const opEnv = { OP_SERVICE_ACCOUNT_TOKEN: "op-session", PATH: [fakeDocker.fakeBin, op.bin, process.env.PATH ?? ""].join(path.delimiter) };
    expect((await runAdmin(() => sourceAddJwtIntent({
      name: "appstore-connect-jwt",
      replaceSource: false,
      alg: "ES256",
      privateKeyRef: "op://Private/AuthKey_KEY123",
      ttl: "19m",
      claims: ["iss=ISSUER123", "aud=appstoreconnect-v1"],
      headers: ["kid=KEY123"],
    }), opEnv)).status).toBe(0);
    writeTokenConfig({ "appstore-connect": { source: "named", name: "appstore-connect-jwt" } });
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    const receiptsBefore = fs.readFileSync(tokenReceiptsFilePath());
    const statusBefore = fs.readFileSync(tokenStatusFilePath());
    op.setMode("read", "hang");

    const parent = await startWatchParent({ launch: "runtime", initialSourceTruth: true }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    const keyRead = await waitForProviderStart(op, parent.watcherPid, "read", "AuthKey_KEY123");
    parent.send("stop");
    const cleanup = await settleAfterCancellation(parent.watcherPid, [keyRead.pid]);

    expect(cleanup).toEqual({ watcherGone: true, providersRunning: [] });
    expect(fs.readFileSync(tokenReceiptsFilePath()).equals(receiptsBefore)).toBe(true);
    expect(fs.readFileSync(tokenStatusFilePath()).equals(statusBefore)).toBe(true);
    expect(tokenRemovalCount(fakeDocker.dockerLog, "appstore-connect")).toBe(0);
  }, 60_000);

  test("next warm launch does not re-read due to cancellation damage", async () => {
    const { fakeDocker, op } = await oneTokenFixture();
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    op.setMode("read", "hang");
    const parent = await startWatchParent({ launch: "runtime", initialSourceTruth: true }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    const read = await waitForProviderStart(op, parent.watcherPid, "read", "GitHub");
    parent.send("stop");
    expect(await settleAfterCancellation(parent.watcherPid, [read.pid])).toEqual({ watcherGone: true, providersRunning: [] });
    const readsBefore = op.events().filter((event) => event.kind === "start").length;
    const writesBefore = tokenWriteCount(fakeDocker.dockerLog, "github");

    // The next launch's receipt-gated preparation: the receipt and the held
    // value the cancelled watch left behind still prove the token current.
    selectEffectiveControlsFromProjectPolicy();
    const warm = await runAdmin(async () => {
      prepareRuntimeTokenSources({ mode: "convergence" });
      await credentialSyncIntent({ ...syncInput, verbose: true, mode: "startup-convergence" });
    }, { FAKE_DOCKER_LOG: fakeDocker.dockerLog, OP_SERVICE_ACCOUNT_TOKEN: "op-session", PATH: [fakeDocker.fakeBin, op.bin, process.env.PATH ?? ""].join(path.delimiter) });

    expect(warm.status, warm.stderr).toBe(0);
    expect(op.events().filter((event) => event.kind === "start").length).toBe(readsBefore);
    expect(tokenWriteCount(fakeDocker.dockerLog, "github")).toBe(writesBefore);
    expect(tokenRemovalCount(fakeDocker.dockerLog, "github")).toBe(0);
  }, 60_000);

  test("retry after interrupted watch succeeds", async () => {
    const { fakeDocker, op } = await oneTokenFixture();
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    op.setMode("read", "hang");
    const interrupted = await startWatchParent({ launch: "runtime", initialSourceTruth: true }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    const read = await waitForProviderStart(op, interrupted.watcherPid, "read", "GitHub");
    interrupted.send("stop");
    expect(await settleAfterCancellation(interrupted.watcherPid, [read.pid])).toEqual({ watcherGone: true, providersRunning: [] });
    const [receiptBefore] = JSON.parse(fs.readFileSync(tokenReceiptsFilePath(), "utf8")).receipts as Array<{ resolvedAt: number }>;
    const writesBefore = tokenWriteCount(fakeDocker.dockerLog, "github");

    // Nothing the interrupted watch held (its locks, its providers) is in the
    // way of the next session's watcher.
    op.setMode("read", "ok");
    const next = await startWatchParent({ launch: "runtime", initialSourceTruth: true }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    expect(await waitUntil(() => fs.existsSync(`${next.configPath}.done`), 30_000)).toBe(true);
    next.send("stop");

    expect(tokenWriteCount(fakeDocker.dockerLog, "github")).toBe(writesBefore + 1);
    expect(readTokenStatus().github).toMatchObject({ ok: true, state: "ok" });
    const [receiptAfter] = JSON.parse(fs.readFileSync(tokenReceiptsFilePath(), "utf8")).receipts as Array<{ resolvedAt: number }>;
    expect(receiptAfter.resolvedAt).toBeGreaterThan(receiptBefore.resolvedAt);
  }, 60_000);

  test("a session exit leaves a peer session's watcher and the held credential intact", async () => {
    const { fakeDocker, op } = await oneTokenFixture({ refreshEverySeconds: 60 });
    await seed(fakeDocker, [op.bin]);
    const { socketPath } = await startDockerBridge(fakeDocker.fakeBin);
    // The peer's watcher waits for its next refresh (a long real sleep here).
    const peerEnv = harnessEnv(fakeDocker, socketPath, [op.bin], { RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS: "30000" });
    const peer = await startWatchParent({ launch: "runtime", initialSourceTruth: false }, peerEnv);
    // The exiting session's watcher is mid-read when its session ends.
    op.setMode("read", "hang");
    const exiting = await startWatchParent({ launch: "runtime", initialSourceTruth: true }, harnessEnv(fakeDocker, socketPath, [op.bin]));
    const read = await waitForProviderStart(op, exiting.watcherPid, "read", "GitHub");
    const before = credentialSnapshot();
    exiting.send("stop");
    const cleanup = await settleAfterCancellation(exiting.watcherPid, [read.pid]);

    expect({ ...cleanup, peerRunning: !processGone(peer.watcherPid), removals: tokenRemovalCount(fakeDocker.dockerLog, "github"), ...credentialSnapshot() })
      .toEqual({ watcherGone: true, providersRunning: [], peerRunning: true, removals: 0, ...before });
    peer.send("stop");
  }, 60_000);

  for (const kill of ["SIGKILL", "timeout"] as const) {
    test(`a token write whose client ended by ${kill} removes nothing and makes the next pass re-read the source`, async () => {
      const { fakeDocker, op } = await oneTokenFixture();
      await seed(fakeDocker, [op.bin]);
      const writesBefore = tokenWriteCount(fakeDocker.dockerLog, "github");
      const env = { FAKE_DOCKER_LOG: fakeDocker.dockerLog, OP_SERVICE_ACCOUNT_TOKEN: "op-session", PATH: [fakeDocker.fakeBin, op.bin, process.env.PATH ?? ""].join(path.delimiter) };

      const killed = await runAdmin(() => credentialSyncIntent(syncInput), { ...env, FAKE_DOCKER_TOKEN_WRITE_KILL: kill });

      expect(killed.status).not.toBe(0);
      expect(killed.stderr).toContain("its outcome is unknown and the next sync re-reads it");
      expect(tokenWriteCount(fakeDocker.dockerLog, "github")).toBe(writesBefore + 1);
      expect(tokenRemovalCount(fakeDocker.dockerLog, "github")).toBe(0);
      // The status is left as it was; only the receipt stops claiming the value.
      expect(readTokenStatus().github).toMatchObject({ ok: true, state: "ok" });
      expect(readReceiptNames()).toEqual([]);

      // Reclaim: the next launch's receipt-gated preparation finds the token
      // unproven, re-reads it before the lock, and the locked sync writes it.
      const readsBefore = op.events().filter((event) => event.kind === "start").length;
      selectEffectiveControlsFromProjectPolicy();
      const warm = await runAdmin(async () => {
        prepareRuntimeTokenSources({ mode: "convergence" });
        await credentialSyncIntent({ ...syncInput, mode: "startup-convergence" });
      }, env);
      expect(warm.status, warm.stderr).toBe(0);
      expect(op.events().filter((event) => event.kind === "start").length).toBe(readsBefore + 1);
      expect(tokenWriteCount(fakeDocker.dockerLog, "github")).toBe(writesBefore + 2);
      expect(readReceiptNames()).toEqual(["github"]);
    }, 60_000);
  }

  // Last in the block: a reproduction is only evidence of the defect if its
  // harness reached the effect it asserts on.
  test("every cancellation reproduction that ran reached its effect assertion", () => {
    expect([...reproductionProgress].filter(([, done]) => !done).map(([name]) => name)).toEqual([]);
  });
});
