import childProcess from "node:child_process";
import type { SpawnSyncOptions, SpawnSyncReturns } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import util from "node:util";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { validateNetworkPolicy, type PolicyJson } from "@runfree/runtime-contracts/network-policy";
import { defaultConfig, projectControlPaths, type ProjectInfo } from "../packages/cli/src/config.ts";
import { approveNetworkCandidate, approveRuntimeIsolationControl } from "../packages/cli/src/control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../packages/cli/src/control/candidates.ts";
import { publishEffectivePolicyGeneration } from "../packages/cli/src/control/effective.ts";
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
import { flushWarnings } from "../packages/cli/src/warnings.ts";
import { cliEntryArgv } from "../tests/support/prebuilt-entry.ts";

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
    signal: null,
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

async function runAdmin(action: () => void | Promise<void>, extraEnv: NodeJS.ProcessEnv = {}): Promise<AdminRunResult> {
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
function installTokenSyncDockerFake(options: { composeProject?: string; onMarkerSwap?: () => void; proxyId?: string } = {}): { dockerLog: string; fakeBin: string } {
  const proxyId = options.proxyId ?? "proxy-id";
  const onMarkerSwap = options.onMarkerSwap;
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
        const rows = expectedTokenSyncComponentRows(args.slice(3), proxyId);
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
      if (text.includes(".State.Running")) return spawnResult({ stdout: "true\n" });
      if (text.includes(".State.StartedAt")) {
        if (env.FAKE_DOCKER_STARTED_AT_STATUS) {
          return spawnResult({ status: Number(env.FAKE_DOCKER_STARTED_AT_STATUS), stderr: "transient inspect failure\n" });
        }
        return spawnResult({ stdout: "2026-06-18T00:00:00.000000000Z\n" });
      }
      if (text.includes("com.docker.compose.project")) return spawnResult({ stdout: `${composeProjectLabel}\n` });
      return spawnResult();
    }
    if (args[0] !== "exec") return spawnResult();
    if (text.includes("ls -1 '/run/runfree-proxy-secrets'")) {
      if (env.FAKE_DOCKER_SECRET_LIST_STATUS) {
        return spawnResult({ status: Number(env.FAKE_DOCKER_SECRET_LIST_STATUS), stderr: "transient exec failure\n" });
      }
      const held = Array.from(fakeProxySecretStore).sort();
      return spawnResult({ stdout: held.length > 0 ? `${held.join("\n")}\n` : "" });
    }
    if (text.includes("request-proxy.json")) {
      const generation = env.FAKE_PROXY_STATUS_GENERATION ?? "";
      if (!generation) return spawnResult({ stdout: "{}\n{}\n" });
      return spawnResult({ stdout: `${JSON.stringify({ generation, rulesetVerified: true, appliedAt: "2026-06-18T00:00:00.000Z" })}\n${JSON.stringify({ generation, appliedAt: "2026-06-18T00:00:00.000Z" })}\n` });
    }
    {
      const writeMatch = /mv '\/run\/runfree-proxy-secrets\/[^']*' '\/run\/runfree-proxy-secrets\/([^']+)'/.exec(text);
      if (writeMatch) {
        fakeProxySecretStore.add(writeMatch[1]);
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
  return { dockerLog, fakeBin };
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
    if [ "$2" = "-aq" ]; then
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
  restart) exit 1 ;;
  start) exit 1 ;;
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
    expect(readJsonLines(fakeDocker.dockerLog).some((entry) => Array.isArray(entry.args) && entry.args[0] === "restart")).toBe(true);
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
    expect(readJsonLines(fakeDocker.dockerLog).some((entry) => Array.isArray(entry.args) && entry.args[0] === "restart")).toBe(false);
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
    // once populated. The store is replaced right after alpha's iteration-2
    // write, so only the post-loop fence stands between the replaced store and
    // the iteration-2 status/receipt persistence.
    writeFixtureRepo(exampleTokenPolicy(["alpha", "bravo", "charlie"]));
    writeTokenConfig({
      alpha: { source: "env", env: "ALPHA_TOKEN", refreshEverySeconds: 1 },
      bravo: { source: "1password", ref: "op://Personal/bravo/token" },
      charlie: { source: "1password", ref: "op://Personal/charlie/token" },
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
    // re-observation; each iteration pays one post-loop fence.
    const markerReads = readJsonLines(fakeDocker.dockerLog).filter((entry) => Array.isArray(entry.args)
      && entry.args[0] === "exec" && entry.args.join(" ").includes("cat /run/runfree-runtime-validation.json")).length;
    expect(markerReads).toMatchInlineSnapshot(`12`);
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
      "--user",
      "1001:1001",
      "-i",
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
    // bravo and charlie resolved once, in iteration 1 only.
    expect(readJsonLines(opLogPath)).toHaveLength(2);
    expect(tokenRemovalCount(fakeDocker.dockerLog)).toBe(1);
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
      Array.isArray(entry.args) && entry.args.join(" ").includes("ls -1 '/run/runfree-proxy-secrets'"));
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
    // Close the parent's write end: the watcher must stop within one sleep
    // tick even though the "parent" PID is still alive.
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
