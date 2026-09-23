import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { assertSessionDisruptionAuthorized } from "./runtime/session-disruption.ts";

import { DEFAULT_WRITE_ACTION, effectiveWriteAction, validateNetworkPolicy } from "@runfree/runtime-contracts/network-policy";
import { service, serviceHostNames } from "../../../scripts/services.ts";
import {
  resolveAgentCommand,
  resolveDefaultAgentName,
} from "./config.ts";
import { effectiveRuntimeDigest } from "./agent-image.ts";
import { builtinAgent } from "./agents.ts";
import { createAdminState } from "./admin/context.ts";
import { prepareRuntimeTokenSources, clearPreparedRuntimeTokenSources, admitPreparedRuntimeTokenSources } from "./admin/admin-core.ts";
import { convergeProxyPolicy, credentialSyncIntent, prepareEffectiveRuntimeIntent, runAdminAction } from "./admin/options.ts";
import { planDesiredServiceEnable } from "./admin/service-policy.ts";
import { compileDesiredPolicies } from "./control/compiler.ts";
import { readActiveEffectiveControl } from "./control/effective.ts";
import { ControlsNotApprovedError } from "./control/refusals.ts";
import { readApprovedNetworkPolicy } from "./control/approvals.ts";
import { mutateDesiredService } from "./control/service-mutation.ts";
import {
  captureQuiescedDesiredPolicyCandidate,
  requireUsableApprovalSelection,
} from "./control/workflow.ts";
import { die } from "./errors.ts";
import { composeProjectName, projectHash, runtimeEnvironment } from "./runtime/env.ts";
import { resumeInterruptedSessionThroughAdmission } from "./runtime/session-admission-resume.ts";
import {
  assertBuiltinLaunchAgent,
  launchConfiguredAgentThroughAdmission,
  launchShellThroughAdmission,
} from "./runtime/session-public-launch.ts";
import { preparedRuntimeContext, preparedRuntimeProxyId, type PreparedRuntime } from "./runtime/prepared-runtime.ts";
import { createRuntimeAdapters } from "./runtime/adapters.ts";
import { grantCoverageLabel, grantRemainingSeconds, readWriteApprovalsStatus } from "./runtime/approvals.ts";
import {
  printAuditStatusLine,
} from "./runtime/audit.ts";
import { printSessionDenialSummary } from "./runtime/denial-summary.ts";
import {
  runtimeComponentDiagnosticLines,
  runtimeLifecycleStateDiagnosticLines,
} from "./runtime/component-diagnostics.ts";
import { prepareDependencyOverlayPlan } from "./runtime/dependency-overlays.ts";
import { runFencedProjectDestroy } from "./runtime/destroy.ts";
import { containerMissingNetwork, dockerClientEnvOptions } from "./runtime/docker.ts";
import {
  activeOrStartingAgentSessions,
  printSessions,
  projectLifecycleLockPath,
  tryAcquireProjectLifecycleLockWithRetry,
} from "./runtime/sessions.ts";
import { readProxySessionFiles, type ProxySessionFile } from "./runtime/session-reconcile.ts";
import {
  classifyRecoveryItemLive,
  formatRecoveryInventory,
  scanRecoveryInventory,
  sessionContainerRecoveryLiveInputs,
  type RecoveryItem,
  type RecoveryLiveInputs,
} from "./runtime/recovery.ts";
import { generatedRuntimeContextIfAvailable } from "./runtime/images.ts";
import {
  listIngressForwarders,
  removeValidatedEmptyManagedIngressHostNetworkAfterForcedSweep,
} from "./runtime/ingress-forwarder.ts";
import {
  planValidatedIngressForwarders,
  removeValidatedIngressForwarders,
} from "./runtime/ingress-forwarder-ownership.ts";
import { createRuntimePlan } from "./runtime/plan.ts";
import { planRuntimeUpgradeFromV2State, startRuntime } from "./runtime/startup.ts";
import type {
  CaptureResult,
  PiProviderChoice,
  PiProviderOption,
  RuntimeAdminIntent,
  RuntimeContext,
  RuntimeIO,
  TokenResolutionReceipt,
} from "./runtime/types.ts";
import { flushWarnings } from "./warnings.ts";
import { remedy } from "./remedies.ts";
import { setMcpLogContext } from "./runtime/mcp.ts";

export { containerMissingNetwork };
export type { CaptureResult, RuntimeAdminIntent, RuntimeContext, RuntimeIO } from "./runtime/types.ts";

function run(command: string, args: string[], options: childProcess.SpawnSyncOptions = {}): number {
  const result = childProcess.spawnSync(command, args, {
    stdio: "inherit",
    ...options,
  });
  if (result.error) die(result.error.message);
  return result.status ?? 1;
}

function capture(command: string, args: string[], options: childProcess.SpawnSyncOptions = {}): CaptureResult {
  const result = childProcess.spawnSync(command, args, {
    encoding: "utf8",
    ...options,
  });
  return {
    status: result.status ?? 1,
    stdout: typeof result.stdout === "string" ? result.stdout : "",
    stderr: typeof result.stderr === "string" ? result.stderr : "",
  };
}

function commandExists(command: string, options: childProcess.SpawnSyncOptions = {}): boolean {
  return childProcess.spawnSync("command", ["-v", command], {
    shell: true,
    stdio: "ignore",
    ...options,
  }).status === 0;
}

function confirm(question: string): boolean {
  if (!process.stdin.isTTY || !process.stderr.isTTY) return false;
  // Defined flush point: the warnings that motivate a prompt print before it.
  flushWarnings();
  process.stderr.write(question);
  const buffer = Buffer.alloc(1);
  let answer = "";
  while (true) {
    const bytes = fs.readSync(0, buffer, 0, 1, null);
    if (bytes === 0) break;
    const char = buffer.toString("utf8", 0, bytes);
    if (char === "\n" || char === "\r") break;
    answer += char;
  }
  const normalized = answer.trim().toLowerCase();
  return normalized === "y" || normalized === "yes";
}

const PI_PROVIDER_OPTIONS: readonly PiProviderOption[] = [
  { value: "agent-codex", label: "ChatGPT Plus/Pro (OpenAI model provider access)" },
  { value: "agent-claude", label: "Claude Pro/Max (Anthropic provider; third-party usage may incur billed extra usage)" },
  { value: "configure", label: "Configure another service" },
  { value: "custom", label: "Continue with custom/no provider" },
];

function choosePiProvider(options: readonly PiProviderOption[]): PiProviderChoice | undefined {
  if (!process.stdin.isTTY || !process.stderr.isTTY) return undefined;
  process.stderr.write(`Choose Pi provider access:\n${options.map((option, index) => `  ${index + 1}. ${option.label}`).join("\n")}\nChoice [1-${options.length}]: `);
  const buffer = Buffer.alloc(1);
  let answer = "";
  while (true) {
    const bytes = fs.readSync(0, buffer, 0, 1, null);
    if (bytes === 0) break;
    const char = buffer.toString("utf8", 0, bytes);
    if (char === "\n" || char === "\r") break;
    answer += char;
  }
  const index = Number(answer.trim()) - 1;
  return Number.isInteger(index) ? options[index]?.value : undefined;
}

type TokenAutoRefreshHandle = {
  stop: () => void;
};

type RunfreeSelfInvocation = {
  args: string[];
  command: string;
};

type RunfreeSelfInvocationInput = {
  argv: readonly string[];
  execArgv: readonly string[];
  execPath: string;
  existsSync: (filePath: string) => boolean;
  sameExistingFile: (left: string, right: string) => boolean;
};

type TokenAutoRefreshSpawnPlan = {
  args: string[];
  command: string;
  options: childProcess.SpawnOptions;
  receiptFd?: number;
  receiptPayload?: string;
  // Parent-liveness pipe: the parent holds the write end (and never writes);
  // the watcher treats EOF/close on its read end as parent death. PIDs are
  // recycled, so the PID probe alone could leave a watcher holding source
  // access (1Password) alive under an unrelated process.
  lifetimeFd: number;
};

function sameExistingFile(left: string, right: string): boolean {
  try {
    return fs.realpathSync(left) === fs.realpathSync(right);
  } catch {
    return false;
  }
}

function isBunVirtualEntrypoint(filePath: string): boolean {
  return filePath === "/$bunfs/root/runfree" || filePath.startsWith("/$bunfs/");
}

export function resolveRunfreeSelfInvocation(input: RunfreeSelfInvocationInput): RunfreeSelfInvocation {
  const scriptPath = input.argv[1];
  if (
    scriptPath
    && !isBunVirtualEntrypoint(scriptPath)
    && input.existsSync(scriptPath)
    && !input.sameExistingFile(scriptPath, input.execPath)
  ) {
    return { command: input.execPath, args: [...input.execArgv, scriptPath] };
  }
  return { command: input.execPath, args: [] };
}

function runfreeSelfInvocation(): RunfreeSelfInvocation {
  return resolveRunfreeSelfInvocation({
    argv: process.argv,
    execArgv: process.execArgv,
    execPath: process.execPath,
    existsSync: fs.existsSync,
    sameExistingFile,
  });
}

export function buildTokenAutoRefreshSpawnPlan(input: {
  base: RunfreeSelfInvocation;
  context: RuntimeContext;
  parentPid: number;
  receipts?: TokenResolutionReceipt[];
  stderrFd?: number;
}): TokenAutoRefreshSpawnPlan {
  const receipts = input.receipts ?? [];
  // Build the stdio array once and derive each channel's fd from its slot, so
  // the fd numbers handed to the watcher (via env) can never disagree with
  // the pipes actually wired up.
  const stdio: Array<number | "ignore" | "pipe"> = ["ignore", "ignore", input.stderrFd ?? "ignore"];
  const receiptFd = receipts.length > 0 ? stdio.push("pipe") - 1 : undefined;
  const lifetimeFd = stdio.push("pipe") - 1;
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...input.context.env,
    RUNFREE_TOKEN_SYNC_WATCH_PARENT_PID: String(input.parentPid),
    RUNFREE_TOKEN_SYNC_LIFETIME_FD: String(lifetimeFd),
  };
  if (receiptFd === undefined) {
    delete env.RUNFREE_TOKEN_SYNC_RECEIPT_FD;
  } else {
    env.RUNFREE_TOKEN_SYNC_RECEIPT_FD = String(receiptFd);
  }
  return {
    command: input.base.command,
    args: [
      ...input.base.args,
      "--workspace",
      input.context.projectRoot,
      "credential",
      "sync",
      "--watch",
      "--quiet",
      "--delay-first-sync",
    ],
    options: {
      detached: process.platform !== "win32",
      env,
      stdio,
    },
    receiptFd,
    receiptPayload: receiptFd === undefined ? undefined : JSON.stringify(receipts),
    lifetimeFd,
  };
}

function tokenAutoRefreshLogPath(context: RuntimeContext): string {
  return path.join(context.project.paths.stateDir, "token-auto-refresh.log");
}

function openTokenAutoRefreshLog(context: RuntimeContext): number | undefined {
  try {
    fs.mkdirSync(context.project.paths.stateDir, { recursive: true, mode: 0o700 });
    return fs.openSync(tokenAutoRefreshLogPath(context), "a", 0o600);
  } catch {
    return undefined;
  }
}

// Close the parent's write end of the lifetime pipe so the watcher sees EOF
// promptly, then signal. The pipe also closes automatically if this process
// dies uncleanly — that is the point of pipe-based liveness.
function closeTokenAutoRefreshLifetimePipe(child: childProcess.ChildProcess, plan: TokenAutoRefreshSpawnPlan): void {
  try {
    child.stdio[plan.lifetimeFd]?.destroy();
  } catch {
    // The watcher's PID probe remains as the secondary liveness signal.
  }
}

function stopTokenAutoRefreshChild(child: childProcess.ChildProcess): void {
  if (child.exitCode !== null || child.signalCode !== null) return;
  if (process.platform !== "win32" && child.pid !== undefined) {
    try {
      process.kill(-child.pid, "SIGTERM");
      return;
    } catch {
      // Fall back to killing the direct child if process-group cleanup fails.
    }
  }
  child.kill("SIGTERM");
}

function writeTokenResolutionReceipts(child: childProcess.ChildProcess, plan: TokenAutoRefreshSpawnPlan): void {
  if (plan.receiptFd === undefined || plan.receiptPayload === undefined) return;
  const stream = child.stdio[plan.receiptFd];
  if (!stream || !("end" in stream)) return;
  stream.on("error", () => {});
  stream.end(plan.receiptPayload);
}

function startTokenAutoRefreshProcess(context: RuntimeContext, receipts: TokenResolutionReceipt[] = []): TokenAutoRefreshHandle {
  const stderrFd = openTokenAutoRefreshLog(context);
  const plan = buildTokenAutoRefreshSpawnPlan({
    base: runfreeSelfInvocation(),
    context,
    parentPid: process.pid,
    receipts,
    stderrFd,
  });
  let child: childProcess.ChildProcess;
  try {
    child = childProcess.spawn(plan.command, plan.args, plan.options);
    writeTokenResolutionReceipts(child, plan);
    // Hold the lifetime pipe's write end open for the session, but never let
    // it keep this process alive: parent exit (clean or not) closes it and
    // the watcher stops within one sleep tick.
    const lifetime = child.stdio[plan.lifetimeFd];
    lifetime?.on("error", () => {});
    (lifetime as { unref?: () => void } | null | undefined)?.unref?.();
  } finally {
    if (stderrFd !== undefined) {
      try {
        fs.closeSync(stderrFd);
      } catch {
        // The child has already received its copy of the descriptor.
      }
    }
  }
  child.on("error", () => {});
  return {
    stop: () => {
      closeTokenAutoRefreshLifetimePipe(child, plan);
      stopTokenAutoRefreshChild(child);
    },
  };
}

async function withTokenAutoRefresh(
  context: RuntimeContext,
  io: RuntimeIO,
  receipts: TokenResolutionReceipt[] | undefined,
  runSession: () => number | Promise<number>,
): Promise<number> {
  const autoRefresh = io.startTokenAutoRefresh?.(context, receipts) ?? { stop: () => {} };
  try {
    return await runSession();
  } finally {
    autoRefresh.stop();
  }
}

function anyEffectiveAskHost(context: RuntimeContext): boolean {
  try {
    const policy = readActiveEffectiveControl(context.project)?.policy;
    return policy
      ? validateNetworkPolicy(policy).allowedHosts.some((host) =>
          effectiveWriteAction(validateNetworkPolicy(policy), host) === "ask")
      : false;
  } catch {
    return false;
  }
}

// Attached interactive sessions register the approver heartbeat (LOW-1 "who
// counts"): a human at the session gets the full hold window even before
// opening the approvals tab, while headless runs keep the fast-deny. The
// heartbeat is a detached self-invocation because the session exec blocks
// this process; it exits when this process dies.
function startApprovalsHeartbeatProcess(context: RuntimeContext): { stop: () => void } {
  const base = runfreeSelfInvocation();
  try {
    const child = childProcess.spawn(base.command, [
      ...base.args,
      "--workspace",
      context.projectRoot,
      "approvals",
      "--heartbeat",
      "--parent-pid",
      String(process.pid),
    ], {
      detached: process.platform !== "win32",
      env: { ...process.env, ...context.env },
      stdio: "ignore",
    });
    child.on("error", () => {});
    child.unref();
    return {
      stop: () => {
        try {
          child.kill("SIGTERM");
        } catch {
          // The parent-pid probe stops the loop on its next tick anyway.
        }
      },
    };
  } catch {
    return { stop: () => {} };
  }
}

// The retired --write-approval override file. Nothing has read it since the
// desired/effective cutover; stop and destroy still clear a leftover copy so
// older state does not linger as an apparent control.
export function clearRetiredWriteApprovalOverride(context: RuntimeContext): void {
  fs.rmSync(path.join(context.project.paths.stateDir, "write-approval-override.json"), { force: true });
}

async function withWriteApprovalSession(
  context: RuntimeContext,
  runSession: () => number | Promise<number>,
): Promise<number> {
  if (process.stdout.isTTY !== true || !anyEffectiveAskHost(context)) return await runSession();
  console.log("writes need your approval this session — run 'runfree approvals' in another terminal to review them");
  const heartbeat = startApprovalsHeartbeatProcess(context);
  try {
    return await runSession();
  } finally {
    heartbeat.stop();
  }
}

async function operationalServiceIds(context: RuntimeContext, io: RuntimeIO): Promise<Set<string>> {
  // These reads refuse for every record that is not `valid` except a genuinely
  // absent one, so the worktree fallback below can only be reached when this
  // project has no approvals at all. Under a binding mismatch it used to be
  // reachable, and a replacement checkout listing a service in its own desired
  // policy would then present an empty `missing` set and skip the host-list
  // review, leaving digest-only consent. Do not soften these reads.
  const approvedProject = readApprovedNetworkPolicy(context.projectRoot, context.project, "network-project");
  const approvedLocal = readApprovedNetworkPolicy(context.projectRoot, context.project, "network-local");
  const candidate = approvedProject && approvedLocal
    ? { project: approvedProject, local: approvedLocal }
    : await captureQuiescedDesiredPolicyCandidate(context, io);
  return new Set(Object.keys(compileDesiredPolicies({
    project: candidate.project,
    local: candidate.local,
  }).selectedServices));
}

function printAgentServiceReview(agentLabel: string, id: string): void {
  const svc = service(id);
  if (!svc) die(`built-in agent ${agentLabel} requires unknown service ${id}`);
  console.log(`${agentLabel} requires credentialless operational network access.`);
  console.log(`service: ${id}`);
  console.log("exact hosts:");
  for (const host of serviceHostNames(svc)) console.log(`  ${host}`);
  console.log("credentials: none (login state remains project-scoped to the agent)");
}

const PI_PROVIDER_PREFERENCE_FILE = "pi-provider-preference.json";

function piProviderPreferencePath(context: RuntimeContext): string {
  return path.join(context.project.paths.stateDir, PI_PROVIDER_PREFERENCE_FILE);
}

function hasRememberedCustomPiProvider(context: RuntimeContext): boolean {
  const filePath = piProviderPreferencePath(context);
  try {
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > 4_096) return false;
    const raw = JSON.parse(fs.readFileSync(filePath, "utf8")) as unknown;
    return raw !== null
      && !Array.isArray(raw)
      && typeof raw === "object"
      && (raw as { schemaVersion?: unknown }).schemaVersion === 1
      && (raw as { preference?: unknown }).preference === "custom";
  } catch {
    return false;
  }
}

function rememberCustomPiProvider(context: RuntimeContext): void {
  const filePath = piProviderPreferencePath(context);
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  try {
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.nlink !== 1) {
      die(`refusing unsafe Pi provider preference path: ${filePath}`);
    }
  } catch (error) {
    if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw error;
  }
  const temporary = `${filePath}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(temporary, `${JSON.stringify({ schemaVersion: 1, preference: "custom" }, null, 2)}\n`, {
      flag: "wx",
      mode: 0o600,
    });
    fs.renameSync(temporary, filePath);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}

async function reviewPiProvider(
  context: RuntimeContext,
  io: RuntimeIO,
  quiet: boolean,
): Promise<{ changed: boolean; status: number }> {
  if ((await operationalServiceIds(context, io)).size > 0 || hasRememberedCustomPiProvider(context)) {
    return { changed: false, status: 0 };
  }
  if (!(io.isInteractive?.() ?? (process.stdin.isTTY === true && process.stdout.isTTY === true))) {
    console.error("Pi has no recognized provider route; continuing with custom/no provider and deny-all network policy.");
    console.error("configure provider access with: runfree service enable <id>");
    console.error("service ids are listed by: runfree service enable --help");
    return { changed: false, status: 0 };
  }
  const choice = io.choosePiProvider?.(PI_PROVIDER_OPTIONS);
  if (choice === undefined) {
    console.error("No Pi provider selected; continuing without changing project policy.");
    return { changed: false, status: 0 };
  }
  if (choice === "configure") {
    console.error("pi did not start; configure provider access with: runfree service enable <id>");
    console.error("service ids are listed by: runfree service enable --help");
    return { changed: false, status: 1 };
  }
  if (choice === "custom") {
    rememberCustomPiProvider(context);
    console.log("Pi provider preference: custom/no provider (advisory only; no network access granted)");
    return { changed: false, status: 0 };
  }

  printAgentServiceReview("Pi", choice);
  if (!io.confirm(`Enable ${choice} for this project? [y/N] `)) {
    console.error("Pi provider activation cancelled; project policy was not changed.");
    return { changed: false, status: 1 };
  }
  const status = await io.admin({ kind: "ensure-agent-service", id: choice, quiet }, context);
  if (status !== 0) return { changed: false, status };
  console.log("Pi login state remains Pi-owned; use /login inside Pi.");
  return { changed: true, status: 0 };
}

async function reviewAgentOperationalServices(
  context: RuntimeContext,
  io: RuntimeIO,
  agentName: string,
  quiet: boolean,
): Promise<{ changed: boolean; status: number }> {
  const descriptor = builtinAgent(agentName);
  if (!descriptor || descriptor.requiredServices.length === 0) return { changed: false, status: 0 };
  const enabled = await operationalServiceIds(context, io);
  const missing = descriptor.requiredServices.filter((id) => !enabled.has(id));
  if (missing.length === 0) return { changed: false, status: 0 };

  if (!(io.isInteractive?.() ?? (process.stdin.isTTY === true && process.stdout.isTTY === true))) {
    const commands = missing.map((id) => `runfree service enable ${id}`);
    console.error(`${descriptor.label} operational network access is not enabled.`);
    for (const command of commands) console.error(`Run: ${command}`);
    return { changed: false, status: 1 };
  }

  for (const id of missing) {
    printAgentServiceReview(descriptor.label, id);
    if (!io.confirm(`Enable ${id} for this project? [y/N] `)) {
      console.error(`${descriptor.label} launch cancelled; project policy was not changed.`);
      return { changed: false, status: 1 };
    }
  }

  for (const id of missing) {
    const status = await io.admin({ kind: "ensure-agent-service", id, quiet }, context);
    if (status !== 0) return { changed: false, status };
  }
  return { changed: true, status: 0 };
}

async function runConfiguredAgent(
  context: RuntimeContext,
  io: RuntimeIO,
  agentName: string,
  options: { quiet?: boolean; useApprovedPolicy?: boolean; verbose?: boolean } = {},
): Promise<number> {
  // First, before any review, any approval read, and any Docker command: a
  // name that cannot be launched at all is refused here rather than after
  // `startRuntime` below. The launch entry re-checks it (defence in depth);
  // this only stops the CLI from building a whole runtime to reach a verdict
  // that depends on nothing the runtime produces.
  assertBuiltinLaunchAgent(agentName);
  // The reviews below read approved authority, so the gate runs before them:
  // a binding mismatch has to render a review here, not throw out of the
  // provider or service review with an unreadable-approval error.
  await requireUsableApprovalSelection(context, io);
  const providerReview = agentName === "pi"
    ? await reviewPiProvider(context, io, Boolean(options.quiet))
    : { changed: false, status: 0 };
  if (providerReview.status !== 0) return providerReview.status;
  const serviceEnsure = await reviewAgentOperationalServices(context, io, agentName, Boolean(options.quiet));
  if (serviceEnsure.status !== 0) return serviceEnsure.status;
  // MCP import/skip lines report only the launched agent's servers.
  setMcpLogContext({
    ...(agentName === "claude" || agentName === "codex" ? { agent: agentName } : {}),
    verbose: options.verbose === true,
  });
  const runtime = await startRuntime(context, io, false, {
    useApprovedPolicy: options.useApprovedPolicy,
    verbose: options.verbose,
  });
  if (runtime.kind === "failed") return runtime.status;
  const activeContext = preparedRuntimeContext(runtime.preparedRuntime);
  const proxyId = preparedRuntimeProxyId(runtime.preparedRuntime);
  const tokenResolutionReceipts = runtime.tokenResolutionReceipts;
  flushWarnings();
  const sessionStartedAt = new Date().toISOString();
  const status = await withWriteApprovalSession(activeContext, () =>
    withTokenAutoRefresh(activeContext, io, tokenResolutionReceipts, () => {
      // Every foreground launch uses per-session admission. Custom-command
      // refusal and legacy-default normalization live in the session path.
      return launchConfiguredAgentThroughAdmission({
        preparedRuntime: runtime.preparedRuntime,
        io,
        agentName,
        reprepare: () => repreparePublicLaunchRuntime(context, io, options.verbose),
      });
    }));
  // Agent sessions only (not `runfree shell`): summarize proxy denials seen
  // during this session. Best effort; never changes the exit status.
  printSessionDenialSummary(activeContext, io, {
    sinceIso: sessionStartedAt,
    quiet: options.quiet,
    proxyId,
  });
  return status;
}

// Typed core for the `$0 [agent]` default command. Resolves the optional agent
// name against project config: an omitted/empty name runs the default agent, a
// configured name runs that agent, and anything else is an unknown command. The
// command module validates nothing about the name (it is data-driven), so this
// performs the resolution and enforcement.
export async function runAgentCommand(
  context: RuntimeContext,
  io: RuntimeIO,
  agent: string | undefined,
  options: { quiet: boolean; useApprovedPolicy?: boolean; verbose: boolean },
): Promise<number> {
  // An omitted/empty name and the literal `default` both run the configured
  // default agent. `config.agents.default` is a name pointer (a string), so it is
  // never itself a runnable agent — the legacy runtime had an explicit
  // `case "default"` for the same reason; preserve that alias.
  if (agent === undefined || agent === "" || agent === "default") {
    return runConfiguredAgent(context, io, resolveDefaultAgentName(context.project.config), options);
  }
  if (resolveAgentCommand(context.project.config, agent)) {
    return runConfiguredAgent(context, io, agent, options);
  }
  return die(`unknown command: ${agent} (try 'runfree help')`);
}

// Dispatch one in-process runtime admin intent (policy reload, token sync,
// prepare) straight to the typed admin enforcement. The intent is built at the
// call site, so there is no argv string to parse here. Runs inside an admin
// state (see runAdminAction caller). The default branch is unreachable for the
// closed union; it only guards against a cast-in invalid intent.
async function dispatchRuntimeAdmin(intent: RuntimeAdminIntent, context: RuntimeContext, io: RuntimeIO): Promise<void> {
  switch (intent.kind) {
    case "converge-proxy-policy":
      await convergeProxyPolicy();
      return;
    case "ensure-agent-service": {
      const plan = planDesiredServiceEnable({
        id: intent.id,
        tokenSource: { kind: "none" },
        fromOnePasswordItem: undefined,
        replaceSource: false,
        skipBroad: false,
        skipHosts: [],
        readOnly: false,
        allowWrite: false,
        automatic: false,
        quiet: intent.quiet,
        reloadProxy: false,
      });
      await mutateDesiredService(context, io, "project", {
        kind: "enable",
        id: plan.id,
        entry: plan.entry,
      });
      return;
    }
    case "prepare-token-sources":
      prepareRuntimeTokenSources();
      return;
    case "token-sync":
      await credentialSyncIntent({
        verbose: intent.verbose,
        watch: false,
        quiet: false,
        delayFirstSync: false,
        cacheSourceSecrets: true,
      });
      return;
    case "prepare": {
      const projectPolicy = readApprovedNetworkPolicy(context.projectRoot, context.project, "network-project");
      const localPolicy = readApprovedNetworkPolicy(context.projectRoot, context.project, "network-local");
      if (!projectPolicy || !localPolicy) {
        throw new ControlsNotApprovedError("approved project and local network controls are required before effective preparation");
      }
      prepareEffectiveRuntimeIntent({
        basePolicy: compileDesiredPolicies({ project: projectPolicy, local: localPolicy }).policy,
        outputPath: context.project.paths.controlMcpNetworkPolicyPath,
      });
      return;
    }
    default:
      throw new Error(`unsupported in-process runtime admin intent: ${JSON.stringify(intent)}`);
  }
}

// Decide which environment the in-process runtime admin runs an intent under,
// and resolve the selected effective control once for the admin-state fields.
//
// The runtime environment is derived from the *selected* effective control
// generation (`selectedAgentEnvironmentPath` throws without one). Two intents
// author desired controls before any generation is selected — `prepare`
// (which creates the first generation) and `ensure-agent-service` (which mutates
// desired policy via `context`, not the admin-state env). They must take a
// minimal env, never the full runtime env, or a fresh project cannot enable
// its first service. The live intents — `token-sync` and `converge-proxy-policy`
// — act on the selected generation and must fail closed when none is selected,
// before the admin state (and any credential side effect) is constructed. An
// unknown/cast-in intent is neither live nor authoring: it takes the minimal env
// and is rejected by the dispatch default branch, unchanged.
export function resolveRuntimeAdminEnvironment(
  intent: RuntimeAdminIntent,
  context: RuntimeContext,
): { env: NodeJS.ProcessEnv; activeEffective: ReturnType<typeof readActiveEffectiveControl> } {
  const activeEffective = intent.kind !== "prepare"
    ? readActiveEffectiveControl(context.project)
    : undefined;
  const liveIntent = intent.kind === "token-sync" || intent.kind === "converge-proxy-policy";
  if (liveIntent && !activeEffective) {
    throw new Error(`${intent.kind} requires a selected effective policy generation`);
  }
  const env = !liveIntent
    ? {
        ...context.env,
        RUNFREE_PROJECT_ROOT: context.projectRoot,
        RUNFREE_STATE_DIR: context.project.paths.stateDir,
        RUNFREE_CLAUDE_JSON: context.project.paths.claudeConfigPath,
        RUNFREE_CLAUDE_MCP_CONFIG_HOST_PATH: context.project.paths.claudeMcpConfigPath,
        RUNFREE_CODEX_HOME: context.project.paths.codexDir,
        RUNFREE_MCP_OPERATION_POLICY_HOST_PATH: context.project.paths.mcpOperationPolicyPath,
      }
    : runtimeEnvironment(context.projectRoot, context.project, context.runtimeRoot, context.env, context.network, {
        agentImage: context.agentImage,
        components: context.runtimeComponents,
        gitLayout: context.gitLayoutPlan,
        runtimeDigest: effectiveRuntimeDigest(context.projectRoot, context.project.config),
      });
  return { env, activeEffective };
}

function createNodeRuntimeIO(): RuntimeIO {
  let tokenResolutionReceipts: TokenResolutionReceipt[] = [];
  return {
    run,
    capture,
    commandExists,
    confirm,
    choosePiProvider,
    isInteractive: () => process.stdin.isTTY === true && process.stdout.isTTY === true,
    admin: async (intent: RuntimeAdminIntent, context: RuntimeContext): Promise<number> => {
      const { env, activeEffective } = resolveRuntimeAdminEnvironment(intent, context);
      const state = createAdminState({
        agentEnvPath: context.project.paths.controlAgentEnvPath,
        projectRoot: context.projectRoot,
        packageRoot: context.runtimeRoot,
        policyPath: activeEffective?.networkPolicyPath ?? context.project.paths.controlProxyActivePath,
        policyAccess: "effective-read-only",
        effectiveControlSelected: activeEffective !== undefined,
        oauthPolicyPath: activeEffective?.oauthPolicyPath,
        tokenConfigPath: context.project.paths.tokenConfigPath,
        stateDir: context.project.paths.stateDir,
        env,
        runtimeContext: context,
        validatedRuntime: context.validatedRuntime,
      });
      // The in-process runtime admin only issues a fixed set of internal intents.
      // Dispatch them to the typed enforcement within the admin state, preserving
      // the token-sync receipt hand-off used by token auto-refresh.
      const status = await runAdminAction(state, () => dispatchRuntimeAdmin(intent, context, nodeRuntimeIO));
      tokenResolutionReceipts = state.tokenResolutionReceipts ?? [];
      return status;
    },
    startTokenAutoRefresh: startTokenAutoRefreshProcess,
    takeTokenResolutionReceipts: () => {
      const receipts = tokenResolutionReceipts;
      tokenResolutionReceipts = [];
      return receipts;
    },
  };
}

// The default host IO. Exported so the typed runtime command modules can invoke
// the typed runtime cores with the real IO while tests inject their own.
export const nodeRuntimeIO: RuntimeIO = createNodeRuntimeIO();
nodeRuntimeIO.prepareTokenSources = async (context) => {
  const status = await nodeRuntimeIO.admin({ kind: "prepare-token-sources" }, context);
  if (status !== 0) throw new Error("credential sources could not be prepared before proxy disruption; repair them and retry");
};
nodeRuntimeIO.admitPreparedTokenSources = (context) => admitPreparedRuntimeTokenSources(context.project);
nodeRuntimeIO.clearPreparedTokenSources = (context) => clearPreparedRuntimeTokenSources(context.project);

function existingRuntimeAdapters(context: RuntimeContext, io: RuntimeIO) {
  return createRuntimeAdapters(generatedRuntimeContextIfAvailable(context), io);
}

export type LogsInput = { service: "proxy"; verbose: boolean };

// Typed core for `runfree logs proxy [--verbose]`. Per-session agents are
// foreground containers, not a fixed Compose log service.
export function logsRuntime(context: RuntimeContext, io: RuntimeIO, input: LogsInput): number {
  const logsAdapters = existingRuntimeAdapters(context, io);
  logsAdapters.docker.assertAvailable();
  const { service, verbose } = input;
  const project = logsAdapters.docker.projectForWorkspace();
  if (!project) die("no compose project found for this repo - try 'runfree up' first");
  if (!verbose) {
    flushWarnings();
    return logsAdapters.docker.followLogs(project, service);
  }

  const proxyId = logsAdapters.docker.serviceContainerId(project, "proxy");
  if (!proxyId) die("no proxy container found for this repo - try 'runfree up' first");
  const markerName = `${process.pid}-${Date.now().toString(36)}`;
  logsAdapters.docker.setProxyVerboseMarker(proxyId, markerName);
  try {
    flushWarnings();
    return logsAdapters.docker.followLogs(project, service);
  } finally {
    logsAdapters.docker.clearProxyVerboseMarker(proxyId, markerName);
  }
}

// Typed cores for the simple runtime commands (status/resources/sessions/stop/
// destroy/shell). Each takes the RuntimeContext and IO and performs no argument
// parsing. The typed command modules call these, adding the dry-run front and
// lazy context.

export function statusRuntime(context: RuntimeContext, io: RuntimeIO, options: { verbose?: boolean } = {}): number {
  const adapters = createRuntimeAdapters(context, io);
  adapters.docker.assertAvailable();
  const status = adapters.docker.status();
  // What the next start would plan, so discover overlays the way startup does
  // rather than reporting the set the running runtime was built from. Status
  // exists to show pending change; the persisted snapshot would hide it.
  const desired = createRuntimePlan(
    { ...context, dependencyOverlayPlan: prepareDependencyOverlayPlan(context, io) },
    { dockerSubnets: [], persistNetwork: false },
  );
  const upgrade = planRuntimeUpgradeFromV2State(desired, context, adapters.docker);
  const componentLines = runtimeComponentDiagnosticLines({
    action: upgrade.action,
    desired: desired.generationV2,
    stateDir: desired.paths.stateDir,
  });
  const lifecycleLines = runtimeLifecycleStateDiagnosticLines(context.project.paths.stateDir);
  if (options.verbose) {
    // The full component/lifecycle dump with untruncated digests.
    for (const line of [...componentLines, ...lifecycleLines]) console.log(line);
  } else {
    // The actionable posture only: digests shortened to 12 hex characters and
    // labeled; the dump is `runfree status --verbose`.
    for (const line of statusPostureLines(componentLines, lifecycleLines)) console.log(line);
  }
  printAuditStatusLine(context, io);
  printWriteApprovalStatusLine(context, io);
  printSessionFilesStatusLine(context, io, adapters);
  printIngressForwarderStatusLine(context, io);
  return status;
}

const FULL_DIGEST = /\b([0-9a-f]{12})[0-9a-f]{52}\b/g;

export function shortenDigests(line: string): string {
  return line.replace(FULL_DIGEST, "$1…");
}

// The lines of the component/lifecycle diagnosis an operator acts on: the
// effective control plane id, the upgrade action, live session counts, and
// the next safe action. Everything else is the verbose dump.
export function statusPostureLines(componentLines: readonly string[], lifecycleLines: readonly string[]): string[] {
  const keep = [
    /^upgrade action: /,
    /^  effective control plane: /,
    /^  active lifecycle records: /,
    /^  next safe action: /,
  ];
  return [...componentLines, ...lifecycleLines]
    .filter((line) => keep.some((pattern) => pattern.test(line)))
    .map((line) => shortenDigests(line.trimStart()))
    .map((line) => (line.startsWith("effective control plane: ") ? `${line} (control plane generation)` : line))
    .concat([`runtime component and lifecycle detail: ${remedy.statusVerbose()}`]);
}

// An open ingress forwarder is a published loopback host→agent port — a hole
// the operator opened. Surface it so it is not forgotten (ingress design I3);
// stay silent when none are open, and never let a listing hiccup break status.
function printIngressForwarderStatusLine(context: RuntimeContext, io: RuntimeIO): void {
  try {
    const open = listIngressForwarders(context, io, projectHash(context.projectRoot));
    if (open.length === 0) return;
    console.log(`ingress forwarders: ${open.length} open loopback host→agent port(s) (runfree forward status)`);
  } catch {
    // A status line must never be the reason status fails.
  }
}

// One-line write-approval posture: opting out of the secure default must be
// visible, so `allow` renders as a loud OFF. When the proxy runs, held writes
// and grants (invisible authority) are appended from the proxy's snapshot.
export function printWriteApprovalStatusLine(context: RuntimeContext, io?: RuntimeIO): void {
  try {
    const policy = validateNetworkPolicy(readActiveEffectiveControl(context.project)?.policy ?? { hosts: [] });
    const configuredDefault = policy.writeApproval ?? DEFAULT_WRITE_ACTION;
    const overrides = Object.entries(policy.requests)
      .filter(([, rule]) => rule.writeAction !== undefined)
      .map(([host, rule]) => `${host}=${rule.writeAction}`)
      .sort();
    const parts: string[] = [];
    const live = io ? readWriteApprovalsStatus(context, io) : undefined;
    if (live) {
      if (live.held > 0) parts.push(`${live.held} held (runfree approvals)`);
      for (const grant of live.grants) {
        const remaining = grantRemainingSeconds(live, grant);
        if (remaining !== undefined && remaining <= 0) continue;
        // The coverage label is shared with `runfree approvals` on purpose: a
        // status line that reduced a denied MCP tool (or a one-request grant)
        // to its bare host told the operator less than the enforcement
        // actually does.
        const bound = remaining === undefined ? "until cleared" : `${Math.max(1, Math.round(remaining / 60))}m left`;
        const subject = grant.session !== undefined ? `session ${grant.session.name}` : "request";
        parts.push(`${subject} ${grant.effect} grant (${grantCoverageLabel(grant)}, ${bound})`);
      }
    }
    if (overrides.length > 0) parts.push(`per-host: ${overrides.join(", ")}`);
    const suffix = parts.length > 0 ? ` — ${parts.join(", ")}` : "";
    if (configuredDefault === "allow") {
      console.log(`write approval: OFF (allow) — writes flow without approval${suffix}`);
    } else {
      console.log(`write approval: on (${configuredDefault})${suffix}`);
    }
  } catch {
    // Status stays useful even when the policy cannot be read.
  }
}

/**
 * One "Session files" line for one file the proxy's listing reported.
 *
 * "served until <aliveUntil>" only when the proxy's own verdict says the file
 * is both eligible and still wall-clock active (Review fix F14): the served
 * set a request proxy and firewall converge toward is consumer-internal and
 * is never claimed from the host side, so anything short of that verdict is
 * reported as present but not served, with the reason the proxy declined it.
 */
export function formatSessionFileStatusLine(file: ProxySessionFile): string {
  const identity = file.sessionKey ?? file.name;
  if (!file.malformed && file.eligible === true && file.wallActive === true) {
    return `${identity}: served until ${file.aliveUntil}`;
  }
  const reason = file.malformed ? "malformed" : file.eligible !== true ? "ineligible" : "expired";
  return `${identity}: on disk, not served (${reason})`;
}

// The "Session files" status section. Status is a report, never a refusal, so
// a proxy that is not running or a read that fails is named on one line rather
// than raised.
function printSessionFilesStatusLine(
  context: RuntimeContext,
  io: RuntimeIO,
  adapters: ReturnType<typeof createRuntimeAdapters>,
): void {
  try {
    const project = composeProjectName(context.projectRoot);
    const proxyId = adapters.docker.runningServiceContainerId(project, "proxy");
    if (!proxyId) {
      console.log("session files: unavailable (proxy not running)");
      return;
    }
    const files = readProxySessionFiles({ io, proxyId, dockerOptions: dockerClientEnvOptions(context) });
    if (files.length === 0) return;
    console.log("Session files:");
    for (const file of files) console.log(`  ${formatSessionFileStatusLine(file)}`);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    console.log(`session files: unavailable (${detail})`);
  }
}

export function resourcesRuntime(context: RuntimeContext, io: RuntimeIO): number {
  const adapters = createRuntimeAdapters(context, io);
  adapters.docker.assertAvailable();
  return adapters.docker.resources();
}

export function sessionsRuntime(context: RuntimeContext, io: RuntimeIO): number {
  const adapters = createRuntimeAdapters(context, io);
  adapters.docker.assertAvailable();
  // Merge Compose-probe, per-session lifecycle, and starting sessions; the
  // bare Compose probe lists nothing after the per-session cutover.
  const activeSessions = activeOrStartingAgentSessions(context, adapters.docker, io);
  printSessions(activeSessions);
  const live: RecoveryLiveInputs = {
    activeSessions,
    agentContainerId: adapters.docker.runningServiceContainerId(
      composeProjectName(context.projectRoot),
      "agent",
    ),
    sessionContainers: sessionContainerRecoveryLiveInputs(context),
  };
  const inventory = scanRecoveryInventory({ env: context.env, projectRoot: context.projectRoot });
  const classified = inventory.items
    .map((item) => classifyRecoveryItemLive(item, context, io, live))
    .filter((item) => item.state !== "active");
  if (classified.length > 0) {
    console.log("\nINTERRUPTED / RECOVERY EVIDENCE");
    console.log(formatRecoveryInventory({ ...inventory, items: classified }));
    console.log("resume with: runfree resume");
  }
  return 0;
}

export async function resumeRecoveryRuntime(
  context: RuntimeContext,
  io: RuntimeIO,
  item: RecoveryItem,
  options: { quiet?: boolean; verbose?: boolean } = {},
): Promise<number> {
  // Resume is a public launch entry, so it meets the recovery gate like every
  // other one. `reviewAgentOperationalServices` below reads approved authority
  // before `startRuntime` runs — without the gate here, a record that carries
  // no authority would surface as an unreadable-approval error out of the
  // service review instead of rendering the review that repairs it.
  await requireUsableApprovalSelection(context, io);
  const adapters = createRuntimeAdapters(context, io);
  adapters.docker.assertAvailable();
  const activeSessions = adapters.docker.activeAgentSessions(composeProjectName(context.projectRoot));
  const live: RecoveryLiveInputs = {
    activeSessions,
    agentContainerId: adapters.docker.runningServiceContainerId(composeProjectName(context.projectRoot), "agent"),
    sessionContainers: sessionContainerRecoveryLiveInputs(context),
  };
  const classified = classifyRecoveryItemLive(item, context, io, live);
  if (classified.state === "active") return die(`recovery item ${classified.id} is still active`);
  if (classified.state === "claimed") return die(`recovery item ${classified.id} is already claimed`);
  if (classified.state !== "interrupted") {
    return die(`recovery item ${classified.id} is ${classified.state}; liveness must be proved before resume`);
  }
  // The admission resume orchestrator owns everything from here: fresh
  // classification under the claim and the lifecycle lock, the typed resume
  // argv, residue reclamation, and evidence consumption. It resumes both
  // evidence kinds — pre-cutover shared-agent items and per-session items —
  // into a new validated lifecycle session, which is the D23 cross-boundary
  // property.
  const serviceEnsure = await reviewAgentOperationalServices(context, io, classified.agent, Boolean(options.quiet));
  if (serviceEnsure.status !== 0) return serviceEnsure.status;
  const runtime = await startRuntime(context, io, false, { verbose: options.verbose });
  if (runtime.kind === "failed") return runtime.status;
  const activeContext = preparedRuntimeContext(runtime.preparedRuntime);
  const proxyId = preparedRuntimeProxyId(runtime.preparedRuntime);
  flushWarnings();
  const sessionStartedAt = new Date().toISOString();
  const status = await withWriteApprovalSession(activeContext, () =>
    withTokenAutoRefresh(activeContext, io, runtime.tokenResolutionReceipts, async () => {
      try {
        const result = await resumeInterruptedSessionThroughAdmission({
          preparedRuntime: runtime.preparedRuntime,
          io,
          item: classified,
          reprepare: () => repreparePublicLaunchRuntime(context, io, options.verbose),
        });
        return result.status;
      } catch (error) {
        return die(error instanceof Error ? error.message : String(error));
      }
    }));
  printSessionDenialSummary(activeContext, io, {
    sinceIso: sessionStartedAt,
    quiet: options.quiet,
    proxyId,
  });
  return status;
}

export async function stopRuntime(context: RuntimeContext, io: RuntimeIO, options: { force?: boolean } = {}): Promise<number> {
  const stopAdapters = existingRuntimeAdapters(context, io);
  stopAdapters.docker.assertAvailable();
  const lifecycleLock = await tryAcquireProjectLifecycleLockWithRetry(context);
  if (!lifecycleLock) throw new Error("runtime stop could not acquire the lifecycle lock; retry after the current operation completes");
  try {
  assertSessionDisruptionAuthorized({
    stateDir: context.project.paths.stateDir,
    expectedProject: { projectId: projectHash(context.projectRoot), composeProject: composeProjectName(context.projectRoot) },
    lifecycleLock, operation: "stop", force: options.force, env: context.env,
  });
  clearRetiredWriteApprovalOverride(context);
  removeValidatedIngressForwarders(context, io, projectHash(context.projectRoot));
  const project = stopAdapters.docker.projectForWorkspace();
  if (project) return stopAdapters.docker.composeDown(project);
  console.log("no container to stop");
  return 0;
  } finally {
    lifecycleLock.release();
  }
}

export async function destroyRuntime(
  context: RuntimeContext,
  io: RuntimeIO,
  options: { force?: boolean } = {},
): Promise<number> {
  const destroyContext = generatedRuntimeContextIfAvailable(context);
  const destroyAdapters = createRuntimeAdapters(destroyContext, io);
  destroyAdapters.docker.assertAvailable();
  // The fence: destroy holds the project lifecycle lock for its whole
  // duration, so no session can be admitted or renewed between its
  // enumeration and its removals, and it defers to an in-flight lifecycle
  // change instead of tearing the runtime down under it.
  const lifecycleLock = await tryAcquireProjectLifecycleLockWithRetry(destroyContext);
  if (!lifecycleLock) {
    return die(`nothing was destroyed: a Runfree runtime lifecycle change is in progress (lock: ${projectLifecycleLockPath(destroyContext)}); retry when it finishes`);
  }
  try {
    return runFencedProjectDestroy({
      context: destroyContext,
      io,
      docker: destroyAdapters.docker,
      lifecycleLock,
      force: options.force === true,
      beforeTeardown: () => {
        clearRetiredWriteApprovalOverride(destroyContext);
      },
      prepareUtilities: () => planValidatedIngressForwarders(
        destroyContext,
        io,
        projectHash(destroyContext.projectRoot),
      ),
      afterForcedResidueTeardown: () => {
        const cleanup = removeValidatedEmptyManagedIngressHostNetworkAfterForcedSweep(
          destroyContext,
          io,
          projectHash(destroyContext.projectRoot),
        );
        if (cleanup.kind === "retained") {
          console.error(`forced destroy retained the ingress host network: ${cleanup.detail ?? "ownership is unverified"}`);
        }
      },
    });
  } finally {
    lifecycleLock.release();
  }
}

export async function shellRuntime(context: RuntimeContext, io: RuntimeIO, options: { verbose: boolean }): Promise<number> {
  const runtime = await startRuntime(context, io, false, { verbose: options.verbose });
  if (runtime.kind === "failed") return runtime.status;
  const activeContext = preparedRuntimeContext(runtime.preparedRuntime);
  flushWarnings();
  return await withWriteApprovalSession(activeContext, () =>
    withTokenAutoRefresh(activeContext, io, runtime.tokenResolutionReceipts, () => {
      return launchShellThroughAdmission({
        preparedRuntime: runtime.preparedRuntime,
        io,
        reprepare: () => repreparePublicLaunchRuntime(context, io, options.verbose),
      });
    }));
}
async function repreparePublicLaunchRuntime(
  context: RuntimeContext,
  io: RuntimeIO,
  verbose: boolean | undefined,
): Promise<PreparedRuntime> {
  const result = await startRuntime(context, io, false, { verbose });
  if (result.kind === "failed") {
    throw new Error(`runtime re-preparation failed with status ${result.status}`);
  }
  return result.preparedRuntime;
}
