import childProcess, { type ChildProcess } from "node:child_process";
import crypto from "node:crypto";
import type { EventEmitter } from "node:events";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createCommandContext } from "../../packages/cli/src/commands/context.ts";
import { createRuntimeSecurityContract } from "../../packages/cli/src/runtime/security-contract.ts";
import { createInternalSessionAdmissionDriver } from "../../packages/cli/src/runtime/session-admission-driver.ts";
import {
  classifySessionContainerReconciliation,
  inspectSessionContainerInventory,
} from "../../packages/cli/src/runtime/session-container-reconciliation.ts";
import { listSessionContainerRecordsV2 } from "../../packages/cli/src/runtime/session-containers.ts";
import {
  BUILTIN_SESSION_ADMISSION_PROBE_AGENTS,
  type SessionAdmissionProbeAgent,
  type SessionAdmissionProbeMetrics,
} from "../../packages/cli/src/runtime/session-admission-probe.ts";
import { generatedRuntimeContextIfAvailable } from "../../packages/cli/src/runtime/images.ts";
import { mintPreparedRuntime } from "../../packages/cli/src/runtime/prepared-runtime.ts";
import {
  activeRuntimePlanFromContext,
  runtimeContextFromActivePlan,
} from "../../packages/cli/src/runtime/plan.ts";
import {
  createSessionLockManager,
  tryAcquireProjectLifecycleLock,
  type ProjectLifecycleLock,
} from "../../packages/cli/src/runtime/sessions.ts";
import { runtimeValidationMarkerStatus } from "../../packages/cli/src/runtime/state.ts";
import type { RuntimeIO } from "../../packages/cli/src/runtime/types.ts";
import { createMatrixRuntimeIO } from "./session-admission-matrix-io.ts";
import { renderFailure } from "./session-admission-failure.ts";

const WORKER_NONCE_ENV = "RUNFREE_SESSION_ADMISSION_MATRIX_WORKER_NONCE";
const WORKER_BOOTSTRAP_KIND = "runfree-session-admission-matrix-worker";
const WORKER_NONCE_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const DEFAULT_REPETITIONS = 1;
const MAX_REPETITIONS = 20;
const DEFAULT_CLEANUP_REQUEST_SECONDS = 600;
const MIN_CLEANUP_REQUEST_SECONDS = 30;
const MAX_CLEANUP_REQUEST_SECONDS = 3600;
const WATCHDOG_CLEANUP_GRACE_MS = 45_000;
const WATCHDOG_FORCE_REAP_MS = 5_000;
const WORKER_BOOTSTRAP_TIMEOUT_MS = 10_000;
// The clean-outcome assertion inspects the Docker host's whole container
// inventory, so this bound scales with the maintainer's machine rather than
// with the tranche: roughly 18KB per container, counting containers this test
// never created. At 1MB it overflowed at about 55 containers and surfaced as a
// bare `spawnSync docker ENOBUFS` on the success path only — the one path that
// reaches the inventory scan. 32MB is a hang-stop for a runaway daemon, not a
// budget.
const CAPTURE_MAX_BYTES = 32 * 1024 * 1024;
const RECOVERY_RETRY_DELAY_MS = 1_000;
const MAX_RECOVERY_ATTEMPTS = 3;

export type SessionAdmissionMatrixBackend = "docker-desktop" | "orbstack";

export type SessionAdmissionMatrixOptions = Readonly<{
  agents: readonly SessionAdmissionProbeAgent[];
  backend: SessionAdmissionMatrixBackend;
  cleanupRequestAfterSeconds: number;
  repetitions: number;
  workspace: string;
}>;

export type SessionAdmissionMatrixSample = Readonly<{
  iteration: number;
  metrics: SessionAdmissionProbeMetrics;
}>;

type NumericDistribution = Readonly<{
  max: number;
  min: number;
  p50: number;
  p95: number;
  values: readonly number[];
}>;

export type SessionAdmissionMatrixAggregate = Readonly<{
  agent: SessionAdmissionProbeAgent;
  dockerOperations: NumericDistribution;
  provisioningToSequenceMs: NumericDistribution;
  samples: number;
}>;

export type SessionAdmissionMatrixBackendDetails = Readonly<{
  architecture: string;
  context: string;
  detected: SessionAdmissionMatrixBackend;
  operatingSystem: string;
  platformName: string;
  version: string;
}>;

export type SessionAdmissionMatrixResult = Readonly<{
  v: 1;
  kind: "runfree-internal-session-admission-matrix";
  gateScope: "nominal-paired-provisioning-tranche";
  observedProbeOutcomes: Readonly<{
    completedProbeRuns: number;
    lifecycleRegistryEmpty: true;
    sessionContainersAbsent: true;
  }>;
  backend: SessionAdmissionMatrixBackendDetails;
  configuration: Readonly<{
    agents: readonly SessionAdmissionProbeAgent[];
    repetitions: number;
    cleanupRequestAfterSeconds: number;
    forcedCleanupGraceSeconds: number;
  }>;
  generatedAt: string;
  aggregates: readonly SessionAdmissionMatrixAggregate[];
  samples: readonly SessionAdmissionMatrixSample[];
}>;

type MatrixDriver = Readonly<{
  probeBuiltin(agent: SessionAdmissionProbeAgent): Promise<SessionAdmissionProbeMetrics>;
  recoverPending(agent: SessionAdmissionProbeAgent): Promise<void>;
}>;

type MatrixExecutionInput = Readonly<{
  acquireLock(): ProjectLifecycleLock | undefined;
  createDriver(lock: ProjectLifecycleLock): MatrixDriver;
  repetitions: number;
  agents?: readonly SessionAdmissionProbeAgent[];
  assertCleanOutcome?(): void;
  interruptionReason?(): string | undefined;
  onRecoveryRetry?(error: unknown, attempt: number): void;
  waitForRecoveryRetry?(): Promise<void>;
}>;

export type SessionAdmissionMatrixWatchdogInput = Readonly<{
  cleanupGraceMs: number;
  cleanupRequestAfterMs: number;
  forceReapMs: number;
  spawnWorker(): ChildProcess;
  writeDiagnostic?(message: string): void;
}>;

export type SessionAdmissionWorkerBootstrapOptions = Readonly<{
  channel?: Pick<EventEmitter, "off" | "once">;
  disconnect?(): void;
  timeoutMs?: number;
}>;

function parseBoundedInteger(value: string, label: string, minimum: number, maximum: number): number {
  if (!/^[1-9][0-9]*$/u.test(value)) {
    throw new Error(`${label} must be an integer from ${minimum} through ${maximum}`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return parsed;
}

function nextArgument(args: readonly string[], index: number, option: string): string {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${option} requires a value`);
  return value;
}

function builtinProbeAgent(value: string): SessionAdmissionProbeAgent {
  const agent = BUILTIN_SESSION_ADMISSION_PROBE_AGENTS.find((candidate) => candidate === value);
  if (!agent) {
    throw new Error(`--agent must be one of ${BUILTIN_SESSION_ADMISSION_PROBE_AGENTS.join(", ")}`);
  }
  return agent;
}

export function parseSessionAdmissionMatrixArgs(
  args: readonly string[],
  cwd = process.cwd(),
): SessionAdmissionMatrixOptions {
  let backend: SessionAdmissionMatrixBackend | undefined;
  let repetitions = DEFAULT_REPETITIONS;
  let cleanupRequestAfterSeconds = DEFAULT_CLEANUP_REQUEST_SECONDS;
  let workspace: string | undefined;
  // `--agent` narrows the tranche to a reproducible slice. Every other option
  // stays single-use: a duplicate there is a caller mistake, but naming several
  // agents is the intended way to ask for several.
  const selected: SessionAdmissionProbeAgent[] = [];
  const seen = new Set<string>();

  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    if (!new Set(["--agent", "--backend", "--cleanup-request-after-seconds", "--repeat", "--workspace"]).has(option)) {
      throw new Error(`unknown session admission matrix option: ${option}`);
    }
    if (option !== "--agent") {
      if (seen.has(option)) throw new Error(`duplicate session admission matrix option: ${option}`);
      seen.add(option);
    }
    const value = nextArgument(args, index, option);
    index += 1;
    if (option === "--agent") {
      const agent = builtinProbeAgent(value);
      if (selected.includes(agent)) throw new Error(`duplicate session admission agent: ${agent}`);
      selected.push(agent);
    } else if (option === "--backend") {
      if (value !== "docker-desktop" && value !== "orbstack") {
        throw new Error("--backend must be docker-desktop or orbstack");
      }
      backend = value;
    } else if (option === "--repeat") {
      repetitions = parseBoundedInteger(value, "--repeat", 1, MAX_REPETITIONS);
    } else if (option === "--cleanup-request-after-seconds") {
      cleanupRequestAfterSeconds = parseBoundedInteger(
        value,
        "--cleanup-request-after-seconds",
        MIN_CLEANUP_REQUEST_SECONDS,
        MAX_CLEANUP_REQUEST_SECONDS,
      );
    } else {
      workspace = path.resolve(cwd, value);
    }
  }
  if (!backend) throw new Error("--backend is required for attributable live matrix output");
  if (!workspace) throw new Error("--workspace is required for an already-started sandbox runtime");
  // Canonical order regardless of the order the caller named them, so a sliced
  // run's sample sequence and aggregate output stay comparable to a full run's.
  const agents = selected.length === 0
    ? BUILTIN_SESSION_ADMISSION_PROBE_AGENTS
    : BUILTIN_SESSION_ADMISSION_PROBE_AGENTS.filter((agent) => selected.includes(agent));
  return Object.freeze({
    agents: Object.freeze([...agents]),
    backend,
    cleanupRequestAfterSeconds,
    repetitions,
    workspace,
  });
}

function exactOutput(value: string, label: string): string {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 512 || /[\u0000-\u001f\u007f-\u009f]/u.test(trimmed)) {
    throw new Error(`Docker returned invalid ${label}`);
  }
  return trimmed;
}

function captureDockerValue(io: RuntimeIO, args: readonly string[], label: string): string {
  const result = io.capture("docker", [...args], {
    encoding: "utf8",
    maxBuffer: CAPTURE_MAX_BYTES,
  });
  if (result.status !== 0) {
    const detail = result.stderr.trim().slice(0, 512) || `exit ${result.status}`;
    throw new Error(`could not inspect Docker ${label}: ${detail}`);
  }
  return exactOutput(result.stdout, label);
}

export function inspectSessionAdmissionMatrixBackend(
  expected: SessionAdmissionMatrixBackend,
  io: RuntimeIO,
): SessionAdmissionMatrixBackendDetails {
  const platformName = captureDockerValue(io, ["version", "--format", "{{.Server.Platform.Name}}"], "platform name");
  const operatingSystem = captureDockerValue(io, ["info", "--format", "{{.OperatingSystem}}"], "operating system");
  const normalized = `${platformName} ${operatingSystem}`.toLowerCase();
  const detected = normalized.includes("orbstack")
    ? "orbstack"
    : normalized.includes("docker desktop")
      ? "docker-desktop"
      : undefined;
  if (detected !== expected) {
    throw new Error(
      `expected ${expected}, detected ${detected ?? "unclassified"}: ${platformName} / ${operatingSystem}`,
    );
  }
  return Object.freeze({
    architecture: captureDockerValue(io, ["version", "--format", "{{.Server.Arch}}"], "server architecture"),
    context: captureDockerValue(io, ["context", "show"], "context"),
    detected,
    operatingSystem,
    platformName,
    version: captureDockerValue(io, ["version", "--format", "{{.Server.Version}}"], "server version"),
  });
}

function finiteNonnegative(value: number, label: string): number {
  if (!Number.isFinite(value) || value < 0) throw new Error(`${label} must be a nonnegative finite number`);
  return value;
}

function safeOperationCount(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("matrix Docker operation count must be a nonnegative safe integer");
  }
  return value;
}

function percentile(sorted: readonly number[], fraction: number): number {
  const value = sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)];
  if (value === undefined) throw new Error("cannot aggregate an empty metric distribution");
  return value;
}

function distribution(values: readonly number[], kind: "duration" | "operations"): NumericDistribution {
  const exact = values.map((value) => kind === "operations"
    ? safeOperationCount(value)
    : finiteNonnegative(value, "matrix provisioning-to-sequence latency"));
  if (exact.length === 0) throw new Error("cannot aggregate an empty metric distribution");
  const sorted = [...exact].sort((left, right) => left - right);
  return Object.freeze({
    max: sorted.at(-1) as number,
    min: sorted[0] as number,
    p50: percentile(sorted, 0.5),
    p95: percentile(sorted, 0.95),
    values: Object.freeze([...exact]),
  });
}

export function aggregateSessionAdmissionMatrix(
  samples: readonly SessionAdmissionMatrixSample[],
  repetitions: number,
  agents: readonly SessionAdmissionProbeAgent[] = BUILTIN_SESSION_ADMISSION_PROBE_AGENTS,
): readonly SessionAdmissionMatrixAggregate[] {
  parseBoundedInteger(String(repetitions), "matrix repetitions", 1, MAX_REPETITIONS);
  if (samples.length !== repetitions * agents.length) {
    throw new Error(`expected ${repetitions * agents.length} session admission samples, got ${samples.length}`);
  }
  let offset = 0;
  for (let iteration = 1; iteration <= repetitions; iteration += 1) {
    for (const agent of agents) {
      const sample = samples[offset];
      if (!sample || sample.iteration !== iteration || sample.metrics.agent !== agent) {
        throw new Error("session admission matrix sample order or identity is invalid");
      }
      offset += 1;
    }
  }
  return Object.freeze(agents.map((agent) => {
    const metrics = samples.filter((sample) => sample.metrics.agent === agent).map((sample) => sample.metrics);
    return Object.freeze({
      agent,
      dockerOperations: distribution(metrics.map((sample) => sample.dockerOperations), "operations"),
      provisioningToSequenceMs: distribution(
        metrics.map((sample) => sample.provisioningToSequenceMs),
        "duration",
      ),
      samples: metrics.length,
    });
  }));
}

function interrupted(reason: string | undefined): void {
  if (reason) throw new Error(`session admission matrix interrupted by ${reason}`);
}

export async function executeSessionAdmissionMatrix(
  input: MatrixExecutionInput,
): Promise<readonly SessionAdmissionMatrixSample[]> {
  parseBoundedInteger(String(input.repetitions), "matrix repetitions", 1, MAX_REPETITIONS);
  const agents = input.agents ?? BUILTIN_SESSION_ADMISSION_PROBE_AGENTS;
  interrupted(input.interruptionReason?.());
  const lock = input.acquireLock();
  if (!lock) throw new Error("project lifecycle lock is held by another runtime operation");
  let failure: unknown;
  let samples: readonly SessionAdmissionMatrixSample[] | undefined;
  let driver: MatrixDriver | undefined;
  let inFlightAgent: SessionAdmissionProbeAgent | undefined;
  try {
    lock.assertHeld();
    driver = input.createDriver(lock);
    const observed: SessionAdmissionMatrixSample[] = [];
    for (let iteration = 1; iteration <= input.repetitions; iteration += 1) {
      for (const agent of agents) {
        interrupted(input.interruptionReason?.());
        lock.assertHeld();
        inFlightAgent = agent;
        const metrics = await driver.probeBuiltin(agent);
        inFlightAgent = undefined;
        lock.assertHeld();
        if (metrics.agent !== agent) {
          throw new Error(`session admission probe returned ${metrics.agent} metrics for ${agent}`);
        }
        safeOperationCount(metrics.dockerOperations);
        finiteNonnegative(metrics.provisioningToSequenceMs, "matrix provisioning-to-sequence latency");
        observed.push(Object.freeze({ iteration, metrics }));
        interrupted(input.interruptionReason?.());
      }
    }
    lock.assertHeld();
    input.assertCleanOutcome?.();
    lock.assertHeld();
    samples = Object.freeze(observed);
  } catch (error) {
    failure = error;
    if (driver && inFlightAgent) {
      let recoveryAttempt = 0;
      let firstRecoveryFailure: unknown;
      while (inFlightAgent && recoveryAttempt < MAX_RECOVERY_ATTEMPTS) {
        try {
          lock.assertHeld();
          await driver.recoverPending(inFlightAgent);
          lock.assertHeld();
          inFlightAgent = undefined;
        } catch (recoveryFailure) {
          recoveryAttempt += 1;
          firstRecoveryFailure ??= recoveryFailure;
          try {
            input.onRecoveryRetry?.(recoveryFailure, recoveryAttempt);
          } catch {
            // Diagnostics cannot terminate the live recovery custodian.
          }
          const interruptionReason = input.interruptionReason?.();
          if (interruptionReason) {
            failure = new AggregateError(
              [error, firstRecoveryFailure],
              `session admission matrix recovery interrupted by ${interruptionReason}; durable pending state remains`,
            );
            break;
          }
          if (recoveryAttempt >= MAX_RECOVERY_ATTEMPTS) {
            failure = new AggregateError(
              [error, firstRecoveryFailure],
              `session admission matrix exact pending-state recovery failed after ${MAX_RECOVERY_ATTEMPTS} attempts; durable pending state remains`,
            );
            break;
          }
          try {
            await (input.waitForRecoveryRetry?.() ?? new Promise((resolve) => {
              setTimeout(resolve, RECOVERY_RETRY_DELAY_MS);
            }));
          } catch (retryWaitFailure) {
            failure = new AggregateError(
              [error, firstRecoveryFailure, retryWaitFailure],
              "session admission matrix recovery wait failed; durable pending state remains",
            );
            break;
          }
        }
      }
      if (!inFlightAgent && firstRecoveryFailure !== undefined) {
        failure = new AggregateError(
          [error, firstRecoveryFailure],
          "session admission matrix failed; exact pending-state recovery succeeded after retry",
        );
      }
    }
  }
  try {
    lock.release();
  } catch (releaseFailure) {
    if (failure !== undefined) {
      failure = new AggregateError(
        [failure, releaseFailure],
        "session admission matrix failed and lifecycle lock release also failed",
      );
    } else {
      failure = releaseFailure;
    }
  }
  if (failure !== undefined) throw failure;
  if (!samples) throw new Error("session admission matrix produced no samples");
  return samples;
}

async function runWorker(options: SessionAdmissionMatrixOptions): Promise<SessionAdmissionMatrixResult> {
  const io = createMatrixRuntimeIO();
  const backend = inspectSessionAdmissionMatrixBackend(options.backend, io);
  let interruptionReason: string | undefined;
  const stop = (signal: NodeJS.Signals) => {
    interruptionReason ??= signal;
  };
  const onSigint = () => stop("SIGINT");
  const onSigterm = () => stop("SIGTERM");
  process.on("SIGINT", onSigint);
  process.on("SIGTERM", onSigterm);
  try {
    interrupted(interruptionReason);
    const commandContext = createCommandContext({
      projectRoot: options.workspace,
      invocationCwd: process.cwd(),
      commandName: "internal-session-admission-matrix",
      env: process.env,
    });
    const generatedContext = generatedRuntimeContextIfAvailable(commandContext.runtimeContext());
    const activePlan = activeRuntimePlanFromContext(generatedContext);
    const activeContext = runtimeContextFromActivePlan(activePlan);
    const contract = createRuntimeSecurityContract(activePlan);
    const validation = runtimeValidationMarkerStatus(activeContext, io, {
      contractHash: contract.contractHash,
    });
    if (!validation.proof || validation.issue) {
      throw new Error(
        `already-started runtime lacks an exact current validation proof: ${validation.issue ?? "missing proof"}`,
      );
    }
    const validationProof = validation.proof;
    const context = Object.freeze({ ...activeContext, validatedRuntime: validationProof });
    const expectedProject = Object.freeze({
      projectId: activePlan.projectId,
      composeProject: activePlan.composeProjectName,
    });
    let observedCleanup: Readonly<{
      lifecycleRegistryEmpty: true;
      sessionContainersAbsent: true;
    }> | undefined;
    const samples = await executeSessionAdmissionMatrix({
      agents: options.agents,
      repetitions: options.repetitions,
      acquireLock: () => tryAcquireProjectLifecycleLock(context),
      createDriver: (lifecycleLock) => createInternalSessionAdmissionDriver({
        preparedRuntime: mintPreparedRuntime({ plan: activePlan, validationProof }),
        sessionLockManager: createSessionLockManager(context, lifecycleLock),
        io,
      }),
      assertCleanOutcome: () => {
        const records = listSessionContainerRecordsV2(activePlan.paths.stateDir, expectedProject);
        if (records.length !== 0) {
          throw new Error("successful session admission probes left lifecycle records behind");
        }
        const containers = inspectSessionContainerInventory(
          (executable, args, dockerOptions) => io.capture(executable, [...args], dockerOptions),
          expectedProject,
          {
            env: activePlan.execution.dockerClientEnv,
            maxBuffer: CAPTURE_MAX_BYTES,
            shell: false,
          },
        );
        const residual = classifySessionContainerReconciliation({
          expectedProject,
          records,
          containers,
        });
        if (residual.length !== 0) {
          throw new Error("successful session admission probes left session containers behind");
        }
        observedCleanup = Object.freeze({
          lifecycleRegistryEmpty: true as const,
          sessionContainersAbsent: true as const,
        });
      },
      interruptionReason: () => interruptionReason,
      onRecoveryRetry: (error, attempt) => {
        const detail = error instanceof Error ? error.message.slice(0, 512) : "unknown recovery failure";
        process.stderr.write(
          `session admission exact recovery attempt ${attempt} failed; retaining the lifecycle fence: ${detail}\n`,
        );
      },
    });
    if (!observedCleanup) throw new Error("session admission matrix did not observe its cleanup outcome");
    return Object.freeze({
      v: 1 as const,
      kind: "runfree-internal-session-admission-matrix" as const,
      gateScope: "nominal-paired-provisioning-tranche" as const,
      observedProbeOutcomes: Object.freeze({
        completedProbeRuns: samples.length,
        ...observedCleanup,
      }),
      backend,
      configuration: Object.freeze({
        agents: options.agents,
        repetitions: options.repetitions,
        cleanupRequestAfterSeconds: options.cleanupRequestAfterSeconds,
        forcedCleanupGraceSeconds: WATCHDOG_CLEANUP_GRACE_MS / 1_000,
      }),
      generatedAt: new Date().toISOString(),
      aggregates: aggregateSessionAdmissionMatrix(samples, options.repetitions, options.agents),
      samples,
    });
  } finally {
    process.off("SIGINT", onSigint);
    process.off("SIGTERM", onSigterm);
  }
}

type SessionAdmissionWorkerProcess = Readonly<{
  exitCode: number | null;
  signalCode: NodeJS.Signals | null;
  pid?: number;
}>;

export function signalSessionAdmissionWorkerProcessGroup(
  child: SessionAdmissionWorkerProcess,
  signal: NodeJS.Signals,
): void {
  if (child.exitCode !== null || child.signalCode !== null) return;
  if (!Number.isSafeInteger(child.pid) || (child.pid ?? 0) < 1) {
    throw new Error("session admission worker has no exact process-group id");
  }
  try {
    process.kill(-(child.pid as number), signal);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ESRCH") return;
    throw error;
  }
}

function positiveFiniteMilliseconds(value: number, label: string): number {
  if (!Number.isFinite(value) || value <= 0) throw new Error(`${label} must be a positive finite number`);
  return value;
}

export function superviseSessionAdmissionMatrixWorker(
  input: SessionAdmissionMatrixWatchdogInput,
): Promise<number> {
  const cleanupRequestAfterMs = positiveFiniteMilliseconds(
    input.cleanupRequestAfterMs,
    "session admission cleanup-request timeout",
  );
  const cleanupGraceMs = positiveFiniteMilliseconds(
    input.cleanupGraceMs,
    "session admission cleanup grace",
  );
  const forceReapMs = positiveFiniteMilliseconds(
    input.forceReapMs,
    "session admission forced-stop reap timeout",
  );
  const writeDiagnostic = input.writeDiagnostic ?? ((message: string) => process.stderr.write(message));
  return new Promise((resolve) => {
    const child = input.spawnWorker();
    if (!Number.isSafeInteger(child.pid) || (child.pid ?? 0) < 1) {
      throw new Error("session admission worker has no exact process-group id");
    }
    let timedOut = false;
    let finished = false;
    let parentSignal: NodeJS.Signals | undefined;
    let forceKillTimer: NodeJS.Timeout | undefined;
    let forceReapTimer: NodeJS.Timeout | undefined;
    let stopRequested = false;
    let forceStopStarted = false;
    let signalFailure = false;
    const completionStatus = (code: number | null = null): number => {
      if (signalFailure) return 1;
      if (timedOut) return 124;
      if (parentSignal === "SIGINT") return 130;
      if (parentSignal === "SIGTERM") return 143;
      return code ?? 1;
    };
    const forceStop = () => {
      if (forceStopStarted) return;
      forceStopStarted = true;
      writeDiagnostic(
        "session admission cleanup grace elapsed; forcing the worker process group to stop; durable pending state remains for the next locked reconciliation\n",
      );
      try {
        signalSessionAdmissionWorkerProcessGroup(child, "SIGKILL");
      } catch (error) {
        signalFailure = true;
        writeDiagnostic(
          `could not force-stop the session admission worker process group: ${error instanceof Error ? error.message : String(error)}\n`,
        );
      }
      forceReapTimer = setTimeout(() => {
        writeDiagnostic(
          "session admission worker did not report exit after forced stop; returning failure with durable pending state intact\n",
        );
        finish(completionStatus());
      }, forceReapMs);
    };
    const requestStop = () => {
      if (stopRequested) return;
      stopRequested = true;
      forceKillTimer = setTimeout(forceStop, cleanupGraceMs);
      try {
        signalSessionAdmissionWorkerProcessGroup(child, "SIGTERM");
      } catch (error) {
        signalFailure = true;
        writeDiagnostic(
          `could not request fail-closed session admission cleanup: ${error instanceof Error ? error.message : String(error)}\n`,
        );
        forceStop();
      }
    };
    const watchdog = setTimeout(() => {
      timedOut = true;
      writeDiagnostic(
        "session admission matrix reached its cleanup-request deadline; requesting fail-closed cleanup\n",
      );
      requestStop();
    }, cleanupRequestAfterMs);
    const onSigint = () => {
      parentSignal ??= "SIGINT";
      requestStop();
    };
    const onSigterm = () => {
      parentSignal ??= "SIGTERM";
      requestStop();
    };
    process.on("SIGINT", onSigint);
    process.on("SIGTERM", onSigterm);
    const finish = (status: number) => {
      if (finished) return;
      finished = true;
      clearTimeout(watchdog);
      if (forceKillTimer) clearTimeout(forceKillTimer);
      if (forceReapTimer) clearTimeout(forceReapTimer);
      process.off("SIGINT", onSigint);
      process.off("SIGTERM", onSigterm);
      child.channel?.unref();
      try {
        if (child.connected) child.disconnect();
      } catch (error) {
        writeDiagnostic(
          `could not disconnect the session admission worker IPC channel: ${error instanceof Error ? error.message : String(error)}\n`,
        );
      }
      child.unref();
      resolve(status);
    };
    child.once("error", (error) => {
      writeDiagnostic(`could not start session admission matrix worker: ${error.message}\n`);
      finish(1);
    });
    child.once("exit", (code) => {
      finish(completionStatus(code));
    });
  });
}

function runWatchdog(options: SessionAdmissionMatrixOptions): Promise<number> {
  return superviseSessionAdmissionMatrixWorker({
    cleanupGraceMs: WATCHDOG_CLEANUP_GRACE_MS,
    cleanupRequestAfterMs: options.cleanupRequestAfterSeconds * 1000,
    forceReapMs: WATCHDOG_FORCE_REAP_MS,
    spawnWorker() {
      const scriptPath = fileURLToPath(import.meta.url);
      const nonce = crypto.randomBytes(32).toString("base64url");
      const child = childProcess.spawn(
        process.execPath,
        [...process.execArgv, scriptPath, ...process.argv.slice(2)],
        {
          detached: true,
          env: { ...process.env, [WORKER_NONCE_ENV]: nonce },
          stdio: ["inherit", "inherit", "inherit", "ipc"],
        },
      );
      if (typeof child.send !== "function") {
        throw new Error("session admission worker has no private bootstrap channel");
      }
      // Deferred and callback-guarded, deliberately. The supervisor attaches its
      // error and exit listeners synchronously after this returns, so sending
      // here races a worker that dies before its IPC channel is ready: Node
      // flushes the queued message against a null channel and throws inside its
      // own internals ("Cannot set properties of null (setting
      // Symbol(kPendingMessages))"), which kills the run with no user frame and
      // hides the worker's real failure. One turn of the event loop is enough
      // for those listeners to exist, and the callback keeps a failed send from
      // reaching an unhandled 'error' event.
      setImmediate(() => {
        if (!child.connected) return;
        child.send({ kind: WORKER_BOOTSTRAP_KIND, nonce }, (error: Error | null) => {
          if (!error) return;
          process.stderr.write(
            `could not deliver the session admission worker bootstrap nonce: ${error.message}\n`,
          );
        });
      });
      return child;
    },
  });
}

export function validSessionAdmissionWorkerBootstrap(message: unknown, expectedNonce: string): boolean {
  if (!WORKER_NONCE_PATTERN.test(expectedNonce)) return false;
  if (!message || typeof message !== "object") return false;
  const record = message as Record<string, unknown>;
  if (record.kind !== WORKER_BOOTSTRAP_KIND
    || typeof record.nonce !== "string"
    || !WORKER_NONCE_PATTERN.test(record.nonce)) return false;
  const received = Buffer.from(record.nonce, "utf8");
  const expected = Buffer.from(expectedNonce, "utf8");
  return received.length === expected.length && crypto.timingSafeEqual(received, expected);
}

export function sessionAdmissionMatrixWorkerNonce(
  workerNonce: string | undefined,
  hasIpcChannel: boolean,
): string | undefined {
  if (workerNonce === undefined) return undefined;
  if (!hasIpcChannel) throw new Error("session admission matrix refuses an ambient worker bootstrap nonce");
  if (!WORKER_NONCE_PATTERN.test(workerNonce)) {
    throw new Error("session admission matrix worker bootstrap nonce is invalid");
  }
  return workerNonce;
}

export function waitForSessionAdmissionWorkerBootstrap(
  expectedNonce: string,
  options: SessionAdmissionWorkerBootstrapOptions = {},
): Promise<void> {
  if (!WORKER_NONCE_PATTERN.test(expectedNonce)) {
    return Promise.reject(new Error("session admission worker bootstrap nonce is invalid"));
  }
  const channel = options.channel ?? process;
  const disconnect = options.disconnect ?? (() => {
    if (process.connected) process.disconnect();
  });
  const timeoutMs = positiveFiniteMilliseconds(
    options.timeoutMs ?? WORKER_BOOTSTRAP_TIMEOUT_MS,
    "session admission worker bootstrap timeout",
  );
  return new Promise((resolve, reject) => {
    const finish = (error?: Error) => {
      clearTimeout(timeout);
      channel.off("message", onMessage);
      channel.off("disconnect", onDisconnect);
      if (error) reject(error);
      else resolve();
    };
    const onMessage = (message: unknown) => {
      const valid = validSessionAdmissionWorkerBootstrap(message, expectedNonce);
      finish(valid ? undefined : new Error("session admission worker bootstrap was rejected"));
      // Deferred, and this is load-bearing rather than stylistic. The bootstrap
      // nonce is normally buffered before this listener exists, so Node
      // delivers it from the pending-message flush in its `newListener` hook
      // (internal/child_process): that code null-checks `target.channel`, emits
      // each queued message, and then writes back
      // `target.channel[kPendingMessages] = []`. Disconnecting synchronously
      // inside the emit sets `target.channel` to null underneath it, so the
      // write-back throws "Cannot set properties of null (setting
      // Symbol(kPendingMessages))" from inside Node with no user frame, killing
      // the worker. Releasing the channel a turn later leaves the flush intact.
      if (valid) setImmediate(disconnect);
    };
    const onDisconnect = () => finish(new Error("session admission worker bootstrap channel closed"));
    const timeout = setTimeout(
      () => finish(new Error("session admission worker bootstrap timed out")),
      timeoutMs,
    );
    channel.once("message", onMessage);
    channel.once("disconnect", onDisconnect);
  });
}

async function main(): Promise<number> {
  const options = parseSessionAdmissionMatrixArgs(process.argv.slice(2));
  const workerNonce = sessionAdmissionMatrixWorkerNonce(
    process.env[WORKER_NONCE_ENV],
    typeof process.send === "function",
  );
  if (workerNonce !== undefined) {
    await waitForSessionAdmissionWorkerBootstrap(workerNonce);
    const result = await runWorker(options);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return 0;
  }
  return runWatchdog(options);
}

function isMainModule(): boolean {
  const entrypoint = process.argv[1];
  return Boolean(entrypoint) && pathToFileURL(path.resolve(entrypoint)).href === import.meta.url;
}

if (isMainModule()) {
  main().then(
    (status) => {
      process.exitCode = status;
    },
    (error: unknown) => {
      process.stderr.write(`${renderFailure(error)}\n`);
      process.exitCode = 1;
    },
  );
}
