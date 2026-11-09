// The headless run orchestrator (headless-run spec §3, plan Task 13).
//
// `runHeadlessAgent` is the whole of `runfree run` below its yargs module:
// it validates the agent and the prompt file, holds the project run lock,
// keeps the host-only run record, runs the same runtime steps as an
// interactive launch on a non-interactive IO, launches the agent with its
// prompt as stdin through the admission driver, and ends every path through
// one stop routine (§3.5):
//
//   1-2. inside the driver: delete the session file, then stop the exact
//        container under its creation receipt (on cancel), or its normal
//        teardown (on completion or failure);
//   3.   delete the inbox prompt and finalize the record;
//   4.   release the lock only when the teardown was confirmed;
//   5.   return the §3.6 exit code.
//
// The process holds a signal-exit deferral and its own persistent SIGINT and
// SIGTERM listeners for the whole run (plan C5): the first signal (or the
// timeout) cancels the launch, a later one only escalates the stop.

import path from "node:path";

import { APPROVAL_HEADLESS_DENIED_EVENT_PREFIX } from "@runfree/runtime-contracts/write-approvals";
import { BUILTIN_AGENT_DESCRIPTORS, builtinAgent } from "../agents.ts";
import { runHeadlessAgentRuntime, type HeadlessRuntimeHooks, type HeadlessRuntimeResult } from "../runtime.ts";
import { deferSignalExit } from "../signal-exit.ts";
import { createHeadlessRuntimeIO, enterHeadlessTerminalMode } from "../terminal-mode.ts";
import { flushWarnings, runfreeError, warn } from "../warnings.ts";
import {
  createHeadlessOutputParser,
  decideHeadlessOutcome,
  type HeadlessOutcome,
} from "./headless-agent-output.ts";
import {
  createHeadlessForegroundSpawner,
  type HeadlessForegroundCapture,
  type HeadlessForegroundSinks,
} from "./headless-foreground.ts";
import { deleteInboxPrompt, HeadlessPromptFileError, readPromptFileBounded, writeInboxPrompt } from "./headless-prompt.ts";
import {
  acquireHeadlessRunLock,
  HeadlessRunLockHeldError,
  type AcquireHeadlessRunLockInput,
  type HeadlessRunLock,
} from "./headless-run-lock.ts";
import {
  createHeadlessRunId,
  assertRunRecordOutsideProject,
  createRunRecord,
  summaryLines,
  type HeadlessRunJson,
  type HeadlessRunOutcome,
  type HeadlessRunRecord,
  type HeadlessRunTeardown,
  type HeadlessUncheckedAuthority,
} from "./headless-run-record.ts";
import {
  headlessAskExposure,
  headlessWritePostureWarning,
  uncheckedAuthority,
  type HeadlessAskExposure,
} from "./headless-write-posture.ts";
import { dockerClientEnvOptions } from "./docker.ts";
import { createDockerClient } from "./docker-client.ts";
import {
  assertBuiltinLaunchAgent,
  launchHeadlessAgentThroughAdmission,
  type SessionHeadlessLaunchInput,
  type SessionHeadlessLaunchResult,
} from "./session-public-launch.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";
import { projectHash } from "../project-identity.ts";

/** §3.6 codes `run` reserves above the agent's own 1-63. */
export const HEADLESS_RUN_EXIT = Object.freeze({
  usage: 64,
  refused: 65,
  skipped: 66,
  interrupted: 67,
  deniedWrites: 68,
});

/** How long the captured streams, the parser, and the record writes get to finish after the launch. */
export const HEADLESS_DRAIN_BOUND_MS = 10_000;
/** The denial count reads the proxy log from a little before the run, for clock skew; the session filter keeps it exact. */
const DENIAL_LOG_SKEW_MS = 60_000;
const DENIAL_LOG_TIMEOUT_MS = 15_000;
const DENIAL_LOG_MAX_BYTES = 64 * 1024 * 1024;
const DENIAL_EVENT_MAX_LINE_BYTES = 64 * 1024;

export type HeadlessRunOptions = Readonly<{
  /** Read as given; the command module resolves it against the invocation directory. */
  promptFile: string;
  timeoutMs?: number;
  acceptDeniedWrites: boolean;
  verbose?: boolean;
}>;

type AbortReason = "timeout" | "signal";

/** Where the run's persistent signal listeners go: `process`, or a test emitter. */
export type HeadlessRunSignalSource = Readonly<{
  on(signal: "SIGINT" | "SIGTERM", listener: () => void): unknown;
  off(signal: "SIGINT" | "SIGTERM", listener: () => void): unknown;
}>;

export type HeadlessRunDeps = Readonly<{
  runtime: <T>(
    context: RuntimeContext,
    io: RuntimeIO,
    agentName: string,
    options: Readonly<{ verbose?: boolean }>,
    hooks: HeadlessRuntimeHooks<T>,
  ) => Promise<HeadlessRuntimeResult<T>>;
  launch: (input: SessionHeadlessLaunchInput) => Promise<SessionHeadlessLaunchResult>;
  createSpawner: (sinks: HeadlessForegroundSinks) => HeadlessForegroundCapture;
  writePosture: (activeContext: RuntimeContext) => HeadlessAskExposure;
  uncheckedAuthority: (activeContext: RuntimeContext, agentName: string) => HeadlessUncheckedAuthority;
  countDenials: (input: HeadlessDenialCountInput) => number | null;
  acquireLock: (input: AcquireHeadlessRunLockInput) => HeadlessRunLock;
  signals: HeadlessRunSignalSource;
  setTimer: (ms: number, fire: () => void) => () => void;
  now: () => Date;
  stdout: (line: string) => void;
}>;

const DEFAULT_DEPS: HeadlessRunDeps = Object.freeze({
  runtime: runHeadlessAgentRuntime,
  launch: launchHeadlessAgentThroughAdmission,
  createSpawner: (sinks: HeadlessForegroundSinks) => createHeadlessForegroundSpawner(sinks),
  writePosture: headlessAskExposure,
  uncheckedAuthority,
  countDenials: countHeadlessDenials,
  acquireLock: acquireHeadlessRunLock,
  signals: process,
  setTimer: (ms: number, fire: () => void) => {
    const timer = setTimeout(fire, ms);
    return () => clearTimeout(timer);
  },
  now: () => new Date(),
  stdout: (line: string) => console.log(line),
});

/** Built-in agents with a headless mode: the only `run` targets. */
export function headlessAgentIds(): string[] {
  return BUILTIN_AGENT_DESCRIPTORS.filter((descriptor) => descriptor.headless !== undefined).map((descriptor) => descriptor.id);
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export type HeadlessRunExitInput = Readonly<{
  stage: "skipped" | "refused" | "launched";
  aborted?: AbortReason;
  /** The outcome rule's answer; absent when the launch never returned a status. */
  agent?: HeadlessOutcome;
  denials?: number | null;
  acceptDeniedWrites: boolean;
}>;

/**
 * The §3.6 exit code and the outcome `run.json` records. Precedence: a held
 * lock (66); a timeout or signal (67, whatever the agent or a refusal said);
 * a refusal before the container (65); the agent's own failure (1-63);
 * unverified (1); a success with headless denials and no
 * `--accept-denied-writes` (68); a success whose denials could not be counted
 * and no flag (1, unverified: never 0 or 68 without evidence); success (0).
 */
export function decideHeadlessRunExit(input: HeadlessRunExitInput): Readonly<{ outcome: HeadlessRunOutcome; exitCode: number }> {
  if (input.stage === "skipped") return { outcome: "skipped", exitCode: HEADLESS_RUN_EXIT.skipped };
  if (input.aborted) return { outcome: input.aborted, exitCode: HEADLESS_RUN_EXIT.interrupted };
  if (input.stage === "refused") return { outcome: "refused", exitCode: HEADLESS_RUN_EXIT.refused };
  const agent = input.agent;
  if (!agent || agent.outcome === "unverified") return { outcome: "unverified", exitCode: 1 };
  if (agent.outcome === "failed") return { outcome: "failed", exitCode: agent.exitCode };
  if (input.acceptDeniedWrites) return { outcome: "success", exitCode: 0 };
  if (input.denials === null || input.denials === undefined) return { outcome: "unverified", exitCode: 1 };
  if (input.denials > 0) return { outcome: "success", exitCode: HEADLESS_RUN_EXIT.deniedWrites };
  return { outcome: "success", exitCode: 0 };
}

/**
 * Counts this session's `headless-denied` events in proxy log text. Only a
 * line that starts with the event prefix counts, so a request path the proxy
 * logs mid-line cannot add one; the proxy logs one such line per refused
 * request, with no repeat suppression (plan C6).
 */
export function countHeadlessDenialEvents(logs: string, sessionId: string): number {
  let count = 0;
  for (const rawLine of logs.split("\n")) {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (!line.startsWith(APPROVAL_HEADLESS_DENIED_EVENT_PREFIX) || line.length > DENIAL_EVENT_MAX_LINE_BYTES) continue;
    try {
      const event: unknown = JSON.parse(line.slice(APPROVAL_HEADLESS_DENIED_EVENT_PREFIX.length));
      if (event === null || typeof event !== "object" || Array.isArray(event)) continue;
      const fields = event as Record<string, unknown>;
      if (fields.v === 1 && fields.sessionId === sessionId) count += 1;
    } catch {
      // A malformed line is not an event.
    }
  }
  return count;
}

export type HeadlessDenialCountInput = Readonly<{
  context: RuntimeContext;
  io: RuntimeIO;
  proxyId: string;
  sinceIso: string;
  sessionId: string;
}>;

/**
 * Reads the run's own proxy log since the run started and counts this
 * session's denials; `null` when the log cannot be read (plan P-D1), for
 * example after a proxy replacement, so the caller never claims a count it
 * did not see.
 */
export function countHeadlessDenials(input: HeadlessDenialCountInput): number | null {
  try {
    const client = createDockerClient(input.io, dockerClientEnvOptions(input.context));
    const logs = client.logs(input.proxyId, { since: input.sinceIso }, {
      timeout: DENIAL_LOG_TIMEOUT_MS,
      maxBuffer: DENIAL_LOG_MAX_BYTES,
    });
    if (logs.status !== 0) return null;
    return countHeadlessDenialEvents(`${logs.stdout}\n${logs.stderr}`, input.sessionId);
  } catch {
    return null;
  }
}

function usage(message: string): number {
  runfreeError(message);
  return HEADLESS_RUN_EXIT.usage;
}

/**
 * Runs one headless agent turn and returns its §3.6 exit code. Never throws
 * for a refusal or a failure of the run itself; a usage problem returns 64
 * before any side effect (no lock, no record, no inbox write, no Docker call).
 */
export async function runHeadlessAgent(
  context: RuntimeContext,
  baseIO: RuntimeIO,
  agentName: string,
  options: HeadlessRunOptions,
  overrides: Partial<HeadlessRunDeps> = {},
): Promise<number> {
  const deps: HeadlessRunDeps = { ...DEFAULT_DEPS, ...overrides };
  try {
    assertBuiltinLaunchAgent(agentName);
  } catch (error) {
    return usage(errorText(error));
  }
  const headless = builtinAgent(agentName)?.headless;
  if (!headless) return usage(`${agentName} has no headless mode yet; agents with one: ${headlessAgentIds().join(", ")}`);
  if (options.timeoutMs !== undefined && (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs <= 0)) {
    return usage(`the timeout must be a positive whole number of milliseconds, not ${options.timeoutMs}`);
  }
  let prompt: Buffer;
  try {
    prompt = readPromptFileBounded(path.resolve(options.promptFile));
  } catch (error) {
    if (error instanceof HeadlessPromptFileError) return usage(error.message);
    throw error;
  }

  const releaseTerminalMode = enterHeadlessTerminalMode();
  const releaseSignalExit = deferSignalExit();
  const cancel = new AbortController();
  const escalate = new AbortController();
  let aborted: AbortReason | undefined;
  const abort = (reason: AbortReason): void => {
    if (aborted === undefined) {
      aborted = reason;
      cancel.abort(reason);
    } else if (reason === "signal") {
      escalate.abort("signal");
    }
  };
  const onSignal = (): void => abort("signal");
  deps.signals.on("SIGINT", onSignal);
  deps.signals.on("SIGTERM", onSignal);
  const cancelTimer = options.timeoutMs !== undefined ? deps.setTimer(options.timeoutMs, () => abort("timeout")) : () => {};
  // The timer alone is not enough: a synchronous startup call can block past
  // the deadline and the run then settle before the overdue timer runs. Every
  // read of the abort reason first honors an elapsed deadline.
  const deadlineMs = options.timeoutMs !== undefined ? deps.now().getTime() + options.timeoutMs : undefined;
  const abortReason = (): AbortReason | undefined => {
    if (aborted === undefined && deadlineMs !== undefined && deps.now().getTime() >= deadlineMs) abort("timeout");
    return aborted;
  };
  try {
    return await runUnderLock({
      context,
      io: createHeadlessRuntimeIO(baseIO),
      agentName,
      options,
      deps,
      prompt,
      outputFormat: headless.outputFormat,
      cancellation: { signal: cancel.signal, escalate: escalate.signal },
      aborted: abortReason,
    });
  } finally {
    cancelTimer();
    deps.signals.off("SIGINT", onSignal);
    deps.signals.off("SIGTERM", onSignal);
    releaseSignalExit();
    releaseTerminalMode();
  }
}

type RunInput = Readonly<{
  context: RuntimeContext;
  io: RuntimeIO;
  agentName: string;
  options: HeadlessRunOptions;
  deps: HeadlessRunDeps;
  prompt: Buffer;
  outputFormat: Parameters<typeof createHeadlessOutputParser>[0];
  cancellation: SessionHeadlessLaunchInput["cancellation"];
  aborted: () => AbortReason | undefined;
}>;

async function runUnderLock(input: RunInput): Promise<number> {
  const { context, io, agentName, options, deps } = input;
  const { stateDir, inboxDir, sessionsDir } = context.project.paths;
  const startedAt = deps.now();
  const runId = createHeadlessRunId(startedAt);
  const baseRun = {
    v: 1 as const,
    runId,
    agent: agentName,
    startedAt: startedAt.toISOString(),
    acceptDeniedWrites: options.acceptDeniedWrites,
  };

  try {
    assertRunRecordOutsideProject(stateDir, runId, context.projectRoot);
  } catch (error) {
    runfreeError(`the headless run did not start: ${errorText(error)}`);
    return HEADLESS_RUN_EXIT.refused;
  }

  let lock: HeadlessRunLock;
  try {
    lock = deps.acquireLock({
      stateDir,
      projectId: projectHash(context.projectRoot),
      inboxDir,
      sessionsDir,
      io,
      ...(context.env ? { env: context.env } : {}),
    });
  } catch (error) {
    if (!(error instanceof HeadlessRunLockHeldError)) {
      runfreeError(`the headless run did not start: ${errorText(error)}`);
      return HEADLESS_RUN_EXIT.refused;
    }
    runfreeError(error.message);
    writeSkippedRecord(input, baseRun);
    return HEADLESS_RUN_EXIT.skipped;
  }

  const parser = createHeadlessOutputParser(input.outputFormat);
  let record: HeadlessRunRecord | undefined;
  const capture = deps.createSpawner({
    // The parser sees every byte even if a record write fails; the failure
    // then makes the capture undrained, so the run is unverified.
    stdout: (chunk) => {
      parser.push(chunk);
      record?.appendTranscript(chunk);
    },
    stderr: (chunk) => record?.appendStderr(chunk),
    stdoutEnded: () => parser.endStream(),
  });
  const session: { sessionId?: string; containerId?: string } = {};
  let promptWritten = false;
  let launchStarted = false;
  let refused = false;
  let launchResult: SessionHeadlessLaunchResult | undefined;
  let launchError: unknown;
  let abortedAtSettle: AbortReason | undefined;
  let unchecked: HeadlessUncheckedAuthority | null = null;
  let askExposure: HeadlessAskExposure | null = null;
  let active: Readonly<{ context: RuntimeContext; proxyId: string }> | undefined;

  try {
    record = createRunRecord(stateDir, runId, { projectRoot: context.projectRoot });
    record.startStderrTee();
    const promptContainerPath = writeInboxPrompt(inboxDir, runId, input.prompt);
    promptWritten = true;
    if (input.aborted() !== undefined) {
      refused = true;
    } else {
      const result = await deps.runtime(context, io, agentName, { verbose: options.verbose === true }, {
        beforeLaunch: (activeContext) => {
          unchecked = deps.uncheckedAuthority(activeContext, agentName);
          // A startup signal skips the launch; the abort decides the code.
          if (input.aborted() !== undefined) return HEADLESS_RUN_EXIT.interrupted;
          // Early warning only: the proxy denies every ask write of a headless
          // session, so an exposed run still starts (maintainer decision
          // 2026-10-29). The list goes to run.json, one line to the terminal.
          askExposure = deps.writePosture(activeContext);
          const warning = headlessWritePostureWarning(askExposure, { acceptDeniedWrites: options.acceptDeniedWrites });
          if (warning !== undefined) {
            warn(warning);
            // `warn` only buffers, and the runtime flushed the buffer just
            // before this hook. Flush now, so the line prints before the
            // launch and lands in the run's stderr.log tee, not at CLI exit.
            flushWarnings();
          }
          return undefined;
        },
        launch: async (launch) => {
          active = { context: launch.activeContext, proxyId: launch.proxyId };
          launchStarted = true;
          return await deps.launch({
            preparedRuntime: launch.preparedRuntime,
            io,
            agentName,
            foregroundSpawner: capture.spawn,
            reprepare: launch.reprepare,
            headless: {
              promptContainerPath,
              observer: {
                allocated: (allocated) => {
                  session.sessionId = allocated.sessionId;
                  lock.recordSession(allocated);
                },
                containerCreated: (containerId) => {
                  session.containerId = containerId;
                  lock.recordContainer(containerId);
                },
              },
            },
            cancellation: input.cancellation,
          });
        },
      });
      if (result.kind === "refused") refused = true;
      else launchResult = result.value;
    }
    // Read at the moment the run settles: a deadline that elapses during
    // the stop routine or the stream drain below is not a timeout of the
    // run, which had already finished.
    abortedAtSettle = input.aborted();
  } catch (error) {
    abortedAtSettle = input.aborted();
    launchError = error;
    runfreeError(`the headless run failed: ${errorText(error)}`);
    // Nothing ran yet: a failure before the container exists is a refusal.
    if (session.containerId === undefined) refused = true;
  }

  // A thrown aggregate is a teardown that did not complete
  // (`SessionTeardownIncompleteError`, or a cleanup failure beside the
  // launch failure); any other end after allocation was torn down by the
  // driver itself.
  const teardown: HeadlessRunTeardown = launchError instanceof AggregateError
    ? "unconfirmed"
    : session.sessionId !== undefined ? "confirmed" : "not-started";

  const drained = launchStarted ? (await capture.drain(HEADLESS_DRAIN_BOUND_MS)).drained : false;
  const parsed = parser.result();
  const streamsDrained = drained && record !== undefined && !record.transcriptTruncated();
  const agent = launchResult
    ? decideHeadlessOutcome({ agentStatus: launchResult.status, streamsDrained, parser: parsed })
    : undefined;
  const denials = session.sessionId === undefined
    ? 0
    : active
      ? deps.countDenials({
        context: active.context,
        io,
        proxyId: active.proxyId,
        sinceIso: new Date(startedAt.getTime() - DENIAL_LOG_SKEW_MS).toISOString(),
        sessionId: session.sessionId,
      })
      : null;
  const decision = decideHeadlessRunExit({
    stage: refused ? "refused" : "launched",
    ...(abortedAtSettle ? { aborted: abortedAtSettle } : {}),
    ...(agent ? { agent } : {}),
    denials,
    acceptDeniedWrites: options.acceptDeniedWrites,
  });

  // Stop routine step 3: the prompt, then the record.
  if (promptWritten) {
    try {
      deleteInboxPrompt(inboxDir, runId);
    } catch (error) {
      warn(`the headless run's inbox prompt could not be removed: ${errorText(error)}`);
    }
  }
  let run: HeadlessRunJson = {
    ...baseRun,
    endedAt: deps.now().toISOString(),
    agentStatus: launchResult?.status ?? null,
    outcome: decision.outcome,
    exitCode: decision.exitCode,
    teardown,
    ...(session.sessionId !== undefined ? { sessionId: session.sessionId } : {}),
    ...(session.containerId !== undefined ? { containerId: session.containerId } : {}),
    headlessDenials: denials,
    uncheckedAuthority: unchecked,
    askExposure,
    streamsDrained,
    reattached: capture.reattached(),
    transcriptBytes: record?.transcriptBytes() ?? 0,
    transcriptTruncated: record?.transcriptTruncated() ?? false,
    stderrTruncated: record?.stderrTruncated() ?? false,
    malformedLines: parsed.malformedLines,
  };
  if (record) {
    try {
      record.finalize(run, parsed.finalMessage !== undefined ? { finalMessage: parsed.finalMessage } : {});
    } catch (error) {
      warn(`the headless run record could not be finalized: ${errorText(error)}`);
      // A success needs its record: without it the run is unverified.
      if (run.exitCode === 0) run = { ...run, outcome: "unverified", exitCode: 1 };
    }
  }

  // Step 4: the lock goes only with a confirmed (or never started) teardown;
  // otherwise it names the container the next run must see gone.
  if (teardown !== "unconfirmed") {
    try {
      lock.release();
    } catch (error) {
      warn(`the headless run lock could not be released: ${errorText(error)}`);
    }
  }

  if (record) {
    for (const line of summaryLines({ run, ...(parsed.finalMessage !== undefined ? { finalMessage: parsed.finalMessage } : {}), recordDir: record.dir })) {
      deps.stdout(line);
    }
  }
  // Step 5.
  return run.exitCode;
}

/** The record of a run skipped by a held lock; best effort, the exit is 66 regardless. */
function writeSkippedRecord(
  input: RunInput,
  baseRun: Pick<HeadlessRunJson, "v" | "runId" | "agent" | "startedAt" | "acceptDeniedWrites">,
): void {
  try {
    const record = createRunRecord(input.context.project.paths.stateDir, baseRun.runId, { projectRoot: input.context.projectRoot });
    const run: HeadlessRunJson = {
      ...baseRun,
      endedAt: input.deps.now().toISOString(),
      agentStatus: null,
      outcome: "skipped",
      exitCode: HEADLESS_RUN_EXIT.skipped,
      teardown: "not-started",
      headlessDenials: 0,
      uncheckedAuthority: null,
      askExposure: null,
      streamsDrained: false,
      reattached: false,
      transcriptBytes: 0,
      transcriptTruncated: false,
      stderrTruncated: false,
      malformedLines: 0,
    };
    record.finalize(run, {});
    for (const line of summaryLines({ run, recordDir: record.dir })) input.deps.stdout(line);
  } catch (error) {
    warn(`the skipped headless run could not be recorded: ${errorText(error)}`);
  }
}
