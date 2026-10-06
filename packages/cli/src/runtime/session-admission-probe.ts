import { remedy } from "../remedies.ts";
import { SessionFileTeardownBlockedError } from "./session-file-teardown.ts";

export const BUILTIN_SESSION_ADMISSION_PROBE_AGENTS = ["claude", "codex", "pi"] as const;

export type SessionAdmissionProbeAgent = typeof BUILTIN_SESSION_ADMISSION_PROBE_AGENTS[number];

/**
 * What a session's first project-controlled process is.
 *
 * A built-in agent, or the agent image's interactive login shell. The shell is
 * a launch-only kind: the container, mounts, environment, admission sequence,
 * and revocation are identical to an agent session — the whole difference is
 * the typed launch argv and the session's display/evidence identity. Probes
 * and metrics remain agent-only, guarded where they consume this.
 */
export type SessionAdmissionSessionKind = SessionAdmissionProbeAgent | "shell";

// Consumed by the live session-admission matrix (tests/runtime): total Docker
// operations and provisioning-to-proof latency per probe run. Per-phase
// accounting was removed with the rest of the metrics apparatus.
export type SessionAdmissionProbeMetrics = Readonly<{
  agent: SessionAdmissionProbeAgent;
  dockerOperations: number;
  provisioningToSequenceMs: number;
}>;

/**
 * The single-inspection admission ladder, as steps.
 *
 * `createStarted` creates the session container and spawns its foreground
 * start in one step: Docker refuses a duplicate static address at start, and
 * the durable record is provisioning-running (bound container id) before the
 * spawn, so a crash at any point leaves exactly one inert, reclaimable pair.
 * `proveRunning` is the ONE shape proof of the whole admission: a single
 * post-start inspection held byte-exact to the create plan, including the
 * network endpoint at exactly the allocated address.
 *
 * Between start and activation the container holds no traffic authority:
 * nothing names it anywhere — its address is in no kernel session set, it has
 * no session file, and the request proxy refuses it as an unknown peer.
 * Activation is the single widening step, spending the single running proof
 * once. `tearDown` is the single narrowing step: one ordered sequence that
 * takes the session file away first and drops the durable record last.
 */
export type SessionAdmissionProbeSteps = Readonly<{
  agent: SessionAdmissionSessionKind;
  nowMs(): number;
  dockerOperationCount(): number;
  preflight(): Promise<void>;
  allocate(): Promise<void>;
  createStarted(): Promise<void>;
  proveRunning(): Promise<void>;
  cleanupUnadmitted(): Promise<void>;
  tearDown(): Promise<void>;
  /**
   * Whether this session could already have been selected by a consumer.
   *
   * It decides which cleanup answers a failure: the ordered teardown, which
   * must run once anything may be serving the session, or the unadmitted
   * cleanup, which is right while nothing can be. A steps object that does not
   * implement this is assumed to be servable from `createStarted` onwards.
   *
   * The driver answers for itself: until the admitting beat has entered its
   * write there is no session file, so running the teardown before it would
   * report a revocation that never happened, and would spend a session-file
   * delete against a proxy that was never told about this session.
   */
  provisioningMayBeSelected?(): boolean;
}>;

/**
 * The launch sequence's extra steps, on top of the probe's.
 *
 * The probe deliberately tears down instead of activating, so it can never
 * enable a public attach. Launch is the same sequence up to the running proof
 * and then diverges: it grants authority, holds it for the life of the attached
 * process while beating its session file, and tears down on the way out.
 */
export type SessionAdmissionLaunchSteps = SessionAdmissionProbeSteps & Readonly<{
  /** Grants the session ordinary proxy authority. First point it has any. */
  activate(): Promise<void>;
  /**
   * Reports the session `attached` once its entry has handed off to the agent.
   *
   * Runs under the same lifecycle lock as `activate`, so no proxy replacement
   * or restore can land between the grant and the entry's exec — the window in
   * which a still-gated entry could be left polling a proxy that no longer
   * serves it. Bounded by a fixed ceiling well inside the lock acquisition
   * window, and it grants nothing: authority was spent by `activate`.
   */
  awaitHandoff(): Promise<void>;
  /**
   * Waits for the attached process to finish, beating its session file as it
   * runs.
   *
   * The heartbeat lives inside the wait rather than beside it because an
   * attached session whose file stops being renewed keeps running with no
   * authority — the failure is silent from the agent's side and looks like an
   * unexplained network outage.
   */
  awaitCompletion(): Promise<SessionAdmissionLaunchOutcome>;
}>;

export type SessionAdmissionLaunchOutcome = Readonly<{
  /** Exit status of the attached process, or null when it died by signal. */
  status: number | null;
  signal: NodeJS.Signals | null;
  /**
   * Set only for a resume launch that reached `attached` and then ended
   * non-zero: its own transient session evidence is kept as interrupted
   * instead of being removed, so the resuming terminal's own ids survive a
   * second Docker stop (security review F3, decision 10). The claim layer
   * reads this to consume the claimed original evidence even though the
   * exit status itself is non-zero.
   */
  resumeRecordKept?: boolean;
}>;

/**
 * Internal launch sequence for one per-session container.
 *
 * Identical to the probe through the running proof, then activates rather than
 * tearing down. Every exit path still tears down: a session that has been
 * granted authority must give it back whether the agent exited cleanly,
 * crashed, or its session file could not be renewed.
 *
 * Reached by every public launch: `runfree claude|codex|pi`, `runfree shell`,
 * `runfree resume`, and `runfree mcp auth` all route here through
 * `session-public-launch.ts`. Source-IP attribution and session-keyed grants
 * must therefore hold together — several containers sharing one approval
 * subject would be strictly worse than the shared agent this replaced. The
 * attached live tranche proves session grant separation.
 */
export async function runInternalSessionAdmissionLaunch(
  steps: SessionAdmissionLaunchSteps,
): Promise<SessionAdmissionLaunchOutcome> {
  let cleanupUnadmitted = false;
  let provisioningMayBeSelected = (): boolean => false;
  let outcome: SessionAdmissionLaunchOutcome;

  try {
    await steps.preflight();
    cleanupUnadmitted = true;
    await steps.allocate();
    await steps.createStarted();

    // Every failure from this point uses the ordered teardown — unless the
    // steps answer for themselves that nothing could be serving this session
    // yet (see `provisioningMayBeSelected`).
    provisioningMayBeSelected = steps.provisioningMayBeSelected ?? ((): boolean => true);
    await steps.proveRunning();
    await steps.activate();
    await steps.awaitHandoff();
    outcome = await steps.awaitCompletion();
  } catch (failure) {
    if (provisioningMayBeSelected()) {
      return await throwWithCleanupFailure(failure, () => cleanupProvisioningSession(steps), "launch");
    }
    if (cleanupUnadmitted) {
      return await throwWithCleanupFailure(failure, () => steps.cleanupUnadmitted(), "launch");
    }
    throw failure;
  }
  // Outside the guard above on purpose. A teardown that fails here is not a
  // launch failure to be answered with a second teardown and reported as a
  // pair: it is the one failure, retried once, and reported once.
  await tearDownAfterCompletion(steps);
  return outcome;
}

/**
 * The session ended but its ordered teardown did not complete.
 *
 * Whatever step stopped the teardown left the record in place, so the
 * session's address stays reserved and the next start or launch finishes the
 * job; this error says so rather than describing an admission that failed.
 * Two identical failures — the ordinary shape when Docker is unreachable — are
 * reported once.
 */
export class SessionTeardownIncompleteError extends AggregateError {
  constructor(failures: readonly unknown[]) {
    super(
      distinctFailures(failures),
      "the session ended but its teardown did not complete; any lifecycle record it left keeps the session's"
        + ` address reserved; once Docker is reachable, the next \`${remedy.up()}\` or launch normally finishes the`
        + " teardown, and otherwise names the remedy",
    );
    this.name = "SessionTeardownIncompleteError";
  }
}

/**
 * What makes two failures the same failure: name, message, typed observation
 * evidence, and cause, recursively. Anything less would let a repeat hide a
 * different cause behind the same sentence.
 */
function failureIdentity(failure: unknown, depth = 0): string {
  if (!(failure instanceof Error)) return String(failure);
  const evidence = (failure as { evidence?: unknown }).evidence;
  let evidenceText = "";
  try {
    evidenceText = evidence === undefined ? "" : JSON.stringify(evidence);
  } catch {
    evidenceText = "<unserializable evidence>";
  }
  const cause = depth < 4 && failure.cause !== undefined ? failureIdentity(failure.cause, depth + 1) : "";
  const nested = failure instanceof AggregateError && Array.isArray(failure.errors) && depth < 4
    ? failure.errors.map((error: unknown) => failureIdentity(error, depth + 1)).join("|")
    : "";
  return JSON.stringify([failure.name, failure.message, evidenceText, cause, nested]);
}

function distinctFailures(failures: readonly unknown[]): unknown[] {
  const seen = new Set<string>();
  return failures.filter((failure) => {
    const identity = failureIdentity(failure);
    if (seen.has(identity)) return false;
    seen.add(identity);
    return true;
  });
}

/**
 * The post-completion teardown, with the one retry the ladder has always
 * given it.
 *
 * A retry that completes still reports the first failure — the first pass
 * left something undone that this host saw fail — but a retry that also fails
 * becomes one `SessionTeardownIncompleteError`, never a probe failure paired
 * with its own repeat.
 */
async function tearDownAfterCompletion(steps: SessionAdmissionProbeSteps): Promise<void> {
  try {
    await cleanupProvisioningSession(steps);
    return;
  } catch (first) {
    try {
      await cleanupProvisioningSession(steps);
    } catch (second) {
      throw new SessionTeardownIncompleteError([first, second]);
    }
    throw first;
  }
}

function nonnegativeFinite(value: number, label: string): number {
  if (!Number.isFinite(value) || value < 0) throw new Error(`${label} must be a nonnegative finite number`);
  return value;
}

function operationCount(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("Docker operation count must be a nonnegative safe integer");
  }
  return value;
}

/**
 * The whole narrowing sequence, in one step.
 *
 * The ordered teardown takes the session file away, stops and removes the
 * container, and drops the durable record last, under one lifecycle lock. The
 * kernel does not split that across steps: a sequence spread over several
 * ladder rungs could stop the container and drop the record after a file
 * delete that never happened.
 */
async function cleanupProvisioningSession(steps: SessionAdmissionProbeSteps): Promise<void> {
  await steps.tearDown();
}

async function throwWithCleanupFailure(
  failure: unknown,
  cleanup: () => Promise<void>,
  sequence: "probe" | "launch" = "probe",
): Promise<never> {
  try {
    await cleanup();
  } catch (cleanupFailure) {
    // The same blocked revocation twice is one fact, not two failures: the
    // launch reports it as the plain refusal it is, with its remedy, rather
    // than as an aggregate of identical internal errors (todo 35 fix 6).
    if (failure instanceof SessionFileTeardownBlockedError && cleanupFailure instanceof SessionFileTeardownBlockedError) {
      throw cleanupFailure;
    }
    throw new AggregateError(
      distinctFailures([failure, cleanupFailure]),
      `session admission ${sequence} failed and fail-closed cleanup also failed`,
    );
  }
  throw failure;
}

/**
 * Internal lifecycle kernel for the opt-in Docker admission gate.
 *
 * Every proof and receipt stays in the concrete adapter process. A successful
 * sequence is deliberately torn down instead of activated, so this kernel
 * cannot enable public per-session attach.
 */
export async function runInternalSessionAdmissionProbe(
  steps: SessionAdmissionProbeSteps,
): Promise<SessionAdmissionProbeMetrics> {
  const operationsBefore = operationCount(steps.dockerOperationCount());
  let cleanupUnadmitted = false;
  let provisioningMayBeSelected = (): boolean => false;
  let metrics: SessionAdmissionProbeMetrics | undefined;

  try {
    await steps.preflight();
    cleanupUnadmitted = true;
    await steps.allocate();
    await steps.createStarted();

    // Every failure from this point uses the ordered teardown — unless the
    // steps answer for themselves that nothing could be serving this session
    // yet (see `provisioningMayBeSelected`).
    provisioningMayBeSelected = steps.provisioningMayBeSelected ?? ((): boolean => true);
    const provisioningStartedAt = nonnegativeFinite(steps.nowMs(), "provisioning start time");
    await steps.proveRunning();
    const sequenceFinishedAt = nonnegativeFinite(steps.nowMs(), "proof sequence completion time");
    const operationsAfterSequence = operationCount(steps.dockerOperationCount());
    if (operationsAfterSequence < operationsBefore) {
      throw new Error("Docker operation count moved backwards during session admission");
    }
    if (sequenceFinishedAt < provisioningStartedAt) {
      throw new Error("proof sequence completion predates provisioning start");
    }
    // Runtime-guarded narrowing: probe metrics are agent-keyed, and the shell
    // session kind is launch-only. A shell steps object reaching the probe
    // sequence is a caller defect, not a metrics shape to invent.
    const agent = steps.agent;
    if (!BUILTIN_SESSION_ADMISSION_PROBE_AGENTS.includes(agent as SessionAdmissionProbeAgent)) {
      throw new Error(`session admission probe metrics require a built-in agent, not ${agent}`);
    }
    metrics = Object.freeze({
      agent: agent as SessionAdmissionProbeAgent,
      dockerOperations: operationsAfterSequence - operationsBefore,
      provisioningToSequenceMs: sequenceFinishedAt - provisioningStartedAt,
    });
  } catch (failure) {
    if (provisioningMayBeSelected()) {
      return await throwWithCleanupFailure(failure, () => cleanupProvisioningSession(steps));
    }
    if (cleanupUnadmitted) {
      return await throwWithCleanupFailure(failure, () => steps.cleanupUnadmitted());
    }
    throw failure;
  }

  if (!metrics) throw new Error("session admission probe did not produce metrics");
  await cleanupProvisioningSession(steps);
  return metrics;
}
