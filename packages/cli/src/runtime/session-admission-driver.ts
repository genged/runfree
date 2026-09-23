import { performance } from "node:perf_hooks";
import { RuntimeObservationError } from "./observation-failure.ts";

import type { SessionFileV1 } from "@runfree/runtime-contracts/session-file";
import { SESSION_ADMISSION_LEASE_MAX_DURATION_MS } from "@runfree/runtime-contracts/session-registry";

import { builtinAgent } from "../agents.ts";
import { resolveAgentCommand } from "../config.ts";
import { CliError } from "../errors.ts";
import { runfreeLog, warn } from "../warnings.ts";
import { hostBootId, hostProcessStart } from "./host-identity.ts";
import {
  createSessionAdmissionDockerGateway,
  type SessionAdmissionDockerGateway,
} from "./session-admission-docker-gateway.ts";
import {
  createAllocatedSessionContainerRecordFromPreflight,
  createRetainedSessionRebindProofPlan,
  createSessionAdmissionDriverPreflight,
  createSessionContainerCreatePlanFromPreflight,
  type SessionAdmissionDriverPreflight,
  type SessionAdmissionPreflightLaunch,
  type SessionAdmissionResumeRequest,
} from "./session-admission-driver-preflight.ts";
import {
  adoptCompatibleSessionControlPlaneRebind,
  assertNoPendingControlPlaneReplacement,
  SessionReplacementPendingError,
} from "./session-admission-rebind-adoption.ts";
import {
  readEffectiveControlPlaneV2,
  type ControlPlaneEffectiveSelectionV2,
} from "./component-state-v2.ts";
import {
  inspectAndWriteSessionFile,
  nextHeartbeatDelayMs,
  SESSION_HEARTBEAT_CADENCE_MS,
  type HeartbeatOutcome,
  type InspectAndWriteSessionFileInput,
  type SessionFileAnchor,
  type SessionFileDisplay,
  type SessionFileEligibilityBindings,
} from "./session-file-heartbeat.ts";
import {
  readSessionHostStatus,
  removeSessionHostStatus,
  writeSessionHostStatus,
  type SessionHostStatusServed,
} from "./session-host-status.ts";
import {
  executeSessionFileCommand,
  sessionIpReuseFenceCommand,
  sessionIpAssignmentReadCommand,
  sessionFileDeleteCommand,
} from "./session-file-publisher.ts";
import {
  teardownSessionRecord,
  type SessionFileTeardownResult,
} from "./session-file-teardown.ts";

import { cancellableDelay } from "./cancellable-delay.ts";
import {
  runInternalSessionAdmissionLaunch,
  runInternalSessionAdmissionProbe,
  type SessionAdmissionLaunchOutcome,
  type SessionAdmissionLaunchSteps,
  type SessionAdmissionProbeAgent,
  type SessionAdmissionProbeMetrics,
  type SessionAdmissionProbeSteps,
  type SessionAdmissionSessionKind,
} from "./session-admission-probe.ts";
import { createRuntimeTimings, type RuntimeTimings } from "./timings.ts";
import {
  authorizeSessionContainerOrphanCleanup,
  authorizeUnboundCreatedSessionRecordRecovery,
  creationAuthorizedSessionContainerRemoveCommand,
  creationAuthorizedSessionContainerStopCommand,
  executeSessionContainerCleanupCommand,
  executeSessionContainerCreate,
  orphanSessionContainerRemoveCommand,
  orphanSessionContainerStopCommand,
  proveSessionContainerAbsent,
  proveSessionContainerOrphanAbsent,
  removeAbsentSessionContainerRecordV2,
  recoverUnboundCreatedSessionRecordV2,
  type SessionContainerAbsenceReceipt,
  type SessionContainerCreationReceipt,
  type SessionContainerNetworkIdentity,
} from "./session-container-cleanup.ts";
import {
  executeSessionDockerCommand,
  sessionContainerAttachCommand,
  sessionContainerCreateCommand,
  sessionContainerInspectCommand,
  sessionContainerObservedExitStatus,
  sessionContainerStartAttachCommand,
  sessionNetworkInspectCommand,
  type SessionDockerCommand,
} from "./session-container-docker.ts";
import {
  authorizeProvisioningRunningSessionContainer,
  type SessionContainerProvisioningRunningAuthorization,
} from "./session-container-lifecycle-authorization.ts";
import {
  classifySessionContainerReconciliation,
  inspectSessionContainerInventory,
  type SessionReconciliationClassification,
} from "./session-container-reconciliation.ts";
import { assertSessionContainerNarrowRunningInspect } from "./session-container-narrow-liveness.ts";
import { waitForRunningSessionContainerProof } from "./session-container-running-proof.ts";
import {
  adoptSessionContainerForegroundControlPlaneRebind,
  cancelSessionContainerForegroundAttach,
  currentSessionContainerForegroundCompletion,
  reattachSessionContainerForeground,
  startSessionContainerForeground,
  type SessionContainerForegroundCompletion,
  type SessionContainerForegroundHandle,
  type SessionContainerForegroundSpawner,
} from "./session-container-start.ts";
import {
  bindSessionContainerCreatePlanRecord,
  type SessionContainerCreatePlan,
} from "./session-container-template.ts";
import {
  bindExactAllocatedSessionContainerRecordIdV2,
  bindAllocatedSessionContainerIdV2,
  listQuarantinedSessionContainerRecordNamesV2,
  listSessionContainerRecordsV2,
  mintSessionContainerLeaseV2,
  readSessionContainerRecordV2,
  removeExactSessionContainerRecordV2,
  replaceExactSessionContainerRecordV2,
  serializeSessionContainerRecordV2,
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2,
  transitionProvisioningRunningSessionContainerToAttachedV2,
  writeSessionContainerRecordV2,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import { reconcileSessions } from "./session-reconcile.ts";
import { sessionRecordOwnerLiveness } from "./session-record-liveness.ts";
import {
  allocateSessionSourceIpFromExactInternalNetworkBaseline,
  createControlPlaneInternalParticipantAuthority,
  validateExactInternalNetworkParticipantBaseline,
  type ExactIngressInternalParticipant,
  type ExactInternalNetworkParticipantBaseline,
} from "./session-internal-network-baseline.ts";
import {
  sessionNamedVolumeInspectRequest,
  validateSessionNamedVolumeInspect,
} from "./session-named-volume-proof.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import {
  consumePreparedRuntime,
  type PreparedRuntime,
} from "./prepared-runtime.ts";
import { createRuntimeDocker } from "./docker.ts";
import {
  createSessionId,
  createSessionMetadata,
  markSessionInterrupted,
  removeSessionMetadata,
  SessionLockAcquisitionAbortedError,
  SessionLockAcquisitionTimeoutError,
  writeSessionMetadata,
  type ProjectLifecycleLock,
  type SessionLockManager,
} from "./sessions.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO, SessionMetadata } from "./types.ts";
import { remedy } from "../remedies.ts";

const DEFAULT_INTERNAL_PROBE_LEASE_DURATION_MS = SESSION_ADMISSION_LEASE_MAX_DURATION_MS;

/**
 * The internally minted probe lease, shortenable for tests only.
 *
 * `RUNFREE_SESSION_INTERNAL_LEASE_DURATION_MS` lets a live acceptance test drive
 * lease-expiry timing in seconds instead of the multi-minute default. It is
 * clamped to `(0, MAX]`, so it can only ever SHORTEN the lease, never extend
 * authority past the contract maximum (which would be a downgrade). The value
 * is read from the host launch process's environment, which the agent container
 * cannot set; an absent, non-numeric, non-positive, or over-maximum value keeps
 * the default. A shorter lease renews more often, which is strictly tighter.
 */
function internalProbeLeaseDurationMs(): number {
  const raw = process.env.RUNFREE_SESSION_INTERNAL_LEASE_DURATION_MS;
  if (raw === undefined) return DEFAULT_INTERNAL_PROBE_LEASE_DURATION_MS;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_INTERNAL_PROBE_LEASE_DURATION_MS;
  return Math.min(Math.floor(parsed), DEFAULT_INTERNAL_PROBE_LEASE_DURATION_MS);
}

/** The floor a shortened heartbeat cadence is raised to. */
const SESSION_HEARTBEAT_MIN_CADENCE_MS = 1_000;

/**
 * How often one session may replace a lost foreground stream, and over what
 * window.
 *
 * A re-attach spends a `docker container attach`, so a stream that dies the
 * moment it is created (a broken terminal, a Docker CLI that cannot run here)
 * would otherwise spin. The limit is a rate and nothing more: reaching it never
 * ends a session whose container this host has just proved running — it stops
 * replacing the view and leaves the beat to report the container's own exit.
 * The window rolls, so a session that loses a stream now and again re-attaches
 * every time.
 */
const SESSION_REATTACH_MAX_PER_WINDOW = 3;
const SESSION_REATTACH_WINDOW_MS = 60_000;

/**
 * Whether a foreground completion is a lost stream rather than the agent's own
 * exit.
 *
 * Two shapes, and only two. A spawn or stream `error` never carried an exit
 * status in the first place, and an exit with a signal but no code is the
 * `docker start --attach` child being killed — neither is news about the
 * process inside the container, which is what the launch's status must report.
 * Every other exit carries the code the agent itself exited with.
 */
function lostForegroundStream(completion: SessionContainerForegroundCompletion): boolean {
  return completion.kind === "error" || (completion.code === null && completion.signal !== null);
}

/**
 * What one confirming inspection says about a lost foreground stream.
 *
 *   reattach  the exact anchored incarnation is still running, and this session
 *             may spend one of its re-attaches on it;
 *   exited    the inspection proved the container's own exit and carries the
 *             status the launch must report;
 *   teardown  the inspection answered, and it is neither of those — a changed
 *             container, or an answer that resolves to no incarnation this
 *             session owns. Handled exactly as this completion is handled
 *             today;
 *   wait      nothing was proved (the observation failed, or the re-attach
 *             limit is reached). Never a verdict about the session: the beat
 *             keeps running and asks again.
 */
type LostForegroundStreamDecision =
  | Readonly<{ kind: "reattach" }>
  | Readonly<{ kind: "exited"; status: number }>
  | Readonly<{ kind: "teardown"; observation: string }>
  | Readonly<{ kind: "wait"; observation: string }>;

/**
 * The per-session file heartbeat cadence, shortenable for tests only.
 *
 * `RUNFREE_SESSION_HEARTBEAT_CADENCE_MS` lets a live acceptance test drive
 * heartbeat timing in seconds instead of the half-minute default, exactly as
 * `RUNFREE_SESSION_INTERNAL_LEASE_DURATION_MS` does for the lease it renews.
 * Clamped to `[1000, SESSION_HEARTBEAT_CADENCE_MS]`, so it can only ever
 * SHORTEN the cadence: beating more often is strictly tighter, while a longer
 * cadence would let a file lapse between beats and read to the agent as an
 * unexplained network outage. The value is read from the host launch process's
 * environment, which the agent container cannot set; an absent, non-numeric,
 * non-positive, or over-default value keeps the default, and a value under the
 * floor is raised to it so a mistyped override cannot spin the beat.
 */
function sessionHeartbeatCadenceMs(): number {
  const raw = process.env.RUNFREE_SESSION_HEARTBEAT_CADENCE_MS;
  if (raw === undefined) return SESSION_HEARTBEAT_CADENCE_MS;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return SESSION_HEARTBEAT_CADENCE_MS;
  return Math.min(
    Math.max(Math.floor(parsed), SESSION_HEARTBEAT_MIN_CADENCE_MS),
    SESSION_HEARTBEAT_CADENCE_MS,
  );
}
const INTERNAL_DOCKER_CAPTURE_MAX_BYTES = 8 * 1024 * 1024;

// The one narrow-inspection verdict that can mean "the agent just exited"
// rather than "this is a different container": Docker can report the container
// stopped a moment before the foreground `docker start --attach` child
// delivers its exit event. Matched exactly, and only for this message.
const SESSION_CONTAINER_NOT_EXACT_RUNNING_OBSERVATION = "session container is not in exact running state";
// How long that one observation may wait on the foreground's own exit event
// before it is treated as identity drift. Short enough that a genuine mismatch
// is not delayed, long enough that the race resolves.
const FOREGROUND_EXIT_BRIDGE_TIMEOUT_MS = 1_000;
// How long the running proof may wait for the started container to reach
// Docker's running state. This is the helper's maximum, and it is deliberate:
// the running proof is now the *first* observation taken after
// `docker start --attach` is issued. Under the pre-file admission source,
// `register` (snapshot publish, selection, acknowledgement) ran in between and
// its Docker round-trips padded the window, so the helper's 5 s fallback was
// never the whole budget it appeared to be. With `register` gone the container
// has to be seen running within whatever this names, and a loaded Docker
// daemon can take longer than 5 s to start one. Widening the window admits
// nothing earlier: the proof still requires the same exact running assertion,
// and no session is authorized before it returns.
const RUNNING_PROOF_TIMEOUT_MS = 30_000;

class PostCompletionAdmissionRecoveryError extends Error {
  readonly outcome: SessionAdmissionLaunchOutcome;

  constructor(outcome: SessionAdmissionLaunchOutcome, cause: unknown) {
    super("attached session completed, but post-completion admission recovery failed", { cause });
    this.name = "PostCompletionAdmissionRecoveryError";
    this.outcome = outcome;
  }
}

function completionOutcomeFromFailure(failure: unknown): SessionAdmissionLaunchOutcome | undefined {
  if (failure instanceof PostCompletionAdmissionRecoveryError) return failure.outcome;
  if (!(failure instanceof AggregateError)) return undefined;
  for (const nested of failure.errors) {
    const outcome = completionOutcomeFromFailure(nested);
    if (outcome) return outcome;
  }
  return undefined;
}

export type SessionAdmissionLaunchOptions = Readonly<{
  /**
   * Launches the recovery spec's typed resume argv for this agent instead of
   * its default argv. Resume never revives an old container: it is a new
   * validated lifecycle session whose first project-controlled process resumes
   * the persisted conversation state. A failed resume removes its transient
   * host session evidence so the original recovery item stays the single
   * retryable representation of the interrupted conversation.
   */
  resume?: SessionAdmissionResumeRequest;
}>;

export type InternalSessionAdmissionDriver = Readonly<{
  /** Runs proof through provisioning, then always revokes it. Never activates. */
  probeBuiltin(agent: SessionAdmissionProbeAgent): Promise<SessionAdmissionProbeMetrics>;
  /**
   * Runs the same sequence but activates, holds the attached process, and
   * revokes on exit. Records outcome-aware host session evidence: a launch that
   * does not end with status 0 leaves interrupted evidence keyed to the
   * lifecycle record's session id (a resume launch instead removes its
   * transient evidence and leaves the claimed original item retryable).
   *
   * Every public foreground launch reaches this after the per-session cutover.
   * Source-IP attribution and session-keyed grants therefore remain part of
   * the same admission contract.
   */
  launchBuiltin(
    agent: SessionAdmissionProbeAgent,
    options?: SessionAdmissionLaunchOptions,
  ): Promise<SessionAdmissionLaunchOutcome>;
  /**
   * Launches the agent image's interactive login shell as a session.
   *
   * The same admission sequence, container, mounts, environment, evidence,
   * and revocation as an agent launch; only the typed launch argv and the
   * session's display/evidence identity differ. Deliberately unaffected by
   * the project's configured agent command — the shell is the escape hatch
   * the custom-command refusal points at.
   */
  launchShell(): Promise<SessionAdmissionLaunchOutcome>;
  /** Reconciles pending admission state and proves the exact registry/network baseline without launching a session. */
  recoverPending(agent: SessionAdmissionProbeAgent): Promise<void>;
}>;

/**
 * Fired once a launched session holds authority and is running, before the
 * attached process is awaited. Generic and additive: the driver knows nothing
 * of what a caller does with it. `runfree mcp auth` uses it to stand up the
 * per-session OAuth callback against the session's now-known IP; other launches
 * pass nothing. It must not throw — a caller's side effect failing may not cost
 * the session its authority — so a hook owns its own error handling.
 */
export type SessionRunningHook = (session: Readonly<{ containerId: string; sourceIp: string }>) => Promise<void> | void;

export type InternalSessionAdmissionDriverInput = Readonly<{
  preparedRuntime: PreparedRuntime;
  /** The only lifecycle-lock authority accepted by a session driver. */
  sessionLockManager: SessionLockManager;
  io: RuntimeIO;
  foregroundSpawner?: SessionContainerForegroundSpawner;
  onSessionRunning?: SessionRunningHook;
  nowEpochMs?: () => number;
  nowMonotonicMs?: () => number;
}>;

type ResolvedInternalSessionAdmissionDriverInput = InternalSessionAdmissionDriverInput & Readonly<{
  /** Derived from the required manager; callers cannot supply a bare lock. */
  lifecycleLock: ProjectLifecycleLock;
  context: RuntimeContext;
  plan: ActiveRuntimePlan;
}>;

function dockerFailure(label: string, result: CaptureResult): Error {
  const detail = result.stderr.trim().slice(0, 512) || `exit ${result.status}`;
  return new Error(`${label}: ${detail}`);
}

function assertSuccessfulDocker(label: string, result: CaptureResult): CaptureResult {
  if (result.status !== 0) throw dockerFailure(label, result);
  return result;
}

function sameRecord(left: SessionContainerRecordV2, right: SessionContainerRecordV2): boolean {
  return serializeSessionContainerRecordV2(left) === serializeSessionContainerRecordV2(right);
}

class InternalBuiltinAdmissionProbeSteps implements SessionAdmissionProbeSteps {
  readonly agent: SessionAdmissionSessionKind;
  readonly #input: ResolvedInternalSessionAdmissionDriverInput;
  readonly #gateway: SessionAdmissionDockerGateway;
  readonly #nowEpochMs: () => number;
  readonly #nowMonotonicMs: () => number;
  #preflight?: SessionAdmissionDriverPreflight;
  #participantNetwork?: SessionContainerNetworkIdentity;
  #ingressParticipants: readonly ExactIngressInternalParticipant[] = [];
  #baseline?: ExactInternalNetworkParticipantBaseline;
  #record?: SessionContainerRecordV2;
  #persistedRecord?: SessionContainerRecordV2;
  #plan?: SessionContainerCreatePlan;
  #creationReceipt?: SessionContainerCreationReceipt;
  #foreground?: SessionContainerForegroundHandle;
  #provisioningAuthorization?: SessionContainerProvisioningRunningAuthorization;
  /**
   * The admit-time running identity of the exact container incarnation, a
   * projection of the single running proof. Every session-file write (this
   * admission's, and every later beat's) is sealed to re-proving it.
   */
  #fileAnchor?: SessionFileAnchor;
  /**
   * The durable lifecycle record every beat re-proves.
   *
   * Set to the provisioning-running record admission beats against, then to
   * the `attached` record that admission produced.
   */
  #fileRecord?: SessionContainerRecordV2;
  /**
   * The last session file this host actually published.
   *
   * The only evidence a failing beat has: a `retrying` stamp reports the
   * window this file granted, because that is the window the proxy is still
   * serving it under.
   */
  #fileWritten?: SessionFileV1;
  /**
   * Whether this session may already be published to the proxy.
   *
   * Set the moment the admitting beat enters `inspectAndWriteSessionFile`,
   * because from there on this host cannot prove no file was written. It is
   * the launch ladder's routing answer under this source: before it, a failure
   * has nothing to revoke and belongs to unadmitted cleanup; after it, the
   * file-first teardown must run.
   */
  #fileMayExist = false;
  /** Set once the ordered file-first teardown has completed for this session. */
  #fileTornDown = false;
  /** So an unwritable stamp path is reported once, not once per beat. */
  #stampFailureWarned = false;
  /**
   * When this session spent each of its recent re-attaches, monotonic, oldest
   * first. Entries outside the window are dropped as they are read, so the
   * limit is a rolling rate rather than a session total.
   */
  #reattaches: number[] = [];
  #preAttachCompletion?: SessionAdmissionLaunchOutcome;
  #foregroundOutcome?: SessionAdmissionLaunchOutcome;
  /**
   * Set only by control-plane rebind adoption. The launch-time preflight
   * selection stays immutable; when a compatible proxy rebind replaces the
   * control plane under this live session, the driver adopts the durable
   * candidate here and every later coordinator call derives from it.
   */
  #adoptedControlPlane?: ControlPlaneEffectiveSelectionV2;
  /**
   * Every address a proxy session file named when preflight reconciled.
   *
   * Passed to the allocator as additional reserved addresses, so an address
   * some file still claims cannot be handed to this session even if the sweep
   * failed to delete that file. That is what turns "the delete probably landed
   * in time" into an ordering property.
   */
  #reservedSessionFileIps: readonly string[] = [];
  /** Present only in launch mode; probes must never leave user-facing session evidence. */
  #launch?: SessionAdmissionLaunchOptions;
  #displayIdentity?: Readonly<{ displayName: string; command: string; agentCommand: string }>;
  #sessionEvidence?: SessionMetadata;

  constructor(
    input: ResolvedInternalSessionAdmissionDriverInput,
    gateway: SessionAdmissionDockerGateway,
    agent: SessionAdmissionSessionKind,
    launch?: SessionAdmissionLaunchOptions,
  ) {
    this.#input = input;
    this.#gateway = gateway;
    this.agent = agent;
    this.#launch = launch;
    this.#nowEpochMs = input.nowEpochMs ?? Date.now;
    this.#nowMonotonicMs = input.nowMonotonicMs ?? (() => performance.now());
  }

  nowMs = (): number => this.#nowMonotonicMs();
  dockerOperationCount = (): number => this.#gateway.dockerOperationCount();

  // Locking invariant: every step asserts the lifecycle lock at entry (and
  // per-iteration around direct registry writes). Coordinator interiors are
  // fenced independently — `assertAuthority` runs on both sides of every
  // Docker effect via the publisher's convergence options — so step-exit
  // re-locks added no coverage and are deliberately absent.
  #lock(): void {
    this.#input.lifecycleLock.assertHeld();
  }

  #dockerOptions(maxBuffer = INTERNAL_DOCKER_CAPTURE_MAX_BYTES) {
    return {
      env: this.#input.plan.execution.dockerClientEnv,
      shell: false as const,
      maxBuffer,
    };
  }

  #captureCommand(command: SessionDockerCommand): CaptureResult {
    return executeSessionDockerCommand(command, (executable, args) => this.#gateway.io.capture(
      executable,
      [...args],
      this.#dockerOptions(),
    ));
  }

  #network(): SessionContainerNetworkIdentity {
    return this.#require(this.#participantNetwork, "canonical participant network");
  }

  #projectIdentity() { return this.#require(this.#preflight, "canonical preflight").expectedProject; }

  /** The control plane this driver currently holds authority under. */
  #controlPlane(): ControlPlaneEffectiveSelectionV2 {
    return this.#adoptedControlPlane
      ?? this.#require(this.#preflight, "canonical preflight").effectiveControlPlane;
  }

  /**
   * The session file's display fields.
   *
   * The same fields the generation snapshot publishes from the record, plus
   * the session kind's descriptive invocation, which the host already knows
   * and writes into its own session evidence. Bounded by the agent descriptor
   * rather than by anything the project can set, so it cannot make a session
   * unpublishable.
   */
  #fileDisplay(record: SessionContainerRecordV2): SessionFileDisplay {
    const identity = this.#displayIdentity;
    return {
      name: record.displayName,
      command: record.command,
      ...(identity ? { agentCommand: identity.agentCommand } : {}),
      startedAt: record.createdAt,
    };
  }

  /**
   * The record's own admission bindings.
   *
   * The heartbeat refuses bindings that differ from the record's, so these are
   * a copy rather than a decision: passing them separately is what lets the
   * caller that owns the eligibility file prove the two came from one
   * admission, not a licence to name another agent or epoch.
   */
  #fileEligibilityBindings(record: SessionContainerRecordV2): SessionFileEligibilityBindings {
    return {
      selectedAgentImageId: record.selectedAgentImageId,
      sessionAgentGenerationDigest: record.sessionAgentGenerationDigest,
      controlPlaneGenerationDigest: record.controlPlaneGenerationDigest,
      admissionContractEpoch: record.admissionContractEpoch,
    };
  }

  /**
   * What one beat inspects and, if it proves out, writes.
   *
   * Admission and every later heartbeat build the beat from here, so the two
   * can never describe the session differently. Every field is derived at call
   * time: the proxy and network from the control plane this driver currently
   * holds authority under (which a rebind adoption may have replaced), the
   * identity and eligibility bindings from the durable record, and the anchor
   * from the admit-time running proof each beat re-proves.
   */
  #fileInputs(): InspectAndWriteSessionFileInput {
    const controlPlane = this.#controlPlane();
    const record = this.#require(this.#fileRecord, "session file lifecycle record");
    return {
      io: this.#gateway.io,
      proxyId: controlPlane.proxyContainerId,
      record,
      anchor: this.#require(this.#fileAnchor, "session file anchor"),
      expectedProject: this.#projectIdentity(),
      networkId: controlPlane.networkIds.agentInternal,
      display: this.#fileDisplay(record),
      eligibilityBindings: this.#fileEligibilityBindings(record),
      leaseMs: internalProbeLeaseDurationMs(),
      nowEpochMs: this.#nowEpochMs,
      dockerOptions: this.#dockerOptions(),
    };
  }

  /**
   * One sealed beat: inspect this exact container incarnation and, only if it
   * still matches the admit-time anchor, write this session's file.
   *
   * The driver's only route to the session-file channel. Invariant 10 keeps
   * the write itself inside `inspectAndWriteSessionFile`, so nothing here
   * builds a session-file command.
   */
  async #beatSessionFile(): Promise<HeartbeatOutcome> {
    // From here this host can no longer prove that no file exists: the exec may
    // have replaced the file and failed to report it. Teardown is routed on
    // that, not on the outcome.
    this.#fileMayExist = true;
    return await inspectAndWriteSessionFile(this.#fileInputs());
  }

  /**
   * Spends one of this session's re-attaches, if the window has room.
   *
   * Answers false at the limit without consuming anything, so a capped session
   * simply keeps beating and asks again on the next one.
   */
  #takeReattach(): boolean {
    const now = this.#nowMonotonicMs();
    const recent = this.#reattaches.filter((at) => now - at < SESSION_REATTACH_WINDOW_MS);
    this.#reattaches = recent;
    if (recent.length >= SESSION_REATTACH_MAX_PER_WINDOW) return false;
    recent.push(now);
    return true;
  }

  /**
   * Asks the container itself what the end of the foreground stream meant.
   *
   * The whole point of the confirmation: a `docker start
   * --attach` child can die on its own while the agent it was showing keeps
   * running as PID 1 of a container this host can still inspect. So nothing is
   * concluded from the stream ending — one pinned inspection is spent, and only
   * what it proves decides. Never throws: a failed observation is a `wait`, the
   * same way the heartbeat treats one, because "this host could not look" is
   * never grounds for ending a session.
   *
   * The order matters. A proved exit is checked before the running proof
   * because it is the answer that carries the status the launch must report; a
   * running proof re-uses the anchor every beat re-proves, so "still running"
   * means this exact incarnation and never a container that was recreated under
   * the pinned id.
   */
  #classifyLostForegroundStream(): LostForegroundStreamDecision {
    const record = this.#fileRecord;
    const anchor = this.#fileAnchor;
    const containerId = record?.containerId;
    if (!record || !anchor || containerId === undefined) {
      return { kind: "teardown", observation: "this session holds no inspectable container identity" };
    }
    let capture: CaptureResult;
    try {
      capture = this.#captureCommand(sessionContainerInspectCommand(record, this.#projectIdentity()));
    } catch (error) {
      return { kind: "wait", observation: error instanceof Error ? error.message : String(error) };
    }
    if (capture.status !== 0) {
      return { kind: "wait", observation: capture.stderr.trim() || capture.stdout.trim() || `exit ${capture.status}` };
    }
    const status = sessionContainerObservedExitStatus(capture.stdout, containerId);
    if (status !== undefined) return { kind: "exited", status };
    try {
      assertSessionContainerNarrowRunningInspect(capture.stdout, {
        containerId,
        composeProject: record.composeProject,
        networkId: this.#controlPlane().networkIds.agentInternal,
        sourceIp: record.sourceIp,
        ...anchor,
      });
    } catch (error) {
      return { kind: "teardown", observation: error instanceof Error ? error.message : String(error) };
    }
    return this.#takeReattach()
      ? { kind: "reattach" }
      : { kind: "wait", observation: "this session has re-attached as often as it may in a minute" };
  }

  /**
   * Replaces the lost stream with a new one over the same sealed authority.
   *
   * The attach command is built from the record every beat re-proves, so it can
   * only ever name the container this session was admitted for. The driver's
   * own handle moves with it, so everything downstream — teardown's cancel
   * above all — acts on the stream this session actually holds rather than on
   * the dead child it replaced.
   */
  async #reattachForeground(
    current: SessionContainerForegroundHandle,
  ): Promise<SessionContainerForegroundHandle> {
    const record = this.#require(this.#fileRecord, "session file lifecycle record");
    const reattached = await reattachSessionContainerForeground(
      current,
      sessionContainerAttachCommand(record, this.#projectIdentity()),
      {
        dockerClientEnv: this.#input.plan.execution.dockerClientEnv,
        spawn: this.#gateway.foregroundSpawner,
      },
    );
    this.#foreground = reattached;
    return reattached;
  }

  /** This launch's answer for a foreground completion that ended the session. */
  #reportForegroundCompletion(
    completion: SessionContainerForegroundCompletion,
  ): SessionAdmissionLaunchOutcome {
    if (completion.kind === "error") throw completion.error;
    this.#foregroundOutcome = Object.freeze({ status: completion.code, signal: completion.signal });
    return this.#foregroundOutcome;
  }

  /**
   * Records that this host is still beating for this session, and until when.
   *
   * Advisory backstop only: the durable record freezes its lease at admission
   * under this source, so without the stamp every host-side liveness consumer
   * would read a live session as stale once the admission lease elapsed.
   *
   * Always stamped from a file this host actually wrote. A `retrying` stamp
   * therefore reports the window the last written file granted rather than a
   * fresh one: the proxy serves that file until it expires, and refreshing the
   * window while beats are failing would be this host inventing evidence it
   * does not have.
   *
   * Advisory means advisory at every call site, so this never throws. A stamp
   * path this host cannot write (a symlinked or unwritable state directory) is
   * exactly the deviation `readSessionHostStatus` already reads as absent, and
   * it is evidence about the host's own state directory, never about the
   * session: it must neither fail a launch whose file is already written nor
   * count as a heartbeat failure and drive the beat onto the backoff. Reported
   * once per session, because the condition is not transient.
   */
  #stampSessionHostStatus(
    file: Readonly<{ sessionId: string; inspectedAt: string; aliveUntil: string }>,
    served: SessionHostStatusServed,
    terminal?: "revoking",
  ): void {
    try {
      writeSessionHostStatus(this.#input.plan.paths.stateDir, {
        v: 1,
        sessionId: file.sessionId,
        lastHeartbeatAt: file.inspectedAt,
        aliveUntil: file.aliveUntil,
        served,
        ...(terminal === undefined ? {} : { terminal }),
      });
    } catch (error) {
      if (this.#stampFailureWarned) return;
      this.#stampFailureWarned = true;
      warn(`session status stamp unwritable: ${error instanceof Error ? error.message : String(error)}; the session is unaffected; the last stamp may be stale and owner liveness remains authoritative`);
    }
  }

  /**
   * Marks this session's stamp terminal: teardown has begun.
   *
   * The durable record is not transitioned on the way out — it stays exactly
   * what it was until it is deleted — so this stamp is
   * the only thing that distinguishes a record mid-teardown from a session to
   * admit beside. Preflight reads it, and refuses.
   *
   * The window it reports is closed at once (`aliveUntil` is now, not the
   * window the last file granted), because the very next step takes that file
   * away. Written through the advisory stamp writer, so a state directory this
   * host cannot write cannot stop a teardown.
   */
  #stampSessionTerminal(record: SessionContainerRecordV2): void {
    const now = new Date(this.#nowEpochMs()).toISOString();
    this.#stampSessionHostStatus(
      { sessionId: record.sessionId, inspectedAt: now, aliveUntil: now },
      "unknown",
      "revoking",
    );
  }

  /**
   * Ends this session file first and record last.
   *
   * The whole ordered sequence runs here, in the first teardown step, rather
   * than one step at a time down the launch ladder: the ladder accumulates
   * failures and keeps going, so a sequence split across its steps could stop
   * the container and drop the record after a delete that never happened. One
   * call under one lock makes the order a property of the code.
   *
   * A blocked delete is reported, not swallowed: the launch reports it, this
   * owner exits, and the next launch's reconcile runs the same sequence for a
   * record whose owner is now gone.
   */
  #tearDownSessionFileSession = async (): Promise<void> => {
    // A completed sequence has nothing left to do. The ladder cleans up twice
    // when the first pass reports anything, and a session whose file,
    // container, and record are already gone must not spend a second round of
    // Docker effects proving it.
    if (this.#fileTornDown) return;
    const record = this.#require(this.#fileRecord ?? this.#record, "session lifecycle record");
    const stateDir = this.#input.plan.paths.stateDir;
    const expectedProject = this.#projectIdentity();
    const failures: unknown[] = [];
    let blockedOnDelete = false;
    try {
      const result: SessionFileTeardownResult = teardownSessionRecord({
        io: this.#gateway.io,
        proxyId: this.#controlPlane().proxyContainerId,
        record,
        expectedProject,
        networkId: this.#controlPlane().networkIds.agentInternal,
        lock: () => this.#lock(),
        markTerminal: () => this.#stampSessionTerminal(record),
        clearStamp: () => removeSessionHostStatus(stateDir, record.sessionId),
        removeRecord: () => removeExactSessionContainerRecordV2(stateDir, expectedProject, record),
        dockerOptions: this.#dockerOptions(),
      });
      if (result.completed) {
        this.#fileTornDown = true;
        this.#persistedRecord = undefined;
      } else {
        blockedOnDelete = true;
        failures.push(result.error);
      }
    } catch (error) {
      failures.push(error);
    }
    // The file is only gone when the delete proved it. Anything else means this
    // host may still have one published, which is what a `retrying` stamp would
    // otherwise be reporting a window for.
    if (!blockedOnDelete) this.#fileWritten = undefined;
    // The stream is released with the session it was showing, whatever the
    // sequence above managed: nothing downstream will attach to it again.
    if (this.#foreground) {
      try {
        cancelSessionContainerForegroundAttach(this.#foreground);
        this.#foreground = undefined;
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1) {
      throw new AggregateError(failures, "session file teardown and foreground detach did not complete");
    }
  };

  /**
   * Advances the durable record and everything bound to it, together.
   *
   * The create plan carries a copy of the record, and later authorization,
   * revocation, and cleanup all match against the plan's copy. So a step that
   * advances the record without rebinding the plan leaves teardown comparing
   * against stale fields and failing to match the registry.
   *
   * Written as one operation because that is exactly how it went wrong: lease
   * renewal updated the record and its persisted twin but not the plan, so the
   * first renewal of a long-running session silently broke its own revocation.
   * Three assignments that must happen together should not be three statements
   * a future step can partially copy.
   */
  #advanceDurableRecord(record: SessionContainerRecordV2, label: string): void {
    this.#record = record;
    this.#persistedRecord = record;
    this.#plan = bindSessionContainerCreatePlanRecord(this.#require(this.#plan, label), record);
  }

  /**
   * Adopts a completed compatible control-plane rebind before this session's
   * next authority-bearing operation, or refuses it.
   *
   * The rebind coordinator replaces the proxy and rebinds this session's
   * durable record while the container keeps running, but it cannot reach into
   * this live process — the held control plane, attached record, and create
   * plan all still name the removed proxy. Called under the lifecycle lock at
   * every point where another process could have rebound the runtime while the
   * attached wait held no lock: the renewal critical section and teardown
   * entry. A no-op while the durable selection is unchanged, and a refusal —
   * before any durable write — for every divergence that is not an exact
   * completed compatible rebind of this exact session.
   *
   * On adoption the held authority advances as one unit, mirroring
   * #advanceDurableRecord: the record, its persisted twin, and the plan —
   * rebuilt from durable artifacts against the candidate control plane by the
   * same canonical builder the rebind coordinator itself uses — plus the
   * adopted selection every later #common() derives from. The liveness anchor
   * survives: it proves container, process, and endpoint identity, which a
   * compatible rebind must not touch.
   */
  #adoptCompatibleControlPlaneRebind(): void {
    this.#lock();
    // The record this session actually holds: the record every heartbeat
    // re-proves.
    const held = this.#fileRecord;
    if (!held) return;
    const preflight = this.#require(this.#preflight, "canonical preflight");
    const adoption = adoptCompatibleSessionControlPlaneRebind({
      stateDir: this.#input.plan.paths.stateDir,
      lifecycleLock: this.#input.lifecycleLock,
      expectedProject: preflight.expectedProject,
      boundControlPlane: this.#controlPlane(),
      launchControlPlaneGeneration: preflight.generationTarget.controlPlane,
      attachedRecord: held,
    });
    if (!adoption) return;
    const plan = createRetainedSessionRebindProofPlan({
      stateDir: this.#input.plan.paths.stateDir,
      expectedProject: preflight.expectedProject,
      replacementRecord: adoption.record,
      candidateControlPlane: adoption.effectiveControlPlane,
      candidateMaterialization: adoption.candidateMaterialization,
      docker: createRuntimeDocker(this.#input.context, this.#gateway.io),
      lifecycleLock: this.#input.lifecycleLock,
      runfreeVersion: this.#input.plan.runfreeVersion,
    });
    // The foreground attach handle's sealed record snapshot pins the control
    // digest too; advance it through the same shared rebind-shape assert so
    // later liveness proofs keep matching the adopted record. Everything above
    // is read-only, so a refusal anywhere leaves the held authority coherent.
    adoptSessionContainerForegroundControlPlaneRebind(
      this.#require(this.#foreground, "foreground attach handle"),
      preflight.expectedProject,
      held,
      adoption.record,
    );
    this.#lock();
    this.#adoptedControlPlane = adoption.effectiveControlPlane;
    // Every later beat re-proves the rebound record and derives its proxy and
    // network from the adopted selection through `#controlPlane()`.
    this.#fileRecord = adoption.record;
    this.#record = adoption.record;
    this.#persistedRecord = adoption.record;
    this.#plan = plan;
  }

  /**
   * Takes on a completed compatible rebind, if one happened, before the next
   * beat writes anything.
   *
   * The heartbeat holds no lock, so the durable selection can be replaced
   * under it at any moment; the file it would then write would name a proxy
   * container that no longer exists. The comparison itself is an unlocked read
   * of two fields — the only two a compatible rebind may move — so the common
   * case (nothing changed) costs no lifecycle lock at all and serializes
   * against nothing. Only a genuine change takes the lock, once, for the
   * adoption's own read-and-swap.
   *
   * Nothing is caught here: the caller classifies. An incompatible replacement
   * means this session no longer holds the control plane it was admitted under
   * — a fact about its authority — while a pending rebind, a contended lock,
   * and an unschedulable renewal are all conditions the session outlives.
   */
  async #adoptDurableSelectionIfChanged(signal: AbortSignal): Promise<void> {
    const held = this.#controlPlane();
    const durable = readEffectiveControlPlaneV2(this.#input.plan.paths.stateDir);
    if (!durable
      || durable.selection.proxyContainerId === held.proxyContainerId
        && durable.selection.controlPlaneGenerationDigest === held.controlPlaneGenerationDigest) {
      return;
    }
    await this.#input.sessionLockManager.withLock(async () => {
      this.#adoptCompatibleControlPlaneRebind();
    }, signal);
  }

  #require<T>(value: T | undefined, label: string): T {
    if (value === undefined) throw new Error(`session admission driver has no ${label}`);
    return value;
  }

  #runCleanupCommand(label: string, command: ReturnType<typeof creationAuthorizedSessionContainerStopCommand>): void {
    const result = executeSessionContainerCleanupCommand(
      command,
      (executable, args, options) => this.#gateway.io.capture(executable, [...args], options),
      this.#dockerOptions(),
    );
    if (result.status !== 0) throw dockerFailure(label, result);
  }

  #cleanExactOrphan(classification: Extract<SessionReconciliationClassification, { kind: "container-only" }>): void {
    const preflight = this.#require(this.#preflight, "canonical preflight");
    const authority = authorizeSessionContainerOrphanCleanup(
      classification,
      preflight.expectedProject,
      this.#network(),
      this.#input.plan.paths.stateDir,
      this.#input.lifecycleLock,
    );
    const failures: unknown[] = [];
    if (classification.container.running) {
      try {
        this.#runCleanupCommand(
          "Docker failed to stop an exact orphan session container",
          orphanSessionContainerStopCommand(authority),
        );
      } catch (error) {
        failures.push(error);
      }
    }
    try {
      this.#runCleanupCommand(
        "Docker failed to remove an exact orphan session container",
        orphanSessionContainerRemoveCommand(authority),
      );
    } catch (error) {
      failures.push(error);
    }
    try {
      proveSessionContainerOrphanAbsent(
        (executable, args, options) => this.#gateway.io.capture(executable, [...args], options),
        authority,
        this.#dockerOptions(),
      );
    } catch (error) {
      failures.push(error);
    }
    if (failures.length > 0) {
      throw new AggregateError(failures, "exact orphan session-container cleanup did not complete");
    }
  }

  #inventoryClassifications(records: readonly SessionContainerRecordV2[]) {
    const preflight = this.#require(this.#preflight, "canonical preflight");
    const containers = inspectSessionContainerInventory(
      (executable, args, options) => this.#gateway.io.capture(executable, [...args], options),
      preflight.expectedProject,
      this.#dockerOptions(),
    );
    return classifySessionContainerReconciliation({
      expectedProject: preflight.expectedProject,
      records,
      containers,
    }).filter((classification) => {
      if (classification.kind !== "untrusted-container") return true;
      const container = classification.container;
      // Only utilities whose full shape was inspected under this same lock
      // are exempt from session orphan handling. Record conflicts still refuse.
      return !this.#ingressParticipants.some((participant) => (
        participant.containerId === container.containerId
        && participant.containerName === container.containerName
        && participant.imageId === container.imageId
        && participant.sourceIp === container.sourceIp
        && container.internalNetworkId === this.#network().networkId
        && container.running && !container.malformedInventoryMetadata
      ));
    });
  }

  #cleanPreexistingOrphans(): void {
    const preflight = this.#require(this.#preflight, "canonical preflight");
    let records = listSessionContainerRecordsV2(
      this.#input.plan.paths.stateDir,
      preflight.expectedProject,
    );
    let classifications = this.#inventoryClassifications(records);
    this.#assertNoUncertainClassifications(classifications);
    const unboundCreated = classifications.filter((classification): classification is Extract<
      SessionReconciliationClassification,
      { kind: "unbound-created" }
    > => classification.kind === "unbound-created");
    for (const classification of unboundCreated) {
      const authority = authorizeUnboundCreatedSessionRecordRecovery(
        classification,
        preflight.expectedProject,
      );
      if (!recoverUnboundCreatedSessionRecordV2(
        this.#input.plan.paths.stateDir,
        preflight.expectedProject,
        authority,
      )) {
        throw new Error("unbound created session-container record was not removed before orphan recovery");
      }
    }
    if (unboundCreated.length > 0) {
      records = listSessionContainerRecordsV2(
        this.#input.plan.paths.stateDir,
        preflight.expectedProject,
      );
      classifications = this.#inventoryClassifications(records);
      this.#assertNoUncertainClassifications(classifications);
      if (classifications.some((classification) => classification.kind === "unbound-created")) {
        throw new Error("unbound created session-container remained after record-first recovery");
      }
    }
    for (const classification of classifications) {
      if (classification.kind === "container-only") this.#cleanExactOrphan(classification);
    }
    if (classifications.some((classification) => classification.kind === "container-only")) {
      records = listSessionContainerRecordsV2(
        this.#input.plan.paths.stateDir,
        preflight.expectedProject,
      );
      const remaining = this.#inventoryClassifications(records);
      if (remaining.some((classification) => (
        classification.kind === "container-only"
        || classification.kind === "unbound-created"
        || classification.kind === "mismatch"
        || classification.kind === "untrusted-container"
      ))) {
        throw new Error("session-container reconciliation remained uncertain after exact orphan cleanup");
      }
    }
  }

  /**
   * Refuses admission while quarantined unreadable records exist.
   *
   * Quarantine restores legibility, not availability: the container a
   * quarantined record named is now claimed by no readable record, so the
   * orphan cleanup that follows would otherwise remove it automatically even
   * though it may still be someone's live session. Refusing here, after the
   * drains have reclaimed every readable stale record, keeps that container
   * untouched and names the remedy instead of surfacing an unexplained
   * baseline refusal later.
   */
  #assertNoQuarantinedSessionRecords(): void {
    const names = listQuarantinedSessionContainerRecordNamesV2(this.#input.plan.paths.stateDir);
    if (names.length === 0) return;
    throw new CliError(
      `session admission refuses ${names.length} quarantined unreadable lifecycle record(s): ${names.join(", ")}; `
      + `run \`${remedy.destroyForce()}\` to clear the residue (this destroys the whole project runtime and ends all of its sessions)`,
    );
  }

  #assertNoUncertainClassifications(classifications: readonly SessionReconciliationClassification[]): void {
    const uncertain = classifications.find((classification) => (
      classification.kind === "mismatch" || classification.kind === "untrusted-container"
    ));
    if (uncertain && (uncertain.kind === "mismatch" || uncertain.kind === "untrusted-container")) {
      throw new Error(`session-container reconciliation refused ${uncertain.kind}: ${uncertain.reason}`);
    }
  }

  preflight = async (): Promise<void> => {
    this.#lock();
    const docker = createRuntimeDocker(this.#input.context, this.#gateway.io);
    let launch: SessionAdmissionPreflightLaunch;
    if (this.agent === "shell") {
      // The shell kind is launch-only and never resumes: resume argv is
      // descriptor-owned agent authority, and silently ignoring a resume
      // request here would be the silent-discard failure mode this CLI has
      // already had to sweep for once.
      if (!this.#launch) throw new Error("a shell session is launch-only; it has no probe mode");
      if (this.#launch.resume) throw new Error("a shell session cannot resume a conversation");
      launch = { kind: "shell" };
    } else {
      const descriptor = builtinAgent(this.agent);
      if (!descriptor || descriptor.id !== this.agent) {
        throw new Error(`unknown built-in admission probe agent: ${this.agent}`);
      }
      // Launch mode threads the project's real configured command, so a
      // customized command is refused here — before allocation, container
      // creation, or any other Docker effect — instead of being silently
      // replaced by the builtin default. `resolveAgentCommand` already
      // normalizes recorded legacy defaults to the current one, so pre-inbox
      // projects launch unchanged. Probe mode stays on the descriptor default:
      // probes are admission dress rehearsals, not project launches, and must
      // not fail because a project customized its command.
      const configuredCommand = this.#launch
        ? (resolveAgentCommand(this.#input.context.project.config, descriptor.id) ?? descriptor.defaultCommand)
        : descriptor.defaultCommand;
      launch = {
        kind: "builtin",
        agentId: descriptor.id,
        configuredCommand,
        ...(this.#launch?.resume ? { resume: this.#launch.resume } : {}),
      };
    }
    this.#preflight = createSessionAdmissionDriverPreflight({
      runtime: this.#input.plan,
      lifecycleLock: this.#input.lifecycleLock,
      docker,
      launch,
    });
    // Nothing below may run beside a journaled control-plane rebind. The
    // recovery region tears dead owners' records down and republishes
    // eligibility, and a rebind (or its crashed recovery) owns exactly that
    // state: reconciling around the journal would remove records the rebind
    // still has to move, and `revalidateSessions` would then fail its own
    // recovery. Checked here, under the lock taken at the top of this preflight
    // and before the first effect, so the refusal costs nothing and names both
    // of its reclamations: `runfree up` resumes the journaled rebind, and
    // `runfree destroy --force` clears one that is stuck.
    assertNoPendingControlPlaneReplacement(this.#input.plan.paths.stateDir, this.#projectIdentity());
    // The durable materialization the running proxy was started from. Read
    // here — before allocation, container creation, and every other Docker
    // effect. The preflight above already proved the durable effective
    // selection exists and belongs to this project; its absence now would mean
    // the state vanished under the held lifecycle lock.
    const effective = readEffectiveControlPlaneV2(this.#input.plan.paths.stateDir);
    if (!effective) throw new Error("session admission requires a durable effective control plane");
    const authority = createControlPlaneInternalParticipantAuthority({
      plan: this.#input.plan,
      context: this.#input.context,
      lifecycleLock: this.#input.lifecycleLock,
      io: this.#gateway.io,
    });
    this.#ingressParticipants = authority.ingressParticipants;
    this.#participantNetwork = Object.freeze({
      networkId: authority.networkId,
      networkName: authority.networkName,
      subnet: authority.subnet,
    });
    // The whole recovery region, in one pass: reconcile ends the records whose
    // owners are gone through the shared ordered teardown, sweeps the files and
    // containers that answer to nobody, and republishes eligibility from what
    // survived — all before the allocation below, inside this same held lock.
    const reconciled = await reconcileSessions({
      stateDir: this.#input.plan.paths.stateDir,
      expectedProject: this.#projectIdentity(),
      io: this.#gateway.io,
      proxyId: this.#controlPlane().proxyContainerId,
      network: this.#network(),
      env: this.#input.context.env,
      lifecycleLock: this.#input.lifecycleLock,
      mode: "repair",
      dockerOptions: this.#dockerOptions(),
    });
    this.#reservedSessionFileIps = reconciled.reservedSourceIps;
    this.#lock();
    this.#assertNoQuarantinedSessionRecords();
    this.#cleanPreexistingOrphans();
    const records = listSessionContainerRecordsV2(
      this.#input.plan.paths.stateDir,
      this.#require(this.#preflight, "canonical preflight").expectedProject,
    );
    // A non-empty registry is not an error. Concurrent sessions are the point
    // of per-session admission, and the baseline below already models live
    // records: it binds each to its network attachment, refuses an unknown
    // participant, and reserves its address against the one allocated next.
    //
    // What must not survive is residue, in either of its two forms.
    //
    // Anything still stale was marked revoking above and should have drained,
    // so its presence means the reclaim did not do what it claimed. And a
    // record already in `revoking` is not a session at all whatever its owner
    // is doing — that state is terminal cleanup, and ownership says nothing
    // about it: a live owner there is a process mid-teardown, not a session to
    // admit beside. Both are checked by what they are rather than by who owns
    // them, because admitting against half-revoked registry and consumer state
    // is exactly what fails closed here.
    //
    // There is a third form of the same thing. Teardown leaves the record
    // untransitioned until the file is gone, so `revoking` is not the state a
    // half-finished teardown is in — a terminal host status stamp
    // is the marker instead, and it says exactly what the `revoking` state
    // says: this record is cleanup, and admitting beside it is admitting
    // beside half-removed authority. It is checked by what it is, not by who
    // owns it, for the same reason.
    const unreclaimed = records.filter((record) => record.state === "revoking"
      || readSessionHostStatus(this.#input.plan.paths.stateDir, record.sessionId)?.terminal === "revoking"
      || sessionRecordOwnerLiveness(record, this.#input.context.env) === "dead");
    if (unreclaimed.length > 0) {
      throw new Error(
        `internal session admission found ${unreclaimed.length} lifecycle record(s) that reconciliation did not clear; `
        + `run \`${remedy.sessions()}\` to inspect them, or \`${remedy.destroyForce()}\` to clear residue whose owner cannot be proved`,
      );
    }
    const networkResult = assertSuccessfulDocker(
      "Docker failed to inspect the exact internal network",
      this.#captureCommand(sessionNetworkInspectCommand(authority.networkId)),
    );
    this.#baseline = validateExactInternalNetworkParticipantBaseline({
      participantAuthority: authority,
      networkInspectJson: networkResult.stdout,
      records,
    });
  };

  /**
   * The record's user-facing identity for this session kind.
   *
   * `command` is the short registry/display kind shared with proxy session
   * metadata. The descriptive invocation stays in `agentCommand`; exact launch
   * authority is bound separately by the typed launch target.
   */
  #sessionDisplayIdentity(): Readonly<{ displayName: string; command: string; agentCommand: string }> {
    if (this.agent === "shell") {
      return Object.freeze({ displayName: "Shell session", command: "shell", agentCommand: "zsh -il" });
    }
    const descriptor = this.#require(builtinAgent(this.agent), "built-in agent descriptor");
    return Object.freeze({
      displayName: this.#launch?.resume ? `${descriptor.label} resume` : `${descriptor.label} admission probe`,
      command: descriptor.id,
      agentCommand: descriptor.defaultCommand,
    });
  }

  /**
   * The reconciled session-file addresses the allocator may be told about.
   *
   * Only addresses inside the session pool's own /24 are passed on. One outside
   * it is not evidence about this pool — the allocator can never return it —
   * and the allocator refuses a reserved address outside its subnet outright,
   * so passing a file left behind by an earlier network would turn a stale file
   * into a permanent refusal instead of reserving anything.
   */
  #reservedSessionPoolAddresses(): readonly string[] {
    if (this.#reservedSessionFileIps.length === 0) return [];
    const prefix = this.#network().subnet.split("/")[0]?.split(".").slice(0, 3).join(".");
    if (prefix === undefined || prefix.length === 0) return [];
    return this.#reservedSessionFileIps.filter((address) => address.startsWith(`${prefix}.`));
  }

  allocate = async (): Promise<void> => {
    this.#lock();
    const preflight = this.#require(this.#preflight, "canonical preflight");
    const identity = this.#sessionDisplayIdentity();
    this.#displayIdentity = identity;
    const createdAtMs = this.#nowEpochMs();
    const record = createAllocatedSessionContainerRecordFromPreflight(preflight, {
      sessionId: createSessionId(this.#input.context, new Date(createdAtMs)),
      displayName: identity.displayName,
      command: identity.command,
      sourceIp: allocateSessionSourceIpFromExactInternalNetworkBaseline({
        baseline: this.#require(this.#baseline, "internal-network baseline"),
        reservedIps: this.#reservedSessionPoolAddresses(),
      }),
      hostPid: process.pid,
      hostBootId: hostBootId(this.#input.context.env),
      hostProcessStart: hostProcessStart(process.pid, this.#input.context.env),
      createdAt: new Date(createdAtMs).toISOString(),
    });
    writeSessionContainerRecordV2(this.#input.plan.paths.stateDir, preflight.expectedProject, record);
    this.#record = record;
    this.#persistedRecord = record;
    this.#plan = createSessionContainerCreatePlanFromPreflight(preflight, record);
  };

  /**
   * Creates the session container and spawns its foreground start, as one step.
   *
   * The durable record advances to provisioning-running — exact bound container
   * id plus a freshly minted lease — before the spawn, so the record never
   * claims less than the container might be: a crash at any point in this step
   * leaves one inert, exactly reclaimable pair. The lease is minted here, before
   * registration, because the request proxy refuses even a provisioning record
   * without valid lease authority. Docker refuses a duplicate static address at
   * start, and the single post-start inspection then holds the container to
   * exactly one internal network at exactly the allocated address, which
   * together replace the deleted pre-start network-target re-read.
   */
  createStarted = async (): Promise<void> => {
    this.#lock();
    const plan = this.#require(this.#plan, "allocated create plan");
    const request = sessionNamedVolumeInspectRequest(plan);
    const volumeInspect = this.#gateway.io.capture(request.executable, [...request.args], this.#dockerOptions());
    if (volumeInspect.status !== 0 && /no such volume/i.test(volumeInspect.stderr)) {
      // The named volumes come from the active generation's plan, and startup
      // creates them from the same plan. A volume missing here means the two
      // disagree, which no retry of this launch can settle. Name the command
      // that re-materializes the generation instead of leaving a raw Docker
      // dump as the only output.
      throw new CliError([
        dockerFailure("Docker failed to inspect exact session named volumes", volumeInspect).message,
        "the active runtime generation expects named volumes this project's current dependency-overlay plan does not create",
        `recreate it from the current plan with: ${remedy.rebuild()}`,
      ].join("\n"));
    }
    const volumeResult = assertSuccessfulDocker(
      "Docker failed to inspect exact session named volumes",
      volumeInspect,
    );
    const namedVolumeProof = validateSessionNamedVolumeInspect(volumeResult.stdout, plan);
    this.#lock();
    const assignment = executeSessionFileCommand(
      this.#gateway.io,
      sessionIpAssignmentReadCommand(this.#controlPlane().proxyContainerId, plan.record.sourceIp),
      this.#dockerOptions(),
    ).stdout.trim();
    this.#lock();
    executeSessionFileCommand(
      this.#gateway.io,
      sessionIpReuseFenceCommand(this.#controlPlane().proxyContainerId, plan.record.sourceIp, plan.record.sessionPrincipal, assignment),
      this.#dockerOptions(),
    );
    this.#lock();
    const creation = executeSessionContainerCreate(
      sessionContainerCreateCommand(plan, namedVolumeProof),
      plan,
      (executable, args, options) => this.#gateway.io.capture(executable, [...args], options),
      this.#dockerOptions(),
    );
    const boundCandidate = bindAllocatedSessionContainerIdV2(plan.record, creation.containerId);
    this.#creationReceipt = creation.receipt;
    this.#record = boundCandidate;
    const bound = bindExactAllocatedSessionContainerRecordIdV2(
      this.#input.plan.paths.stateDir,
      plan.expectedProject,
      plan.record,
      creation.containerId,
    );
    this.#record = bound;
    this.#persistedRecord = bound;
    const boundPlan = bindSessionContainerCreatePlanRecord(plan, bound);
    this.#plan = boundPlan;
    const provisioning = transitionBoundAllocatedSessionContainerToProvisioningRunningV2(
      bound,
      mintSessionContainerLeaseV2({
        durationMs: internalProbeLeaseDurationMs(),
        nowEpochMs: this.#nowEpochMs,
      }),
    );
    const provisioningPlan = bindSessionContainerCreatePlanRecord(boundPlan, provisioning);
    this.#lock();
    replaceExactSessionContainerRecordV2(
      this.#input.plan.paths.stateDir,
      plan.expectedProject,
      bound,
      provisioning,
    );
    this.#record = provisioning;
    this.#persistedRecord = provisioning;
    this.#plan = provisioningPlan;
    const command = sessionContainerStartAttachCommand(provisioningPlan.record, provisioningPlan.expectedProject);
    // Host session evidence is written before the foreground spawn, matching
    // the legacy attach path: a host client killed while the start is in
    // flight must still leave a durable crash manifest. Launch mode only —
    // probes revoke by design and must not surface as recoverable sessions.
    //
    // Resume launches write it too, on purpose. If the host dies during the
    // resumed session this file is that session's only crash manifest (for
    // codex the only evidence at all), so removing it would trade the
    // conversation's recoverability for deduplication — the inverse of the
    // recovery spec's stated priority. The duplicate it leaves beside the
    // still-retryable original shares the same exclusive per-agent claim, so
    // the two can never launch concurrently, and the lineage field below
    // keeps the survivor exact rather than a picker item.
    if (this.#launch) {
      const resumeConversationId = this.#launch.resume?.conversationId;
      const metadata = createSessionMetadata(
        this.#input.context,
        this.#gateway.io,
        this.agent,
        this.#require(this.#displayIdentity, "session display identity").agentCommand,
        {
          id: provisioningPlan.record.sessionId,
          sessionContainerName: provisioningPlan.record.containerName,
          ...(resumeConversationId !== undefined ? { resumeConversationId } : {}),
        },
      );
      writeSessionMetadata(this.#input.context, metadata);
      this.#sessionEvidence = metadata;
    }
    this.#foreground = await startSessionContainerForeground(
      command,
      provisioningPlan.record,
      provisioningPlan.expectedProject,
      {
        dockerClientEnv: this.#input.plan.execution.dockerClientEnv,
        spawn: this.#gateway.foregroundSpawner,
      },
    );
  };

  proveRunning = async (): Promise<void> => {
    this.#lock();
    const provisioningPlan = this.#require(this.#plan, "provisioning create plan");
    const runningProof = await waitForRunningSessionContainerProof(
      (executable, args, options) => this.#gateway.io.capture(executable, [...args], options),
      provisioningPlan,
      this.#require(this.#foreground, "foreground attach handle"),
      {
        timeoutMs: RUNNING_PROOF_TIMEOUT_MS,
        nowMs: this.#nowMonotonicMs,
        dockerOptions: this.#dockerOptions(),
      },
    );
    const durable = this.#require(this.#persistedRecord, "durable provisioning record");
    if (!sameRecord(durable, provisioningPlan.record)) {
      throw new Error("running proof lifecycle record differs from the durable provisioning record");
    }
    const previous = readSessionContainerRecordV2(
      this.#input.plan.paths.stateDir,
      provisioningPlan.expectedProject,
      durable.sessionId,
    );
    if (!previous || !sameRecord(previous, durable)) {
      throw new Error("running proof lifecycle registry changed before authorization");
    }
    // The session-file anchor is a projection of that one proof — the three
    // mutable running-identity fields every later beat re-proves — so holding
    // it costs no extra inspection and cannot describe a different moment.
    // Re-inspecting would prove a different moment than the single inspection
    // this ladder has.
    this.#fileAnchor = Object.freeze({
      dockerPid: runningProof.dockerPid,
      dockerStartedAt: runningProof.dockerStartedAt,
      networkEndpointId: runningProof.networkEndpointId,
    });
    this.#provisioningAuthorization = authorizeProvisioningRunningSessionContainer(
      provisioningPlan.record,
      provisioningPlan.expectedProject,
      this.#network().networkId,
      this.#require(this.#foreground, "foreground attach handle").receipt,
      runningProof,
    );
    if (!sameRecord(this.#provisioningAuthorization.record, durable)) {
      throw new Error("running proof authorization differs from the durable provisioning record");
    }
  };


  /**
   * Reports a foreground that ended before this session was ever admitted.
   *
   * Two answers: a spawn failure is this launch's error, and an exit is this
   * launch's outcome. No file was written and the durable record is still
   * provisioning-running either way, so nothing has to be revoked — the
   * ordinary teardown that follows removes the pair.
   */
  #reportForegroundEnded(ended: SessionContainerForegroundCompletion): void {
    if (ended.kind === "error") {
      throw new Error(
        `foreground Docker attach failed before session admission: ${ended.error.message}`,
        { cause: ended.error },
      );
    }
    this.#preAttachCompletion = Object.freeze({ status: ended.code, signal: ended.signal });
  }

  /**
   * Whether a mismatched inspection is really the agent's own exit.
   *
   * Docker can report the container stopped just before the foreground
   * `docker start --attach` child delivers its exit event, so a not-running
   * verdict alone cannot tell "the agent finished" from "this is a different
   * container". Exactly that one observation waits briefly on the foreground;
   * every other verdict is identity drift and is answered by whatever the
   * handle already knows, without waiting. Bounded so a genuine mismatch is
   * never delayed by more than `FOREGROUND_EXIT_BRIDGE_TIMEOUT_MS`.
   */
  async #foregroundEndedBefore(
    foreground: SessionContainerForegroundHandle,
    observation: string,
  ): Promise<SessionContainerForegroundCompletion | undefined> {
    const observed = currentSessionContainerForegroundCompletion(foreground);
    if (observed || observation !== SESSION_CONTAINER_NOT_EXACT_RUNNING_OBSERVATION) return observed;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        foreground.completion,
        new Promise<undefined>((resolve) => {
          timer = setTimeout(() => resolve(undefined), FOREGROUND_EXIT_BRIDGE_TIMEOUT_MS);
          timer.unref();
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /**
   * Grants the session ordinary proxy authority by writing its session file.
   *
   * One sealed inspect-and-write replaces the whole activation transaction:
   * there is no snapshot to publish, no consumer pointer to advance, and no
   * acknowledgement to wait for. The file the proxy reads is minted only after
   * the same call has re-proved the exact container incarnation, so authority
   * and evidence are granted in one step or not at all.
   *
   * The three outcomes are the three things the host can know, and each one
   * leaves this session in the state its evidence supports:
   *
   *   written      authority granted; the durable record follows the file to
   *                `attached` and the host stamps the lease it handed out;
   *   unavailable  the observation could not be made, so nothing was written
   *                and nothing is claimed — raised as the typed observation
   *                failure the launch ladder already fails closed on;
   *   mismatch     the inspection proved a different container — unless the
   *                foreground has ended, in which case what it really proved
   *                is the agent's own exit (see `#foregroundEndedBefore`).
   */
  #admitThroughSessionFile = async (record: SessionContainerRecordV2): Promise<void> => {
    const foreground = this.#require(this.#foreground, "foreground attach handle");
    // A foreground that ended before authority was sealed is this launch's
    // outcome, not an admission failure: without this, an agent that exits
    // immediately would reach the inspection, be proved not running, and
    // surface as an admission mismatch instead of as the exit status it is.
    const before = currentSessionContainerForegroundCompletion(foreground);
    if (before) return this.#reportForegroundEnded(before);
    // Admission is the first beat, and it beats against the same record every
    // later heartbeat will: the loop reads it from here.
    this.#fileRecord = record;
    this.#lock();
    const outcome = await this.#beatSessionFile();
    this.#lock();
    if (outcome.kind === "unavailable") throw outcome.error;
    if (outcome.kind === "mismatch") {
      const after = await this.#foregroundEndedBefore(foreground, outcome.observation);
      if (after) return this.#reportForegroundEnded(after);
      throw new Error(
        `session admission inspected a different container before granting authority: ${outcome.observation}`,
      );
    }
    // The file now exists. Everything below it can still fail, and a failure
    // that left the file behind would be a session the proxy serves under a
    // record this launch is about to tear down — so the window is closed here
    // rather than left to the caller's teardown to notice.
    try {
      const attached = transitionProvisioningRunningSessionContainerToAttachedV2(record);
      replaceExactSessionContainerRecordV2(
        this.#input.plan.paths.stateDir,
        this.#projectIdentity(),
        record,
        attached,
      );
      this.#advanceDurableRecord(attached, "provisioning create plan");
      // From here every beat re-proves the record the session actually holds.
      this.#fileRecord = attached;
      this.#fileWritten = outcome.file;
      this.#lock();
      this.#stampSessionHostStatus(outcome.file, "served");
      // The hook fires at the one moment it means something: the session holds
      // authority and is running with a known container id and source IP.
      const containerId = attached.containerId;
      if (containerId !== undefined && this.#input.onSessionRunning !== undefined) {
        await this.#input.onSessionRunning({ containerId, sourceIp: attached.sourceIp });
      }
    } catch (error) {
      this.#deleteSessionFileBestEffort(record);
      throw error;
    }
  };

  /**
   * Takes back a file this admission wrote but could not finish granting.
   *
   * Best effort by construction: the failure being rethrown is the news, and a
   * delete this host could not perform leaves a file that expires on its own
   * lease — and that the ordered teardown will try again to remove before it
   * touches the record.
   */
  #deleteSessionFileBestEffort(record: SessionContainerRecordV2): void {
    try {
      executeSessionFileCommand(
        this.#gateway.io,
        sessionFileDeleteCommand(this.#controlPlane().proxyContainerId, record.sessionPrincipal),
        this.#dockerOptions(),
      );
      this.#fileWritten = undefined;
    } catch {
      // Reported by the teardown that follows; never in place of the cause.
    }
  }

  /**
   * Grants the session ordinary proxy authority.
   *
   * The first moment the container may use the normal proxy path, and the only
   * step in the sequence that widens what it can do. Everything before this
   * establishes that the container is exactly what was planned; this spends
   * that evidence once.
   */
  activate = async (): Promise<void> => {
    this.#lock();
    const provisioning = this.#require(this.#provisioningAuthorization, "provisioning-running authority");
    await this.#admitThroughSessionFile(provisioning.record);
  };

  /**
   * Holds the session for the life of the attached process, beating its file.
   *
   * The heartbeat runs inside the wait rather than beside it because the file's
   * lease is short: an attached session that stops beating keeps running with
   * no authority, which the agent experiences as an unexplained network outage
   * rather than as a failure. A beat is spent well before expiry so a single
   * slow Docker call does not silently cost the session its network.
   *
   * No failing beat is authority to end the attached process — the loop's only
   * power is over this session's file, and an unrenewed file lapses on its own
   * lease.
   */
  awaitCompletion = async (): Promise<SessionAdmissionLaunchOutcome> => {
    this.#lock();
    if (this.#preAttachCompletion) return this.#preAttachCompletion;
    const foreground = this.#require(this.#foreground, "foreground attach handle");
    const sessionLockManager = this.#input.sessionLockManager;
    let finished = false;
    let wakeRenewal: (() => void) | undefined;
    const renewalLockAcquisition = new AbortController();

    const waitForCompletion = async (): Promise<SessionAdmissionLaunchOutcome> => {
      /**
       * The stream this launch is currently attached to.
       *
       * A lost stream is replaced rather than mourned, so the completion this
       * wait races is not fixed for the life of the session.
       */
      let attachedForeground = foreground;
      /**
       * A lost stream whose meaning is not yet known.
       *
       * Present only between a stream ending unconfirmed — the observation
       * failed, or this session has re-attached as often as it may — and the
       * beat that finally answers. While it is present the completion race
       * waits on `settled` instead of on a foreground that has already ended,
       * so nothing spins and nothing is concluded.
       */
      let lostStream: {
        readonly lost: SessionContainerForegroundCompletion;
        readonly settled: Promise<LostForegroundStreamDecision>;
        readonly decide: (decision: LostForegroundStreamDecision) => void;
        answered: boolean;
      } | undefined;
      const awaitLostStream = (lost: SessionContainerForegroundCompletion, observation: string): void => {
        let decide!: (decision: LostForegroundStreamDecision) => void;
        const settled = new Promise<LostForegroundStreamDecision>((resolve) => { decide = resolve; });
        lostStream = { lost, settled, decide, answered: false };
        // Immediate, not buffered. This is the one state where the terminal
        // goes quiet while the launch keeps waiting, so the person watching it
        // has to be told now — a warning flushed when the command ends would
        // arrive only after they had given up and interrupted it. Every exit
        // from the wait announces itself the same way.
        runfreeLog(`session output stream lost: ${observation}; the agent process is preserved; waiting for the container to be reachable again`);
      };
      /**
       * One beat's share of the confirmation: ask the container again.
       *
       * A beat that proved a mismatch is itself an answer when the inspection
       * could not be read — the shipped judge already decided that this is not
       * the container the session was admitted for (it is gone, or it is
       * different), and waiting for an inspection that will never resolve would
       * hold the launch open over a session that no longer exists.
       */
      const confirmLostStream = (beat: HeartbeatOutcome | undefined): void => {
        const waiting = lostStream;
        if (!waiting || waiting.answered) return;
        const decision = this.#classifyLostForegroundStream();
        if (decision.kind === "wait") {
          if (beat?.kind !== "mismatch") return;
          waiting.answered = true;
          waiting.decide({ kind: "teardown", observation: beat.observation });
          return;
        }
        waiting.answered = true;
        waiting.decide(decision);
      };
      /**
       * Renewal: one sealed inspect-and-write per beat, and nothing else.
       *
       * It publishes no snapshot, drains no peer transaction, and mints no
       * lease, and it takes the lifecycle lock only on the one beat that finds
       * a completed compatible rebind to adopt — so an ordinary beat serializes
       * against nothing and cannot be delayed by another launcher's lifecycle
       * operation. That is also why no failing beat may end the session: the
       * loop's only power is over this session's file, and the proxy already
       * stops serving a file that stops being renewed. A beat that cannot
       * observe the container leaves the last file to expire on its own lease;
       * a beat that proves a different container has already had its file
       * deleted by the sealed write itself. Either way the agent process keeps
       * running until it exits, unserved rather than killed.
       */
      const heartbeatLoop = async (): Promise<void> => {
        const cadenceMs = sessionHeartbeatCadenceMs();
        let failures = 0;
        // Whether the last beat failed on a host-side fault rather than on an
        // observation, which is the difference between "this will pass" and
        // "this will not pass without someone acting".
        let faulted = false;
        // Whether the last adoption attempt could not be completed for a reason
        // that ends on its own. Reported once per gap, like every other
        // condition here that is expected to pass.
        let adoptionBlocked = false;
        const stampRetrying = (): void => {
          const written = this.#fileWritten;
          if (written) this.#stampSessionHostStatus(written, "retrying");
        };
        while (!finished) {
          // Healthy beats run on the cadence; consecutive failures back off
          // from 1 s, doubling to a 30 s cap with jitter. Cancellable because
          // teardown waits on this loop, and an uninterruptible sleep would
          // hold the session's file for a full cadence after its process had
          // already exited.
          const sleep = cancellableDelay(nextHeartbeatDelayMs({ consecutiveFailures: failures, cadenceMs }));
          wakeRenewal = sleep.cancel;
          await sleep.elapsed;
          if (finished) return;
          // Deliberately OUTSIDE the guard below: a refused adoption is a
          // decision about this session's authority, not a beat that failed,
          // and swallowing it as one would keep renewing under a control plane
          // this session no longer holds. An unchanged selection reads two
          // durable fields and takes no lock.
          //
          // Three failures are not that decision, and every one of them means
          // "preserve the process": a rebind still in flight (the journal
          // exists, so adoption
          // refuses until its recovery settles — and a crashed rebinder leaves
          // it there indefinitely), a lifecycle lock held past the renewal wait
          // budget, and a host queue that cannot schedule a renewal. Ending a
          // live agent over any of them would be the wedge this loop must not
          // become. The beat still runs and still writes into the proxy this
          // session holds, which is fail-closed rather than destructive: if the
          // replacement really did happen, that write fails and the file lapses
          // on its own lease. Q5's accepted cost is one cadence plus adoption
          // unserved, never a teardown.
          try {
            await this.#adoptDurableSelectionIfChanged(renewalLockAcquisition.signal);
            adoptionBlocked = false;
          } catch (error) {
            if (error instanceof SessionLockAcquisitionAbortedError) return;
            if (!(error instanceof SessionReplacementPendingError)
              && !(error instanceof SessionLockAcquisitionTimeoutError)
              && !(error instanceof RuntimeObservationError && error.evidence.kind === "observation-unavailable")) {
              throw error;
            }
            // The manager retains the lock when the adoption itself threw and
            // has already returned to waiting when acquisition did, so the
            // release is best effort for exactly that reason.
            try { sessionLockManager.releaseForWait(); }
            catch { /* The manager may already be waiting, or the fence was lost. */ }
            // Immediate, not buffered: the session is running unrestored, and
            // the person watching it can act on that now rather than when the
            // command finally ends.
            if (!adoptionBlocked) {
              runfreeLog(`${error.message}; the session process remains attached; network restoration is incomplete`);
            }
            adoptionBlocked = true;
          }
          if (finished) return;
          let beat: HeartbeatOutcome | undefined;
          try {
            const outcome = await this.#beatSessionFile();
            beat = outcome;
            if (outcome.kind === "written") {
              // Only after a gap: a healthy beat is silent.
              if (failures > 0 || faulted) runfreeLog("session network restored");
              failures = 0;
              faulted = false;
              this.#fileWritten = outcome.file;
              this.#stampSessionHostStatus(outcome.file, "served");
            } else {
              failures += 1;
              if (outcome.kind === "mismatch") {
                // The beat deleted the file, which is the whole of the authority
                // this source can withdraw. Ending the process is not part of it.
                warn(`${outcome.observation}; session file removed; the process is preserved until it exits`);
              } else if (failures === 1) {
                // Once per outage, not once per beat: an unavailable observation
                // is expected to end, and the loop is already retrying.
                warn(`${outcome.error.message}; session process preserved; heartbeat will retry`);
              }
              stampRetrying();
            }
          } catch (error) {
            // `inspectAndWriteSessionFile` answers every post-Docker condition
            // with an outcome and the stamp above never throws, so a throw here
            // is a host-side fault — this driver's own inputs — and nothing
            // about it is expected to end on its own. Ending a live agent over
            // it would be exactly the wedge this loop must not become, so it is
            // swallowed; but a fault that is silently retried until the file
            // lapses would take the session's network away with no signal at
            // all, so unlike a transient outage it is reported on every beat
            // until a write succeeds.
            failures += 1;
            faulted = true;
            const detail = error instanceof Error ? error.message : String(error);
            const expiry = this.#fileWritten?.aliveUntil;
            warn(`session heartbeat is failing on a host-side fault: ${detail}; the session loses network at ${expiry ?? "the end of its current session-file lease"} unless it recovers`);
          }
          // A lost stream this host could not confirm — and a session that has
          // re-attached as often as it may — waits here rather than in a loop of
          // its own: the beat is already the thing that keeps asking the daemon
          // about this container, so the confirmation rides with it and costs
          // one extra inspection only while a stream is actually missing.
          //
          // Invariant: this call sits OUTSIDE the beat's guard above, so it must
          // stay throw-free. `#classifyLostForegroundStream` answers every
          // condition with a decision and `runfreeLog` writes a line; anything
          // added here that could throw would reject the heartbeat loop and send
          // a live agent to teardown.
          confirmLostStream(beat);
        }
      };
      const renewalLoop = heartbeatLoop();

      /**
       * The completion race.
       *
       * The end of the foreground is not the end of the session: the stream can
       * end while the agent keeps running, and ending the session on that would
       * destroy a live process over a lost view of it. So
       * a lost stream is confirmed by inspection first, and the race is a loop —
       * a re-attach continues it under the new stream, an unconfirmed loss
       * continues it under the beat's confirmation, and only a proved exit, a
       * proved change, or an ordinary exit status leaves it.
       */
      const awaitFileSourceCompletion = async (): Promise<SessionAdmissionLaunchOutcome> => {
        for (;;) {
          const waiting = lostStream;
          const settled = waiting
            ? await Promise.race([
              waiting.settled.then((decision) => ({ kind: "decided" as const, decision, lost: waiting.lost })),
              renewalLoop.then(() => ({ kind: "renewal" as const })),
            ])
            : await Promise.race([
              attachedForeground.completion.then((completion) => ({ kind: "foreground" as const, completion })),
              renewalLoop.then(() => ({ kind: "renewal" as const })),
            ]);
          if (settled.kind === "renewal") {
            throw new Error("session lease renewal stopped before the attached process finished");
          }
          if (settled.kind === "foreground" && !lostForegroundStream(settled.completion)) {
            return this.#reportForegroundCompletion(settled.completion);
          }
          const lost = settled.kind === "foreground" ? settled.completion : settled.lost;
          // Whether the person at the terminal was told this session was
          // waiting, and is therefore owed the answer.
          const announced = settled.kind === "decided";
          if (announced) lostStream = undefined;
          const decision = settled.kind === "decided" ? settled.decision : this.#classifyLostForegroundStream();
          if (decision.kind === "exited") {
            // The stream is gone and so is the container: the status the launch
            // reports is the one the container actually exited with, never the
            // signal that killed this host's view of it.
            if (announced) runfreeLog(`session container exited with code ${decision.status}`);
            this.#foregroundOutcome = Object.freeze({ status: decision.status, signal: null });
            return this.#foregroundOutcome;
          }
          if (decision.kind === "teardown") {
            if (announced) runfreeLog(`session output stream cannot be recovered: ${decision.observation}`);
            return this.#reportForegroundCompletion(lost);
          }
          if (decision.kind === "wait") {
            awaitLostStream(lost, decision.observation);
            continue;
          }
          try {
            attachedForeground = await this.#reattachForeground(attachedForeground);
            runfreeLog("session output stream ended while the container is still running; re-attached");
          } catch (error) {
            // A re-attach that cannot spawn is this host's failure, not the
            // container's: the process it could not reach is still running, so
            // the beat keeps asking rather than ending it.
            awaitLostStream(lost, error instanceof Error ? error.message : String(error));
          }
        }
      };

      try {
        return await awaitFileSourceCompletion();
      } finally {
        finished = true;
        renewalLockAcquisition.abort();
        wakeRenewal?.();
        await renewalLoop.catch(() => undefined);
      }
    };

    // The session file is durable and the proxy serves from it. The project
    // lock protects lifecycle transitions, not the interactive process
    // lifetime, so release it while the foreground process runs. Heartbeats
    // take short critical sections, and teardown starts only after
    // reacquisition.
    sessionLockManager.releaseForWait();
    let completion: Readonly<{ ok: true; outcome: SessionAdmissionLaunchOutcome }>
      | Readonly<{ ok: false; error: unknown }>;
    try {
      completion = { ok: true, outcome: await waitForCompletion() };
    } catch (error) {
      completion = { ok: false, error };
    }
    let recoveryFailure: unknown;
    try {
      await sessionLockManager.reacquire();
      this.#lock();
      // Cover the window after the last beat and before reacquisition: the
      // durable selection can have been replaced under the unlocked wait, and
      // the teardown below derives its proxy and network from it.
      this.#adoptCompatibleControlPlaneRebind();
      this.#lock();
    } catch (error) {
      // A replacement that arrived while this session was unlocked is not a
      // failure of a completed launch: the teardown below still ends the
      // session under whatever control plane it now holds.
      if (!(error instanceof SessionReplacementPendingError && completion.ok)) recoveryFailure = error;
    }
    if (!completion.ok && recoveryFailure !== undefined) {
      throw new AggregateError(
        [completion.error, recoveryFailure],
        "attached session wait and post-completion admission recovery both failed",
      );
    }
    if (!completion.ok) throw completion.error;
    if (recoveryFailure !== undefined) {
      throw new PostCompletionAdmissionRecoveryError(completion.outcome, recoveryFailure);
    }
    return completion.outcome;
  };

  /**
   * The launch ladder's routing answer for this driver.
   *
   * Until the admitting beat has entered its write there is no session file,
   * so a failure before that belongs to unadmitted cleanup, which tears the
   * container down under the creation receipt without spending a session-file
   * delete against a proxy that never heard of this session.
   */
  provisioningMayBeSelected = (): boolean => this.#fileMayExist;

  cleanupUnadmitted = async (): Promise<void> => {
    this.#lock();
    const preflight = this.#require(this.#preflight, "canonical preflight");
    const record = this.#record;
    if (!record) return;
    const failures: unknown[] = [];
    if (this.#foreground) {
      try {
        cancelSessionContainerForegroundAttach(this.#foreground);
        this.#foreground = undefined;
      } catch (error) {
        failures.push(error);
      }
    }
    if (record.containerId && this.#creationReceipt) {
      // The creation receipt authorizes this exact container across lifecycle
      // transitions, so one cleanup path covers every pre-registration failure:
      // a bound allocated record and a provisioning-running record whose
      // foreground start never converged tear down the same way.
      for (const [label, command] of [
        ["Docker failed to stop the unadmitted session container", creationAuthorizedSessionContainerStopCommand(
          record,
          preflight.expectedProject,
          this.#creationReceipt,
        )],
        ["Docker failed to remove the unadmitted session container", creationAuthorizedSessionContainerRemoveCommand(
          record,
          preflight.expectedProject,
          this.#creationReceipt,
        )],
      ] as const) {
        try {
          this.#runCleanupCommand(label, command);
        } catch (error) {
          failures.push(error);
        }
      }
      let absence: SessionContainerAbsenceReceipt | undefined;
      try {
        absence = proveSessionContainerAbsent(
          (executable, args, options) => this.#gateway.io.capture(executable, [...args], options),
          record,
          preflight.expectedProject,
          this.#network(),
          this.#dockerOptions(),
        );
      } catch (error) {
        failures.push(error);
      }
      if (absence && this.#persistedRecord) {
        try {
          if (sameRecord(record, this.#persistedRecord)) {
            if (!removeAbsentSessionContainerRecordV2(
              this.#input.plan.paths.stateDir,
              preflight.expectedProject,
              record,
              this.#network(),
              absence,
            )) {
              throw new Error("absent unadmitted session-container record was not removed");
            }
          } else {
            if (!removeExactSessionContainerRecordV2(
              this.#input.plan.paths.stateDir,
              preflight.expectedProject,
              this.#persistedRecord,
            )) {
              throw new Error("unbound unadmitted session-container record was not removed");
            }
          }
          this.#persistedRecord = undefined;
        } catch (error) {
          failures.push(error);
        }
      }
    } else {
      try {
        if (this.#persistedRecord) {
          if (!removeExactSessionContainerRecordV2(
            this.#input.plan.paths.stateDir,
            preflight.expectedProject,
            this.#persistedRecord,
          )) {
            throw new Error("unadmitted session-container record was not removed before reconciliation");
          }
          this.#persistedRecord = undefined;
        }
        const records = listSessionContainerRecordsV2(
          this.#input.plan.paths.stateDir,
          preflight.expectedProject,
        );
        const classifications = this.#inventoryClassifications(records);
        const target = classifications.find((classification): classification is Extract<
          SessionReconciliationClassification,
          { kind: "container-only" }
        > => classification.kind === "container-only"
          && classification.identity.sessionId === record.sessionId
          && classification.identity.sessionIncarnation === record.sessionIncarnation);
        if (target) this.#cleanExactOrphan(target);
        const uncertain = classifications.find((classification) => (
          classification.kind === "mismatch"
          && classification.record.sessionId === record.sessionId
        ) || (
          classification.kind === "untrusted-container"
          && classification.container.containerName === record.containerName
        ));
        if (!target && uncertain) {
          throw new Error("malformed session create left a container without exact cleanup authority");
        }
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length > 0) {
      throw new AggregateError(failures, "unadmitted session-container cleanup did not complete");
    }
  };

  tearDown = async (): Promise<void> => {
    this.#lock();
    await this.#tearDownSessionFileSession();
  };

  /**
   * Applies the outcome-aware session evidence rule after a launch: status 0
   * consumes the evidence; any other outcome (nonzero, signal, or a thrown
   * failure passed as `undefined`) preserves it as interrupted host evidence.
   * A resume launch always removes its transient evidence instead, so one
   * failed attempt cannot mint a second, less precise recovery item beside the
   * claimed original.
   */
  finalizeSessionEvidence(outcome: SessionAdmissionLaunchOutcome | undefined): void {
    outcome ??= this.#foregroundOutcome ?? this.#preAttachCompletion;
    this.#foregroundOutcome = undefined;
    this.#preAttachCompletion = undefined;
    const metadata = this.#sessionEvidence;
    if (!metadata) return;
    // Each evidence file has one exact session id and is not part of the
    // whole-registry admission generation. Finalize it even if bounded teardown
    // reacquisition failed; otherwise one lock timeout leaves both registry
    // residue and misleading open host evidence.
    if (outcome?.status === 0 || this.#launch?.resume !== undefined) {
      removeSessionMetadata(this.#input.context, metadata.id);
    } else {
      markSessionInterrupted(this.#input.context, metadata, outcome?.status ?? undefined);
    }
    // Cleared only after the filesystem effect succeeded: a removal that threw
    // on the success path must leave the handle populated so the caller's
    // failure-path finalize can still preserve the evidence as interrupted
    // instead of silently orphaning an open metadata file.
    this.#sessionEvidence = undefined;
  }
}

/**
 * L0 instrumentation facade: delegates every admission and teardown step to
 * the same steps object, timing each one. `awaitCompletion` is deliberately
 * untimed — its duration is the interactive session's lifetime, not launch
 * latency. Behaves identically to the bare steps in every other respect.
 */
function timedSessionAdmissionLaunchSteps(
  steps: SessionAdmissionLaunchSteps,
  timings: RuntimeTimings,
): SessionAdmissionLaunchSteps {
  const timed = (phase: string, fn: () => Promise<void>) => (): Promise<void> => timings.timeAsync(phase, fn);
  return Object.freeze({
    agent: steps.agent,
    nowMs: steps.nowMs,
    dockerOperationCount: steps.dockerOperationCount,
    preflight: timed("admission:preflight", steps.preflight),
    allocate: timed("admission:allocate", steps.allocate),
    createStarted: timed("admission:create-started", steps.createStarted),
    proveRunning: timed("admission:prove-running", steps.proveRunning),
    activate: timed("admission:activate", steps.activate),
    cleanupUnadmitted: timed("admission:cleanup-unadmitted", steps.cleanupUnadmitted),
    awaitCompletion: steps.awaitCompletion,
    tearDown: timed("teardown:session-file", steps.tearDown),
    // Not a step and not timed, but it must be forwarded: it decides which
    // cleanup answers a failure, and dropping it here would make `RUNFREE_TIMINGS`
    // change the teardown a failed launch performs.
    ...(steps.provisioningMayBeSelected === undefined
      ? {}
      : { provisioningMayBeSelected: steps.provisioningMayBeSelected }),
  });
}

/**
 * Creates the production adapter for the internal admission proof gate.
 *
 * Its only public operation is a built-in probe. All Docker targets, lifecycle
 * records, launch argv, image authority, network identity, and eligibility are
 * derived from the held lifecycle lock and the exact active runtime plan.
 */
export function createInternalSessionAdmissionDriver(
  input: InternalSessionAdmissionDriverInput,
): InternalSessionAdmissionDriver {
  const sessionLockManager = input.sessionLockManager;
  if (!sessionLockManager) throw new Error("session admission requires a SessionLockManager");
  const lifecycleLock = sessionLockManager.lock;
  lifecycleLock.assertHeld();
  const prepared = consumePreparedRuntime({
    preparedRuntime: input.preparedRuntime,
    lifecycleLock,
    io: input.io,
  });
  const resolvedInput = Object.freeze({
    ...input,
    lifecycleLock,
    context: prepared.context,
    plan: prepared.plan,
  });
  lifecycleLock.assertHeld();
  let inFlight = false;
  const begin = (): void => {
    if (inFlight) throw new Error("an internal session admission operation is already in flight");
    inFlight = true;
  };
  const stepsFor = (
    agent: SessionAdmissionSessionKind,
    launch?: SessionAdmissionLaunchOptions,
  ): InternalBuiltinAdmissionProbeSteps => {
    resolvedInput.lifecycleLock.assertHeld();
    const gateway = createSessionAdmissionDockerGateway({
      io: resolvedInput.io,
      ...(resolvedInput.foregroundSpawner ? { foregroundSpawner: resolvedInput.foregroundSpawner } : {}),
    });
    return new InternalBuiltinAdmissionProbeSteps(resolvedInput, gateway, agent, launch);
  };
  const runLaunch = async (
    kind: SessionAdmissionSessionKind,
    options: SessionAdmissionLaunchOptions,
  ): Promise<SessionAdmissionLaunchOutcome> => {
    begin();
    // L0 instrumentation: opt-in per-step timing plus the gateway's Docker
    // operation count, surfaced per launch. Measurement only — the facade
    // delegates every step to the same object and never reorders or retries.
    const timings = createRuntimeTimings(resolvedInput.context.env);
    let steps: InternalBuiltinAdmissionProbeSteps | undefined;
    try {
      steps = stepsFor(kind, options);
      const launchSteps = timings.enabled ? timedSessionAdmissionLaunchSteps(steps, timings) : steps;
      try {
        const outcome = await runInternalSessionAdmissionLaunch(launchSteps);
        steps.finalizeSessionEvidence(outcome);
        resolvedInput.lifecycleLock.assertHeld();
        return outcome;
      } catch (failure) {
        try {
          steps.finalizeSessionEvidence(
            completionOutcomeFromFailure(failure),
          );
        } catch (evidenceFailure) {
          throw new AggregateError(
            [failure, evidenceFailure],
            "session launch failed and its host session evidence could not be finalized",
          );
        }
        throw failure;
      }
    } finally {
      if (timings.enabled && steps) {
        timings.report("session-admission", `docker-operations=${steps.dockerOperationCount()}`);
      }
      inFlight = false;
    }
  };
  return Object.freeze({
    async probeBuiltin(agent: SessionAdmissionProbeAgent) {
      begin();
      try {
        const steps = stepsFor(agent);
        const metrics = await runInternalSessionAdmissionProbe(steps);
        resolvedInput.lifecycleLock.assertHeld();
        return metrics;
      } finally {
        inFlight = false;
      }
    },
    async launchBuiltin(agent: SessionAdmissionProbeAgent, options: SessionAdmissionLaunchOptions = {}) {
      return await runLaunch(agent, options);
    },
    async launchShell() {
      return await runLaunch("shell", {});
    },
    async recoverPending(agent: SessionAdmissionProbeAgent) {
      begin();
      try {
        const steps = stepsFor(agent);
        await steps.preflight();
        resolvedInput.lifecycleLock.assertHeld();
      } finally {
        inFlight = false;
      }
    },
  });
}
