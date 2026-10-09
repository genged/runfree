import { performance } from "node:perf_hooks";
import { RuntimeObservationError } from "./observation-failure.ts";

import type { SessionFileV1 } from "@runfree/runtime-contracts/session-file";
import { SESSION_ADMISSION_LEASE_MAX_DURATION_MS } from "@runfree/runtime-contracts/session-registry";

import { builtinAgent } from "../agents.ts";
import { resolveAgentCommand } from "../config.ts";
import { CliError } from "../errors.ts";
import { warn } from "../warnings.ts";
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
  proveSessionContainerExited,
  SessionFileTeardownBlockedError,
  teardownSessionRecord,
  UNCERTAIN_SESSION_COMPLETION,
  type SessionFileTeardownResult,
  type SessionTeardownCompletion,
} from "./session-file-teardown.ts";

import {
  waitForAttachedSessionCompletion,
  type LostForegroundStreamDecision,
} from "./session-attached-wait.ts";
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
import { createOperationHistogram, type OperationHistogram } from "./operation-histogram.ts";
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
  parseSessionContainerTopHandoff,
  SESSION_CONTAINER_TOP_MAX_BYTES,
  sessionContainerStartAttachCommand,
  sessionContainerTopCommand,
  sessionNetworkInspectCommand,
  type SessionContainerTopHandoff,
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
  sessionContainerTemplateInit,
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
  transitionSessionContainerToRevokingV2,
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
  type SessionNamedVolumeProof,
  sessionNamedVolumeInspectRequest,
  validateSessionNamedVolumeInspect,
} from "./session-named-volume-proof.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import {
  consumePreparedRuntime,
  StalePreparedRuntimeError,
  type LaunchHandoff,
  type PreparedRuntime,
} from "./prepared-runtime.ts";
import { sessionRegistryDigest } from "./launch-handoff.ts";
import { consumeWarmEmptySessionState, isWarmEmptySessionState } from "./warm-empty-session-state.ts";
import { createRuntimeDocker } from "./docker.ts";
import { createDockerClient } from "./docker-client.ts";
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
import {
  reclaimStaleSessionMcpCallbackForwarders,
  removeOrphanSessionMcpCallbackIngress,
  removeSessionMcpCallbackIngress,
} from "./session-callback-ingress.ts";
import {
  type SessionCallbackOwner,
  type SessionCallbackReservation,
  sessionMcpCallbackLifecycle,
  type SessionIngressLifecycle,
} from "./session-mcp-callback.ts";
import { createTaskScope, type ScopedTask } from "./task-scope.ts";
import { launchLockHoldDeadline, RUNNING_PROOF_TIMEOUT_MS } from "./launch-lock-hold.ts";
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
// Docker's running state (`RUNNING_PROOF_TIMEOUT_MS`, defined beside the
// launch lock-hold budget it is part of). This is the helper's maximum, and it
// is deliberate: the running proof is now the *first* observation taken after
// `docker start --attach` is issued. Under the pre-file admission source,
// `register` (snapshot publish, selection, acknowledgement) ran in between and
// its Docker round-trips padded the window, so the helper's 5 s fallback was
// never the whole budget it appeared to be. With `register` gone the container
// has to be seen running within whatever this names, and a loaded Docker
// daemon can take longer than 5 s to start one. Widening the window admits
// nothing earlier: the proof still requires the same exact running assertion,
// and no session is authorized before it returns.
export { RUNNING_PROOF_TIMEOUT_MS };
/**
 * The longest a launch holds the project lifecycle lock after its grant while
 * waiting for the session entry to hand off to the agent (`awaitHandoff`).
 *
 * Fixed, and far inside the window another command waits for the same lock
 * (`PROJECT_LIFECYCLE_LOCK_RETRY_WINDOW_MS`, pinned by a unit test at no more
 * than a third of it): an entry that never hands off — the project image may
 * replace it — must never make a concurrent launch, `up`, or `destroy` in the
 * same project give up. A healthy handoff takes well under a second.
 */
export const SESSION_HANDOFF_WAIT_CEILING_MS = 10_000;
/** How often the handoff wait asks the daemon for the container's processes. */
const SESSION_HANDOFF_POLL_MS = 100;
/**
 * The least time one handoff read is given, so a read started just before the
 * ceiling is not cut off before the daemon can answer at all.
 */
const SESSION_HANDOFF_MIN_READ_MS = 250;

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
  /**
   * Host-chosen conversation id for a fresh launch only (spec `local/specs/
   * 2026-10-04-same-terminal-session-resume-design.md` section 2). The public
   * launch frame mints this once with `crypto.randomUUID()`, outside its own
   * retry loop, so an admission retry after a re-prepared runtime still
   * resumes the same conversation. Never present together with `resume`: the
   * driver's preflight step (below) refuses both the resume-plus-id
   * combination and a fresh launch of an agent that accepts the flag but was
   * given no id.
   */
  launchConversationId?: string;
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

export type InternalSessionAdmissionDriverInput = Readonly<{
  preparedRuntime: PreparedRuntime;
  /** The only lifecycle-lock authority accepted by a session driver. */
  sessionLockManager: SessionLockManager;
  io: RuntimeIO;
  foregroundSpawner?: SessionContainerForegroundSpawner;
  /**
   * The session-owned ingress a launch sets up before activation (today the
   * MCP OAuth callback path). Omitted: derived from the project — present only
   * when an OAuth-capable MCP server needs a callback. `null`: none. Probes
   * never set any up.
   */
  sessionIngress?: SessionIngressLifecycle | null;
  nowEpochMs?: () => number;
  nowMonotonicMs?: () => number;
  /**
   * The held-lock handoff this launch took (sub-second launch plan Task 3). Its
   * lock must be the manager's lock. With it, preflight may skip repeating
   * startup's reconcile and orphan cleanup when both still describe the
   * registry and the proxy incarnation; it never skips the network baseline,
   * the fence, or the post-start proof.
   */
  handoff?: LaunchHandoff;
  /**
   * When the caller took the lifecycle lock this admission runs under, on the
   * `nowMonotonicMs` clock. The launch's one continuous hold ends by
   * `launchLockHoldDeadline` of it (or of the handoff's acquisition). Omitted:
   * the driver's construction time.
   */
  lockHeldSinceMonotonicMs?: number;
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
  /** When this launch's continuous hold of the lifecycle lock must end. */
  readonly #lockHoldDeadlineMs: number;
  readonly #lockHeldSinceMs: number;
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
   * The provisioning-running record whose session file `activate` wrote, held
   * until `awaitHandoff` reports it `attached`.
   */
  #admittedRecord?: SessionContainerRecordV2;
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
   * Set once `#confirmAttached` has durably transitioned the record to
   * `attached`. `finalizeSessionEvidence` reads this to tell a resume that
   * never reached attachment (its evidence is disposable, same as any other
   * pre-attach failure) from a resume that did and then ended non-zero (its
   * evidence is this terminal's only record of the conversation and must be
   * kept — security review F3, decision 10).
   */
  #attached = false;
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
  /** The handoff's IP assignment listing, until the one fence that may use it. */
  #handoffIpAssignments?: Readonly<Record<string, string>>;
  /** Present only in launch mode; probes must never leave user-facing session evidence. */
  #launch?: SessionAdmissionLaunchOptions;
  /**
   * Set before this launch starts creating its session-owned ingress, so
   * unadmitted cleanup knows to prove that ingress absent before it releases
   * the record — and with it the address the ingress targets.
   */
  #ingressMayExist = false;
  /**
   * Every branch this launch runs beside its foreground steps. Cleanup,
   * teardown, and the launch's return each settle it first, under the
   * lifecycle lock, so no Docker call outlives the lock or races a cleanup.
   */
  readonly #tasks = createTaskScope({ assertHeld: () => this.#lock() });
  /** The session ingress whose reservation is running beside the session container's start. */
  #ingress?: Readonly<{
    lifecycle: SessionIngressLifecycle;
    owner: SessionCallbackOwner;
    reservation: ScopedTask<SessionCallbackReservation>;
  }>;
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
    this.#lockHeldSinceMs = input.handoff?.lockAcquiredAtMonotonicMs ?? input.lockHeldSinceMonotonicMs ?? this.#nowMonotonicMs();
    this.#lockHoldDeadlineMs = launchLockHoldDeadline(this.#lockHeldSinceMs);
  }

  nowMs = (): number => this.#nowMonotonicMs();
  dockerOperationCount = (): number => this.#gateway.dockerOperationCount();
  /** How long this launch has held the lifecycle lock in its one continuous hold. */
  lockHoldMs = (): number => this.#nowMonotonicMs() - this.#lockHeldSinceMs;
  #teardownPath: "exited" | "full" = "full";

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
   * running (under Docker's init, or as PID 1 of a session created before the
   * init wrapper) in a container this host can still inspect. So nothing is
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
  ): boolean {
    try {
      writeSessionHostStatus(this.#input.plan.paths.stateDir, {
        v: 1,
        sessionId: file.sessionId,
        lastHeartbeatAt: file.inspectedAt,
        aliveUntil: file.aliveUntil,
        served,
        ...(terminal === undefined ? {} : { terminal }),
      });
      return true;
    } catch (error) {
      if (this.#stampFailureWarned) return false;
      this.#stampFailureWarned = true;
      warn(`session status stamp unwritable: ${error instanceof Error ? error.message : String(error)}; the session is unaffected; the last stamp may be stale and owner liveness remains authoritative`);
      return false;
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
  #stampSessionTerminal(record: SessionContainerRecordV2): boolean {
    const now = new Date(this.#nowEpochMs()).toISOString();
    return this.#stampSessionHostStatus(
      { sessionId: record.sessionId, inspectedAt: now, aliveUntil: now },
      "unknown",
      "revoking",
    );
  }

  /**
   * How this session ended, as far as one exact inspection can prove it.
   *
   * Only a numeric exit this launch reported (the foreground's own code, or a
   * code a confirming inspection proved) is even considered, and only an
   * inspection taken now — after the stream closed, the heartbeat stopped, the
   * lock was reacquired, and the session file was proved gone — that shows
   * this exact incarnation stopped with that code mints the proof. Everything else, including an inspection that
   * could not be made, is `uncertain`, which keeps the full teardown with its
   * stop grace. Never throws: this only chooses between two revocation orders
   * that both delete the file first.
   */
  #teardownCompletion(record: SessionContainerRecordV2): SessionTeardownCompletion {
    const outcome = this.#foregroundOutcome ?? this.#preAttachCompletion;
    const anchor = this.#fileAnchor;
    const containerId = record.containerId;
    if (!outcome || typeof outcome.status !== "number" || outcome.signal !== null
      || !anchor || containerId === undefined) {
      return UNCERTAIN_SESSION_COMPLETION;
    }
    try {
      this.#lock();
      const inspected = this.#captureCommand(sessionContainerInspectCommand(record, this.#projectIdentity()));
      if (inspected.status !== 0) return UNCERTAIN_SESSION_COMPLETION;
      const proof = proveSessionContainerExited(inspected.stdout, {
        containerId,
        startedAt: anchor.dockerStartedAt,
        exitCode: outcome.status,
      });
      if (proof) this.#teardownPath = "exited";
      return proof ? Object.freeze({ kind: "exited" as const, proof }) : UNCERTAIN_SESSION_COMPLETION;
    } catch {
      return UNCERTAIN_SESSION_COMPLETION;
    }
  }

  /** Which revocation order the last teardown took; timing diagnostics only. */
  teardownPath = (): "exited" | "full" => this.#teardownPath;

  /**
   * Marks a blocked teardown in the durable record itself when its terminal
   * stamp could not be written either (todo 35 fix 6).
   *
   * Without either marker a peer would read this record as a live session: the
   * address stays reserved through the attachment baseline, but `runfree
   * sessions` and preflight would not see cleanup in progress. The record's own
   * `revoking` state says the same thing the stamp would have said, and every
   * peer (preflight, destroy, reconcile) already reads it as cleanup. Best
   * effort: the blocked delete is the news, and this cannot make it worse.
   */
  #markBlockedTeardownRevoking(record: SessionContainerRecordV2): void {
    if (record.state === "revoking") return;
    try {
      this.#lock();
      const revoking = transitionSessionContainerToRevokingV2(record);
      replaceExactSessionContainerRecordV2(
        this.#input.plan.paths.stateDir,
        this.#projectIdentity(),
        record,
        revoking,
      );
      this.#record = revoking;
      this.#persistedRecord = revoking;
      if (this.#fileRecord) this.#fileRecord = revoking;
    } catch {
      // The record stays as it was; the address is still reserved by it.
    }
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
    let terminalStamped = true;
    try {
      const result: SessionFileTeardownResult = teardownSessionRecord({
        io: this.#gateway.io,
        proxyId: this.#controlPlane().proxyContainerId,
        record,
        expectedProject,
        networkId: this.#controlPlane().networkIds.agentInternal,
        lock: () => this.#lock(),
        markTerminal: () => { terminalStamped = this.#stampSessionTerminal(record); },
        clearStamp: () => removeSessionHostStatus(stateDir, record.sessionId),
        removeRecord: () => removeExactSessionContainerRecordV2(stateDir, expectedProject, record),
        completion: () => this.#teardownCompletion(record),
        dockerOptions: this.#dockerOptions(),
      });
      if (result.completed) {
        this.#fileTornDown = true;
        this.#persistedRecord = undefined;
      } else {
        blockedOnDelete = true;
        if (!terminalStamped) this.#markBlockedTeardownRevoking(record);
        failures.push(new SessionFileTeardownBlockedError(result.error));
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
    // The orphan's callback route goes before the container that holds its
    // address (the same order as the ordered teardown); unproved, the
    // container is kept and the launch refuses before any allocation.
    this.#lock();
    removeOrphanSessionMcpCallbackIngress({
      io: this.#gateway.io,
      dockerOptions: this.#dockerOptions(),
      projectId: preflight.expectedProject.projectId,
      containerId: authority.containerId,
      sessionId: classification.identity.sessionId,
      running: classification.container.running,
      ...(classification.container.sourceIp ? { sourceIp: classification.container.sourceIp } : {}),
    });
    this.#lock();
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

  /** Returns how many orphan containers (and their callback routes) it removed. */
  #cleanPreexistingOrphans(): number {
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
    let removed = 0;
    for (const classification of classifications) {
      if (classification.kind !== "container-only") continue;
      this.#cleanExactOrphan(classification);
      removed += 1;
    }
    if (removed > 0) {
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
    return removed;
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

  /**
   * The handoff's reconcile snapshot, when admission may rely on it instead of
   * reconciling again; undefined runs today's full preflight.
   *
   * Requires the startup reconcile to have been clean, the registry on disk to
   * be byte-for-byte what startup left, the handoff to name the selected proxy,
   * and one exact inspection to show that proxy is still the incarnation
   * startup proved (the validation marker survives `docker restart`, so
   * nothing else would notice an in-place restart). A different incarnation
   * refuses as stale, which the launch frame answers with one bounded
   * re-preparation.
   */
  /**
   * The fence's CAS precondition from the handoff's listing, once (Task 6).
   *
   * Only when the preflight relied on the handoff (so the same held lock and
   * the same proxy incarnation were proved), and only for the one allocation
   * that follows it. The fence still takes its kernel lock and compares: a
   * delayed executor that wrote after the listing makes it refuse, exactly as
   * it would against a separate read.
   */
  #takeHandoffIpAssignment(sourceIp: string): string | undefined {
    const digests = this.#handoffIpAssignments;
    this.#handoffIpAssignments = undefined;
    if (!digests) return undefined;
    return digests[sourceIp] ?? "-";
  }

  #settledByHandoff(): LaunchHandoff | undefined {
    const handoff = this.#input.handoff;
    if (!handoff || !handoffMaySettle(handoff)) return undefined;
    this.#lock();
    const proxyId = this.#controlPlane().proxyContainerId;
    if (handoff.proxy.id !== proxyId) return undefined;
    if (sessionRegistryDigest(this.#input.plan.paths.stateDir, this.#projectIdentity()) !== handoff.registryDigest) {
      return undefined;
    }
    const inspected = createDockerClient(this.#gateway.io, this.#dockerOptions()).inspect([proxyId], { type: "container" });
    let startedAt: unknown;
    let running: unknown;
    try {
      const parsed = JSON.parse(inspected.stdout) as unknown;
      const proxy = Array.isArray(parsed) && parsed.length === 1 ? parsed[0] as Record<string, unknown> : undefined;
      const state = proxy?.Id === proxyId ? proxy.State as Record<string, unknown> | undefined : undefined;
      startedAt = state?.StartedAt;
      running = state?.Running;
    } catch {
      // An unreadable inspection proves nothing: the full preflight decides.
    }
    if (inspected.status !== 0 || typeof startedAt !== "string") return undefined;
    if (running !== true || startedAt !== handoff.proxy.startedAt) {
      throw new StalePreparedRuntimeError("the proxy restarted after startup prepared this launch");
    }
    // A warm-empty state settles admission once, and only bound to exactly
    // what was just re-proved: the registry, the proxy incarnation, and this
    // held lock. One that does not consume runs the full preflight.
    const state = handoff.sessionState;
    if (state.kind === "warm-empty" && !consumeWarmEmptySessionState(state, {
      registryDigest: handoff.registryDigest,
      proxyId,
      proxyStartedAt: handoff.proxy.startedAt,
      lockOwnerToken: this.#input.lifecycleLock.ownerToken,
    })) {
      return undefined;
    }
    return handoff;
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
      // Host-chosen conversation id shape, refused here — before allocation,
      // container creation, or any other Docker effect (spec §2). Resume argv
      // is descriptor-owned recovery authority and must never carry a fresh
      // launch's id; a descriptor that accepts one must always get one for a
      // fresh launch, or a killed client's crash evidence could not be matched
      // back to the same-terminal conversation that started it.
      if (this.#launch?.resume && this.#launch.launchConversationId !== undefined) {
        throw new Error("a resume launch cannot carry a host-chosen conversation id");
      }
      if (this.#launch && !this.#launch.resume && descriptor.launchConversationIdFlag
        && this.#launch.launchConversationId === undefined) {
        throw new Error(`a fresh ${descriptor.id} launch requires a host-chosen conversation id`);
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
        ...(this.#launch?.launchConversationId !== undefined
          ? { launchConversationId: this.#launch.launchConversationId }
          : {}),
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
    let authority = this.#participantAuthorityReclaimingStaleCallbacks();
    this.#ingressParticipants = authority.ingressParticipants;
    this.#participantNetwork = Object.freeze({
      networkId: authority.networkId,
      networkName: authority.networkName,
      subnet: authority.subnet,
    });
    // Startup settled the project's sessions under the lock this launch still
    // holds, in one of two ways. Either its reconcile saw nothing that needed
    // repair, or its warm evidence proved there were no session files, no
    // session participants, no records, and no session containers, so it had
    // nothing to reconcile. Either way, while the registry and proxy
    // incarnation are still exactly what it left, repeating the reconcile (and
    // the orphan sweep) would observe the same state again. Neither path
    // revoked a dead owner or removed an orphan container, so no callback
    // forwarder went away since the participant proof above was taken.
    const settledByHandoff = this.#settledByHandoff();
    if (settledByHandoff) {
      // A warm-empty state saw no session file, so no address is reserved.
      this.#reservedSessionFileIps = settledByHandoff.sessionState.kind === "reconciled"
        ? settledByHandoff.sessionState.reservedSourceIps
        : [];
      this.#handoffIpAssignments = settledByHandoff.ipAssignmentDigests;
      this.#lock();
      this.#assertNoQuarantinedSessionRecords();
    } else {
      // The whole recovery region, in one pass: reconcile ends the records
      // whose owners are gone through the shared ordered teardown, sweeps the
      // files and containers that answer to nobody, and republishes
      // eligibility from what survived — all before the allocation below,
      // inside this same held lock.
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
      const orphansCleaned = this.#cleanPreexistingOrphans();
      if (reconciled.deadOwnersRevoked.length > 0
        || reconciled.orphanContainersRemoved.length > 0
        || orphansCleaned > 0) {
        // Ending a dead owner's session, or removing an orphan container, also
        // removed its callback forwarder, so the participant proof taken before
        // reconcile names an endpoint that is gone. Take it again, under the
        // same held lock, before the baseline.
        this.#lock();
        authority = createControlPlaneInternalParticipantAuthority({
          plan: this.#input.plan,
          context: this.#input.context,
          lifecycleLock: this.#input.lifecycleLock,
          io: this.#gateway.io,
        });
        this.#ingressParticipants = authority.ingressParticipants;
      }
    }
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
   * The internal participant proof, after reclaiming dead callback routes.
   *
   * A callback forwarder whose session is gone (a killed launcher's leftover)
   * makes the proof refuse. Only then — so the healthy path spends no Docker
   * call on it — are forwarders that route to no running session removed under
   * the held lock, and the proof is taken once more. With nothing to reclaim,
   * the original refusal stands.
   */
  #participantAuthorityReclaimingStaleCallbacks(): ReturnType<typeof createControlPlaneInternalParticipantAuthority> {
    const create = () => createControlPlaneInternalParticipantAuthority({
      plan: this.#input.plan,
      context: this.#input.context,
      lifecycleLock: this.#input.lifecycleLock,
      io: this.#gateway.io,
    });
    try {
      return create();
    } catch (refusal) {
      let reclaimed = 0;
      try {
        this.#lock();
        reclaimed = reclaimStaleSessionMcpCallbackForwarders({
          io: this.#gateway.io,
          dockerOptions: this.#dockerOptions(),
          projectId: this.#input.plan.projectId,
          internalNetwork: `${this.#input.plan.composeProjectName}_agent_internal`,
        });
      } catch (reclaimFailure) {
        throw new AggregateError([refusal, reclaimFailure], refusal instanceof Error ? refusal.message : String(refusal));
      }
      if (reclaimed === 0) throw refusal;
      this.#lock();
      return create();
    }
  }

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
    // Every address an ingress forwarder still splices to is reserved too, for
    // any purpose and whatever its session's state: a forward or callback
    // route that outlived its session must not reach the next session given
    // that address.
    const forwarderTargets = this.#ingressParticipants
      .flatMap((participant) => participant.targetIp === undefined ? [] : [participant.targetIp]);
    const candidates = [...new Set([...this.#reservedSessionFileIps, ...forwarderTargets])];
    if (candidates.length === 0) return [];
    const prefix = this.#network().subnet.split("/")[0]?.split(".").slice(0, 3).join(".");
    if (prefix === undefined || prefix.length === 0) return [];
    return candidates.filter((address) => address.startsWith(`${prefix}.`));
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

  #proveNamedVolumes(plan: SessionContainerCreatePlan): SessionNamedVolumeProof {
    const request = sessionNamedVolumeInspectRequest(plan);
    if (!request) return validateSessionNamedVolumeInspect("[]", plan);
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
    return validateSessionNamedVolumeInspect(volumeResult.stdout, plan);
  }

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
    const namedVolumeProof = this.#proveNamedVolumes(plan);
    this.#lock();
    const assignment = this.#takeHandoffIpAssignment(plan.record.sourceIp)
      ?? executeSessionFileCommand(
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
    // The durable record now names the exact container, so the reservation can
    // bind its forwarder to it. It runs beside the evidence write, the
    // foreground start, and the running proof, and finishes before them: it
    // starts first and its budget is no longer than the proof's.
    this.#startSessionIngressReservation(provisioning);
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
      const launchConversationId = this.#launch.launchConversationId;
      const metadata = createSessionMetadata(
        this.#input.context,
        this.#gateway.io,
        this.agent,
        this.#require(this.#displayIdentity, "session display identity").agentCommand,
        {
          id: provisioningPlan.record.sessionId,
          sessionContainerName: provisioningPlan.record.containerName,
          ...(resumeConversationId !== undefined ? { resumeConversationId } : {}),
          ...(launchConversationId !== undefined ? { launchConversationId } : {}),
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
   *                `attached`, and the host stamps the lease it handed out,
   *                once the entry has handed off (`awaitHandoff`);
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
    // The file now exists, and from here every failure takes it back through
    // the ordered teardown (file first): `#fileMayExist` already routes the
    // ladder there. The durable record stays provisioning-running until the
    // entry has handed off (`awaitHandoff`).
    this.#fileWritten = outcome.file;
    this.#admittedRecord = record;
  };

  /**
   * Reports the admitted session `attached`: the durable record, the plan
   * bound to it, the host status stamp,.
   *
   * Called once, by `awaitHandoff`, after the entry has handed off (or the
   * wait has ended without that answer). A failure here would leave a file the
   * proxy serves under a record this launch is about to tear down, so the
   * window is closed here rather than left to the caller's teardown to notice.
   */
  #confirmAttached = async (record: SessionContainerRecordV2): Promise<void> => {
    const file = this.#require(this.#fileWritten, "admitted session file");
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
      this.#admittedRecord = undefined;
      // Durable, not best-effort: the record above is already written as
      // `attached`, so from here a resume's own evidence is this terminal's
      // only record of the conversation (security review F3, decision 10).
      this.#attached = true;
      this.#lock();
      this.#stampSessionHostStatus(file, "served");
    } catch (error) {
      this.#deleteSessionFileBestEffort(record);
      throw error;
    }
  };

  /**
   * One daemon-side read of whether the entry has handed off. Never throws:
   * a failed read, a read that outlived `timeoutMs`, an unparseable answer,
   * and a missing anchor are all `unreadable`. The read is synchronous, so its
   * own timeout is what keeps the ceiling a real bound on the lock hold: a
   * hung daemon or CLI is killed, not waited out.
   */
  #observeEntryHandoff(record: SessionContainerRecordV2, timeoutMs: number): SessionContainerTopHandoff {
    try {
      const anchor = this.#require(this.#fileAnchor, "session-file anchor");
      const plan = this.#require(this.#plan, "session-container create plan");
      const result = executeSessionDockerCommand(
        sessionContainerTopCommand(record, this.#projectIdentity()),
        (executable, args) => this.#gateway.io.capture(executable, [...args], {
          ...this.#dockerOptions(SESSION_CONTAINER_TOP_MAX_BYTES),
          timeout: timeoutMs,
          killSignal: "SIGKILL",
        }),
      );
      if (result.status !== 0) return "unreadable";
      return parseSessionContainerTopHandoff(result.stdout, {
        anchorPid: anchor.dockerPid,
        init: sessionContainerTemplateInit(plan.template),
      });
    } catch {
      return "unreadable";
    }
  }

  /**
   * Waits, still holding the lifecycle lock `activate` held, until the session
   * entry has handed off to the agent, and only then reports `attached`.
   *
   * The gap this closes: the proxy serves the session from the moment its file
   * is written, but the entry execs the agent only once its readiness probe
   * has seen that. A proxy replacement landing in between — possible as soon
   * as this launch released the lock — left the entry polling a proxy that no
   * longer served it, and a recovery slower than the entry's own bound ended
   * the session with exit 111 before the agent ever ran. Every lifecycle writer
   * that could replace the proxy needs this lock, so holding it here moves the
   * replacement after the handoff.
   *
   * The wait ends, and `attached` is reported, on the first of:
   *
   *   handed-off   the anchored process no longer runs the entry;
   *   foreground   the foreground stream ended. Nothing is concluded here: the
   *                attached wait's own lost-stream classification decides
   *                whether the container exited or only the stream was lost,
   *                exactly as it did before this step existed;
   *   unreadable   the daemon's answer cannot say (reported once, unless the
   *                foreground ends within the exit bridge: a container that
   *                has just stopped has no process table to list);
   *   ceiling      `SESSION_HANDOFF_WAIT_CEILING_MS` (reported once) — the
   *                project image may replace the entry with one that never
   *                execs, and no launch may hold the project lock for long.
   *                Every daemon read is itself cut off at the time remaining,
   *                so a hung daemon cannot stretch the hold past it. The
   *                ceiling is lowered to what is left of the launch's
   *                lock-hold budget (`launch-lock-hold.ts`), so a slow start
   *                or admission shortens this wait instead of the hold
   *                outgrowing another command's lock wait.
   *
   * The process table read is container-controlled data, so it only ever
   * decides *when* this launch reports; it grants nothing, and its text is
   * never echoed.
   */
  awaitHandoff = async (): Promise<void> => {
    this.#lock();
    // The foreground ended before the grant: there is nothing to attach, and
    // the attached wait returns that outcome.
    if (this.#preAttachCompletion) return;
    const record = this.#require(this.#admittedRecord, "admitted provisioning-running record");
    const foreground = this.#require(this.#foreground, "foreground attach handle");
    const startedAt = this.#nowMonotonicMs();
    // The wait never carries this launch's one continuous lock hold past its
    // deadline: when admission (or startup before it, under a handed-off lock)
    // has used most of the budget, the wait is shorter than the ceiling, and
    // ends the way the ceiling does.
    const holdLeftMs = Math.max(0, this.#lockHoldDeadlineMs - startedAt);
    const ceilingMs = Math.min(SESSION_HANDOFF_WAIT_CEILING_MS, holdLeftMs);
    const remainingMs = (): number => ceilingMs - (this.#nowMonotonicMs() - startedAt);
    let foregroundEnded = false;
    void foreground.completion.then(() => { foregroundEnded = true; });
    /** Waits up to `ms` for the foreground to end; true when it has. */
    const foregroundEndsWithin = async (ms: number): Promise<boolean> => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          foreground.completion,
          new Promise<void>((resolve) => {
            timer = setTimeout(resolve, Math.max(0, ms));
            timer.unref?.();
          }),
        ]);
      } finally {
        if (timer) clearTimeout(timer);
      }
      return foregroundEnded || currentSessionContainerForegroundCompletion(foreground) !== undefined;
    };
    for (;;) {
      this.#lock();
      if (foregroundEnded || currentSessionContainerForegroundCompletion(foreground)) break;
      const remaining = remainingMs();
      if (remaining <= 0) {
        if (ceilingMs < SESSION_HANDOFF_WAIT_CEILING_MS) {
          warn("the session entry did not hand off to the agent before this launch had to release the project lifecycle lock; reporting the session attached now");
        } else {
          warn(`the session entry did not hand off to the agent within ${SESSION_HANDOFF_WAIT_CEILING_MS} ms; reporting the session attached now (the proxy has not served it yet, or the project image replaces the Runfree session entry)`);
        }
        break;
      }
      // spawnSync refuses a fractional timeout (the monotonic clock is), which
      // would make every read unreadable and end the wait at once.
      const observed = this.#observeEntryHandoff(record, Math.ceil(Math.max(remaining, SESSION_HANDOFF_MIN_READ_MS)));
      this.#lock();
      if (observed === "handed-off") break;
      if (observed === "unreadable") {
        if (!await foregroundEndsWithin(FOREGROUND_EXIT_BRIDGE_TIMEOUT_MS)) {
          warn("could not observe the session entry handing off to the agent; reporting the session attached now");
        }
        break;
      }
      if (await foregroundEndsWithin(Math.min(SESSION_HANDOFF_POLL_MS, remainingMs()))) break;
    }
    this.#lock();
    await this.#confirmAttached(record);
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
    await this.#completeSessionIngress();
    this.#lock();
    await this.#admitThroughSessionFile(provisioning.record);
  };

  /**
   * Starts reserving the session-owned ingress (the MCP OAuth callback port)
   * beside the session container's start. Launch mode only. Ingress intent is
   * recorded before the reservation's first effect, so every failure path
   * proves the ingress gone before the record — and with it the address the
   * ingress targets — is released.
   */
  #startSessionIngressReservation(record: SessionContainerRecordV2): void {
    if (!this.#launch) return;
    const lifecycle = this.#input.sessionIngress === undefined
      ? sessionMcpCallbackLifecycle(this.#input.context, this.#gateway.io)
      : this.#input.sessionIngress;
    if (!lifecycle) return;
    const owner: SessionCallbackOwner = Object.freeze({
      sessionId: record.sessionId,
      containerId: this.#require(record.containerId, "session container id"),
      sourceIp: record.sourceIp,
      internalNetwork: this.#network().networkName,
    });
    this.#lock();
    this.#ingressMayExist = true;
    this.#ingress = Object.freeze({
      lifecycle,
      owner,
      reservation: this.#tasks.start("session-ingress-reserve", () => lifecycle.reserve(owner)),
    });
  }

  /**
   * Completes the reserved ingress after the running proof and before the
   * session file: attaches it, starts the in-session bridge (which announces
   * the port), and proves the path, while the session entry still waits, so
   * no client starts before its callback port exists. A failure of either
   * phase fails the launch, and the unadmitted cleanup that follows proves
   * the ingress gone before the record goes.
   */
  #completeSessionIngress = async (): Promise<void> => {
    const ingress = this.#ingress;
    if (!ingress) return;
    const reserved = await ingress.reservation.result();
    this.#lock();
    await ingress.lifecycle.complete(ingress.owner, reserved);
  };

  /** Waits for every branch started beside the foreground steps, then asserts the lock. */
  settleTasks = (): Promise<void> => this.#tasks.settleAll();

  /** How many branches started beside the foreground steps are still in flight. */
  pendingTasks = (): number => this.#tasks.pending();

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
    const waitForCompletion = (): Promise<SessionAdmissionLaunchOutcome> => waitForAttachedSessionCompletion({
      foreground,
      cadenceMs: sessionHeartbeatCadenceMs(),
      beat: () => this.#beatSessionFile(),
      adoptDurableSelectionIfChanged: (signal) => this.#adoptDurableSelectionIfChanged(signal),
      classifyAdoptionFailure: (error) => {
        if (error instanceof SessionLockAcquisitionAbortedError) return "abort";
        if (error instanceof SessionReplacementPendingError
          || error instanceof SessionLockAcquisitionTimeoutError
          || (error instanceof RuntimeObservationError && error.evidence.kind === "observation-unavailable")) {
          return "preserve";
        }
        return "fatal";
      },
      releaseLockForWait: () => sessionLockManager.releaseForWait(),
      onBeatWritten: (file) => {
        this.#fileWritten = file;
        this.#stampSessionHostStatus(file, "served");
      },
      onBeatRetrying: () => {
        const written = this.#fileWritten;
        if (written) this.#stampSessionHostStatus(written, "retrying");
      },
      leaseExpiry: () => this.#fileWritten?.aliveUntil,
      classifyLostStream: () => this.#classifyLostForegroundStream(),
      reattach: (current) => this.#reattachForeground(current),
      reportCompletion: (completion) => this.#reportForegroundCompletion(completion),
      reportInspectedExit: (status) => {
        this.#foregroundOutcome = Object.freeze({ status, signal: null });
        return this.#foregroundOutcome;
      },
    });

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
    // A reservation still in flight may yet create a forwarder; nothing is
    // removed until it has settled.
    await this.#tasks.settleAll();
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
    if (this.#ingressMayExist) {
      // A route to this session's address must be proved gone before the
      // record that reserves the address is released. When it cannot be, the
      // record stays: this owner exits, and the next launch's reconcile runs
      // the shared teardown, which retries the same removal first.
      try {
        removeSessionMcpCallbackIngress({
          io: this.#gateway.io,
          dockerOptions: this.#dockerOptions(),
          projectId: preflight.expectedProject.projectId,
          sessionId: record.sessionId,
          sourceIp: record.sourceIp,
        });
        this.#ingressMayExist = false;
      } catch (error) {
        throw new AggregateError(
          [...failures, error],
          "unadmitted session cleanup kept its record because its MCP OAuth callback forwarder could not be proved removed",
        );
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
    await this.#tasks.settleAll();
    await this.#tearDownSessionFileSession();
  };

  /**
   * Applies the outcome-aware session evidence rule after a launch: status 0
   * consumes the evidence; any other outcome (nonzero, signal, or a thrown
   * failure passed as `undefined`) preserves it as interrupted host evidence.
   * A resume launch that never reached `attached` always removes its
   * transient evidence instead, so one failed attempt cannot mint a second,
   * less precise recovery item beside the claimed original. A resume launch
   * that *did* reach `attached` and then ended non-zero — a second Docker
   * stop while tab 2 is resuming tab 1's interrupted session — keeps its own
   * evidence as interrupted instead: it carries this terminal's own ids, so
   * tab 2 is the one `runfree resume` asks next (security review F3,
   * decision 10). The returned outcome carries `resumeRecordKept: true` in
   * that case, so the claim layer can consume the original it claimed even
   * though the exit status itself is non-zero.
   */
  finalizeSessionEvidence(outcome: SessionAdmissionLaunchOutcome | undefined): SessionAdmissionLaunchOutcome | undefined {
    outcome ??= this.#foregroundOutcome ?? this.#preAttachCompletion;
    this.#foregroundOutcome = undefined;
    this.#preAttachCompletion = undefined;
    const metadata = this.#sessionEvidence;
    if (!metadata) return outcome;
    const resumeRecordKept = this.#launch?.resume !== undefined && this.#attached && outcome?.status !== 0;
    // Each evidence file has one exact session id and is not part of the
    // whole-registry admission generation. Finalize it even if bounded teardown
    // reacquisition failed; otherwise one lock timeout leaves both registry
    // residue and misleading open host evidence.
    if (outcome?.status === 0 || (this.#launch?.resume !== undefined && !this.#attached)) {
      removeSessionMetadata(this.#input.context, metadata.id);
    } else {
      markSessionInterrupted(this.#input.context, metadata, outcome?.status ?? undefined);
    }
    // Cleared only after the filesystem effect succeeded: a removal that threw
    // on the success path must leave the handle populated so the caller's
    // failure-path finalize can still preserve the evidence as interrupted
    // instead of silently orphaning an open metadata file.
    this.#sessionEvidence = undefined;
    return resumeRecordKept && outcome ? { ...outcome, resumeRecordKept: true } : outcome;
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
  histogram: OperationHistogram,
  lockHoldMs: () => number,
): SessionAdmissionLaunchSteps {
  const timed = (phase: string, fn: () => Promise<void>) => (): Promise<void> => timings.timeAsync(phase, fn);
  // The handoff wait is the last step before the session entry execs the
  // agent (it ends once the entry has handed off), so the histogram at that
  // point is exactly the admission's Docker work before agent start (plan
  // Phase 0), the handoff polls included. The categories are verbs only and
  // always sum to the gateway count printed beside them.
  const awaitHandoff = async (): Promise<void> => {
    await timings.timeAsync("admission:await-handoff", steps.awaitHandoff);
    for (const line of histogram.lines()) timings.report("admission-ops", line);
    timings.report("session-admission", `docker-operations-before-agent=${steps.dockerOperationCount()}`);
    // The launch's one continuous lifecycle-lock hold, measured where it ends
    // (the attached wait releases the lock next): the live suite's evidence
    // that the hold stayed inside its budget.
    timings.report("session-admission", `lifecycle-lock-hold-ms=${Math.round(lockHoldMs())}`);
  };
  return Object.freeze({
    agent: steps.agent,
    nowMs: steps.nowMs,
    dockerOperationCount: steps.dockerOperationCount,
    preflight: timed("admission:preflight", steps.preflight),
    allocate: timed("admission:allocate", steps.allocate),
    createStarted: timed("admission:create-started", steps.createStarted),
    proveRunning: timed("admission:prove-running", steps.proveRunning),
    activate: timed("admission:activate", steps.activate),
    awaitHandoff,
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
 * Whether a handoff may settle admission without its full preflight: a
 * reconcile that saw only settled state, or a warm-empty state this process
 * minted and nobody has consumed. A peek only; `#settledByHandoff` consumes.
 */
function handoffMaySettle(handoff: LaunchHandoff | undefined): boolean {
  if (!handoff) return false;
  return handoff.sessionState.kind === "reconciled"
    ? handoff.sessionState.inventoryClean
    : isWarmEmptySessionState(handoff.sessionState);
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
  // The manager wraps the lock it was built from; the owner token is what
  // proves it is the handed-off lock rather than a lock taken since.
  if (input.handoff && input.handoff.lockOwnerToken !== lifecycleLock.ownerToken) {
    throw new Error("a launch handoff must be admitted under its own lifecycle lock");
  }
  const prepared = consumePreparedRuntime({
    preparedRuntime: input.preparedRuntime,
    lifecycleLock,
    io: input.io,
    // Only a handoff that may settle admission (`#settledByHandoff`) skips
    // the marker re-read; any other runs the full preflight, so it re-reads
    // the marker too.
    ...(handoffMaySettle(input.handoff) ? { handoff: input.handoff } : {}),
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
    histogram?: OperationHistogram,
  ): InternalBuiltinAdmissionProbeSteps => {
    resolvedInput.lifecycleLock.assertHeld();
    const gateway = createSessionAdmissionDockerGateway({
      io: resolvedInput.io,
      ...(resolvedInput.foregroundSpawner ? { foregroundSpawner: resolvedInput.foregroundSpawner } : {}),
      ...(histogram ? { histogram } : {}),
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
    const histogram = timings.enabled ? createOperationHistogram() : undefined;
    let steps: InternalBuiltinAdmissionProbeSteps | undefined;
    try {
      steps = stepsFor(kind, options, histogram);
      const launchSteps = histogram ? timedSessionAdmissionLaunchSteps(steps, timings, histogram, steps.lockHoldMs) : steps;
      try {
        const outcome = await runInternalSessionAdmissionLaunch(launchSteps);
        const finalized = steps.finalizeSessionEvidence(outcome);
        resolvedInput.lifecycleLock.assertHeld();
        return finalized ?? outcome;
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
      // Every cleanup path settles the launch's branches first; this is the
      // backstop, so nothing started under the lock outlives the launch that
      // holds it. Only a branch still in flight is waited on, so a launch that
      // already lost the lock reports its own failure, not a second one.
      try {
        if (steps && steps.pendingTasks() > 0) await steps.settleTasks();
      } finally {
        if (timings.enabled && steps) {
          timings.report("session-admission", `docker-operations=${steps.dockerOperationCount()}`);
          timings.report("teardown-path", steps.teardownPath());
        }
        inFlight = false;
      }
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
