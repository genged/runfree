import { LIFECYCLE_OPERATION_BUDGET_MS, withLifecycleOperationBudget } from "./lifecycle-operation-budget.ts";
import { launchHandoffSpanFits } from "./launch-lock-hold.ts";
import { captureRebindTrustReceipt } from "./rebind-trust-receipt.ts";
import { isDeepStrictEqual } from "node:util";
import { readConfig } from "../config.ts";
import { readControlApprovalSelection } from "../control/approvals.ts";
import { containExactOwnedProxy, observeExactProxy } from "./proxy-containment.ts";
import { withRebindBudgetIO } from "./control-plane-rebind-budget.ts";
import { RuntimeObservationError, type RuntimeFailureKind } from "./observation-failure.ts";
import { inspectRebindCreation, rebindParticipantIsAbsent } from "./control-plane-rebind-docker.ts";

import { projectHash } from "../project-identity.ts";
import { runfreeLog, warn } from "../warnings.ts";
import { waitForProxyFirewallReadiness } from "./proxy-firewall-readiness.ts";
import { planValidatedIngressForwardersForRebuild } from "./ingress-forwarder-ownership.ts";
import { reclaimStaleSessionMcpCallbackForwarders } from "./session-callback-ingress.ts";
import { prepareEffectiveControlsForLaunch } from "../control/workflow.ts";
import {
  convergeEffectivePolicyGeneration,
  effectiveControlSelectionForGeneration,
  readActiveControlSelection,
  readActiveEffectiveControl,
  readConvergedPolicyReceipt,
  readEffectiveHostServices,
} from "../control/effective.ts";
import { validateNetworkPolicy } from "@runfree/runtime-contracts/network-policy";
import { hostServiceOwnerWarningsFromSnapshot, probeHostListeners } from "../host-listener-snapshot.ts";
import { projectHasRegisteredHostServicePorts, recordedHostServiceOwners, recordProjectHostServicePorts } from "../host-service-registry.ts";
import type { EffectiveHostServices } from "./probes.ts";
import {
  composeManagedSessionVolumeLogicalNames,
  emptyDependencyOverlayPlan,
  ensureComposeManagedSessionVolumes,
  ensureDependencyVolumeOwnership,
  prepareDependencyOverlayPlanResult,
  type PreparedDependencyOverlayPlan,
} from "./dependency-overlays.ts";
import {
  containerMissingNetwork,
  createRuntimeDocker,
  dockerClientEnvOptions,
  lastObservedDockerDaemonIdentity,
  parseDockerJson,
  type RuntimeDocker,
} from "./docker.ts";
import { createDockerClient } from "./docker-client.ts";
import { runFencedProjectRebuildTeardown } from "./destroy.ts";
import { runtimeComponentDiagnosticLines } from "./component-diagnostics.ts";
import {
  readEffectiveControlPlaneV2,
  readControlPlaneMaterializationV2,
  readRetainedDesiredSessionAgentV2,
  type ControlPlaneEffectiveSelectionV2,
} from "./component-state-v2.ts";
import {
  effectiveControlPlaneMatchesLiveRuntimeValidationV2,
  effectiveControlPlaneMatchesRuntimeValidationV2,
  proveCandidateControlPlaneV2,
  proveAndSelectEffectiveControlPlaneV2,
  reproveRecordedCandidateControlPlaneV2,
} from "./control-plane-effective-proof.ts";
import { composeProjectName } from "./env.ts";
import {
  type HostGitRelativeWorktreesCapability,
  prepareGitRepositoryLayoutResult,
  probeHostGitRelativeWorktrees,
  refuseGitLayoutUnusableByHostGit,
  serializeGitLayoutPlan,
} from "./git-layout.ts";
import {
  cleanupRunfreeImages,
  ensureRuntimeMaterialized,
  imageCleanupInputsDigest,
  type RuntimeCleanupCandidates,
  existingActiveRuntimePlan,
  materializeRetainedRebindRuntimePlan,
  RuntimeImageBuildStatus,
  selectEffectiveRuntimePlan,
  selectPreparedSessionAgent,
} from "./images.ts";
import {
  createRuntimePlan,
  runtimeContextFromActivePlan,
  runtimeContextFromPlan,
  type ActiveRuntimePlan,
  type RuntimePlan,
} from "./plan.ts";
import { writeProjectRecoveryPointer } from "./recovery.ts";
import {
  createRuntimeSecurityContract,
  parseRuntimeSecurityContractProbe,
  runtimeSecurityContractProbeScript,
  validateRuntimeSecurityContractEvidence,
  type RuntimeContainerContract,
  type RuntimeSecurityContract,
  type RuntimeSecurityContractEvidence,
  type RuntimeSecurityContractProof,
} from "./security-contract.ts";
import {
  activeAgentSessions,
  activeOrStartingAgentSessions,
  confirmRebuildIfActiveSessions,
  projectLifecycleLockPath,
  serviceList,
  tryAcquireProjectLifecycleLockWithRetry,
  warnDeferredRuntimeUpgrade,
  type ProjectLifecycleLock,
  type RebuildOptions,
} from "./sessions.ts";
import {
  assertSafeRuntimePolicyPath,
  ensureAgentState,
  ensureSandboxGitConfig,
  removeRuntimeValidationMarker,
  runtimeValidationMarkerStatus,
  writeRuntimeValidationMarkerResult,
  observeRuntimeValidationProof,
  type RuntimeValidationProof,
} from "./state.ts";
import {
  formatTopologyIssues,
  validateRuntimeTopologyWithProof,
} from "./topology.ts";
import type { DenyByDefaultObservationV1 } from "./control-plane-deny-proof.ts";
import { tokenSyncComponentEvidenceIssue } from "./upgrade-classification.ts";
import { ensureAgentCaBundle, waitForProxyCaPublished } from "./ca-bundle.ts";
import { EPHEMERAL_HELPER_FENCE_REQUIRED } from "./ephemeral-helper.ts";
import { reclaimHelperResidue, type EphemeralHelperFence } from "./ephemeral-helper-residue.ts";
import type {
  ActiveAgentSession,
  DockerContainerInspect,
  RuntimeAdminIntent,
  RuntimeContext,
  RuntimeIO,
  TokenResolutionReceipt,
} from "./types.ts";
import {
  listQuarantinedSessionContainerRecordNamesV2,
  listSessionContainerRecordsV2,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import { readSessionHostStatus } from "./session-host-status.ts";
import { sessionRecordLiveUnderSessionFiles, sessionRecordOwnerLiveness } from "./session-record-liveness.ts";
import { planRuntimeUpgradeV2 } from "./upgrade-plan-v2.ts";
import {
  assertControlPlaneRebindReceiptForTokenSync,
  ControlPlaneRebindCandidateMismatchError,
  runCompatibleControlPlaneRebind,
} from "./control-plane-rebind-coordinator.ts";
import { readControlPlaneRebindTransaction } from "./control-plane-rebind.ts";
import { createRetainedSessionRebindProofPlan } from "./session-admission-driver-preflight.ts";
import { validateSessionContainerInspect } from "./session-container-proof.ts";
import { compileAllowedSessionAgentMaterializationsV2 } from "./session-materialization-eligibility.ts";
import {
  ensureSessionEligibilityPublished,
  observeProxyStartedAt,
} from "./session-eligibility-publication.ts";
import { reconcileSessions, type SessionReconcileResult } from "./session-reconcile.ts";
import {
  pendingSessionFileAdmissionRecords,
  reclaimPendingSessionAdmissions,
} from "./session-admission-pending-reclaim.ts";
import { waitForSessionAdmissionFirewallSetEmpty } from "./session-file-publisher.ts";
import {
  attachLaunchHandoff,
  markLaunchHandoffDeclined,
  mintPreparedRuntime,
  type LaunchHandoff,
  type PreparedRuntime,
} from "./prepared-runtime.ts";
import { createRuntimeTimings, type RuntimeTimings } from "./timings.ts";
import {
  assertWarmValidation,
  recordWarmRuntimeProof,
  removeWarmProofRecord,
  tryWarmRuntimeValidation,
  type WarmProofInput,
  type WarmProofVerdict,
  type WarmValidation,
} from "./warm-proof.ts";
import { TOKEN_SYNC_DEFERRED_STATUS } from "./constants.ts";
import { imageCleanupStampMatches, writeImageCleanupStamp } from "./image-cleanup-stamp.ts";
import { createOperationHistogram, withOperationHistogram } from "./operation-histogram.ts";
import { remedy } from "../remedies.ts";
import { sessionRegistryDigest } from "./launch-handoff.ts";
import { proveWarmEmptySessionState, type WarmEmptySessionState } from "./warm-empty-session-state.ts";
import {
  consumeWarmPeerValidation,
  tryWarmPeerValidation,
  type WarmPeerConsumptionBinding,
  type WarmPeerValidation,
} from "./warm-peer-proof.ts";
import { setMcpLogContext } from "./mcp.ts";

const RETAINED_AGENT_TEMPLATE_REMEDY =
  "restart admission restoration requires the retained current agent template; prepare it with a compatible CLI and retry";

export const COMPOSE_UP_FAILURE_REMEDY = `Docker Compose failed to start the runtime; try \`${remedy.stop()}\`, then \`${remedy.up()}\`; if that fails, \`${remedy.rebuild()}\` recreates the runtime`;
export type { RebuildOptions } from "./sessions.ts";

export type RuntimeStartResult =
  | {
      kind: "ready";
      status: 0;
      fastPath: boolean;
      preparedRuntime: PreparedRuntime;
  // True when this run (re)created the proxy container, so it booted with the
  // current on-disk policy and the startup token sync already populated its
  // tmpfs. Callers use this to skip a redundant policy reload.
      proxyRecreated?: boolean;
      tokenResolutionReceipts?: TokenResolutionReceipt[];
      /**
       * `receipt-gated`: this launch reused proxy-held credentials without
       * re-reading their sources (launch plan D4); the auto-refresh watcher
       * owes one immediate source-truth pass. `source-truth` (or absent):
       * every source was read before the launch.
       */
      credentialFreshness?: "source-truth" | "receipt-gated";
    }
  | {
      kind: "failed";
      status: number;
      fastPath: false;
    };

/**
 * What startup needs to hand its held lifecycle lock to the launch that asked
 * for it (sub-second launch plan Task 3). `build` runs only after the last
 * fallible startup step, with the lock still held.
 */
/** Startup held the lock too long to hand it to admission (launch-lock-hold.ts). */
class LaunchHandoffSpanExceededError extends Error {
  constructor() {
    super("startup already held the lifecycle lock longer than a handoff may carry");
  }
}

type LaunchHandoffRequest = Readonly<{
  build: () => LaunchHandoff;
  /** Releases the lock before a deferred sync reads a source. */
  releaseLock: () => void;
  /** Marks the lock as the launch's: startup's `finally` no longer releases it. */
  onHandedOff: () => void;
}>;

type RuntimeStartupAdapters = {
  admin(intent: RuntimeAdminIntent): Promise<number>;
  docker: RuntimeDocker;
};

export type RuntimeUpgradePlan =
  | { action: "none"; services: [] }
  | { action: "token-sync"; services: [] }
  | { action: "proxy-restart"; services: string[] }
  | { action: "component-select"; services: [] }
  | { action: "blocked-incompatible"; reason: "admission-epoch" | "control-plane-topology"; services: [] }
  | { action: "invalid"; reason: string; services: string[] };

function createRuntimeAdapters(context: RuntimeContext, io: RuntimeIO): RuntimeStartupAdapters {
  return {
    admin: (intent) => io.admin(intent, context),
    docker: createRuntimeDocker(context, io, (project) => activeAgentSessions(project, context, io)),
  };
}

// Step-level progress prints only with --verbose (contract D7): the default
// warm launch shows the start line, denials/warnings, and the handoff.
function reportRuntimeProgress(message: string, verbose: boolean | undefined): void {
  if (verbose) runfreeLog(message);
}

// The one always-printed start line.
function reportRuntimeStart(message: string): void {
  runfreeLog(message);
}

function reportRuntimeVerbose(verbose: boolean | undefined, message: string): void {
  if (verbose) runfreeLog(`verbose: ${message}`);
}

async function syncProxyManagedTokens(
  admin: (intent: RuntimeAdminIntent) => Promise<number>,
  verbose?: boolean,
  mode?: "startup-convergence",
): Promise<number> {
  reportRuntimeProgress("syncing proxy-managed tokens", verbose);
  return admin({ kind: "token-sync", verbose: Boolean(verbose), ...(mode ? { mode } : {}) });
}

/**
 * The warm-launch credential sync (launch plan D4, sub-second launch plan
 * Task 5): receipt-gated, resolving no source. When it defers — a due token
 * the preparation did not re-read, a busy control or token-store lock, a
 * runtime that is not ready — nothing was written or removed, so the full
 * source-truth order runs instead: every source is read again (prompts
 * allowed), then synced.
 */
async function syncWarmLaunchTokens(input: Readonly<{
  context: RuntimeContext;
  io: RuntimeIO;
  verbose?: boolean;
  timings: RuntimeTimings;
  /** Runs before any source is read (releases a held lifecycle lock). */
  beforeSourceResolution?: () => void;
}>): Promise<Readonly<{ status: number; freshness: "source-truth" | "receipt-gated" }>> {
  const admin = (intent: RuntimeAdminIntent) => input.io.admin(intent, input.context);
  const gated = await syncProxyManagedTokens(admin, input.verbose, "startup-convergence");
  if (gated !== TOKEN_SYNC_DEFERRED_STATUS) return { status: gated, freshness: "receipt-gated" };
  input.timings.report("token-sync", "deferred source-truth");
  input.beforeSourceResolution?.();
  await input.io.prepareTokenSources?.(input.context);
  return { status: await syncProxyManagedTokens(admin, input.verbose), freshness: "source-truth" };
}

async function finalizeValidatedRuntime(
  plan: ActiveRuntimePlan,
  io: RuntimeIO,
  proof: RuntimeValidationProof | undefined,
  verbose?: boolean,
  proxyRecreated = false,
  lifecycleLock?: ProjectLifecycleLock,
  withCredentialResolution: (work: () => Promise<number>) => Promise<number> = (work) => work(),
  credentialMode: "source-truth" | "receipt-gated" = "source-truth",
  launchHandoff?: LaunchHandoffRequest,
  /** The preparation skipped held tokens (launch plan D4): a source-truth sync must re-read them first. */
  preparedReceiptGated = false,
): Promise<RuntimeStartResult> {
  const context = runtimeContextFromActivePlan(plan);
  const activeContext = { ...context, validatedRuntime: proof };
  const timings = createRuntimeTimings(activeContext.env);
  try {
    lifecycleLock?.assertHeld();
  } catch (error) {
    warn(error instanceof Error ? error.message : String(error));
    return { kind: "failed", fastPath: false, status: 1 };
  }
  {
    const docker = createRuntimeDocker(activeContext, io, (project) => activeAgentSessions(project, activeContext, io));
    const selected = readActiveControlSelection(activeContext.project);
    if (!selected) {
      warn("effective policy selection is missing before credential sync");
      return { kind: "failed", fastPath: false, status: 1 };
    }
    const lastConverged = readConvergedPolicyReceipt(activeContext.project);
    const previous = lastConverged && lastConverged.controlGeneration !== selected.controlGeneration
      ? effectiveControlSelectionForGeneration(activeContext.project, lastConverged.controlGeneration)
      : undefined;
    reportRuntimeProgress("proving effective policy convergence", verbose);
    try {
      lifecycleLock?.assertHeld();
      await timings.timeAsync("control-convergence", () => convergeEffectivePolicyGeneration(activeContext.project, {
        previous,
        probe: async () => {
          lifecycleLock?.assertHeld();
          const receipts = docker.proxyControlReceipts(composeProjectName(activeContext.projectRoot)) ?? {};
          lifecycleLock?.assertHeld();
          return receipts;
        },
        stopRuntime: async () => {
          lifecycleLock?.assertHeld();
          if (!proof) throw new Error("partial policy convergence has no exact proxy proof; safety is unconfirmed");
          containValidationProxy(plan, io, proof.proxyId, lifecycleLock);
        },
      }));
      lifecycleLock?.assertHeld();
    } catch (error) {
      warn(error instanceof Error ? error.message : String(error));
      return { kind: "failed", fastPath: false, status: 1 };
    }
  }
  try {
    lifecycleLock?.assertHeld();
  } catch (error) {
    warn(error instanceof Error ? error.message : String(error));
    return { kind: "failed", fastPath: false, status: 1 };
  }
  if (!proof) {
    warn("prepared runtime requires an exact validation proof");
    return { kind: "failed", fastPath: false, status: 1 };
  }
  let preparedRuntime: PreparedRuntime;
  try {
    lifecycleLock?.assertHeld();
    preparedRuntime = mintPreparedRuntime({ plan, validationProof: proof });
    lifecycleLock?.assertHeld();
  } catch (error) {
    warn(error instanceof Error ? error.message : String(error));
    return { kind: "failed", fastPath: false, status: 1 };
  }
  let credentialFreshness: "source-truth" | "receipt-gated" = "source-truth";
  // A held-lock handoff (sub-second launch plan Task 3) keeps the lifecycle
  // lock through the receipt-gated sync, which resolves no source; a deferral
  // releases it before any source is read, and then there is no handoff.
  const holdLockThroughSync = launchHandoff !== undefined && credentialMode === "receipt-gated";
  let lockReleasedForSync = !holdLockThroughSync;
  const runCredentialSync = holdLockThroughSync
    ? (work: () => Promise<number>) => work()
    : withCredentialResolution;
  const tokenSync = await timings.timeAsync(
    "token-sync",
    () => runCredentialSync(async () => {
      if (credentialMode !== "receipt-gated") {
        // A proxy replaced after a receipt-gated preparation needs every
        // source: re-read them, outside the lock, before the sync.
        if (preparedReceiptGated) await io.prepareTokenSources?.(activeContext);
        return await syncProxyManagedTokens((intent) => io.admin(intent, activeContext), verbose);
      }
      const warm = await syncWarmLaunchTokens({
        context: activeContext,
        io,
        verbose,
        timings,
        ...(holdLockThroughSync
          ? { beforeSourceResolution: () => { lockReleasedForSync = true; launchHandoff.releaseLock(); } }
          : {}),
      });
      credentialFreshness = warm.freshness;
      return warm.status;
    }),
  );
  if (tokenSync === 0 && launchHandoff && !lockReleasedForSync) {
    try {
      lifecycleLock?.assertHeld();
      attachLaunchHandoff(preparedRuntime, launchHandoff.build());
      launchHandoff.onHandedOff();
      timings.report("launch-handoff", "minted");
    } catch (error) {
      // No handoff is not a failure: the launch takes its own lock and runs
      // the full preflight. The lock is still startup's to release.
      if (error instanceof LaunchHandoffSpanExceededError) {
        markLaunchHandoffDeclined(preparedRuntime);
        timings.report("launch-handoff", "skipped hold-span");
      }
      reportRuntimeVerbose(verbose, `launch handoff not minted: ${error instanceof Error ? error.message : String(error)}`);
    }
  } else if (launchHandoff) {
    timings.report("launch-handoff", lockReleasedForSync ? "skipped token-resolution" : "skipped");
  }
  const tokenResolutionReceipts = tokenSync === 0 ? io.takeTokenResolutionReceipts?.() ?? [] : [];
  if (tokenSync === 0) reportRuntimeProgress("runtime startup complete", verbose);
  return tokenSync === 0 ? {
    kind: "ready",
    fastPath: true,
    preparedRuntime,
    proxyRecreated,
    status: 0,
    tokenResolutionReceipts,
    credentialFreshness,
  } : { kind: "failed", fastPath: false, status: tokenSync };
}

function ensureDependencyVolumeOwnershipOrRemoveInvalid(
  context: RuntimeContext,
  io: RuntimeIO,
  docker: RuntimeDocker,
  options: { verbose?: boolean; helperFence?: EphemeralHelperFence; helperImage?: string } = {},
): number {
  const status = ensureDependencyVolumeOwnership(context, io, docker, options);
  if (status === 0) return 0;
  warn("dependency volume ownership setup failed; runtime resources were preserved; repair the reported volume and retry");
  return status;
}

function activeSessionIdentity(session: ActiveAgentSession): string {
  if (session.sessionId) return `session:${session.sessionId}`;
  // Sessionless entries are conservative placeholders (unreadable lifecycle
  // records, failed inspection). Their container tty and root command identify
  // the entry; processCount and display metadata are observations that can
  // change while the confirmation prompt is open.
  return `untracked:${JSON.stringify([session.containerTty, session.command])}`;
}

function hasNewActiveSessions(
  observed: readonly ActiveAgentSession[],
  locked: readonly ActiveAgentSession[],
): boolean {
  const remaining = new Map<string, number>();
  for (const session of observed) {
    const identity = activeSessionIdentity(session);
    remaining.set(identity, (remaining.get(identity) ?? 0) + 1);
  }
  for (const session of locked) {
    const identity = activeSessionIdentity(session);
    const count = remaining.get(identity) ?? 0;
    if (count === 0) return true;
    remaining.set(identity, count - 1);
  }
  return false;
}

const LIVE_ADMISSION_WAIT_ATTEMPTS = 20;
const LIVE_ADMISSION_WAIT_DELAY_MS = 250;

/**
 * Waits briefly for another launch's in-flight session admission to finish
 * before the pre-lock evidence read. The session container is already running
 * while its registration converges, so a quick follow-up invocation lands
 * inside that transaction window routinely; refusing it with recovery guidance
 * would be wrong for a healthy admission. Only a transaction whose recorded
 * owner is provably alive is waited on — an abandoned one (owner dead or
 * unprovable) returns immediately so the planner's refusal is not delayed, and
 * a transaction that outlives the bounded wait is still refused unchanged.
 */
export async function awaitLiveSessionAdmissionQuiescence(
  stateDir: string,
  expectedProject: SessionContainerProjectIdentity,
  options: Readonly<{ attempts?: number; delayMs?: number; env?: NodeJS.ProcessEnv }> = {},
): Promise<void> {
  const attempts = options.attempts ?? LIVE_ADMISSION_WAIT_ATTEMPTS;
  const delayMs = options.delayMs ?? LIVE_ADMISSION_WAIT_DELAY_MS;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    // The records the planner would refuse over, waited on only while one of
    // their owners is still running.
    let pending: readonly SessionContainerRecordV2[];
    try {
      pending = pendingSessionFileAdmissionRecords({
        stateDir,
        records: listSessionContainerRecordsV2(stateDir, expectedProject),
        nowEpochMs: Date.now(),
      });
    } catch {
      // An unreadable registry is the planner's refusal to make.
      return;
    }
    if (!pending.some((record) => sessionRecordOwnerLiveness(record, options.env) === "alive")) return;
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
}

export function planRuntimeUpgradeFromV2State(
  desiredPlan: RuntimePlan,
  context: RuntimeContext,
  docker: RuntimeDocker,
  options: Readonly<{
    /**
     * Leave a pending session admission to the locked reclaim that follows.
     *
     * Only the unlocked pre-plan of a start passes this: under the lifecycle
     * lock, `reclaimPendingSessionAdmissions` finishes every interrupted
     * teardown Docker proves safe and refuses the rest with its own remedy,
     * and the locked plan after it is strict again. Every other caller —
     * `runfree status`, the locked plan — still reports the pending record.
     */
    deferPendingSessionAdmission?: boolean;
  }> = {},
): RuntimeUpgradePlan {
  try {
    const expectedProject = {
      projectId: desiredPlan.projectId,
      composeProject: desiredPlan.composeProjectName,
    };
    const effectiveControlPlane = readEffectiveControlPlaneV2(desiredPlan.paths.stateDir);
    const retainedDesiredSessionAgent = readRetainedDesiredSessionAgentV2(desiredPlan.paths.stateDir);
    const registeredRecords = listSessionContainerRecordsV2(desiredPlan.paths.stateDir, expectedProject);
    const pendingRecords = pendingSessionFileAdmissionRecords({
      stateDir: desiredPlan.paths.stateDir,
      records: registeredRecords,
      nowEpochMs: Date.now(),
    });
    // Deferred, a pending record is the locked reclaim's to decide, so the
    // pre-plan plans as if it were already gone: counted as a live record it
    // would turn an incompatible upgrade into "wait for the sessions to
    // drain", which a dead owner's record never does. If the reclaim refuses,
    // the start stops there; if it succeeds, the strict plan sees exactly this
    // registry.
    const lifecycleRecords = options.deferPendingSessionAdmission
      ? registeredRecords.filter((record) => !pendingRecords.includes(record))
      : registeredRecords;
    const pendingAdmission = !options.deferPendingSessionAdmission && pendingRecords.length > 0;
    const pendingRebind = readControlPlaneRebindTransaction(desiredPlan.paths.stateDir, expectedProject);
    const proxyContainerIds = docker.serviceContainerIds(
      desiredPlan.composeProjectName,
      "proxy",
      { runningOnly: true },
    );
    const action = planRuntimeUpgradeV2({
      desired: desiredPlan.generationV2,
      ...(retainedDesiredSessionAgent?.selectable
        ? {
            desiredSessionAgent: {
              selection: retainedDesiredSessionAgent.selection,
              manifest: retainedDesiredSessionAgent.manifest,
            },
          }
        : {}),
      ...(effectiveControlPlane ? { effectiveControlPlane } : {}),
      ...(proxyContainerIds.length > 0
        ? {
            liveProxies: proxyContainerIds.map((containerId) => ({
              ...expectedProject,
              containerId,
              imageId: effectiveControlPlane?.selection.proxyImageId ?? "unresolved",
            })),
          }
        : {}),
      lifecycleRecords,
      ...(pendingRebind
        ? { pendingTransaction: { ...expectedProject, kind: "control-plane-rebind" as const } }
        : pendingAdmission
          ? { pendingTransaction: { ...expectedProject, kind: "session-admission" as const } }
          : {}),
    });
    switch (action.kind) {
      case "none":
        return runningWarmRuntime(context, docker)
          ? { action: "token-sync", services: [] }
          : { action: "none", services: [] };
      case "select-session-agent":
        return { action: "component-select", services: [] };
      case "restart-compatible-proxy":
        // Active sessions no longer defer a COMPATIBLE proxy restart: the
        // durable rebind transaction stops the old proxy, proves the candidate
        // deny-all, re-proves and rebinds every retained session record, and
        // requires both consumer acknowledgements before selection — sessions
        // keep their containers, IPs, and processes throughout. Incompatible
        // topology or admission-epoch changes never reach this arm; the
        // planner classifies them `block-incompatible` above.
        return { action: "proxy-restart", services: ["proxy"] };
      case "block-incompatible":
        return { action: "blocked-incompatible", reason: action.reason, services: [] };
      case "refuse-invalid":
        return { action: "invalid", reason: action.reason, services: [] };
    }
  } catch (error) {
    return {
      action: "invalid",
      reason: error instanceof Error ? error.message : String(error),
      services: [],
    };
  }
}

/**
 * The durable effective control-plane selection as a value this start can
 * compare against itself, with an unreadable one folded in rather than raised.
 *
 * A control plane materialized before this CLI's admission contract cannot be
 * parsed at all: a pre-cutover manifest carries no `sessionAdmissionSource`,
 * and the reader refuses it rather than reading it as "not files". That is
 * exactly the state a start exists to leave — it materializes the control plane
 * again and selects the result, which replaces what could not be read. Raising
 * here would wedge the project on state no command could clear. The reason is
 * kept in the compared value, so a selection that becomes readable (or stops
 * being readable) during preparation is still a change.
 */
function comparableEffectiveControlPlaneSelection(stateDir: string): unknown {
  try {
    return readEffectiveControlPlaneV2(stateDir)?.selection;
  } catch (error) {
    return { unreadable: error instanceof Error ? error.message : String(error) };
  }
}

function applyRuntimeUpgradePlan(context: RuntimeContext, docker: RuntimeDocker, plan: RuntimeUpgradePlan): number {
  switch (plan.action) {
    case "none":
    case "token-sync":
      return 0;
    case "proxy-restart": {
      warn(`runtime upgrade plan: proxy restart (${serviceList(plan.services)})`);
      return 0;
    }
    case "component-select":
      warn("runtime upgrade plan: select new host materialization");
      return 0;
    case "blocked-incompatible":
      warn(`the runtime was not updated: active sessions use an incompatible ${plan.reason === "admission-epoch" ? "admission epoch" : "control-plane topology"}`);
      warn(`wait for the active sessions to drain (${remedy.sessions()} lists them), then retry the command`);
      return 1;
    case "invalid":
      warn(`the runtime did not start: component evidence is invalid: ${plan.reason}`);
      // Nothing here may pick between contradictory or ambiguous containers,
      // but an operator can. Name the command that clears it, or this refusal
      // repeats on every start with no way out of it.
      warn(`inspect the runtime, then recreate it from the selected effective policy generation with: ${remedy.rebuild()}`);
      return 1;
  }
}

async function repairStaleComposeNetworkState(
  context: RuntimeContext,
  docker: RuntimeDocker,
  options: { lifecycleLock?: ProjectLifecycleLock } = {},
): Promise<number> {
  const project = composeProjectName(context.projectRoot);
  const expectedNetwork = `${project}_agent_internal`;
  const staleContainers = docker.composeContainers(project).filter((container) => containerMissingNetwork(container, expectedNetwork));
  if (staleContainers.length === 0) return 0;
  let lifecycleLock = options.lifecycleLock;
  const releaseLifecycleLock = lifecycleLock === undefined;
  if (lifecycleLock === undefined) {
    lifecycleLock = await tryAcquireProjectLifecycleLockWithRetry(context);
    if (!lifecycleLock) {
      warn(`the stale runtime was not repaired: another Runfree runtime lifecycle change is in progress (lock: ${projectLifecycleLockPath(context)}); retry when it finishes`);
      return 1;
    }
  }
  try {
    const sessions = activeOrStartingAgentSessions(context, docker);
    if (sessions.length > 0) {
      warnDeferredRuntimeUpgrade({
        reason: "full recreate",
        services: ["proxy"],
        sessions,
      });
      return 1;
    }
    // Report the removal after it ran, in the tense of what happened.
    const removal = docker.removeContainers(staleContainers.map((container) => container.id));
    if (removal === 0) warn(`stale Docker network state for ${project} was removed before start`);
    else warn(`stale Docker network state for ${project} could not be removed before start (docker exited ${removal})`);
    return removal;
  } finally {
    if (releaseLifecycleLock) lifecycleLock?.release();
  }
}

function runningWarmRuntime(context: RuntimeContext, docker: RuntimeDocker): boolean {
  const project = composeProjectName(context.projectRoot);
  // Post-cutover, Compose owns only the proxy control plane. Agent containers
  // are admitted per session, so their absence is the normal warm topology.
  return Boolean(docker.runningServiceContainerId(project, "proxy"));
}

function containValidationProxy(plan: ActiveRuntimePlan, io: RuntimeIO, proxyId: string, lifecycleLock?: ProjectLifecycleLock): void {
  if (!lifecycleLock) throw new Error("proxy boundary violation requires fenced containment; runtime safety is unconfirmed");
  containExactOwnedProxy({
    proxyId, projectId: plan.projectId, composeProject: plan.composeProjectName,
    io, env: plan.execution.dockerClientEnv,
    assertAuthority: () => lifecycleLock.assertHeld(),
  });
  warn(`proxy ${proxyId} was contained; session resources were preserved; repair the reported boundary and resume runtime recovery`);
}

export function validateRuntimeTopologyOrRemoveInvalid(
  plan: ActiveRuntimePlan,
  context: RuntimeContext,
  io: RuntimeIO,
  docker: RuntimeDocker,
  options: {
    verbose?: boolean;
    expectedProxyId?: string;
    lifecycleLock?: ProjectLifecycleLock;
    containmentIO?: RuntimeIO;
    helperFence?: EphemeralHelperFence;
    helperImage?: string;
    readOnly?: boolean;
    /**
     * The host services of the effective policy generation the firewall
     * readiness check waited for. Required: the host-service proof (SR10)
     * cannot be skipped by omitting it.
     */
    effectiveHostServices: EffectiveHostServices;
  },
): { denyByDefaultObservation?: DenyByDefaultObservationV1; status: number; failureKind?: RuntimeFailureKind } {
  let boundaryViolated = false;
  const validate = () => validateRuntimeTopologyWithProof(plan, io, {
    onBoundaryViolation: () => { boundaryViolated = true; },
    progress: options.verbose === true,
    verbose: options.verbose,
    expectedProxyId: options.expectedProxyId,
    helperFence: options.helperFence,
    helperImage: options.helperImage,
    effectiveHostServices: options.effectiveHostServices,
  });
  let validation = validate();
  if (validation.issues.length > 0 && reclaimDeadCallbackRoutes(plan, context, io, options)) {
    // A dead session's callback forwarder (a killed launcher's leftover, or
    // an unbound one from before session-owned callbacks) fails the
    // participant check on every later launch; it is reclaimed here, under
    // the held lock, and the topology proved once more from scratch.
    boundaryViolated = false;
    validation = validate();
  }
  if (validation.issues.length === 0) {
    return {
      status: 0,
      ...(validation.denyByDefaultBaseObservation
        ? { denyByDefaultObservation: validation.denyByDefaultBaseObservation }
        : {}),
    };
  }
  warn("runtime topology validation failed; new authority was refused");
  for (const issue of formatTopologyIssues(validation.issues)) warn(`  ${issue}`);
  if (boundaryViolated && options.expectedProxyId) {
    containValidationProxy(plan, options.containmentIO ?? io, options.expectedProxyId, options.lifecycleLock);
  }
  return { status: 1, failureKind: boundaryViolated ? "boundary-violation" : "observation-unavailable" };
}

/**
 * Removes MCP OAuth callback forwarders that route to no running session, when
 * this caller may mutate under the held lifecycle lock. True when anything was
 * removed. A failure to prove what is stale removes nothing and reports the
 * original refusal unchanged.
 */
function reclaimDeadCallbackRoutes(
  plan: ActiveRuntimePlan,
  context: RuntimeContext,
  io: RuntimeIO,
  options: Readonly<{ lifecycleLock?: ProjectLifecycleLock; readOnly?: boolean }>,
): boolean {
  if (options.readOnly || !options.lifecycleLock) return false;
  options.lifecycleLock.assertHeld();
  try {
    return reclaimStaleSessionMcpCallbackForwarders({
      io,
      dockerOptions: dockerClientEnvOptions(context),
      projectId: plan.projectId,
      internalNetwork: `${plan.composeProjectName}_agent_internal`,
    }) > 0;
  } catch (error) {
    warn(`could not reclaim stale MCP OAuth callback forwarders: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

function inspectById(inspects: DockerContainerInspect[] | undefined, id: string): DockerContainerInspect | undefined {
  return inspects?.find((inspect) => inspect.Id === id);
}

function containerContract(contract: RuntimeSecurityContract, name: "agent" | "proxy"): RuntimeContainerContract | undefined {
  return contract.containers.find((container) => container.name === name);
}

function runtimeSecurityContractContainerEvidence(
  context: RuntimeContext,
  io: RuntimeIO,
  containerId: string,
  inspect: DockerContainerInspect,
  contract: RuntimeContainerContract | undefined,
): NonNullable<RuntimeSecurityContractEvidence["agent"]> {
  if (!contract) return { inspect };
  const probe = createDockerClient(io, dockerClientEnvOptions(context)).exec(
    containerId,
    ["sh", "-c", runtimeSecurityContractProbeScript(contract)],
  );
  if (probe.status !== 0) {
    return { inspect };
  }
  return {
    inspect,
    ...parseRuntimeSecurityContractProbe(probe.stdout),
  };
}

function runtimeSecurityContractEvidence(
  context: RuntimeContext,
  io: RuntimeIO,
  docker: RuntimeDocker,
  contract: RuntimeSecurityContract,
): RuntimeSecurityContractEvidence {
  const project = composeProjectName(context.projectRoot);
  // Post-cutover the fixed runtime is proxy-only; the security contract has no
  // agent container, so its evidence is not collected or required here.
  const agentId = undefined;
  const proxyId = docker.runningServiceContainerId(project, "proxy");
  const evidence: RuntimeSecurityContractEvidence = {};
  if (!proxyId) return evidence;
  const client = createDockerClient(io, dockerClientEnvOptions(context));
  const inspects = parseDockerJson<DockerContainerInspect[]>(
    client.inspect([...(agentId ? [agentId] : []), proxyId]),
    "docker inspect runtime security contract",
  );
  const agentInspect = agentId ? inspectById(inspects, agentId) : undefined;
  const proxyInspect = inspectById(inspects, proxyId) ?? inspects?.[agentId ? 1 : 0];
  if (agentId && agentInspect) {
    evidence.agent = runtimeSecurityContractContainerEvidence(
      context,
      io,
      agentId,
      agentInspect,
      containerContract(contract, "agent"),
    );
    if (!evidence.agent.presentPaths) {
      const privateCaProbe = client.exec(agentId, ["sh", "-c", "test ! -e /ca/private/proxy-ca.key"]);
      evidence.agent.presentPaths = privateCaProbe.status === 0 ? [] : ["/ca/private/proxy-ca.key"];
    }
  }
  if (proxyInspect) {
    evidence.proxy = runtimeSecurityContractContainerEvidence(
      context,
      io,
      proxyId,
      proxyInspect,
      containerContract(contract, "proxy"),
    );
  }
  return evidence;
}

function validateRuntimeSecurityContractOrRemoveInvalid(
  contract: RuntimeSecurityContract,
  context: RuntimeContext,
  io: RuntimeIO,
  docker: RuntimeDocker,
  plan: ActiveRuntimePlan,
  proxyId: string,
  lifecycleLock?: ProjectLifecycleLock,
  containmentIO: RuntimeIO = io,
): { proof?: RuntimeSecurityContractProof; status: number; failureKind?: RuntimeFailureKind } {
  let boundaryViolated = false;
  const proof = validateRuntimeSecurityContractEvidence(
    contract,
    runtimeSecurityContractEvidence(context, io, docker, contract),
    { requireLiveProbes: true, scope: "startup", onBoundaryViolation: () => { boundaryViolated = true; } },
  );
  if (proof.ok) return { proof, status: 0 };
  warn("runtime security contract validation failed; new authority was refused");
  for (const issue of proof.issues) warn(`  ${issue.container}: ${issue.code}: ${issue.detail}`);
  if (boundaryViolated) containValidationProxy(plan, containmentIO, proxyId, lifecycleLock);
  return { status: 1, failureKind: boundaryViolated ? "boundary-violation" : "observation-unavailable" };
}

type RuntimeTokenSyncPreparation = {
  failureKind?: RuntimeFailureKind;
  denyByDefaultObservation?: DenyByDefaultObservationV1;
  proof?: RuntimeValidationProof;
  securityProof?: RuntimeSecurityContractProof;
  status: number;
};

export { planValidatedIngressForwardersForRebuild };


const SELECTED_IMAGE_ID_PATTERN = /^sha256:[a-f0-9]{64}$/u;

/**
 * The image an ephemeral helper runs: the bound selected image id when the
 * plan carries the prepared session agent for this exact image reference, so
 * the helper runs the image admission proves and its removal proof compares
 * the immutable id (ruling D1). Otherwise the tag, authorized at removal by
 * the reference string plus the run nonce.
 */
export function ephemeralHelperImage(plan: ActiveRuntimePlan): string {
  const prepared = plan.activeRuntime.preparedSessionAgent;
  if (prepared
    && prepared.selectedAgentImageRef === plan.activeRuntime.agentImage
    && SELECTED_IMAGE_ID_PATTERN.test(prepared.selectedAgentImageId)) {
    return prepared.selectedAgentImageId;
  }
  return plan.activeRuntime.agentImage;
}

/** The fence every helper needs; undefined (helpers refuse) without the lock or containment IO. */
function ephemeralHelperFence(
  plan: ActiveRuntimePlan,
  options: { lifecycleLock?: ProjectLifecycleLock; containmentIO?: RuntimeIO },
): EphemeralHelperFence | undefined {
  if (!options.lifecycleLock || !options.containmentIO) return undefined;
  return { lifecycleLock: options.lifecycleLock, containmentIO: options.containmentIO, stateDir: plan.paths.stateDir };
}

/**
 * Image cleanup, skipped on a launch whose cleanup inputs did not change since
 * the last completed pass (sub-second launch plan Task 4).
 *
 * Cleanup only deletes, so skipping it can only retain garbage; it never
 * changes what a session may do. `runfree up` and `rebuild` (not launches)
 * always run it. The stamp is written only after a pass that reached its end,
 * from the inputs as they are after that pass (the pass itself removes stale
 * materializations), so the next launch compares against what it will see.
 */
function runImageCleanupUnlessUnchanged(input: Readonly<{
  context: RuntimeContext;
  docker: RuntimeDocker;
  io: RuntimeIO;
  launch: boolean;
  timings: RuntimeTimings;
  candidates: RuntimeCleanupCandidates;
}>): void {
  const stateDir = input.context.project.paths.stateDir;
  const projectId = projectHash(input.context.projectRoot);
  const inputsDigest = (): string | undefined => {
    try {
      return imageCleanupInputsDigest(input.context, input.candidates);
    } catch {
      return undefined;
    }
  };
  if (input.launch) {
    const current = inputsDigest();
    if (current !== undefined && imageCleanupStampMatches(stateDir, projectId, current)) {
      input.timings.report("image-cleanup", "skipped inputs-unchanged");
      return;
    }
  }
  const status = input.timings.time("image-cleanup", () => cleanupRunfreeImages(input.context, input.docker, input.io, input.candidates));
  if (status !== "completed") return;
  const after = inputsDigest();
  if (after === undefined) return;
  try {
    writeImageCleanupStamp(stateDir, projectId, after);
  } catch {
    // Advisory: a stamp this host cannot write only means the next launch
    // runs the pass again.
  }
}

async function prepareRuntimeForTokenSyncOrRemoveInvalid(
  activePlan: ActiveRuntimePlan,
  context: RuntimeContext,
  io: RuntimeIO,
  docker: RuntimeDocker,
  options: {
    verbose?: boolean;
    lifecycleLock?: ProjectLifecycleLock;
    readOnly?: boolean;
    containmentIO?: RuntimeIO;
    // The launch's host Git probe result, when this runs inside a launch.
    hostGit?: HostGitRelativeWorktreesCapability;
  } = {},
): Promise<RuntimeTokenSyncPreparation> {
  const timings = createRuntimeTimings(context.env);
  const project = composeProjectName(context.projectRoot);
  // Without a launch probe result, host Git is probed only if the layout is
  // fatal, so the refusal names the version requirement on old host Git.
  const gitLayout = timings.time("validation:git-layout", () => prepareGitRepositoryLayoutResult(context, options.hostGit, io));
  if (serializeGitLayoutPlan(gitLayout.plan) !== serializeGitLayoutPlan(activePlan.gitLayout)) {
    warn("the Git worktree layout changed since the runtime was created; new authority was refused; repair the reported inputs and retry");
    return { status: 1 };
  }
  const validationContext: RuntimeContext = {
    ...context,
    gitLayoutPlan: gitLayout.plan,
    gitLayoutPlanChanged: gitLayout.changed,
    gitRepositoryShape: gitLayout.shape,
  };
  const identity = {
    composeProject: activePlan.composeProjectName,
    projectId: activePlan.projectId,
  };
  const containers = docker.runtimeContainers(project);
  const effectiveControlPlane = readEffectiveControlPlaneV2(activePlan.paths.stateDir);
  // Branch selection (warm container pinning vs plan components, and why a
  // pending rebind suspends the pinning) is documented on the helper.
  const componentIssue = tokenSyncComponentEvidenceIssue({
    containers,
    effectiveControlPlane,
    pendingControlPlaneRebind: readControlPlaneRebindTransaction(activePlan.paths.stateDir, identity) !== undefined,
    desiredControlPlaneGenerationDigest: activePlan.generationV2.controlPlane.controlPlaneGenerationDigest,
    components: activePlan.activeRuntime.manifest?.components ?? activePlan.components,
    images: {
      agent: activePlan.activeRuntime.agentImage,
      proxy: activePlan.activeRuntime.proxyImage,
    },
    identity,
  });
  if (componentIssue) {
    warn(`runtime component validation failed: ${componentIssue.message}`);
    return { status: 1 };
  }
  const securityContract = createRuntimeSecurityContract(activePlan);
  const helperFence = ephemeralHelperFence(activePlan, options);
  const helperImage = ephemeralHelperImage(activePlan);
  if (!options.readOnly) {
  const markerResetIssue = removeRuntimeValidationMarker(validationContext, io);
  if (markerResetIssue) {
    warn("runtime validation marker reset failed; new authority was refused; repair the reported inputs and retry");
    warn(`  ${markerResetIssue}`);
    return { status: 1 };
  }
  // Wait for the proxy to publish its CA before rendering the bundle host-side.
  // Per-session runtimes have no shared-agent trust exec to wait in-container,
  // so on a fresh runtime the render would otherwise race the proxy's first-start
  // CA generation and fail closed on ENOENT. Fails closed here for the same reason
  // the render does — the agent environment points every file-based trust
  // variable at the bundle, so continuing without it would trade this loud
  // error for quiet TLS failures inside sessions.
  if (!(await timings.timeAsync("validation:proxy-ca-wait", () => waitForProxyCaPublished(validationContext)))) {
    warn("proxy did not publish its CA before trust bundle rendering; new authority was refused; repair the reported inputs and retry");
    return { status: 1 };
  }
  const caBundle = timings.time("validation:ca-bundle", () => ensureAgentCaBundle(validationContext, io, {
    agentImage: activePlan.activeRuntime.agentImage,
    projectId: activePlan.projectId,
    helperImage,
    helperFence,
  }));
  if (caBundle !== 0) {
    warn("agent CA bundle rendering failed; new authority was refused; repair the reported inputs and retry");
    return { status: 1 };
  }
  reportRuntimeProgress("ensuring session volumes", options.verbose);
  // Create the Compose-managed session named volumes the removed `agent`
  // service used to make `compose up` create. Runs before the dependency-volume
  // ownership step so those volumes exist (labelled) before that step mounts and
  // chowns them. With dependency overlays off there are none.
  const sessionVolumes = timings.time(
    "validation:session-volumes",
    () => ensureComposeManagedSessionVolumes(validationContext, docker),
  );
  if (sessionVolumes !== 0) {
    warn("session named-volume setup failed; new authority was refused; repair the reported inputs and retry");
    return { status: sessionVolumes };
  }
  reportRuntimeProgress("checking dependency volumes", options.verbose);
  const dependencyVolumeOwnership = timings.time(
    "validation:dependency-volumes",
    () => ensureDependencyVolumeOwnershipOrRemoveInvalid(validationContext, io, docker, { verbose: options.verbose, helperFence, helperImage }),
  );
  if (dependencyVolumeOwnership !== 0) return { status: dependencyVolumeOwnership };
  }
  reportRuntimeProgress("validating runtime topology", options.verbose);
  const readinessProxyId = docker.serviceContainerId(project, "proxy");
  const readinessPolicy = readActiveControlSelection(context.project);
  if (!readinessProxyId || !readinessPolicy) {
    warn("proxy firewall readiness requires an exact proxy and selected effective policy generation");
    return { status: 1 };
  }
  try {
    await timings.timeAsync("validation:firewall-readiness", () => waitForProxyFirewallReadiness({
      assertAuthority: () => options.lifecycleLock?.assertHeld(),
      io, proxyId: readinessProxyId, effectivePolicyGeneration: readinessPolicy.controlGeneration,
      dockerEnv: activePlan.execution.dockerClientEnv,
    }));
  } catch (error) {
    warn(error instanceof Error ? error.message : String(error));
    return { status: 1, failureKind: error instanceof RuntimeObservationError ? error.evidence.kind : "unclassified" };
  }
  // The host services the firewall proof judges `@host_service` against come
  // from the same effective policy generation readiness waited for. An
  // unreadable generation refuses: the proof never assumes "none".
  let effectiveHostServices: EffectiveHostServices;
  try {
    effectiveHostServices = readEffectiveHostServices(context.project, readinessPolicy.controlGeneration);
  } catch (error) {
    warn(`effective host services could not be read: ${error instanceof Error ? error.message : String(error)}; new authority was refused`);
    return { status: 1 };
  }
  const validation = timings.time(
    "validation:topology",
    () => validateRuntimeTopologyOrRemoveInvalid(activePlan, validationContext, io, docker, {
      ...options, expectedProxyId: readinessProxyId, helperFence, helperImage, effectiveHostServices,
    }),
  );
  if (validation.status !== 0) return validation;
  reportRuntimeProgress("validating runtime security contract", options.verbose);
  const securityValidation = timings.time(
    "validation:security-contract",
    () => validateRuntimeSecurityContractOrRemoveInvalid(securityContract, validationContext, io, docker, activePlan, readinessProxyId, options.lifecycleLock, options.containmentIO),
  );
  if (securityValidation.status !== 0) return { status: securityValidation.status, failureKind: securityValidation.failureKind };
  const marker = (options.readOnly ? observeRuntimeValidationProof : writeRuntimeValidationMarkerResult)(validationContext, io, { contractHash: securityContract.contractHash, expectedProxyId: readinessProxyId });
  if (marker.issue) {
    warn("runtime validation marker write failed; new authority was refused; repair the reported inputs and retry");
    warn(`  ${marker.issue}`);
    return { status: 1 };
  }
  return {
    proof: marker.proof,
    securityProof: securityValidation.proof,
    denyByDefaultObservation: validation.denyByDefaultObservation,
    status: 0,
  };
}

/**
 * The launch-time half of the host-service re-check (design "Policy shape",
 * Re-check, SR13) and host-global port registry refresh (HS7): reads the
 * active effective policy generation's approved host services, warns on
 * every live-owner problem, and refreshes the registry's row for this
 * project with the effective ports. Never throws and never changes the
 * launch's own result -- the proxy's own enforcement, not this probe,
 * protects the agent.
 *
 * F29: the live-owner check for the warning loop is one bounded listener
 * observation (`probeHostListeners`) regardless of how many host services
 * are approved, not one `lsof` call per service; zero approved services
 * still makes zero calls. `admitHostServicePort` (`host-service add`) and
 * `runfree status` are unchanged: they keep probing one port at a time.
 *
 * R15: a project that never used host services must not take the
 * host-global registry lock on every launch, so the write is skipped unless
 * there is something to record or an existing row needs pruning.
 */
async function refreshHostServicesAtLaunch(context: RuntimeContext, io: RuntimeIO): Promise<void> {
  try {
    const effectivePolicy = readActiveEffectiveControl(context.project)?.policy;
    const hostServices = effectivePolicy ? validateNetworkPolicy(effectivePolicy).hostServices : {};
    const env = context.env ?? process.env;
    const projectId = projectHash(context.projectRoot);
    if (Object.keys(hostServices).length > 0) {
      const recorded = recordedHostServiceOwners(env, projectId);
      const snapshot = probeHostListeners(context, io);
      for (const line of hostServiceOwnerWarningsFromSnapshot(snapshot, hostServices, recorded)) warn(line);
    }
    const ports = Array.from(new Set(Object.values(hostServices).map((entry) => entry.port))).sort((left, right) => left - right);
    if (ports.length > 0 || projectHasRegisteredHostServicePorts(env, projectId)) {
      await recordProjectHostServicePorts(env, { id: projectId, root: context.projectRoot }, ports);
    }
  } catch (error) {
    warn(`host-service re-check failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export async function startRuntime(
  context: RuntimeContext,
  io: RuntimeIO,
  removeExisting = false,
  rebuildOptions: RebuildOptions = {},
): Promise<RuntimeStartResult> {
  const verbose = rebuildOptions.verbose === true;
  reportRuntimeStart(removeExisting ? "rebuilding runtime" : "starting runtime");
  const timings = createRuntimeTimings(context.env);
  const operations = timings.enabled ? createOperationHistogram() : undefined;
  if (operations) io = withOperationHistogram(io, operations);
  const containmentIO = io;
  const startupStartedAt = performance.now();
  const initialAdapters = createRuntimeAdapters(context, io);
  const result = (status: number, _fastPath = false, _resultContext: RuntimeContext = context): RuntimeStartResult => ({
    kind: "failed",
    fastPath: false,
    status,
  });
  let dockerChecked = false;
  const ensureDockerAvailable = (): void => {
    if (dockerChecked) return;
    reportRuntimeVerbose(verbose, "checking Docker CLI and daemon");
    initialAdapters.docker.assertAvailable();
    dockerChecked = true;
  };

  let lifecycleLock: ProjectLifecycleLock | undefined;
  // The exact lock object this start acquired, for a held-lock launch handoff,
  // and whether that handoff now owns it.
  let acquiredLifecycleLock: ProjectLifecycleLock | undefined;
  let lockHandedOff = false;
  let confirmedRebuildSessions: readonly ActiveAgentSession[] = [];
  try {
    // Probe host Git once per launch, before any project state is written:
    // shapes old host Git cannot use refuse here; the result also feeds the
    // layout preparation and the sandbox Git config's degraded-mode warning.
    const hostGit = timings.time("startup:host-git-probe", () => probeHostGitRelativeWorktrees(context, io));
    refuseGitLayoutUnusableByHostGit(context.projectRoot, hostGit);
    const capturedConfig = readConfig(context.projectRoot);
    if (removeExisting) {
      ensureDockerAvailable();
      // Rebuild owns the operator decision about stopping live sessions. Make
      // that decision before control preparation, because control preparation
      // correctly refuses to read or write desired state while a session is
      // active. Reaching it first would turn an explicit rebuild into an
      // unprompted control-plane refusal.
      confirmedRebuildSessions = activeOrStartingAgentSessions(context, initialAdapters.docker);
      const confirmed = confirmRebuildIfActiveSessions(
        context,
        initialAdapters.docker,
        io,
        rebuildOptions,
        confirmedRebuildSessions,
      );
      if (confirmed !== 0) return result(confirmed, false, context);
    }
    reportRuntimeProgress("preparing approved effective controls", verbose);
    try {
      const preparedControls = await timings.timeAsync("control-preparation", () => prepareEffectiveControlsForLaunch(context, io, {
        useApprovedPolicy: rebuildOptions.useApprovedPolicy,
      }));
      reportRuntimeVerbose(
        verbose,
        `selected ${preparedControls.generation.controlGeneration} via ${preparedControls.mechanism}`,
      );
    } catch (error) {
      warn(error instanceof Error ? error.message : String(error));
      const status = error && typeof error === "object" && "status" in error && typeof error.status === "number"
        ? error.status
        : 1;
      return result(status, false, context);
    }
    const dockerSubnets = context.network
      ? []
      : (() => {
        timings.time("startup:docker-available", ensureDockerAvailable);
        return timings.time("startup:network-subnets", () => initialAdapters.docker.networkSubnets());
      })();
    // Plan the bootstrap without overlay discovery: the Git facts it needs are
    // not available yet, and preparedPlan below replaces every overlay-derived
    // field anyway. See emptyDependencyOverlayPlan.
    const initialPlan = createRuntimePlan(
      { ...context, dependencyOverlayPlan: emptyDependencyOverlayPlan(context.projectRoot) },
      { dockerSubnets, persistNetwork: !context.network },
    );
    const initialContext = runtimeContextFromPlan(initialPlan);
    let adapters = createRuntimeAdapters(initialContext, io);

    reportRuntimeVerbose(verbose,
      `using runtime network ${initialPlan.network.subnet}, proxy egress ${initialPlan.network.proxyEgressSubnet}`);

    const gitLayout = timings.time("startup:git-layout", () => prepareGitRepositoryLayoutResult(initialContext, hostGit));
    const gitPreparedPlan: RuntimePlan = {
      ...initialPlan,
      gitLayout: gitLayout.plan,
      gitRepositoryShape: gitLayout.shape,
    };
    const gitPreparedContext = runtimeContextFromPlan(gitPreparedPlan, {
      gitLayoutPlanChanged: gitLayout.changed,
    });
    adapters = createRuntimeAdapters(gitPreparedContext, io);

    reportRuntimeProgress("preparing project runtime state", verbose);
    assertSafeRuntimePolicyPath(gitPreparedContext);
    timings.time("startup:agent-state", () => {
      ensureAgentState(gitPreparedContext);
      writeProjectRecoveryPointer(gitPreparedContext);
    });
    // Host-service re-check and registry refresh (design "Policy shape",
    // Re-check, SR13; registry, HS7). Runs here, after control preparation
    // selected the effective policy generation, but before any lock is held
    // (within the launch lock-hold budget) -- a probe failure only warns, it
    // never refuses the launch. Refreshing the host-global registry here too
    // keeps it current even when an activation came from `runfree up` rather
    // than `host-service add/remove`.
    await timings.timeAsync("startup:host-services-refresh", () => refreshHostServicesAtLaunch(gitPreparedContext, io));
    timings.time("startup:sandbox-git-config", () => ensureSandboxGitConfig(gitPreparedContext, io, hostGit));
    const dependencyPlan: PreparedDependencyOverlayPlan = timings.time("startup:dependency-overlay-plan", () => prepareDependencyOverlayPlanResult(gitPreparedContext, io));
    // Supply the freshly discovered overlays before the plan is built, not
    // after. Compose output, the topology digest, the session container
    // template, and the generation target are all derived from the plan's
    // overlay set, so patching only that field would leave every derived field
    // describing the previous set: startup would select one generation while
    // persisting the overlays for another, and the same command's session
    // admission would then fail its exact-generation check.
    const dependencyPreparedContext: RuntimeContext = {
      ...gitPreparedContext,
      dependencyOverlayPlan: dependencyPlan.plan,
    };
    const preparedPlan = {
      ...createRuntimePlan(dependencyPreparedContext, { dockerSubnets: [], persistNetwork: false }),
      gitLayout: gitLayout.plan,
      gitRepositoryShape: gitLayout.shape,
    };
    const preparedContext = runtimeContextFromPlan(preparedPlan, {
      dependencyOverlayPlanChanged: dependencyPlan.changed,
      gitLayoutPlanChanged: gitLayout.changed,
    });
    const existingActivePlan = existingActiveRuntimePlan(preparedPlan);
    const existingContext = runtimeContextFromActivePlan(existingActivePlan, {
      dependencyOverlayPlanChanged: dependencyPlan.changed,
      gitLayoutPlanChanged: gitLayout.changed,
    });
    adapters = createRuntimeAdapters(existingContext, io);

    timings.time("startup:docker-available-prepared", ensureDockerAvailable);
    const startupDaemonIdentity = lastObservedDockerDaemonIdentity();
    // Capture the proxy container id before any lifecycle change. The proxy
    // loads the on-disk policy at boot, so a changed id afterwards means it
    // already reflects the merged policy and a follow-up policy reload is moot.
    const proxyContainerIdBefore = timings.time("startup:proxy-id-before", () => adapters.docker.runningServiceContainerId(
      existingActivePlan.composeProjectName,
      "proxy",
    ));
    const proxyRecreatedSinceStart = (docker: RuntimeDocker): boolean =>
      docker.runningServiceContainerId(existingActivePlan.composeProjectName, "proxy")
        !== proxyContainerIdBefore;
    let upgradePlan: RuntimeUpgradePlan = { action: "none", services: [] };
    if (!removeExisting) {
      await timings.timeAsync("startup:admission-quiescence", () => awaitLiveSessionAdmissionQuiescence(preparedPlan.paths.stateDir, {
        projectId: preparedPlan.projectId,
        composeProject: preparedPlan.composeProjectName,
      }));
      upgradePlan = timings.time("startup:upgrade-plan", () => planRuntimeUpgradeFromV2State(preparedPlan, existingContext, adapters.docker,
        { deferPendingSessionAdmission: true }));
      reportRuntimeVerbose(verbose, `runtime upgrade plan is ${upgradePlan.action}`);
      if (verbose) {
        for (const line of runtimeComponentDiagnosticLines({
          action: upgradePlan.action,
          desired: preparedPlan.generationV2,
          stateDir: preparedPlan.paths.stateDir,
        })) reportRuntimeVerbose(true, line);
      }
      const upgradeStatus = timings.time("startup:upgrade-apply", () => applyRuntimeUpgradePlan(existingContext, adapters.docker, upgradePlan));
      if (upgradeStatus !== 0) return result(upgradeStatus, false, existingContext);
      // Diagnostic only: the marker status picks between two verbose lines and
      // validation replaces the marker right after, so a quiet start skips the
      // two `ps` lookups and the root exec it costs.
      if (verbose && upgradePlan.action === "token-sync") {
        const securityContract = createRuntimeSecurityContract(existingActivePlan);
        const marker = runtimeValidationMarkerStatus(existingContext, io, { contractHash: securityContract.contractHash });
        if (!marker.issue) {
          reportRuntimeVerbose(verbose, "runtime validation marker is fresh; checking current locked runtime evidence");
            reportRuntimeVerbose(verbose, "v2 effective control-plane selection requires locked live validation");
        } else {
          reportRuntimeVerbose(verbose, `runtime validation marker requires revalidation: ${marker.issue}`);
        }
      }
      {
        const repair = await timings.timeAsync("startup:network-repair", () => repairStaleComposeNetworkState(existingContext, adapters.docker));
        if (repair !== 0) return result(repair, false, existingContext);
      }

    }

    const preparedSelection = comparableEffectiveControlPlaneSelection(preparedPlan.paths.stateDir);
    const preparedPolicySelection = readActiveControlSelection(context.project);
    reportRuntimeProgress("ensuring runtime images", verbose);
    let activePlan: ActiveRuntimePlan;
    try {
      activePlan = timings.time("image-materialization", () => ensureRuntimeMaterialized(preparedPlan, {
        docker: adapters.docker,
        io,
        force: removeExisting,
        deferSelection: true,
        verbose,
      }));
    } catch (error) {
      if (error instanceof RuntimeImageBuildStatus) {
        warn(error.message);
        return result(error.status, false, preparedContext);
      }
      throw error;
    }
    const pendingPreparedRebind = readControlPlaneRebindTransaction(preparedPlan.paths.stateDir,
      { projectId: preparedPlan.projectId, composeProject: preparedPlan.composeProjectName });
    if (pendingPreparedRebind) activePlan = materializeRetainedRebindRuntimePlan(activePlan, pendingPreparedRebind.candidateMaterialization, adapters.docker);
    // Launch plan D4: a warm launch re-reads only the sources whose held value
    // is not provably current (receipt, live store generation, held file,
    // warm age bound); `up`, a cold start, and a proxy change read them all.
    const receiptGatedCredentials = rebuildOptions.launch === true
      && (upgradePlan.action === "token-sync" || upgradePlan.action === "component-select");
    await timings.timeAsync("startup:prepare-token-sources", async () => io.prepareTokenSources?.(
      runtimeContextFromActivePlan(activePlan),
      receiptGatedCredentials ? { mode: "convergence" } : undefined,
    ));
    // Capture and compare under the lock. This pair detects a *change during
    // preparation*; it is not the mismatch gate. Once the reader returns a
    // value instead of throwing, a persistent mismatch compares equal to itself
    // and passes the comparison below — the recovery gate ran long before here.
    const preparedApproval = readControlApprovalSelection(context.projectRoot, context.project);
    lifecycleLock ??= await timings.timeAsync("startup:lock-acquire", () => tryAcquireProjectLifecycleLockWithRetry(preparedContext));
    acquiredLifecycleLock = lifecycleLock;
    // Where a handed-off lock's one continuous hold starts (launch-lock-hold.ts).
    const lockAcquiredAtMonotonicMs = performance.now();
    if (!lifecycleLock) {
      warn(`the runtime did not start: another Runfree runtime lifecycle change is in progress (lock: ${projectLifecycleLockPath(preparedContext)}); retry when it finishes`);
      return result(1, false, preparedContext);
    }
    let lockSpanStarted = performance.now();
    io = withLifecycleOperationBudget(io, () => lifecycleLock ? LIFECYCLE_OPERATION_BUDGET_MS - (performance.now() - lockSpanStarted) : undefined);
    adapters = createRuntimeAdapters(preparedContext, io);
    const heldLifecycleLock: ProjectLifecycleLock = {
      get ownerToken() {
        if (!lifecycleLock) throw new Error("project lifecycle lock is released for credential resolution");
        return lifecycleLock.ownerToken;
      },
      assertHeld() {
        if (!lifecycleLock) throw new Error("project lifecycle lock is released for credential resolution");
        lifecycleLock.assertHeld();
      },
      release() { lifecycleLock?.release(); lifecycleLock = undefined; },
    };

    heldLifecycleLock.assertHeld();
    // Design D-D: a helper marker present when the lock is newly acquired
    // means a helper may have outlived its run. Sweep this project's helpers
    // before anything can run a new helper or admit a session. No marker costs
    // two lstat calls and no Docker call.
    try {
      reclaimHelperResidue({
        lifecycleLock: heldLifecycleLock,
        containmentIO,
        stateDir: preparedPlan.paths.stateDir,
        dockerEnv: dockerClientEnvOptions(preparedContext).env,
      }, preparedPlan.projectId);
    } catch (error) {
      warn(error instanceof Error ? error.message : String(error));
      return result(1, false, preparedContext);
    }
    heldLifecycleLock.assertHeld();
    const currentConfig = readConfig(context.projectRoot);
    const currentPlan = timings.time("startup:recheck-plan", () => createRuntimePlan(preparedContext,
      { dockerSubnets: [], persistNetwork: false }));
    if (!isDeepStrictEqual(currentConfig, capturedConfig)
      || !isDeepStrictEqual(currentPlan.generationV2, preparedPlan.generationV2)
      || !isDeepStrictEqual(readControlApprovalSelection(context.projectRoot, context.project), preparedApproval)
      || !isDeepStrictEqual(comparableEffectiveControlPlaneSelection(preparedPlan.paths.stateDir), preparedSelection)
      || !isDeepStrictEqual(readActiveControlSelection(context.project), preparedPolicySelection)) {
      throw new Error("runtime inputs, approval, or effective selection changed during preparation; retry before selecting the prepared images");
    }
    if (removeExisting && !rebuildOptions.assumeYes
      && hasNewActiveSessions(confirmedRebuildSessions, activeOrStartingAgentSessions(preparedContext, adapters.docker))) {
      warn("a new active session appeared during preparation; retry rebuild to review the current sessions");
      return result(1, false, preparedContext);
    }
    if (!removeExisting) {
      // An interrupted session teardown — a daemon that died under a live
      // session is the ordinary cause — is finished here, under the lock and
      // before the strict plan below, once Docker proves it safe; otherwise
      // the start refuses with the reason and the remedy for that record.
      let reclaim: ReturnType<typeof reclaimPendingSessionAdmissions>;
      try {
        reclaim = timings.time("startup:reclaim-pending-admissions", () => reclaimPendingSessionAdmissions({
          stateDir: preparedPlan.paths.stateDir,
          expectedProject: { projectId: preparedPlan.projectId, composeProject: preparedPlan.composeProjectName },
          io,
          lifecycleLock: heldLifecycleLock,
          env: preparedContext.env,
          dockerOptions: dockerClientEnvOptions(preparedContext),
          nowEpochMs: Date.now(),
        }));
      } catch (error) {
        // A lost lock is not a refusal to report; it ends the start.
        heldLifecycleLock.assertHeld();
        // What escapes the per-record refusals is an unreadable registry,
        // selection, or rebind journal. The strict plan below reads the same
        // state and refuses it with its own remedy; nothing was changed.
        reportRuntimeVerbose(verbose, `pending session admission reclaim skipped: ${error instanceof Error ? error.message : String(error)}`);
        reclaim = { kind: "none" };
      }
      if (reclaim.kind === "refused") {
        warn("the runtime did not start: an interrupted session teardown could not be finished");
        for (const reason of reclaim.reasons) warn(reason);
        return result(1, false, existingContext);
      }
      if (reclaim.kind === "reclaimed") {
        runfreeLog(`finished the interrupted teardown of session ${reclaim.sessionIds.join(", ")}`);
      }
    }
    io.admitPreparedTokenSources?.(runtimeContextFromActivePlan(activePlan));
    timings.time("startup:select-session-agent", () => selectPreparedSessionAgent(activePlan, adapters.docker));
    if (!removeExisting) {
      upgradePlan = timings.time("startup:upgrade-plan-locked", () => planRuntimeUpgradeFromV2State(preparedPlan, existingContext, adapters.docker));
      const status = timings.time("startup:upgrade-apply-locked", () => applyRuntimeUpgradePlan(existingContext, adapters.docker, upgradePlan));
      if (status !== 0) return result(status, false, existingContext);
    }
    const activeContext = runtimeContextFromActivePlan(activePlan, {
      dependencyOverlayPlanChanged: dependencyPlan.changed,
      gitLayoutPlanChanged: gitLayout.changed,
    });
    adapters = createRuntimeAdapters(activeContext, io);

    const project = activePlan.composeProjectName;
    const warmProofInput = (): WarmProofInput | undefined => {
      const effective = readEffectiveControlPlaneV2(activePlan.paths.stateDir);
      const policy = readActiveControlSelection(context.project);
      if (!effective || !policy) return undefined;
      let effectiveHostServices: EffectiveHostServices;
      try {
        effectiveHostServices = readEffectiveHostServices(context.project, policy.controlGeneration);
      } catch {
        // Unreadable host services: no warm path; the full validation refuses.
        return undefined;
      }
      return {
        plan: activePlan,
        context: activeContext,
        io,
        effective: effective.selection,
        effectivePolicyGeneration: policy.controlGeneration,
        daemon: startupDaemonIdentity,
        agentImage: ephemeralHelperImage(activePlan),
        volumeLogicalNames: composeManagedSessionVolumeLogicalNames(activeContext),
        gitLayout: serializeGitLayoutPlan(activePlan.gitLayout),
        effectiveHostServices,
      };
    };
    // Why this start may not even ask the warm proof, or undefined when it may.
    const warmIneligibility = (): string | undefined => {
      if (rebuildOptions.launch !== true) return "not-a-launch";
      if (removeExisting) return "rebuild";
      if (upgradePlan.action !== "token-sync") return `upgrade-${upgradePlan.action}`;
      if (dependencyPlan.changed || gitLayout.changed) return "inputs-changed";
      const identity = { projectId: activePlan.projectId, composeProject: project };
      // Enumerated first: the listing quarantines what it cannot read.
      listSessionContainerRecordsV2(activePlan.paths.stateDir, identity);
      if (listQuarantinedSessionContainerRecordNamesV2(activePlan.paths.stateDir).length > 0) return "quarantined-records";
      if (readControlPlaneRebindTransaction(activePlan.paths.stateDir, identity)) return "pending-rebind";
      return undefined;
    };
    // A warm launch: the stable match, and beside live peers the judgement
    // that accounted for every one of them (`warm-peer-proof.ts`).
    type WarmLaunch = Readonly<{ warm: WarmValidation; peer?: WarmPeerValidation }>;
    const warmValidationForLaunch = (): WarmLaunch | undefined => {
      let reason: string | undefined;
      try {
        reason = warmIneligibility();
      } catch (error) {
        reason = `unreadable: ${error instanceof Error ? error.message : String(error)}`;
      }
      if (reason !== undefined) {
        if (rebuildOptions.launch === true) timings.report("validation:warm-proof", `skipped ${reason}`);
        return undefined;
      }
      const input = warmProofInput();
      if (!input) {
        timings.report("validation:warm-proof", "unavailable");
        return undefined;
      }
      let verdict: WarmProofVerdict = timings.time("validation:warm-proof-check", () => tryWarmRuntimeValidation(input));
      // The same no-Docker selection check the full path's reuse decision
      // makes (image ref, rendered topology, generation, proxy id, contract).
      if (verdict.kind === "match" && !effectiveControlPlaneMatchesRuntimeValidationV2(activePlan, verdict.validation.runtimeProof)) {
        verdict = { kind: "mismatch", field: "effective-selection" };
      }
      timings.report("validation:warm-proof", verdict.kind === "mismatch" ? `mismatch:${verdict.field}` : verdict.kind);
      if (verdict.kind !== "match") {
        if (verdict.kind === "unavailable") reportRuntimeVerbose(verbose, `warm-proof unavailable: ${verdict.reason}`);
        return undefined;
      }
      const stable = verdict.validation;
      const identity = { projectId: activePlan.projectId, composeProject: project };
      let hasPeers: boolean;
      let effective: ReturnType<typeof readEffectiveControlPlaneV2>;
      try {
        hasPeers = listSessionContainerRecordsV2(activePlan.paths.stateDir, identity).length > 0;
        effective = readEffectiveControlPlaneV2(activePlan.paths.stateDir);
      } catch (error) {
        timings.report("validation:warm-peer", "miss:registry-unreadable");
        reportRuntimeVerbose(verbose, `warm peer validation skipped: ${error instanceof Error ? error.message : String(error)}`);
        return undefined;
      }
      if (!hasPeers) return { warm: stable };
      // Beside live peers the stable match is extended by an exact account of
      // every peer and participant; any miss takes the full path.
      if (!effective) {
        timings.report("validation:warm-peer", "miss:evidence-unreadable");
        return undefined;
      }
      const effectiveSelection = effective;
      const peerVerdict = timings.time("validation:warm-peer-check", () => tryWarmPeerValidation({
        stable,
        stateDir: activePlan.paths.stateDir,
        expectedProject: identity,
        effective: effectiveSelection.selection,
        effectiveManifest: effectiveSelection.manifest,
        effectivePolicyGeneration: input.effectivePolicyGeneration,
        lifecycleLock: heldLifecycleLock,
        io,
        docker: adapters.docker,
        dockerOptions: dockerClientEnvOptions(activeContext),
        env: activeContext.env,
        runfreeVersion: activePlan.runfreeVersion,
      }));
      timings.report("validation:warm-peer", peerVerdict.kind === "match" ? "match" : `miss:${peerVerdict.reason}`);
      if (peerVerdict.kind !== "match") {
        if (peerVerdict.detail) reportRuntimeVerbose(verbose, `warm peer validation missed (${peerVerdict.reason}): ${peerVerdict.detail}`);
        return undefined;
      }
      return { warm: stable, peer: peerVerdict.validation };
    };
    const validateSelectAndSync = async (): Promise<RuntimeStartResult> => {
      runImageCleanupUnlessUnchanged({
        context: activeContext,
        docker: adapters.docker,
        io,
        launch: rebuildOptions.launch === true,
        timings,
        candidates: {
          controlPlaneMaterializationDigest: activePlan.activeRuntime.controlPlaneMaterializationDigest,
          sessionAgentMaterializationDigest: readRetainedDesiredSessionAgentV2(
            activePlan.paths.stateDir,
          )?.selection.sessionAgentMaterializationDigest,
        },
      });
      // Sub-second launch plan Task 2: a warm session launch whose warm-proof
      // fingerprint matches skips the full validation. The verdict carries only
      // the re-judged marker proof, so the control-plane selection below is
      // never asked to prove or select from warm evidence.
      heldLifecycleLock.assertHeld();
      const warmLaunch = warmValidationForLaunch();
      const warm = warmLaunch?.warm;
      const warmPeer = warmLaunch?.peer;
      const dropWarmRecord = (why: string): void => {
        try {
          removeWarmProofRecord(activePlan.paths.stateDir);
        } catch (error) {
          warn(`the warm-proof record could not be removed after ${why}: ${error instanceof Error ? error.message : String(error)}`);
        }
      };
      let validation: RuntimeTokenSyncPreparation | undefined;
      let runtimeProof: RuntimeValidationProof | undefined;
      if (warm) {
        assertWarmValidation(warm);
        runtimeProof = warm.runtimeProof;
      } else {
        // The record goes before the full path runs and is written again only
        // after the session reconcile below, so a validation that fails
        // anywhere below leaves no record a later launch could match.
        try {
          removeWarmProofRecord(activePlan.paths.stateDir);
        } catch (error) {
          warn(`the warm-proof record could not be removed before full runtime validation: ${error instanceof Error ? error.message : String(error)}`);
          return result(1, false, activeContext);
        }
        const full = await timings.timeAsync(
          "runtime-validation",
          () => prepareRuntimeForTokenSyncOrRemoveInvalid(activePlan, activeContext, io, adapters.docker, { verbose, lifecycleLock: heldLifecycleLock, containmentIO, hostGit }),
        );
        if (full.status !== 0) return result(full.status, false, activeContext);
        validation = full;
        runtimeProof = full.proof;
      }
      const securityProof = validation?.securityProof;
      const denyByDefaultObservation = validation?.denyByDefaultObservation;
      if (!runtimeProof || (!warm && (!securityProof || !denyByDefaultObservation))) {
        warn("validated control-plane proof is incomplete before credential sync");
        return result(1, false, activeContext);
      }
      let selectedPlan: ActiveRuntimePlan;
      try {
        heldLifecycleLock.assertHeld();
        selectedPlan = selectEffectiveRuntimePlan(activePlan);
        heldLifecycleLock.assertHeld();
        if (!warm) timings.time("control-plane-selection", () => {
          const alreadySelected = readEffectiveControlPlaneV2(activePlan.paths.stateDir);
          const reusesExactControlPlane = alreadySelected !== undefined
            && alreadySelected.manifest.generation.controlPlaneGenerationDigest
              === activePlan.generationV2.controlPlane.controlPlaneGenerationDigest
            && alreadySelected.manifest.controlPlaneMaterializationDigest
              === activePlan.activeRuntime.controlPlaneMaterializationDigest
            && effectiveControlPlaneMatchesLiveRuntimeValidationV2(activePlan, runtimeProof, io);
          if (!reusesExactControlPlane) {
            if (!securityProof || !denyByDefaultObservation) {
              throw new Error("control-plane selection requires the full validation's proofs");
            }
            proveAndSelectEffectiveControlPlaneV2({
              plan: activePlan,
              runtimeProof,
              securityProof,
              denyByDefaultObservation,
              lifecycleLock: heldLifecycleLock,
              io,
            });
          }
        });
        heldLifecycleLock.assertHeld();
      } catch (error) {
        warn(error instanceof Error ? error.message : String(error));
        return result(1, false, activeContext);
      }
      let proxyStartedAt: string | undefined;
      let reconciled: SessionReconcileResult | undefined;
      let warmEmpty: WarmEmptySessionState | undefined;
      // Invariant 9, widen-before-new-files: the proxy is proven ready and the
      // control plane is selected, so publish the project's session eligibility
      // before anything waits on session admission. A proxy holding no
      // eligibility file serves nothing, and the publication is idempotent, so
      // this is also the point a rolling agent upgrade widens the admitted set.
      try {
        heldLifecycleLock.assertHeld();
        const effective = readEffectiveControlPlaneV2(activePlan.paths.stateDir);
        const desired = readRetainedDesiredSessionAgentV2(activePlan.paths.stateDir);
        if (!effective || !desired) {
          throw new Error("session eligibility requires the selected control plane and the retained current agent template");
        }
        const observedProxyStartedAt = warm?.proxyStartedAt ?? observeProxyStartedAt(io, runtimeProof.proxyId, dockerClientEnvOptions(activeContext));
        proxyStartedAt = observedProxyStartedAt;
        timings.time("startup:eligibility-publish", () => ensureSessionEligibilityPublished({
          io,
          proxyId: runtimeProof.proxyId,
          proxyStartedAt: observedProxyStartedAt,
          stateDir: activePlan.paths.stateDir,
          effective,
          desired,
          records: listSessionContainerRecordsV2(activePlan.paths.stateDir, { projectId: activePlan.projectId, composeProject: project }),
          dockerOptions: dockerClientEnvOptions(activeContext),
        }));
        heldLifecycleLock.assertHeld();
        // Invariant 3, from the other end: `up` is the point a project comes
        // back after a crash, so the same reconcile every launch runs is run
        // here too — files no record accounts for, records whose owner is
        // gone, and containers nothing claims are cleared while the lock is
        // held and before any session can be admitted. It follows the
        // publication above, which widened the admitted set; step 5 of the
        // reconcile narrows it again once the residue is gone.
        //
        // A warm launch that will hand this lock to its admission skips the
        // reconcile only when its own evidence proves there is nothing to
        // reconcile: no proxy session file, no session participant, no
        // lifecycle or quarantined record, and no container that may be a
        // session. The publication above already used that empty registry,
        // so nothing is left to narrow. Anything short of that reconciles.
        if (warm && rebuildOptions.launchHandoff === true && rebuildOptions.launch === true && !removeExisting
          && acquiredLifecycleLock !== undefined) {
          const verdict = timings.time("startup:warm-empty-check", () => proveWarmEmptySessionState({
            warm,
            io,
            stateDir: activePlan.paths.stateDir,
            expectedProject: { projectId: activePlan.projectId, composeProject: project },
            proxyId: runtimeProof.proxyId,
            proxyStartedAt: observedProxyStartedAt,
            lifecycleLock: heldLifecycleLock,
            dockerOptions: dockerClientEnvOptions(activeContext),
          }));
          timings.report("startup:warm-empty", verdict.kind === "empty" ? "empty" : `blocked:${verdict.reason}`);
          if (verdict.kind === "empty") warmEmpty = verdict.state;
        }
        if (warmEmpty) {
          timings.report("startup:reconcile-sessions", "skipped warm-empty");
        } else {
          reconciled = await timings.timeAsync("startup:reconcile-sessions", () => reconcileSessions({
            stateDir: activePlan.paths.stateDir,
            expectedProject: { projectId: activePlan.projectId, composeProject: project },
            io,
            proxyId: runtimeProof.proxyId,
            network: {
              networkId: effective.selection.networkIds.agentInternal,
              networkName: `${project}_agent_internal`,
              subnet: activePlan.network.subnet,
            },
            env: activeContext.env,
            lifecycleLock: heldLifecycleLock,
            mode: "repair",
            dockerOptions: dockerClientEnvOptions(activeContext),
          }));
        }
        heldLifecycleLock.assertHeld();
      } catch (error) {
        warn(error instanceof Error ? error.message : String(error));
        dropWarmRecord("a session reconcile that did not complete");
        return result(1, false, activeContext);
      }
      const sessionIdentity = { projectId: activePlan.projectId, composeProject: project };
      if (warmPeer) {
        // A warm launch beside live peers skips the restore only while the
        // judgement's binding still holds after the reconcile. Anything short
        // of that refuses: nothing is restored from warm evidence, and the
        // retry, finding no record, validates fully and restores.
        const refusal = warmPeerRestoreSkipRefusal({
          validation: warmPeer,
          reconciled,
          io,
          stateDir: activePlan.paths.stateDir,
          expectedProject: sessionIdentity,
          proxyId: runtimeProof.proxyId,
          project: context.project,
          lifecycleLock: heldLifecycleLock,
          dockerOptions: dockerClientEnvOptions(activeContext),
        });
        if (refusal !== undefined) {
          timings.report("startup:restore-sessions", `refused ${refusal}`);
          reportRuntimeVerbose(verbose, `warm launch beside peers refused: ${refusal}`);
          dropWarmRecord("a warm launch beside peers whose session state changed");
          warn("the session state changed during a warm launch; retry the command to validate the runtime fully");
          return result(1, false, activeContext);
        }
        timings.report("startup:restore-sessions", "skipped warm-peer");
      } else {
        if (reconciled && !reconciled.inventoryClean) dropWarmRecord("a session reconcile that repaired residue");
        // A warm proxy that kept its container id can still have restarted in
        // place, taking its session-file directory and eligibility with it. The
        // restore re-proves every surviving session and republishes the
        // eligibility unconditionally, so it runs whenever this project still has
        // lifecycle records to restore.
        let restoredProxyStartedAt: string | undefined;
        if (listSessionContainerRecordsV2(activePlan.paths.stateDir, sessionIdentity).length) {
          // The warm-empty path runs only with an empty registry, checked under
          // this same held lock, and reconcile adds no records; a record here
          // means that premise broke, so nothing is restored from warm evidence.
          if (!validation) {
            warn("a lifecycle record appeared during a warm launch; retry the command to validate the runtime fully");
            return result(1, false, activeContext);
          }
          const fullValidation = validation;
          restoredProxyStartedAt = await timings.timeAsync("startup:restore-sessions", () => restoreSameProxySessionAdmission({
            plan: activePlan, io, lifecycleLock: heldLifecycleLock, proxyId: runtimeProof.proxyId, validation: fullValidation,
          }));
        }
        // The record is written only after a reconcile that found nothing to
        // repair and after the restore completed: a record taken earlier could
        // bind a participant the reconcile was about to remove, or a run whose
        // restore never finished, and a later launch would match it. Its proxy
        // start must be the one this validation observed and, when a restore
        // ran, the one that restore published against: a same-id restart in
        // between records nothing. A full validation just proved the runtime
        // and the selection matches it, so record the warm-proof facts for the
        // next launch (runfree up and launches alike; never a rebuild). Best
        // effort.
        if (!warm && !removeExisting && reconciled?.inventoryClean && proxyStartedAt !== undefined) {
          const input = warmProofInput();
          const recorded = restoredProxyStartedAt !== undefined && restoredProxyStartedAt !== proxyStartedAt
            ? "the proxy restarted between the validation and the restore"
            : input ? recordWarmRuntimeProof(input, proxyStartedAt) : "the warm-proof inputs are unavailable";
          timings.report("validation:warm-proof", recorded === "written" ? "recorded" : "not-recorded");
          if (recorded !== "written") reportRuntimeVerbose(verbose, `warm-proof record not written: ${recorded}`);
        }
      }
      const proxyRecreated = proxyRecreatedSinceStart(adapters.docker);
      const credentialMode = receiptGatedCredentials && !proxyRecreated ? "receipt-gated" : "source-truth";
      // Sub-second launch plan Task 3: a launch that asked for it gets this
      // lock, still held, with what this startup proved under it. Not for
      // `up`, a rebuild, or `resume` (whose recovery claim takes the lifecycle
      // lock itself).
      const handoffLock = acquiredLifecycleLock;
      const launchHandoff: LaunchHandoffRequest | undefined = rebuildOptions.launchHandoff === true
        && rebuildOptions.launch === true && !removeExisting && handoffLock !== undefined
        && proxyStartedAt !== undefined && (reconciled !== undefined || warmEmpty !== undefined)
        ? {
            build: () => {
              heldLifecycleLock.assertHeld();
              if (lifecycleLock !== handoffLock) throw new Error("the startup lock was replaced before the handoff");
              // A start that already held the lock this long hands nothing
              // off: admission takes its own lock, so the one continuous hold
              // stays inside another command's lock wait.
              if (!launchHandoffSpanFits(lockAcquiredAtMonotonicMs, performance.now())) {
                throw new LaunchHandoffSpanExceededError();
              }
              return {
                lifecycleLock: handoffLock,
                lockOwnerToken: handoffLock.ownerToken,
                lockAcquiredAtMonotonicMs,
                proxy: {
                  id: runtimeProof.proxyId,
                  startedAt: proxyStartedAt as string,
                  ...(warm ? { pid: warm.proxyPid, bootId: warm.bootId } : {}),
                },
                ...(warm?.ipAssignmentDigests ? { ipAssignmentDigests: warm.ipAssignmentDigests } : {}),
                registryDigest: sessionRegistryDigest(activePlan.paths.stateDir, { projectId: activePlan.projectId, composeProject: project }),
                sessionState: warmEmpty ?? Object.freeze({
                  kind: "reconciled" as const,
                  inventoryClean: (reconciled as SessionReconcileResult).inventoryClean,
                  reservedSourceIps: [...(reconciled as SessionReconcileResult).reservedSourceIps],
                }),
              };
            },
            releaseLock: () => heldLifecycleLock.release(),
            onHandedOff: () => { lockHandedOff = true; },
          }
        : undefined;
      return finalizeValidatedRuntime(
        selectedPlan,
        io,
        runtimeProof,
        verbose,
        proxyRecreated,
        heldLifecycleLock,
        async (work) => { heldLifecycleLock.release(); return await work(); },
        credentialMode,
        launchHandoff,
        receiptGatedCredentials,
      );
    };
    if (upgradePlan.action === "component-select" && runningWarmRuntime(activeContext, adapters.docker)) {
      reportRuntimeProgress("validating new runtime materialization", verbose);
      return await validateSelectAndSync();
    }
    if (upgradePlan.action === "token-sync" && runningWarmRuntime(activeContext, adapters.docker)) {
      return await validateSelectAndSync();
    }
    if (upgradePlan.action === "proxy-restart") {
      const oldControlPlane = readEffectiveControlPlaneV2(activePlan.paths.stateDir);
      const candidateDigest = activePlan.activeRuntime.controlPlaneMaterializationDigest;
      const candidateMaterialization = candidateDigest
        ? readControlPlaneMaterializationV2(activePlan.paths.stateDir, candidateDigest)
        : undefined;
      if (!oldControlPlane || !candidateMaterialization) {
        warn("compatible proxy restart requires exact old and candidate control-plane materializations");
        return result(1, false, activeContext);
      }
      const rebindIO = withRebindBudgetIO(io, activePlan.paths.stateDir, { projectId: activePlan.projectId, composeProject: project }, () => heldLifecycleLock.assertHeld(), rebuildOptions.recoveryRetry);
      const rebindDocker = createRuntimeAdapters(activeContext, rebindIO).docker;
      let candidateValidation: RuntimeTokenSyncPreparation | undefined;
      let candidateSelection: ControlPlaneEffectiveSelectionV2 | undefined;
      try {
        const proveCandidate = async (): Promise<ControlPlaneEffectiveSelectionV2> => {
          heldLifecycleLock.assertHeld();
          candidateValidation = await prepareRuntimeForTokenSyncOrRemoveInvalid(
            activePlan,
            activeContext,
            rebindIO,
            rebindDocker,
            { verbose, lifecycleLock: heldLifecycleLock, readOnly: true, containmentIO, hostGit },
          );
          if (candidateValidation.status !== 0
            || !candidateValidation.proof
            || !candidateValidation.securityProof
            || !candidateValidation.denyByDefaultObservation) {
            throw new RuntimeObservationError({ kind: candidateValidation.failureKind ?? "unclassified", subject: "proxy",
              expectedIdentity: candidateValidation.proof?.proxyId ?? "unrecorded-candidate", phase: "proxy-started-deny-all", observation: "candidate proxy failed exact deny-all validation; session resources were preserved" });
          }
          candidateSelection = proveCandidateControlPlaneV2({
            plan: activePlan,
            runtimeProof: candidateValidation.proof,
            securityProof: candidateValidation.securityProof,
            denyByDefaultObservation: candidateValidation.denyByDefaultObservation,
            lifecycleLock: heldLifecycleLock,
            io: rebindIO,
          });
          return candidateSelection;
        };
        const reproveCandidate = async (recorded: ControlPlaneEffectiveSelectionV2): Promise<void> => {
          heldLifecycleLock.assertHeld();
          candidateValidation = await prepareRuntimeForTokenSyncOrRemoveInvalid(
            activePlan,
            activeContext,
            rebindIO,
            rebindDocker,
            { verbose, lifecycleLock: heldLifecycleLock, readOnly: true, containmentIO, hostGit },
          );
          if (candidateValidation.status !== 0
            || !candidateValidation.proof
            || !candidateValidation.securityProof
            // The deny-by-default observation validates ruleset SHAPE (INPUT
            // policy drop, @session_ipv4 the sole agent->proxy path), not set
            // emptiness, so it stays required after admission publication —
            // a topology-validator change that stopped minting it must not
            // quietly weaken the re-proof.
            || !candidateValidation.denyByDefaultObservation) {
            throw new RuntimeObservationError({ kind: candidateValidation.failureKind ?? "unclassified", subject: "proxy",
              expectedIdentity: recorded.proxyContainerId, phase: "records-rebound", observation: "candidate proxy failed exact validation after session admission publication; session resources were preserved" });
          }
          reproveRecordedCandidateControlPlaneV2({
            plan: activePlan,
            recorded,
            runtimeProof: candidateValidation.proof,
            securityProof: candidateValidation.securityProof,
            lifecycleLock: heldLifecycleLock,
            io: rebindIO,
          });
          candidateSelection = recorded;
        };
        const retireStoppedProxy = async (proxyId: string): Promise<void> => {
          const subject = { proxyId, projectId: activePlan.projectId,
            composeProject: project, io: rebindIO, env: activePlan.execution.dockerClientEnv, assertAuthority: () => heldLifecycleLock.assertHeld() };
          const proxy = observeExactProxy(subject);
          if (!proxy) return;
          if (proxy.State?.Running !== false) throw new Error("candidate retirement requires proof that the exact proxy is stopped");
          heldLifecycleLock.assertHeld();
          const removed = createDockerClient(rebindIO, { env: activePlan.execution.dockerClientEnv, timeout: 1000 }).removeContainers([proxyId]);
          heldLifecycleLock.assertHeld();
          if (removed.status !== 0 || observeExactProxy(subject)) throw new Error("exact stopped candidate could not be retired; inspect it before recovery");
        };
        const rebound = await runCompatibleControlPlaneRebind({
          plan: activePlan,
          lifecycleLock: heldLifecycleLock,
          io: rebindIO,
          explicitRetry: rebuildOptions.recoveryRetry,
          oldControlPlane,
          candidateMaterialization,
          services: {
            captureTrustReceipt: () => captureRebindTrustReceipt(activePlan, rebindIO, () => heldLifecycleLock.assertHeld()),
            recoverUnrecordedCandidate: async (transaction) => {
              const state = inspectRebindCreation({ plan: activePlan, io: rebindIO, transaction, assertAuthority: () => heldLifecycleLock.assertHeld() });
              return state === "recover" ? await proveCandidate() : state === "create" ? undefined : state;
            },
            observeRecordedCandidate: async (recorded) => {
              const proxy = observeExactProxy({ proxyId: recorded.proxyContainerId, projectId: activePlan.projectId,
                composeProject: project, io: rebindIO, env: activePlan.execution.dockerClientEnv, assertAuthority: () => heldLifecycleLock.assertHeld() });
              return !proxy ? "absent" : proxy.State?.Running === false ? "stopped" : "present";
            },
            retireStoppedCandidate: (recorded) => retireStoppedProxy(recorded.proxyContainerId),
            retireUnrecordedCandidate: retireStoppedProxy,
            startAndProveCandidate: async (transaction) => {
              heldLifecycleLock.assertHeld();
              if (inspectRebindCreation({ plan: activePlan, io: rebindIO, transaction, assertAuthority: () => heldLifecycleLock.assertHeld() }) !== "create") {
                throw new Error("candidate appeared before creation; retry recovery without force-recreating it");
              }
              reportRuntimeProgress("restarting compatible proxy runtime in deny-all mode", verbose);
              io.admitPreparedTokenSources?.(activeContext);
              const proxyStatus = rebindDocker.composeUp(project, {
                forceRecreate: true,
                noDeps: true,
                removeOrphans: false,
                services: ["proxy"],
                creationMarker: { transactionId: transaction.transactionId, attempt: transaction.recovery?.candidateAttempt ?? 0 },
              });
              if (proxyStatus !== 0) throw new RuntimeObservationError({ kind: "observation-unavailable", subject: "proxy",
                expectedIdentity: transaction.transactionId, phase: "prepared", observation: `candidate proxy start failed with status ${proxyStatus}; recapture its creation marker` });
              warn("proxy replacement reset pending approvals, temporary grants, remembered denials, and audit capture; interrupted requests are not replayed");
              return await proveCandidate();
            },
            proveCandidate,
            reproveCandidate,
            participantIsAbsent: (record) => rebindParticipantIsAbsent({ containerId: record.containerId, io: rebindIO,
              env: activePlan.execution.dockerClientEnv, assertAuthority: () => heldLifecycleLock.assertHeld() }),
            proveSession: (replacementRecord) => {
              heldLifecycleLock.assertHeld();
              const transactionCandidate = readControlPlaneRebindTransaction(
                activePlan.paths.stateDir,
                { projectId: activePlan.projectId, composeProject: activePlan.composeProjectName },
              )?.candidateControlPlane;
              const exactCandidateSelection = candidateSelection ?? transactionCandidate;
              if (!exactCandidateSelection) {
                throw new Error("control-plane rebind candidate proof is missing before session proof");
              }
              const proofPlan = createRetainedSessionRebindProofPlan({
                stateDir: activePlan.paths.stateDir,
                expectedProject: { projectId: activePlan.projectId, composeProject: activePlan.composeProjectName },
                replacementRecord,
                candidateControlPlane: exactCandidateSelection,
                candidateMaterialization,
                docker: rebindDocker,
                lifecycleLock: heldLifecycleLock,
                runfreeVersion: activePlan.runfreeVersion,
              });
              const inspect = createDockerClient(rebindIO, dockerClientEnvOptions(activeContext)).inspect(
                [replacementRecord.containerId as string],
                { type: "container" },
              );
              if (inspect.status !== 0) throw new RuntimeObservationError({ kind: "observation-unavailable", subject: "session",
                expectedIdentity: replacementRecord.containerId as string, phase: "sessions-revalidated", observation: `session ${replacementRecord.sessionId} inspection failed` });
              return validateSessionContainerInspect(inspect.stdout, proofPlan, { kind: "active-running" });
            },
            finalize: async () => {
              heldLifecycleLock.assertHeld();
              // Receipt gate (Increment 6): fails closed before any credential
              // resolution unless the durable journal attests candidate
              // selection. See the assertion's own doc for the full claim.
              assertControlPlaneRebindReceiptForTokenSync(activePlan.paths.stateDir, {
                projectId: activePlan.projectId,
                composeProject: activePlan.composeProjectName,
              });
              heldLifecycleLock.assertHeld();
              // The effective control plane has durably flipped to the candidate
              // (phase control-selected), so the host materialization selection
              // must flip with it before token sync: credential resolution
              // re-derives the expected runtime components from the durable
              // selection, and a pointer still naming the old materialization
              // reads the fresh candidate proof as stale. Re-running this on
              // crash recovery re-selects the same digest.
              const selectedPlan = selectEffectiveRuntimePlan(activePlan);
              heldLifecycleLock.assertHeld();
              // Token sync is the sensitive side effect: the only proof allowed
              // to authorize it is the one this process just minted against the
              // recorded candidate. No durable-marker fallback — a marker proof
              // is not pinned to the transaction's candidate container.
              const proof = candidateValidation?.proof;
              if (!proof) throw new Error("candidate proxy validation proof is missing before finalization");
              const marker = writeRuntimeValidationMarkerResult(runtimeContextFromActivePlan(selectedPlan), rebindIO,
                { contractHash: proof.contractHash, expectedProxyId: proof.proxyId });
              if (marker.issue || !marker.proof) throw new Error(marker.issue ?? "candidate validation marker could not be persisted");
              const finalized = await finalizeValidatedRuntime(
                selectedPlan,
                rebindIO,
                proof,
                verbose,
                true,
                heldLifecycleLock,
                async (work) => {
                  const expected = readControlPlaneRebindTransaction(activePlan.paths.stateDir,
                    { projectId: activePlan.projectId, composeProject: project });
                  heldLifecycleLock.release();
                  let outcome: { ok: true; value: Awaited<ReturnType<typeof work>> } | { ok: false; error: unknown };
                  try { outcome = { ok: true, value: await work() }; }
                  catch (error) { outcome = { ok: false, error }; }
                  lifecycleLock = await tryAcquireProjectLifecycleLockWithRetry(activeContext);
                  lockSpanStarted = performance.now();
                  heldLifecycleLock.assertHeld();
                  const current = readControlPlaneRebindTransaction(activePlan.paths.stateDir,
                    { projectId: activePlan.projectId, composeProject: project });
                  if (!isDeepStrictEqual(current, expected)) throw new Error("proxy replacement changed during credential resolution; recapture it through runtime recover");
                  await reproveCandidate(candidateSelection as ControlPlaneEffectiveSelectionV2);
                  if (!outcome.ok) throw outcome.error;
                  return outcome.value;
                },
              );
              if (finalized.kind === "failed") {
                throw new Error(`candidate proxy finalization failed with status ${finalized.status}`);
              }
              return {
                preparedRuntime: finalized.preparedRuntime,
                tokenResolutionReceipts: finalized.tokenResolutionReceipts ?? [],
              };
            },
          },
        });
        return {
          kind: "ready",
          status: 0,
          fastPath: false,
          proxyRecreated: true,
          preparedRuntime: rebound.finalization.preparedRuntime,
          tokenResolutionReceipts: [...rebound.finalization.tokenResolutionReceipts],
        };
      } catch (error) {
        if (error instanceof ControlPlaneRebindCandidateMismatchError) throw error;
        warn(error instanceof Error ? error.message : String(error));
        return result(1, false, activeContext);
      }
    }
    if (removeExisting) {
      reportRuntimeProgress("removing existing runtime containers", verbose);
      // Rebuild recovery is unconditional. Compose can already be absent after
      // a crash while journals or revoking records still need fenced teardown.
      // The active plan supplies the deterministic fallback identity.
      io.admitPreparedTokenSources?.(activeContext);
      const downStatus = runFencedProjectRebuildTeardown({
        context: activeContext,
        io,
        docker: adapters.docker,
        lifecycleLock: heldLifecycleLock,
        prepareUtilities: () => planValidatedIngressForwardersForRebuild(
          activeContext,
          io,
          projectHash(activeContext.projectRoot),
        ),
      });
      if (downStatus !== 0) return result(downStatus, false, activeContext);
    }
    reportRuntimeProgress("starting Docker Compose runtime", verbose);
    io.admitPreparedTokenSources?.(activeContext);
    const status = timings.time("compose-up", () => adapters.docker.composeUp(project, { forceRecreate: removeExisting }));
    if (status !== 0) {
      // Compose already printed the daemon error. Without a next command a
      // recoverable runtime (a stale network id, a half-removed container)
      // looks unrecoverable. The remedy is the same for every Compose start
      // failure, so it never matches on daemon output. A rebuild that fails
      // here has already run the last step of that remedy, so it stays quiet.
      if (!removeExisting) warn(COMPOSE_UP_FAILURE_REMEDY);
      return result(status, false, activeContext);
    }
    return await validateSelectAndSync();
  } finally {
    io.clearPreparedTokenSources?.(context);
    if (timings.enabled) {
      timings.report("startup-total", `${(performance.now() - startupStartedAt).toFixed(1)}ms`);
      for (const line of operations?.lines() ?? []) timings.report("startup-ops", line);
    }
    try {
      if (!lockHandedOff) lifecycleLock?.release();
    } catch (error) {
      warn(error instanceof Error ? error.message : String(error));
    }
  }
}

export async function up(
  context: RuntimeContext,
  io: RuntimeIO,
  removeExisting = false,
  rebuildOptions: RebuildOptions = {},
): Promise<number> {
  setMcpLogContext({ verbose: rebuildOptions.verbose === true });
  return (await startRuntime(context, io, removeExisting, rebuildOptions)).status;
}

/**
 * Why a warm launch beside live peers may not skip
 * `restoreSameProxySessionAdmission`, or undefined when it may. Runs after the
 * startup reconcile, under the same held lock: the reconcile must have found
 * nothing at all to repair, the proxy must still be the incarnation the
 * judgement saw, there must be no rebind journal and no revoking record, and
 * the one-shot judgement must still bind every re-read field. Only the last
 * check consumes it. A lost lock throws.
 */
function warmPeerRestoreSkipRefusal(input: Readonly<{
  validation: WarmPeerValidation;
  reconciled: SessionReconcileResult | undefined;
  io: RuntimeIO;
  stateDir: string;
  expectedProject: SessionContainerProjectIdentity;
  proxyId: string;
  project: RuntimeContext["project"];
  lifecycleLock: ProjectLifecycleLock;
  dockerOptions: ReturnType<typeof dockerClientEnvOptions>;
}>): string | undefined {
  const { reconciled } = input;
  if (!reconciled) return "the startup reconcile did not run";
  if (!reconciled.inventoryClean
    || reconciled.orphanFilesDeleted.length > 0
    || reconciled.deadOwnersRevoked.length > 0
    || reconciled.orphanContainersRemoved.length > 0
    || reconciled.unknownOwners.length > 0
    || reconciled.recordsWithoutFiles.length > 0
    || reconciled.orphanFiles.length > 0
    || reconciled.quarantinedFiles.length > 0) {
    return "the startup reconcile found session state to repair";
  }
  input.lifecycleLock.assertHeld();
  let proxyStartedAt: string;
  try {
    proxyStartedAt = observeProxyStartedAt(input.io, input.proxyId, input.dockerOptions);
  } catch (error) {
    return `the proxy start is unavailable: ${error instanceof Error ? error.message : String(error)}`;
  }
  if (proxyStartedAt !== input.validation.proxyStartedAt) return "the proxy restarted since the warm peer judgement";
  let binding: WarmPeerConsumptionBinding;
  try {
    const effective = readEffectiveControlPlaneV2(input.stateDir);
    const policy = readActiveControlSelection(input.project);
    if (!effective || !policy) return "the effective selection is unreadable";
    if (readControlPlaneRebindTransaction(input.stateDir, input.expectedProject)) return "a control-plane rebind is pending";
    if (listSessionContainerRecordsV2(input.stateDir, input.expectedProject).some((record) => record.state === "revoking")) {
      return "a session record is revoking";
    }
    binding = {
      lockOwnerToken: input.lifecycleLock.ownerToken,
      proxyId: effective.selection.proxyContainerId,
      proxyStartedAt,
      registryDigest: sessionRegistryDigest(input.stateDir, input.expectedProject),
      effectivePolicyGeneration: policy.controlGeneration,
      controlPlaneGenerationDigest: effective.selection.controlPlaneGenerationDigest,
      controlPlaneMaterializationDigest: effective.selection.controlPlaneMaterializationDigest,
      admissionContractEpoch: effective.selection.admissionContractEpoch,
    };
  } catch (error) {
    input.lifecycleLock.assertHeld();
    return `the session state is unreadable: ${error instanceof Error ? error.message : String(error)}`;
  }
  input.lifecycleLock.assertHeld();
  if (!consumeWarmPeerValidation(input.validation, binding)) return "the warm peer judgement no longer binds the runtime";
  return undefined;
}

/**
 * Restore admission after an explicitly authorized restart of the same proxy.
 * Returns the proxy start its eligibility publication was observed against.
 */
export async function restoreSameProxySessionAdmission(input: {
  plan: ActiveRuntimePlan;
  io: RuntimeIO;
  lifecycleLock: ProjectLifecycleLock;
  proxyId: string;
  validation?: RuntimeTokenSyncPreparation;
  /**
   * Unbudgeted IO for helper reclaim. Required when no `validation` is given:
   * the validation runs the ephemeral helpers, which refuse without it.
   */
  containmentIO?: RuntimeIO;
}): Promise<string> {
  const { plan, io, lifecycleLock, proxyId } = input;
  const expectedProject = { projectId: plan.projectId, composeProject: plan.composeProjectName };
  lifecycleLock.assertHeld();
  if (readControlPlaneRebindTransaction(plan.paths.stateDir, expectedProject)) {
    throw new Error("proxy replacement is pending; resume that transaction before a same-container restart");
  }
  // There is no admission journal to be pending; what says a session's
  // admission is unfinished is a record its owner stamped terminal.
  // Republishing this proxy's authority over an address whose teardown is
  // mid-flight is exactly what that stamp exists to stop.
  const admissionPending = listSessionContainerRecordsV2(plan.paths.stateDir, expectedProject).some((record) => (
    readSessionHostStatus(plan.paths.stateDir, record.sessionId)?.terminal === "revoking"
  ));
  if (admissionPending) {
    throw new Error(
      "session admission is pending; complete its owner recovery before restoring a restarted proxy; "
      + `run \`${remedy.up()}\` again once that teardown finishes`,
    );
  }
  const effective = readEffectiveControlPlaneV2(plan.paths.stateDir);
  if (!effective || effective.selection.proxyContainerId !== proxyId) {
    throw new Error("proxy identity changed; same-container admission restoration refused");
  }
  const context = runtimeContextFromActivePlan(plan);
  const { docker } = createRuntimeAdapters(context, io);
  if (!input.validation) {
    // The validation below runs ephemeral helpers, so this lock span needs the
    // same residue sweep `up` runs before its first helper (review C4).
    if (!input.containmentIO) throw new Error(EPHEMERAL_HELPER_FENCE_REQUIRED);
    reclaimHelperResidue({
      lifecycleLock,
      containmentIO: input.containmentIO,
      stateDir: plan.paths.stateDir,
      dockerEnv: dockerClientEnvOptions(context).env,
    }, plan.projectId);
  }
  const validation = input.validation ?? await prepareRuntimeForTokenSyncOrRemoveInvalid(plan, context, io, docker,
    { lifecycleLock, containmentIO: input.containmentIO });
  if (validation.status || !validation.proof || !validation.securityProof) {
    throw new Error("proxy restart validation failed; restore the reported runtime inputs and retry runtime reload-policy --force");
  }
  // Admin commands reconstruct the live plan without materializing a candidate.
  // Recover its missing digest from the selected immutable artifact, then run
  // the same generation, image, topology, and exact Docker identity checks.
  // An explicit conflicting plan digest must still refuse before publication.
  const proofPlan: ActiveRuntimePlan = {
    ...plan,
    activeRuntime: {
      ...plan.activeRuntime,
      controlPlaneMaterializationDigest: plan.activeRuntime.controlPlaneMaterializationDigest
        ?? effective.selection.controlPlaneMaterializationDigest,
    },
  };
  reproveRecordedCandidateControlPlaneV2({
    plan: proofPlan, recorded: effective.selection, runtimeProof: validation.proof,
    securityProof: validation.securityProof, lifecycleLock, io,
  });
  const records = listSessionContainerRecordsV2(plan.paths.stateDir, expectedProject);
  const assertAuthority = () => {
    lifecycleLock.assertHeld();
    if (!isDeepStrictEqual(readEffectiveControlPlaneV2(plan.paths.stateDir)?.selection, effective.selection)) {
      throw new Error("proxy selection changed during restart admission restoration");
    }
  };
  // Whether a surviving record still names a session this restart must restore.
  //
  // The record's own lease freezes at admission and nothing renews it, so a
  // session that has been beating for an hour carries the same lapsed lease as
  // one abandoned an hour ago, and a lease-only gate would clear the base state
  // under a live agent. Unknown owners remain protected until positive
  // process-death evidence permits reclamation.
  const restorableAuthority = (record: SessionContainerRecordV2): boolean => {
    if (record.leaseExpiresAt && Date.parse(record.leaseExpiresAt) > Date.now()) return true;
    const stamp = readSessionHostStatus(plan.paths.stateDir, record.sessionId);
    return sessionRecordLiveUnderSessionFiles(record, {
      nowEpochMs: Date.now(),
      env: context.env,
      ...(stamp ? { stamp } : {}),
    });
  };
  // Invariant 9, widen-before-new-files. The restart recreated the proxy's
  // session-file directory and removed `eligibility.json` with it, so the
  // eligibility comes back first and unconditionally — before the surviving
  // sessions are proved, and whether or not any survived. Publishing it admits
  // nothing on its own; the heartbeats refill the session files.
  const retained = readRetainedDesiredSessionAgentV2(plan.paths.stateDir);
  if (!retained) throw new Error(RETAINED_AGENT_TEMPLATE_REMEDY);
  assertAuthority();
  const proxyStartedAt = observeProxyStartedAt(io, proxyId, dockerClientEnvOptions(context));
  ensureSessionEligibilityPublished({
    io, proxyId, stateDir: plan.paths.stateDir, effective, desired: retained, records,
    proxyStartedAt,
    ignorePublicationRecord: true,
    dockerOptions: dockerClientEnvOptions(context),
  });
  assertAuthority();
  if (!records.some((record) => restorableAuthority(record))) {
    // The restarted proxy holds no session files, so its firewall supervisor's
    // next scan admits nothing. Prove that from the live kernel set rather than
    // assuming the loop ran.
    lifecycleLock.assertHeld();
    await waitForSessionAdmissionFirewallSetEmpty(io, proxyId, { assertAuthority: () => lifecycleLock.assertHeld(), dockerOptions: dockerClientEnvOptions(context) });
    return proxyStartedAt;
  }
  if (!("sessionTemplateArtifactSha256" in retained.manifest)) {
    throw new Error(RETAINED_AGENT_TEMPLATE_REMEDY);
  }
  // Every surviving record must still name a materialization this project
  // retains: the heartbeats below refill session files the proxy will serve,
  // and the eligibility they are served against is compiled from exactly this
  // set.
  compileAllowedSessionAgentMaterializationsV2({
    stateDir: plan.paths.stateDir, expectedProject, effectiveControlPlane: effective.selection,
    records, candidate: retained.manifest,
  });
  for (const record of records) {
    if (record.state !== "attached" && record.state !== "provisioning-running" || !restorableAuthority(record)) continue;
    lifecycleLock.assertHeld();
    const proofPlan = createRetainedSessionRebindProofPlan({
      stateDir: plan.paths.stateDir, expectedProject, replacementRecord: record,
      candidateControlPlane: effective.selection, candidateMaterialization: effective.manifest,
      docker, lifecycleLock, runfreeVersion: plan.runfreeVersion,
    });
    const inspected = createDockerClient(io, dockerClientEnvOptions(context)).inspect([record.containerId as string], { type: "container" });
    if (inspected.status !== 0) throw new Error(`session ${record.sessionId} cannot be inspected; restart admission remains incomplete`);
    validateSessionContainerInspect(inspected.stdout, proofPlan, { kind: "active-running" });
  }
  // There is no snapshot to republish and no consumer pointer to advance: the
  // eligibility was published above and the per-session heartbeats refill the
  // session files themselves.
  assertAuthority();
  return proxyStartedAt;
}
