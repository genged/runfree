import { LIFECYCLE_OPERATION_BUDGET_MS, withLifecycleOperationBudget } from "./lifecycle-operation-budget.ts";
import { captureRebindTrustReceipt } from "./rebind-trust-receipt.ts";
import net from "node:net";
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
import { PROJECT_ID_LABEL } from "./constants.ts";
import { CONTAINER_ROLE_LABEL, INGRESS_PURPOSE_LABEL } from "./container-inventory.ts";
import {
  ingressForwarderName,
} from "./ingress-forwarder.ts";
import { planValidatedIngressForwardersForRebuild } from "./ingress-forwarder-ownership.ts";
import { prepareEffectiveControlsForStartup } from "../control/workflow.ts";
import {
  convergeEffectivePolicyGeneration,
  effectiveControlSelectionForGeneration,
  readActiveControlSelection,
  readConvergedPolicyReceipt,
} from "../control/effective.ts";
import {
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
  parseDockerJson,
  type RuntimeDocker,
} from "./docker.ts";
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
  proveCandidateControlPlaneV2,
  proveAndSelectEffectiveControlPlaneV2,
  reproveRecordedCandidateControlPlaneV2,
} from "./control-plane-effective-proof.ts";
import { composeProjectName } from "./env.ts";
import { prepareGitRepositoryLayoutResult, serializeGitLayoutPlan } from "./git-layout.ts";
import {
  cleanupRunfreeImages,
  ensureRuntimeMaterialized,
  existingActiveRuntimePlan,
  materializeRetainedRebindRuntimePlan,
  RuntimeImageBuildStatus,
  selectEffectiveRuntimePlan,
  selectPreparedSessionAgent,
} from "./images.ts";
import {
  mcpOAuthCallbackPort,
  runtimeMcpOAuthPolicyHasServers,
} from "./mcp.ts";
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
import { reclaimHelperRunResidue, type EphemeralHelperFence } from "./ephemeral-helper-residue.ts";
import type {
  ActiveAgentSession,
  DockerContainerInspect,
  DockerPortBindings,
  RuntimeAdminIntent,
  RuntimeContext,
  RuntimeIO,
  TokenResolutionReceipt,
} from "./types.ts";
import {
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
import { reconcileSessions } from "./session-reconcile.ts";
import { waitForSessionAdmissionFirewallSetEmpty } from "./session-file-publisher.ts";
import {
  mintPreparedRuntime,
  type PreparedRuntime,
} from "./prepared-runtime.ts";
import { createRuntimeTimings } from "./timings.ts";
import { createOperationHistogram, withOperationHistogram } from "./operation-histogram.ts";
import { remedy } from "../remedies.ts";
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
    }
  | {
      kind: "failed";
      status: number;
      fastPath: false;
    };

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
): Promise<number> {
  reportRuntimeProgress("syncing proxy-managed tokens", verbose);
  return admin({ kind: "token-sync", verbose: Boolean(verbose) });
}

async function finalizeValidatedRuntime(
  plan: ActiveRuntimePlan,
  io: RuntimeIO,
  proof: RuntimeValidationProof | undefined,
  verbose?: boolean,
  proxyRecreated = false,
  lifecycleLock?: ProjectLifecycleLock,
  withCredentialResolution: (work: () => Promise<number>) => Promise<number> = (work) => work(),
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
  const tokenSync = await timings.timeAsync(
    "token-sync",
    () => withCredentialResolution(() => syncProxyManagedTokens((intent) => io.admin(intent, activeContext), verbose)),
  );
  const tokenResolutionReceipts = tokenSync === 0 ? io.takeTokenResolutionReceipts?.() ?? [] : [];
  if (tokenSync === 0) reportRuntimeProgress("runtime startup complete", verbose);
  return tokenSync === 0 ? {
    kind: "ready",
    fastPath: true,
    preparedRuntime,
    proxyRecreated,
    status: 0,
    tokenResolutionReceipts,
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

// How long an allocation may sit without a container before it stops being an
// admission in flight and becomes one that needs recovery. Allocation binds a
// created container within one Docker create; a minute is far outside that and
// far inside any human's retry.
const SESSION_FILE_ALLOCATION_WINDOW_MS = 60_000;

/**
 * What "a session admission is pending" means under the session-file source.
 *
 * There is no admission journal here, so the evidence is the registry itself,
 * in the two shapes that say a session's admission is unfinished:
 *
 *   - a record its owner stamped `terminal`: revocation started and did not
 *     finish, so the address is still reserved and the proxy may still hold the
 *     file;
 *   - an `allocated` record with no container id, older than the allocation
 *     window: the address was reserved and the container never appeared.
 *
 * Everything else — a young allocation, a bound record, a record beating
 * normally — is ordinary concurrent state that no runtime upgrade may be
 * refused over. Reading the stamp never throws; an unreadable one is absent,
 * which leaves only the allocation rule.
 */
function pendingSessionFileAdmissionRecords(input: Readonly<{
  stateDir: string;
  records: readonly SessionContainerRecordV2[];
  nowEpochMs: number;
}>): readonly SessionContainerRecordV2[] {
  return input.records.filter((record) => {
    if (readSessionHostStatus(input.stateDir, record.sessionId)?.terminal === "revoking") return true;
    if (record.state !== "allocated" || record.containerId !== undefined) return false;
    const createdAtMs = Date.parse(record.createdAt);
    return Number.isFinite(createdAtMs)
      && input.nowEpochMs - createdAtMs > SESSION_FILE_ALLOCATION_WINDOW_MS;
  });
}

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
): RuntimeUpgradePlan {
  try {
    const expectedProject = {
      projectId: desiredPlan.projectId,
      composeProject: desiredPlan.composeProjectName,
    };
    const effectiveControlPlane = readEffectiveControlPlaneV2(desiredPlan.paths.stateDir);
    const retainedDesiredSessionAgent = readRetainedDesiredSessionAgentV2(desiredPlan.paths.stateDir);
    const lifecycleRecords = listSessionContainerRecordsV2(desiredPlan.paths.stateDir, expectedProject);
    const pendingAdmission = pendingSessionFileAdmissionRecords({
      stateDir: desiredPlan.paths.stateDir,
      records: lifecycleRecords,
      nowEpochMs: Date.now(),
    }).length > 0;
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

function hasOnlyLoopbackPortBinding(bindings: DockerPortBindings | null | undefined, port: number): boolean {
  const entries = Object.entries(bindings ?? {})
    .filter(([, values]) => Array.isArray(values) && values.length > 0);
  if (entries.length !== 1) return false;
  const [[containerPort, values]] = entries;
  return containerPort === `${port}/tcp`
    && Array.isArray(values)
    && values.length > 0
    && values.every((binding) => binding?.HostIp === "127.0.0.1" && binding.HostPort === String(port));
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

function validateRuntimeTopologyOrRemoveInvalid(
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
  } = {},
): { denyByDefaultObservation?: DenyByDefaultObservationV1; status: number; failureKind?: RuntimeFailureKind } {
  let boundaryViolated = false;
  const validation = validateRuntimeTopologyWithProof(plan, io, {
    onBoundaryViolation: () => { boundaryViolated = true; },
    progress: options.verbose === true,
    verbose: options.verbose,
    expectedProxyId: options.expectedProxyId,
    helperFence: options.helperFence,
    helperImage: options.helperImage,
  });
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
  const probe = io.capture(
    "docker",
    ["exec", containerId, "sh", "-c", runtimeSecurityContractProbeScript(contract)],
    dockerClientEnvOptions(context),
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
  const inspects = parseDockerJson<DockerContainerInspect[]>(
    io.capture("docker", ["inspect", ...(agentId ? [agentId] : []), proxyId], dockerClientEnvOptions(context)),
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
      const privateCaProbe = io.capture(
        "docker",
        ["exec", agentId, "sh", "-c", "test ! -e /ca/private/proxy-ca.key"],
        dockerClientEnvOptions(context),
      );
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


/**
 * The OAuth callback port is held by the per-session mcp-callback ingress forwarder
 * (hop 1), a standalone hardened sidecar named
 * `runfree-ingress-mcp-callback-<projectId>-<port>` rather than a Compose
 * service. The only benign case is our own forwarder for this exact project,
 * still running and still publishing exactly 127.0.0.1:<port> on both the
 * requested publication and the live binding. Every unproven case — no
 * forwarder, a failed or malformed inspection, a stopped container, a wrong
 * project id, a wrong role or purpose label, a different published port, or any
 * non-loopback binding — returns false and the port stays denied.
 */
export function mcpOAuthCallbackPortHeldByOwnIngressForwarder(
  context: RuntimeContext,
  io: RuntimeIO,
  port: number,
): boolean {
  const projectId = projectHash(context.projectRoot);
  const name = ingressForwarderName(projectId, "mcp-callback", String(port));
  const inspect = parseDockerJson<DockerContainerInspect[]>(
    io.capture("docker", ["inspect", name], dockerClientEnvOptions(context)),
    "docker inspect MCP OAuth callback ingress forwarder port ownership",
  );
  const forwarder = inspect?.[0];
  if (!forwarder || inspect.length !== 1) return false;
  if (forwarder.State?.Running !== true) return false;
  const forwarderLabels = forwarder.Config?.Labels ?? {};
  if (forwarderLabels[PROJECT_ID_LABEL] !== projectId) return false;
  if (forwarderLabels[CONTAINER_ROLE_LABEL] !== "ingress-forwarder") return false;
  if (forwarderLabels[INGRESS_PURPOSE_LABEL] !== "mcp-callback") return false;
  // Both views must agree: the requested publication and the live binding.
  return hasOnlyLoopbackPortBinding(forwarder.HostConfig?.PortBindings, port)
    && hasOnlyLoopbackPortBinding(forwarder.NetworkSettings?.Ports, port);
}

function checkMcpOAuthCallbackPortAvailable(
  context: RuntimeContext,
  io: RuntimeIO,
): Promise<number> {
  if (!runtimeMcpOAuthPolicyHasServers(context.project)) return Promise.resolve(0);
  if (context.env?.RUNFREE_TEST_MCP_CALLBACK_PORT_AVAILABLE === "1") return Promise.resolve(0);
  const port = mcpOAuthCallbackPort(context.projectRoot);
  return new Promise((resolve) => {
    const server = net.createServer();
    const done = (status: number) => {
      server.removeAllListeners();
      resolve(status);
    };
    const denyUnlessOwnSidecar = () => {
      if (mcpOAuthCallbackPortHeldByOwnIngressForwarder(context, io, port)) {
        done(0);
        return;
      }
      runfreeLog(`MCP OAuth callback port ${port} is already in use on 127.0.0.1`);
      runfreeLog("stop the process using that port or remove stale Runfree runtime state");
      done(1);
    };
    server.once("error", () => {
      denyUnlessOwnSidecar();
    });
    server.listen({ host: "127.0.0.1", port, exclusive: true }, () => {
      server.close((error) => {
        if (error) {
          denyUnlessOwnSidecar();
          return;
        }
        done(0);
      });
    });
  });
}

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

async function prepareRuntimeForTokenSyncOrRemoveInvalid(
  activePlan: ActiveRuntimePlan,
  context: RuntimeContext,
  io: RuntimeIO,
  docker: RuntimeDocker,
  options: { verbose?: boolean; lifecycleLock?: ProjectLifecycleLock; readOnly?: boolean; containmentIO?: RuntimeIO } = {},
): Promise<RuntimeTokenSyncPreparation> {
  const timings = createRuntimeTimings(context.env);
  const project = composeProjectName(context.projectRoot);
  const gitLayout = timings.time("validation:git-layout", () => prepareGitRepositoryLayoutResult(context));
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
  // chowns them, and unconditionally so `runfree-commandhistory` exists even
  // when dependency overlays are off.
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
  const validation = timings.time(
    "validation:topology",
    () => validateRuntimeTopologyOrRemoveInvalid(activePlan, validationContext, io, docker, { ...options, expectedProxyId: readinessProxyId, helperFence, helperImage }),
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
  let confirmedRebuildSessions: readonly ActiveAgentSession[] = [];
  try {
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
      const preparedControls = await timings.timeAsync("control-preparation", () => prepareEffectiveControlsForStartup(context, io, {
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
        ensureDockerAvailable();
        return initialAdapters.docker.networkSubnets();
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

    const gitLayout = prepareGitRepositoryLayoutResult(initialContext);
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
    ensureAgentState(gitPreparedContext);
    writeProjectRecoveryPointer(gitPreparedContext);
    ensureSandboxGitConfig(gitPreparedContext, io);
    const dependencyPlan: PreparedDependencyOverlayPlan = prepareDependencyOverlayPlanResult(gitPreparedContext, io);
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

    ensureDockerAvailable();
    // Capture the proxy container id before any lifecycle change. The proxy
    // loads the on-disk policy at boot, so a changed id afterwards means it
    // already reflects the merged policy and a follow-up policy reload is moot.
    const proxyContainerIdBefore = adapters.docker.runningServiceContainerId(
      existingActivePlan.composeProjectName,
      "proxy",
    );
    const proxyRecreatedSinceStart = (docker: RuntimeDocker): boolean =>
      docker.runningServiceContainerId(existingActivePlan.composeProjectName, "proxy")
        !== proxyContainerIdBefore;
    let upgradePlan: RuntimeUpgradePlan = { action: "none", services: [] };
    if (!removeExisting) {
      await awaitLiveSessionAdmissionQuiescence(preparedPlan.paths.stateDir, {
        projectId: preparedPlan.projectId,
        composeProject: preparedPlan.composeProjectName,
      });
      upgradePlan = planRuntimeUpgradeFromV2State(preparedPlan, existingContext, adapters.docker);
      reportRuntimeVerbose(verbose, `runtime upgrade plan is ${upgradePlan.action}`);
      if (verbose) {
        for (const line of runtimeComponentDiagnosticLines({
          action: upgradePlan.action,
          desired: preparedPlan.generationV2,
          stateDir: preparedPlan.paths.stateDir,
        })) reportRuntimeVerbose(true, line);
      }
      const upgradeStatus = applyRuntimeUpgradePlan(existingContext, adapters.docker, upgradePlan);
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
        const repair = await repairStaleComposeNetworkState(existingContext, adapters.docker);
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
    await io.prepareTokenSources?.(runtimeContextFromActivePlan(activePlan));
    // Capture and compare under the lock. This pair detects a *change during
    // preparation*; it is not the mismatch gate. Once the reader returns a
    // value instead of throwing, a persistent mismatch compares equal to itself
    // and passes the comparison below — the recovery gate ran long before here.
    const preparedApproval = readControlApprovalSelection(context.projectRoot, context.project);
    lifecycleLock ??= await tryAcquireProjectLifecycleLockWithRetry(preparedContext);
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
    // Design D-D: a helper-run directory present when the lock is newly
    // acquired is residue of a run whose CLI died (invariant I5). Reclaim it
    // before anything can run a new helper or admit a session, since a
    // lingering helper blocks admission as an unclaimed project container.
    // No residue costs one lstat and no Docker call.
    try {
      const residue = reclaimHelperRunResidue({
        lifecycleLock: heldLifecycleLock,
        containmentIO,
        stateDir: preparedPlan.paths.stateDir,
        dockerEnv: dockerClientEnvOptions(preparedContext).env,
      }, preparedPlan.projectId);
      if (residue.pending > 0) {
        warn(`${residue.pending} killed ephemeral helper run(s) are kept until a late container create can no longer land; the next \`${remedy.up()}\` re-checks them`);
      }
    } catch (error) {
      warn(error instanceof Error ? error.message : String(error));
      return result(1, false, preparedContext);
    }
    heldLifecycleLock.assertHeld();
    const currentConfig = readConfig(context.projectRoot);
    const currentPlan = createRuntimePlan(preparedContext,
      { dockerSubnets: [], persistNetwork: false });
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
    io.admitPreparedTokenSources?.(runtimeContextFromActivePlan(activePlan));
    selectPreparedSessionAgent(activePlan, adapters.docker);
    if (!removeExisting) {
      upgradePlan = planRuntimeUpgradeFromV2State(preparedPlan, existingContext, adapters.docker);
      const status = applyRuntimeUpgradePlan(existingContext, adapters.docker, upgradePlan);
      if (status !== 0) return result(status, false, existingContext);
    }
    const activeContext = runtimeContextFromActivePlan(activePlan, {
      dependencyOverlayPlanChanged: dependencyPlan.changed,
      gitLayoutPlanChanged: gitLayout.changed,
    });
    adapters = createRuntimeAdapters(activeContext, io);

    const project = activePlan.composeProjectName;
    const validateSelectAndSync = async (): Promise<RuntimeStartResult> => {
      timings.time("image-cleanup", () => cleanupRunfreeImages(activeContext, adapters.docker, io, {
        controlPlaneMaterializationDigest: activePlan.activeRuntime.controlPlaneMaterializationDigest,
        sessionAgentMaterializationDigest: readRetainedDesiredSessionAgentV2(
          activePlan.paths.stateDir,
        )?.selection.sessionAgentMaterializationDigest,
      }));
      const validation = await timings.timeAsync(
        "runtime-validation",
        () => prepareRuntimeForTokenSyncOrRemoveInvalid(activePlan, activeContext, io, adapters.docker, { verbose, lifecycleLock: heldLifecycleLock, containmentIO }),
      );
      if (validation.status !== 0) return result(validation.status, false, activeContext);
      const runtimeProof = validation.proof;
      const securityProof = validation.securityProof;
      const denyByDefaultObservation = validation.denyByDefaultObservation;
      if (!runtimeProof || !securityProof || !denyByDefaultObservation) {
        warn("validated control-plane proof is incomplete before credential sync");
        return result(1, false, activeContext);
      }
      let selectedPlan: ActiveRuntimePlan;
      try {
        heldLifecycleLock.assertHeld();
        selectedPlan = selectEffectiveRuntimePlan(activePlan);
        heldLifecycleLock.assertHeld();
        timings.time("control-plane-selection", () => {
          const alreadySelected = readEffectiveControlPlaneV2(activePlan.paths.stateDir);
          const reusesExactControlPlane = alreadySelected !== undefined
            && alreadySelected.manifest.generation.controlPlaneGenerationDigest
              === activePlan.generationV2.controlPlane.controlPlaneGenerationDigest
            && alreadySelected.manifest.controlPlaneMaterializationDigest
              === activePlan.activeRuntime.controlPlaneMaterializationDigest
            && effectiveControlPlaneMatchesLiveRuntimeValidationV2(activePlan, runtimeProof, io);
          if (!reusesExactControlPlane) {
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
        ensureSessionEligibilityPublished({
          io,
          proxyId: runtimeProof.proxyId,
          proxyStartedAt: observeProxyStartedAt(io, runtimeProof.proxyId, dockerClientEnvOptions(activeContext)),
          stateDir: activePlan.paths.stateDir,
          effective,
          desired,
          records: listSessionContainerRecordsV2(activePlan.paths.stateDir, { projectId: activePlan.projectId, composeProject: project }),
          dockerOptions: dockerClientEnvOptions(activeContext),
        });
        heldLifecycleLock.assertHeld();
        // Invariant 3, from the other end: `up` is the point a project comes
        // back after a crash, so the same reconcile every launch runs is run
        // here too — files no record accounts for, records whose owner is
        // gone, and containers nothing claims are cleared while the lock is
        // held and before any session can be admitted. It follows the
        // publication above, which widened the admitted set; step 5 of the
        // reconcile narrows it again once the residue is gone.
        await reconcileSessions({
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
        });
        heldLifecycleLock.assertHeld();
      } catch (error) {
        warn(error instanceof Error ? error.message : String(error));
        return result(1, false, activeContext);
      }
      // A warm proxy that kept its container id can still have restarted in
      // place, taking its session-file directory and eligibility with it. The
      // restore re-proves every surviving session and republishes the
      // eligibility unconditionally, so it runs whenever this project still has
      // lifecycle records to restore.
      if (listSessionContainerRecordsV2(activePlan.paths.stateDir, { projectId: activePlan.projectId, composeProject: project }).length) {
        await restoreSameProxySessionAdmission({ plan: activePlan, io, lifecycleLock: heldLifecycleLock, proxyId: runtimeProof.proxyId, validation });
      }
      return finalizeValidatedRuntime(
        selectedPlan,
        io,
        runtimeProof,
        verbose,
        proxyRecreatedSinceStart(adapters.docker),
        heldLifecycleLock,
        async (work) => { heldLifecycleLock.release(); return await work(); },
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
            { verbose, lifecycleLock: heldLifecycleLock, readOnly: true, containmentIO },
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
            { verbose, lifecycleLock: heldLifecycleLock, readOnly: true, containmentIO },
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
          const removed = rebindIO.capture("docker", ["rm", proxyId], { env: activePlan.execution.dockerClientEnv, timeout: 1000 });
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
              const inspect = rebindIO.capture(
                "docker",
                ["container", "inspect", replacementRecord.containerId as string],
                dockerClientEnvOptions(activeContext),
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
    const callbackPortAvailable = await checkMcpOAuthCallbackPortAvailable(activeContext, io);
    if (callbackPortAvailable !== 0) return result(callbackPortAvailable, false, activeContext);
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
      lifecycleLock?.release();
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

/** Restore admission after an explicitly authorized restart of the same proxy. */
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
}): Promise<void> {
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
    // same residue reclaim `up` runs before its first helper (review C4).
    if (!input.containmentIO) throw new Error(EPHEMERAL_HELPER_FENCE_REQUIRED);
    reclaimHelperRunResidue({
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
  ensureSessionEligibilityPublished({
    io, proxyId, stateDir: plan.paths.stateDir, effective, desired: retained, records,
    proxyStartedAt: observeProxyStartedAt(io, proxyId, dockerClientEnvOptions(context)),
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
    return;
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
    const inspected = io.capture("docker", ["container", "inspect", record.containerId as string], dockerClientEnvOptions(context));
    if (inspected.status !== 0) throw new Error(`session ${record.sessionId} cannot be inspected; restart admission remains incomplete`);
    validateSessionContainerInspect(inspected.stdout, proofPlan, { kind: "active-running" });
  }
  // There is no snapshot to republish and no consumer pointer to advance: the
  // eligibility was published above and the per-session heartbeats refill the
  // session files themselves.
  assertAuthority();
}
