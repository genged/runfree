import { isDeepStrictEqual } from "node:util";
import { sha256Digest } from "./component-state.ts";

import {
  readDesiredSessionAgentV2,
  readEffectiveControlPlaneV2,
  readRetainedDesiredSessionAgentV2,
  selectEffectiveControlPlaneV2,
  type ControlPlaneEffectiveSelectionV2,
  type ControlPlaneMaterializationManifestV2,
} from "./component-state-v2.ts";
import {
  CONTROL_PLANE_REBIND_PHASES,
  advanceControlPlaneRebindTransaction,
  nextControlPlaneRebindPhase,
  completeControlPlaneRebindTransaction,
  createControlPlaneRebindTransaction,
  createReboundSessionContainerRecordV2,
  prepareControlPlaneRebindTransaction,
  readControlPlaneRebindTransaction,
  refreshControlPlaneRebindTransaction,
  takeOverControlPlaneRebindTransaction,
  type ControlPlaneRebindPhase,
  type ControlPlaneRebindTransaction,
  type SessionRebindProofSummary,
  checkpointRebindRecovery,
  appendRetiredRebindReceipt,
  migrateRebindTransactionV1,
  restartRebindCandidateAttempt,
} from "./control-plane-rebind.ts";
import { REBIND_PHASE_EFFECTS, REBIND_RECOVERY_BUDGET_MS, REBIND_RECOVERY_CREATIONS, RebindRecoveryExhaustedError } from "./control-plane-rebind-recovery.ts";
import {
  ensureSessionEligibilityPublished,
  observeProxyStartedAt,
} from "./session-eligibility-publication.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import type { PreparedRuntime } from "./prepared-runtime.ts";
import {
  classifySessionAgentMaterializationEligibilityV2,
} from "./session-materialization-eligibility.ts";
import {
  assertSessionContainerProof,
  type SessionContainerProof,
} from "./session-container-proof.ts";
import {
  listSessionContainerRecordsV2,
  readSessionContainerRecordV2,
  replaceExactSessionContainerRecordForControlPlaneRebindV2,
  replaceExactSessionContainerRecordV2,
  transitionSessionContainerToRevokingV2,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { RuntimeIO, TokenResolutionReceipt } from "./types.ts";
import { sessionRecordOwnerLiveness } from "./session-record-liveness.ts";
import { RuntimeObservationError } from "./observation-failure.ts";

export type ControlPlaneRebindFinalization = Readonly<{
  preparedRuntime: PreparedRuntime;
  tokenResolutionReceipts: readonly TokenResolutionReceipt[];
}>;

type RebindServices = Readonly<{
  captureTrustReceipt?(): string;
  startAndProveCandidate(transaction: ControlPlaneRebindTransaction): Promise<ControlPlaneEffectiveSelectionV2>;
  recoverUnrecordedCandidate?(transaction: ControlPlaneRebindTransaction): Promise<ControlPlaneEffectiveSelectionV2 | { stoppedProxyId: string } | undefined>;
  retireUnrecordedCandidate?(proxyId: string): Promise<void>;
  observeRecordedCandidate?(recorded: ControlPlaneEffectiveSelectionV2): Promise<"present" | "absent" | "stopped">;
  retireStoppedCandidate?(recorded: ControlPlaneEffectiveSelectionV2): Promise<void>;
  proveCandidate(): Promise<ControlPlaneEffectiveSelectionV2>;
  reproveCandidate(recorded: ControlPlaneEffectiveSelectionV2): Promise<void>;
  proveSession(record: SessionContainerRecordV2): SessionContainerProof;
  participantIsAbsent?(record: SessionContainerRecordV2): boolean;
  finalize(): Promise<ControlPlaneRebindFinalization>;
}>;

export type ControlPlaneRebindCoordinatorInput = Readonly<{
  plan: ActiveRuntimePlan;
  lifecycleLock: ProjectLifecycleLock;
  io: RuntimeIO;
  oldControlPlane: Readonly<{
    selection: ControlPlaneEffectiveSelectionV2;
    manifest: ControlPlaneMaterializationManifestV2;
  }>;
  candidateMaterialization: ControlPlaneMaterializationManifestV2;
  services: RebindServices;
  now?: () => Date;
  randomBytes?: (size: number) => Uint8Array;
  explicitRetry?: boolean;
}>;

export class ControlPlaneRebindCandidateMismatchError extends Error {
  constructor(fields: readonly string[] = []) {
    super("proved candidate control-plane authority contradicts the rebind journal"
      + (fields.length ? `: ${fields.join(", ")}` : ""));
    this.name = "ControlPlaneRebindCandidateMismatchError";
  }
}

function expectedProject(input: ControlPlaneRebindCoordinatorInput): SessionContainerProjectIdentity {
  return { projectId: input.plan.projectId, composeProject: input.plan.composeProjectName };
}

function nextTransaction(
  input: ControlPlaneRebindCoordinatorInput,
  current: ControlPlaneRebindTransaction,
  phase: ControlPlaneRebindPhase,
  changes: Partial<ControlPlaneRebindTransaction> = {},
): ControlPlaneRebindTransaction {
  input.lifecycleLock.assertHeld();
  if (current.lockOwnerToken !== input.lifecycleLock.ownerToken) {
    throw new Error("control-plane rebind transaction is fenced by another lifecycle lock");
  }
  if (nextControlPlaneRebindPhase(current.phase) !== phase) {
    throw new Error("control-plane rebind coordinator attempted an out-of-order phase");
  }
  const next = Object.freeze({
    ...current,
    ...changes,
    ...(current.recovery ? { recovery: { ...current.recovery, ...changes.recovery,
      outstandingEffect: REBIND_PHASE_EFFECTS[phase] } } : {}),
    phase,
    updatedAt: (input.now?.() ?? new Date()).toISOString(),
  }) as ControlPlaneRebindTransaction;
  advanceControlPlaneRebindTransaction(input.plan.paths.stateDir, current, next);
  return next;
}

function claimTransactionFence(
  input: ControlPlaneRebindCoordinatorInput,
  current: ControlPlaneRebindTransaction,
): ControlPlaneRebindTransaction {
  input.lifecycleLock.assertHeld();
  if (current.lockOwnerToken === input.lifecycleLock.ownerToken) return current;
  const claimed = Object.freeze({
    ...current,
    lockOwnerToken: input.lifecycleLock.ownerToken,
    updatedAt: (input.now?.() ?? new Date()).toISOString(),
  }) as ControlPlaneRebindTransaction;
  takeOverControlPlaneRebindTransaction(input.plan.paths.stateDir, current, claimed);
  input.lifecycleLock.assertHeld();
  return claimed;
}

function exactCandidate(
  transaction: ControlPlaneRebindTransaction,
  candidate: ControlPlaneEffectiveSelectionV2,
): ControlPlaneEffectiveSelectionV2 {
  if (candidate.projectId !== transaction.projectId
    || candidate.composeProject !== transaction.composeProject
    || candidate.controlPlaneGenerationDigest
      !== transaction.candidateMaterialization.generation.controlPlaneGenerationDigest
    || candidate.controlPlaneMaterializationDigest
      !== transaction.candidateMaterialization.controlPlaneMaterializationDigest
    || candidate.proxyImageId !== transaction.candidateMaterialization.proxyImageId
    || candidate.admissionContractEpoch
      !== transaction.candidateMaterialization.generation.admissionContractEpoch) {
    throw new Error("proved candidate control plane contradicts the rebind transaction");
  }
  if (transaction.candidateControlPlane) {
    // Receipt time/hash and the observing CLI version describe provenance.
    // All remaining fields, including future fields, bind exact identity.
    const { selectedAt: _recordedAt, denyByDefaultBaseProofHash: _recordedHash, runfreeVersion: _recordedVersion, ...recordedAuthority } = transaction.candidateControlPlane;
    const { selectedAt: _provedAt, denyByDefaultBaseProofHash: _provedHash, runfreeVersion: _provedVersion, ...provedAuthority } = candidate;
    if (!isDeepStrictEqual(recordedAuthority, provedAuthority)) {
      const fields = [...new Set([...Object.keys(recordedAuthority), ...Object.keys(provedAuthority)])]
        .filter((key) => !isDeepStrictEqual(Reflect.get(recordedAuthority, key), Reflect.get(provedAuthority, key)));
      throw new ControlPlaneRebindCandidateMismatchError(fields);
    }
    return transaction.candidateControlPlane;
  }
  return candidate;
}

function assertDurableControlFence(
  input: ControlPlaneRebindCoordinatorInput,
  transaction: ControlPlaneRebindTransaction,
): void {
  const durable = readEffectiveControlPlaneV2(input.plan.paths.stateDir);
  if (!durable) throw new Error("control-plane rebind lost its durable effective selection");
  const phaseIndex = CONTROL_PLANE_REBIND_PHASES.indexOf(transaction.phase);
  const selectedIndex = CONTROL_PLANE_REBIND_PHASES.indexOf("control-selected");
  // The phase whose own case body performs the selection: a crash inside it
  // leaves the journal there with either selection durable.
  const selectingIndex = CONTROL_PLANE_REBIND_PHASES.indexOf("eligibility-published");
  const isOld = isDeepStrictEqual(durable.selection, transaction.oldControlPlane);
  const isCandidate = transaction.candidateControlPlane !== undefined
    && isDeepStrictEqual(durable.selection, transaction.candidateControlPlane);
  if (phaseIndex >= selectedIndex ? !isCandidate : phaseIndex === selectingIndex ? !isOld && !isCandidate : !isOld) {
    throw new Error("control-plane rebind durable selection contradicts its transaction phase");
  }
}

function proofSummary(record: SessionContainerRecordV2, proof: SessionContainerProof): SessionRebindProofSummary {
  if (!proof.dockerPid || !proof.dockerStartedAt || !proof.networkEndpointId) {
    throw new Error(`session ${record.sessionId} proof has incomplete Docker identity`);
  }
  return Object.freeze({
    sessionId: record.sessionId,
    projectId: proof.projectId,
    sessionIncarnation: proof.sessionIncarnation,
    sessionPrincipal: proof.sessionPrincipal,
    containerId: proof.containerId,
    imageId: proof.imageId,
    sessionAgentGenerationDigest: proof.sessionAgentGenerationDigest,
    controlPlaneGenerationDigest: proof.controlPlaneGenerationDigest,
    admissionContractEpoch: proof.admissionContractEpoch,
    networkId: proof.networkId,
    sourceIp: proof.sourceIp,
    dockerPid: proof.dockerPid,
    dockerStartedAt: proof.dockerStartedAt,
    networkEndpointId: proof.networkEndpointId,
  });
}

function sameProof(left: SessionRebindProofSummary, right: SessionContainerProof): boolean {
  return left.projectId === right.projectId
    && left.sessionIncarnation === right.sessionIncarnation
    && left.sessionPrincipal === right.sessionPrincipal
    && left.containerId === right.containerId
    && left.imageId === right.imageId
    && left.sessionAgentGenerationDigest === right.sessionAgentGenerationDigest
    && left.controlPlaneGenerationDigest === right.controlPlaneGenerationDigest
    && left.admissionContractEpoch === right.admissionContractEpoch
    && left.networkId === right.networkId
    && left.sourceIp === right.sourceIp
    && left.dockerPid === right.dockerPid
    && left.dockerStartedAt === right.dockerStartedAt
    && left.networkEndpointId === right.networkEndpointId;
}

function sameRebindParticipant(
  current: SessionContainerRecordV2,
  old: SessionContainerRecordV2,
  transaction: ControlPlaneRebindTransaction,
): boolean {
  if (current.state !== "attached"
    || (current.controlPlaneGenerationDigest !== transaction.oldControlPlane.controlPlaneGenerationDigest
      && current.controlPlaneGenerationDigest
        !== transaction.candidateControlPlane?.controlPlaneGenerationDigest)) return false;
  const {
    state: _currentState,
    controlPlaneGenerationDigest: _currentControl,
    leaseGeneration: _currentLease,
    leaseExpiresAt: _currentExpiry,
    ...currentIdentity
  } = current;
  const {
    state: _oldState,
    controlPlaneGenerationDigest: _oldControl,
    leaseGeneration: _oldLease,
    leaseExpiresAt: _oldExpiry,
    ...oldIdentity
  } = old;
  return isDeepStrictEqual(currentIdentity, oldIdentity);
}

function revalidateSessions(
  input: ControlPlaneRebindCoordinatorInput,
  transaction: ControlPlaneRebindTransaction,
): Readonly<{
  inputs: readonly SessionContainerRecordV2[];
  replacements: readonly SessionContainerRecordV2[];
  invalidSessionIds: readonly string[];
  proofs: readonly SessionRebindProofSummary[];
}> {
  const candidate = transaction.candidateControlPlane;
  if (!candidate) throw new Error("control-plane rebind has no proved candidate");
  const inputs: SessionContainerRecordV2[] = [];
  const replacements: SessionContainerRecordV2[] = [];
  const invalidSessionIds: string[] = [];
  const proofs: SessionRebindProofSummary[] = [];
  transaction.oldRecords.forEach((record) => {
    try {
      const current = readSessionContainerRecordV2(
        input.plan.paths.stateDir,
        expectedProject(input),
        record.sessionId,
      );
      if (!current && input.services.participantIsAbsent?.(record)) {
        invalidSessionIds.push(record.sessionId);
        return;
      }
      if (current?.state === "revoking" && sameRebindParticipant({ ...current, state: "attached" }, { ...record, state: "attached" }, transaction)) {
        inputs.push(current);
        invalidSessionIds.push(record.sessionId);
        return;
      }
      if (!current || !sameRebindParticipant(current, record, transaction)) {
        throw new Error("session record no longer matches its rebind participant");
      }
      inputs.push(current);
      const replacement = createReboundSessionContainerRecordV2({
        current,
        candidateControlPlane: candidate,
      });
      const proof = input.services.proveSession(replacement);
      assertSessionContainerProof(
        proof,
        replacement,
        "active-running",
        candidate.networkIds.agentInternal,
      );
      replacements.push(replacement);
      proofs.push(proofSummary(record, proof));
    } catch (cause) {
      input.lifecycleLock.assertHeld();
      if (record.state === "revoking" || sessionRecordOwnerLiveness(record, input.plan.execution.dockerClientEnv) === "dead") {
        invalidSessionIds.push(record.sessionId);
      } else {
        if (cause instanceof RuntimeObservationError) throw cause;
        throw new RuntimeObservationError({
          kind: "unclassified", subject: "session", expectedIdentity: record.sessionId,
          phase: transaction.phase,
          observation: "fresh rebind proof failed; record and process preserved; restore its runtime evidence and resume recovery",
        }, cause);
      }
    }
  });
  if (replacements.length > 0) {
    const desired = readDesiredSessionAgentV2(input.plan.paths.stateDir);
    if (!desired) throw new Error("control-plane rebind requires a desired session-agent materialization");
    const classified = classifySessionAgentMaterializationEligibilityV2({
      stateDir: input.plan.paths.stateDir,
      expectedProject: expectedProject(input),
      effectiveControlPlane: candidate,
      records: replacements,
      candidate: desired.manifest,
    });
    const materializationInvalid = new Set(classified.invalidRecords.map((record) => record.sessionId));
    if (materializationInvalid.size > 0) {
      for (const record of classified.invalidRecords) {
        if (sessionRecordOwnerLiveness(record, input.plan.execution.dockerClientEnv) !== "dead") {
          throw new RuntimeObservationError({
            kind: "identity-contradiction", subject: "session", expectedIdentity: record.sessionId,
            phase: transaction.phase,
            observation: "retained agent materialization is unavailable or incompatible; restore it before resuming recovery",
          });
        }
      }
      invalidSessionIds.push(...materializationInvalid);
      const retainedProofs = new Map(proofs.map((proof) => [proof.sessionId, proof]));
      return {
        inputs: Object.freeze(inputs),
        replacements: Object.freeze(replacements.filter((record) => !materializationInvalid.has(record.sessionId))),
        invalidSessionIds: Object.freeze([...new Set(invalidSessionIds)]),
        proofs: Object.freeze([...retainedProofs.values()].filter((proof) => (
          !materializationInvalid.has(proof.sessionId)
        ))),
      };
    }
  }
  return {
    inputs: Object.freeze(inputs),
    replacements: Object.freeze(replacements),
    invalidSessionIds: Object.freeze([...new Set(invalidSessionIds)]),
    proofs: Object.freeze(proofs),
  };
}

function applyRecordBatch(
  input: ControlPlaneRebindCoordinatorInput,
  transaction: ControlPlaneRebindTransaction,
): void {
  const project = expectedProject(input);
  const replacements = new Map(transaction.replacementRecords.map((record) => [record.sessionId, record]));
  const invalid = new Set(transaction.invalidSessionIds);
  for (const old of transaction.oldRecords) {
    input.lifecycleLock.assertHeld();
    const current = readSessionContainerRecordV2(input.plan.paths.stateDir, project, old.sessionId);
    if (!current) {
      if (invalid.has(old.sessionId)) continue;
      throw new Error(`session ${old.sessionId} disappeared during control-plane rebind`);
    }
    const replacement = replacements.get(old.sessionId);
    if (replacement) {
      if (isDeepStrictEqual(current, replacement)) continue;
      const expectedInput = transaction.recovery?.batchInputs?.find((record) => record.sessionId === old.sessionId) ?? old;
      if (!isDeepStrictEqual(current, expectedInput)) {
        throw new Error(`session ${old.sessionId} changed during control-plane rebind; revalidate a new batch before writing`);
      }
      if (current.controlPlaneGenerationDigest === replacement.controlPlaneGenerationDigest) {
        replaceExactSessionContainerRecordV2(input.plan.paths.stateDir, project, current, replacement);
      } else {
        replaceExactSessionContainerRecordForControlPlaneRebindV2(
          input.plan.paths.stateDir,
          project,
          current,
          replacement,
        );
      }
      continue;
    }
    if (!invalid.has(old.sessionId)) throw new Error("control-plane rebind record batch is incomplete");
    if (current.state === "revoking") {
      const attached = { ...current, state: "attached" as const };
      if (!sameRebindParticipant(attached, old, transaction)) {
        throw new Error(`invalid session ${old.sessionId} changed before revocation`);
      }
      continue;
    }
    if (!sameRebindParticipant(current, old, transaction)) {
      throw new Error(`invalid session ${old.sessionId} changed before revocation`);
    }
    if (sessionRecordOwnerLiveness(current, input.plan.execution.dockerClientEnv) !== "dead") {
      throw new Error(`session ${old.sessionId} has no proved dead owner; restore its evidence before recovery`);
    }
    replaceExactSessionContainerRecordV2(
      input.plan.paths.stateDir,
      project,
      current,
      transitionSessionContainerToRevokingV2(current),
    );
  }
}

function phaseAtLeast(transaction: ControlPlaneRebindTransaction, phase: ControlPlaneRebindPhase): boolean {
  return CONTROL_PLANE_REBIND_PHASES.indexOf(transaction.phase) >= CONTROL_PLANE_REBIND_PHASES.indexOf(phase);
}

/**
 * Re-proves the candidate for the transaction's current phase.
 *
 * The strict deny-all candidate proof asserts absent session-admission base
 * state and an empty firewall session set. That claim only holds before the
 * records-rebound phase: the durable records-rebound marker is written before
 * any publication, so a crash at or after it may already have published the
 * snapshot or selected a consumer, and the overlay it wrote is then the
 * expected state, not a violation. Re-running the deny-all proof there refuses
 * a healthy transaction and permanently wedges crash recovery on its own
 * publication. From records-rebound onward the candidate is re-proved as the
 * exact recorded identity instead; snapshot correctness stays owned by the
 * consumer acknowledgement steps.
 */
async function assertCandidateAuthority(
  input: ControlPlaneRebindCoordinatorInput,
  transaction: ControlPlaneRebindTransaction,
): Promise<void> {
  if (!phaseAtLeast(transaction, "records-rebound")) {
    exactCandidate(transaction, await input.services.proveCandidate());
    return;
  }
  const recorded = transaction.candidateControlPlane;
  if (!recorded) throw new Error("control-plane rebind has no proved candidate");
  await input.services.reproveCandidate(recorded);
}

/**
 * The last per-session identity re-proof before the selection flips.
 *
 * Every retained session is proved again, against the candidate's own network,
 * and matched to the proof this transaction journaled when it minted the
 * batch. Both sources spend it in the phase immediately before
 * `control-selected`, so the selection is never published over a session whose
 * container changed while the rebind ran.
 */
function reproveRetainedSessions(
  input: ControlPlaneRebindCoordinatorInput,
  transaction: ControlPlaneRebindTransaction,
): void {
  const durableProofs = new Map(transaction.sessionProofs.map((proof) => [proof.sessionId, proof]));
  for (const record of transaction.replacementRecords) {
    const current = input.services.proveSession(record);
    assertSessionContainerProof(
      current,
      record,
      "active-running",
      transaction.candidateControlPlane?.networkIds.agentInternal as string,
    );
    const original = durableProofs.get(record.sessionId);
    if (!original || !sameProof(original, current)) {
      throw new Error(`session ${record.sessionId} changed after control-plane rebind acknowledgement`);
    }
  }
}

async function refreshRecoveredSessionAuthority(
  input: ControlPlaneRebindCoordinatorInput,
  transaction: ControlPlaneRebindTransaction,
): Promise<ControlPlaneRebindTransaction> {
  const revalidated = revalidateSessions(input, transaction);
  const observedNow = (input.now?.() ?? new Date()).getTime();
  const updatedAt = new Date(Math.max(observedNow, Date.parse(transaction.updatedAt) + 1)).toISOString();
  const { finalizationReceipt: _receipt, ...recoveryWithoutReceipt } = transaction.recovery ?? {};
  const refreshed = Object.freeze({
    ...transaction,
    ...(transaction.recovery ? { recovery: { ...recoveryWithoutReceipt, batchRevision: transaction.recovery.batchRevision + 1, batchInputs: revalidated.inputs } } : {}),
    replacementRecords: revalidated.replacements,
    sessionProofs: revalidated.proofs,
    invalidSessionIds: revalidated.invalidSessionIds,
    updatedAt,
  }) as ControlPlaneRebindTransaction;
  refreshControlPlaneRebindTransaction(input.plan.paths.stateDir, transaction, refreshed);
  // The proxy acknowledges no snapshot and holds no selection pointers, so the
  // revised records are the whole of what the refresh owes; each surviving
  // session's next heartbeat adopts the selection and rewrites its own file.
  if (phaseAtLeast(refreshed, "records-rebound")) applyRecordBatch(input, refreshed);
  return refreshed;
}

async function continueControlPlaneRebind(
  input: ControlPlaneRebindCoordinatorInput,
  initial: ControlPlaneRebindTransaction,
): Promise<Readonly<{
  selection: ControlPlaneEffectiveSelectionV2;
  finalization: ControlPlaneRebindFinalization;
}>> {
  const recoveryStartedAt = input.now?.() ?? new Date();
  const recovering = initial.lockOwnerToken !== input.lifecycleLock.ownerToken;
  let observed = initial;
  const trustReceipt = input.services.captureTrustReceipt?.();
  if (initial.recovery?.trustReceipt !== undefined && trustReceipt !== initial.recovery.trustReceipt) {
    throw new Error("retained CA or OAuth volume changed; restore the exact recorded trust inputs before recovery");
  }
  let candidateLost = false;
  let candidateStopped = false;
  if (initial.candidateControlPlane && input.services.observeRecordedCandidate) {
    const state = await input.services.observeRecordedCandidate(initial.candidateControlPlane);
    candidateLost = state === "absent" || state === "stopped";
    candidateStopped = state === "stopped";
  }
  // Exact candidate proof publishes no Runfree authority. Run it before taking
  // over an interrupted journal so a contradictory Docker identity cannot
  // rewrite the recovery evidence merely by reaching the refusal. A matching
  // recovery still claims the durable fence before it changes any authority.
  let carriedCandidateProof = false;
  if (recovering && initial.phase === "prepared") {
    await input.services.recoverUnrecordedCandidate?.(initial);
  }
  if (recovering && initial.phase !== "prepared" && !candidateLost) {
    await assertCandidateAuthority(input, initial);
    carriedCandidateProof = true;
  }
  observed = migrateRebindTransactionV1(input.plan.paths.stateDir, observed, input.now?.() ?? new Date());
  let transaction = claimTransactionFence(input, observed);
  if (trustReceipt && transaction.recovery && !transaction.recovery.trustReceipt) {
    transaction = checkpointRebindRecovery(input.plan.paths.stateDir, transaction, { ...transaction.recovery, trustReceipt });
  }
  if (input.explicitRetry) {
    const recovery = transaction.recovery;
    if (!recovery) throw new Error("explicit recovery requires a v2 journal");
    const now = recoveryStartedAt;
    transaction = checkpointRebindRecovery(input.plan.paths.stateDir, transaction, {
      ...recovery,
      retired: appendRetiredRebindReceipt(input.plan.paths.stateDir, recovery.retired, JSON.stringify({ allowance: recovery.allowance, phase: transaction.phase })),
      allowance: { number: recovery.allowance.number + 1, startedAt: now.toISOString(),
        deadlineAt: new Date(now.getTime() + REBIND_RECOVERY_BUDGET_MS).toISOString(), lastObservedAt: now.toISOString(), creations: 0, exhausted: false },
    }, true);
  }
  const attemptStarted = performance.now();
  const assertBudget = (creation = false): void => {
    input.lifecycleLock.assertHeld();
    const recovery = transaction.recovery;
    if (!recovery) throw new Error("rebind recovery allowance is missing");
    const now = (input.now?.() ?? new Date()).getTime();
    const allowance = recovery.allowance;
    const exhausted = allowance.exhausted || now < Date.parse(allowance.lastObservedAt)
      || now >= Date.parse(allowance.deadlineAt) || performance.now() - attemptStarted >= REBIND_RECOVERY_BUDGET_MS
      || creation && allowance.creations >= REBIND_RECOVERY_CREATIONS;
    transaction = checkpointRebindRecovery(input.plan.paths.stateDir, transaction, { ...recovery,
      ...(creation && !exhausted ? { creationChargedAttempt: recovery.candidateAttempt } : {}),
      allowance: { ...allowance, lastObservedAt: new Date(Math.max(now, Date.parse(allowance.lastObservedAt))).toISOString(),
        creations: allowance.creations + (creation && !exhausted ? 1 : 0), exhausted } });
    if (exhausted) throw new RebindRecoveryExhaustedError(transaction.transactionId, transaction.phase);
  };
  assertBudget();
  if (candidateLost) {
    assertDurableControlFence(input, transaction);
    if (candidateStopped) {
      if (!input.services.retireStoppedCandidate || !transaction.candidateControlPlane) throw new Error("stopped candidate requires exact retirement before recovery");
      await input.services.retireStoppedCandidate(transaction.candidateControlPlane);
    }
    const durable = readEffectiveControlPlaneV2(input.plan.paths.stateDir);
    if (!durable) throw new Error("candidate recovery has no retained selection");
    transaction = restartRebindCandidateAttempt(input.plan.paths.stateDir, transaction, {
      oldControlPlane: durable.selection, oldMaterialization: durable.manifest,
      records: listSessionContainerRecordsV2(input.plan.paths.stateDir, expectedProject(input)), now: input.now?.() ?? new Date(),
    });
    carriedCandidateProof = false;
  }
  const assertCurrentCandidateAuthority = async (): Promise<void> => {
    if (carriedCandidateProof) {
      carriedCandidateProof = false;
      return;
    }
    await assertCandidateAuthority(input, transaction);
  };
  let finalization: ControlPlaneRebindFinalization | undefined;
  const batchNeedsRefresh = (): boolean => phaseAtLeast(transaction, "sessions-revalidated") && transaction.replacementRecords.some((record) => {
      const current = readSessionContainerRecordV2(input.plan.paths.stateDir, expectedProject(input), record.sessionId);
      const expectedInput = transaction.recovery?.batchInputs?.find((entry) => entry.sessionId === record.sessionId)
        ?? transaction.oldRecords.find((entry) => entry.sessionId === record.sessionId);
      // The batch retains the record's lease by construction and nothing
      // renews it, so lease expiry says nothing about staleness here: only a
      // record that no longer matches the batch or its input needs a refresh.
      return !isDeepStrictEqual(current, record) && !isDeepStrictEqual(current, expectedInput);
    });
  if (phaseAtLeast(transaction, "sessions-revalidated")) {
    const batchChanged = batchNeedsRefresh();
    assertDurableControlFence(input, transaction);
    if (batchChanged) {
      await assertCurrentCandidateAuthority();
      transaction = await refreshRecoveredSessionAuthority(input, transaction);
    } else if (recovering && phaseAtLeast(transaction, "records-rebound")) {
      await assertCurrentCandidateAuthority();
      for (const record of transaction.replacementRecords) {
        assertSessionContainerProof(input.services.proveSession(record), record, "active-running", transaction.candidateControlPlane?.networkIds.agentInternal as string);
      }
      applyRecordBatch(input, transaction);
    }
  }
  if (transaction.phase === "complete") {
    await assertCurrentCandidateAuthority();
  }
  while (transaction.phase !== "complete") {
    assertBudget();
    input.lifecycleLock.assertHeld();
    if (transaction.recovery?.trustReceipt && input.services.captureTrustReceipt?.() !== transaction.recovery.trustReceipt) {
      throw new Error("retained trust inputs changed during recovery; restore them before further effects");
    }
    if (transaction.lockOwnerToken !== input.lifecycleLock.ownerToken) {
      throw new Error("control-plane rebind transaction lost its lifecycle lock fence");
    }
    assertDurableControlFence(input, transaction);
    if (transaction.phase !== "prepared") {
      await assertCurrentCandidateAuthority();
    }
    if (batchNeedsRefresh()) {
      transaction = await refreshRecoveredSessionAuthority(input, transaction);
      finalization = undefined;
    }
    switch (transaction.phase) {
      case "prepared": {
        const recovered = await input.services.recoverUnrecordedCandidate?.(transaction);
        const stoppedProxyId = recovered && "stoppedProxyId" in recovered ? recovered.stoppedProxyId : undefined;
        if (stoppedProxyId || !recovered && transaction.recovery?.creationChargedAttempt === transaction.recovery?.candidateAttempt) {
          if (stoppedProxyId) {
            if (!input.services.retireUnrecordedCandidate) throw new Error("exact stopped creation requires scoped retirement; inspect its marker before retry");
            await input.services.retireUnrecordedCandidate(stoppedProxyId);
          }
          const durable = readEffectiveControlPlaneV2(input.plan.paths.stateDir);
          if (!durable) throw new Error("creation recovery lost its durable predecessor selection");
          transaction = restartRebindCandidateAttempt(input.plan.paths.stateDir, transaction, {
            oldControlPlane: durable.selection, oldMaterialization: durable.manifest,
            records: listSessionContainerRecordsV2(input.plan.paths.stateDir, expectedProject(input)),
            now: input.now?.() ?? new Date(), ...(stoppedProxyId ? { retiredProxyId: stoppedProxyId } : {}),
          });
          break;
        }
        if (!recovered) assertBudget(true);
        const candidate = exactCandidate(transaction, recovered as ControlPlaneEffectiveSelectionV2 | undefined ?? await input.services.startAndProveCandidate(transaction));
        transaction = nextTransaction(input, transaction, "proxy-started-deny-all", {
          candidateControlPlane: candidate,
        });
        break;
      }
      case "proxy-started-deny-all": {
        const revalidated = revalidateSessions(input, transaction);
        transaction = nextTransaction(input, transaction, "sessions-revalidated", {
          ...(transaction.recovery ? { recovery: { ...transaction.recovery, batchInputs: revalidated.inputs } } : {}),
          replacementRecords: revalidated.replacements,
          sessionProofs: revalidated.proofs,
          invalidSessionIds: revalidated.invalidSessionIds,
        });
        break;
      }
      case "sessions-revalidated":
        applyRecordBatch(input, transaction);
        transaction = nextTransaction(input, transaction, "records-rebound");
        break;
      case "records-rebound":
        transaction = nextTransaction(input, transaction, "eligibility-published");
        break;
      /**
       * Invariant 9, and F6 of the design review.
       *
       * There is no snapshot to publish and no consumer pointer to advance, but
       * two things still happen here: the last per-session identity re-proof
       * before the selection flips, and the proxy's own eligibility.
       * Eligibility goes to the candidate container BEFORE `control-selected`,
       * because a proxy holding none serves nothing, and the first heartbeat
       * after the selection must find a proxy that already knows this project's
       * admission bindings.
       */
      case "eligibility-published": {
        reproveRetainedSessions(input, transaction);
        const candidate = transaction.candidateControlPlane as ControlPlaneEffectiveSelectionV2;
        const desired = readRetainedDesiredSessionAgentV2(input.plan.paths.stateDir);
        if (!desired) {
          throw new Error("session eligibility requires the retained current agent template; prepare it with a compatible CLI and retry");
        }
        input.lifecycleLock.assertHeld();
        ensureSessionEligibilityPublished({
          io: input.io,
          proxyId: candidate.proxyContainerId,
          proxyStartedAt: observeProxyStartedAt(input.io, candidate.proxyContainerId, { env: input.plan.execution.dockerClientEnv }),
          stateDir: input.plan.paths.stateDir,
          // The candidate's own selection and manifest: the durable effective
          // selection is still the old one until the line below.
          effective: { selection: candidate, manifest: transaction.candidateMaterialization },
          desired,
          records: transaction.replacementRecords,
          dockerOptions: { env: input.plan.execution.dockerClientEnv },
        });
        input.lifecycleLock.assertHeld();
        selectEffectiveControlPlaneV2(input.plan.paths.stateDir, candidate);
        transaction = nextTransaction(input, transaction, "control-selected");
        break;
      }
      case "control-selected": {
        finalization = await input.services.finalize();
        // Credential resolution can yield the lifecycle lock for host prompts.
        // A new fence must reprove this exact candidate before recording effects.
        if (transaction.lockOwnerToken !== input.lifecycleLock.ownerToken) {
          await assertCandidateAuthority(input, transaction);
          assertDurableControlFence(input, transaction);
          transaction = claimTransactionFence(input, transaction);
        }
        transaction = nextTransaction(input, transaction, "tokens-synced", transaction.recovery ? {
          recovery: { ...transaction.recovery, finalizationReceipt: {
            proxyContainerId: transaction.candidateControlPlane?.proxyContainerId as string,
            candidateAttempt: transaction.recovery.candidateAttempt, batchRevision: transaction.recovery.batchRevision,
            sourceReceiptDigest: sha256Digest(JSON.stringify(finalization.tokenResolutionReceipts)),
          } },
        } : {});
        break;
      }
      case "tokens-synced":
        if (!finalization) {
          finalization = await input.services.finalize();
          await assertCandidateAuthority(input, transaction);
          transaction = claimTransactionFence(input, transaction);
          transaction = checkpointRebindRecovery(input.plan.paths.stateDir, transaction, { ...(transaction.recovery as NonNullable<ControlPlaneRebindTransaction["recovery"]>), finalizationReceipt: {
            proxyContainerId: transaction.candidateControlPlane?.proxyContainerId as string,
            candidateAttempt: transaction.recovery?.candidateAttempt as number, batchRevision: transaction.recovery?.batchRevision as number,
            sourceReceiptDigest: sha256Digest(JSON.stringify(finalization.tokenResolutionReceipts)),
          } });
        }
        transaction = nextTransaction(input, transaction, "complete");
        break;
      default:
        throw new Error(`unsupported control-plane rebind phase: ${transaction.phase}`);
    }
  }
  const selected = transaction.candidateControlPlane;
  if (!selected) throw new Error("completed control-plane rebind has no selected candidate");
  const durableEffective = readEffectiveControlPlaneV2(input.plan.paths.stateDir);
  if (!durableEffective || !isDeepStrictEqual(durableEffective.selection, selected)) {
    throw new Error("completed control-plane rebind candidate is not the durable effective control plane");
  }
  // Finalization releases the lock. Recheck the batch after every handoff,
  // including recovery of a journal already marked complete.
  for (;;) {
    assertBudget();
    if (batchNeedsRefresh()) {
      transaction = await refreshRecoveredSessionAuthority(input, transaction);
      finalization = undefined;
    }
    if (finalization) break;
    finalization = await input.services.finalize();
    await assertCandidateAuthority(input, transaction);
    assertDurableControlFence(input, transaction);
    transaction = claimTransactionFence(input, transaction);
  }
  assertBudget();
  completeControlPlaneRebindTransaction(input.plan.paths.stateDir, transaction);
  return Object.freeze({ selection: selected, finalization });
}

/**
 * Receipt gate for rebind token sync: credential resolution is impossible
 * until the durable rebind journal records candidate selection. The proxy
 * stays credentialless until every retained session was re-proved, both
 * consumers acknowledged the exact snapshot, and the effective selection
 * durably flipped to the candidate — all attested by the journal's
 * `control-selected` phase plus the matching durable selection. A caller that
 * reaches token sync earlier fails here, before any credential resolution.
 */
export function assertControlPlaneRebindReceiptForTokenSync(
  stateDir: string,
  project: SessionContainerProjectIdentity,
): void {
  const receipt = readControlPlaneRebindTransaction(stateDir, project);
  if (!receipt
    || !receipt.candidateControlPlane
    || CONTROL_PLANE_REBIND_PHASES.indexOf(receipt.phase)
      < CONTROL_PLANE_REBIND_PHASES.indexOf("control-selected")) {
    throw new Error("token sync is impossible before the rebind receipt records candidate selection");
  }
  const durable = readEffectiveControlPlaneV2(stateDir);
  if (durable?.selection.proxyContainerId !== receipt.candidateControlPlane.proxyContainerId
    || durable?.selection.controlPlaneMaterializationDigest
      !== receipt.candidateControlPlane.controlPlaneMaterializationDigest) {
    throw new Error("token sync is impossible while the effective selection is not the rebind candidate");
  }
}

export async function runCompatibleControlPlaneRebind(
  input: ControlPlaneRebindCoordinatorInput,
): Promise<Readonly<{
  selection: ControlPlaneEffectiveSelectionV2;
  finalization: ControlPlaneRebindFinalization;
}>> {
  input.lifecycleLock.assertHeld();
  const project = expectedProject(input);
  const existing = readControlPlaneRebindTransaction(input.plan.paths.stateDir, project);
  const oldRecords = existing ? [] : listSessionContainerRecordsV2(input.plan.paths.stateDir, project);
  let transaction = existing ?? createControlPlaneRebindTransaction({
    expectedProject: project,
    lockOwnerToken: input.lifecycleLock.ownerToken,
    oldControlPlane: input.oldControlPlane.selection,
    oldMaterialization: input.oldControlPlane.manifest,
    candidateMaterialization: input.candidateMaterialization,
    oldRecords,
    now: input.now,
    randomBytes: input.randomBytes,
  });
  if (!existing) prepareControlPlaneRebindTransaction(input.plan.paths.stateDir, transaction);
  // A diagnostic retry must not discard what started the failure: the last
  // observation is usually a consequence of the first. The reported evidence
  // stays the last one, because callers select a remedy from `evidence.kind`
  // and an AggregateError would erase it (`startup.ts` classifies on it).
  let firstFailure: unknown;
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await continueControlPlaneRebind({ ...input, explicitRetry: input.explicitRetry && attempt === 0 }, transaction);
    } catch (error) {
      input.lifecycleLock.assertHeld();
      transaction = readControlPlaneRebindTransaction(input.plan.paths.stateDir, project) ?? transaction;
      const reported = firstFailure !== undefined && error instanceof RuntimeObservationError
        ? new RuntimeObservationError(error.evidence, firstFailure)
        : error;
      if (error instanceof RebindRecoveryExhaustedError && transaction.recovery) {
        checkpointRebindRecovery(input.plan.paths.stateDir, transaction, { ...transaction.recovery,
          allowance: { ...transaction.recovery.allowance, exhausted: true } });
        throw reported;
      }
      if (!(error instanceof RuntimeObservationError)
        || !["observation-unavailable", "boundary-violation", "subject-absent"].includes(error.evidence.kind)
        || attempt >= 2) throw reported;
      firstFailure ??= error;
      await new Promise((resolve) => setTimeout(resolve, (attempt + 1) * 1000));
    }
  }
}
