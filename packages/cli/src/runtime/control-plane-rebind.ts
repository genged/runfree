import { isDeepStrictEqual } from "node:util";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  parseControlPlaneMaterializationManifestV2,
  parseEffectiveControlPlaneSelectionV2,
  type ControlPlaneEffectiveSelectionV2,
  type ControlPlaneMaterializationManifestV2,
} from "./component-state-v2.ts";
import {
  parseSessionContainerRecordV2,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import { readBoundedRegularFile, exactKeySet as exactKeys, isRecord } from "../strict-primitives.ts";
import { fsyncDirectory } from "../safe-fs.ts";
import { stableJson } from "../strict-primitives.ts";

import { REBIND_PHASE_EFFECTS, initialRebindRecoveryState, parseRebindRecoveryState, type RebindRecoveryState } from "./control-plane-rebind-recovery.ts";

export const CONTROL_PLANE_REBIND_SCHEMA_VERSION = 2 as const;
export const CONTROL_PLANE_REBIND_PHASES = [
  "prepared",
  "proxy-started-deny-all",
  "sessions-revalidated",
  "records-rebound",
  "eligibility-published",
  "control-selected",
  "tokens-synced",
  "complete",
] as const;

export type ControlPlaneRebindPhase = typeof CONTROL_PLANE_REBIND_PHASES[number];

/** The one phase that may follow `current`, or undefined at the end. */
export function nextControlPlaneRebindPhase(
  current: ControlPlaneRebindPhase,
): ControlPlaneRebindPhase | undefined {
  return CONTROL_PLANE_REBIND_PHASES[CONTROL_PLANE_REBIND_PHASES.indexOf(current) + 1];
}

export type SessionRebindProofSummary = Readonly<{
  sessionId: string;
  projectId: string;
  sessionIncarnation: string;
  sessionPrincipal: string;
  containerId: string;
  imageId: string;
  sessionAgentGenerationDigest: string;
  controlPlaneGenerationDigest: string;
  admissionContractEpoch: number;
  networkId: string;
  sourceIp: string;
  dockerPid: number;
  dockerStartedAt: string;
  networkEndpointId: string;
}>;

export type ControlPlaneRebindTransaction = Readonly<{
  schemaVersion: 1 | typeof CONTROL_PLANE_REBIND_SCHEMA_VERSION;
  recovery?: RebindRecoveryState;
  transactionId: string;
  projectId: string;
  composeProject: string;
  lockOwnerToken: string;
  phase: ControlPlaneRebindPhase;
  oldControlPlane: ControlPlaneEffectiveSelectionV2;
  oldMaterialization: ControlPlaneMaterializationManifestV2;
  candidateMaterialization: ControlPlaneMaterializationManifestV2;
  candidateControlPlane?: ControlPlaneEffectiveSelectionV2;
  oldRecords: readonly SessionContainerRecordV2[];
  replacementRecords: readonly SessionContainerRecordV2[];
  sessionProofs: readonly SessionRebindProofSummary[];
  invalidSessionIds: readonly string[];
  preparedAt: string;
  updatedAt: string;
}>;

const MAX_TRANSACTION_BYTES = 1024 * 1024;
const HEX_64 = /^[a-f0-9]{64}$/u;
const SESSION_ID = /^rf-[0-9]{8}-[a-z0-9]{6,32}$/u;




function exactTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value;
}

function exactDockerStartedAt(value: unknown): value is string {
  return typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value)
    && !value.startsWith("0001-")
    && Number.isFinite(Date.parse(value));
}

function exactProject(value: Readonly<{ projectId: string; composeProject: string }>): boolean {
  return /^[a-f0-9]{12}$/u.test(value.projectId)
    && value.composeProject === `runfree-${value.projectId}`;
}

export function parseControlPlaneRebindTransaction(
  value: unknown,
): ControlPlaneRebindTransaction | undefined {
  if (!isRecord(value)) return undefined;
  const keys = [
    "schemaVersion", "transactionId", "projectId", "composeProject", "lockOwnerToken", "phase",
    "oldControlPlane", "oldMaterialization", "candidateMaterialization", "oldRecords", "replacementRecords", "sessionProofs",
    "invalidSessionIds", "preparedAt", "updatedAt",
    ...(value.schemaVersion === 2 ? ["recovery"] : []),
    ...(Object.hasOwn(value, "candidateControlPlane") ? ["candidateControlPlane"] : []),
  ];
  if (!exactKeys(value, keys)
    || (value.schemaVersion !== 1 && value.schemaVersion !== CONTROL_PLANE_REBIND_SCHEMA_VERSION)
    || (value.schemaVersion === 2 && !parseRebindRecoveryState(value.recovery))
    || typeof value.transactionId !== "string" || !HEX_64.test(value.transactionId)
    || typeof value.projectId !== "string"
    || typeof value.composeProject !== "string"
    || !exactProject({ projectId: value.projectId, composeProject: value.composeProject })
    || typeof value.lockOwnerToken !== "string" || !HEX_64.test(value.lockOwnerToken)
    || typeof value.phase !== "string"
    || !CONTROL_PLANE_REBIND_PHASES.includes(value.phase as ControlPlaneRebindPhase)
    || !exactTimestamp(value.preparedAt)
    || !exactTimestamp(value.updatedAt)
    || !Array.isArray(value.oldRecords)
    || !Array.isArray(value.replacementRecords)
    || !Array.isArray(value.sessionProofs)
    || !Array.isArray(value.invalidSessionIds)
    || value.oldRecords.length > 64
    || value.replacementRecords.length > 64
    || value.sessionProofs.length > 64
    || value.invalidSessionIds.length > 64) return undefined;
  const oldControlPlane = parseEffectiveControlPlaneSelectionV2(value.oldControlPlane);
  const oldMaterialization = parseControlPlaneMaterializationManifestV2(value.oldMaterialization);
  const candidateMaterialization = parseControlPlaneMaterializationManifestV2(value.candidateMaterialization);
  const candidateControlPlane = Object.hasOwn(value, "candidateControlPlane")
    ? parseEffectiveControlPlaneSelectionV2(value.candidateControlPlane)
    : undefined;
  if (!oldControlPlane || !oldMaterialization || !candidateMaterialization
    || (Object.hasOwn(value, "candidateControlPlane") && !candidateControlPlane)) return undefined;
  const expected = { projectId: value.projectId, composeProject: value.composeProject };
  if (![oldControlPlane, oldMaterialization, candidateMaterialization, ...(candidateControlPlane ? [candidateControlPlane] : [])]
    .every((entry) => entry.projectId === expected.projectId && entry.composeProject === expected.composeProject)) {
    return undefined;
  }
  if (oldControlPlane.controlPlaneGenerationDigest !== oldMaterialization.generation.controlPlaneGenerationDigest
    || oldControlPlane.controlPlaneMaterializationDigest !== oldMaterialization.controlPlaneMaterializationDigest
    || oldControlPlane.proxyImageId !== oldMaterialization.proxyImageId
    || oldControlPlane.admissionContractEpoch !== oldMaterialization.generation.admissionContractEpoch) return undefined;
  if (candidateControlPlane
    && (candidateControlPlane.controlPlaneGenerationDigest
      !== candidateMaterialization.generation.controlPlaneGenerationDigest
      || candidateControlPlane.controlPlaneMaterializationDigest
        !== candidateMaterialization.controlPlaneMaterializationDigest
      || candidateControlPlane.proxyImageId !== candidateMaterialization.proxyImageId
      || candidateControlPlane.admissionContractEpoch
        !== candidateMaterialization.generation.admissionContractEpoch
      || (candidateControlPlane.controlPlaneGenerationDigest
          === oldControlPlane.controlPlaneGenerationDigest
        && candidateControlPlane.proxyContainerId === oldControlPlane.proxyContainerId))) return undefined;
  const parseRecords = (records: unknown[]): SessionContainerRecordV2[] | undefined => {
    const parsed = records.map(parseSessionContainerRecordV2);
    if (parsed.some((entry) => entry === undefined)) return undefined;
    const exact = parsed as SessionContainerRecordV2[];
    return exact.every((entry) => entry.projectId === expected.projectId && entry.composeProject === expected.composeProject)
      ? exact
      : undefined;
  };
  const oldRecords = parseRecords(value.oldRecords);
  const replacementRecords = parseRecords(value.replacementRecords);
  const recovery = value.schemaVersion === 2 ? parseRebindRecoveryState(value.recovery) : undefined;
  if (recovery?.batchInputs?.some((record) => record.projectId !== expected.projectId || record.composeProject !== expected.composeProject
    || !oldRecords?.some((old) => old.sessionId === record.sessionId && old.sessionIncarnation === record.sessionIncarnation
      && old.sessionPrincipal === record.sessionPrincipal && old.containerId === record.containerId))) return undefined;
  const sessionProofs = value.sessionProofs as unknown[];
  if (!oldRecords || !replacementRecords
    || !value.invalidSessionIds.every((entry) => typeof entry === "string" && SESSION_ID.test(entry))
    || new Set(value.invalidSessionIds).size !== value.invalidSessionIds.length
    || new Set(oldRecords.map((entry) => entry.sessionId)).size !== oldRecords.length
    || new Set(replacementRecords.map((entry) => entry.sessionId)).size !== replacementRecords.length) {
    return undefined;
  }
  if (oldRecords.length > 0
    && (candidateMaterialization.generation.admissionContractEpoch
      !== oldMaterialization.generation.admissionContractEpoch
      || candidateMaterialization.generation.controlPlaneTopologyDigest
        !== oldMaterialization.generation.controlPlaneTopologyDigest)) {
    return undefined;
  }
  if (Date.parse(value.updatedAt) < Date.parse(value.preparedAt)) return undefined;
  if (oldRecords.some((record) => (
    (record.controlPlaneGenerationDigest !== oldControlPlane.controlPlaneGenerationDigest
      && !(value.schemaVersion === 2 && record.controlPlaneGenerationDigest === candidateMaterialization.generation.controlPlaneGenerationDigest))
    || record.admissionContractEpoch !== oldControlPlane.admissionContractEpoch
  ))) return undefined;
  const phaseIndex = CONTROL_PLANE_REBIND_PHASES.indexOf(value.phase as ControlPlaneRebindPhase);
  if (recovery && (recovery.outstandingEffect !== REBIND_PHASE_EFFECTS[value.phase as ControlPlaneRebindPhase]
    || recovery.finalizationReceipt && (phaseIndex < CONTROL_PLANE_REBIND_PHASES.indexOf("tokens-synced")
      || recovery.finalizationReceipt.proxyContainerId !== candidateControlPlane?.proxyContainerId))) return undefined;
  if (phaseIndex === 0 && (candidateControlPlane || replacementRecords.length > 0
    || sessionProofs.length > 0 || value.invalidSessionIds.length > 0)) {
    return undefined;
  }
  if (phaseIndex >= CONTROL_PLANE_REBIND_PHASES.indexOf("proxy-started-deny-all") && !candidateControlPlane) {
    return undefined;
  }
  if (phaseIndex >= CONTROL_PLANE_REBIND_PHASES.indexOf("sessions-revalidated")) {
    const oldById = new Map(oldRecords.map((record) => [record.sessionId, record]));
    const retainedIds = new Set(replacementRecords.map((record) => record.sessionId));
    const invalidIds = new Set(value.invalidSessionIds as string[]);
    if (retainedIds.size + invalidIds.size !== oldRecords.length
      || [...retainedIds].some((id) => invalidIds.has(id) || !oldById.has(id))
      || [...invalidIds].some((id) => !oldById.has(id))) return undefined;
    if (sessionProofs.length !== replacementRecords.length) return undefined;
    const proofById = new Map<string, SessionRebindProofSummary>();
    for (const candidate of sessionProofs) {
      if (!isRecord(candidate)
        || !exactKeys(candidate, [
          "sessionId", "projectId", "sessionIncarnation", "sessionPrincipal", "containerId", "imageId",
          "sessionAgentGenerationDigest", "controlPlaneGenerationDigest", "admissionContractEpoch", "networkId",
          "sourceIp", "dockerPid", "dockerStartedAt", "networkEndpointId",
        ])
        || typeof candidate.sessionId !== "string" || !SESSION_ID.test(candidate.sessionId)
        || candidate.projectId !== expected.projectId
        || typeof candidate.sessionIncarnation !== "string" || !HEX_64.test(candidate.sessionIncarnation)
        || typeof candidate.sessionPrincipal !== "string" || !HEX_64.test(candidate.sessionPrincipal)
        || typeof candidate.containerId !== "string" || !HEX_64.test(candidate.containerId)
        || typeof candidate.imageId !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(candidate.imageId)
        || typeof candidate.sessionAgentGenerationDigest !== "string"
        || !/^sha256:[a-f0-9]{64}$/u.test(candidate.sessionAgentGenerationDigest)
        || typeof candidate.controlPlaneGenerationDigest !== "string"
        || !/^sha256:[a-f0-9]{64}$/u.test(candidate.controlPlaneGenerationDigest)
        || typeof candidate.admissionContractEpoch !== "number"
        || !Number.isSafeInteger(candidate.admissionContractEpoch) || candidate.admissionContractEpoch < 1
        || typeof candidate.networkId !== "string" || !HEX_64.test(candidate.networkId)
        || typeof candidate.sourceIp !== "string" || candidate.sourceIp.length > 15
        || typeof candidate.dockerPid !== "number"
        || !Number.isSafeInteger(candidate.dockerPid) || candidate.dockerPid < 1
        || !exactDockerStartedAt(candidate.dockerStartedAt)
        || typeof candidate.networkEndpointId !== "string" || !HEX_64.test(candidate.networkEndpointId)
        || proofById.has(candidate.sessionId)) return undefined;
      proofById.set(candidate.sessionId, candidate as SessionRebindProofSummary);
    }
    for (const replacement of replacementRecords) {
      const old = oldById.get(replacement.sessionId);
      const proof = proofById.get(replacement.sessionId);
      if (!old
        || !proof
        || replacement.state !== "attached"
        || old.state !== "attached"
        || replacement.controlPlaneGenerationDigest
          !== candidateMaterialization.generation.controlPlaneGenerationDigest
        || replacement.admissionContractEpoch
          !== candidateMaterialization.generation.admissionContractEpoch
        || replacement.sessionIncarnation !== old.sessionIncarnation
        || replacement.sessionPrincipal !== old.sessionPrincipal
        || replacement.containerId !== old.containerId
        || replacement.sourceIp !== old.sourceIp
        || replacement.sessionAgentMaterializationDigest !== old.sessionAgentMaterializationDigest
        || replacement.selectedAgentImageId !== old.selectedAgentImageId
        || replacement.admittedAt !== old.admittedAt
        // The record's lease is not the session's authority and no heartbeat
        // renews it, so the batch moves the digest and nothing else.
        || replacement.leaseGeneration !== old.leaseGeneration
        || replacement.leaseExpiresAt !== old.leaseExpiresAt
        || proof.sessionIncarnation !== replacement.sessionIncarnation
        || proof.sessionPrincipal !== replacement.sessionPrincipal
        || proof.containerId !== replacement.containerId
        || proof.imageId !== replacement.selectedAgentImageId
        || proof.sessionAgentGenerationDigest !== replacement.sessionAgentGenerationDigest
        || proof.controlPlaneGenerationDigest !== replacement.controlPlaneGenerationDigest
        || proof.admissionContractEpoch !== replacement.admissionContractEpoch
        || proof.networkId !== candidateControlPlane?.networkIds.agentInternal
        || proof.sourceIp !== replacement.sourceIp) return undefined;
    }
  } else if (sessionProofs.length > 0) {
    return undefined;
  }
  return Object.freeze({
    schemaVersion: value.schemaVersion as 1 | 2,
    ...(value.schemaVersion === 2 ? { recovery: parseRebindRecoveryState(value.recovery) as RebindRecoveryState } : {}),
    transactionId: value.transactionId,
    ...expected,
    lockOwnerToken: value.lockOwnerToken,
    phase: value.phase as ControlPlaneRebindPhase,
    oldControlPlane,
    oldMaterialization,
    candidateMaterialization,
    ...(candidateControlPlane ? { candidateControlPlane } : {}),
    oldRecords: Object.freeze(oldRecords),
    replacementRecords: Object.freeze(replacementRecords),
    sessionProofs: Object.freeze(sessionProofs as SessionRebindProofSummary[]),
    invalidSessionIds: Object.freeze(value.invalidSessionIds as string[]),
    preparedAt: value.preparedAt,
    updatedAt: value.updatedAt,
  });
}

export function serializeControlPlaneRebindTransaction(transaction: ControlPlaneRebindTransaction): string {
  const parsed = parseControlPlaneRebindTransaction(transaction);
  if (!parsed) throw new Error("control-plane rebind transaction is invalid");
  return `${stableJson(parsed)}\n`;
}

/** Archive provenance before replacing its inline representation. Never discard prior effects. */
export function appendRetiredRebindReceipt(stateDir: string, previous: readonly string[], source: string): readonly string[] {
  const archive = (contents: string): string => {
    if (Buffer.byteLength(contents) > MAX_TRANSACTION_BYTES) throw new Error("rebind recovery receipt exceeds its archive bound");
    const digest = `sha256:${crypto.createHash("sha256").update(contents).digest("hex")}`;
    ensureRoot(stateDir);
    const file = path.join(path.dirname(controlPlaneRebindTransactionPath(stateDir)), `rebind-retired.${digest.slice(7)}.json`);
    const existing = readSafeSource(stateDir, file);
    if (existing !== undefined) {
      if (existing !== contents) throw new Error("retired recovery receipt contradicts its content digest");
      return digest;
    }
    const temporary = `${file}.${crypto.randomBytes(16).toString("hex")}.tmp`;
    const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    try {
      try { fs.writeFileSync(fd, contents); fs.fsyncSync(fd); }
      finally { fs.closeSync(fd); }
      if (readSafeSource(stateDir, file) !== undefined) throw new Error("retired recovery receipt changed before commit");
      fs.renameSync(temporary, file);
      fsyncDirectory(path.dirname(file));
    } finally { fs.rmSync(temporary, { force: true }); }
    return digest;
  };
  const retained = previous.length >= 31 ? [archive(stableJson({ retired: previous }))] : [...previous];
  return Object.freeze([...retained, archive(source)]);
}

function retainsRebindHistory(stateDir: string, previous: readonly string[], next: readonly string[]): boolean {
  if (previous.length <= next.length && previous.every((value, index) => value === next[index])) return true;
  if (next.length !== 2 || !/^sha256:[a-f0-9]{64}$/u.test(next[0])) return false;
  const source = readSafeSource(stateDir, path.join(path.dirname(controlPlaneRebindTransactionPath(stateDir)), `rebind-retired.${next[0].slice(7)}.json`));
  return source === stableJson({ retired: previous }) && `sha256:${crypto.createHash("sha256").update(source).digest("hex")}` === next[0];
}

/** Metadata checkpoint, with no change to record, selection, or phase authority. */
export function checkpointRebindRecovery(stateDir: string, current: ControlPlaneRebindTransaction, recovery: RebindRecoveryState, grantNewAllowance = false): ControlPlaneRebindTransaction {
  if (current.schemaVersion !== 2 || !current.recovery || !parseRebindRecoveryState(recovery)) {
    throw new Error("rebind recovery checkpoint requires a valid v2 journal");
  }
  const previous = current.recovery;
  const oldAllowance = previous.allowance;
  const nextAllowance = recovery.allowance;
  const sameAllowance = nextAllowance.number === oldAllowance.number;
  if (recovery.candidateAttempt !== previous.candidateAttempt || recovery.batchRevision !== previous.batchRevision
    || !retainsRebindHistory(stateDir, previous.retired, recovery.retired)
    || recovery.originalV1 !== previous.originalV1
    || previous.trustReceipt !== undefined && recovery.trustReceipt !== previous.trustReceipt
    || !isDeepStrictEqual(recovery.batchInputs, previous.batchInputs)
    || recovery.outstandingEffect !== previous.outstandingEffect
    || recovery.creationChargedAttempt !== previous.creationChargedAttempt
      && (recovery.creationChargedAttempt !== recovery.candidateAttempt || nextAllowance.creations !== oldAllowance.creations + 1)
    || (sameAllowance
      ? nextAllowance.creations < oldAllowance.creations || nextAllowance.startedAt !== oldAllowance.startedAt
        || nextAllowance.deadlineAt !== oldAllowance.deadlineAt || Date.parse(nextAllowance.lastObservedAt) < Date.parse(oldAllowance.lastObservedAt)
        || oldAllowance.exhausted && !nextAllowance.exhausted
      : !grantNewAllowance || nextAllowance.number !== oldAllowance.number + 1 || nextAllowance.creations !== 0
        || nextAllowance.exhausted || isDeepStrictEqual(recovery.retired, previous.retired))) {
    throw new Error("rebind recovery accounting cannot discard evidence or reset without explicit retry");
  }
  const next = Object.freeze({ ...current, recovery });
  replaceSource(stateDir, serializeControlPlaneRebindTransaction(current), serializeControlPlaneRebindTransaction(next));
  return next;
}

/** Caller first proves the exact candidate or its authoritative absence under the lock. */
export function migrateRebindTransactionV1(stateDir: string, current: ControlPlaneRebindTransaction, now: Date): ControlPlaneRebindTransaction {
  if (current.schemaVersion === 2) return current;
  const originalV1 = serializeControlPlaneRebindTransaction(current);
  const initial = initialRebindRecoveryState(now);
  const next: ControlPlaneRebindTransaction = Object.freeze({ ...current, schemaVersion: 2,
    recovery: { ...initial, originalV1, outstandingEffect: REBIND_PHASE_EFFECTS[current.phase], allowance: { ...initial.allowance, creations: current.candidateControlPlane ? 1 : 0 } } });
  replaceSource(stateDir, originalV1, serializeControlPlaneRebindTransaction(next));
  return next;
}

/** Retire attributable effects before creating another candidate. Never roll records back. */
export function restartRebindCandidateAttempt(stateDir: string, current: ControlPlaneRebindTransaction, input: {
  oldControlPlane: ControlPlaneEffectiveSelectionV2;
  oldMaterialization: ControlPlaneMaterializationManifestV2;
  records: readonly SessionContainerRecordV2[];
  now: Date;
  retiredProxyId?: string;
}): ControlPlaneRebindTransaction {
  const recovery = current.recovery;
  if (current.schemaVersion !== 2 || !recovery) throw new Error("candidate recovery requires a v2 journal");
  const { recovery: _recovery, ...receipt } = current;
  const { finalizationReceipt, batchInputs: _batchInputs, ...recoveryWithoutReceipt } = recovery;
  const { candidateControlPlane: _candidate, ...base } = current;
  const next: ControlPlaneRebindTransaction = Object.freeze({ ...base,
    phase: "prepared", oldControlPlane: input.oldControlPlane, oldMaterialization: input.oldMaterialization,
    oldRecords: input.records, replacementRecords: [], sessionProofs: [], invalidSessionIds: [], updatedAt: input.now.toISOString(),
    recovery: { ...recoveryWithoutReceipt, candidateAttempt: recovery.candidateAttempt + 1, batchRevision: recovery.batchRevision + 1,
      outstandingEffect: "create" as const, retired: appendRetiredRebindReceipt(stateDir, recovery.retired, stableJson({ ...receipt,
        batchRevision: recovery.batchRevision, ...(input.retiredProxyId ? { retiredProxyId: input.retiredProxyId } : {}), ...(finalizationReceipt ? { finalizationReceipt } : {}) })) },
  });
  replaceSource(stateDir, serializeControlPlaneRebindTransaction(current), serializeControlPlaneRebindTransaction(next));
  return next;
}

export function controlPlaneRebindTransactionPath(stateDir: string): string {
  return path.join(stateDir, "runtime", "v2", "control-plane-rebind.json");
}

function safeDirectory(directory: string): void {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`control-plane rebind state path is unsafe: ${directory}`);
  }
}

function ensureRoot(stateDir: string): void {
  const root = path.dirname(controlPlaneRebindTransactionPath(stateDir));
  if (!fs.existsSync(stateDir)) fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  safeDirectory(stateDir);
  fsyncDirectory(path.dirname(stateDir));
  let current = stateDir;
  for (const segment of path.relative(stateDir, root).split(path.sep)) {
    const parent = current;
    current = path.join(current, segment);
    if (!fs.existsSync(current)) fs.mkdirSync(current, { mode: 0o700 });
    safeDirectory(current);
    fsyncDirectory(parent);
  }
}

function existingSafeParentTree(stateDir: string, filePath: string): boolean {
  const resolvedStateDir = path.resolve(stateDir);
  const relative = path.relative(resolvedStateDir, path.resolve(filePath));
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("control-plane rebind transaction path escapes the state directory");
  }
  let current = resolvedStateDir;
  for (const segment of ["", ...relative.split(path.sep).slice(0, -1)]) {
    if (segment !== "") current = path.join(current, segment);
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(current);
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") return false;
      throw error;
    }
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error(`control-plane rebind state path is unsafe: ${current}`);
    }
  }
  return true;
}

function readSafeSource(stateDir: string, filePath: string): string | undefined {
  if (!existingSafeParentTree(stateDir, filePath)) return undefined;
  return readBoundedRegularFile(filePath, {
    maxBytes: MAX_TRANSACTION_BYTES,
    sizeRecheck: "exact",
    notFileMessage: () => "control-plane rebind transaction is not a bounded regular single-link file",
    changedMessage: () => "control-plane rebind transaction changed during read",
  })?.source;
}


function replaceSource(stateDir: string, expected: string | undefined, source: string): void {
  if (Buffer.byteLength(source) > MAX_TRANSACTION_BYTES) {
    throw new Error("control-plane rebind transaction exceeds its size limit");
  }
  ensureRoot(stateDir);
  const filePath = controlPlaneRebindTransactionPath(stateDir);
  if (readSafeSource(stateDir, filePath) !== expected) {
    throw new Error("control-plane rebind transaction changed before replacement");
  }
  const temporary = path.join(path.dirname(filePath), `.rebind.${process.pid}.${crypto.randomBytes(16).toString("hex")}.tmp`);
  const descriptor = fs.openSync(
    temporary,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  try {
    fs.writeFileSync(descriptor, source);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  try {
    if (readSafeSource(stateDir, filePath) !== expected) {
      throw new Error("control-plane rebind transaction changed before commit");
    }
    fs.renameSync(temporary, filePath);
    fsyncDirectory(path.dirname(filePath));
  } finally {
    try { fs.unlinkSync(temporary); } catch { /* rename consumed it */ }
  }
}

export function createControlPlaneRebindTransaction(input: Readonly<{
  expectedProject: SessionContainerProjectIdentity;
  lockOwnerToken: string;
  oldControlPlane: ControlPlaneEffectiveSelectionV2;
  oldMaterialization: ControlPlaneMaterializationManifestV2;
  candidateMaterialization: ControlPlaneMaterializationManifestV2;
  oldRecords: readonly SessionContainerRecordV2[];
  now?: () => Date;
  randomBytes?: (size: number) => Uint8Array;
}>): ControlPlaneRebindTransaction {
  const preparedAt = (input.now?.() ?? new Date()).toISOString();
  const transactionId = Buffer.from((input.randomBytes ?? crypto.randomBytes)(32)).toString("hex");
  const parsed = parseControlPlaneRebindTransaction({
    schemaVersion: CONTROL_PLANE_REBIND_SCHEMA_VERSION,
    recovery: initialRebindRecoveryState(new Date(preparedAt)),
    transactionId,
    ...input.expectedProject,
    lockOwnerToken: input.lockOwnerToken,
    phase: "prepared",
    oldControlPlane: input.oldControlPlane,
    oldMaterialization: input.oldMaterialization,
    candidateMaterialization: input.candidateMaterialization,
    oldRecords: input.oldRecords,
    replacementRecords: [],
    sessionProofs: [],
    invalidSessionIds: [],
    preparedAt,
    updatedAt: preparedAt,
  });
  if (!parsed) throw new Error("control-plane rebind transaction inputs are invalid");
  return parsed;
}

/**
 * Rebinds one attached record to the candidate control plane: the digest moves
 * and nothing else.
 *
 * The record's lease is not the session's authority — the session file the
 * proxy reads is, and each heartbeat re-mints that — and nothing renews the
 * record's lease at all. A rebind that minted one would be granting liveness no
 * later proof ever backs.
 */
export function createReboundSessionContainerRecordV2(input: Readonly<{
  current: SessionContainerRecordV2;
  candidateControlPlane: ControlPlaneEffectiveSelectionV2;
}>): SessionContainerRecordV2 {
  const current = parseSessionContainerRecordV2(input.current);
  const candidate = parseEffectiveControlPlaneSelectionV2(input.candidateControlPlane);
  if (!current || current.state !== "attached" || !current.containerId
    || !current.admittedAt || !current.leaseGeneration || !current.leaseExpiresAt
    || !candidate
    || current.projectId !== candidate.projectId
    || current.composeProject !== candidate.composeProject
    || current.admissionContractEpoch !== candidate.admissionContractEpoch
    ) {
    throw new Error("session record cannot be rebound to the candidate control plane");
  }
  const replacement = parseSessionContainerRecordV2({
    ...current,
    controlPlaneGenerationDigest: candidate.controlPlaneGenerationDigest,
  });
  if (!replacement) throw new Error("rebound session record is invalid");
  return replacement;
}

export function readControlPlaneRebindTransaction(
  stateDir: string,
  expectedProject: SessionContainerProjectIdentity,
): ControlPlaneRebindTransaction | undefined {
  const source = readSafeSource(stateDir, controlPlaneRebindTransactionPath(stateDir));
  if (source === undefined) return undefined;
  let value: unknown;
  try { value = JSON.parse(source) as unknown; } catch { throw new Error("control-plane rebind transaction is malformed"); }
  const transaction = parseControlPlaneRebindTransaction(value);
  if (!transaction) throw new Error("control-plane rebind transaction is invalid");
  if (transaction.projectId !== expectedProject.projectId
    || transaction.composeProject !== expectedProject.composeProject) {
    throw new Error("control-plane rebind transaction belongs to another project");
  }
  return transaction;
}

export function prepareControlPlaneRebindTransaction(stateDir: string, transaction: ControlPlaneRebindTransaction): void {
  replaceSource(stateDir, undefined, serializeControlPlaneRebindTransaction(transaction));
}

export function advanceControlPlaneRebindTransaction(
  stateDir: string,
  current: ControlPlaneRebindTransaction,
  next: ControlPlaneRebindTransaction,
): void {
  // One step along the sequence.
  if (next.phase !== nextControlPlaneRebindPhase(current.phase)
    || current.transactionId !== next.transactionId
    || current.projectId !== next.projectId
    || current.composeProject !== next.composeProject
    || current.lockOwnerToken !== next.lockOwnerToken
    || current.preparedAt !== next.preparedAt) {
    throw new Error("control-plane rebind transaction phase transition is invalid");
  }
  replaceSource(
    stateDir,
    serializeControlPlaneRebindTransaction(current),
    serializeControlPlaneRebindTransaction(next),
  );
}

export function takeOverControlPlaneRebindTransaction(
  stateDir: string,
  current: ControlPlaneRebindTransaction,
  next: ControlPlaneRebindTransaction,
): void {
  if (current.transactionId !== next.transactionId
    || current.projectId !== next.projectId
    || current.composeProject !== next.composeProject
    || current.phase !== next.phase
    || current.preparedAt !== next.preparedAt
    || current.lockOwnerToken === next.lockOwnerToken
    || !HEX_64.test(next.lockOwnerToken)) {
    throw new Error("control-plane rebind lock-fence takeover is invalid");
  }
  const expectedNext = parseControlPlaneRebindTransaction({
    ...current,
    lockOwnerToken: next.lockOwnerToken,
    updatedAt: next.updatedAt,
  });
  if (!expectedNext || serializeControlPlaneRebindTransaction(expectedNext)
    !== serializeControlPlaneRebindTransaction(next)) {
    throw new Error("control-plane rebind lock-fence takeover changed transaction authority");
  }
  replaceSource(
    stateDir,
    serializeControlPlaneRebindTransaction(current),
    serializeControlPlaneRebindTransaction(next),
  );
}

/**
 * Reissues the retained-session authority in an incomplete transaction after
 * lock-fence takeover. The phase and every control-plane input stay fixed;
 * only the exact replacement batch and its proof partition can change.
 */
export function refreshControlPlaneRebindTransaction(
  stateDir: string,
  current: ControlPlaneRebindTransaction,
  next: ControlPlaneRebindTransaction,
): void {
  if (CONTROL_PLANE_REBIND_PHASES.indexOf(current.phase)
      < CONTROL_PLANE_REBIND_PHASES.indexOf("sessions-revalidated")
    || current.transactionId !== next.transactionId
    || current.projectId !== next.projectId
    || current.composeProject !== next.composeProject
    || current.lockOwnerToken !== next.lockOwnerToken
    || current.phase !== next.phase
    || current.preparedAt !== next.preparedAt
    || Date.parse(next.updatedAt) <= Date.parse(current.updatedAt)) {
    throw new Error("control-plane rebind authority refresh is invalid");
  }
  if (current.recovery && (!next.recovery
    || next.recovery.batchRevision !== current.recovery.batchRevision + 1
    || !isDeepStrictEqual(next.recovery.allowance, current.recovery.allowance)
    || next.recovery.candidateAttempt !== current.recovery.candidateAttempt
    || next.recovery.originalV1 !== current.recovery.originalV1
    || !isDeepStrictEqual(next.recovery.retired, current.recovery.retired)
    || next.recovery.finalizationReceipt !== undefined)) throw new Error("invalid rebind batch revision");
  const expectedNext = parseControlPlaneRebindTransaction({
    ...current,
    ...(next.recovery ? { recovery: next.recovery } : {}),
    replacementRecords: next.replacementRecords,
    sessionProofs: next.sessionProofs,
    invalidSessionIds: next.invalidSessionIds,
    updatedAt: next.updatedAt,
  });
  if (!expectedNext || serializeControlPlaneRebindTransaction(expectedNext)
    !== serializeControlPlaneRebindTransaction(next)) {
    throw new Error("control-plane rebind authority refresh changed transaction inputs");
  }
  replaceSource(
    stateDir,
    serializeControlPlaneRebindTransaction(current),
    serializeControlPlaneRebindTransaction(next),
  );
}

export function completeControlPlaneRebindTransaction(
  stateDir: string,
  transaction: ControlPlaneRebindTransaction,
): void {
  if (transaction.phase !== "complete") throw new Error("control-plane rebind transaction is not complete");
  discardControlPlaneRebindTransaction(stateDir, transaction);
}

/**
 * Removes an exact validated transaction at any phase after an operator-
 * approved teardown has removed every authority and container it describes.
 */
export function discardControlPlaneRebindTransaction(
  stateDir: string,
  transaction: ControlPlaneRebindTransaction,
): void {
  const filePath = controlPlaneRebindTransactionPath(stateDir);
  const source = readSafeSource(stateDir, filePath);
  if (source === undefined) {
    // An earlier attempt can unlink the exact journal and then fail while
    // syncing its parent. Retry that durability barrier while the safe parent
    // tree still exists; an absent tree already contains no journal authority.
    if (existingSafeParentTree(stateDir, filePath)) fsyncDirectory(path.dirname(filePath));
    return;
  }
  if (source !== serializeControlPlaneRebindTransaction(transaction)) {
    throw new Error("control-plane rebind transaction changed before cleanup");
  }
  fs.unlinkSync(filePath);
  fsyncDirectory(path.dirname(filePath));
}
