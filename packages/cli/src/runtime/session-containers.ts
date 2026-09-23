import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  isExactSessionSourceIpv4,
  SESSION_ADMISSION_LEASE_MAX_DURATION_MS,
  SESSION_DISPLAY_COMMAND_MAX_CHARACTERS,
} from "@runfree/runtime-contracts/session-registry";

import { parseStrictJson } from "../control/strict-json.ts";
import {
  parseEffectiveControlPlaneSelectionV2,
  parseSessionAgentMaterializationManifestV2,
  type ControlPlaneEffectiveSelectionV2,
  type SessionAgentMaterializationManifestV2,
} from "./component-state-v2.ts";
import {
  assertSessionLaunchTarget,
  createSessionLaunchTarget,
  type SessionLaunchTarget,
} from "./session-launch.ts";
import { readBoundedRegularFile, isRecord } from "../strict-primitives.ts";
import { fsyncDirectory } from "../safe-fs.ts";
import { stableJson } from "../strict-primitives.ts";

export const SESSION_CONTAINER_RECORD_SCHEMA_VERSION = 4 as const;
export const SESSION_CONTAINER_RECORD_SCAN_LIMIT = 256;
export const SESSION_CONTAINER_LEASE_MIN_DURATION_MS = 1_000;
export const SESSION_CONTAINER_LEASE_MAX_DURATION_MS = SESSION_ADMISSION_LEASE_MAX_DURATION_MS;

const MAX_RECORD_BYTES = 64 * 1024;
const PROJECT_ID_PATTERN = /^[a-f0-9]{12}$/;
// Shared with session-host-status.ts, whose stamps name the same session ids.
export const SESSION_ID_PATTERN = /^rf-[0-9]{8}-[a-z0-9]{6,32}$/;
const OPAQUE_SESSION_IDENTITY_PATTERN = /^[a-f0-9]{64}$/;
const DOCKER_CONTAINER_ID_PATTERN = /^[a-f0-9]{64}$/;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const LEASE_GENERATION_PATTERN = /^[a-f0-9]{32,64}$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u;

export const SESSION_CONTAINER_STATES = [
  "allocated",
  "provisioning-running",
  "attached",
  "revoking",
] as const;

export type SessionContainerStateV2 = typeof SESSION_CONTAINER_STATES[number];

export type SessionContainerRecordV2 = {
  schemaVersion: typeof SESSION_CONTAINER_RECORD_SCHEMA_VERSION;
  projectId: string;
  composeProject: string;
  sessionId: string;
  sessionIncarnation: string;
  sessionPrincipal: string;
  displayName: string;
  command: string;
  launchPath: string;
  launchArgs: readonly string[];
  interactive: boolean;
  tty: boolean;
  state: SessionContainerStateV2;
  containerName: string;
  containerId?: string;
  sourceIp: string;
  selectedAgentImageRef: string;
  selectedAgentImageId: string;
  sessionAgentMaterializationDigest: string;
  selectedAgentImageInputDigest: string;
  sessionTemplateDigest: string;
  sessionAgentGenerationDigest: string;
  controlPlaneGenerationDigest: string;
  admissionContractEpoch: number;
  hostPid: number;
  hostBootId?: string;
  hostProcessStart?: string;
  createdAt: string;
  admittedAt?: string;
  leaseGeneration?: string;
  leaseExpiresAt?: string;
};

export type SessionContainerLeaseV2 = Readonly<Required<Pick<
  SessionContainerRecordV2,
  "admittedAt" | "leaseGeneration" | "leaseExpiresAt"
>>>;

export type MintSessionContainerLeaseV2Options = Readonly<{
  durationMs: number;
  nowEpochMs?: () => number;
  randomBytes?: (size: number) => Uint8Array;
}>;

export type SessionContainerProjectIdentity = {
  projectId: string;
  composeProject: string;
};

export type AllocatedSessionContainerInputV2 = Pick<
  SessionContainerRecordV2,
  | "sessionId"
  | "displayName"
  | "command"
  | "sourceIp"
  | "hostPid"
  | "hostBootId"
  | "hostProcessStart"
  | "createdAt"
> & {
  materialization: SessionAgentMaterializationManifestV2;
  effectiveControlPlane: ControlPlaneEffectiveSelectionV2;
  launch: SessionLaunchTarget;
  sessionIncarnation?: string;
  sessionPrincipal?: string;
};

export const SESSION_CONTAINER_LABELS = {
  managed: "io.runfree.managed",
  role: "io.runfree.container-role",
  // Descriptive taxonomy labels (label-schema 1). Ownership is derived from
  // the lifecycle registry, never dispatched on the owner label.
  lifecycleOwner: "io.runfree.lifecycle-owner",
  labelSchema: "io.runfree.label-schema",
  projectId: "io.runfree.project-id",
  composeProject: "io.runfree.compose-project",
  sessionId: "io.runfree.session-id",
  sessionIncarnation: "io.runfree.session-incarnation",
  selectedAgentImageInputDigest: "io.runfree.selected-agent-image-input-digest",
  selectedAgentImageId: "io.runfree.selected-agent-image-id",
  sessionAgentMaterializationDigest: "io.runfree.session-agent-materialization-digest",
  sessionAgentGenerationDigest: "io.runfree.session-agent-generation-digest",
  sessionTemplateDigest: "io.runfree.session-template-digest",
  admissionContractEpoch: "io.runfree.admission-contract-epoch",
  version: "io.runfree.version",
} as const;

export type SessionContainerLabels = Record<
  typeof SESSION_CONTAINER_LABELS[keyof typeof SESSION_CONTAINER_LABELS],
  string
>;

const REQUIRED_RECORD_KEYS = [
  "schemaVersion",
  "projectId",
  "composeProject",
  "sessionId",
  "sessionIncarnation",
  "sessionPrincipal",
  "displayName",
  "command",
  "launchPath",
  "launchArgs",
  "interactive",
  "tty",
  "state",
  "containerName",
  "sourceIp",
  "selectedAgentImageRef",
  "selectedAgentImageId",
  "sessionAgentMaterializationDigest",
  "selectedAgentImageInputDigest",
  "sessionTemplateDigest",
  "sessionAgentGenerationDigest",
  "controlPlaneGenerationDigest",
  "admissionContractEpoch",
  "hostPid",
  "createdAt",
] as const;

const OPTIONAL_RECORD_KEYS = [
  "containerId",
  "hostBootId",
  "hostProcessStart",
  "admittedAt",
  "leaseGeneration",
  "leaseExpiresAt",
] as const;

const ALLOWED_TRANSITIONS: Record<SessionContainerStateV2, readonly SessionContainerStateV2[]> = {
  allocated: ["provisioning-running", "revoking"],
  "provisioning-running": ["attached", "revoking"],
  attached: ["attached", "revoking"],
  revoking: [],
};

const IMMUTABLE_RECORD_KEYS = [
  "schemaVersion",
  "projectId",
  "composeProject",
  "sessionId",
  "sessionIncarnation",
  "sessionPrincipal",
  "command",
  "launchPath",
  "interactive",
  "tty",
  "containerName",
  "sourceIp",
  "selectedAgentImageRef",
  "selectedAgentImageId",
  "sessionAgentMaterializationDigest",
  "selectedAgentImageInputDigest",
  "sessionTemplateDigest",
  "sessionAgentGenerationDigest",
  "controlPlaneGenerationDigest",
  "admissionContractEpoch",
  "hostPid",
  "hostBootId",
  "hostProcessStart",
  "createdAt",
] as const;

type StrictJson = boolean | null | number | string | StrictJson[] | { [key: string]: StrictJson };


function hasExactRecordKeys(value: Record<string, unknown>): boolean {
  const keys = new Set([...REQUIRED_RECORD_KEYS, ...OPTIONAL_RECORD_KEYS]);
  return REQUIRED_RECORD_KEYS.every((key) => Object.hasOwn(value, key))
    && Object.keys(value).every((key) => keys.has(key as never));
}

function boundedText(value: unknown, maximum: number): value is string {
  return typeof value === "string"
    && value === value.trim()
    && value.length > 0
    && Array.from(value).length <= maximum
    && !CONTROL_CHARACTER_PATTERN.test(value);
}

function optionalBoundedText(value: unknown, maximum: number): value is string | undefined {
  return value === undefined || boundedText(value, maximum);
}

function exactLaunchContract(value: Record<string, unknown>): boolean {
  try {
    createSessionLaunchTarget({
      path: value.launchPath as string,
      args: value.launchArgs as string[],
      interactive: value.interactive as boolean,
      tty: value.tty as boolean,
    });
    return true;
  } catch {
    return false;
  }
}

function exactTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 32) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function stateIs(value: unknown): value is SessionContainerStateV2 {
  return typeof value === "string" && (SESSION_CONTAINER_STATES as readonly string[]).includes(value);
}

function hasAdmissionFields(value: Record<string, unknown>): boolean {
  return exactTimestamp(value.admittedAt)
    && typeof value.leaseGeneration === "string"
    && LEASE_GENERATION_PATTERN.test(value.leaseGeneration)
    && exactTimestamp(value.leaseExpiresAt)
    && Date.parse(value.leaseExpiresAt) > Date.parse(value.admittedAt);
}

function lacksAdmissionFields(value: Record<string, unknown>): boolean {
  return value.admittedAt === undefined
    && value.leaseGeneration === undefined
    && value.leaseExpiresAt === undefined;
}

function stateFieldsAreValid(value: Record<string, unknown>): boolean {
  if (!stateIs(value.state)) return false;
  const hasContainerId = typeof value.containerId === "string" && DOCKER_CONTAINER_ID_PATTERN.test(value.containerId);
  if (value.containerId !== undefined && !hasContainerId) return false;
  // Allocation owns the identity before Docker creation. After create returns,
  // the same state may carry the exact created container ID so a host crash
  // cannot leave an unbound object between create and the provisioning-running
  // transition.
  if (value.state === "allocated") return lacksAdmissionFields(value);
  // The host transitions to provisioning-running with the exact bound container
  // id and the freshly minted lease, durably, before it spawns the foreground
  // start. Every live state therefore carries both, and a crash between start
  // and registration leaves an inert record recovery can reclaim exactly.
  if (value.state === "provisioning-running"
    || value.state === "attached") return hasContainerId && hasAdmissionFields(value);
  // Revocation may begin before container creation, or preserve the exact
  // container/admission proof being revoked. Admission evidence without the
  // container it authenticated is contradictory.
  return lacksAdmissionFields(value) || (hasContainerId && hasAdmissionFields(value));
}


export function sessionContainerName(projectId: string, sessionId: string): string {
  if (!PROJECT_ID_PATTERN.test(projectId)) throw new Error("invalid session-container project id");
  if (!SESSION_ID_PATTERN.test(sessionId)) throw new Error("invalid session id");
  return `runfree-${projectId}-session-${sessionId}`;
}

export function mintSessionIncarnation(): string {
  return crypto.randomBytes(32).toString("hex");
}

export function mintSessionPrincipal(): string {
  return crypto.randomBytes(32).toString("hex");
}

/**
 * Mints the one host-owned lease shape shared by initial admission and renewal.
 * Renewal deliberately selects only its mutable fields so this newly minted
 * timestamp cannot replace the incarnation's original admission timestamp.
 */
export function mintSessionContainerLeaseV2(
  options: MintSessionContainerLeaseV2Options,
): SessionContainerLeaseV2 {
  if (!Number.isSafeInteger(options.durationMs)
    || options.durationMs < SESSION_CONTAINER_LEASE_MIN_DURATION_MS
    || options.durationMs > SESSION_CONTAINER_LEASE_MAX_DURATION_MS) {
    throw new Error(
      `session-container lease duration must be an integer between ${SESSION_CONTAINER_LEASE_MIN_DURATION_MS} and ${SESSION_CONTAINER_LEASE_MAX_DURATION_MS} milliseconds`,
    );
  }

  const nowEpochMs = (options.nowEpochMs ?? Date.now)();
  if (!Number.isSafeInteger(nowEpochMs) || nowEpochMs < 0) {
    throw new Error("session-container lease clock must return a non-negative integer epoch millisecond");
  }
  const expiresAtMs = nowEpochMs + options.durationMs;
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= nowEpochMs) {
    throw new Error("session-container lease expiry arithmetic overflowed");
  }

  let admittedAt: string;
  let leaseExpiresAt: string;
  try {
    admittedAt = new Date(nowEpochMs).toISOString();
    leaseExpiresAt = new Date(expiresAtMs).toISOString();
  } catch {
    throw new Error("session-container lease clock is outside the exact ISO timestamp range");
  }
  if (Date.parse(admittedAt) !== nowEpochMs || Date.parse(leaseExpiresAt) !== expiresAtMs) {
    throw new Error("session-container lease clock is outside the exact ISO timestamp range");
  }

  const generationBytes = (options.randomBytes ?? crypto.randomBytes)(32);
  if (!(generationBytes instanceof Uint8Array) || generationBytes.byteLength !== 32) {
    throw new Error("session-container lease generation requires exactly 32 random bytes");
  }
  const leaseGeneration = Array.from(
    generationBytes,
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");

  return Object.freeze({ admittedAt, leaseGeneration, leaseExpiresAt });
}

export function parseSessionContainerRecordV2(value: unknown): SessionContainerRecordV2 | undefined {
  if (!isRecord(value) || !hasExactRecordKeys(value)) return undefined;
  if (value.schemaVersion !== SESSION_CONTAINER_RECORD_SCHEMA_VERSION) return undefined;
  if (typeof value.projectId !== "string" || !PROJECT_ID_PATTERN.test(value.projectId)) return undefined;
  if (value.composeProject !== `runfree-${value.projectId}`) return undefined;
  if (typeof value.sessionId !== "string" || !SESSION_ID_PATTERN.test(value.sessionId)) return undefined;
  if (typeof value.sessionIncarnation !== "string" || !OPAQUE_SESSION_IDENTITY_PATTERN.test(value.sessionIncarnation)) return undefined;
  if (typeof value.sessionPrincipal !== "string" || !OPAQUE_SESSION_IDENTITY_PATTERN.test(value.sessionPrincipal)) return undefined;
  if (value.sessionPrincipal === value.sessionIncarnation) return undefined;
  if (!boundedText(value.displayName, 80)
    || !boundedText(value.command, SESSION_DISPLAY_COMMAND_MAX_CHARACTERS)) return undefined;
  if (!exactLaunchContract(value)) return undefined;
  if (value.containerName !== sessionContainerName(value.projectId, value.sessionId)) return undefined;
  if (typeof value.sourceIp !== "string" || !isExactSessionSourceIpv4(value.sourceIp)) return undefined;
  if (!boundedText(value.selectedAgentImageRef, 512) || /\s/u.test(value.selectedAgentImageRef)) return undefined;
  for (const key of [
    "selectedAgentImageId",
    "sessionAgentMaterializationDigest",
    "selectedAgentImageInputDigest",
    "sessionTemplateDigest",
    "sessionAgentGenerationDigest",
    "controlPlaneGenerationDigest",
  ] as const) {
    if (typeof value[key] !== "string" || !SHA256_PATTERN.test(value[key])) return undefined;
  }
  if (typeof value.admissionContractEpoch !== "number"
    || !Number.isSafeInteger(value.admissionContractEpoch)
    || value.admissionContractEpoch < 1) return undefined;
  if (typeof value.hostPid !== "number" || !Number.isSafeInteger(value.hostPid) || value.hostPid < 1) return undefined;
  if (!optionalBoundedText(value.hostBootId, 256) || !optionalBoundedText(value.hostProcessStart, 256)) return undefined;
  if (!exactTimestamp(value.createdAt) || !stateFieldsAreValid(value)) return undefined;
  if (value.admittedAt !== undefined && Date.parse(value.admittedAt as string) < Date.parse(value.createdAt)) return undefined;
  return value as SessionContainerRecordV2;
}

// One identity-overlap predicate for "could this authority belong to the same
// session?" comparisons across lifecycle records and published snapshot
// records. Snapshot records carry the principal as `sessionKey`; lifecycle
// records carry it as `sessionPrincipal`. Any single shared identity claim
// counts as overlap; `containerId` participates only when both sides carry
// one. `networkId` is deliberately not session identity and is checked
// separately by callers.
export type SessionIdentityClaims = Readonly<{
  sessionId?: string;
  sessionIncarnation?: string;
  sourceIp?: string;
  containerId?: string;
  sessionPrincipal?: string;
  sessionKey?: string;
}>;

function sessionIdentityPrincipal(record: SessionIdentityClaims): string | undefined {
  return record.sessionKey ?? record.sessionPrincipal;
}

export function hasPossiblySelectedIdentity(
  record: SessionIdentityClaims,
  candidate: SessionIdentityClaims,
): boolean {
  return sessionIdentityPrincipal(record) === sessionIdentityPrincipal(candidate)
    || record.sessionId === candidate.sessionId
    || record.sessionIncarnation === candidate.sessionIncarnation
    || record.sourceIp === candidate.sourceIp
    || (record.containerId !== undefined
      && candidate.containerId !== undefined
      && record.containerId === candidate.containerId);
}

export function serializeSessionContainerRecordV2(record: SessionContainerRecordV2): string {
  const parsed = parseSessionContainerRecordV2(record);
  if (!parsed) throw new Error("session-container lifecycle record is invalid");
  return `${stableJson(parsed as unknown as StrictJson)}\n`;
}

export function createAllocatedSessionContainerRecordV2(
  input: AllocatedSessionContainerInputV2,
): SessionContainerRecordV2 {
  const materialization = parseSessionAgentMaterializationManifestV2(input.materialization);
  if (!materialization) throw new Error("allocated session-container materialization is invalid");
  assertSessionLaunchTarget(input.launch);
  const controlPlane = parseEffectiveControlPlaneSelectionV2(input.effectiveControlPlane);
  if (!controlPlane) throw new Error("allocated session-container effective control plane is invalid");
  if (materialization.projectId !== controlPlane.projectId
    || materialization.composeProject !== controlPlane.composeProject) {
    throw new Error("allocated session-container authorities belong to different projects");
  }
  if (materialization.generation.admissionContractEpoch !== controlPlane.admissionContractEpoch) {
    throw new Error("allocated session-container authorities have incompatible admission epochs");
  }
  const record: SessionContainerRecordV2 = {
    schemaVersion: SESSION_CONTAINER_RECORD_SCHEMA_VERSION,
    projectId: materialization.projectId,
    composeProject: materialization.composeProject,
    sessionId: input.sessionId,
    sessionIncarnation: input.sessionIncarnation ?? mintSessionIncarnation(),
    sessionPrincipal: input.sessionPrincipal ?? mintSessionPrincipal(),
    displayName: input.displayName,
    command: input.command,
    launchPath: input.launch.path,
    launchArgs: Object.freeze([...input.launch.args]),
    interactive: input.launch.interactive,
    tty: input.launch.tty,
    state: "allocated",
    containerName: sessionContainerName(materialization.projectId, input.sessionId),
    sourceIp: input.sourceIp,
    selectedAgentImageRef: materialization.selectedAgentImageRef,
    selectedAgentImageId: materialization.selectedAgentImageId,
    sessionAgentMaterializationDigest: materialization.sessionAgentMaterializationDigest,
    selectedAgentImageInputDigest: materialization.generation.selectedAgentImageInputDigest,
    sessionTemplateDigest: materialization.generation.sessionTemplateDigest,
    sessionAgentGenerationDigest: materialization.generation.sessionAgentGenerationDigest,
    controlPlaneGenerationDigest: controlPlane.controlPlaneGenerationDigest,
    admissionContractEpoch: controlPlane.admissionContractEpoch,
    hostPid: input.hostPid,
    ...(input.hostBootId !== undefined ? { hostBootId: input.hostBootId } : {}),
    ...(input.hostProcessStart !== undefined ? { hostProcessStart: input.hostProcessStart } : {}),
    createdAt: input.createdAt,
  };
  if (!parseSessionContainerRecordV2(record)) throw new Error("allocated session-container lifecycle record is invalid");
  return record;
}

export function bindAllocatedSessionContainerIdV2(
  record: SessionContainerRecordV2,
  containerId: string,
): SessionContainerRecordV2 {
  if (!parseSessionContainerRecordV2(record) || record.state !== "allocated") {
    throw new Error("only an allocated session-container record can bind a created container");
  }
  if (record.containerId !== undefined) throw new Error("allocated session-container record already has a container id");
  if (!DOCKER_CONTAINER_ID_PATTERN.test(containerId)) throw new Error("created session container id must be exact");
  const bound = { ...record, containerId };
  if (!parseSessionContainerRecordV2(bound)) throw new Error("bound allocated session-container record is invalid");
  return bound;
}

export function transitionBoundAllocatedSessionContainerToProvisioningRunningV2(
  record: SessionContainerRecordV2,
  lease: Readonly<Required<Pick<
    SessionContainerRecordV2,
    "admittedAt" | "leaseGeneration" | "leaseExpiresAt"
  >>>,
): SessionContainerRecordV2 {
  if (!parseSessionContainerRecordV2(record)
    || record.state !== "allocated"
    || record.containerId === undefined) {
    throw new Error("provisioning-running transition requires a bound allocated session container");
  }
  const next: SessionContainerRecordV2 = { ...record, state: "provisioning-running", ...lease };
  assertSessionContainerTransitionV2(record, next);
  return next;
}

export function transitionProvisioningRunningSessionContainerToAttachedV2(
  record: SessionContainerRecordV2,
): SessionContainerRecordV2 {
  if (!parseSessionContainerRecordV2(record) || record.state !== "provisioning-running") {
    throw new Error("attached transition requires a provisioning-running session container");
  }
  const next: SessionContainerRecordV2 = { ...record, state: "attached" };
  assertSessionContainerTransitionV2(record, next);
  return next;
}

/**
 * Advances an attached record's lease authority.
 *
 * Retained with the record schema rather than with the retired renewal loop:
 * `assertSessionContainerTransitionV2` refuses a lease that does not strictly
 * advance, and this is the only typed way to produce one.
 */
export function renewAttachedSessionContainerLeaseV2(
  record: SessionContainerRecordV2,
  lease: Readonly<Required<Pick<SessionContainerRecordV2, "leaseGeneration" | "leaseExpiresAt">>>,
): SessionContainerRecordV2 {
  if (!parseSessionContainerRecordV2(record) || record.state !== "attached") {
    throw new Error("lease renewal requires an attached session container");
  }
  const next: SessionContainerRecordV2 = {
    ...record,
    leaseGeneration: lease.leaseGeneration,
    leaseExpiresAt: lease.leaseExpiresAt,
  };
  assertSessionContainerTransitionV2(record, next);
  return next;
}

export function transitionSessionContainerToRevokingV2(
  record: SessionContainerRecordV2,
): SessionContainerRecordV2 {
  if (!parseSessionContainerRecordV2(record)) {
    throw new Error("revoking transition requires a valid session-container lifecycle record");
  }
  if (record.state === "revoking") {
    throw new Error("session-container lifecycle record is already revoking");
  }
  const next: SessionContainerRecordV2 = { ...record, state: "revoking" };
  assertSessionContainerTransitionV2(record, next);
  return next;
}

export function assertSessionContainerRecordProject(
  record: SessionContainerRecordV2,
  expected: SessionContainerProjectIdentity,
): void {
  if (!parseSessionContainerRecordV2(record)) throw new Error("session-container lifecycle record is invalid");
  if (record.projectId !== expected.projectId || record.composeProject !== expected.composeProject) {
    throw new Error("session-container lifecycle record belongs to a different project");
  }
  if (expected.composeProject !== `runfree-${expected.projectId}`) {
    throw new Error("expected session-container project identity is invalid");
  }
}

export function assertSessionContainerTransitionV2(
  current: SessionContainerRecordV2,
  next: SessionContainerRecordV2,
): void {
  if (!parseSessionContainerRecordV2(current) || !parseSessionContainerRecordV2(next)) {
    throw new Error("session-container lifecycle transition contains an invalid record");
  }
  if (!ALLOWED_TRANSITIONS[current.state].includes(next.state)) {
    throw new Error(`invalid session-container lifecycle transition: ${current.state} -> ${next.state}`);
  }
  for (const key of IMMUTABLE_RECORD_KEYS) {
    if (current[key] !== next[key]) throw new Error(`session-container lifecycle transition changed immutable ${key}`);
  }
  if (current.launchArgs.length !== next.launchArgs.length
    || current.launchArgs.some((argument, index) => argument !== next.launchArgs[index])) {
    throw new Error("session-container lifecycle transition changed immutable launchArgs");
  }
  if (current.containerId !== undefined && next.containerId !== current.containerId) {
    throw new Error("session-container lifecycle transition changed immutable containerId");
  }
  if (current.containerId === undefined && next.containerId !== undefined && current.state !== "allocated") {
    throw new Error("session-container lifecycle transition introduced a container outside allocation");
  }
  if (current.containerId === undefined && next.containerId !== undefined && next.state === "provisioning-running") {
    throw new Error("created session container id must be bound before provisioning-running transition");
  }

  const admissionChanged = current.admittedAt !== next.admittedAt
    || current.leaseGeneration !== next.leaseGeneration
    || current.leaseExpiresAt !== next.leaseExpiresAt;
  const isAttachedLeaseRenewal = current.state === "attached" && next.state === "attached";
  const mayChangeAdmission = (current.state === "allocated" && next.state === "provisioning-running")
    || isAttachedLeaseRenewal;
  if (admissionChanged && !mayChangeAdmission) {
    throw new Error("session-container lifecycle transition changed admission proof out of order");
  }
  if (isAttachedLeaseRenewal
    && (!admissionChanged
      || current.admittedAt !== next.admittedAt
      || current.leaseGeneration === next.leaseGeneration
      || !current.leaseExpiresAt
      || !next.leaseExpiresAt
      || Date.parse(next.leaseExpiresAt) <= Date.parse(current.leaseExpiresAt))) {
    throw new Error("attached session-container lease renewal must advance exact lease authority");
  }
}

export function sessionContainerLabels(record: SessionContainerRecordV2, runfreeVersion: string): SessionContainerLabels {
  if (!parseSessionContainerRecordV2(record)) throw new Error("session-container lifecycle record is invalid");
  if (!boundedText(runfreeVersion, 64) || /\s/u.test(runfreeVersion)) throw new Error("invalid Runfree version label");
  return {
    [SESSION_CONTAINER_LABELS.managed]: "true",
    [SESSION_CONTAINER_LABELS.role]: "session-agent",
    [SESSION_CONTAINER_LABELS.lifecycleOwner]: "session",
    [SESSION_CONTAINER_LABELS.labelSchema]: "1",
    [SESSION_CONTAINER_LABELS.projectId]: record.projectId,
    [SESSION_CONTAINER_LABELS.composeProject]: record.composeProject,
    [SESSION_CONTAINER_LABELS.sessionId]: record.sessionId,
    [SESSION_CONTAINER_LABELS.sessionIncarnation]: record.sessionIncarnation,
    [SESSION_CONTAINER_LABELS.selectedAgentImageInputDigest]: record.selectedAgentImageInputDigest,
    [SESSION_CONTAINER_LABELS.selectedAgentImageId]: record.selectedAgentImageId,
    [SESSION_CONTAINER_LABELS.sessionAgentMaterializationDigest]: record.sessionAgentMaterializationDigest,
    [SESSION_CONTAINER_LABELS.sessionAgentGenerationDigest]: record.sessionAgentGenerationDigest,
    [SESSION_CONTAINER_LABELS.sessionTemplateDigest]: record.sessionTemplateDigest,
    [SESSION_CONTAINER_LABELS.admissionContractEpoch]: String(record.admissionContractEpoch),
    [SESSION_CONTAINER_LABELS.version]: runfreeVersion,
  };
}

export function sessionContainerRecordsRoot(stateDir: string): string {
  return path.join(stateDir, "runtime", "v2", "session-containers");
}

export function sessionContainerQuarantineRoot(stateDir: string): string {
  return path.join(stateDir, "runtime", "v2", "session-containers-quarantine");
}

export function sessionContainerRecordPath(stateDir: string, sessionId: string): string {
  if (!SESSION_ID_PATTERN.test(sessionId)) throw new Error("invalid session id");
  return path.join(sessionContainerRecordsRoot(stateDir), `${sessionId}.json`);
}

function isMissing(error: unknown): boolean {
  return error instanceof Error && "code" in error && error.code === "ENOENT";
}

function assertSafeDirectory(directory: string): void {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`session-container state path is not a safe directory: ${directory}`);
  }
}


function ensureSafeDirectoryTree(stateDir: string, target: string): void {
  const relative = path.relative(path.resolve(stateDir), path.resolve(target));
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("session-container state target escapes the state directory");
  }
  if (!fs.existsSync(stateDir)) fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  assertSafeDirectory(stateDir);
  fsyncDirectory(path.dirname(stateDir));
  let current = stateDir;
  for (const segment of relative.split(path.sep)) {
    const parent = current;
    current = path.join(current, segment);
    try {
      fs.mkdirSync(current, { mode: 0o700 });
    } catch (error) {
      if (!isMissing(error) && (!(error instanceof Error) || !("code" in error) || error.code !== "EEXIST")) throw error;
    }
    assertSafeDirectory(current);
    fsyncDirectory(parent);
  }
}

function assertExistingSafeDirectoryTree(stateDir: string, target: string): boolean {
  if (!fs.existsSync(stateDir)) return false;
  assertSafeDirectory(stateDir);
  const relative = path.relative(path.resolve(stateDir), path.resolve(target));
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("session-container state target escapes the state directory");
  }
  let current = stateDir;
  for (const segment of relative.split(path.sep)) {
    current = path.join(current, segment);
    try {
      assertSafeDirectory(current);
    } catch (error) {
      if (isMissing(error)) return false;
      throw error;
    }
  }
  return true;
}

type ReadStateFile = { source: string; dev: number; ino: number; size: number };

function readRegularStateFile(filePath: string): ReadStateFile | undefined {
  return readBoundedRegularFile(filePath, {
    maxBytes: MAX_RECORD_BYTES,
    sizeRecheck: "exact",
    notFileMessage: (path) => `session-container state path is not a bounded regular single-link file: ${path}`,
    changedMessage: (path) => `session-container state path changed during read: ${path}`,
  });
}

function assertStateFileAbsent(filePath: string): void {
  try {
    fs.lstatSync(filePath);
  } catch (error) {
    if (isMissing(error)) return;
    throw error;
  }
  throw new Error("session-container lifecycle record already exists");
}

function assertStateFileUnchanged(filePath: string, expected: ReadStateFile): void {
  const current = readRegularStateFile(filePath);
  if (!current
    || current.dev !== expected.dev
    || current.ino !== expected.ino
    || current.size !== expected.size
    || current.source !== expected.source) {
    throw new Error("session-container lifecycle record changed before replacement");
  }
}

function atomicReplaceStateFile(
  stateDir: string,
  filePath: string,
  contents: string,
  expected?: ReadStateFile,
): void {
  ensureSafeDirectoryTree(stateDir, path.dirname(filePath));
  if (expected) assertStateFileUnchanged(filePath, expected);
  else assertStateFileAbsent(filePath);
  const temporaryPath = path.join(
    path.dirname(filePath),
    `.runfree-${process.pid}-${crypto.randomBytes(8).toString("hex")}.tmp`,
  );
  const descriptor = fs.openSync(
    temporaryPath,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  try {
    fs.writeFileSync(descriptor, contents);
    fs.fchmodSync(descriptor, 0o600);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  try {
    const temporaryStat = fs.lstatSync(temporaryPath);
    if (!temporaryStat.isFile() || temporaryStat.isSymbolicLink() || temporaryStat.nlink !== 1) {
      throw new Error("session-container temporary state is not a regular single-link file");
    }
    if (expected) {
      assertStateFileUnchanged(filePath, expected);
      fs.renameSync(temporaryPath, filePath);
    } else {
      try {
        // Linking the complete fsynced temporary file is the portable atomic
        // no-clobber publication primitive. A concurrent publisher wins with
        // EEXIST; it is never overwritten by initial lifecycle publication.
        fs.linkSync(temporaryPath, filePath);
      } catch (error) {
        if (error instanceof Error && "code" in error && error.code === "EEXIST") {
          throw new Error("session-container lifecycle record already exists");
        }
        throw error;
      }
    }
  } finally {
    try {
      fs.unlinkSync(temporaryPath);
    } catch {
      // A successful atomic rename consumes the temporary path.
    }
  }
  fsyncDirectory(path.dirname(filePath));
}

function parseStateSource(source: string): SessionContainerRecordV2 {
  let parsed: unknown;
  try {
    parsed = parseStrictJson(source);
  } catch {
    throw new Error("session-container lifecycle record is malformed");
  }
  const record = parseSessionContainerRecordV2(parsed);
  if (!record) throw new Error("session-container lifecycle record is invalid");
  return record;
}

export function writeSessionContainerRecordV2(
  stateDir: string,
  expected: SessionContainerProjectIdentity,
  record: SessionContainerRecordV2,
): void {
  assertSessionContainerRecordProject(record, expected);
  atomicReplaceStateFile(stateDir, sessionContainerRecordPath(stateDir, record.sessionId), serializeSessionContainerRecordV2(record));
}

export function replaceExactSessionContainerRecordV2(
  stateDir: string,
  expected: SessionContainerProjectIdentity,
  current: SessionContainerRecordV2,
  next: SessionContainerRecordV2,
): void {
  assertSessionContainerRecordProject(current, expected);
  assertSessionContainerRecordProject(next, expected);
  assertSessionContainerTransitionV2(current, next);
  const root = sessionContainerRecordsRoot(stateDir);
  if (!assertExistingSafeDirectoryTree(stateDir, root)) {
    throw new Error("session-container lifecycle record changed before replacement");
  }
  const filePath = sessionContainerRecordPath(stateDir, current.sessionId);
  const observed = readRegularStateFile(filePath);
  if (!observed || observed.source !== serializeSessionContainerRecordV2(current)) {
    throw new Error("session-container lifecycle record changed before replacement");
  }
  atomicReplaceStateFile(stateDir, filePath, serializeSessionContainerRecordV2(next), observed);
}

/**
 * Asserts that `next` is exactly `current` advanced by one control-plane
 * rebind: the same attached identity, a changed control-plane generation
 * digest, and nothing else — the record's lease is neither the session's
 * authority nor renewed by anything, so a rebind leaves it exactly as it was.
 * Shared by the durable batch rebind writer and by a surviving client that
 * adopts the rebound record.
 */
export function assertAttachedSessionContainerControlPlaneRebindV2(
  current: SessionContainerRecordV2,
  next: SessionContainerRecordV2,
): void {
  if (!parseSessionContainerRecordV2(current) || !parseSessionContainerRecordV2(next)
    || current.state !== "attached" || next.state !== "attached") {
    throw new Error("control-plane rebind requires exact attached lifecycle records");
  }
  for (const key of IMMUTABLE_RECORD_KEYS) {
    if (key === "controlPlaneGenerationDigest") continue;
    if (current[key] !== next[key]) {
      throw new Error(`control-plane rebind changed immutable ${key}`);
    }
  }
  if (current.controlPlaneGenerationDigest === next.controlPlaneGenerationDigest
    || current.launchArgs.length !== next.launchArgs.length
    || current.launchArgs.some((argument, index) => argument !== next.launchArgs[index])
    || current.containerId !== next.containerId
    || current.admittedAt !== next.admittedAt
    || current.leaseGeneration !== next.leaseGeneration
    || current.leaseExpiresAt !== next.leaseExpiresAt) {
    throw new Error("control-plane rebind did not advance exact compatible authority");
  }
}

/**
 * Rebinds one attached record to a proved compatible control plane. Ordinary
 * lifecycle transitions cannot change control authority; only the durable
 * batch rebind transaction may call this exact compare-and-replace operation.
 */
export function replaceExactSessionContainerRecordForControlPlaneRebindV2(
  stateDir: string,
  expected: SessionContainerProjectIdentity,
  current: SessionContainerRecordV2,
  next: SessionContainerRecordV2,
): void {
  assertSessionContainerRecordProject(current, expected);
  assertSessionContainerRecordProject(next, expected);
  assertAttachedSessionContainerControlPlaneRebindV2(current, next);
  const root = sessionContainerRecordsRoot(stateDir);
  if (!assertExistingSafeDirectoryTree(stateDir, root)) {
    throw new Error("session-container lifecycle record changed before control-plane rebind");
  }
  const filePath = sessionContainerRecordPath(stateDir, current.sessionId);
  const observed = readRegularStateFile(filePath);
  if (!observed || observed.source !== serializeSessionContainerRecordV2(current)) {
    throw new Error("session-container lifecycle record changed before control-plane rebind");
  }
  atomicReplaceStateFile(stateDir, filePath, serializeSessionContainerRecordV2(next), observed);
}

export function bindExactAllocatedSessionContainerRecordIdV2(
  stateDir: string,
  expected: SessionContainerProjectIdentity,
  current: SessionContainerRecordV2,
  containerId: string,
): SessionContainerRecordV2 {
  assertSessionContainerRecordProject(current, expected);
  const next = bindAllocatedSessionContainerIdV2(current, containerId);
  const root = sessionContainerRecordsRoot(stateDir);
  if (!assertExistingSafeDirectoryTree(stateDir, root)) {
    throw new Error("session-container lifecycle record changed before container-id binding");
  }
  const filePath = sessionContainerRecordPath(stateDir, current.sessionId);
  const observed = readRegularStateFile(filePath);
  if (!observed || observed.source !== serializeSessionContainerRecordV2(current)) {
    throw new Error("session-container lifecycle record changed before container-id binding");
  }
  atomicReplaceStateFile(stateDir, filePath, serializeSessionContainerRecordV2(next), observed);
  return next;
}

export function readSessionContainerRecordV2(
  stateDir: string,
  expected: SessionContainerProjectIdentity,
  sessionId: string,
): SessionContainerRecordV2 | undefined {
  const root = sessionContainerRecordsRoot(stateDir);
  if (!assertExistingSafeDirectoryTree(stateDir, root)) return undefined;
  const read = readRegularStateFile(sessionContainerRecordPath(stateDir, sessionId));
  if (!read) return undefined;
  const record = parseStateSource(read.source);
  assertSessionContainerRecordProject(record, expected);
  if (record.sessionId !== sessionId) throw new Error("session-container record filename does not match its session id");
  return record;
}

export type QuarantinedSessionContainerRecordV2 = Readonly<{
  fileName: string;
  reason: string;
  quarantinedPath?: string;
}>;

export type SessionContainerRecordEnumerationV2 = Readonly<{
  records: readonly SessionContainerRecordV2[];
  quarantined: readonly QuarantinedSessionContainerRecordV2[];
}>;

// A record replaced by a concurrent atomic rename reads as "changed during
// read" exactly once, so a single failure must not condemn it: only a failure
// that repeats across fresh attempts is corruption rather than a race.
const RECORD_ENUMERATION_READ_ATTEMPTS = 3;

function readSessionContainerRecordEntry(
  stateDir: string,
  expected: SessionContainerProjectIdentity,
  entry: string,
): SessionContainerRecordV2 | undefined {
  const sessionId = entry.slice(0, -".json".length);
  if (!SESSION_ID_PATTERN.test(sessionId)) throw new Error(`invalid session-container record filename: ${entry}`);
  const read = readRegularStateFile(path.join(sessionContainerRecordsRoot(stateDir), entry));
  if (!read) return undefined;
  const record = parseStateSource(read.source);
  assertSessionContainerRecordProject(record, expected);
  if (record.sessionId !== sessionId) throw new Error("session-container record filename does not match its session id");
  return record;
}

type QuarantineOutcome =
  | Readonly<{ kind: "quarantined"; path: string }>
  | Readonly<{ kind: "gone" }>
  | Readonly<{ kind: "replaced" }>
  | Readonly<{ kind: "unpersisted" }>;

/**
 * Moves one unreadable record into quarantine with a single atomic rename.
 *
 * Rename is the whole safety argument. Enumeration tolerates concurrent atomic
 * writers, so any preserve-then-delete pair (link+unlink, copy+unlink) has a
 * window where a writer republishes the pathname between the two steps and the
 * delete destroys a fresh valid record while preserving only the stale bytes.
 * A rename moves whatever inode the pathname names in one step: the worst a
 * race can do is move a just-published valid record into quarantine, where its
 * bytes survive, the quarantine guards fail closed, and an operator can
 * recover it — never silent destruction. The inode pre-check below narrows
 * even that to a vanishing window by re-reading a pathname that was visibly
 * replaced. The target name carries a random suffix so a repeat offender can
 * never overwrite earlier quarantined evidence.
 */
function quarantineSessionContainerRecord(stateDir: string, entry: string): QuarantineOutcome {
  const source = path.join(sessionContainerRecordsRoot(stateDir), entry);
  const root = sessionContainerQuarantineRoot(stateDir);
  let observed: fs.Stats;
  try {
    observed = fs.lstatSync(source);
  } catch (error) {
    if (isMissing(error)) return Object.freeze({ kind: "gone" as const });
    return Object.freeze({ kind: "unpersisted" as const });
  }
  try {
    ensureSafeDirectoryTree(stateDir, root);
    let current: fs.Stats;
    try {
      current = fs.lstatSync(source);
    } catch (error) {
      if (isMissing(error)) return Object.freeze({ kind: "gone" as const });
      return Object.freeze({ kind: "unpersisted" as const });
    }
    if (current.dev !== observed.dev || current.ino !== observed.ino) {
      // A concurrent writer replaced the record after the failed reads; the
      // fresh inode must be read, not condemned for its predecessor's bytes.
      return Object.freeze({ kind: "replaced" as const });
    }
    const target = path.join(root, `${entry}.${crypto.randomBytes(4).toString("hex")}`);
    try {
      fs.renameSync(source, target);
    } catch (error) {
      if (isMissing(error)) return Object.freeze({ kind: "gone" as const });
      return Object.freeze({ kind: "unpersisted" as const });
    }
    return Object.freeze({ kind: "quarantined" as const, path: target });
  } catch {
    return Object.freeze({ kind: "unpersisted" as const });
  }
}

export function listQuarantinedSessionContainerRecordNamesV2(stateDir: string): string[] {
  const root = sessionContainerQuarantineRoot(stateDir);
  if (!assertExistingSafeDirectoryTree(stateDir, root)) return [];
  return fs.readdirSync(root).sort();
}

const ILLEGIBLE_REGISTRY_ASIDE_PREFIX = "session-containers-illegible-";

/**
 * Moves a records root that cannot be enumerated aside in one atomic rename,
 * making the whole registry non-authorizing while preserving its bytes.
 *
 * The tree is re-validated with the same safe-path primitive the readers use,
 * so a structural failure — an intermediate symlink, an escaping path — stays
 * fatal here too: renaming through an unvalidated tree and later recursively
 * removing the aside could otherwise reach outside the state directory.
 */
export function quarantineIllegibleSessionContainerRegistryV2(stateDir: string): string | undefined {
  const root = sessionContainerRecordsRoot(stateDir);
  if (!assertExistingSafeDirectoryTree(stateDir, root)) return undefined;
  const aside = `${root}-illegible-${crypto.randomBytes(4).toString("hex")}`;
  try {
    fs.renameSync(root, aside);
  } catch (error) {
    if (isMissing(error)) return undefined;
    throw error;
  }
  return aside;
}

export function listIllegibleSessionContainerRegistryAsidesV2(stateDir: string): string[] {
  const parent = path.dirname(sessionContainerRecordsRoot(stateDir));
  if (!assertExistingSafeDirectoryTree(stateDir, parent)) return [];
  return fs.readdirSync(parent)
    .filter((entry) => entry.startsWith(ILLEGIBLE_REGISTRY_ASIDE_PREFIX))
    .sort();
}

export function removeIllegibleSessionContainerRegistryAsidesV2(stateDir: string): void {
  const parent = path.dirname(sessionContainerRecordsRoot(stateDir));
  if (!assertExistingSafeDirectoryTree(stateDir, parent)) return;
  for (const entry of listIllegibleSessionContainerRegistryAsidesV2(stateDir)) {
    fs.rmSync(path.join(parent, entry), { recursive: true, force: true });
  }
}

/**
 * Total enumeration of the project's lifecycle records.
 *
 * One unreadable file must never make the whole registry illegible: preflight,
 * reclamation, status, and destroy all enumerate, so a scan that throws on the
 * first bad byte wedges every one of them at once. An entry that repeatedly
 * fails to read is moved to the quarantine directory beside the record root —
 * preserved as evidence, never deleted — and reported by name, while every
 * readable record is still returned. Quarantine restores legibility, not
 * availability: the container a quarantined record named is untouched here, and
 * admission separately refuses the project while quarantined records exist.
 */
export function enumerateSessionContainerRecordsV2(
  stateDir: string,
  expected: SessionContainerProjectIdentity,
): SessionContainerRecordEnumerationV2 {
  const root = sessionContainerRecordsRoot(stateDir);
  if (!assertExistingSafeDirectoryTree(stateDir, root)) {
    return Object.freeze({ records: Object.freeze([]), quarantined: Object.freeze([]) });
  }
  const entries = fs.readdirSync(root).filter((entry) => entry.endsWith(".json"));
  if (entries.length > SESSION_CONTAINER_RECORD_SCAN_LIMIT) {
    throw new Error(`session-container record count exceeds ${SESSION_CONTAINER_RECORD_SCAN_LIMIT}`);
  }
  const records: SessionContainerRecordV2[] = [];
  const quarantined: QuarantinedSessionContainerRecordV2[] = [];
  for (const entry of entries.sort()) {
    // The outer pass exists for one case: quarantine observed that a concurrent
    // writer replaced the entry with a fresh inode, so the fresh record must be
    // read rather than condemned alongside the superseded bytes.
    let settled = false;
    for (let pass = 0; pass < 2 && !settled; pass += 1) {
      let record: SessionContainerRecordV2 | undefined;
      let failure: unknown;
      let read = false;
      for (let attempt = 0; attempt < RECORD_ENUMERATION_READ_ATTEMPTS && !read; attempt += 1) {
        try {
          record = readSessionContainerRecordEntry(stateDir, expected, entry);
          read = true;
        } catch (error) {
          failure = error;
        }
      }
      if (read) {
        // An entry that vanished between readdir and read was removed by a
        // legitimate concurrent revocation, not corrupted.
        if (record) records.push(record);
        settled = true;
        continue;
      }
      // Only this module's own validation failures condemn a record. A raw
      // filesystem error carries an errno code and describes the host, not
      // the bytes — EMFILE or EIO surviving the quick retries must propagate
      // rather than move a possibly valid live-session record into
      // quarantine.
      if (failure instanceof Error && "code" in failure) throw failure;
      const reason = failure instanceof Error ? failure.message : String(failure);
      const outcome = quarantineSessionContainerRecord(stateDir, entry);
      if (outcome.kind === "replaced" && pass === 0) continue;
      if (outcome.kind !== "gone") {
        quarantined.push(Object.freeze({
          fileName: entry,
          reason,
          ...(outcome.kind === "quarantined" ? { quarantinedPath: outcome.path } : {}),
        }));
      }
      settled = true;
    }
  }
  return Object.freeze({ records: Object.freeze(records), quarantined: Object.freeze(quarantined) });
}

export type SessionContainerRecordPeekV2 = Readonly<{
  records: readonly SessionContainerRecordV2[];
  /** Entries that could not be read; the view is partial, not authoritative. */
  unreadable: number;
}>;

/**
 * Strictly read-only registry view for consumers that must not mutate state.
 *
 * Recovery listing and classification are contractually side-effect-free, so
 * they cannot use `enumerateSessionContainerRecordsV2`, whose quarantine step
 * moves unreadable records. This peek reports the same readable records and
 * counts what it could not read instead of condemning it; callers must treat a
 * nonzero `unreadable` as "cannot prove" rather than as an empty registry.
 */
export function peekSessionContainerRecordsV2(
  stateDir: string,
  expected: SessionContainerProjectIdentity,
): SessionContainerRecordPeekV2 {
  const root = sessionContainerRecordsRoot(stateDir);
  if (!assertExistingSafeDirectoryTree(stateDir, root)) {
    return Object.freeze({ records: Object.freeze([]), unreadable: 0 });
  }
  const entries = fs.readdirSync(root).filter((entry) => entry.endsWith(".json"));
  if (entries.length > SESSION_CONTAINER_RECORD_SCAN_LIMIT) {
    throw new Error(`session-container record count exceeds ${SESSION_CONTAINER_RECORD_SCAN_LIMIT}`);
  }
  const records: SessionContainerRecordV2[] = [];
  let unreadable = 0;
  for (const entry of entries.sort()) {
    let settled = false;
    for (let attempt = 0; attempt < RECORD_ENUMERATION_READ_ATTEMPTS && !settled; attempt += 1) {
      try {
        const record = readSessionContainerRecordEntry(stateDir, expected, entry);
        // A vanished entry was removed by a legitimate concurrent revocation.
        if (record) records.push(record);
        settled = true;
      } catch {
        // Retried: an atomic replacement mid-read fails exactly once.
      }
    }
    if (!settled) unreadable += 1;
  }
  return Object.freeze({ records: Object.freeze(records), unreadable });
}

export function listSessionContainerRecordsV2(
  stateDir: string,
  expected: SessionContainerProjectIdentity,
): SessionContainerRecordV2[] {
  const enumeration = enumerateSessionContainerRecordsV2(stateDir, expected);
  // Guards that refuse quarantined registries consult the quarantine
  // directory. An unreadable record whose quarantine could not be persisted
  // would be invisible there while still omitted from the records, so this
  // strict listing must fail closed rather than present a partial registry
  // as complete.
  const unpersisted = enumeration.quarantined.filter((entry) => entry.quarantinedPath === undefined);
  if (unpersisted.length > 0) {
    throw new Error(
      `session-container registry has unreadable record(s) whose quarantine could not be persisted: ${unpersisted.map((entry) => entry.fileName).join(", ")}`,
    );
  }
  return [...enumeration.records];
}

export function removeExactSessionContainerRecordV2(
  stateDir: string,
  expected: SessionContainerProjectIdentity,
  record: SessionContainerRecordV2,
): boolean {
  assertSessionContainerRecordProject(record, expected);
  const root = sessionContainerRecordsRoot(stateDir);
  if (!assertExistingSafeDirectoryTree(stateDir, root)) return false;
  const filePath = sessionContainerRecordPath(stateDir, record.sessionId);
  const read = readRegularStateFile(filePath);
  if (!read) return false;
  const current = parseStateSource(read.source);
  assertSessionContainerRecordProject(current, expected);
  if (serializeSessionContainerRecordV2(current) !== serializeSessionContainerRecordV2(record)) {
    throw new Error("session-container lifecycle record changed before removal");
  }
  const finalStat = fs.lstatSync(filePath);
  if (!finalStat.isFile()
    || finalStat.isSymbolicLink()
    || finalStat.nlink !== 1
    || finalStat.dev !== read.dev
    || finalStat.ino !== read.ino
    || finalStat.size !== read.size) {
    throw new Error("session-container lifecycle record changed before removal");
  }
  fs.unlinkSync(filePath);
  fsyncDirectory(root);
  return true;
}
