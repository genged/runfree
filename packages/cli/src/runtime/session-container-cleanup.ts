import type * as childProcess from "node:child_process";

import { isExactSessionSourceIpv4 } from "@runfree/runtime-contracts/session-registry";

import {
  assertSessionContainerCreateCommand,
  executeSessionDockerCommand,
  parseCreatedSessionContainerId,
  SESSION_CONTAINER_STOP_SECONDS,
  type SessionContainerCreatePlan,
  type SessionDockerCommand,
} from "./session-container-docker.ts";
import {
  assertExactContainerOnlySessionClassification,
  assertExactUnboundCreatedSessionClassification,
  parseSessionNetworkAttachments,
  reclassifyExactContainerOnlySessionClassification,
  type SessionReconciliationClassification,
} from "./session-container-reconciliation.ts";
import {
  assertSessionContainerRecordProject,
  bindAllocatedSessionContainerIdV2,
  enumerateSessionContainerRecordsV2,
  listQuarantinedSessionContainerRecordNamesV2,
  parseSessionContainerRecordV2,
  removeExactSessionContainerRecordV2,
  serializeSessionContainerRecordV2,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { CaptureResult } from "./types.ts";

const MAX_CREATE_OUTPUT_BYTES = 4 * 1024;
const MAX_CONTAINER_LIST_OUTPUT_BYTES = 4 * 1024;
const MAX_NETWORK_INSPECT_OUTPUT_BYTES = 512 * 1024;

declare const sessionContainerCreationReceiptBrand: unique symbol;
declare const sessionContainerCleanupCommandBrand: unique symbol;
declare const sessionContainerAbsenceReceiptBrand: unique symbol;
declare const sessionContainerOrphanCleanupAuthorityBrand: unique symbol;
declare const sessionContainerOrphanAbsenceReceiptBrand: unique symbol;
declare const sessionContainerCreateOutputRecoveryAuthorityBrand: unique symbol;

export type SessionContainerCreationReceipt = Readonly<{
  readonly [sessionContainerCreationReceiptBrand]: true;
  containerId: string;
  sessionId: string;
  sessionIncarnation: string;
}>;

export type SessionContainerCleanupCommand = Readonly<{
  readonly [sessionContainerCleanupCommandBrand]: true;
  executable: "docker";
  args: readonly string[];
  effect:
    | "stop-creation-authorized-session-container"
    | "remove-creation-authorized-session-container"
    | "stop-orphan-session-container"
    | "remove-orphan-session-container"
    | "list-exact-session-container"
    | "inspect-session-network-for-absence";
  exactTarget: string;
}>;

export type SessionContainerAbsenceReceipt = Readonly<{
  readonly [sessionContainerAbsenceReceiptBrand]: true;
  containerId: string;
  sourceIp: string;
  networkId: string;
}>;

export type SessionContainerOrphanCleanupAuthority = Readonly<{
  readonly [sessionContainerOrphanCleanupAuthorityBrand]: true;
  projectId: string;
  composeProject: string;
  containerId: string;
  containerName: string;
  imageId: string;
  sessionId: string;
  sessionIncarnation: string;
  selectedAgentImageInputDigest: string;
  selectedAgentImageId: string;
  sessionAgentMaterializationDigest: string;
  sessionAgentGenerationDigest: string;
  sessionTemplateDigest: string;
  admissionContractEpoch: number;
  runfreeVersion: string;
  sourceIp?: string;
  networkId: string;
}>;

export type SessionContainerOrphanAbsenceReceipt = Readonly<{
  readonly [sessionContainerOrphanAbsenceReceiptBrand]: true;
  containerId: string;
  networkId: string;
  sourceIp?: string;
}>;

export type SessionContainerCreateOutputRecoveryAuthority = Readonly<{
  readonly [sessionContainerCreateOutputRecoveryAuthorityBrand]: true;
  projectId: string;
  composeProject: string;
  sessionId: string;
  sessionIncarnation: string;
  containerId: string;
  containerName: string;
}>;

export type SessionContainerCleanupExecutor = (
  executable: "docker",
  args: readonly string[],
  options?: childProcess.SpawnSyncOptions,
) => CaptureResult;

export type SessionContainerNetworkIdentity = Readonly<{
  networkId: string;
  networkName: string;
  subnet: string;
}>;

const creationReceiptRecords = new WeakMap<object, SessionContainerRecordV2>();
const cleanupCommands = new WeakSet<object>();
const absenceReceiptBindings = new WeakMap<object, Readonly<{
  record: SessionContainerRecordV2;
  network: SessionContainerNetworkIdentity;
}>>();
const orphanCleanupAuthorityBindings = new WeakMap<object, Readonly<{
  classification: Extract<SessionReconciliationClassification, { kind: "container-only" }>;
  expectedProject: Readonly<SessionContainerProjectIdentity>;
  network: SessionContainerNetworkIdentity;
  stateDir: string;
  lifecycleLock: ProjectLifecycleLock;
  registrySource: string;
}>>();
const orphanCleanupCommandAuthorities = new WeakMap<object, SessionContainerOrphanCleanupAuthority>();
const orphanAbsenceReceiptBindings = new WeakMap<object, Readonly<{
  authority: SessionContainerOrphanCleanupAuthority;
}>>();
const createOutputRecoveryAuthorityBindings = new WeakMap<object, Readonly<{
  classification: Extract<SessionReconciliationClassification, { kind: "unbound-created" }>;
  expectedProject: Readonly<SessionContainerProjectIdentity>;
}>>();

function exactRecordSnapshot(record: SessionContainerRecordV2): SessionContainerRecordV2 {
  const parsed = parseSessionContainerRecordV2(JSON.parse(serializeSessionContainerRecordV2(record)));
  if (!parsed) throw new Error("could not seal the session-container cleanup authority");
  return parsed;
}

function sealedCleanupCommand(
  command: Omit<SessionContainerCleanupCommand, typeof sessionContainerCleanupCommandBrand>,
): SessionContainerCleanupCommand {
  const sealed = Object.freeze({ ...command, args: Object.freeze([...command.args]) }) as SessionContainerCleanupCommand;
  cleanupCommands.add(sealed);
  return sealed;
}

function exactInternalNetworkIdentity(
  network: SessionContainerNetworkIdentity,
  expectedProject: SessionContainerProjectIdentity,
): SessionContainerNetworkIdentity {
  if (!/^[a-f0-9]{64}$/.test(network.networkId)) {
    throw new Error("session network id must be an exact Docker object id");
  }
  if (network.networkName !== `${expectedProject.composeProject}_agent_internal`) {
    throw new Error("session network does not belong to the expected project's internal network");
  }
  const [subnetAddress, subnetPrefix, subnetExtra] = network.subnet.split("/");
  if (subnetExtra !== undefined
    || subnetPrefix !== "24"
    || !subnetAddress
    || !isExactSessionSourceIpv4(subnetAddress)
    || !subnetAddress.endsWith(".0")) {
    throw new Error("session internal network requires an exact IPv4 /24 subnet");
  }
  return Object.freeze({ ...network });
}

function exactRegistrySource(records: readonly SessionContainerRecordV2[]): string {
  return records.map(serializeSessionContainerRecordV2).join("");
}

function readExactLifecycleRegistry(input: {
  stateDir: string;
  expectedProject: SessionContainerProjectIdentity;
  lifecycleLock: ProjectLifecycleLock;
}): Readonly<{ records: readonly SessionContainerRecordV2[]; source: string }> {
  input.lifecycleLock.assertHeld();
  // Orphan authorization proves that no record claims a container. A partially
  // legible registry cannot prove that: the quarantined record may be exactly
  // the claim, so treating its container as an orphan would remove what may
  // still be a live session. Enumerate first and check quarantine after, so a
  // record that this very scan quarantines is refused rather than silently
  // omitted from an allegedly exact registry.
  const enumeration = enumerateSessionContainerRecordsV2(input.stateDir, input.expectedProject);
  input.lifecycleLock.assertHeld();
  const quarantined = [...new Set([
    ...enumeration.quarantined.map((entry) => entry.fileName),
    ...listQuarantinedSessionContainerRecordNamesV2(input.stateDir),
  ])].sort();
  if (quarantined.length > 0) {
    throw new Error(
      `session-container cleanup refuses a partially legible lifecycle registry: quarantined record(s) ${quarantined.join(", ")}`,
    );
  }
  const records = [...enumeration.records];
  input.lifecycleLock.assertHeld();
  return Object.freeze({ records: Object.freeze(records), source: exactRegistrySource(records) });
}

function assertSessionContainerOrphanCleanupAuthority(
  authority: SessionContainerOrphanCleanupAuthority,
  verifyRegistry = false,
): Readonly<{
  classification: Extract<SessionReconciliationClassification, { kind: "container-only" }>;
  expectedProject: Readonly<SessionContainerProjectIdentity>;
  network: SessionContainerNetworkIdentity;
  stateDir: string;
  lifecycleLock: ProjectLifecycleLock;
  registrySource: string;
}> {
  const binding = orphanCleanupAuthorityBindings.get(authority);
  if (!binding) throw new Error("refusing an unsealed session-container orphan cleanup authority");
  binding.lifecycleLock.assertHeld();
  if (verifyRegistry) {
    const currentRegistry = readExactLifecycleRegistry(binding);
    if (currentRegistry.source !== binding.registrySource) {
      throw new Error("session-container lifecycle registry changed after orphan cleanup authorization");
    }
  }
  const { container, identity } = binding.classification;
  if (authority.projectId !== binding.expectedProject.projectId
    || authority.composeProject !== binding.expectedProject.composeProject
    || authority.containerId !== container.containerId
    || authority.containerName !== container.containerName
    || authority.imageId !== container.imageId
    || authority.sessionId !== identity.sessionId
    || authority.sessionIncarnation !== identity.sessionIncarnation
    || authority.selectedAgentImageInputDigest !== identity.selectedAgentImageInputDigest
    || authority.selectedAgentImageId !== identity.selectedAgentImageId
    || authority.sessionAgentMaterializationDigest !== identity.sessionAgentMaterializationDigest
    || authority.sessionAgentGenerationDigest !== identity.sessionAgentGenerationDigest
    || authority.sessionTemplateDigest !== identity.sessionTemplateDigest
    || authority.admissionContractEpoch !== identity.admissionContractEpoch
    || authority.runfreeVersion !== identity.runfreeVersion
    || authority.sourceIp !== container.sourceIp
    || authority.networkId !== binding.network.networkId) {
    throw new Error("session-container orphan cleanup authority no longer matches its exact identity");
  }
  return binding;
}

function assertSessionContainerCreateOutputRecoveryAuthority(
  authority: SessionContainerCreateOutputRecoveryAuthority,
  expectedProject: SessionContainerProjectIdentity,
): Extract<SessionReconciliationClassification, { kind: "unbound-created" }> {
  const binding = createOutputRecoveryAuthorityBindings.get(authority);
  if (!binding) throw new Error("refusing an unsealed session-container create-output recovery authority");
  const { record, container } = binding.classification;
  if (expectedProject.projectId !== binding.expectedProject.projectId
    || expectedProject.composeProject !== binding.expectedProject.composeProject
    || authority.projectId !== binding.expectedProject.projectId
    || authority.composeProject !== binding.expectedProject.composeProject
    || authority.sessionId !== record.sessionId
    || authority.sessionIncarnation !== record.sessionIncarnation
    || authority.containerId !== container.containerId
    || authority.containerName !== container.containerName
    || record.state !== "allocated"
    || record.containerId !== undefined
    || record.admittedAt !== undefined
    || record.leaseGeneration !== undefined
    || record.leaseExpiresAt !== undefined) {
    throw new Error("session-container create-output recovery authority no longer matches its exact identity");
  }
  return binding.classification;
}

/**
 * Authorizes record-first recovery for the narrow crash window where Docker
 * created the exact stopped container but its ID was not persisted.
 */
export function authorizeUnboundCreatedSessionRecordRecovery(
  classification: SessionReconciliationClassification,
  expectedProject: SessionContainerProjectIdentity,
): SessionContainerCreateOutputRecoveryAuthority {
  assertExactUnboundCreatedSessionClassification(classification, expectedProject);
  const authority = Object.freeze({
    projectId: expectedProject.projectId,
    composeProject: expectedProject.composeProject,
    sessionId: classification.record.sessionId,
    sessionIncarnation: classification.record.sessionIncarnation,
    containerId: classification.container.containerId,
    containerName: classification.container.containerName,
  }) as SessionContainerCreateOutputRecoveryAuthority;
  createOutputRecoveryAuthorityBindings.set(authority, Object.freeze({
    classification,
    expectedProject: Object.freeze({ ...expectedProject }),
  }));
  return authority;
}

/**
 * Removes only the exact unchanged, unleased allocation record. Repeating the
 * operation after successful removal is safe and returns false; the container
 * remains for a fresh inventory to authorize ordinary orphan cleanup.
 */
export function recoverUnboundCreatedSessionRecordV2(
  stateDir: string,
  expectedProject: SessionContainerProjectIdentity,
  authority: SessionContainerCreateOutputRecoveryAuthority,
): boolean {
  const classification = assertSessionContainerCreateOutputRecoveryAuthority(authority, expectedProject);
  return removeExactSessionContainerRecordV2(stateDir, expectedProject, classification.record);
}

/**
 * Reconstructs cleanup authority from a fresh exact Docker classification, so
 * restart recovery does not depend on the process-local creation receipt.
 */
export function authorizeSessionContainerOrphanCleanup(
  classification: SessionReconciliationClassification,
  expectedProject: SessionContainerProjectIdentity,
  network: SessionContainerNetworkIdentity,
  stateDir: string,
  lifecycleLock: ProjectLifecycleLock,
): SessionContainerOrphanCleanupAuthority {
  assertExactContainerOnlySessionClassification(classification, expectedProject);
  const registry = readExactLifecycleRegistry({ stateDir, expectedProject, lifecycleLock });
  const exactClassification = reclassifyExactContainerOnlySessionClassification(
    classification,
    registry.records,
    expectedProject,
  );
  lifecycleLock.assertHeld();
  const exactNetwork = exactInternalNetworkIdentity(network, expectedProject);
  if (exactClassification.container.internalNetworkId !== undefined
    && exactClassification.container.internalNetworkId !== exactNetwork.networkId) {
    throw new Error("session-container orphan belongs to another internal network");
  }
  const authority = Object.freeze({
    projectId: expectedProject.projectId,
    composeProject: expectedProject.composeProject,
    containerId: exactClassification.container.containerId,
    containerName: exactClassification.container.containerName,
    imageId: exactClassification.container.imageId,
    sessionId: exactClassification.identity.sessionId,
    sessionIncarnation: exactClassification.identity.sessionIncarnation,
    selectedAgentImageInputDigest: exactClassification.identity.selectedAgentImageInputDigest,
    selectedAgentImageId: exactClassification.identity.selectedAgentImageId,
    sessionAgentMaterializationDigest: exactClassification.identity.sessionAgentMaterializationDigest,
    sessionAgentGenerationDigest: exactClassification.identity.sessionAgentGenerationDigest,
    sessionTemplateDigest: exactClassification.identity.sessionTemplateDigest,
    admissionContractEpoch: exactClassification.identity.admissionContractEpoch,
    runfreeVersion: exactClassification.identity.runfreeVersion,
    ...(exactClassification.container.sourceIp === undefined ? {} : { sourceIp: exactClassification.container.sourceIp }),
    networkId: exactNetwork.networkId,
  }) as SessionContainerOrphanCleanupAuthority;
  orphanCleanupAuthorityBindings.set(authority, Object.freeze({
    classification: exactClassification,
    expectedProject: Object.freeze({ ...expectedProject }),
    network: exactNetwork,
    stateDir,
    lifecycleLock,
    registrySource: registry.source,
  }));
  return authority;
}

export function orphanSessionContainerStopCommand(
  authority: SessionContainerOrphanCleanupAuthority,
): SessionContainerCleanupCommand {
  assertSessionContainerOrphanCleanupAuthority(authority);
  const command = sealedCleanupCommand({
    executable: "docker",
    args: ["container", "stop", "--time", String(SESSION_CONTAINER_STOP_SECONDS), authority.containerId],
    effect: "stop-orphan-session-container",
    exactTarget: authority.containerId,
  });
  orphanCleanupCommandAuthorities.set(command, authority);
  return command;
}

export function orphanSessionContainerRemoveCommand(
  authority: SessionContainerOrphanCleanupAuthority,
): SessionContainerCleanupCommand {
  assertSessionContainerOrphanCleanupAuthority(authority);
  const command = sealedCleanupCommand({
    executable: "docker",
    args: ["container", "rm", authority.containerId],
    effect: "remove-orphan-session-container",
    exactTarget: authority.containerId,
  });
  orphanCleanupCommandAuthorities.set(command, authority);
  return command;
}

export function executeSessionContainerCreate(
  command: SessionDockerCommand,
  plan: SessionContainerCreatePlan,
  executor: SessionContainerCleanupExecutor,
  options: childProcess.SpawnSyncOptions = {},
): Readonly<{ containerId: string; receipt: SessionContainerCreationReceipt }> {
  assertSessionContainerCreateCommand(command, plan);
  const result = executeSessionDockerCommand(command, (executable, args) => executor(executable, args, options));
  if (result.status !== 0) throw new Error("Docker failed to create the stopped session container");
  if (Buffer.byteLength(result.stdout) > MAX_CREATE_OUTPUT_BYTES) {
    throw new Error("Docker session-container create output exceeds the size limit");
  }
  const containerId = parseCreatedSessionContainerId(result.stdout);
  const receipt = Object.freeze({
    containerId,
    sessionId: plan.record.sessionId,
    sessionIncarnation: plan.record.sessionIncarnation,
  }) as SessionContainerCreationReceipt;
  creationReceiptRecords.set(receipt, exactRecordSnapshot(plan.record));
  return Object.freeze({ containerId, receipt });
}

function exactCreationAuthorizedRecord(
  receipt: SessionContainerCreationReceipt,
  record: SessionContainerRecordV2,
  expectedProject: SessionContainerProjectIdentity,
): SessionContainerRecordV2 {
  const binding = creationReceiptRecords.get(receipt);
  if (!binding) throw new Error("refusing an unsealed session-container creation receipt");
  const parsed = parseSessionContainerRecordV2(record);
  if (!parsed || !parsed.containerId) {
    throw new Error("creation-authorized cleanup requires an exact bound session container");
  }
  assertSessionContainerRecordProject(parsed, expectedProject);
  const expectedBound = bindAllocatedSessionContainerIdV2(binding, receipt.containerId);
  const normalized: SessionContainerRecordV2 = { ...parsed, state: "allocated" };
  delete normalized.admittedAt;
  delete normalized.leaseGeneration;
  delete normalized.leaseExpiresAt;
  if (serializeSessionContainerRecordV2(normalized) !== serializeSessionContainerRecordV2(expectedBound)
    || receipt.containerId !== parsed.containerId
    || receipt.sessionId !== parsed.sessionId
    || receipt.sessionIncarnation !== parsed.sessionIncarnation) {
    throw new Error("session-container creation receipt belongs to a different lifecycle incarnation");
  }
  return parsed;
}

/**
 * Process-local fallback cleanup for the exact container created under this
 * sealed receipt. It remains valid across lifecycle transitions but cannot
 * authorize a different container, project, or session incarnation.
 */
export function creationAuthorizedSessionContainerStopCommand(
  record: SessionContainerRecordV2,
  expectedProject: SessionContainerProjectIdentity,
  creationReceipt: SessionContainerCreationReceipt,
): SessionContainerCleanupCommand {
  const parsed = exactCreationAuthorizedRecord(creationReceipt, record, expectedProject);
  return sealedCleanupCommand({
    executable: "docker",
    args: ["container", "stop", "--time", String(SESSION_CONTAINER_STOP_SECONDS), parsed.containerId as string],
    effect: "stop-creation-authorized-session-container",
    exactTarget: parsed.containerId as string,
  });
}

export function creationAuthorizedSessionContainerRemoveCommand(
  record: SessionContainerRecordV2,
  expectedProject: SessionContainerProjectIdentity,
  creationReceipt: SessionContainerCreationReceipt,
): SessionContainerCleanupCommand {
  const parsed = exactCreationAuthorizedRecord(creationReceipt, record, expectedProject);
  return sealedCleanupCommand({
    executable: "docker",
    args: ["container", "rm", parsed.containerId as string],
    effect: "remove-creation-authorized-session-container",
    exactTarget: parsed.containerId as string,
  });
}

export function executeSessionContainerCleanupCommand(
  command: SessionContainerCleanupCommand,
  executor: SessionContainerCleanupExecutor,
  options: childProcess.SpawnSyncOptions = {},
): CaptureResult {
  if (!cleanupCommands.has(command)) throw new Error("refusing an unsealed session-container cleanup command");
  const orphanAuthority = orphanCleanupCommandAuthorities.get(command);
  if (orphanAuthority) assertSessionContainerOrphanCleanupAuthority(orphanAuthority, true);
  return executor(command.executable, command.args, options);
}

function exactSessionContainerAbsenceListCommand(
  containerId: string,
): SessionContainerCleanupCommand {
  if (!/^[a-f0-9]{64}$/.test(containerId)) {
    throw new Error("session-container absence proof requires an exact container id");
  }
  return sealedCleanupCommand({
    executable: "docker",
    args: [
      "container",
      "ls",
      "--all",
      "--no-trunc",
      "--filter",
      `id=${containerId}`,
      "--format",
      "{{.ID}}",
    ],
    effect: "list-exact-session-container",
    exactTarget: containerId,
  });
}

function sessionNetworkAbsenceInspectCommand(networkId: string): SessionContainerCleanupCommand {
  if (!/^[a-f0-9]{64}$/.test(networkId)) {
    throw new Error("session network id must be an exact Docker object id");
  }
  return sealedCleanupCommand({
    executable: "docker",
    args: ["network", "inspect", networkId],
    effect: "inspect-session-network-for-absence",
    exactTarget: networkId,
  });
}

export function proveSessionContainerAbsent(
  executor: SessionContainerCleanupExecutor,
  record: SessionContainerRecordV2,
  expectedProject: SessionContainerProjectIdentity,
  network: SessionContainerNetworkIdentity,
  options: childProcess.SpawnSyncOptions = {},
): SessionContainerAbsenceReceipt {
  assertSessionContainerRecordProject(record, expectedProject);
  if (!record.containerId) throw new Error("session-container absence proof requires an exact container id");
  const containerResult = executeSessionContainerCleanupCommand(
    exactSessionContainerAbsenceListCommand(record.containerId),
    executor,
    options,
  );
  if (containerResult.status !== 0) throw new Error("Docker could not prove the session container absent");
  if (Buffer.byteLength(containerResult.stdout) > MAX_CONTAINER_LIST_OUTPUT_BYTES) {
    throw new Error("Docker session-container absence output exceeds the size limit");
  }
  if (containerResult.stdout !== "") throw new Error("session container still exists");

  const networkResult = executeSessionContainerCleanupCommand(
    sessionNetworkAbsenceInspectCommand(network.networkId),
    executor,
    options,
  );
  if (networkResult.status !== 0) throw new Error("Docker could not inspect the session network for absence");
  if (Buffer.byteLength(networkResult.stdout) > MAX_NETWORK_INSPECT_OUTPUT_BYTES) {
    throw new Error("Docker session-network absence output exceeds the size limit");
  }
  const attachments = parseSessionNetworkAttachments(networkResult.stdout, network);
  if (attachments.some((attachment) => (
    attachment.containerId === record.containerId || attachment.sourceIp === record.sourceIp
  ))) {
    throw new Error("session container or source IP still owns an internal-network endpoint");
  }
  const receipt = Object.freeze({
    containerId: record.containerId,
    sourceIp: record.sourceIp,
    networkId: network.networkId,
  }) as SessionContainerAbsenceReceipt;
  absenceReceiptBindings.set(receipt, Object.freeze({
    record: exactRecordSnapshot(record),
    network: Object.freeze({ ...network }),
  }));
  return receipt;
}

export function proveSessionContainerOrphanAbsent(
  executor: SessionContainerCleanupExecutor,
  authority: SessionContainerOrphanCleanupAuthority,
  options: childProcess.SpawnSyncOptions = {},
): SessionContainerOrphanAbsenceReceipt {
  const binding = assertSessionContainerOrphanCleanupAuthority(authority, true);
  const containerResult = executeSessionContainerCleanupCommand(
    exactSessionContainerAbsenceListCommand(authority.containerId),
    executor,
    options,
  );
  if (containerResult.status !== 0) throw new Error("Docker could not prove the orphan session container absent");
  if (Buffer.byteLength(containerResult.stdout) > MAX_CONTAINER_LIST_OUTPUT_BYTES) {
    throw new Error("Docker orphan session-container absence output exceeds the size limit");
  }
  if (containerResult.stdout !== "") throw new Error("orphan session container still exists");

  const networkResult = executeSessionContainerCleanupCommand(
    sessionNetworkAbsenceInspectCommand(binding.network.networkId),
    executor,
    options,
  );
  if (networkResult.status !== 0) throw new Error("Docker could not inspect the internal network for orphan absence");
  if (Buffer.byteLength(networkResult.stdout) > MAX_NETWORK_INSPECT_OUTPUT_BYTES) {
    throw new Error("Docker internal-network orphan absence output exceeds the size limit");
  }
  const attachments = parseSessionNetworkAttachments(networkResult.stdout, binding.network);
  if (attachments.some((attachment) => (
    attachment.containerId === authority.containerId
    || (authority.sourceIp !== undefined && attachment.sourceIp === authority.sourceIp)
  ))) {
    throw new Error("orphan session container or source IP still owns an internal-network endpoint");
  }
  const receipt = Object.freeze({
    containerId: authority.containerId,
    networkId: binding.network.networkId,
    ...(authority.sourceIp === undefined ? {} : { sourceIp: authority.sourceIp }),
  }) as SessionContainerOrphanAbsenceReceipt;
  orphanAbsenceReceiptBindings.set(receipt, Object.freeze({ authority }));
  return receipt;
}

export function assertSessionContainerOrphanAbsenceReceipt(
  receipt: SessionContainerOrphanAbsenceReceipt,
  authority: SessionContainerOrphanCleanupAuthority,
): void {
  assertSessionContainerOrphanCleanupAuthority(authority);
  const binding = orphanAbsenceReceiptBindings.get(receipt);
  if (!binding) throw new Error("refusing an unsealed session-container orphan absence receipt");
  if (binding.authority !== authority
    || receipt.containerId !== authority.containerId
    || receipt.networkId !== authority.networkId
    || receipt.sourceIp !== authority.sourceIp) {
    throw new Error("session-container orphan absence receipt belongs to another cleanup authority");
  }
}

export function assertSessionContainerAbsenceReceipt(
  receipt: SessionContainerAbsenceReceipt,
  record: SessionContainerRecordV2,
  expectedProject: SessionContainerProjectIdentity,
  network: SessionContainerNetworkIdentity,
): void {
  assertSessionContainerRecordProject(record, expectedProject);
  const binding = absenceReceiptBindings.get(receipt);
  if (!binding) throw new Error("refusing an unsealed session-container absence receipt");
  if (serializeSessionContainerRecordV2(binding.record) !== serializeSessionContainerRecordV2(record)
    || binding.network.networkId !== network.networkId
    || binding.network.networkName !== network.networkName
    || binding.network.subnet !== network.subnet
    || receipt.containerId !== record.containerId
    || receipt.sourceIp !== record.sourceIp
    || receipt.networkId !== network.networkId) {
    throw new Error("session-container absence receipt belongs to a different lifecycle authority");
  }
}

export function removeAbsentSessionContainerRecordV2(
  stateDir: string,
  expectedProject: SessionContainerProjectIdentity,
  record: SessionContainerRecordV2,
  network: SessionContainerNetworkIdentity,
  absenceReceipt: SessionContainerAbsenceReceipt,
): boolean {
  assertSessionContainerAbsenceReceipt(absenceReceipt, record, expectedProject, network);
  return removeExactSessionContainerRecordV2(stateDir, expectedProject, record);
}
