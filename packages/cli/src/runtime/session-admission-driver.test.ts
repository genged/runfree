import { SessionReplacementPendingError } from "./session-admission-rebind-adoption.ts";
import { RuntimeObservationError } from "./observation-failure.ts";
import { beforeEach, describe, expect, test, vi, type Mock } from "vitest";

const mocks = vi.hoisted(() => ({
  events: [] as string[],
  /** Every `docker exec` payload this launch sent, in order, by effect label. */
  dockerInputs: [] as Array<{ label: string; input: string }>,
  failRunningProof: false,
  /** What `docker container inspect` answers; the session-file heartbeat reads it. */
  containerInspect: { status: 0, stdout: "[]", stderr: "" },
  /**
   * Docker answers scripted by effect label, for the effects a test needs to
   * fail. Anything unscripted succeeds, which is every existing test's world.
   * A list is played in order and its last entry repeats, so a step can be
   * failed once and then allowed.
   */
  effectAnswers: new Map<string, { status: number; stdout: string; stderr: string }[]>(),
  foregroundCompletion: { kind: "exit", code: 0, signal: null } as
    | { kind: "exit"; code: number | null; signal: string | null }
    | { kind: "error"; error: Error },
  readEffectiveControlPlane: vi.fn(),
  transitionAttached: vi.fn(),
  writeHostStatus: vi.fn(),
  readHostStatus: vi.fn(),
  removeHostStatus: vi.fn(),
  currentForegroundCompletion: vi.fn(),
  createSessionMetadata: vi.fn(),
  writeSessionMetadata: vi.fn(),
  markSessionInterrupted: vi.fn(),
  removeSessionMetadata: vi.fn(),
  builtinAgent: vi.fn(),
  hostBootId: vi.fn(),
  hostProcessStart: vi.fn(),
  recordedOnPreviousBoot: vi.fn(),
  compareHostBootId: vi.fn(),
  compareHostProcessStart: vi.fn(),
  processAlive: vi.fn(),
  transitionRevoking: vi.fn(),
  reconcileSessions: vi.fn(),
  createPreflight: vi.fn(),
  createAllocated: vi.fn(),
  createPlanFromPreflight: vi.fn(),
  createRetainedRebindPlan: vi.fn(),
  adoptRebind: vi.fn(),
  readRebindTransaction: vi.fn(),
  adoptForegroundRebind: vi.fn(),
  authorizeOrphan: vi.fn(),
  authorizeUnboundRecovery: vi.fn(),
  creationAuthorizedStop: vi.fn(),
  creationAuthorizedRemove: vi.fn(),
  cleanupCommand: vi.fn(),
  createContainer: vi.fn(),
  proveAbsent: vi.fn(),
  proveOrphanAbsent: vi.fn(),
  removeAbsent: vi.fn(),
  recoverUnboundRecord: vi.fn(),
  orphanStop: vi.fn(),
  orphanRemove: vi.fn(),
  executeDocker: vi.fn(),
  createCommand: vi.fn(),
  disconnectCommand: vi.fn(),
  attachCommand: vi.fn(),
  inspectCommand: vi.fn(),
  observedExited: vi.fn(),
  observedExitStatus: vi.fn(),
  removeCommand: vi.fn(),
  startCommand: vi.fn(),
  stopCommand: vi.fn(),
  networkInspectCommand: vi.fn(),
  authorizeProvisioning: vi.fn(),
  classify: vi.fn(),
  inventory: vi.fn(),
  waitRunning: vi.fn(),
  cancelForeground: vi.fn(),
  reattachForeground: vi.fn(),
  startForeground: vi.fn(),
  bindPlan: vi.fn(),
  bindAllocatedRecord: vi.fn(),
  bindExactAllocatedRecord: vi.fn(),
  listRecords: vi.fn(),
  listQuarantinedNames: vi.fn(),
  mintLease: vi.fn(),
  readRecord: vi.fn(),
  removeExactRecord: vi.fn(),
  replaceRecord: vi.fn(),
  serializeRecord: vi.fn(),
  transitionProvisioning: vi.fn(),
  writeRecord: vi.fn(),
  allocateIp: vi.fn(),
  createParticipantAuthority: vi.fn(),
  validateBaseline: vi.fn(),
  namedVolumeRequest: vi.fn(),
  validateNamedVolumes: vi.fn(),
  activeRuntimePlan: vi.fn(),
  createRuntimeDocker: vi.fn(),
  createSessionId: vi.fn(),
  consumePreparedRuntime: vi.fn(),
  compileMaterializationEligibility: vi.fn(),
}));

vi.mock("../agents.ts", () => ({ builtinAgent: mocks.builtinAgent }));
vi.mock("./host-identity.ts", () => ({
  hostBootId: mocks.hostBootId,
  hostProcessStart: mocks.hostProcessStart,
  processAlive: mocks.processAlive,
  // Reached through `session-record-liveness.ts`, which preflight consults to
  // tell a live session's record from a killed client's residue.
  recordedOnPreviousBoot: mocks.recordedOnPreviousBoot,
  compareHostBootId: mocks.compareHostBootId,
  compareHostProcessStart: mocks.compareHostProcessStart,
}));
vi.mock("./session-admission-driver-preflight.ts", () => ({
  createSessionAdmissionDriverPreflight: mocks.createPreflight,
  createAllocatedSessionContainerRecordFromPreflight: mocks.createAllocated,
  createSessionContainerCreatePlanFromPreflight: mocks.createPlanFromPreflight,
  createRetainedSessionRebindProofPlan: mocks.createRetainedRebindPlan,
}));
vi.mock("./session-admission-rebind-adoption.ts", async (importOriginal) => ({
  ...await importOriginal<typeof import("./session-admission-rebind-adoption.ts")>(),
  adoptCompatibleSessionControlPlaneRebind: mocks.adoptRebind,
}));
// Only the journal read is faked, so the real `assertNoPendingControlPlaneReplacement`
// and its real typed refusal run in every case below.
vi.mock("./control-plane-rebind.ts", async (importOriginal) => ({
  ...await importOriginal<typeof import("./control-plane-rebind.ts")>(),
  readControlPlaneRebindTransaction: mocks.readRebindTransaction,
}));
vi.mock("./session-container-cleanup.ts", () => ({
  authorizeSessionContainerOrphanCleanup: mocks.authorizeOrphan,
  authorizeUnboundCreatedSessionRecordRecovery: mocks.authorizeUnboundRecovery,
  creationAuthorizedSessionContainerStopCommand: mocks.creationAuthorizedStop,
  creationAuthorizedSessionContainerRemoveCommand: mocks.creationAuthorizedRemove,
  executeSessionContainerCleanupCommand: mocks.cleanupCommand,
  executeSessionContainerCreate: mocks.createContainer,
  proveSessionContainerAbsent: mocks.proveAbsent,
  proveSessionContainerOrphanAbsent: mocks.proveOrphanAbsent,
  removeAbsentSessionContainerRecordV2: mocks.removeAbsent,
  recoverUnboundCreatedSessionRecordV2: mocks.recoverUnboundRecord,
  orphanSessionContainerStopCommand: mocks.orphanStop,
  orphanSessionContainerRemoveCommand: mocks.orphanRemove,
}));
vi.mock("./session-container-docker.ts", () => ({
  executeSessionDockerCommand: mocks.executeDocker,
  sessionContainerAttachCommand: mocks.attachCommand,
  sessionContainerCreateCommand: mocks.createCommand,
  sessionContainerInspectCommand: mocks.inspectCommand,
  sessionContainerNetworkDisconnectCommand: mocks.disconnectCommand,
  sessionContainerObservedExited: mocks.observedExited,
  sessionContainerObservedExitStatus: mocks.observedExitStatus,
  sessionContainerRemoveCommand: mocks.removeCommand,
  sessionContainerStartAttachCommand: mocks.startCommand,
  sessionContainerStopCommand: mocks.stopCommand,
  sessionNetworkInspectCommand: mocks.networkInspectCommand,
}));
vi.mock("./session-container-lifecycle-authorization.ts", () => ({
  authorizeProvisioningRunningSessionContainer: mocks.authorizeProvisioning,
}));
vi.mock("./session-container-reconciliation.ts", () => ({
  classifySessionContainerReconciliation: mocks.classify,
  inspectSessionContainerInventory: mocks.inventory,
}));
vi.mock("./session-reconcile.ts", () => ({ reconcileSessions: mocks.reconcileSessions }));
vi.mock("./session-container-running-proof.ts", () => ({
  waitForRunningSessionContainerProof: mocks.waitRunning,
}));
vi.mock("./session-container-start.ts", () => ({
  adoptSessionContainerForegroundControlPlaneRebind: mocks.adoptForegroundRebind,
  cancelSessionContainerForegroundAttach: mocks.cancelForeground,
  currentSessionContainerForegroundCompletion: mocks.currentForegroundCompletion,
  reattachSessionContainerForeground: mocks.reattachForeground,
  startSessionContainerForeground: mocks.startForeground,
}));
// Only the durable read is replaced: the admission-source helpers the driver
// calls (`session-admission-source.ts`) stay real, so the mode and the
// host-flag contradiction check are decided by the same code that ships.
vi.mock("./component-state-v2.ts", async (importOriginal) => ({
  ...await importOriginal<typeof import("./component-state-v2.ts")>(),
  readEffectiveControlPlaneV2: mocks.readEffectiveControlPlane,
}));
vi.mock("./session-host-status.ts", () => ({
  writeSessionHostStatus: mocks.writeHostStatus,
  readSessionHostStatus: mocks.readHostStatus,
  removeSessionHostStatus: mocks.removeHostStatus,
}));
vi.mock("./session-container-template.ts", () => ({
  bindSessionContainerCreatePlanRecord: mocks.bindPlan,
}));
vi.mock("./session-containers.ts", () => ({
  bindAllocatedSessionContainerIdV2: mocks.bindAllocatedRecord,
  bindExactAllocatedSessionContainerRecordIdV2: mocks.bindExactAllocatedRecord,
  listQuarantinedSessionContainerRecordNamesV2: mocks.listQuarantinedNames,
  listSessionContainerRecordsV2: mocks.listRecords,
  mintSessionContainerLeaseV2: mocks.mintLease,
  readSessionContainerRecordV2: mocks.readRecord,
  removeExactSessionContainerRecordV2: mocks.removeExactRecord,
  replaceExactSessionContainerRecordV2: mocks.replaceRecord,
  serializeSessionContainerRecordV2: mocks.serializeRecord,
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2: mocks.transitionProvisioning,
  transitionProvisioningRunningSessionContainerToAttachedV2: mocks.transitionAttached,
  transitionSessionContainerToRevokingV2: mocks.transitionRevoking,
  writeSessionContainerRecordV2: mocks.writeRecord,
}));
vi.mock("./session-internal-network-baseline.ts", () => ({
  allocateSessionSourceIpFromExactInternalNetworkBaseline: mocks.allocateIp,
  createControlPlaneInternalParticipantAuthority: mocks.createParticipantAuthority,
  validateExactInternalNetworkParticipantBaseline: mocks.validateBaseline,
}));
vi.mock("./session-named-volume-proof.ts", () => ({
  sessionNamedVolumeInspectRequest: mocks.namedVolumeRequest,
  validateSessionNamedVolumeInspect: mocks.validateNamedVolumes,
}));
vi.mock("./prepared-runtime.ts", () => ({ consumePreparedRuntime: mocks.consumePreparedRuntime }));
vi.mock("./session-materialization-eligibility.ts", () => ({
  classifySessionAgentMaterializationEligibilityV2: mocks.compileMaterializationEligibility,
}));
vi.mock("./docker.ts", () => ({ createRuntimeDocker: mocks.createRuntimeDocker }));
vi.mock("./sessions.ts", () => ({
  SessionLockAcquisitionAbortedError: class SessionLockAcquisitionAbortedError extends Error {},
  // The one message-bearing lock error a test asserts on; the real class
  // builds exactly this line from the same two arguments.
  SessionLockAcquisitionTimeoutError: class SessionLockAcquisitionTimeoutError extends Error {
    constructor(lockPath: string, timeoutMs: number) {
      super(`timed out after ${timeoutMs}ms waiting to reacquire the project lifecycle lock (lock: ${lockPath})`);
      this.name = "SessionLockAcquisitionTimeoutError";
    }
  },
  createSessionId: mocks.createSessionId,
  processAlive: mocks.processAlive,
  createSessionMetadata: mocks.createSessionMetadata,
  writeSessionMetadata: mocks.writeSessionMetadata,
  markSessionInterrupted: mocks.markSessionInterrupted,
  removeSessionMetadata: mocks.removeSessionMetadata,
}));

import { parseSessionFileV1, SESSION_ELIGIBILITY_PATH, SESSION_FILES_DIR } from "@runfree/runtime-contracts/session-file";
import { SESSION_ADMISSION_LEASE_MAX_DURATION_MS } from "@runfree/runtime-contracts/session-registry";

import { createInternalSessionAdmissionDriver } from "./session-admission-driver.ts";
import { flushWarnings, setOutputWriterForTest } from "../warnings.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import {
  SessionLockAcquisitionTimeoutError,
  type ProjectLifecycleLock,
  type SessionLockManager,
} from "./sessions.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

const CONTAINER_ID = "c".repeat(64);
const NETWORK_ID = "d".repeat(64);
const PROXY_ID = "e".repeat(64);
const ENDPOINT_ID = "1".repeat(64);
const SESSION_PRINCIPAL = "b".repeat(64);
const SOURCE_IP = "172.31.90.20";
const DOCKER_PID = 4242;
const DOCKER_STARTED_AT = "2026-08-09T00:00:00.000000000Z";
const CONTROL_PLANE_DIGEST = `sha256:${"2".repeat(64)}`;
const AGENT_GENERATION_DIGEST = `sha256:${"3".repeat(64)}`;
const AGENT_IMAGE_ID = `sha256:${"4".repeat(64)}`;
const ADMISSION_CONTRACT_EPOCH = 1;

type FakeRecord = Readonly<{
  state: string;
  sessionId: string;
  sessionIncarnation: string;
  containerName: string;
  command: string;
  containerId?: string;
  [field: string]: unknown;
}>;

// The full v2 lifecycle shape, not a stub: the session-file heartbeat copies
// this record's own identity and eligibility fields into the bytes it writes,
// so a partial record could not produce a file the contract accepts.
function record(state: string, containerId?: string): FakeRecord {
  return Object.freeze({
    schemaVersion: 2,
    projectId: "0123456789ab",
    composeProject: "runfree-0123456789ab",
    state,
    sessionId: "rf-20260809-abcdef",
    sessionIncarnation: "a".repeat(64),
    sessionPrincipal: SESSION_PRINCIPAL,
    displayName: "Codex admission probe",
    containerName: "runfree-session-0123456789ab-rf-20260809-abcdef",
    command: "codex",
    launchPath: "/usr/local/bin/codex",
    launchArgs: [],
    interactive: true,
    tty: true,
    sourceIp: SOURCE_IP,
    selectedAgentImageRef: "runfree-agent-0123456789ab:local",
    selectedAgentImageId: AGENT_IMAGE_ID,
    sessionAgentMaterializationDigest: `sha256:${"5".repeat(64)}`,
    selectedAgentImageInputDigest: `sha256:${"6".repeat(64)}`,
    sessionTemplateDigest: `sha256:${"7".repeat(64)}`,
    sessionAgentGenerationDigest: AGENT_GENERATION_DIGEST,
    controlPlaneGenerationDigest: CONTROL_PLANE_DIGEST,
    admissionContractEpoch: ADMISSION_CONTRACT_EPOCH,
    hostPid: 321,
    createdAt: "2026-08-09T00:00:00.000Z",
    ...(containerId ? { containerId } : {}),
  });
}

/**
 * One `docker container inspect` answer.
 *
 * With no argument it proves the anchored incarnation; `state` overrides the
 * running state so a test can produce an exact narrow-inspection verdict
 * (a stopped container, a drifted process id) instead of asserting on a
 * hand-written message.
 */
function runningInspect(state: Record<string, unknown> = {}): string {
  return JSON.stringify([{
    Id: CONTAINER_ID,
    State: {
      Running: true,
      Status: "running",
      Dead: false,
      Paused: false,
      Restarting: false,
      OOMKilled: false,
      Error: "",
      ExitCode: 0,
      Pid: DOCKER_PID,
      StartedAt: DOCKER_STARTED_AT,
      ...state,
    },
    NetworkSettings: {
      Networks: {
        "runfree-0123456789ab_agent_internal": {
          NetworkID: NETWORK_ID,
          IPAddress: SOURCE_IP,
          GlobalIPv6Address: "",
          EndpointID: ENDPOINT_ID,
        },
      },
    },
  }]);
}

/**
 * The compact label for one captured Docker effect.
 *
 * Session-file commands run as a pinned `docker exec ... node -e <script>
 * <path> [sha256]`, whose argv is thousands of characters of inlined script.
 * They are named by what they do to which file instead, so the effect list
 * stays readable and a write can never be mistaken for a delete.
 */
function effectLabel(args: readonly string[]): string {
  const scriptIndex = args.indexOf("-e");
  if (args[0] !== "exec" || scriptIndex < 0) return `docker:${args.join(" ")}`;
  const target = args[scriptIndex + 2] ?? "";
  if (target === "/run/runfree-sessions/ip-reuse") return args.includes("flock") ? "session-file:ip-reuse-fence" : "session-file:read-ip-assignment";
  if (target === SESSION_ELIGIBILITY_PATH) return "session-file:publish-eligibility";
  if (!target.startsWith(`${SESSION_FILES_DIR}/`)) return `session-file:unknown ${target}`;
  return args.length > scriptIndex + 3 ? "session-file:write" : "session-file:delete";
}

function planFor(recordValue: FakeRecord) {
  return Object.freeze({ record: recordValue, expectedProject: { projectId: "0123456789ab", composeProject: "runfree-0123456789ab" } });
}

function ordered(name: string) {
  return (..._args: unknown[]) => {
    mocks.events.push(name);
  };
}

/** The durable effective control plane this project's proxy was started from. */
let effectiveControlPlane: {
  selection: Record<string, unknown>;
  manifest: Record<string, unknown>;
};

beforeEach(() => {
  vi.clearAllMocks();
  mocks.events.length = 0;
  mocks.dockerInputs.length = 0;
  mocks.failRunningProof = false;
  mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
  mocks.effectAnswers.clear();
  const allocated = record("allocated");
  const bound = record("allocated", CONTAINER_ID);
  const provisioning = record("provisioning-running", CONTAINER_ID);
  const expectedProject = { projectId: "0123456789ab", composeProject: "runfree-0123456789ab" };
  const selection = {
    ...expectedProject,
    proxyContainerId: PROXY_ID,
    networkIds: { agentInternal: NETWORK_ID },
    controlPlaneGenerationDigest: CONTROL_PLANE_DIGEST,
    admissionContractEpoch: ADMISSION_CONTRACT_EPOCH,
  };
  const preflight = {
    expectedProject,
    effectiveControlPlane: selection,
    generationTarget: { controlPlane: { controlPlaneTopologyDigest: "sha256:topology" } },
    sessionAgentMaterialization: { sessionAgentMaterializationDigest: "sha256:test" },
    liveProbe: { asset: true },
  };
  const baseline = {
    ...expectedProject,
    controlPlaneGenerationDigest: "sha256:generation",
    admissionContractEpoch: 1,
    networkId: NETWORK_ID,
    networkName: `${expectedProject.composeProject}_agent_internal`,
    subnet: "172.31.90.0/24",
    participants: [],
    ingressParticipants: [],
  };

  mocks.builtinAgent.mockReturnValue({ id: "codex", label: "Codex", defaultCommand: "codex" });
  effectiveControlPlane = {
    selection,
    manifest: {
      ...expectedProject,
      sessionAdmissionSource: "files",
      generation: { controlPlaneGenerationDigest: CONTROL_PLANE_DIGEST },
    },
  };
  mocks.readEffectiveControlPlane.mockImplementation(() => effectiveControlPlane);
  mocks.transitionAttached.mockImplementation((value: FakeRecord) => ({ ...value, state: "attached" }));
  // The terminal stamp is the marker teardown writes in place of a `revoking`
  // record under the file source, so it is named apart from a heartbeat stamp.
  mocks.writeHostStatus.mockImplementation((_stateDir: string, status: { terminal?: string }) => {
    mocks.events.push(status.terminal === "revoking" ? "stamp-revoking" : "write-host-status");
  });
  mocks.readHostStatus.mockReturnValue(undefined);
  mocks.removeHostStatus.mockImplementation(ordered("clear-host-status"));
  mocks.currentForegroundCompletion.mockReturnValue(undefined);
  // Default: no rebind is journaled, no compatible rebind happened while the
  // session ran, and the held control plane is still the durable effective
  // selection.
  mocks.readRebindTransaction.mockReturnValue(undefined);
  mocks.adoptRebind.mockReturnValue(undefined);
  mocks.hostBootId.mockReturnValue("linux:00000000-0000-0000-0000-000000000000");
  mocks.hostProcessStart.mockReturnValue("linux:1");
  // Owner identity defaults to a live owner, so no case reclaims a record
  // unless it says so. A test that wants residue proves the previous boot,
  // which settles ownership without consulting a PID.
  mocks.recordedOnPreviousBoot.mockReturnValue(false);
  mocks.compareHostBootId.mockReturnValue("match");
  mocks.compareHostProcessStart.mockReturnValue("match");
  mocks.processAlive.mockReturnValue(true);
  mocks.transitionRevoking.mockImplementation((value: FakeRecord) => ({ ...value, state: "revoking" }));
  // The record is dropped by its exact identity rather than against an absence
  // receipt, so the removal is observable in the event stream.
  mocks.removeExactRecord.mockImplementation((_stateDir: string, _project: unknown, target: FakeRecord) => {
    mocks.events.push(`remove-exact-record:${target.sessionId}`);
    return true;
  });
  mocks.createRuntimeDocker.mockReturnValue({});
  mocks.createPreflight.mockImplementation(() => {
    mocks.events.push("preflight");
    return preflight;
  });
  mocks.compileMaterializationEligibility.mockImplementation((input) => ({
    allowed: [input.candidate],
    invalidRecords: [],
  }));
  mocks.createParticipantAuthority.mockImplementation(() => {
    mocks.events.push("participant-authority");
    return baseline;
  });
  // The whole recovery region is one reconcile.
  mocks.reconcileSessions.mockImplementation(async () => {
    mocks.events.push("reconcile-sessions");
    return {
      orphanFilesDeleted: [],
      deadOwnersRevoked: [],
      orphanContainersRemoved: [],
      unknownOwners: [],
      reservedSourceIps: [],
      orphanFiles: [],
      recordsWithoutFiles: [],
    };
  });
  mocks.listRecords.mockReturnValue([]);
  mocks.listQuarantinedNames.mockReturnValue([]);
  mocks.inventory.mockReturnValue([]);
  mocks.classify.mockReturnValue([]);
  mocks.networkInspectCommand.mockReturnValue({ executable: "docker", args: ["network", "inspect", NETWORK_ID] });
  mocks.inspectCommand.mockReturnValue({ executable: "docker", args: ["container", "inspect", CONTAINER_ID] });
  // Default: the pre-stop inspection does NOT prove the container exited, so
  // every existing teardown expectation keeps the SIGTERM+grace stop path,
  // and no inspection carries a proved exit status.
  mocks.observedExited.mockReturnValue(false);
  mocks.observedExitStatus.mockReturnValue(undefined);
  mocks.attachCommand.mockReturnValue({
    executable: "docker",
    args: ["container", "attach", CONTAINER_ID],
    effect: "attach-session-container",
    exactTarget: CONTAINER_ID,
  });
  mocks.executeDocker.mockImplementation((command, execute) => execute(command.executable, command.args));
  mocks.validateBaseline.mockImplementation(() => {
    mocks.events.push("baseline");
    return baseline;
  });
  mocks.allocateIp.mockReturnValue("172.31.90.20");
  mocks.createSessionId.mockReturnValue(allocated.sessionId);
  mocks.createAllocated.mockImplementation(() => {
    mocks.events.push("allocate");
    return allocated;
  });
  mocks.writeRecord.mockImplementation(ordered("write-allocated"));
  mocks.createPlanFromPreflight.mockReturnValue(planFor(allocated));
  mocks.namedVolumeRequest.mockReturnValue({ executable: "docker", args: ["volume", "inspect", "state"] });
  mocks.validateNamedVolumes.mockReturnValue({ volume: true });
  mocks.createCommand.mockReturnValue({ executable: "docker", args: ["container", "create"] });
  mocks.createContainer.mockImplementation((_command, _plan, execute) => {
    mocks.events.push("create");
    execute("docker", ["container", "create"]);
    return { containerId: CONTAINER_ID, receipt: { containerId: CONTAINER_ID } };
  });
  mocks.bindAllocatedRecord.mockReturnValue(bound);
  mocks.bindPlan.mockImplementation((_plan, next) => planFor(next));
  mocks.bindExactAllocatedRecord.mockImplementation(() => {
    mocks.events.push("bind-container-id");
    return bound;
  });
  mocks.mintLease.mockReturnValue({ admittedAt: "2026-08-09T00:00:00.000Z", leaseGeneration: "f".repeat(64), leaseExpiresAt: "2026-08-09T00:05:00.000Z" });
  mocks.replaceRecord.mockImplementation(ordered("replace-record"));
  mocks.startCommand.mockReturnValue({ executable: "docker", args: ["container", "start", CONTAINER_ID] });
  mocks.foregroundCompletion = { kind: "exit", code: 0, signal: null };
  mocks.startForeground.mockImplementation(async (_command, _record, _project, options) => {
    mocks.events.push("start-foreground");
    options.spawn("docker", ["container", "start", CONTAINER_ID], { shell: false, stdio: "inherit", env: {} });
    return {
      receipt: { containerId: CONTAINER_ID },
      containerId: CONTAINER_ID,
      pid: 123,
      completion: Promise.resolve(mocks.foregroundCompletion),
    };
  });
  mocks.createSessionMetadata.mockImplementation((_context, _io, command, agentCommand, options) => {
    mocks.events.push("create-session-evidence");
    return { id: options?.id ?? "rf-20260809-abcdef", command, agentCommand, ...options };
  });
  mocks.writeSessionMetadata.mockImplementation(ordered("write-session-evidence"));
  mocks.markSessionInterrupted.mockImplementation(ordered("mark-session-interrupted"));
  mocks.removeSessionMetadata.mockImplementation(ordered("remove-session-evidence"));
  mocks.transitionProvisioning.mockReturnValue(provisioning);
  mocks.waitRunning.mockImplementation(async () => {
    mocks.events.push("running-proof");
    // The full proof already carries the mutable running identity every later
    // beat re-proves, so the session-file anchor is a projection of it.
    return {
      running: true,
      containerId: CONTAINER_ID,
      networkId: NETWORK_ID,
      sourceIp: SOURCE_IP,
      dockerPid: DOCKER_PID,
      dockerStartedAt: DOCKER_STARTED_AT,
      networkEndpointId: ENDPOINT_ID,
    };
  });
  mocks.serializeRecord.mockImplementation((value) => JSON.stringify(value));
  mocks.readRecord.mockImplementation(() => provisioning);
  mocks.authorizeProvisioning.mockImplementation(() => {
    mocks.events.push("authorize-running");
    if (mocks.failRunningProof) throw new Error("running proof failed closed");
    return { record: provisioning };
  });
  for (const [mock, effect] of [
    [mocks.disconnectCommand, "disconnect"],
    [mocks.stopCommand, "stop"],
    [mocks.removeCommand, "remove"],
  ] as const) {
    mock.mockImplementation(() => ({ executable: "docker", args: [effect] }));
  }
  mocks.creationAuthorizedStop.mockReturnValue({
    executable: "docker",
    args: ["container", "stop", "--time", "10", CONTAINER_ID],
  });
  mocks.creationAuthorizedRemove.mockReturnValue({
    executable: "docker",
    args: ["container", "rm", CONTAINER_ID],
  });
  mocks.proveAbsent.mockImplementation((_execute, target) => {
    mocks.events.push("prove-absent");
    mocks.events.push(`prove-absent:${target.sessionId}`);
    return { absent: true };
  });
  mocks.removeAbsent.mockImplementation((_stateDir, _project, target) => {
    mocks.events.push("remove-record");
    mocks.events.push(`remove-record:${target.sessionId}`);
    return true;
  });
  mocks.cancelForeground.mockReturnValue(true);
  mocks.authorizeUnboundRecovery.mockImplementation(() => {
    mocks.events.push("authorize-unbound-recovery");
    return { recovery: true };
  });
  mocks.recoverUnboundRecord.mockImplementation(() => {
    mocks.events.push("recover-unbound-record");
    return true;
  });
  mocks.authorizeOrphan.mockImplementation(() => {
    mocks.events.push("authorize-container-only");
    return { orphan: true };
  });
  mocks.orphanRemove.mockReturnValue({ executable: "docker", args: ["container", "rm", CONTAINER_ID] });
  mocks.cleanupCommand.mockImplementation((command, execute) => execute(command.executable, command.args));
  mocks.proveOrphanAbsent.mockImplementation(ordered("prove-orphan-absent"));
});

function fixture() {
  let held = true;
  const lifecycleLock: ProjectLifecycleLock = {
    ownerToken: "owner",
    assertHeld: vi.fn(() => {
      if (!held) throw new Error("test lifecycle lock is not held");
    }),
    release: vi.fn(() => { held = false; }),
  };
  const sessionLockManager: SessionLockManager = {
    lock: lifecycleLock,
    releaseForWait: vi.fn(() => {
      lifecycleLock.assertHeld();
      held = false;
    }),
    withLock: vi.fn(async (operation) => {
      held = true;
      try {
        const value = await operation();
        held = false;
        return value;
      } catch (error) {
        // The real manager retains the lock after a failed renewal so this
        // driver's compensated record cannot be consumed by a peer drain.
        throw error;
      }
    }),
    reacquire: vi.fn(async () => { held = true; }),
    close: vi.fn(() => { held = false; }),
  };
  const io: RuntimeIO = {
    capture: vi.fn((_command, args, options) => {
      const label = effectLabel(args);
      mocks.events.push(label);
      const input = (options as { input?: unknown } | undefined)?.input;
      if (typeof input === "string") mocks.dockerInputs.push({ label, input });
      const scripted = mocks.effectAnswers.get(label);
      if (scripted && scripted.length > 0) {
        return { ...(scripted.length > 1 ? scripted.shift() : scripted[0]) } as ReturnType<RuntimeIO["capture"]>;
      }
      if (label === "session-file:read-ip-assignment") return { status: 0, stdout: "-", stderr: "" };
      if (args[0] === "container" && args[1] === "inspect") return { ...mocks.containerInspect };
      return { status: 0, stdout: "[]", stderr: "" };
    }),
    run: vi.fn(() => 0),
    commandExists: vi.fn(() => true),
    confirm: vi.fn(() => true),
    admin: vi.fn(async () => 0),
  };
  const foregroundSpawner = vi.fn(() => ({
    pid: 123,
    exitCode: null,
    signalCode: null,
    once: vi.fn(),
    kill: vi.fn(() => true),
  }));
  const plan = {
    paths: { stateDir: "/state" },
    execution: { dockerClientEnv: {} },
    network: { proxyIp: "172.31.90.10" },
  } as unknown as ActiveRuntimePlan;
  // A real (unmocked) config layer resolves the launch command from this, so
  // launch-mode tests exercise the actual normalization path. No `codex` entry
  // means "not customized", which resolves to the builtin default.
  const context = { env: {}, project: { config: { agents: { default: "codex" } } } } as unknown as RuntimeContext;
  const preparedRuntime = Object.freeze({ version: 1 }) as never;
  mocks.consumePreparedRuntime.mockReturnValue({ plan, context });
  return { sessionLockManager, io, foregroundSpawner, preparedRuntime, context };
}

function orderedSessionLockManager(base: SessionLockManager): SessionLockManager {
  return {
    lock: base.lock,
    releaseForWait: vi.fn(() => {
      mocks.events.push("release-attached-lock");
      base.releaseForWait();
    }),
    withLock: async <T>(
      operation: () => Promise<T>,
      signal: AbortSignal,
    ): Promise<T> => {
      mocks.events.push("acquire-renewal-lock");
      try {
        const value = await base.withLock(operation, signal);
        mocks.events.push("release-renewal-lock");
        return value;
      } catch (error) {
        mocks.events.push("retain-renewal-lock");
        throw error;
      }
    },
    reacquire: vi.fn(async () => {
      mocks.events.push("reacquire-teardown-lock");
      await base.reacquire();
    }),
    close: vi.fn(() => base.close()),
  };
}

describe("internal session admission driver", () => {
  test("rejects a bare lifecycle lock instead of accepting an unmanaged foreground path", () => {
    const input = fixture();

    expect(() => createInternalSessionAdmissionDriver({
      preparedRuntime: input.preparedRuntime,
      lifecycleLock: input.sessionLockManager.lock,
      io: input.io,
    } as never)).toThrow("session admission requires a SessionLockManager");

    expect(mocks.consumePreparedRuntime).not.toHaveBeenCalled();
    expect(mocks.events).toEqual([]);
  });

  test("reconciles pending admission without allocating, starting, or activating a session", async () => {
    const input = fixture();
    const driver = createInternalSessionAdmissionDriver(input);

    await driver.recoverPending("codex");

    expect(mocks.events).toEqual(expect.arrayContaining([
      "preflight",
      "participant-authority",
      "reconcile-sessions",
      "baseline",
    ]));
    for (const forbidden of ["allocate", "create", "start-foreground", "session-file:write"]) {
      expect(mocks.events).not.toContain(forbidden);
    }
  });

  test("derives a built-in probe, proves the complete sequence, never grants it, and tears it down", async () => {
    const input = fixture();
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    const metrics = await driver.probeBuiltin("codex");

    expect(metrics.agent).toBe("codex");
    expect(metrics.dockerOperations).toBeGreaterThanOrEqual(0);
    expect(mocks.events).toEqual(expect.arrayContaining([
      "preflight",
      "participant-authority",
      "reconcile-sessions",
      "baseline",
      "allocate",
      "create",
      "bind-container-id",
      "replace-record",
      "start-foreground",
      "running-proof",
      "authorize-running",
      "stamp-revoking",
      "session-file:delete",
      "remove-exact-record:rf-20260809-abcdef",
      "clear-host-status",
    ]));
    expect(mocks.events.indexOf("start-foreground"))
      .toBeLessThan(mocks.events.indexOf("running-proof"));
    expect(mocks.events.indexOf("authorize-running"))
      .toBeLessThan(mocks.events.indexOf("stamp-revoking"));
    // A probe is never granted: it writes no session file, so nothing the
    // proxy serves ever names it.
    expect(mocks.events).not.toContain("session-file:write");
  });

  // Regression from the first live run of the file source: with the pre-file
  // `register` gone, the running proof is the first observation taken after
  // `docker start --attach` is issued, so the window it waits is the whole
  // budget the container has to reach Docker's running state. The driver has
  // to name that window; inheriting the helper's short fallback turns an
  // ordinarily busy daemon into "did not reach Docker running state before
  // timeout". Widening it admits nothing earlier — the proof's assertions are
  // unchanged and no session is authorized until it returns.
  test("waits the running proof's full window rather than the helper's fallback", async () => {
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await driver.probeBuiltin("codex");

    expect(mocks.waitRunning).toHaveBeenCalledTimes(1);
    expect(mocks.waitRunning.mock.calls[0]?.[3]).toMatchObject({ timeoutMs: 30_000 });
  });

  // A running proof that fails closed happens before the session file is
  // written, so nothing could be serving this session yet: the ladder answers
  // with the unadmitted cleanup — exact creation authority, no `--force`, no
  // network disconnect — rather than the ordered file-first teardown.
  test("cleans an unadmitted session up under exact creation authority when the running proof fails", async () => {
    mocks.failRunningProof = true;
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await expect(driver.probeBuiltin("codex")).rejects.toThrow("running proof failed closed");

    expect(mocks.events).toEqual(expect.arrayContaining([
      `docker:container stop --time 10 ${CONTAINER_ID}`,
      `docker:container rm ${CONTAINER_ID}`,
      "prove-absent",
      "remove-record",
    ]));
    expect(mocks.events).not.toContain("docker:disconnect");
    expect(mocks.creationAuthorizedStop).toHaveBeenCalledTimes(1);
    expect(mocks.creationAuthorizedRemove).toHaveBeenCalledTimes(1);
    expect(mocks.cancelForeground).toHaveBeenCalledTimes(1);
    // Nothing was ever granted, so no file is written and no terminal stamp is
    // spent taking one back.
    expect(mocks.events).not.toContain("session-file:write");
    expect(mocks.events).not.toContain("stamp-revoking");
  });

  test("retains the durable record when the unadmitted cleanup itself fails", async () => {
    mocks.failRunningProof = true;
    mocks.proveAbsent.mockImplementation(() => {
      mocks.events.push("prove-absent");
      throw new Error("absence could not be proven");
    });
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await expect(driver.probeBuiltin("codex")).rejects.toThrow("fail-closed cleanup also failed");

    expect(mocks.events).toEqual(expect.arrayContaining([
      `docker:container stop --time 10 ${CONTAINER_ID}`,
      `docker:container rm ${CONTAINER_ID}`,
      "prove-absent",
    ]));
    expect(mocks.removeAbsent).not.toHaveBeenCalled();
    expect(mocks.removeExactRecord).not.toHaveBeenCalled();
  });

  test("rejects a concurrent probe before a second lifecycle or Docker effect", async () => {
    let releaseRecovery: (() => void) | undefined;
    const reconciled = mocks.reconcileSessions.getMockImplementation();
    mocks.reconcileSessions.mockImplementationOnce(async (input: never) => {
      mocks.events.push("recover-paused");
      await new Promise<void>((resolve) => {
        releaseRecovery = resolve;
      });
      return reconciled?.(input);
    });
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });
    const first = driver.probeBuiltin("codex");
    await vi.waitFor(() => expect(mocks.events).toContain("recover-paused"));
    const effectsBeforeSecond = [...mocks.events];

    await expect(driver.probeBuiltin("codex")).rejects.toThrow("already in flight");
    expect(mocks.events).toEqual(effectsBeforeSecond);

    releaseRecovery?.();
    await expect(first).resolves.toMatchObject({ agent: "codex" });
  });

  test("recovers create-output loss record-first, then re-inventories before orphan cleanup", async () => {
    const allocated = record("allocated");
    const container = Object.freeze({ containerId: CONTAINER_ID, running: false });
    mocks.listRecords
      .mockReturnValueOnce([allocated])
      .mockReturnValueOnce([])
      .mockReturnValueOnce([])
      .mockReturnValueOnce([]);
    mocks.classify
      .mockReturnValueOnce([{ kind: "unbound-created", record: allocated, container }])
      .mockReturnValueOnce([{
        kind: "container-only",
        container,
        identity: { sessionId: allocated.sessionId, sessionIncarnation: allocated.sessionIncarnation },
      }])
      .mockReturnValueOnce([]);
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await driver.probeBuiltin("codex");

    expect(mocks.events.indexOf("recover-unbound-record"))
      .toBeLessThan(mocks.events.indexOf("authorize-container-only"));
    expect(mocks.inventory).toHaveBeenCalledTimes(3);
    expect(mocks.events).toContain("prove-orphan-absent");
  });

  // Replaces "fails closed on an ordinary preexisting lifecycle record":
  // refusing every surviving record was a placeholder for two answers it could
  // not tell apart, and it is wrong for both. A live record belongs to another
  // session — concurrent sessions being the point of per-session admission —
  // and residue must be reclaimable or one killed client denies the project
  // every future session.
  test("admits a session beside a record whose owner is still running", async () => {
    const existing = record("attached", CONTAINER_ID);
    mocks.listRecords.mockReturnValue([existing]);
    mocks.classify.mockReturnValue([{ kind: "record-only", record: existing }]);
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await driver.probeBuiltin("codex");

    expect(mocks.events).toContain("allocate");
    // Left exactly as found: not revoked, not torn down.
    expect(mocks.transitionRevoking).not.toHaveBeenCalled();
    expect(mocks.replaceRecord).not.toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      existing,
      expect.objectContaining({ state: "revoking" }),
    );
  });

  // `revoking` is terminal in the state machine, so re-marking it is an illegal
  // transition, and the record is already the drain's business: it is the exact
  // unjournaled cue the residual path recognises. Reclamation must step over it
  // rather than act on it — and if the drain then fails to clear it, admission
  // must still refuse, because that state is teardown in progress rather than a
  // session to allocate beside.
  //
  // Both owner verdicts are covered on purpose. A live owner there is a process
  // mid-teardown, not a concurrent session, so ownership must not rescue the
  // record: judging it by liveness alone let exactly this case through.
  test.each([
    ["a departed owner", true],
    ["an owner that still reads live", false],
  ])("refuses a surviving revoking record with %s", async (_label, ownerGone) => {
    const revokingRecord = record("revoking", CONTAINER_ID);
    mocks.recordedOnPreviousBoot.mockReturnValue(ownerGone);
    mocks.listRecords.mockReturnValue([revokingRecord]);
    mocks.classify.mockReturnValue([{ kind: "record-only", record: revokingRecord }]);
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await expect(driver.probeBuiltin("codex")).rejects.toThrow("reconciliation did not clear");

    expect(mocks.transitionRevoking).not.toHaveBeenCalled();
    expect(mocks.events).not.toContain("allocate");
    expect(mocks.createContainer).not.toHaveBeenCalled();
  });

  test("refuses when a stale record survives its own reclamation", async () => {
    // The reclaim above is registry-first and the drain that follows is what
    // clears it. A record that is still stale afterwards means neither did what
    // it claimed, and admitting beside it would build on unaccounted state.
    const abandoned = record("attached", CONTAINER_ID);
    mocks.recordedOnPreviousBoot.mockReturnValue(true);
    mocks.transitionRevoking.mockImplementation((value: FakeRecord) => value);
    mocks.listRecords.mockReturnValue([abandoned]);
    mocks.classify.mockReturnValue([{ kind: "record-only", record: abandoned }]);
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await expect(driver.probeBuiltin("codex")).rejects.toThrow("reconciliation did not clear");

    expect(mocks.events).not.toContain("allocate");
    expect(mocks.createContainer).not.toHaveBeenCalled();
  });

  // The recovery region below ends dead owners' records and republishes
  // eligibility — exactly the state a journaled control-plane rebind is in the
  // middle of moving. Reconciling around the journal would remove records the
  // rebind still has to rebind, and its own recovery would then fail on state
  // that is no longer there. The refusal lands before the first effect, and the
  // journal's disappearance is all it takes for the same launch to proceed.
  test("refuses a launch under a journaled control-plane rebind, before any effect", async () => {
    mocks.readRebindTransaction.mockReturnValue({
      transactionId: "t".repeat(64),
      phase: "records-rebound",
      oldRecords: [],
      replacementRecords: [],
    });
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    // One refusal, read once: it names the phase and both of its reclamations
    // (output contract D4).
    const refusal = await driver.launchBuiltin("codex").then(
      () => undefined,
      (error: unknown) => error as Error,
    );
    expect(refusal?.message).toContain("a control-plane rebind is pending at records-rebound");
    expect(refusal?.message).toContain("run `runfree up` to resume it");
    expect(refusal?.message).toContain("`runfree destroy --force` to clear a stuck one");

    // Nothing was reconciled, torn down, allocated, or created: the whole
    // recovery region is behind the refusal.
    expect(mocks.reconcileSessions).not.toHaveBeenCalled();
    expect(mocks.events).not.toContain("reconcile-sessions");
    expect(mocks.events).not.toContain("allocate");
    expect(mocks.events).not.toContain("stamp-revoking");
    expect(mocks.events.filter((event) => event.startsWith("docker:"))).toEqual([]);
    expect(mocks.removeExactRecord).not.toHaveBeenCalled();
    expect(mocks.writeRecord).not.toHaveBeenCalled();
    expect(mocks.createContainer).not.toHaveBeenCalled();
  });

  test("a launch proceeds unchanged once the journal is gone", async () => {
    mocks.readRebindTransaction.mockReturnValueOnce({
      transactionId: "t".repeat(64),
      phase: "records-rebound",
      oldRecords: [],
      replacementRecords: [],
    });
    const refused = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });
    await expect(refused.launchBuiltin("codex")).rejects.toThrow("rebind is pending");

    // The reclamation: the rebind completed (or was cleared), so the next
    // launch runs the ordinary sequence with nothing skipped.
    mocks.events.length = 0;
    const proceeding = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await expect(proceeding.launchBuiltin("codex")).resolves.toEqual({ status: 0, signal: null });

    expect(mocks.events.indexOf("reconcile-sessions")).toBeLessThan(mocks.events.indexOf("allocate"));
    expect(mocks.events).toContain("session-file:write");
  });

  test.each([false, true])("launch beside a verified ingress forwarder rechecks inventory identity (drift=%s)", async (drift) => {
    const participant = {
      containerId: "f".repeat(64),
      containerName: "runfree-ingress-port-0123456789ab-3000",
      sourceIp: "172.31.90.20",
      imageId: `sha256:${"e".repeat(64)}`,
    };
    mocks.createParticipantAuthority.mockReturnValue({
      networkId: NETWORK_ID,
      networkName: "runfree-0123456789ab_agent_internal",
      subnet: "172.31.90.0/24",
      ingressParticipants: [participant],
    });
    mocks.classify.mockReturnValue([{
      kind: "untrusted-container",
      container: { ...participant, running: true, internalNetworkId: NETWORK_ID,
        imageId: drift ? `sha256:${"a".repeat(64)}` : participant.imageId },
      reason: "container lacks exact Runfree session identity proof",
    }]);
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });
    if (drift) {
      await expect(driver.launchBuiltin("codex")).rejects.toThrow("untrusted-container");
      expect(mocks.events).not.toContain("allocate");
      expect(mocks.events).not.toContain("session-file:write");
      expect(mocks.createContainer).not.toHaveBeenCalled();
    } else {
      await expect(driver.launchBuiltin("codex")).resolves.toEqual({ status: 0, signal: null });
      expect(mocks.events).toContain("session-file:write");
    }
    expect(mocks.authorizeOrphan).not.toHaveBeenCalled();
  });

  test("refuses admission while quarantined unreadable records exist, before orphan cleanup", async () => {
    // The container a quarantined record named is claimed by no readable
    // record, so letting preflight continue would hand it to orphan cleanup as
    // container-only. The refusal must land after the drains (so readable
    // stale records still reclaim) and before any orphan authorization.
    mocks.listQuarantinedNames.mockReturnValue(["rf-20260814-zz9999.json"]);
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await expect(driver.probeBuiltin("codex")).rejects.toThrow(
      /quarantined unreadable lifecycle record.*rf-20260814-zz9999\.json.*destroy --force/s,
    );

    expect(mocks.reconcileSessions).toHaveBeenCalled();
    expect(mocks.authorizeOrphan).not.toHaveBeenCalled();
    expect(mocks.events).not.toContain("allocate");
    expect(mocks.createContainer).not.toHaveBeenCalled();
  });

  test("launch writes session evidence before the foreground start and consumes it on a clean exit", async () => {
    const agentCommand = "codex -c check_for_update_on_startup=false --dangerously-bypass-approvals-and-sandbox";
    mocks.builtinAgent.mockReturnValue({ id: "codex", label: "Codex", defaultCommand: agentCommand });
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    const outcome = await driver.launchBuiltin("codex");

    expect(outcome).toEqual({ status: 0, signal: null });
    expect(mocks.events.indexOf("write-session-evidence"))
      .toBeLessThan(mocks.events.indexOf("start-foreground"));
    expect(mocks.events.indexOf("authorize-running"))
      .toBeLessThan(mocks.events.indexOf("session-file:write"));
    expect(mocks.events.indexOf("session-file:write"))
      .toBeLessThan(mocks.events.indexOf("stamp-revoking"));
    expect(mocks.events).toContain("remove-session-evidence");
    expect(mocks.markSessionInterrupted).not.toHaveBeenCalled();
    expect(mocks.createAllocated).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ command: "codex" }),
    );
    // Evidence is keyed to the lifecycle record's session id and names the
    // exact container, so recovery classification can consult the registry.
    expect(mocks.createSessionMetadata).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      "codex",
      agentCommand,
      expect.objectContaining({
        id: "rf-20260809-abcdef",
        sessionContainerName: "runfree-session-0123456789ab-rf-20260809-abcdef",
      }),
    );
  });

  // A teardown the proxy blocks is the owner's failure to report, and it must
  // not be confused with the agent's own exit: the process ended cleanly, so
  // its session evidence is consumed rather than preserved as interrupted.
  test("a blocked teardown is reported without preserving the clean exit as interrupted", async () => {
    mocks.effectAnswers.set("session-file:delete", [
      { status: 1, stdout: "", stderr: "proxy exec failed" },
      { status: 1, stdout: "", stderr: "proxy exec failed" },
    ]);
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    const failure = await driver.launchBuiltin("codex").catch((error: unknown) => error);
    const messages = (value: unknown): string[] => (value instanceof AggregateError
      ? [value.message, ...value.errors.flatMap(messages)]
      : [String(value)]);
    expect(messages(failure).join("\n")).toContain("observation-unavailable during delete-session-file");

    expect(mocks.removeSessionMetadata).toHaveBeenCalled();
    expect(mocks.markSessionInterrupted).not.toHaveBeenCalled();
    // The record outlives the blocked delete: nothing may release this
    // session's address while the proxy may still be serving its file.
    expect(mocks.removeExactRecord).not.toHaveBeenCalled();
  });

  test("teardown lock timeout still finalizes clean host session evidence", async () => {
    const input = fixture();
    const baseManager = input.sessionLockManager;
    const sessionLockManager: SessionLockManager = {
      ...baseManager,
      reacquire: vi.fn(async () => {
        throw new Error("timed out waiting for teardown lock after the lease window");
      }),
    };
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      sessionLockManager,
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await expect(driver.launchBuiltin("codex")).rejects.toThrow(
      "session admission probe failed and fail-closed cleanup also failed",
    );

    expect(mocks.removeSessionMetadata).toHaveBeenCalledOnce();
    expect(mocks.markSessionInterrupted).not.toHaveBeenCalled();
  });

  test("launch yields the lifecycle lock while attached and reacquires it before teardown", async () => {
    const input = fixture();
    let held = true;
    const lifecycleLock = input.sessionLockManager.lock;
    lifecycleLock.assertHeld = vi.fn(() => {
      if (!held) throw new Error("test lifecycle lock is not held");
    });
    const sessionLockManager: SessionLockManager = {
      lock: lifecycleLock,
      releaseForWait: vi.fn(() => {
        lifecycleLock.assertHeld();
        mocks.events.push("release-attached-lock");
        held = false;
      }),
      withLock: vi.fn(async (operation) => {
        mocks.events.push("acquire-renewal-lock");
        held = true;
        try {
          return await operation();
        } finally {
          held = false;
          mocks.events.push("release-renewal-lock");
        }
      }),
      reacquire: vi.fn(async () => {
        mocks.events.push("reacquire-teardown-lock");
        held = true;
      }),
      close: vi.fn(),
    };
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      sessionLockManager,
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await driver.launchBuiltin("codex");

    expect(mocks.events.indexOf("session-file:write"))
      .toBeLessThan(mocks.events.indexOf("release-attached-lock"));
    expect(mocks.events.indexOf("release-attached-lock"))
      .toBeLessThan(mocks.events.indexOf("reacquire-teardown-lock"));
    expect(mocks.events.indexOf("reacquire-teardown-lock"))
      .toBeLessThan(mocks.events.indexOf("stamp-revoking"));
    // The heartbeat runs outside the lock entirely, so nothing on this path
    // ever asks for it back until teardown does.
    expect(sessionLockManager.withLock).not.toHaveBeenCalled();
  });

  test("launch fires onSessionRunning with the session identity, after the grant and before teardown", async () => {
    const onSessionRunning = vi.fn(() => { mocks.events.push("session-running"); });
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
      onSessionRunning,
    });

    await driver.launchBuiltin("codex");

    expect(onSessionRunning).toHaveBeenCalledWith({ containerId: CONTAINER_ID, sourceIp: SOURCE_IP });
    expect(mocks.events.indexOf("session-file:write")).toBeLessThan(mocks.events.indexOf("session-running"));
    expect(mocks.events.indexOf("session-running")).toBeLessThan(mocks.events.indexOf("stamp-revoking"));
  });

  test("launch preserves interrupted session evidence when the attached process does not exit 0", async () => {
    mocks.foregroundCompletion = { kind: "exit", code: 137, signal: null };
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    const outcome = await driver.launchBuiltin("codex");

    expect(outcome).toEqual({ status: 137, signal: null });
    expect(mocks.markSessionInterrupted).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ id: "rf-20260809-abcdef" }),
      137,
    );
    expect(mocks.removeSessionMetadata).not.toHaveBeenCalled();
  });

  test("launch marks evidence interrupted when the sequence fails after the foreground start", async () => {
    mocks.failRunningProof = true;
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await expect(driver.launchBuiltin("codex")).rejects.toThrow("running proof failed closed");

    expect(mocks.events).toContain("write-session-evidence");
    expect(mocks.markSessionInterrupted).toHaveBeenCalled();
    expect(mocks.removeSessionMetadata).not.toHaveBeenCalled();
    expect(mocks.events).not.toContain("activate");
  });

  test("resume launch mints the resume preflight and removes its transient evidence on failure", async () => {
    mocks.failRunningProof = true;
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });
    const conversationId = "0f8b1a2c-3d4e-4f5a-8b6c-7d8e9f0a1b2c";

    await expect(driver.launchBuiltin("codex", { resume: { conversationId } }))
      .rejects.toThrow("running proof failed closed");

    expect(mocks.createPreflight).toHaveBeenCalledWith(
      expect.objectContaining({ launch: expect.objectContaining({ kind: "builtin", resume: { conversationId } }) }),
    );
    expect(mocks.createAllocated).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ displayName: "Codex resume" }),
    );
    // The evidence carries the exact conversation as lineage, so a host crash
    // during the resumed session leaves an exact item rather than a picker one.
    expect(mocks.createSessionMetadata).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      "codex",
      "codex",
      expect.objectContaining({ resumeConversationId: conversationId }),
    );
    // A failed resume must not mint a second, less precise recovery item: the
    // claimed original evidence stays the only retryable representation.
    expect(mocks.removeSessionMetadata).toHaveBeenCalled();
    expect(mocks.markSessionInterrupted).not.toHaveBeenCalled();
  });

  test("a failed evidence removal after a clean exit still preserves the evidence as interrupted", async () => {
    mocks.removeSessionMetadata.mockImplementation(() => {
      mocks.events.push("remove-session-evidence");
      throw new Error("evidence removal failed");
    });
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await expect(driver.launchBuiltin("codex")).rejects.toThrow("evidence removal failed");

    // The handle survives the failed removal, so the failure-path finalize can
    // still preserve the evidence instead of orphaning an open metadata file.
    expect(mocks.markSessionInterrupted).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ id: "rf-20260809-abcdef" }),
      undefined,
    );
  });

  test("launch threads the project's real configured command into preflight; probe stays on the builtin default", async () => {
    // The cutover's enforcement point: a customized command must reach the
    // preflight builder, whose typed-argv rule refuses it before any Docker
    // effect. Silently substituting the builtin default would launch something
    // other than what the project configured. (The mocked descriptor's default
    // is the bare "codex".)
    const input = fixture();
    (input.context as unknown as { project: { config: unknown } }).project = {
      config: { agents: { default: "codex", codex: { command: "codex --my-custom-flag" } } },
    };
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await driver.launchBuiltin("codex");
    expect(mocks.createPreflight).toHaveBeenLastCalledWith(
      expect.objectContaining({
        launch: expect.objectContaining({ kind: "builtin", configuredCommand: "codex --my-custom-flag" }),
      }),
    );

    // Probes are admission dress rehearsals, not project launches: a custom
    // command must not make the machinery unprovable.
    await driver.probeBuiltin("codex");
    expect(mocks.createPreflight).toHaveBeenLastCalledWith(
      expect.objectContaining({
        launch: expect.objectContaining({ kind: "builtin", configuredCommand: "codex" }),
      }),
    );
  });

  test("launch resolves a recorded legacy default to the current builtin command", async () => {
    // Pre-inbox projects store an old default. The unmocked config layer
    // normalizes any recorded `legacyDefaultCommands` entry, so those projects
    // launch with the current typed argv rather than being refused as
    // customized.
    const input = fixture();
    // After fixture(), which installs the plain descriptor stub.
    mocks.builtinAgent.mockReturnValue({
      id: "codex",
      label: "Codex",
      defaultCommand: "codex",
      legacyDefaultCommands: ["codex --old-default-flag"],
    });
    (input.context as unknown as { project: { config: unknown } }).project = {
      config: { agents: { default: "codex", codex: { command: "codex --old-default-flag" } } },
    };
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await driver.launchBuiltin("codex");

    expect(mocks.createPreflight).toHaveBeenLastCalledWith(
      expect.objectContaining({
        launch: expect.objectContaining({ kind: "builtin", configuredCommand: "codex" }),
      }),
    );
  });

  test("a shell launch mints the shell preflight kind and records shell evidence", async () => {
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    const outcome = await driver.launchShell();

    expect(outcome).toEqual({ status: 0, signal: null });
    expect(mocks.createPreflight).toHaveBeenLastCalledWith(
      expect.objectContaining({ launch: { kind: "shell" } }),
    );
    // The record's user-facing identity is the shell's, not any agent's.
    expect(mocks.createAllocated).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ displayName: "Shell session", command: "shell" }),
    );
    // Host evidence carries the same "shell" command the legacy shell wrote,
    // so session listing and recovery classification keep their vocabulary.
    expect(mocks.createSessionMetadata).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      "shell",
      "zsh -il",
      expect.objectContaining({ id: "rf-20260809-abcdef" }),
    );
    // Same revocation discipline as every launch: nothing outlives the exit.
    expect(mocks.events.indexOf("session-file:write")).toBeLessThan(mocks.events.indexOf("stamp-revoking"));
  });

  test("probe leaves no user-facing session evidence", async () => {
    const driver = createInternalSessionAdmissionDriver({
      ...fixture(),
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await driver.probeBuiltin("codex");

    expect(mocks.createSessionMetadata).not.toHaveBeenCalled();
    expect(mocks.writeSessionMetadata).not.toHaveBeenCalled();
    expect(mocks.createPreflight).not.toHaveBeenCalledWith(expect.objectContaining({ resume: expect.anything() }));
  });
});

describe("session admission under the per-session file source", () => {
  /**
   * The Docker and session-file effects this launch spent before teardown.
   *
   * Teardown begins at the terminal stamp, or — when the failure was answered
   * by unadmitted cleanup — at its first creation-authorized Docker effect.
   */
  function admissionEffects(): string[] {
    const end = mocks.events.findIndex((event) => event === "stamp-revoking"
      || event.startsWith("docker:container stop")
      || event.startsWith("docker:container rm")
      || event.startsWith("docker:network disconnect"));
    return mocks.events
      .slice(0, end === -1 ? mocks.events.length : end)
      .filter((event) => event.startsWith("docker:") || event.startsWith("session-file:"));
  }

  /**
   * The teardown's own steps, in order, from the terminal stamp onwards.
   *
   * Session evidence finalization follows teardown and is not part of it, so
   * only the effects and host-state writes teardown itself performs are kept.
   */
  function teardownEvents(): string[] {
    const start = mocks.events.indexOf("stamp-revoking");
    return start === -1 ? [] : mocks.events.slice(start).filter((event) => event.startsWith("docker:")
      || event.startsWith("session-file:")
      || event.startsWith("remove-exact-record")
      || event === "stamp-revoking"
      || event === "write-host-status"
      || event === "clear-host-status");
  }

  /**
   * Every message in a nested cleanup failure.
   *
   * The ladder reports a failed teardown as an `AggregateError` holding the
   * cause and the cleanup failure, and the cleanup failure is itself one, so
   * the cause a test cares about is two levels down.
   */
  function flattenCauses(error: unknown): string {
    const flatten = (value: unknown): string[] => (value instanceof AggregateError
      ? [value.message, ...value.errors.flatMap(flatten)]
      : [String(value)]);
    return flatten(error).join("\n");
  }

  /** How many sealed beats (`docker container inspect`) this launch has issued. */
  function beats(): number {
    return mocks.events.filter((event) => event === `docker:container inspect ${CONTAINER_ID}`).length;
  }

  /** How many session files this launch has written. */
  function writes(): number {
    return mocks.events.filter((event) => event === "session-file:write").length;
  }

  /** The `served` value of every host stamp this launch has written, in order. */
  function stamped(): string[] {
    return mocks.writeHostStatus.mock.calls.map((call) => (call[1] as { served: string }).served);
  }

  /**
   * Everything this launch emits.
   *
   * `runfreeLog` writes through the output writer as it happens; `warn`
   * buffers, so the buffer is drained through the same captured writer at
   * every assertion point. Draining on entry and on exit keeps one test's
   * warnings out of another's console.
   */
  function captureOutput(): Readonly<{
    drain: () => string[];
    immediate: () => string[];
    restore: () => void;
  }> {
    const lines: string[] = [];
    setOutputWriterForTest((line) => lines.push(line));
    flushWarnings();
    lines.length = 0;
    return Object.freeze({
      drain: () => {
        flushWarnings();
        return [...lines];
      },
      // What has actually reached the terminal by now, with the warning buffer
      // left alone: the only way to tell a line the operator can see while the
      // command is still running from one they will see when it ends.
      immediate: () => [...lines],
      restore: () => {
        flushWarnings();
        setOutputWriterForTest(undefined);
      },
    });
  }

  /**
   * A launch whose attached foreground keeps running until the test ends it,
   * so the heartbeat can be driven beat by beat on the fake clock.
   */
  function heldForeground(): (completion: typeof mocks.foregroundCompletion) => void {
    let finish!: (completion: typeof mocks.foregroundCompletion) => void;
    const completion = new Promise<typeof mocks.foregroundCompletion>((resolve) => { finish = resolve; });
    mocks.startForeground.mockImplementationOnce(async (_command, _record, _project, options) => {
      mocks.events.push("start-foreground");
      options.spawn("docker", ["container", "start", CONTAINER_ID], { shell: false, stdio: "inherit", env: {} });
      return { receipt: { containerId: CONTAINER_ID }, containerId: CONTAINER_ID, pid: 123, completion };
    });
    return finish;
  }

  /**
   * A launch whose foreground stream this test ends, and re-attaches, by hand.
   *
   * `end` resolves whichever stream the driver is currently attached to; every
   * re-attach the driver asks for hands back a fresh handle whose completion
   * the next `end` resolves. The receipt is carried across, exactly as the real
   * re-attach carries the sealed lifecycle authority.
   */
  function attachableForeground(): Readonly<{
    end: (completion: typeof mocks.foregroundCompletion) => void;
    reattaches: () => number;
  }> {
    let finish!: (completion: typeof mocks.foregroundCompletion) => void;
    const nextCompletion = (): Promise<typeof mocks.foregroundCompletion> =>
      new Promise((resolve) => { finish = resolve; });
    mocks.startForeground.mockImplementationOnce(async (_command, _record, _project, options) => {
      mocks.events.push("start-foreground");
      options.spawn("docker", ["container", "start", CONTAINER_ID], { shell: false, stdio: "inherit", env: {} });
      return { receipt: { containerId: CONTAINER_ID }, containerId: CONTAINER_ID, pid: 123, completion: nextCompletion() };
    });
    mocks.reattachForeground.mockImplementation(async (handle: { receipt: unknown; containerId: string }) => {
      mocks.events.push("reattach-foreground");
      return { receipt: handle.receipt, containerId: handle.containerId, pid: 124, completion: nextCompletion() };
    });
    return Object.freeze({
      end: (completion) => { finish(completion); },
      reattaches: () => mocks.reattachForeground.mock.calls.length,
    });
  }

  /** One `docker container inspect` answer proving the pinned container exited. */
  function exitedInspect(exitCode: number): string {
    return runningInspect({ Running: false, Status: "exited", ExitCode: exitCode });
  }

  /** The project this launch's records and commands are pinned to. */
  const EXPECTED_PROJECT = { projectId: "0123456789ab", composeProject: "runfree-0123456789ab" };

  test("admits through one inspect-and-write, with no snapshot publication or consumer selection", async () => {
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    const outcome = await driver.launchBuiltin("codex");

    expect(outcome).toEqual({ status: 0, signal: null });
    expect(admissionEffects()).toEqual([
      `docker:network inspect ${NETWORK_ID}`,
      "docker:volume inspect state",
      "session-file:read-ip-assignment",
      "session-file:ip-reuse-fence",
      "docker:container create",
      `docker:container inspect ${CONTAINER_ID}`,
      "session-file:write",
    ]);
    expect(mocks.events.indexOf("start-foreground"))
      .toBeLessThan(mocks.events.indexOf(`docker:container inspect ${CONTAINER_ID}`));
  });

  test("a failed IP reuse fence refuses before creating an agent and can be retried", async () => {
    const input = fixture();
    mocks.effectAnswers.set("session-file:ip-reuse-fence", [
      { status: 1, stdout: "", stderr: "old TCP connections remain" },
    ]);
    const driver = createInternalSessionAdmissionDriver(input);
    await expect(driver.launchBuiltin("codex")).rejects.toThrow();
    expect(mocks.events).not.toContain("docker:container create");
    expect(mocks.events).not.toContain("start-foreground");
    expect(mocks.events).not.toContain("session-file:write");
    mocks.effectAnswers.clear();
    const retry = createInternalSessionAdmissionDriver(fixture());
    await expect(retry.launchBuiltin("codex")).resolves.toMatchObject({ status: 0 });
  });

  test("writes one session file carrying the record identity, the selection bindings, and the lease", async () => {
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    await driver.launchBuiltin("codex");

    const writes = mocks.dockerInputs.filter((entry) => entry.label === "session-file:write");
    expect(writes).toHaveLength(1);
    // The real bytes, parsed by the contract the proxy's own reader applies.
    const file = parseSessionFileV1(writes[0]?.input ?? "", SESSION_PRINCIPAL);
    expect(file).toBeDefined();
    expect(file).toMatchObject({
      v: 1,
      projectId: "0123456789ab",
      sessionKey: SESSION_PRINCIPAL,
      sessionId: "rf-20260809-abcdef",
      sessionIncarnation: "a".repeat(64),
      sourceIp: SOURCE_IP,
      containerId: CONTAINER_ID,
      networkId: NETWORK_ID,
      selectedAgentImageId: AGENT_IMAGE_ID,
      sessionAgentGenerationDigest: AGENT_GENERATION_DIGEST,
      controlPlaneGenerationDigest: CONTROL_PLANE_DIGEST,
      admissionContractEpoch: ADMISSION_CONTRACT_EPOCH,
      command: "codex",
    });
    expect(Date.parse(file?.inspectedAt ?? "")).toBe(Date.parse("2026-08-09T00:10:00.000Z"));
    expect(Date.parse(file?.aliveUntil ?? "") - Date.parse(file?.inspectedAt ?? ""))
      .toBe(SESSION_ADMISSION_LEASE_MAX_DURATION_MS);
    // The durable record follows the file, and the host stamp records the same
    // lease the proxy was handed.
    expect(mocks.transitionAttached).toHaveBeenCalledOnce();
    expect(mocks.events.indexOf("session-file:write"))
      .toBeLessThan(mocks.events.lastIndexOf("write-host-status"));
    expect(mocks.writeHostStatus).toHaveBeenCalledWith("/state", {
      v: 1,
      sessionId: "rf-20260809-abcdef",
      lastHeartbeatAt: file?.inspectedAt,
      aliveUntil: file?.aliveUntil,
      served: "served",
    });
  });

  test("fires onSessionRunning with the session identity once the file is written", async () => {
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const onSessionRunning = vi.fn(() => {
      mocks.events.push("on-session-running");
    });
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      onSessionRunning,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    await driver.launchBuiltin("codex");

    expect(onSessionRunning).toHaveBeenCalledWith({ containerId: CONTAINER_ID, sourceIp: SOURCE_IP });
    expect(mocks.events.indexOf("session-file:write"))
      .toBeLessThan(mocks.events.indexOf("on-session-running"));
  });

  test("an unavailable inspection at activation writes no session file and tears the session down", async () => {
    const input = fixture();
    mocks.containerInspect = { status: 1, stdout: "", stderr: "Cannot connect to the Docker daemon" };
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    await expect(driver.launchBuiltin("codex")).rejects.toThrow(
      "observation-unavailable during session-file-heartbeat-inspect",
    );

    expect(mocks.dockerInputs).toEqual([]);
    expect(mocks.events).not.toContain("session-file:write");
    // Nothing was served, so the only stamp this launch wrote is the terminal
    // one teardown leaves while the record is still there.
    expect(mocks.events).not.toContain("write-host-status");
    expect(mocks.transitionAttached).not.toHaveBeenCalled();
    // Nothing was admitted, but the write was entered, so the failure is
    // answered by the file-first sequence rather than by unadmitted cleanup:
    // a file this host may have written is deleted before the container is
    // touched, and the record goes last.
    expect(teardownEvents()).toEqual([
      "stamp-revoking",
      "session-file:delete",
      `docker:network disconnect ${NETWORK_ID} ${CONTAINER_ID}`,
      `docker:container stop --time 10 ${CONTAINER_ID}`,
      `docker:container rm --force ${CONTAINER_ID}`,
      "remove-exact-record:rf-20260809-abcdef",
      "clear-host-status",
    ]);
    // Teardown leaves no absence receipt and never transitions the record to
    // `revoking`: the terminal host stamp is the whole of the marker.
    expect(mocks.transitionRevoking).not.toHaveBeenCalled();
    expect(mocks.proveAbsent).not.toHaveBeenCalled();
    expect(mocks.removeAbsent).not.toHaveBeenCalled();
  });

  test("reports the agent's exit when the container stops during the admitting inspection", async () => {
    const input = fixture();
    // Docker answers "not running" while the attach child's exit event is
    // still in flight, which is the one verdict that can mean the agent
    // finished rather than that this is a different container.
    mocks.containerInspect = {
      status: 0,
      stdout: runningInspect({ Running: false, Status: "exited", ExitCode: 3, Pid: 0 }),
      stderr: "",
    };
    mocks.foregroundCompletion = { kind: "exit", code: 3, signal: null };
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    const outcome = await driver.launchBuiltin("codex");

    expect(outcome).toEqual({ status: 3, signal: null });
    expect(mocks.events).not.toContain("session-file:write");
    // The heartbeat deletes on a proved mismatch, which for an admission that
    // never wrote a file is an idempotent no-op against an absent path.
    expect(mocks.events).toContain("session-file:delete");
    // Teardown's terminal stamp is the only one this launch writes.
    expect(mocks.events).not.toContain("write-host-status");
    expect(mocks.transitionAttached).not.toHaveBeenCalled();
  });

  test("refuses a mismatched inspection as an error while the foreground is still running", async () => {
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect({ Pid: DOCKER_PID + 1 }), stderr: "" };
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    await expect(driver.launchBuiltin("codex")).rejects.toThrow(
      "session admission inspected a different container before granting authority: "
      + "session container Docker process id changed",
    );

    expect(mocks.events).not.toContain("session-file:write");
    // Teardown's terminal stamp is the only one this launch writes.
    expect(mocks.events).not.toContain("write-host-status");
    expect(mocks.transitionAttached).not.toHaveBeenCalled();
  });

  test("reports a foreground spawn failure instead of inspecting or writing anything", async () => {
    const input = fixture();
    mocks.currentForegroundCompletion.mockReturnValue({
      kind: "error",
      error: new Error("docker start refused the attach"),
    });
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    await expect(driver.launchBuiltin("codex")).rejects.toThrow(
      "foreground Docker attach failed before session admission: docker start refused the attach",
    );

    // No beat was issued at all: the effects stop at container creation.
    expect(admissionEffects()).toEqual([
      `docker:network inspect ${NETWORK_ID}`,
      "docker:volume inspect state",
      "session-file:read-ip-assignment",
      "session-file:ip-reuse-fence",
      "docker:container create",
    ]);
    // And because no session file can exist, the failure is answered by
    // unadmitted cleanup rather than by the file-first sequence: nothing is
    // marked terminal and no delete is spent against the proxy.
    expect(mocks.events).not.toContain("stamp-revoking");
    expect(mocks.events).not.toContain("session-file:delete");
    expect(mocks.creationAuthorizedStop).toHaveBeenCalledTimes(1);
    expect(mocks.creationAuthorizedRemove).toHaveBeenCalledTimes(1);
  });

  test("reports a foreground that already exited instead of inspecting or writing anything", async () => {
    const input = fixture();
    mocks.currentForegroundCompletion.mockReturnValue({ kind: "exit", code: 7, signal: null });
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    const outcome = await driver.launchBuiltin("codex");

    expect(outcome).toEqual({ status: 7, signal: null });
    expect(admissionEffects()).toEqual([
      `docker:network inspect ${NETWORK_ID}`,
      "docker:volume inspect state",
      "session-file:read-ip-assignment",
      "session-file:ip-reuse-fence",
      "docker:container create",
    ]);
    // Teardown's terminal stamp is the only one this launch writes.
    expect(mocks.events).not.toContain("write-host-status");
    expect(mocks.transitionAttached).not.toHaveBeenCalled();
  });

  test("renews on the heartbeat cadence without ever taking the lifecycle lock", async () => {
    vi.useFakeTimers();
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const finishForeground = heldForeground();
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    try {
      const launch = driver.launchBuiltin("codex");
      // Admission's own beat; the loop's first sleep starts from here.
      await vi.advanceTimersByTimeAsync(0);
      expect(beats()).toBe(1);
      expect(writes()).toBe(1);

      await vi.advanceTimersByTimeAsync(29_999);
      expect(beats()).toBe(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(beats()).toBe(2);
      expect(writes()).toBe(2);
      await vi.advanceTimersByTimeAsync(30_000);
      expect(beats()).toBe(3);
      expect(writes()).toBe(3);
      // The whole point of the source: renewal is one inspect-and-write, so it
      // serializes against no other lifecycle operation.
      expect(input.sessionLockManager.withLock).not.toHaveBeenCalled();
      expect(mocks.events).not.toContain("stamp-revoking");

      finishForeground({ kind: "exit", code: 0, signal: null });
      await vi.advanceTimersByTimeAsync(0);
      await expect(launch).resolves.toEqual({ status: 0, signal: null });
      // Not even teardown reaches for it: the wait held no lock to renew under.
      expect(input.sessionLockManager.withLock).not.toHaveBeenCalled();
      // The beat that was sleeping when the process exited never ran: teardown's
      // own pre-stop inspection follows, but no fourth file does.
      expect(writes()).toBe(3);
      // Three beats, then the terminal stamp teardown leaves while the record
      // is still on disk.
      expect(stamped()).toEqual(["served", "served", "served", "unknown"]);
    } finally {
      vi.useRealTimers();
    }
  });

  // The renewal loop must not hand this session authority it no longer holds:
  // once the foreground has completed, the beat that was sleeping ends without
  // writing, and the last file written is the one teardown takes back.
  test("a foreground that completes mid-sleep renews nothing", async () => {
    vi.useFakeTimers();
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const finishForeground = heldForeground();
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    try {
      const launch = driver.launchBuiltin("codex");
      await vi.advanceTimersByTimeAsync(0);
      expect(writes()).toBe(1);

      // Half a cadence in: the loop is asleep and the stream ends.
      await vi.advanceTimersByTimeAsync(15_000);
      finishForeground({ kind: "exit", code: 0, signal: null });
      await vi.advanceTimersByTimeAsync(60_000);
      await expect(launch).resolves.toEqual({ status: 0, signal: null });

      expect(writes()).toBe(1);
      expect(mocks.events.lastIndexOf("session-file:write"))
        .toBeLessThan(mocks.events.indexOf("stamp-revoking"));
    } finally {
      vi.useRealTimers();
    }
  });

  test("backs off from one second, doubling, and returns to the cadence once a beat is written", async () => {
    vi.useFakeTimers();
    // Seeded jitter: 0.25 is a 10 % shortening, so every delay below is the
    // exact backoff step rather than the un-jittered base.
    const random = vi.spyOn(Math, "random").mockReturnValue(0.25);
    const output = captureOutput();
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const finishForeground = heldForeground();
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    try {
      const launch = driver.launchBuiltin("codex");
      await vi.advanceTimersByTimeAsync(0);
      expect(beats()).toBe(1);
      const admitted = mocks.writeHostStatus.mock.calls[0]?.[1] as { aliveUntil: string };

      mocks.containerInspect = { status: 1, stdout: "", stderr: "Cannot connect to the Docker daemon" };
      // The first beat is on the cadence; it fails.
      await vi.advanceTimersByTimeAsync(29_999);
      expect(beats()).toBe(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(beats()).toBe(2);
      // 1 s, jittered.
      await vi.advanceTimersByTimeAsync(899);
      expect(beats()).toBe(2);
      await vi.advanceTimersByTimeAsync(1);
      expect(beats()).toBe(3);
      // 2 s, jittered.
      await vi.advanceTimersByTimeAsync(1_799);
      expect(beats()).toBe(3);
      await vi.advanceTimersByTimeAsync(1);
      expect(beats()).toBe(4);
      // 4 s, jittered — and this one is answered.
      mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
      await vi.advanceTimersByTimeAsync(3_599);
      expect(beats()).toBe(4);
      await vi.advanceTimersByTimeAsync(1);
      expect(beats()).toBe(5);
      expect(writes()).toBe(2);
      // Back on the cadence, not on the backoff.
      await vi.advanceTimersByTimeAsync(29_999);
      expect(beats()).toBe(5);
      await vi.advanceTimersByTimeAsync(1);
      expect(beats()).toBe(6);

      // Failing beats stamp `retrying` and keep the window the last written
      // file actually granted; a written beat stamps `served` again.
      expect(stamped()).toEqual(["served", "retrying", "retrying", "retrying", "served", "served"]);
      expect(mocks.writeHostStatus.mock.calls[1]?.[1]).toMatchObject({ aliveUntil: admitted.aliveUntil });
      // Announced once, and only after a gap.
      expect(output.drain().filter((line) => line.includes("session network restored"))).toHaveLength(1);
      // No failing beat revoked, paused, or tore anything down.
      expect(input.sessionLockManager.withLock).not.toHaveBeenCalled();
      expect(mocks.events).not.toContain("session-file:delete");
      expect(mocks.events).not.toContain("stamp-revoking");

      finishForeground({ kind: "exit", code: 0, signal: null });
      await vi.advanceTimersByTimeAsync(0);
      await expect(launch).resolves.toEqual({ status: 0, signal: null });
    } finally {
      output.restore();
      random.mockRestore();
      vi.useRealTimers();
    }
  });

  test("a proved mismatch removes the file and keeps beating without ending the process", async () => {
    vi.useFakeTimers();
    const random = vi.spyOn(Math, "random").mockReturnValue(0.25);
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const finishForeground = heldForeground();
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    try {
      const launch = driver.launchBuiltin("codex");
      let settled = false;
      launch.then(() => { settled = true; }, () => { settled = true; });
      await vi.advanceTimersByTimeAsync(0);
      expect(beats()).toBe(1);

      // A different Docker process id under the pinned container id: proof
      // that this is no longer the incarnation the file names.
      mocks.containerInspect = { status: 0, stdout: runningInspect({ Pid: DOCKER_PID + 1 }), stderr: "" };
      await vi.advanceTimersByTimeAsync(30_000);

      expect(beats()).toBe(2);
      expect(mocks.events.filter((event) => event === "session-file:delete")).toHaveLength(1);
      expect(writes()).toBe(1);
      expect(stamped()).toEqual(["served", "retrying"]);
      // The heartbeat's only power is over the file. The process it cannot
      // prove is still not the process it may end.
      expect(settled).toBe(false);
      expect(mocks.cancelForeground).not.toHaveBeenCalled();
      expect(input.sessionLockManager.withLock).not.toHaveBeenCalled();
      expect(mocks.events).not.toContain("stamp-revoking");

      // And the loop keeps beating: the container coming back is served again.
      mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
      await vi.advanceTimersByTimeAsync(900);
      expect(beats()).toBe(3);
      expect(writes()).toBe(2);

      finishForeground({ kind: "exit", code: 0, signal: null });
      await vi.advanceTimersByTimeAsync(0);
      await expect(launch).resolves.toEqual({ status: 0, signal: null });
    } finally {
      random.mockRestore();
      vi.useRealTimers();
    }
  });

  test("a failing host stamp is reported once and changes nothing about the beat", async () => {
    vi.useFakeTimers();
    const random = vi.spyOn(Math, "random").mockReturnValue(0.25);
    const output = captureOutput();
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    let stamps = 0;
    mocks.writeHostStatus.mockImplementation(() => {
      stamps += 1;
      // Admission stamps once; every stamp after it hits an unwritable path.
      if (stamps > 1) throw new Error("session host status path is not a bounded regular single-link file");
    });
    const finishForeground = heldForeground();
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    try {
      const launch = driver.launchBuiltin("codex");
      let settled = false;
      launch.then(() => { settled = true; }, () => { settled = true; });
      await vi.advanceTimersByTimeAsync(0);
      expect(beats()).toBe(1);

      // The stamp is advisory, so a beat that wrote its file is a healthy beat:
      // the cadence is unchanged, no backoff, and nothing to announce.
      for (const expected of [2, 3, 4]) {
        await vi.advanceTimersByTimeAsync(30_000);
        expect(beats()).toBe(expected);
        expect(writes()).toBe(expected);
      }
      expect(settled).toBe(false);
      expect(output.drain().filter((line) => line.includes("session network restored"))).toHaveLength(0);
      expect(output.drain().filter((line) => line.includes("session status stamp unwritable"))).toHaveLength(1);

      // And a beat that really fails still counts exactly once: the first
      // backoff step is 1 s, not the 2 s a double-counted stamp would give.
      mocks.containerInspect = { status: 1, stdout: "", stderr: "Cannot connect to the Docker daemon" };
      await vi.advanceTimersByTimeAsync(30_000);
      expect(beats()).toBe(5);
      await vi.advanceTimersByTimeAsync(899);
      expect(beats()).toBe(5);
      await vi.advanceTimersByTimeAsync(1);
      expect(beats()).toBe(6);

      mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
      finishForeground({ kind: "exit", code: 0, signal: null });
      await vi.advanceTimersByTimeAsync(0);
      await expect(launch).resolves.toEqual({ status: 0, signal: null });
      // Still one report for every failing stamp in the whole run.
      expect(output.drain().filter((line) => line.includes("session status stamp unwritable"))).toHaveLength(1);
    } finally {
      output.restore();
      random.mockRestore();
      vi.useRealTimers();
    }
  });

  test("a host-side fault is reported on every beat until a write succeeds", async () => {
    vi.useFakeTimers();
    const random = vi.spyOn(Math, "random").mockReturnValue(0.25);
    const output = captureOutput();
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const finishForeground = heldForeground();
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    try {
      const launch = driver.launchBuiltin("codex");
      let settled = false;
      launch.then(() => { settled = true; }, () => { settled = true; });
      await vi.advanceTimersByTimeAsync(0);
      expect(beats()).toBe(1);
      const admitted = mocks.writeHostStatus.mock.calls[0]?.[1] as { aliveUntil: string };

      // A throw before Docker is ever reached: this driver's own inputs, which
      // is never one of the three outcomes and never resolves by itself.
      mocks.inspectCommand.mockImplementation(() => {
        throw new Error("session file heartbeat anchor is invalid");
      });
      for (const [delay, reports] of [[30_000, 1], [900, 2], [1_800, 3]] as const) {
        await vi.advanceTimersByTimeAsync(delay);
        expect(output.drain().filter((line) => line.includes("host-side fault"))).toHaveLength(reports);
      }
      // Each report names when the session actually loses its network.
      expect(output.drain().filter((line) => line.includes(admitted.aliveUntil))).toHaveLength(3);
      expect(output.drain().filter((line) => line.includes("session network restored"))).toHaveLength(0);
      // Nothing was observed, nothing was written, and the process is intact.
      expect(beats()).toBe(1);
      expect(writes()).toBe(1);
      expect(settled).toBe(false);
      expect(input.sessionLockManager.withLock).not.toHaveBeenCalled();

      mocks.inspectCommand.mockReturnValue({ executable: "docker", args: ["container", "inspect", CONTAINER_ID] });
      await vi.advanceTimersByTimeAsync(3_600);
      expect(beats()).toBe(2);
      expect(writes()).toBe(2);
      expect(output.drain().filter((line) => line.includes("session network restored"))).toHaveLength(1);
      expect(output.drain().filter((line) => line.includes("host-side fault"))).toHaveLength(3);

      finishForeground({ kind: "exit", code: 0, signal: null });
      await vi.advanceTimersByTimeAsync(0);
      await expect(launch).resolves.toEqual({ status: 0, signal: null });
    } finally {
      output.restore();
      random.mockRestore();
      vi.useRealTimers();
    }
  });

  test.each([
    ["shortens the cadence", "2000", 2_000],
    ["is ignored above the default", "600000", 30_000],
    ["is ignored when it is not a number", "soon", 30_000],
    ["is clamped up to the one-second floor", "10", 1_000],
  ])("the host heartbeat cadence override %s", async (_name, value, expected) => {
    vi.useFakeTimers();
    vi.stubEnv("RUNFREE_SESSION_HEARTBEAT_CADENCE_MS", value);
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const finishForeground = heldForeground();
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    try {
      const launch = driver.launchBuiltin("codex");
      await vi.advanceTimersByTimeAsync(0);
      expect(beats()).toBe(1);

      await vi.advanceTimersByTimeAsync(expected - 1);
      expect(beats()).toBe(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(beats()).toBe(2);

      finishForeground({ kind: "exit", code: 0, signal: null });
      await vi.advanceTimersByTimeAsync(0);
      await expect(launch).resolves.toEqual({ status: 0, signal: null });
    } finally {
      vi.unstubAllEnvs();
      vi.useRealTimers();
    }
  });
  test.each([
    ["a stream error", { kind: "error", error: new Error("attach stream closed") }],
    ["a signal-only exit", { kind: "exit", code: null, signal: "SIGHUP" }],
  ] as const)("re-attaches the proved-running incarnation when the foreground ends on %s", async (_name, lost) => {
    vi.useFakeTimers();
    const output = captureOutput();
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const foreground = attachableForeground();
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
      nowMonotonicMs: () => Date.now(),
    });

    try {
      const launch = driver.launchBuiltin("codex");
      let settled = false;
      launch.then(() => { settled = true; }, () => { settled = true; });
      await vi.advanceTimersByTimeAsync(0);
      expect(beats()).toBe(1);

      foreground.end(lost);
      await vi.advanceTimersByTimeAsync(0);

      // One confirming inspect, and it proved the anchored incarnation: the
      // stream is re-attached rather than read as the agent's own exit.
      expect(beats()).toBe(2);
      expect(foreground.reattaches()).toBe(1);
      expect(mocks.attachCommand).toHaveBeenCalledWith(
        expect.objectContaining({ state: "attached", containerId: CONTAINER_ID }),
        EXPECTED_PROJECT,
      );
      expect(mocks.reattachForeground.mock.calls[0]?.[1]).toBe(mocks.attachCommand.mock.results[0]?.value);
      // Nothing was torn down, and the session never took the lifecycle lock.
      expect(settled).toBe(false);
      expect(mocks.events).not.toContain("stamp-revoking");
      expect(mocks.cancelForeground).not.toHaveBeenCalled();
      expect(input.sessionLockManager.withLock).not.toHaveBeenCalled();

      // The heartbeat kept the session served across the loss.
      await vi.advanceTimersByTimeAsync(30_000);
      expect(writes()).toBe(2);

      // The re-attached stream is the one the launch now waits on.
      foreground.end({ kind: "exit", code: 7, signal: null });
      await vi.advanceTimersByTimeAsync(0);
      await expect(launch).resolves.toEqual({ status: 7, signal: null });
      expect(output.drain().filter((line) => line.includes("re-attach"))).toHaveLength(1);
      // Teardown acts on the stream this session actually holds: the driver's
      // handle moved to the re-attached child, not the one that died.
      expect(mocks.cancelForeground).toHaveBeenCalledWith(expect.objectContaining({ pid: 124 }));
    } finally {
      output.restore();
      vi.useRealTimers();
    }
  });

  test("a lost stream whose inspect proves the exit ends the session with the inspected status", async () => {
    vi.useFakeTimers();
    const output = captureOutput();
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const foreground = attachableForeground();
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
      nowMonotonicMs: () => Date.now(),
    });

    try {
      const launch = driver.launchBuiltin("codex");
      await vi.advanceTimersByTimeAsync(0);

      // The container stopped while the stream was ending: the inspection, not
      // the lost stream, is what says so — and it carries the real status.
      mocks.containerInspect = { status: 0, stdout: exitedInspect(42), stderr: "" };
      mocks.observedExitStatus.mockReturnValue(42);
      foreground.end({ kind: "error", error: new Error("attach stream closed") });
      await vi.advanceTimersByTimeAsync(0);

      await expect(launch).resolves.toEqual({ status: 42, signal: null });
      expect(mocks.observedExitStatus).toHaveBeenCalledWith(exitedInspect(42), CONTAINER_ID);
      // A stopped container is never re-attached.
      expect(foreground.reattaches()).toBe(0);
      expect(mocks.attachCommand).not.toHaveBeenCalled();
      expect(mocks.events).toContain("remove-exact-record:rf-20260809-abcdef");
    } finally {
      output.restore();
      vi.useRealTimers();
    }
  });

  test("a lost stream over a changed container is reported as it is today", async () => {
    vi.useFakeTimers();
    const output = captureOutput();
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const foreground = attachableForeground();
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
      nowMonotonicMs: () => Date.now(),
    });

    try {
      const launch = driver.launchBuiltin("codex");
      // Handled from the start: this launch ends in a rejection, and an
      // unobserved one would surface as an unhandled rejection in the run.
      let settled = false;
      launch.then(() => { settled = true; }, () => { settled = true; });
      await vi.advanceTimersByTimeAsync(0);
      expect(settled).toBe(false);

      // A different Docker process id under the pinned id: running, but not
      // the incarnation this session was admitted for.
      mocks.containerInspect = { status: 0, stdout: runningInspect({ Pid: DOCKER_PID + 1 }), stderr: "" };
      foreground.end({ kind: "error", error: new Error("attach stream closed") });
      await vi.advanceTimersByTimeAsync(0);

      await expect(launch).rejects.toThrow("attach stream closed");
      expect(foreground.reattaches()).toBe(0);
      expect(mocks.attachCommand).not.toHaveBeenCalled();
      expect(mocks.events).toContain("remove-exact-record:rf-20260809-abcdef");
    } finally {
      output.restore();
      vi.useRealTimers();
    }
  });

  test("a lost stream the inspect cannot confirm keeps the session and retries on the next beat", async () => {
    vi.useFakeTimers();
    const output = captureOutput();
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const foreground = attachableForeground();
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
      nowMonotonicMs: () => Date.now(),
    });

    try {
      const launch = driver.launchBuiltin("codex");
      let settled = false;
      launch.then(() => { settled = true; }, () => { settled = true; });
      await vi.advanceTimersByTimeAsync(0);

      mocks.containerInspect = { status: 1, stdout: "", stderr: "Cannot connect to the Docker daemon" };
      foreground.end({ kind: "error", error: new Error("attach stream closed") });
      await vi.advanceTimersByTimeAsync(0);

      // Unconfirmed is not proof of anything: no re-attach, and no teardown of
      // a process this host cannot see.
      expect(foreground.reattaches()).toBe(0);
      expect(settled).toBe(false);
      expect(mocks.events).not.toContain("stamp-revoking");
      expect(mocks.cancelForeground).not.toHaveBeenCalled();
      // And the terminal is told now, while it is going quiet — not in a
      // warning buffer flushed after the command ends.
      expect(output.immediate().filter((line) => line.includes("session output stream lost:"))).toHaveLength(1);

      // The next beat retries the confirmation, and this one answers.
      mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
      await vi.advanceTimersByTimeAsync(30_000);
      expect(foreground.reattaches()).toBe(1);
      expect(settled).toBe(false);

      foreground.end({ kind: "exit", code: 0, signal: null });
      await vi.advanceTimersByTimeAsync(0);
      await expect(launch).resolves.toEqual({ status: 0, signal: null });
    } finally {
      output.restore();
      vi.useRealTimers();
    }
  });

  test("a lost stream over a container that is gone ends the session instead of waiting for it", async () => {
    vi.useFakeTimers();
    const output = captureOutput();
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const foreground = attachableForeground();
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
      nowMonotonicMs: () => Date.now(),
    });

    try {
      const launch = driver.launchBuiltin("codex");
      let settled = false;
      launch.then(() => { settled = true; }, () => { settled = true; });
      await vi.advanceTimersByTimeAsync(0);

      // The container was removed under this session: the inspection cannot
      // resolve a state at all, so the confirmation alone would wait forever.
      mocks.containerInspect = {
        status: 1,
        stdout: "",
        stderr: `Error response from daemon: No such container: ${CONTAINER_ID}`,
      };
      foreground.end({ kind: "error", error: new Error("attach stream closed") });
      await vi.advanceTimersByTimeAsync(0);
      expect(settled).toBe(false);
      expect(foreground.reattaches()).toBe(0);

      // The beat's own judgement is the bound: it proved this is not the
      // container the session was admitted for, so the lost stream is reported
      // exactly as it is reported today.
      await vi.advanceTimersByTimeAsync(30_000);
      await expect(launch).rejects.toThrow("attach stream closed");
      expect(foreground.reattaches()).toBe(0);
      expect(mocks.events).toContain("session-file:delete");
      expect(mocks.events).toContain("remove-exact-record:rf-20260809-abcdef");
      const lines = output.immediate();
      expect(lines.filter((line) => line.includes("session output stream lost:"))).toHaveLength(1);
      expect(lines.filter((line) => line.includes("session output stream cannot be recovered:"))).toHaveLength(1);
    } finally {
      output.restore();
      vi.useRealTimers();
    }
  });

  test("a fourth lost stream in one minute stops re-attaching, keeps beating, and ends on the proved exit", async () => {
    vi.useFakeTimers();
    const output = captureOutput();
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const foreground = attachableForeground();
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
      nowMonotonicMs: () => Date.now(),
    });

    try {
      const launch = driver.launchBuiltin("codex");
      let settled = false;
      launch.then(() => { settled = true; }, () => { settled = true; });
      await vi.advanceTimersByTimeAsync(0);

      for (let attempt = 0; attempt < 3; attempt += 1) {
        foreground.end({ kind: "error", error: new Error(`attach stream closed ${attempt}`) });
        await vi.advanceTimersByTimeAsync(0);
      }
      expect(foreground.reattaches()).toBe(3);

      foreground.end({ kind: "error", error: new Error("attach stream closed 4") });
      await vi.advanceTimersByTimeAsync(0);

      // At the limit the session is left exactly as it is: still running,
      // still served, and never torn down over a stream this host lost.
      expect(foreground.reattaches()).toBe(3);
      expect(settled).toBe(false);
      expect(mocks.events).not.toContain("stamp-revoking");
      expect(mocks.cancelForeground).not.toHaveBeenCalled();

      const written = writes();
      await vi.advanceTimersByTimeAsync(30_000);
      expect(writes()).toBe(written + 1);
      expect(foreground.reattaches()).toBe(3);
      expect(settled).toBe(false);

      // The beat's own confirmation is what ends the session, with the status
      // the container actually exited with.
      mocks.containerInspect = { status: 0, stdout: exitedInspect(13), stderr: "" };
      mocks.observedExitStatus.mockReturnValue(13);
      await vi.advanceTimersByTimeAsync(30_000);

      await expect(launch).resolves.toEqual({ status: 13, signal: null });
      expect(foreground.reattaches()).toBe(3);
      expect(mocks.events).toContain("remove-exact-record:rf-20260809-abcdef");
      // The wait was announced when it began and when it ended, both while the
      // command was still running.
      const lines = output.immediate();
      expect(lines.filter((line) => line.includes("session output stream lost:"))).toHaveLength(1);
      expect(lines.filter((line) => line.includes("session container exited with code 13"))).toHaveLength(1);
    } finally {
      output.restore();
      vi.useRealTimers();
    }
  });

  test("the re-attach limit rolls: a minute after the first attempts the session may re-attach again", async () => {
    vi.useFakeTimers();
    const output = captureOutput();
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const foreground = attachableForeground();
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
      nowMonotonicMs: () => Date.now(),
    });

    try {
      const launch = driver.launchBuiltin("codex");
      await vi.advanceTimersByTimeAsync(0);

      for (let attempt = 0; attempt < 4; attempt += 1) {
        foreground.end({ kind: "error", error: new Error(`attach stream closed ${attempt}`) });
        await vi.advanceTimersByTimeAsync(0);
      }
      expect(foreground.reattaches()).toBe(3);

      // Still inside the window: the beat's confirmation proves the container
      // is running and still declines to spend a fourth attempt.
      await vi.advanceTimersByTimeAsync(30_000);
      expect(foreground.reattaches()).toBe(3);
      // The window has rolled, so the same beat that was declining now
      // re-attaches: the limit is a rate, not a session-ending verdict.
      await vi.advanceTimersByTimeAsync(30_000);
      expect(foreground.reattaches()).toBe(4);
      // Announced at both ends: the wait, and the re-attach that ended it.
      const lines = output.immediate();
      expect(lines.filter((line) => line.includes("session output stream lost:"))).toHaveLength(1);
      expect(lines.filter((line) => line.includes("still running; re-attached"))).toHaveLength(4);

      foreground.end({ kind: "exit", code: 0, signal: null });
      await vi.advanceTimersByTimeAsync(0);
      await expect(launch).resolves.toEqual({ status: 0, signal: null });
    } finally {
      output.restore();
      vi.useRealTimers();
    }
  });

  test("routes cleanup the same way when timings are enabled", async () => {
    const input = fixture();
    // The timing facade rebuilds the steps object, so anything it forgets to
    // forward silently changes behaviour under `RUNFREE_TIMINGS`.
    (input.context.env as Record<string, string>).RUNFREE_TIMINGS = "1";
    const output = captureOutput();
    mocks.currentForegroundCompletion.mockReturnValue({
      kind: "error",
      error: new Error("docker start refused the attach"),
    });
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    try {
      await expect(driver.launchBuiltin("codex")).rejects.toThrow(
        "foreground Docker attach failed before session admission",
      );

      expect(mocks.events).not.toContain("stamp-revoking");
      expect(mocks.events).not.toContain("session-file:delete");
      expect(mocks.creationAuthorizedStop).toHaveBeenCalledTimes(1);
    } finally {
      output.restore();
    }
  });

  test("takes back a file it wrote but could not finish granting", async () => {
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    // The durable record cannot be advanced to `attached` after the file is
    // already published — the window where a file outlives the record it was
    // granted for.
    mocks.replaceRecord.mockImplementation((_stateDir: string, _project: unknown, _current: unknown, next: FakeRecord) => {
      mocks.events.push("replace-record");
      if (next.state === "attached") {
        throw new Error("session-container lifecycle record changed before replacement");
      }
    });
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    const failure = await driver.launchBuiltin("codex").catch((error: unknown) => error);
    expect(flattenCauses(failure)).toContain("session-container lifecycle record changed before replacement");

    // The file is taken back where it was written, before the failure is even
    // reported, rather than left for teardown to notice.
    const written = mocks.events.indexOf("session-file:write");
    const deleted = mocks.events.indexOf("session-file:delete");
    expect(written).toBeGreaterThan(-1);
    expect(deleted).toBeGreaterThan(written);
    expect(deleted).toBeLessThan(mocks.events.indexOf("stamp-revoking"));
    // And the ordered teardown still runs its own delete before it touches the
    // container or the record.
    expect(teardownEvents()).toEqual([
      "stamp-revoking",
      "session-file:delete",
      `docker:network disconnect ${NETWORK_ID} ${CONTAINER_ID}`,
      `docker:container stop --time 10 ${CONTAINER_ID}`,
      `docker:container rm --force ${CONTAINER_ID}`,
      "remove-exact-record:rf-20260809-abcdef",
      "clear-host-status",
    ]);
  });

  test("tears the session down file first and drops the host record last", async () => {
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    await expect(driver.launchBuiltin("codex")).resolves.toEqual({ status: 0, signal: null });

    // Invariant 3 as an ordering: the proxy is told first, by the file's
    // absence, that this session may no longer be served; the record — which
    // is what reserves the session's address — is dropped last.
    expect(teardownEvents()).toEqual([
      "stamp-revoking",
      "session-file:delete",
      `docker:network disconnect ${NETWORK_ID} ${CONTAINER_ID}`,
      `docker:container stop --time 10 ${CONTAINER_ID}`,
      `docker:container rm --force ${CONTAINER_ID}`,
      "remove-exact-record:rf-20260809-abcdef",
      "clear-host-status",
    ]);
    // The record itself is never transitioned: the terminal stamp is the
    // marker, so the record a peer reads stays exactly what it was until it is
    // gone.
    expect(mocks.transitionRevoking).not.toHaveBeenCalled();
    expect(mocks.proveAbsent).not.toHaveBeenCalled();
    expect(mocks.removeAbsent).not.toHaveBeenCalled();
    expect(mocks.removeExactRecord).toHaveBeenCalledWith(
      "/state",
      EXPECTED_PROJECT,
      expect.objectContaining({ state: "attached", containerId: CONTAINER_ID }),
    );
    expect(mocks.removeHostStatus).toHaveBeenCalledWith("/state", "rf-20260809-abcdef");
    // The attached stream is released with the session it was showing.
    expect(mocks.cancelForeground).toHaveBeenCalledTimes(1);
  });

  test("a session file the proxy will not delete stops the teardown and keeps the record", async () => {
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    mocks.effectAnswers.set("session-file:delete", [
      { status: 1, stdout: "", stderr: "Error response from daemon: No such container: proxy" },
    ]);
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    const failure = await driver.launchBuiltin("codex").catch((error: unknown) => error);

    // The blocked delete is what the launch reports, nested inside the
    // ladder's own cleanup-failed aggregate.
    expect(flattenCauses(failure)).toContain("observation-unavailable during delete-session-file");

    // A file this host could not remove may still be serving the session, so
    // nothing past the delete may run and the record keeps the address
    // reserved. Both cleanup attempts the ladder makes are blocked the same
    // way.
    expect(teardownEvents()).toEqual([
      "stamp-revoking",
      "session-file:delete",
      "stamp-revoking",
      "session-file:delete",
    ]);
    expect(mocks.removeExactRecord).not.toHaveBeenCalled();
    expect(mocks.removeHostStatus).not.toHaveBeenCalled();
  });

  test("a rerun of a blocked teardown completes the sequence it was not allowed to start", async () => {
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    // The first delete is refused; the proxy answers the retry.
    mocks.effectAnswers.set("session-file:delete", [
      { status: 1, stdout: "", stderr: "proxy exec failed" },
      { status: 0, stdout: "", stderr: "" },
    ]);
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    // The launch still reports the blocked attempt; the reclamation is that
    // the record and container do not survive it.
    const failure = await driver.launchBuiltin("codex").catch((error: unknown) => error);
    expect(flattenCauses(failure)).toContain("observation-unavailable during delete-session-file");

    expect(teardownEvents()).toEqual([
      "stamp-revoking",
      "session-file:delete",
      "stamp-revoking",
      "session-file:delete",
      `docker:network disconnect ${NETWORK_ID} ${CONTAINER_ID}`,
      `docker:container stop --time 10 ${CONTAINER_ID}`,
      `docker:container rm --force ${CONTAINER_ID}`,
      "remove-exact-record:rf-20260809-abcdef",
      "clear-host-status",
    ]);
    expect(mocks.removeExactRecord).toHaveBeenCalledTimes(1);
  });

  test("a completed teardown is not repeated when the ladder cleans up twice", async () => {
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    // Detaching the foreground fails after the sequence has completed, which
    // is what makes the ladder run its cleanup a second time.
    mocks.cancelForeground.mockImplementation(() => {
      throw new Error("foreground detach failed");
    });
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    const failure = await driver.launchBuiltin("codex").catch((error: unknown) => error);
    expect(flattenCauses(failure)).toContain("foreground detach failed");

    // Exactly one of each effect: a session whose file, container, and record
    // are already gone has nothing left for a second pass to do.
    expect(teardownEvents()).toEqual([
      "stamp-revoking",
      "session-file:delete",
      `docker:network disconnect ${NETWORK_ID} ${CONTAINER_ID}`,
      `docker:container stop --time 10 ${CONTAINER_ID}`,
      `docker:container rm --force ${CONTAINER_ID}`,
      "remove-exact-record:rf-20260809-abcdef",
      "clear-host-status",
    ]);
    expect(mocks.removeExactRecord).toHaveBeenCalledTimes(1);
  });

  test("every teardown step is fenced by the lifecycle lock", async () => {
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    // The lock is lost the moment teardown marks the record terminal. Every
    // step after it must refuse rather than act on a session this host can no
    // longer prove it owns.
    mocks.writeHostStatus.mockImplementation((_stateDir: string, status: { terminal?: string }) => {
      if (status.terminal !== "revoking") {
        mocks.events.push("write-host-status");
        return;
      }
      mocks.events.push("stamp-revoking");
      input.sessionLockManager.lock.release();
    });
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    const failure = await driver.launchBuiltin("codex").catch((error: unknown) => error);
    expect(flattenCauses(failure)).toContain("test lifecycle lock is not held");

    expect(teardownEvents()).toEqual(["stamp-revoking"]);
    expect(mocks.removeExactRecord).not.toHaveBeenCalled();
    expect(mocks.removeHostStatus).not.toHaveBeenCalled();
  });

  test("refuses a launch while a record whose teardown did not finish survives", async () => {
    const input = fixture();
    const surviving = record("attached", CONTAINER_ID);
    mocks.listRecords.mockReturnValue([surviving]);
    // The owner is alive (the default), and the record is not `revoking`: the
    // terminal stamp is the only thing that says this is cleanup rather than a
    // session to admit beside.
    mocks.readHostStatus.mockReturnValue({
      v: 1,
      sessionId: surviving.sessionId,
      lastHeartbeatAt: "2026-08-09T00:09:00.000Z",
      aliveUntil: "2026-08-09T00:09:00.000Z",
      served: "unknown",
      terminal: "revoking",
    });
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    const refusal = await driver.launchBuiltin("codex").then(
      () => undefined,
      (error: unknown) => error as Error,
    );
    expect(refusal?.message).toContain(
      "internal session admission found 1 lifecycle record(s) that reconciliation did not clear",
    );
    // The unknown-owner remedy pair the refusal must name (spec F9, output
    // contract D4): what to inspect with, and what reclaims the wedge.
    expect(refusal?.message).toContain("run `runfree sessions` to inspect them");
    expect(refusal?.message).toContain("`runfree destroy --force` to clear residue");

    expect(mocks.events).not.toContain("allocate");
    expect(mocks.readHostStatus).toHaveBeenCalledWith("/state", surviving.sessionId);
  });

  test("admits beside a live peer whose session is not being torn down", async () => {
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const peer = record("attached", CONTAINER_ID);
    mocks.listRecords.mockReturnValue([peer]);
    // The same record, with a beating stamp instead of a terminal one.
    mocks.readHostStatus.mockReturnValue({
      v: 1,
      sessionId: peer.sessionId,
      lastHeartbeatAt: "2026-08-09T00:09:00.000Z",
      aliveUntil: "2026-08-09T00:14:00.000Z",
      served: "served",
    });
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    await expect(driver.launchBuiltin("codex")).resolves.toEqual({ status: 0, signal: null });
  });

  /** One session file this reconcile deleted, issued through the driver's own io. */
  function reconcileDeleting(io: RuntimeIO, sessionKey: string, reservedSourceIps: string[] = []) {
    return async () => {
      mocks.events.push("reconcile-sessions");
      io.capture("docker", [
        "exec", "--user", "0:0", "-i", PROXY_ID, "node", "-e", "<delete script>",
        `${SESSION_FILES_DIR}/${sessionKey}.json`,
      ], {});
      return {
        orphanFilesDeleted: [sessionKey],
        deadOwnersRevoked: [],
        orphanContainersRemoved: [],
        unknownOwners: [],
        reservedSourceIps,
        orphanFiles: [sessionKey],
        recordsWithoutFiles: [],
      };
    };
  }

  test("sweeps the proxy's session files before any address is allocated", async () => {
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    mocks.reconcileSessions.mockImplementation(reconcileDeleting(input.io, "c".repeat(64)));
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await driver.launchBuiltin("codex");

    expect(mocks.reconcileSessions).toHaveBeenCalledWith(expect.objectContaining({
      mode: "repair",
      proxyId: PROXY_ID,
      stateDir: "/state",
      expectedProject: { projectId: "0123456789ab", composeProject: "runfree-0123456789ab" },
    }));
    // Invariant 3: the sweep and the allocation are one critical section, and
    // the sweep is first.
    expect(mocks.events.indexOf("reconcile-sessions")).toBeLessThan(mocks.events.indexOf("allocate"));
    expect(admissionEffects()[0]).toBe("session-file:delete");
    expect(mocks.events.indexOf("session-file:delete")).toBeLessThan(mocks.events.indexOf("allocate"));
    expect(admissionEffects()).not.toContain("session-file:publish-eligibility");
  });

  test("never allocates an address a proxy session file still names", async () => {
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    mocks.reconcileSessions.mockImplementation(
      reconcileDeleting(input.io, "c".repeat(64), [SOURCE_IP, "172.31.90.99"]),
    );
    // The real allocator's rule, in miniature: the lowest address in the pool
    // that nothing reserves.
    mocks.allocateIp.mockImplementation((request: { reservedIps?: readonly string[] }) => {
      const reserved = new Set(request.reservedIps ?? []);
      for (let host = 20; host <= 30; host += 1) {
        const candidate = `172.31.90.${host}`;
        if (!reserved.has(candidate)) return candidate;
      }
      throw new Error("session-container source IP pool is exhausted");
    });
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await driver.launchBuiltin("codex");

    expect(mocks.allocateIp).toHaveBeenCalledWith(expect.objectContaining({
      reservedIps: expect.arrayContaining([SOURCE_IP]),
    }));
    expect(mocks.createAllocated).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ sourceIp: "172.31.90.21" }),
    );
  });

  test("keeps a reserved address that is outside the session pool's subnet out of the allocator", async () => {
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    mocks.reconcileSessions.mockImplementation(
      reconcileDeleting(input.io, "c".repeat(64), ["10.9.9.9"]),
    );
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await driver.launchBuiltin("codex");

    // An address the pool could never return is not evidence about the pool,
    // and passing it would refuse the launch instead of reserving anything.
    expect(mocks.allocateIp).toHaveBeenCalledWith(expect.objectContaining({ reservedIps: [] }));
  });

  test("refuses before allocation when the reconcile cannot observe the proxy, and a rerun proceeds", async () => {
    const input = fixture();
    mocks.reconcileSessions.mockImplementationOnce(async () => {
      mocks.events.push("reconcile-sessions");
      throw new RuntimeObservationError({
        kind: "observation-unavailable",
        subject: "proxy",
        expectedIdentity: PROXY_ID,
        phase: "read-served-set",
        observation: `the proxy's session file listing is unavailable; run \`runfree up\` and retry`,
      });
    });
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await expect(driver.launchBuiltin("codex")).rejects.toBeInstanceOf(RuntimeObservationError);

    expect(mocks.events).not.toContain("allocate");
    expect(mocks.createContainer).not.toHaveBeenCalled();
    expect(writes()).toBe(0);

    // Reclamation: the same launch, once the proxy answers.
    mocks.events.length = 0;
    const second = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const rerun = createInternalSessionAdmissionDriver({
      ...second,
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await expect(rerun.launchBuiltin("codex")).resolves.toEqual({ status: 0, signal: null });
    expect(mocks.events).toContain("allocate");
  });

  test("tears a dead owner's record down through the reconcile, with no revoking transition", async () => {
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const abandoned = record("attached", CONTAINER_ID);
    mocks.recordedOnPreviousBoot.mockReturnValue(true);
    let reconciled = false;
    mocks.reconcileSessions.mockImplementation(async () => {
      mocks.events.push("reconcile-sessions");
      reconciled = true;
      return {
        orphanFilesDeleted: [],
        deadOwnersRevoked: [abandoned.sessionId],
        orphanContainersRemoved: [],
        unknownOwners: [],
        reservedSourceIps: [],
        orphanFiles: [],
        recordsWithoutFiles: [],
      };
    });
    mocks.listRecords.mockImplementation(() => (reconciled ? [] : [abandoned]));
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:00:00.000Z"),
    });

    await driver.launchBuiltin("codex");

    // The record is torn down by the shared ordered teardown, never marked
    // revoking: the terminal host stamp is the only marker this teardown sets.
    expect(mocks.transitionRevoking).not.toHaveBeenCalled();
    expect(mocks.replaceRecord).not.toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      abandoned,
      expect.objectContaining({ state: "revoking" }),
    );
    expect(mocks.events).toContain("allocate");
  });
  /**
   * The proxy container every session-file `docker exec` was addressed to.
   *
   * `docker exec --user 0:0 -i <proxyId> node -e …` — the fifth argument is the
   * exact container the file was written into, which is the whole of what a
   * rebind adoption has to move.
   */
  function writeTargets(io: RuntimeIO): string[] {
    return (io.capture as unknown as Mock).mock.calls
      .filter((call) => effectLabel(call[1] as string[]) === "session-file:write")
      .map((call) => (call[1] as string[])[4] as string);
  }

  test("one beat adopts a completed compatible rebind under the lock, then writes to the new proxy without it", async () => {
    vi.useFakeTimers();
    const input = fixture();
    const sessionLockManager = orderedSessionLockManager(input.sessionLockManager);
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const finishForeground = heldForeground();
    const candidateProxyId = "f".repeat(64);
    const candidateDigest = `sha256:${"a".repeat(64)}`;
    const candidateSelection = {
      ...effectiveControlPlane.selection,
      proxyContainerId: candidateProxyId,
      controlPlaneGenerationDigest: candidateDigest,
    };
    const reboundRecord = Object.freeze({
      ...record("attached", CONTAINER_ID),
      controlPlaneGenerationDigest: candidateDigest,
    });
    mocks.adoptRebind.mockImplementation(() => {
      mocks.events.push("adopt-rebind");
      return {
        effectiveControlPlane: candidateSelection,
        candidateMaterialization: { controlPlaneMaterializationDigest: `sha256:${"b".repeat(64)}` },
        record: reboundRecord,
      };
    });
    mocks.createRetainedRebindPlan.mockReturnValue(planFor(reboundRecord));
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      sessionLockManager,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    try {
      const launch = driver.launchBuiltin("codex");
      await vi.advanceTimersByTimeAsync(0);
      expect(writes()).toBe(1);
      expect(writeTargets(input.io)).toEqual([PROXY_ID]);
      // The ordered wrapper delegates to the fixture's spy; admission itself
      // takes no critical section.
      expect(input.sessionLockManager.withLock).not.toHaveBeenCalled();

      // A compatible rebind completes while this session holds no lock.
      effectiveControlPlane = { selection: candidateSelection, manifest: effectiveControlPlane.manifest };
      await vi.advanceTimersByTimeAsync(30_000);

      expect(mocks.adoptRebind).toHaveBeenCalledTimes(1);
      // The lock is taken for the adoption alone, and released before the beat.
      expect(mocks.events.filter((event) => event === "acquire-renewal-lock"
        || event === "release-renewal-lock"
        || event === "adopt-rebind"
        || event === "session-file:write")).toEqual([
        "session-file:write",
        "acquire-renewal-lock",
        "adopt-rebind",
        "release-renewal-lock",
        "session-file:write",
      ]);
      // The heartbeat now beats against the rebound record, into the new proxy.
      expect(writeTargets(input.io)).toEqual([PROXY_ID, candidateProxyId]);
      const written = mocks.dockerInputs.filter((entry) => entry.label === "session-file:write");
      expect(parseSessionFileV1(written[1]?.input ?? "", SESSION_PRINCIPAL))
        .toMatchObject({ controlPlaneGenerationDigest: candidateDigest });

      // Nothing else about the session moved, and the next beats cost no lock
      // at all: the durable selection is the held one again.
      await vi.advanceTimersByTimeAsync(60_000);
      expect(writes()).toBe(4);
      expect(mocks.adoptRebind).toHaveBeenCalledTimes(1);
      expect(mocks.events.filter((event) => event === "acquire-renewal-lock")).toHaveLength(1);
      expect(writeTargets(input.io).slice(1)).toEqual([candidateProxyId, candidateProxyId, candidateProxyId]);

      finishForeground({ kind: "exit", code: 0, signal: null });
      await vi.advanceTimersByTimeAsync(0);
      await expect(launch).resolves.toEqual({ status: 0, signal: null });
    } finally {
      vi.useRealTimers();
    }
  });

  test("an unchanged durable selection costs the heartbeat no lock and no adoption", async () => {
    vi.useFakeTimers();
    const input = fixture();
    const sessionLockManager = orderedSessionLockManager(input.sessionLockManager);
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    const finishForeground = heldForeground();
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      sessionLockManager,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    try {
      const launch = driver.launchBuiltin("codex");
      await vi.advanceTimersByTimeAsync(0);
      const readsAfterAdmission = mocks.readEffectiveControlPlane.mock.calls.length;

      await vi.advanceTimersByTimeAsync(90_000);

      expect(writes()).toBe(4);
      // Every beat asks the durable selection, unlocked, and answers "unchanged".
      expect(mocks.readEffectiveControlPlane.mock.calls.length).toBe(readsAfterAdmission + 3);
      expect(mocks.adoptRebind).not.toHaveBeenCalled();
      expect(mocks.events).not.toContain("acquire-renewal-lock");
      expect(input.sessionLockManager.withLock).not.toHaveBeenCalled();

      finishForeground({ kind: "exit", code: 0, signal: null });
      await vi.advanceTimersByTimeAsync(0);
      await expect(launch).resolves.toEqual({ status: 0, signal: null });
    } finally {
      vi.useRealTimers();
    }
  });

  test.each([
    [
      "a rebind still in flight",
      "adoption",
      () => new SessionReplacementPendingError("t".repeat(64), "control-selected"),
      "a control-plane rebind is pending at control-selected",
    ],
    [
      "a lifecycle lock held past the renewal wait budget",
      "lock",
      () => new SessionLockAcquisitionTimeoutError("/state/runtime-lifecycle.lock", 5_000),
      "timed out after 5000ms waiting to reacquire the project lifecycle lock",
    ],
    [
      "a host queue that cannot schedule a renewal",
      "lock",
      () => new RuntimeObservationError({
        kind: "observation-unavailable",
        subject: "owner",
        expectedIdentity: "/state/runtime-lifecycle.lock",
        phase: "renewal-lock-acquisition",
        observation: "renewal scheduling is unavailable; repair the host queue and retry",
      }),
      "renewal scheduling is unavailable",
    ],
  ] as const)(
    "%s leaves the session beating into the proxy it still holds",
    async (_label, thrower, makeError, fragment) => {
      vi.useFakeTimers();
      const output = captureOutput();
      const input = fixture();
        mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
      const finishForeground = heldForeground();
      // The manager retains the lock when the adoption itself threw and has
      // already returned to waiting when acquisition did; the loop releases
      // best effort for exactly that reason, so both shapes are exercised.
      if (thrower === "adoption") mocks.adoptRebind.mockImplementation(() => { throw makeError(); });
      else (input.sessionLockManager.withLock as unknown as Mock)
        .mockImplementation(async () => { throw makeError(); });
      const driver = createInternalSessionAdmissionDriver({
        ...input,
        nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
      });

      try {
        let settled = false;
        const launch = driver.launchBuiltin("codex").then((value) => { settled = true; return value; });
        await vi.advanceTimersByTimeAsync(0);
        expect(writes()).toBe(1);
        const releasesBefore = (input.sessionLockManager.releaseForWait as unknown as Mock).mock.calls.length;
        effectiveControlPlane = {
          selection: {
            ...effectiveControlPlane.selection,
            proxyContainerId: "f".repeat(64),
            controlPlaneGenerationDigest: `sha256:${"a".repeat(64)}`,
          },
          manifest: effectiveControlPlane.manifest,
        };

        // Three beats meet the same unfinished replacement.
        await vi.advanceTimersByTimeAsync(90_000);

        // None of these is news about this session's container: the process is
        // preserved, the beat still runs, and the file it writes still names the
        // proxy this launch holds. Q5's accepted cost is one cadence unserved,
        // never a teardown.
        expect(settled).toBe(false);
        expect(writes()).toBe(4);
        expect(writeTargets(input.io)).toEqual([PROXY_ID, PROXY_ID, PROXY_ID, PROXY_ID]);
        expect(mocks.events).not.toContain("stamp-revoking");
        expect(mocks.cancelForeground).not.toHaveBeenCalled();
        expect((input.sessionLockManager.releaseForWait as unknown as Mock).mock.calls.length)
          .toBeGreaterThan(releasesBefore);
        // Once per gap, immediately: the operator can act on it while the
        // session is still running.
        const reported = output.immediate().filter((line) => line.includes(fragment));
        expect(reported).toHaveLength(1);
        expect(reported[0]).toContain("the session process remains attached; network restoration is incomplete");

        finishForeground({ kind: "exit", code: 0, signal: null });
        await vi.advanceTimersByTimeAsync(0);
        await expect(launch).resolves.toEqual({ status: 0, signal: null });
      } finally {
        output.restore();
        vi.useRealTimers();
      }
    },
  );

  test("a refused adoption ends the launch instead of counting as a failed beat", async () => {
    vi.useFakeTimers();
    const output = captureOutput();
    const input = fixture();
    mocks.containerInspect = { status: 0, stdout: runningInspect(), stderr: "" };
    heldForeground();
    mocks.adoptRebind.mockImplementation(() => {
      mocks.events.push("adopt-refused");
      throw new Error("durable effective control plane is not a compatible rebind of the session's launch authority");
    });
    const driver = createInternalSessionAdmissionDriver({
      ...input,
      nowEpochMs: () => Date.parse("2026-08-09T00:10:00.000Z"),
    });

    try {
      // The rejection is handled from the moment the launch exists, so a
      // refusal is observed rather than escaping as an unhandled rejection.
      const settled = driver.launchBuiltin("codex").then(() => undefined, (error: unknown) => error);
      await vi.advanceTimersByTimeAsync(0);
      expect(writes()).toBe(1);
      effectiveControlPlane = {
        selection: {
          ...effectiveControlPlane.selection,
          proxyContainerId: "f".repeat(64),
          controlPlaneGenerationDigest: `sha256:${"a".repeat(64)}`,
        },
        manifest: effectiveControlPlane.manifest,
      };

      await vi.advanceTimersByTimeAsync(30_000);
      const failure = await settled;

      // A session that no longer holds its control plane is not a beat that
      // failed: the refusal surfaces rather than backing off under an authority
      // this launch has lost.
      expect(flattenCauses(failure)).toContain("not a compatible rebind");
      expect(mocks.events).toContain("adopt-refused");
      expect(writes()).toBe(1);
      expect(output.drain().join("\n")).not.toContain("host-side fault");
    } finally {
      output.restore();
      vi.useRealTimers();
    }
  });
});
