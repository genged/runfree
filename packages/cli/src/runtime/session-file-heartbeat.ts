import type * as childProcess from "node:child_process";

import {
  mintSessionFileNonce,
  parseSessionFileV1,
  serializeSessionFileV1,
  SESSION_FILE_SCHEMA_VERSION,
  type SessionFileV1,
} from "@runfree/runtime-contracts/session-file";
import { SESSION_ADMISSION_LEASE_MAX_DURATION_MS } from "@runfree/runtime-contracts/session-registry";

import { RuntimeObservationError } from "./observation-failure.ts";
import {
  executeSessionDockerCommand,
  sessionContainerInspectCommand,
} from "./session-container-docker.ts";
import {
  assertSessionContainerNarrowRunningInspect,
  NARROW_LIVENESS_UNREADABLE_INSPECT_MESSAGES,
} from "./session-container-narrow-liveness.ts";
import { SESSION_CONTAINER_INSPECT_MAX_BYTES } from "./session-container-proof.ts";
import type {
  SessionContainerProjectIdentity,
  SessionContainerRecordV2,
} from "./session-containers.ts";
import {
  executeSessionFileCommand,
  sessionFileDeleteCommand,
  sessionFileWriteCommand,
  type SessionAdmissionDockerExecutor,
} from "./session-file-publisher.ts";
import type { CaptureResult } from "./types.ts";

// The one place a session file may be written. Every write is sealed to a
// same-call Docker inspection of the exact container incarnation the file
// claims: the identity fields are copied from the lifecycle record and the
// admit-time anchor only after that inspection proves them, so a file can
// never outlive the container it names by more than one lease.
//
// The three outcomes are the three things the host can actually know:
//
//   written      the container was proved running with the anchored identity
//                and the proxy accepted a fresh file;
//   mismatch     the inspection proved a *different* answer — a differing
//                inspected field, a not-running state, or Docker's definitive
//                "No such container: <pinned id>" — so the file is deleted at
//                once and no write is attempted;
//   unavailable  the observation could not be made (timeout, daemon error,
//                unparseable answer, failed exec). Nothing is deleted and
//                nothing is written; the caller backs off and retries.
//
// The asymmetry is the point: only proof revokes. An unavailable inspection
// leaves the previous file to expire on its own lease rather than cutting a
// live session off because the host could not reach the daemon.
//
// The loop contract: `inspectAndWriteSessionFile` throws only on caller-contract
// violations that are detectable *before* any Docker call, and every one of
// those refusals happens with no captured effect. Once Docker has been reached,
// every condition is one of the three outcomes — the heartbeat loop can treat a
// throw as a bug in its own inputs and an outcome as news about the session.

export const SESSION_HEARTBEAT_CADENCE_MS = 30_000;
export const SESSION_HEARTBEAT_BACKOFF_BASE_MS = 1_000;
export const SESSION_HEARTBEAT_BACKOFF_MAX_MS = 30_000;
export const SESSION_HEARTBEAT_BACKOFF_JITTER = 0.2;
// The inspection is the gate in front of a write, so it is bounded here rather
// than by the caller: a hung `docker container inspect` must become a skipped
// heartbeat, never a stalled one.
export const SESSION_HEARTBEAT_INSPECT_TIMEOUT_MS = 5_000;
// The same reasoning for the two sealed `docker exec` calls, with more room for
// the proxy-side fsync: a caller may tighten this bound but never raise it, so
// a hung exec cannot stall a beat either.
export const SESSION_HEARTBEAT_EXEC_TIMEOUT_MS = 10_000;

const DOCKER_OBJECT_ID_PATTERN = /^[a-f0-9]{64}$/;
const HEARTBEAT_STATES: ReadonlySet<SessionContainerRecordV2["state"]> = new Set([
  "provisioning-running",
  "attached",
]);

// The exact `StartedAt` shape `assertSessionContainerNarrowRunningInspect`
// requires of its identity argument. Checked here too, before Docker, so a
// malformed anchor is refused as the caller bug it is instead of reaching the
// assertion and being read as evidence about the container.
const DOCKER_STARTED_AT_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u;
// Stands in for the real nonce while the pre-Docker candidate is validated; the
// file that is actually written always carries a freshly minted one.
const CANDIDATE_NONCE = "0".repeat(32);

/** The admit-time inspect's mutable running identity, re-proved on every beat. */
export type SessionFileAnchor = Readonly<{
  dockerPid: number;
  dockerStartedAt: string;
  networkEndpointId: string;
}>;

export type SessionFileDisplay = Readonly<{
  name: string;
  command: string;
  agentCommand?: string;
  hostTty?: string;
  hostTermProgram?: string;
  startedAt: string;
}>;

/**
 * The eligibility-matching bindings the published `eligibility.json` will be
 * compared against by the proxy. They are supplied by the caller that owns the
 * effective selection rather than re-derived from the lifecycle record, so the
 * file and the eligibility file always come from one decision.
 */
export type SessionFileEligibilityBindings = Pick<
  SessionFileV1,
  | "selectedAgentImageId"
  | "sessionAgentGenerationDigest"
  | "controlPlaneGenerationDigest"
  | "admissionContractEpoch"
>;

export type HeartbeatOutcome =
  | { kind: "written"; file: SessionFileV1 }
  | { kind: "unavailable"; error: RuntimeObservationError }
  | { kind: "mismatch"; observation: string; deleted: boolean };

export type InspectAndWriteSessionFileInput = {
  io: SessionAdmissionDockerExecutor;
  proxyId: string;
  record: SessionContainerRecordV2;
  anchor: SessionFileAnchor;
  expectedProject: SessionContainerProjectIdentity;
  networkId: string;
  display: SessionFileDisplay;
  eligibilityBindings: SessionFileEligibilityBindings;
  leaseMs?: number;
  nowEpochMs?: () => number;
  dockerOptions?: childProcess.SpawnSyncOptions;
};

/**
 * Docker's definitive answer that the *pinned* container does not exist, the
 * one negative that proves a heartbeat mismatch. Matched the way
 * `ingress-forwarder.ts` matches it: the exact diagnostic line naming this
 * exact id, never a bare substring — a nested "No such container: <other id>"
 * inside some other failure proves nothing about this one.
 */
export function provesContainerAbsent(stderr: string, containerId: string): boolean {
  const escaped = containerId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(
    `^(?:Error response from daemon: |Error: )?No such (?:container|object): ${escaped}\\s*$`,
    "imu",
  ).test(stderr.trim());
}

function unavailable(containerId: string, phase: string, observation: string): HeartbeatOutcome {
  return {
    kind: "unavailable",
    error: new RuntimeObservationError({
      kind: "observation-unavailable",
      subject: "session",
      expectedIdentity: containerId,
      phase,
      observation,
    }),
  };
}

/**
 * The caller's Docker options with a heartbeat bound on the exec: a caller may
 * tighten the timeout but never raise it (or drop it, which `spawnSync` reads
 * as "wait forever").
 */
function boundedExecOptions(dockerOptions: childProcess.SpawnSyncOptions): childProcess.SpawnSyncOptions {
  const requested = dockerOptions.timeout;
  const bounded = typeof requested === "number" && Number.isFinite(requested) && requested > 0
    ? Math.min(requested, SESSION_HEARTBEAT_EXEC_TIMEOUT_MS)
    : SESSION_HEARTBEAT_EXEC_TIMEOUT_MS;
  return { ...dockerOptions, timeout: bounded };
}

/**
 * Deletes this session's file, reporting rather than throwing. A delete that
 * cannot run leaves a file that will expire on its own lease; a delete of an
 * already-absent file exits 0, so repeating a mismatch is idempotent.
 */
function deleteSessionFile(
  io: SessionAdmissionDockerExecutor,
  proxyId: string,
  sessionKey: string,
  dockerOptions: childProcess.SpawnSyncOptions,
): boolean {
  try {
    executeSessionFileCommand(io, sessionFileDeleteCommand(proxyId, sessionKey), boundedExecOptions(dockerOptions));
    return true;
  } catch {
    return false;
  }
}

/**
 * The file this beat would publish. Called twice: once before Docker with a
 * stand-in nonce, only to prove the caller's record, display, and bindings can
 * produce a file the contract accepts, and once after the inspection has proved
 * the identity, to build the bytes that are actually written. Every identity
 * field is read from the record and the caller's network id at each call.
 */
function buildSessionFile(
  input: InspectAndWriteSessionFileInput,
  containerId: string,
  inspectedAtEpochMs: number,
  leaseMs: number,
  nonce: string,
): SessionFileV1 {
  return {
    v: SESSION_FILE_SCHEMA_VERSION,
    projectId: input.record.projectId,
    sessionKey: input.record.sessionPrincipal,
    sessionId: input.record.sessionId,
    sessionIncarnation: input.record.sessionIncarnation,
    sourceIp: input.record.sourceIp,
    containerId,
    networkId: input.networkId,
    selectedAgentImageId: input.eligibilityBindings.selectedAgentImageId,
    sessionAgentGenerationDigest: input.eligibilityBindings.sessionAgentGenerationDigest,
    controlPlaneGenerationDigest: input.eligibilityBindings.controlPlaneGenerationDigest,
    admissionContractEpoch: input.eligibilityBindings.admissionContractEpoch,
    name: input.display.name,
    command: input.display.command,
    ...(input.display.agentCommand !== undefined ? { agentCommand: input.display.agentCommand } : {}),
    ...(input.display.hostTty !== undefined ? { hostTty: input.display.hostTty } : {}),
    ...(input.display.hostTermProgram !== undefined ? { hostTermProgram: input.display.hostTermProgram } : {}),
    startedAt: input.display.startedAt,
    nonce,
    inspectedAt: new Date(inspectedAtEpochMs).toISOString(),
    aliveUntil: new Date(inspectedAtEpochMs + leaseMs).toISOString(),
  };
}

function mismatch(
  io: SessionAdmissionDockerExecutor,
  input: InspectAndWriteSessionFileInput,
  dockerOptions: childProcess.SpawnSyncOptions,
  observation: string,
): HeartbeatOutcome {
  return {
    kind: "mismatch",
    observation,
    deleted: deleteSessionFile(io, input.proxyId, input.record.sessionPrincipal, dockerOptions),
  };
}

export async function inspectAndWriteSessionFile(
  input: InspectAndWriteSessionFileInput,
): Promise<HeartbeatOutcome> {
  const { io, record, anchor } = input;
  const leaseMs = input.leaseMs ?? SESSION_ADMISSION_LEASE_MAX_DURATION_MS;
  const dockerOptions = input.dockerOptions ?? {};

  // Everything this block refuses is a caller-contract violation, refused
  // before Docker is reached and therefore with no captured effect: these are
  // programming errors, and neither a mismatch (which would delete a live
  // session's file) nor an unavailable outcome (which would hide the bug behind
  // a retry) would be an honest answer.
  if (!HEARTBEAT_STATES.has(record.state)) {
    throw new Error(`session file heartbeat is invalid while session-container state is ${record.state}`);
  }
  if (!Number.isSafeInteger(leaseMs) || leaseMs < 1 || leaseMs > SESSION_ADMISSION_LEASE_MAX_DURATION_MS) {
    throw new Error("session file heartbeat lease is invalid");
  }
  if (!DOCKER_OBJECT_ID_PATTERN.test(input.networkId)
    || !DOCKER_OBJECT_ID_PATTERN.test(anchor.networkEndpointId)
    || !Number.isSafeInteger(anchor.dockerPid)
    || anchor.dockerPid < 1
    || typeof anchor.dockerStartedAt !== "string"
    || !DOCKER_STARTED_AT_PATTERN.test(anchor.dockerStartedAt)
    || anchor.dockerStartedAt.startsWith("0001-")
    || !Number.isFinite(Date.parse(anchor.dockerStartedAt))) {
    throw new Error("session file heartbeat anchor is invalid");
  }
  // The bindings must be the ones this lifecycle record was admitted under.
  // They are passed separately because the caller owns the eligibility file
  // they have to match, not so they can name a different agent or epoch.
  if (input.eligibilityBindings.selectedAgentImageId !== record.selectedAgentImageId
    || input.eligibilityBindings.sessionAgentGenerationDigest !== record.sessionAgentGenerationDigest
    || input.eligibilityBindings.controlPlaneGenerationDigest !== record.controlPlaneGenerationDigest
    || input.eligibilityBindings.admissionContractEpoch !== record.admissionContractEpoch) {
    throw new Error("session file heartbeat eligibility bindings contradict the lifecycle record");
  }

  // Taken before the inspection, so the lease it grants is never longer than
  // the age of the proof behind it.
  const inspectedAtEpochMs = (input.nowEpochMs ?? Date.now)();

  // Also the point that proves the record is a valid lifecycle authority for
  // this project and carries an exact container id. Building the command runs
  // no Docker.
  const command = sessionContainerInspectCommand(record, input.expectedProject);
  const containerId = record.containerId as string;

  // Display fields come from the host environment (tty, term program, the
  // agent's own command line), so they can violate the contract's bounds
  // without anything being wrong with the session. Prove the file this beat
  // would publish is acceptable now, while a throw is still effect-free,
  // rather than after spending an inspection on it.
  const candidate = buildSessionFile(input, containerId, inspectedAtEpochMs, leaseMs, CANDIDATE_NONCE);
  if (!parseSessionFileV1(serializeSessionFileV1(candidate), candidate.sessionKey)) {
    throw new Error("session file heartbeat inputs cannot produce a valid session file");
  }

  let inspect: CaptureResult;
  try {
    inspect = executeSessionDockerCommand(command, (executable, args) => io.capture(executable, [...args], {
      ...dockerOptions,
      maxBuffer: SESSION_CONTAINER_INSPECT_MAX_BYTES,
      timeout: SESSION_HEARTBEAT_INSPECT_TIMEOUT_MS,
    }));
  } catch (error) {
    // The IO layer itself can refuse an observation (a budget, a closed
    // executor). That is a skipped beat, never evidence about the container.
    if (error instanceof RuntimeObservationError) return { kind: "unavailable", error };
    throw error;
  }

  // Classified by exit status alone: a Docker CLI warning on stderr beside a
  // zero exit is not a failed observation, and treating it as one would make a
  // healthy session permanently unservable. The answer's content is what the
  // narrow assertion below validates.
  if (inspect.status !== 0) {
    if (provesContainerAbsent(inspect.stderr, containerId)) {
      return mismatch(io, input, dockerOptions, inspect.stderr.trim());
    }
    return unavailable(
      containerId,
      "session-file-heartbeat-inspect",
      inspect.stderr.trim() || inspect.stdout.trim() || `exit ${inspect.status}`,
    );
  }

  try {
    assertSessionContainerNarrowRunningInspect(inspect.stdout, {
      containerId,
      composeProject: record.composeProject,
      networkId: input.networkId,
      sourceIp: record.sourceIp,
      ...anchor,
    });
  } catch (error) {
    // `assertSessionContainerNarrowRunningInspect` throws one plain Error per
    // rule, and this classifies its message. The refusals that prove nothing
    // about this incarnation may not delete anything (invariant 4); every
    // other message names a field the inspection did resolve, and resolved
    // differently, which is a mismatch.
    //
    // The set is imported from the module that throws it, rather than restated
    // here as text. A copy would let a rename over there silently reclassify a
    // skipped beat as a mismatch — and a mismatch deletes a live session's file.
    const observation = error instanceof Error ? error.message : String(error);
    if (NARROW_LIVENESS_UNREADABLE_INSPECT_MESSAGES.has(observation)) {
      return unavailable(containerId, "session-file-heartbeat-inspect", observation);
    }
    return mismatch(io, input, dockerOptions, observation);
  }

  // Only now, with this incarnation proved, are the identity fields copied into
  // the bytes that are written.
  const file = buildSessionFile(input, containerId, inspectedAtEpochMs, leaseMs, mintSessionFileNonce());
  try {
    executeSessionFileCommand(
      io,
      sessionFileWriteCommand(input.proxyId, file),
      boundedExecOptions(dockerOptions),
    );
  } catch (error) {
    if (error instanceof RuntimeObservationError) return { kind: "unavailable", error };
    throw error;
  }
  return { kind: "written", file };
}

/**
 * How long to wait before the next beat. A healthy heartbeat runs on the fixed
 * cadence; consecutive failures back off from 1 s, doubling to a 30 s cap, with
 * ±20 % jitter so a proxy restart does not resynchronize every session's retry.
 */
export function nextHeartbeatDelayMs(input: {
  consecutiveFailures: number;
  cadenceMs: number;
  random?: () => number;
}): number {
  if (!(input.consecutiveFailures > 0)) return input.cadenceMs;
  const base = Math.min(
    SESSION_HEARTBEAT_BACKOFF_MAX_MS,
    SESSION_HEARTBEAT_BACKOFF_BASE_MS * 2 ** (input.consecutiveFailures - 1),
  );
  const random = input.random ?? Math.random;
  return Math.round(base * (1 + (random() * 2 - 1) * SESSION_HEARTBEAT_BACKOFF_JITTER));
}
