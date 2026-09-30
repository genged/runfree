// Ending one session in the only order that is safe: the file first, the host
// record last.
//
// The session file IS the authority. The proxy serves a session because a file
// names it, so the first thing teardown must do is take that file away;
// everything after it — the network endpoint, the container,
// the record — is cleanup of something that can no longer be used. The record
// goes last because it is what reserves the session's address: while it exists
// no peer may be allocated that address, so keeping it is exactly the right
// answer to "this host could not finish".
//
// That gives the one refusal in here its shape. A delete this host could not
// perform is not proof the file is gone, so the sequence stops and reports
// `blockedAt: "delete-session-file"`: no disconnect, no stop, no remove, and
// above all no record removal, because releasing the address of a session that
// may still be served is how two containers end up sharing one identity. The
// reclamation is that the same call, run again — by this owner's second cleanup
// pass, or by the next launch's reconcile once this owner is gone — finishes
// the steps it was not allowed to start.
//
// Nothing here transitions the record. Under this source the durable record
// stays exactly what it was until it is deleted, and the marker that says "this
// is terminal cleanup, not a session" is the host status stamp the caller
// writes in step 0. That is what a peer's preflight reads, and what a later
// reconcile reads, so it must be written before the file is touched.
//
// Every step is fenced by the caller's lock assertion, because the whole
// sequence is one indivisible transition from a live session to no session:
// a peer that observed it half-done would see a record it may neither admit
// beside nor reclaim.
//
// The three Docker commands come from the validated builders in
// `session-container-docker.ts` and are spent inside this function, so there
// is nothing here for a caller to smuggle argv through. They are receipt-free
// on purpose: a reconciling host that never created this container holds no
// creation receipt and, since this source publishes no snapshot, there is no
// revocation receipt for anyone to hold. The authority is the exact record plus
// the lock, checked before the first effect.
//
// A normal exit takes a shorter path: with an exact proof that the anchored
// incarnation has already exited, the disconnect and the stop grace are
// skipped and the file delete is followed directly by the forced removal. The
// order that matters — file first, record last — is the same on both paths.

import type * as childProcess from "node:child_process";

import { CliError } from "../errors.ts";
import { remedy } from "../remedies.ts";
import { SESSION_CONTAINER_STOP_SECONDS } from "./session-container-contract.ts";
import {
  executeSessionDockerCommand,
  sessionContainerNetworkDisconnectCommand,
  sessionContainerRemoveCommand,
  sessionContainerStopCommand,
  type SessionDockerCommand,
} from "./session-container-docker.ts";
import type {
  SessionContainerProjectIdentity,
  SessionContainerRecordV2,
} from "./session-containers.ts";
import { removeSessionMcpCallbackIngress } from "./session-callback-ingress.ts";
import { provesContainerAbsent } from "./session-file-heartbeat.ts";
import {
  executeSessionFileCommand,
  sessionFileDeleteCommand,
  type SessionAdmissionDockerExecutor,
} from "./session-file-publisher.ts";
import type { CaptureResult } from "./types.ts";

const DOCKER_OBJECT_ID_PATTERN = /^[a-f0-9]{64}$/;

export type SessionFileTeardownInput = Readonly<{
  io: SessionAdmissionDockerExecutor;
  /** The proxy whose session directory holds this session's file. */
  proxyId: string;
  record: SessionContainerRecordV2;
  expectedProject: SessionContainerProjectIdentity;
  /** The internal network the session container is attached to. */
  networkId: string;
  /**
   * Asserts the project lifecycle lock, before every step.
   *
   * Passed in rather than assumed because the two callers hold it differently:
   * a launch owner reacquired it for teardown, a reconciling launch holds it
   * for its whole preflight.
   */
  lock: () => void;
  /**
   * Writes the `terminal: "revoking"` host status stamp for this session.
   *
   * Advisory, exactly like every other stamp write: it must not throw, and a
   * stamp this host could not write is never grounds for leaving a session
   * file in place.
   */
  markTerminal: () => void;
  /** Clears this session's host status stamp. Runs only after the record is gone. */
  clearStamp: () => void;
  /**
   * Removes this session's durable record by its exact identity.
   *
   * `false` means the record file was already gone, which is the state this
   * step exists to reach; a record that changed under the caller throws from
   * `removeExactSessionContainerRecordV2` itself.
   */
  removeRecord: () => boolean;
  /**
   * How the session ended, as far as this caller can prove it.
   *
   * Asked once, under the lock, right after the session file is proved gone,
   * so the observation that picks the short path is taken with no authority
   * left to lose and never delays the revocation. Required, so no caller can
   * reach the short path by omission. Only the launch owner can return an
   * `exited` proof (minted from one exact inspection by
   * `proveSessionContainerExited`); reconcile always answers
   * `UNCERTAIN_SESSION_COMPLETION`. A throw reads as uncertain.
   */
  completion: () => SessionTeardownCompletion;
  /**
   * Replaces step 1's `docker exec` delete, for a caller that proves the file
   * cannot exist rather than deleting it.
   *
   * Startup's reclaim of an interrupted teardown passes a fresh proof that the
   * selected proxy is absent or stopped: session files live on its tmpfs, so a
   * proxy with no running process holds none, and there is nothing to `exec`
   * into. Throwing blocks exactly like a failed delete — nothing after step 1
   * runs and the record is kept. Omitted, the ordinary delete runs.
   */
  removeSessionFile?: () => void;
  dockerOptions?: childProcess.SpawnSyncOptions;
}>;

declare const sessionContainerExitProofBrand: unique symbol;

/**
 * Proof, from one exact `docker container inspect`, that the anchored
 * container incarnation has exited on its own with the status the foreground
 * reported. Minted only by `proveSessionContainerExited`; a copy or a
 * hand-built object is not one.
 */
export type SessionContainerExitProof = Readonly<{
  readonly [sessionContainerExitProofBrand]: true;
  containerId: string;
  startedAt: string;
  exitCode: number;
}>;

export type SessionTeardownCompletion =
  | Readonly<{ kind: "exited"; proof: SessionContainerExitProof }>
  | Readonly<{ kind: "uncertain" }>;

export const UNCERTAIN_SESSION_COMPLETION: SessionTeardownCompletion = Object.freeze({ kind: "uncertain" });

const exitProofs = new WeakSet<object>();

function exactIsoTime(value: unknown): number | undefined {
  if (typeof value !== "string") return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

/**
 * Judges one inspection as proof that this exact incarnation exited by itself.
 *
 * Every condition must hold, or there is no proof and teardown keeps the full
 * sequence with its stop grace (sub-second launch plan Task 8; review Q6): one
 * object; the exact id; the admitted `StartedAt` (a restarted or recreated
 * container is a different incarnation); not running, restarting, or paused;
 * `Status` exited or dead; `FinishedAt` not before `StartedAt`; the exit code
 * the foreground reported; and restart policy `no`, so nothing will start it
 * again between this read and the removal.
 */
export function proveSessionContainerExited(
  inspectStdout: string,
  expected: Readonly<{ containerId: string; startedAt: string; exitCode: number }>,
): SessionContainerExitProof | undefined {
  if (!DOCKER_OBJECT_ID_PATTERN.test(expected.containerId)) return undefined;
  if (!Number.isSafeInteger(expected.exitCode) || expected.exitCode < 0 || expected.exitCode > 255) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(inspectStdout);
  } catch {
    return undefined;
  }
  if (!Array.isArray(parsed) || parsed.length !== 1) return undefined;
  const container: unknown = parsed[0];
  if (!container || typeof container !== "object") return undefined;
  if (Reflect.get(container, "Id") !== expected.containerId) return undefined;
  const state: unknown = Reflect.get(container, "State");
  if (!state || typeof state !== "object") return undefined;
  if (Reflect.get(state, "Running") !== false
    || Reflect.get(state, "Restarting") === true
    || Reflect.get(state, "Paused") === true) {
    return undefined;
  }
  const status = Reflect.get(state, "Status");
  if (status !== "exited" && status !== "dead") return undefined;
  if (Reflect.get(state, "StartedAt") !== expected.startedAt) return undefined;
  const startedAt = exactIsoTime(expected.startedAt);
  const finishedAt = exactIsoTime(Reflect.get(state, "FinishedAt"));
  if (startedAt === undefined || finishedAt === undefined || finishedAt < startedAt) return undefined;
  if (Reflect.get(state, "ExitCode") !== expected.exitCode) return undefined;
  const hostConfig: unknown = Reflect.get(container, "HostConfig");
  const restartPolicy: unknown = hostConfig && typeof hostConfig === "object"
    ? Reflect.get(hostConfig, "RestartPolicy")
    : undefined;
  if (!restartPolicy || typeof restartPolicy !== "object" || Reflect.get(restartPolicy, "Name") !== "no") {
    return undefined;
  }
  const proof = Object.freeze({
    containerId: expected.containerId,
    startedAt: expected.startedAt,
    exitCode: expected.exitCode,
  }) as SessionContainerExitProof;
  exitProofs.add(proof);
  return proof;
}

/**
 * The launch-facing refusal for a session file this host could not delete.
 *
 * A plain status with the remedy, not an aggregate of internal failures: the
 * address stays reserved by the record, and the next `runfree up` (or the next
 * launch's reconcile, once this owner is gone) finishes the teardown.
 */
export class SessionFileTeardownBlockedError extends CliError {
  constructor(cause: unknown) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    super(
      "the session's network authority could not be revoked: its proxy session file was not deleted "
      + `(${detail}); the session record and its address stay reserved; run \`${remedy.up()}\` to finish the teardown`,
    );
    this.name = "SessionFileTeardownBlockedError";
    this.cause = cause;
  }
}

export type SessionFileTeardownResult =
  | Readonly<{ completed: true }>
  | Readonly<{ completed: false; blockedAt: "delete-session-file"; error: unknown }>;

/**
 * The exact container this teardown may act on.
 *
 * Refuses before the first effect: a record from another project, an
 * unbound record, or a network id that is not an exact Docker object id.
 * These are the same gates the receipt-carrying builders apply, minus the
 * receipt this source does not mint.
 */
function exactTeardownTarget(input: SessionFileTeardownInput): Readonly<{
  containerId: string;
  networkId: string;
}> {
  const { record, expectedProject } = input;
  if (record.projectId !== expectedProject.projectId
    || record.composeProject !== expectedProject.composeProject) {
    throw new Error("session teardown record belongs to a different project");
  }
  const containerId = record.containerId;
  if (containerId === undefined || !DOCKER_OBJECT_ID_PATTERN.test(containerId)) {
    throw new Error("session teardown requires an exact container id");
  }
  if (!DOCKER_OBJECT_ID_PATTERN.test(input.networkId)) {
    throw new Error("session network id must be an exact Docker object id");
  }
  return Object.freeze({ containerId, networkId: input.networkId });
}

function execute(input: SessionFileTeardownInput, command: SessionDockerCommand): CaptureResult {
  return executeSessionDockerCommand(
    command,
    (executable, args) => input.io.capture(executable, [...args], input.dockerOptions ?? {}),
  );
}

function exitedProofFor(input: SessionFileTeardownInput, containerId: string): SessionContainerExitProof | undefined {
  let completion: SessionTeardownCompletion;
  try {
    completion = input.completion();
  } catch {
    return undefined;
  }
  if (completion.kind !== "exited") return undefined;
  const proof = completion.proof;
  return exitProofs.has(proof) && proof.containerId === containerId ? proof : undefined;
}

/**
 * Ends one session.
 *
 * Ordered and idempotent: safe to run twice, and safe to run against objects
 * that are already gone. Shared by the launch owner (which runs it from its
 * own teardown) and by reconcile (which runs it for a dead owner's residue),
 * so the order is a property of this function rather than of either caller.
 */
export function teardownSessionRecord(input: SessionFileTeardownInput): SessionFileTeardownResult {
  const target = exactTeardownTarget(input);

  // Step 0. The marker that this record is terminal cleanup rather than a
  // session, written before the file is touched so a crash anywhere below
  // leaves evidence a later reconcile can act on.
  input.lock();
  input.markTerminal();

  // Step 1. The authority itself. Only proof that the file is gone allows any
  // of the steps below to run.
  input.lock();
  try {
    if (input.removeSessionFile) {
      input.removeSessionFile();
    } else {
      executeSessionFileCommand(
        input.io,
        sessionFileDeleteCommand(input.proxyId, input.record.sessionPrincipal),
        input.dockerOptions ?? {},
      );
    }
  } catch (error) {
    return Object.freeze({ completed: false, blockedAt: "delete-session-file" as const, error });
  }

  // Step 1b. The session's host ingress. Its MCP OAuth callback forwarder
  // routes host loopback to this record's address, so it must be proved gone
  // before step 5 releases that address to a peer. A failure throws: the
  // record stays, the address stays reserved, and the same call run again
  // (this owner's second pass, or the next launch's reconcile) retries it.
  // The short path below runs it too: the forwarder outlives the container.
  input.lock();
  removeSessionMcpCallbackIngress({
    io: input.io,
    ...(input.dockerOptions ? { dockerOptions: input.dockerOptions } : {}),
    projectId: input.expectedProject.projectId,
    sessionId: input.record.sessionId,
    sourceIp: input.record.sourceIp,
  });

  // Steps 2 and 3 exist for a container that may still be running. An exact
  // proof that this incarnation already exited (a normal exit, sub-second
  // launch plan Task 8) skips both: there is no process left to give a grace
  // period to, and the removal below takes the endpoint with the container.
  // Anything short of that proof keeps the full sequence.
  if (exitedProofFor(input, target.containerId) === undefined) {
    // Step 2. Defense in depth, and tolerant of its own failure: the session
    // has no authority left whatever the endpoint says, and the removal below
    // takes the endpoint with the container. An already-disconnected or
    // already-removed container is exactly the state a rerun meets.
    input.lock();
    execute(input, sessionContainerNetworkDisconnectCommand(target.networkId, target.containerId));

    // Step 3. The agent's grace period. Tolerant for the same reason: a
    // container that has already exited, or that is already gone, is the state
    // this step was trying to reach.
    input.lock();
    execute(input, sessionContainerStopCommand(target.containerId, SESSION_CONTAINER_STOP_SECONDS));
  }

  // Step 4. The one container step that must succeed. `--force` because the
  // stop above already spent the SIGTERM grace (or the container had already
  // exited), and a container that ignored it must not be able to hold this
  // session's record — and therefore its address — forever. Docker's
  // definitive "no such container" is success: absence is the state this step
  // exists to prove.
  input.lock();
  const removed = execute(input, sessionContainerRemoveCommand(target.containerId));
  if (removed.status !== 0 && !provesContainerAbsent(removed.stderr, target.containerId)) {
    throw new Error(
      `Docker failed to remove the torn-down session container: ${removed.stderr.trim() || removed.stdout.trim() || `exit ${removed.status}`}`,
    );
  }

  // Step 5. Last, because this is what releases the session's address.
  input.lock();
  input.removeRecord();
  input.clearStamp();
  return Object.freeze({ completed: true as const });
}
