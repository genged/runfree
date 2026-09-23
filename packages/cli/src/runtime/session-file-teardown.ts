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
// The three Docker commands are built and spent inside this function and never
// cross a boundary, so unlike the receipt-gated builders in
// `session-container-docker.ts` there is nothing here for a caller to smuggle
// argv through. They are receipt-free on purpose: a reconciling host that never
// created this container holds no creation receipt and, since this source
// publishes no snapshot, there is no revocation receipt for anyone to hold. The
// authority is the exact record plus the lock, checked before the first effect.

import type * as childProcess from "node:child_process";

import { SESSION_CONTAINER_STOP_SECONDS } from "./session-container-contract.ts";
import type {
  SessionContainerProjectIdentity,
  SessionContainerRecordV2,
} from "./session-containers.ts";
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
  dockerOptions?: childProcess.SpawnSyncOptions;
}>;

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

function capture(input: SessionFileTeardownInput, args: readonly string[]): CaptureResult {
  return input.io.capture("docker", [...args], input.dockerOptions ?? {});
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
    executeSessionFileCommand(
      input.io,
      sessionFileDeleteCommand(input.proxyId, input.record.sessionPrincipal),
      input.dockerOptions ?? {},
    );
  } catch (error) {
    return Object.freeze({ completed: false, blockedAt: "delete-session-file" as const, error });
  }

  // Step 2. Defense in depth, and tolerant of its own failure: the session has
  // no authority left whatever the endpoint says, and the removal below takes
  // the endpoint with the container. An already-disconnected or already-removed
  // container is exactly the state a rerun meets.
  input.lock();
  capture(input, ["network", "disconnect", target.networkId, target.containerId]);

  // Step 3. The agent's grace period. Tolerant for the same reason: a container
  // that has already exited, or that is already gone, is the state this step
  // was trying to reach.
  input.lock();
  capture(input, ["container", "stop", "--time", String(SESSION_CONTAINER_STOP_SECONDS), target.containerId]);

  // Step 4. The one container step that must succeed. `--force` because the
  // stop above already spent the SIGTERM grace, and a container that ignored it
  // must not be able to hold this session's record — and therefore its
  // address — forever. Docker's definitive "no such container" is success:
  // absence is the state this step exists to prove.
  input.lock();
  const removed = capture(input, ["container", "rm", "--force", target.containerId]);
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
