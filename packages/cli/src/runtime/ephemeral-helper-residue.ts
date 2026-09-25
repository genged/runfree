// Ephemeral-helper residue: one host marker and a label sweep under the lock.
//
// An ephemeral helper runs the project's untrusted agent image under the
// lifecycle lock. A helper whose `docker run` client timed out, was killed, or
// whose CLI crashed can outlive the call, and a lingering helper holds a
// reserved address and blocks later probes. This module removes such helpers.
//
// Why a label sweep is enough: helpers run only while the project lifecycle
// lock is held. So when a holder observes this project's helpers, none of them
// belongs to a live run — each one is residue, or this holder's own failed run.
// The sweep selects by the project-id and helper-role labels together. Every
// container Runfree creates sets both explicitly (session agents, forwarders,
// the proxy, helpers), and an explicit `--label` overrides an inherited image
// LABEL, so an untrusted project image cannot make a session look like a
// helper. Only a Docker-socket holder can mint these labels on another
// container; the Docker daemon is trusted and the agent has no socket.
//
// The marker (`helpers-pending.json` in the host-owned project state dir) only
// avoids a Docker call on the common path: it is written before every spawn
// and cleared after a clean exit or a confirmed sweep. It grants nothing. A
// missing or malformed marker at worst skips or adds one sweep.
//
// Late create: a client killed with its create request in flight can leave the
// daemon to create the helper after the sweep found none. So the marker is kept,
// and every lock holder sweeps again, until the window has passed: 180 s after
// a killed client in this process (`lateCreateUntil`), or 180 s after the spawn
// (`writtenAt`) when the marker was left by a process that died. A container
// whose client was killed stays `created`. If only the CLI process died, its
// orphaned `docker run` client has no timeout and can still start the helper,
// even after the window; that helper is an unadmitted source the firewall
// drops, and a later deny probe that needs its address fails closed.
//
// Accepted residuals: a Docker-socket holder can mint the helper labels on a
// container the sweep then removes; two Runfree state roots (a development
// setup, or two users on one Docker daemon) driving the same project path do
// not share the lock, so one can sweep the other's running helper, which then
// fails that run closed.

import fs from "node:fs";
import path from "node:path";

import { CliError } from "../errors.ts";
import { remedy } from "../remedies.ts";
import { atomicReplaceFile } from "../safe-fs.ts";
import { projectEphemeralHelperFilters } from "./container-inventory.ts";
import { RuntimeObservationError, type RuntimeFailureKind } from "./observation-failure.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { CaptureResult, RuntimeIO } from "./types.ts";

export const HELPER_MARKER_FILE = "helpers-pending.json";
/** Per-run records from earlier releases; removed on sight, never trusted. */
export const LEGACY_HELPER_RUNS_DIRECTORY = "helper-runs";
const MAX_MARKER_BYTES = 1024;
const CONTAINER_ID_PATTERN = /^[a-f0-9]{64}$/u;

// Fixed per-call bounds. They are never budgeted: removal must be able to run
// after the lifecycle budget is spent.
const LIST_TIMEOUT_MS = 2_000;
const REMOVE_TIMEOUT_MS = 10_000;
const DEFAULT_POLL_DEADLINE_MS = 3_000;
const POLL_INTERVAL_MS = 200;
const MAX_BUFFER = 1024 * 1024;
// How long after a killed client a late create is still taken to be possible:
// the longest helper bound (120 s) plus a margin.
export const PENDING_CREATE_GRACE_MS = 180_000;

/**
 * What a helper run needs from its caller: the held lifecycle lock, the
 * unbudgeted IO used for removal, and the host-owned state dir of the marker.
 */
export type EphemeralHelperFence = Readonly<{
  lifecycleLock: Pick<ProjectLifecycleLock, "assertHeld">;
  containmentIO: Pick<RuntimeIO, "capture">;
  stateDir: string;
  /** Docker client environment for the sweep calls. */
  dockerEnv?: NodeJS.ProcessEnv;
}>;

export type HelperSweepOptions = Readonly<{
  /** How long the post-rm absence re-check may poll. */
  pollDeadlineMs?: number;
  sleep?: (milliseconds: number) => void;
  now?: () => number;
  /** Wall clock for the late-create window; defaults to `Date.now`. */
  wallClockMs?: () => number;
}>;

/** Removal of a helper could not be proven; the marker was kept for the next `up`. */
export class EphemeralHelperUnconfirmedError extends CliError {
  /** The failure kind of the helper run's own error, when it was an observation failure. */
  readonly failureKind?: RuntimeFailureKind;

  constructor(message: string, options: { cause?: unknown } = {}) {
    super(message);
    this.name = "EphemeralHelperUnconfirmedError";
    if (options.cause !== undefined) (this as { cause?: unknown }).cause = options.cause;
    if (options.cause instanceof RuntimeObservationError) this.failureKind = options.cause.evidence.kind;
  }

  /**
   * The same refusal, caused by the helper run's own failure (for example a
   * spent lifecycle budget) rather than by the sweep, so the original error
   * and its failure kind reach the caller.
   */
  withRunFailure(runFailure: unknown): EphemeralHelperUnconfirmedError {
    const detail = runFailure instanceof Error ? runFailure.message : String(runFailure);
    return new EphemeralHelperUnconfirmedError(`${this.message}; the helper run itself failed: ${detail}`, { cause: runFailure });
  }
}

function unconfirmed(reason: string, cause?: unknown): EphemeralHelperUnconfirmedError {
  return new EphemeralHelperUnconfirmedError(
    `ephemeral helpers could not be confirmed removed (${reason}); `
      + `run \`${remedy.up()}\` to retry, or \`${remedy.destroyForce()}\` to reset the project`,
    { cause },
  );
}

export function helperMarkerPath(stateDir: string): string {
  return path.join(stateDir, HELPER_MARKER_FILE);
}

export function legacyHelperRunsRoot(stateDir: string): string {
  return path.join(stateDir, LEGACY_HELPER_RUNS_DIRECTORY);
}

type HelperMarker = Readonly<{ v: 1; writtenAt?: string; lateCreateUntil?: string }>;

/**
 * Reads the marker. `undefined` means no marker. Anything present but not a
 * well-formed small regular file reads as a marker with no late-create window,
 * which only causes one sweep.
 */
export function readHelperMarker(stateDir: string): HelperMarker | undefined {
  const markerPath = helperMarkerPath(stateDir);
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(markerPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    return { v: 1 };
  }
  if (!stat.isFile() || stat.size > MAX_MARKER_BYTES) return { v: 1 };
  try {
    const parsed = JSON.parse(fs.readFileSync(markerPath, "utf8")) as unknown;
    const record = parsed as Record<string, unknown>;
    if (record?.v !== 1) return { v: 1 };
    const time = (value: unknown): string | undefined =>
      typeof value === "string" && !Number.isNaN(Date.parse(value)) ? value : undefined;
    const writtenAt = time(record.writtenAt);
    const lateCreateUntil = time(record.lateCreateUntil);
    return {
      v: 1,
      ...(writtenAt !== undefined ? { writtenAt } : {}),
      ...(lateCreateUntil !== undefined ? { lateCreateUntil } : {}),
    };
  } catch {
    return { v: 1 };
  }
}

function writeHelperMarker(stateDir: string, marker: HelperMarker): void {
  atomicReplaceFile(helperMarkerPath(stateDir), `${JSON.stringify(marker)}\n`);
}

function clearHelperMarker(stateDir: string): void {
  // `rmSync` unlinks a symlink rather than following it.
  fs.rmSync(helperMarkerPath(stateDir), { recursive: true, force: true });
}

/**
 * Records, durably and before the spawn, that a helper may exist. A marker
 * already present here was kept for an open late-create window (a clean or
 * confirmed run clears it), so that window is carried forward as
 * `lateCreateUntil` rather than lost when `writtenAt` moves.
 */
export function markHelperRunPending(stateDir: string, options: HelperSweepOptions = {}): void {
  const current = readHelperMarker(stateDir);
  const now = (options.wallClockMs ?? Date.now)();
  const carried = current ? openWindowUntil(current, true) : Number.NEGATIVE_INFINITY;
  writeHelperMarker(stateDir, {
    v: 1,
    writtenAt: new Date(now).toISOString(),
    ...(Number.isFinite(carried) ? { lateCreateUntil: new Date(carried).toISOString() } : {}),
  });
}

function openWindowUntil(marker: HelperMarker, leftBehind: boolean): number {
  return Math.max(
    marker.lateCreateUntil === undefined ? Number.NEGATIVE_INFINITY : Date.parse(marker.lateCreateUntil),
    leftBehind && marker.writtenAt !== undefined ? Date.parse(marker.writtenAt) + PENDING_CREATE_GRACE_MS : Number.NEGATIVE_INFINITY,
  );
}

/**
 * Clears the marker unless a late-create window is still open. `leftBehind`
 * marks a marker found at lock acquisition: its writer died, possibly with a
 * create in flight, so the window also runs from its spawn time. A future
 * time (clock skew) keeps the marker: it never settles early.
 */
function settleHelperMarker(stateDir: string, options: HelperSweepOptions, leftBehind: boolean): void {
  const marker = readHelperMarker(stateDir);
  if (!marker) return;
  if (openWindowUntil(marker, leftBehind) > (options.wallClockMs ?? Date.now)()) return;
  clearHelperMarker(stateDir);
}

type DockerStep = (args: string[], timeout: number) => CaptureResult;

function fencedDocker(fence: EphemeralHelperFence): DockerStep {
  return (args, timeout) => {
    fence.lifecycleLock.assertHeld();
    const result = fence.containmentIO.capture("docker", args, {
      env: fence.dockerEnv,
      timeout,
      killSignal: "SIGKILL",
      maxBuffer: MAX_BUFFER,
    });
    fence.lifecycleLock.assertHeld();
    return result;
  };
}

class ListingUnavailable extends Error {}

function listProjectHelpers(docker: DockerStep, projectId: string, timeout = LIST_TIMEOUT_MS): string[] {
  const listing = docker(["ps", "--all", "--quiet", "--no-trunc", ...projectEphemeralHelperFilters(projectId)], timeout);
  // A failed, timed-out, or killed listing is not an answer: an empty stdout
  // from it never proves absence (the spawn maps each to a non-zero status).
  // Stderr alone does not refuse: a Docker CLI that always prints a warning
  // would otherwise wedge every sweep. The stdout is validated id by id.
  if (listing.status !== 0) throw new ListingUnavailable("the helper listing is unavailable");
  const ids = [...new Set(listing.stdout.split(/\s+/u).filter(Boolean))];
  if (ids.some((id) => !CONTAINER_ID_PATTERN.test(id))) throw new Error("the helper listing returned a non-id line");
  return ids;
}

function sleepSync(milliseconds: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

/**
 * Removes every container carrying this project's id and the helper role, and
 * returns how many it found. Only an observed empty listing is success; the
 * absence is polled (bounded) because Docker's own `--rm` can race the removal.
 */
export function sweepProjectHelpers(
  fence: EphemeralHelperFence,
  projectId: string,
  options: HelperSweepOptions = {},
): number {
  const docker = fencedDocker(fence);
  try {
    const found = listProjectHelpers(docker, projectId);
    if (found.length === 0) return 0;
    docker(["rm", "--force", ...found], REMOVE_TIMEOUT_MS);
    const now = options.now ?? (() => performance.now());
    const sleep = options.sleep ?? sleepSync;
    const deadline = now() + (options.pollDeadlineMs ?? DEFAULT_POLL_DEADLINE_MS);
    for (;;) {
      const remaining = deadline - now();
      let left: string[] | undefined;
      try {
        left = listProjectHelpers(docker, projectId, Math.min(LIST_TIMEOUT_MS, Math.max(250, remaining)));
      } catch (error) {
        if (!(error instanceof ListingUnavailable)) throw error;
      }
      if (left?.length === 0) return found.length;
      if (now() >= deadline) {
        throw new Error(left === undefined ? "the helper listing is unavailable" : `${left.length} helper(s) still present after rm`);
      }
      sleep(Math.min(POLL_INTERVAL_MS, Math.max(1, deadline - now())));
    }
  } catch (error) {
    if (error instanceof EphemeralHelperUnconfirmedError) throw error;
    throw unconfirmed(error instanceof Error ? error.message : String(error), error);
  }
}

/**
 * Settles one run in the process that spawned it. A clean exit means `--rm`
 * already removed the container, so no Docker call is made. Anything else is
 * swept; a client that may have died mid-create also opens the late-create
 * window. A sweep that cannot be confirmed keeps the marker and throws.
 */
export function settleHelperRun(
  fence: EphemeralHelperFence,
  projectId: string,
  outcome: Readonly<{ clean: boolean; clientKilled: boolean }>,
  options: HelperSweepOptions = {},
): void {
  if (!outcome.clean) {
    if (outcome.clientKilled) {
      const current = readHelperMarker(fence.stateDir);
      const until = Math.max(
        (options.wallClockMs ?? Date.now)() + PENDING_CREATE_GRACE_MS,
        current?.lateCreateUntil === undefined ? Number.NEGATIVE_INFINITY : Date.parse(current.lateCreateUntil),
      );
      writeHelperMarker(fence.stateDir, {
        v: 1,
        ...(current?.writtenAt !== undefined ? { writtenAt: current.writtenAt } : {}),
        lateCreateUntil: new Date(until).toISOString(),
      });
    }
    sweepProjectHelpers(fence, projectId, options);
  }
  fence.lifecycleLock.assertHeld();
  settleHelperMarker(fence.stateDir, options, false);
}

/**
 * Run by every lock holder before its first helper or admission. With no
 * marker and no legacy record directory it costs two `lstat` calls and no
 * Docker call. Otherwise it sweeps, removes the legacy directory, and clears
 * the marker unless a late-create window is still open.
 *
 * A marker whose late-create window is still open does not refuse the launch:
 * it holds no authority, and a late container carries the helper labels, so a
 * later sweep removes it.
 */
export function reclaimHelperResidue(
  fence: EphemeralHelperFence,
  projectId: string,
  options: HelperSweepOptions = {},
): { swept: number } {
  const legacyRoot = legacyHelperRunsRoot(fence.stateDir);
  const legacy = fs.existsSync(legacyRoot) || isSymlink(legacyRoot);
  if (!readHelperMarker(fence.stateDir) && !legacy) return { swept: 0 };
  fence.lifecycleLock.assertHeld();
  const swept = sweepProjectHelpers(fence, projectId, options);
  fence.lifecycleLock.assertHeld();
  // `rmSync` unlinks a symlinked root rather than following it.
  if (legacy) fs.rmSync(legacyRoot, { recursive: true, force: true });
  settleHelperMarker(fence.stateDir, options, true);
  return { swept };
}

function isSymlink(target: string): boolean {
  try {
    return fs.lstatSync(target).isSymbolicLink();
  } catch {
    return false;
  }
}

/** Destroy's reset: every project container is already gone. */
export function removeHelperState(stateDir: string): void {
  clearHelperMarker(stateDir);
  fs.rmSync(legacyHelperRunsRoot(stateDir), { recursive: true, force: true });
}
