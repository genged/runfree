// The per-project run lock of headless runs (headless-run spec §3.5 "Project
// run lock", plan Task 10).
//
// Every headless run takes this lock before it launches; a second run in the
// same project is refused (exit 66) and does nothing. Interactive sessions
// never touch it. The lock lives under XDG state, never in the project.
//
//   <stateDir>/headless-run.lock/
//     boot, process-start, owner-token, pid   holder stamps (`stampLockOwner`)
//     session.json                            the session the holder allocated
//
// mkdir is the atomic acquire. The holder records its session's deterministic
// container name at allocation, before `docker container create`, and the
// exact id once create returns (plan C9), so a crash anywhere after allocation
// leaves a lock that names the container it may have left behind.
//
// A held lock is reclaimed only when its holder is dead, judged by the same
// rule as the project lifecycle lock (`lockHolderIsDead`), AND the recorded
// container is proven absent by Docker: an exact "No such container" answer
// for the exact id when known, else the exact name. Any other answer (Docker
// unreachable, the container present, a malformed record) keeps the lock. The
// reclaim path for that refusal is removing the dead run's container
// (`runfree sessions`, `runfree stop`), after which the next run reclaims.
//
// The holder releases the lock only after a confirmed teardown; after an
// unconfirmed one it keeps it, so no run starts beside a possible orphan.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { remedy } from "../remedies.ts";
import { atomicReplaceFile, statKind } from "../safe-fs.ts";
import { createDockerClient, type DockerIo } from "./docker-client.ts";
import { HEADLESS_RUN_ID_PATTERN } from "./headless-run-record.ts";
import { hostBootId, hostProcessStart } from "./host-identity.ts";
import { provesContainerAbsent } from "./session-file-heartbeat.ts";
import { SESSION_ID_PATTERN } from "./session-containers.ts";
import { projectSessionContainerFilters } from "./container-inventory.ts";
import { filterValues } from "./docker.ts";
import {
  lifecycleLockIdentity,
  lifecycleLockIsOwned,
  lockHolderIsDead,
  readLifecycleLockOwnerToken,
  removeExactLifecycleLock,
  stampLockOwner,
  type LifecycleLockIdentity,
} from "./sessions.ts";

export const HEADLESS_RUN_LOCK_DIRNAME = "headless-run.lock";
const SESSION_FILE = "session.json";
const SESSION_FILE_MAX_BYTES = 4 * 1024;
const CONTAINER_ID_PATTERN = /^[a-f0-9]{64}$/;
const CONTAINER_NAME_PATTERN = /^runfree-[a-f0-9]{12}-session-(rf-[0-9]{8}-[a-z0-9]{6,32})$/;
const INSPECT_TIMEOUT_MS = 5_000;
const INSPECT_MAX_BYTES = 1024 * 1024;
/**
 * How long a headless run's host session record is kept after it ends. It is
 * never offered by resume; it stays only so its window keeps that run's Codex
 * rollout from matching an overlapping interactive session.
 */
export const HEADLESS_SESSION_EVIDENCE_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const SESSION_EVIDENCE_MAX_BYTES = 64 * 1024;
/** The inbox prompt files headless runs write (`<runId>.prompt`). */
const INBOX_PROMPT_PATTERN = new RegExp(`^${HEADLESS_RUN_ID_PATTERN.source.slice(1, -1)}\\.prompt$`);

export function headlessRunLockPath(stateDir: string): string {
  return path.join(stateDir, HEADLESS_RUN_LOCK_DIRNAME);
}

/** What a held lock says about its holder; every field is the holder's claim. */
export type HeadlessRunLockHolder = Readonly<{
  pid?: number;
  sessionId?: string;
  containerName?: string;
  containerId?: string;
}>;

/** Another headless run holds the project lock, or its container is not proven gone (exit 66). */
export class HeadlessRunLockHeldError extends Error {
  readonly lockPath: string;
  readonly holder: HeadlessRunLockHolder;
  readonly reason: string;

  constructor(lockPath: string, holder: HeadlessRunLockHolder, reason: string) {
    const who = [
      holder.pid !== undefined ? `pid ${holder.pid}` : "no pid recorded",
      ...(holder.containerId ?? holder.containerName ? [`container ${holder.containerId ?? holder.containerName}`] : []),
    ].join(", ");
    super(
      `another headless run holds this project's run lock (${who}): ${reason}. `
        + `If that run is gone, find its session with \`${remedy.sessions()}\` and remove its container with `
        + `\`${remedy.stop()}\`; the next run then reclaims the lock. Lock: ${lockPath}`,
    );
    this.name = "HeadlessRunLockHeldError";
    this.lockPath = lockPath;
    this.holder = holder;
    this.reason = reason;
  }
}

export type HeadlessRunLock = Readonly<{
  path: string;
  /** Records the allocated session and its container name, before create. */
  recordSession(session: Readonly<{ sessionId: string; containerName: string }>): void;
  /** Records the exact container id once create returned. */
  recordContainer(containerId: string): void;
  /** Throws when this process no longer owns the lock. */
  assertHeld(): void;
  /** Removes the lock only if this process still owns it; throws otherwise. */
  release(): void;
}>;

export type AcquireHeadlessRunLockInput = Readonly<{
  stateDir: string;
  /** This project's id label, so a dead holder's unreadable session can be judged by the project's containers. */
  projectId: string;
  inboxDir: string;
  /** The project's host session records; headless ones past the retention are pruned. */
  sessionsDir: string;
  /** Runs `docker container inspect` for a dead holder's container. */
  io: DockerIo;
  env?: NodeJS.ProcessEnv;
}>;

type LockSessionRecord = { v: 1; sessionId: string; containerName: string; containerId?: string };


function lockError(message: string): Error {
  return new Error(`headless run lock ${message}`);
}

function validSessionRecord(sessionId: unknown, containerName: unknown, containerId?: unknown): string | undefined {
  if (typeof sessionId !== "string" || !SESSION_ID_PATTERN.test(sessionId)) return "the session id is malformed";
  if (typeof containerName !== "string" || CONTAINER_NAME_PATTERN.exec(containerName)?.[1] !== sessionId) {
    return "the container name is malformed";
  }
  if (containerId !== undefined && (typeof containerId !== "string" || !CONTAINER_ID_PATTERN.test(containerId))) {
    return "the container id is malformed";
  }
  return undefined;
}

type ReadSession =
  | { kind: "none" }
  | { kind: "recorded"; record: LockSessionRecord }
  | { kind: "malformed"; reason: string };

function readLockSession(lockPath: string): ReadSession {
  const filePath = path.join(lockPath, SESSION_FILE);
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(filePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { kind: "none" };
    return { kind: "malformed", reason: "its session record is unreadable" };
  }
  if (!stat.isFile() || stat.nlink !== 1) return { kind: "malformed", reason: `its session record is not a regular file (${statKind(stat)})` };
  if (stat.size > SESSION_FILE_MAX_BYTES) return { kind: "malformed", reason: "its session record is oversized" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return { kind: "malformed", reason: "its session record is not JSON" };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return { kind: "malformed", reason: "its session record is not an object" };
  const raw = parsed as Record<string, unknown>;
  const keys = Object.keys(raw).sort();
  const expected = ["containerName", "sessionId", "v", ...(Object.hasOwn(raw, "containerId") ? ["containerId"] : [])].sort();
  if (raw.v !== 1 || keys.join(",") !== expected.join(",")) return { kind: "malformed", reason: "its session record fields are malformed" };
  const invalid = validSessionRecord(raw.sessionId, raw.containerName, raw.containerId);
  if (invalid !== undefined) return { kind: "malformed", reason: `its session record is malformed: ${invalid}` };
  return {
    kind: "recorded",
    record: {
      v: 1,
      sessionId: raw.sessionId as string,
      containerName: raw.containerName as string,
      ...(raw.containerId !== undefined ? { containerId: raw.containerId as string } : {}),
    },
  };
}

function readHolderPid(lockPath: string): number | undefined {
  try {
    const pid = Number.parseInt(fs.readFileSync(path.join(lockPath, "pid"), "utf8").trim(), 10);
    return Number.isInteger(pid) && pid > 0 ? pid : undefined;
  } catch {
    return undefined;
  }
}

function holderOf(lockPath: string, session: ReadSession): HeadlessRunLockHolder {
  const pid = readHolderPid(lockPath);
  return {
    ...(pid !== undefined ? { pid } : {}),
    ...(session.kind === "recorded"
      ? {
        sessionId: session.record.sessionId,
        containerName: session.record.containerName,
        ...(session.record.containerId !== undefined ? { containerId: session.record.containerId } : {}),
      }
      : {}),
  };
}

type Judgement = { kind: "reclaim"; identity: LifecycleLockIdentity; ownerToken?: string } | { kind: "held"; error: HeadlessRunLockHeldError };

/**
 * Judges an existing lock. Reclaim needs a dead holder and, when it recorded
 * a session, Docker's exact answer that the container does not exist.
 */
function judgeExistingLock(lockPath: string, input: AcquireHeadlessRunLockInput): Judgement | undefined {
  const identity = lifecycleLockIdentity(lockPath);
  // Gone (or replaced by a non-directory) since mkdir failed: contend again.
  if (identity === undefined) return undefined;
  const ownerToken = readLifecycleLockOwnerToken(lockPath);
  const held = (reason: string, session = readLockSession(lockPath)): Judgement => ({ kind: "held", error: new HeadlessRunLockHeldError(lockPath, holderOf(lockPath, session), reason) });
  // Liveness first: a live holder is refused before any Docker call.
  if (!lockHolderIsDead(lockPath, input.env)) return held("its holder is still running");
  // Read only once the holder is dead: a session it recorded before dying is
  // then always seen, so reclaim needs that session's container gone.
  const session = readLockSession(lockPath);
  if (session.kind === "malformed") {
    // The record cannot name the container, so the project's own labels do:
    // Docker's complete list of this project's session containers, running
    // or not, must be empty before the lock is reclaimed. Before, this state
    // was a permanent 66 whose remedy (stop the recorded container) named a
    // container nobody could read.
    const listed = createDockerClient(input.io).listContainers({
      all: true,
      quiet: true,
      noTrunc: true,
      filters: filterValues(projectSessionContainerFilters(input.projectId)),
    }, { timeout: INSPECT_TIMEOUT_MS, maxBuffer: INSPECT_MAX_BYTES });
    if (listed.status !== 0 || listed.stderr.trim()) {
      return held(`${session.reason}, and Docker could not list this project's session containers (${listed.stderr.trim().split("\n")[0] || `exit ${listed.status}`})`, session);
    }
    const leftover = listed.stdout.trim().split(/\s+/u).filter(Boolean);
    if (leftover.length > 0) {
      return held(
        `${session.reason}, and this project still has ${leftover.length} session container(s) (${leftover.map((id) => id.slice(0, 12)).join(", ")}); `
          + `run \`${remedy.up()}\` to remove leftover session containers, then retry`,
        session,
      );
    }
    return { kind: "reclaim", identity, ...(ownerToken !== undefined ? { ownerToken } : {}) };
  }
  if (session.kind === "recorded") {
    const reference = session.record.containerId ?? session.record.containerName;
    const inspected = createDockerClient(input.io).inspect([reference], { type: "container" }, {
      timeout: INSPECT_TIMEOUT_MS,
      maxBuffer: INSPECT_MAX_BYTES,
    });
    if (inspected.status === 0) return held(`its holder exited, but its session container ${reference} still exists`, session);
    if (!provesContainerAbsent(inspected.stderr, reference)) {
      const observation = (inspected.stderr.trim() || inspected.stdout.trim() || `exit ${inspected.status}`).split("\n")[0];
      return held(`its holder exited, but Docker could not prove its session container ${reference} is gone (${observation})`, session);
    }
  }
  return { kind: "reclaim", identity, ...(ownerToken !== undefined ? { ownerToken } : {}) };
}

/**
 * Deletes stale `run-*.prompt` files from the inbox. Safe only under the
 * lock: no other headless run can be live while this process holds it, so
 * every such file was left by a run that crashed before its stop routine.
 * Other inbox files (pasted images) are not touched.
 */
function sweepStaleInboxPrompts(inboxDir: string): void {
  let entries: string[];
  try {
    const stat = fs.lstatSync(inboxDir);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw lockError(`refuses an inbox that is not a plain directory: ${inboxDir}`);
    entries = fs.readdirSync(inboxDir);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  for (const name of entries) {
    if (!INBOX_PROMPT_PATTERN.test(name)) continue;
    const filePath = path.join(inboxDir, name);
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(filePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    // unlink never follows a symlink; a directory is not ours to remove.
    if (!stat.isFile() && !stat.isSymbolicLink()) continue;
    try {
      fs.unlinkSync(filePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
}

/**
 * Deletes headless host session records that ended (or, after a crash, were
 * last seen) more than `HEADLESS_SESSION_EVIDENCE_RETENTION_MS` ago. Safe only
 * under the lock: no headless run is live. Interactive records, links, and
 * anything unreadable are left alone. Best effort: housekeeping never refuses
 * a run.
 */
function pruneExpiredHeadlessSessionRecords(sessionsDir: string, nowMs: number): void {
  let entries: string[];
  try {
    entries = fs.readdirSync(sessionsDir);
  } catch {
    return;
  }
  for (const name of entries) {
    const sessionId = name.endsWith(".json") ? name.slice(0, -".json".length) : "";
    if (!SESSION_ID_PATTERN.test(sessionId)) continue;
    const filePath = path.join(sessionsDir, name);
    try {
      const stat = fs.lstatSync(filePath);
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > SESSION_EVIDENCE_MAX_BYTES) continue;
      const fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
      let text: string;
      try {
        text = fs.readFileSync(fd, "utf8");
      } finally {
        fs.closeSync(fd);
      }
      const record: unknown = JSON.parse(text);
      if (record === null || typeof record !== "object" || Array.isArray(record)) continue;
      const fields = record as Record<string, unknown>;
      if (fields.id !== sessionId || fields.launchMode !== "headless") continue;
      const endedMs = Date.parse(String(fields.endedAt ?? fields.lastSeenAt ?? fields.startedAt));
      if (Number.isFinite(endedMs) && nowMs - endedMs > HEADLESS_SESSION_EVIDENCE_RETENTION_MS) fs.unlinkSync(filePath);
    } catch {
      // Unreadable or already gone: kept for the next run, or nothing to do.
    }
  }
}

/**
 * Takes the project's headless run lock, reclaiming a dead holder's lock only
 * when its container is proven absent, sweeps stale inbox prompts, and prunes
 * expired headless session records.
 * Throws `HeadlessRunLockHeldError` when the lock is held; that refusal has
 * no side effect beyond the Docker inspection of a dead holder's container.
 */
export function acquireHeadlessRunLock(input: AcquireHeadlessRunLockInput): HeadlessRunLock {
  const lockPath = headlessRunLockPath(input.stateDir);
  fs.mkdirSync(input.stateDir, { recursive: true, mode: 0o700 });
  // Resolved before mkdir, never inside the acquisition window (`stampLockOwner`).
  const bootId = hostBootId(input.env);
  const processStart = hostProcessStart(process.pid, input.env);
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const ownerToken = crypto.randomBytes(32).toString("hex");
    let identity: LifecycleLockIdentity | undefined;
    try {
      fs.mkdirSync(lockPath, { mode: 0o700 });
      identity = lifecycleLockIdentity(lockPath);
      if (identity === undefined) continue;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const judgement = judgeExistingLock(lockPath, input);
      if (judgement === undefined) continue;
      if (judgement.kind === "held") throw judgement.error;
      // Removes only the exact object judged. When that fails, a contender
      // replaced it in between, and the rename may even have moved the
      // contender's lock to quarantine, leaving the path free. Refuse rather
      // than contend again: nothing proved that contender dead or its
      // container gone. The next run judges whatever lock it then finds.
      if (!removeExactLifecycleLock(lockPath, judgement.identity, judgement.ownerToken)) {
        throw new HeadlessRunLockHeldError(lockPath, holderOf(lockPath, readLockSession(lockPath)), "another run took it while this one reclaimed it");
      }
      continue;
    }
    try {
      stampLockOwner(lockPath, bootId, processStart, ownerToken);
    } catch {
      removeExactLifecycleLock(lockPath, identity, readLifecycleLockOwnerToken(lockPath) === ownerToken ? ownerToken : undefined);
      continue;
    }
    const acquired = identity;
    if (!lifecycleLockIsOwned(lockPath, acquired, ownerToken)) {
      removeExactLifecycleLock(lockPath, acquired, ownerToken);
      continue;
    }
    let released = false;
    let session: LockSessionRecord | undefined;
    const assertHeld = (): void => {
      if (released || !lifecycleLockIsOwned(lockPath, acquired, ownerToken)) {
        throw lockError(`ownership was lost or replaced: ${lockPath}`);
      }
    };
    const writeSession = (next: LockSessionRecord): void => {
      assertHeld();
      atomicReplaceFile(path.join(lockPath, SESSION_FILE), `${JSON.stringify(next)}\n`);
      session = next;
    };
    const release = (): void => {
      if (released) return;
      if (!removeExactLifecycleLock(lockPath, acquired, ownerToken)) {
        throw lockError(`refuses to release a replaced lock: ${lockPath}`);
      }
      released = true;
    };
    try {
      sweepStaleInboxPrompts(input.inboxDir);
    } catch (error) {
      release();
      throw error;
    }
    pruneExpiredHeadlessSessionRecords(input.sessionsDir, Date.now());
    return Object.freeze({
      path: lockPath,
      recordSession({ sessionId, containerName }) {
        const invalid = validSessionRecord(sessionId, containerName);
        if (invalid !== undefined) throw lockError(`refuses to record a session: ${invalid}`);
        writeSession({ v: 1, sessionId, containerName });
      },
      recordContainer(containerId: string) {
        if (session === undefined) throw lockError("refuses a container id before its session is recorded");
        const invalid = validSessionRecord(session.sessionId, session.containerName, containerId);
        if (invalid !== undefined) throw lockError(`refuses to record a container: ${invalid}`);
        writeSession({ ...session, containerId });
      },
      assertHeld,
      release,
    });
  }
  throw new HeadlessRunLockHeldError(lockPath, holderOf(lockPath, readLockSession(lockPath)), "it could not be taken");
}
