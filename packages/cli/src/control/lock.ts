import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import type { ProjectInfo } from "../config.ts";
import {
  compareHostBootId,
  compareHostProcessStart,
  hostBootId,
  hostProcessStart,
} from "../runtime/host-identity.ts";
import {
  PROJECT_LIFECYCLE_LOCK_RETRY_ATTEMPTS,
  PROJECT_LIFECYCLE_LOCK_RETRY_DELAY_MS,
  PROJECT_LIFECYCLE_LOCK_RETRY_WINDOW_MS,
  processAlive,
} from "../runtime/sessions.ts";
import { runfreeLog } from "../warnings.ts";

const PIDLESS_GRACE_MS = 5_000;

type ControlLockOwner = {
  createdAt: string;
  hostBootId?: string;
  hostProcessStart?: string;
  nonce: string;
  pid: number;
  schemaVersion: 1;
};

export type ControlLock = { release(): void };

export function controlLockPath(project: ProjectInfo): string {
  return path.join(project.paths.controlDir, "control.lock");
}

function ownerPath(lockPath: string): string {
  return path.join(lockPath, "owner.json");
}

function reclaimPath(lockPath: string): string {
  return `${lockPath}.reclaim`;
}

function readOwner(lockPath: string): ControlLockOwner | undefined {
  try {
    return JSON.parse(fs.readFileSync(ownerPath(lockPath), "utf8")) as ControlLockOwner;
  } catch {
    return undefined;
  }
}

function staleLock(lockPath: string, env: NodeJS.ProcessEnv): boolean {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(lockPath);
  } catch {
    return true;
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) return false;
  const owner = readOwner(lockPath);
  if (!owner) return Date.now() - stat.mtimeMs >= PIDLESS_GRACE_MS;
  if (owner.schemaVersion !== 1 || !Number.isSafeInteger(owner.pid) || owner.pid <= 0) return false;
  const boot = compareHostBootId(owner.hostBootId, env);
  if (boot === "mismatch") return true;
  if (!processAlive(owner.pid)) return true;
  if (boot === "match") {
    const start = compareHostProcessStart(owner.hostProcessStart, owner.pid, env);
    if (start === "mismatch") return true;
  }
  return false;
}

export function tryAcquireControlLock(
  project: ProjectInfo,
  env: NodeJS.ProcessEnv = process.env,
): ControlLock | undefined {
  const lockPath = controlLockPath(project);
  fs.mkdirSync(project.paths.controlDir, { recursive: true, mode: 0o700 });
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      fs.mkdirSync(lockPath, { mode: 0o700 });
    } catch (error) {
      if (!(error instanceof Error) || !("code" in error) || error.code !== "EEXIST") throw error;
      if (!staleLock(lockPath, env)) return undefined;
      const reclaim = reclaimPath(lockPath);
      try {
        fs.renameSync(lockPath, reclaim);
      } catch (reclaimError) {
        if (reclaimError instanceof Error && "code" in reclaimError) {
          if (reclaimError.code === "EEXIST") return undefined;
          if (reclaimError.code === "ENOENT") continue;
        }
        throw reclaimError;
      }
      fs.rmSync(reclaim, { recursive: true, force: true });
      continue;
    }
    fs.rmSync(reclaimPath(lockPath), { recursive: true, force: true });
    const boot = hostBootId(env);
    const start = hostProcessStart(process.pid, env);
    const nonce = randomUUID();
    const owner: ControlLockOwner = {
      schemaVersion: 1,
      pid: process.pid,
      nonce,
      createdAt: new Date().toISOString(),
      ...(boot ? { hostBootId: boot } : {}),
      ...(start ? { hostProcessStart: start } : {}),
    };
    try {
      fs.writeFileSync(ownerPath(lockPath), `${JSON.stringify(owner, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    } catch {
      fs.rmSync(lockPath, { recursive: true, force: true });
      continue;
    }
    return {
      release() {
        if (readOwner(lockPath)?.nonce !== nonce) return;
        fs.rmSync(lockPath, { recursive: true, force: true });
      },
    };
  }
  return undefined;
}

/**
 * The control lock is held by another live operation. Distinct from every
 * other failure so that a caller that may wait (a launch's control
 * preparation) can tell contention from a real error.
 */
export class ControlLockBusyError extends Error {
  readonly lockPath: string;

  constructor(lockPath: string) {
    super(`another control operation is in progress (${lockPath})`);
    this.name = "ControlLockBusyError";
    this.lockPath = lockPath;
  }
}

export function withControlLock<T>(
  project: ProjectInfo,
  action: () => T,
  env: NodeJS.ProcessEnv = process.env,
): T {
  const lock = tryAcquireControlLock(project, env);
  if (!lock) throw new ControlLockBusyError(controlLockPath(project));
  try {
    return action();
  } finally {
    lock.release();
  }
}

export type ControlLockWaitOptions = {
  attempts?: number;
  delayMs?: number;
  diagnosticIntervalMs?: number;
  log?: (message: string) => void;
  now?: () => number;
  windowMs?: number;
};

/**
 * Runs `attempt` again while it fails with `ControlLockBusyError`. Retrying
 * stops at whichever comes first: `windowMs` of wall-clock time since the
 * first busy failure (by default the window another command waits for the
 * project lifecycle lock), or `attempts` tries. The clock matters because
 * one attempt can itself take long (it may wait for the lifecycle lock or for
 * an interactive answer), so a count of tries alone does not bound the wait.
 * Any other error propagates at once, and the last busy error propagates
 * unchanged when the bound is reached.
 *
 * The caller must hold no lock across the wait: each attempt has to take and
 * release its own locks, so a busy error leaves nothing held while this sleeps.
 * A lock left by a dead or earlier-boot owner is not contention:
 * `tryAcquireControlLock` reclaims it on the next try.
 */
export async function waitWhileControlLockBusy<T>(
  project: ProjectInfo,
  attempt: () => T | Promise<T>,
  options: ControlLockWaitOptions = {},
): Promise<T> {
  const attempts = options.attempts ?? PROJECT_LIFECYCLE_LOCK_RETRY_ATTEMPTS;
  const delayMs = options.delayMs ?? PROJECT_LIFECYCLE_LOCK_RETRY_DELAY_MS;
  const windowMs = options.windowMs ?? PROJECT_LIFECYCLE_LOCK_RETRY_WINDOW_MS;
  const diagnosticIntervalMs = options.diagnosticIntervalMs ?? 5_000;
  const log = options.log ?? runfreeLog;
  const now = options.now ?? Date.now;
  if (!Number.isSafeInteger(attempts) || attempts < 1) {
    throw new Error("control lock wait attempts must be a positive integer");
  }
  if (!Number.isSafeInteger(delayMs) || delayMs < 1) {
    throw new Error("control lock wait delay must be a positive integer");
  }
  if (!Number.isSafeInteger(windowMs) || windowMs < 0) {
    throw new Error("control lock wait window must be a non-negative integer");
  }
  let firstBusyAt: number | undefined;
  let nextDiagnosticAt = 0;
  for (let tried = 1; ; tried += 1) {
    try {
      return await attempt();
    } catch (error) {
      if (!(error instanceof ControlLockBusyError)) throw error;
      const busyAt = now();
      if (firstBusyAt === undefined) {
        firstBusyAt = busyAt;
        nextDiagnosticAt = busyAt + diagnosticIntervalMs;
      }
      if (tried >= attempts || busyAt - firstBusyAt >= windowMs) throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    const waitedAt = now();
    if (waitedAt >= nextDiagnosticAt) {
      const elapsedSeconds = Math.max(1, Math.round((waitedAt - firstBusyAt) / 1_000));
      log(`waiting for the project control lock (${elapsedSeconds}s; lock: ${controlLockPath(project)})`);
      nextDiagnosticAt = waitedAt + diagnosticIntervalMs;
    }
  }
}
