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
import { processAlive } from "../runtime/sessions.ts";

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

export function withControlLock<T>(
  project: ProjectInfo,
  action: () => T,
  env: NodeJS.ProcessEnv = process.env,
): T {
  const lock = tryAcquireControlLock(project, env);
  if (!lock) throw new Error(`another control operation is in progress (${controlLockPath(project)})`);
  try {
    return action();
  } finally {
    lock.release();
  }
}
