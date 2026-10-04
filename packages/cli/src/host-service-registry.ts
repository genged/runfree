// The host-global port registry (SR13, HS7).
//
// Every project's effective, approved host-service ports are recorded in one
// registry under XDG state — the first host-global (not per-project) state
// this CLI keeps. Its purpose is narrow: keep Runfree's own loopback
// publications (`forward`, `vnc`, the per-session MCP OAuth callback) off a
// port another project approved as a host service, so a later command in one
// project can never shadow or hijack a bridge another project's agent relies
// on.
//
// Writers run under a directory lock copied from `control/lock.ts` (owner.json
// with pid, host boot id, and process start; a stale holder is reclaimed by
// renaming the lock aside before removing it) — this is a second, independent
// instance of that scheme because the lock here guards one host-global file
// rather than one project's control directory, not a new scheme. Readers never
// take the lock: the registry file is always replaced atomically, so a
// concurrent reader either sees the old complete file or the new one.
//
// A corrupt or unreadable registry fails closed for `forward` and `vnc` (they
// refuse rather than risk a port another project approved); the MCP callback
// keeps its own fixed port block, which a host-service port can never occupy
// (Task 1 statically refuses 47100-48099 and 5901 as host-service ports), so
// an unreadable registry never changes its safety there. The reclaim path is
// `repairHostServicePortRegistry`, driven by `runfree host-service list
// --repair` (Task 9).

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { parseStrictJson } from "./control/strict-json.ts";
import { remedy } from "./remedies.ts";
import { runfreeStateRoot } from "./paths.ts";
import { projectHash } from "./project-identity.ts";
import {
  compareHostBootId,
  compareHostProcessStart,
  hostBootId,
  hostProcessStart,
  processAlive,
} from "./runtime/host-identity.ts";
import {
  assertNoSymlinkPath,
  assertOptionalNormalProjectDirectory,
  ensureSafeProjectDir,
  safeReplaceProjectFile,
} from "./safe-fs.ts";
import { isRecord, readBoundedRegularFile } from "./strict-primitives.ts";

const REGISTRY_FILE_NAME = "host-service-ports.json";
const LOCK_DIR_NAME = "host-service-ports.lock";
const PROJECT_ID_RE = /^[0-9a-f]{12}$/;
const PORT_KEY_RE = /^[1-9][0-9]{0,4}$/;
const MAX_REGISTRY_BYTES = 4 * 1024 * 1024;

// Matches `control/lock.ts`'s PIDLESS_GRACE_MS exactly: a lock directory with
// no readable owner.json is reclaimed only once it has aged past this, so a
// holder that is mid-write (mkdir succeeded, owner.json not yet written) is
// never torn down from under it.
const PIDLESS_GRACE_MS = 5_000;

// A held, live lock blocks a writer only for this long in total before it
// reports contention; this is a host-global file multiple concurrent
// `runfree` invocations (different projects, different terminals) can
// legitimately race to update, so a brief wait is cheap and avoids spurious
// failures a fail-fast acquire (as in `control/lock.ts`, scoped to one
// project and rarely contended) would not need.
const LOCK_RETRY_ATTEMPTS = 50;
const LOCK_RETRY_DELAY_MS = 100;

function isValidPort(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= 65535;
}

function registryFilePath(stateRoot: string): string {
  return path.join(stateRoot, REGISTRY_FILE_NAME);
}

function lockDirPath(stateRoot: string): string {
  return path.join(stateRoot, LOCK_DIR_NAME);
}

// ---------------------------------------------------------------------------
// Lock: copied from `control/lock.ts`, parameterized on a raw directory path
// instead of a per-project `ProjectInfo`, because this lock guards one
// host-global file rather than one project's control directory.
// ---------------------------------------------------------------------------

type RegistryLockOwner = {
  createdAt: string;
  hostBootId?: string;
  hostProcessStart?: string;
  nonce: string;
  pid: number;
  schemaVersion: 1;
};

function ownerJsonPath(lockDir: string): string {
  return path.join(lockDir, "owner.json");
}

function reclaimDirPath(lockDir: string): string {
  return `${lockDir}.reclaim`;
}

function readLockOwner(lockDir: string): RegistryLockOwner | undefined {
  try {
    return JSON.parse(fs.readFileSync(ownerJsonPath(lockDir), "utf8")) as RegistryLockOwner;
  } catch {
    return undefined;
  }
}

function lockIsStale(lockDir: string, env: NodeJS.ProcessEnv): boolean {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(lockDir);
  } catch {
    return true;
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) return false;
  const owner = readLockOwner(lockDir);
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

type RegistryLock = { release(): void };

function tryAcquireRegistryLock(stateRoot: string, env: NodeJS.ProcessEnv): RegistryLock | undefined {
  const lockDir = lockDirPath(stateRoot);
  fs.mkdirSync(stateRoot, { recursive: true, mode: 0o700 });
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      fs.mkdirSync(lockDir, { mode: 0o700 });
    } catch (error) {
      if (!(error instanceof Error) || !("code" in error) || error.code !== "EEXIST") throw error;
      if (!lockIsStale(lockDir, env)) return undefined;
      const reclaim = reclaimDirPath(lockDir);
      try {
        fs.renameSync(lockDir, reclaim);
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
    fs.rmSync(reclaimDirPath(lockDir), { recursive: true, force: true });
    const boot = hostBootId(env);
    const start = hostProcessStart(process.pid, env);
    const nonce = randomUUID();
    const owner: RegistryLockOwner = {
      schemaVersion: 1,
      pid: process.pid,
      nonce,
      createdAt: new Date().toISOString(),
      ...(boot ? { hostBootId: boot } : {}),
      ...(start ? { hostProcessStart: start } : {}),
    };
    try {
      fs.writeFileSync(ownerJsonPath(lockDir), `${JSON.stringify(owner, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    } catch {
      fs.rmSync(lockDir, { recursive: true, force: true });
      continue;
    }
    return {
      release() {
        if (readLockOwner(lockDir)?.nonce !== nonce) return;
        fs.rmSync(lockDir, { recursive: true, force: true });
      },
    };
  }
  return undefined;
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function withRegistryLock<T>(stateRoot: string, env: NodeJS.ProcessEnv, action: () => T): T {
  let lock = tryAcquireRegistryLock(stateRoot, env);
  for (let attempt = 1; !lock && attempt < LOCK_RETRY_ATTEMPTS; attempt += 1) {
    sleepSync(LOCK_RETRY_DELAY_MS);
    lock = tryAcquireRegistryLock(stateRoot, env);
  }
  if (!lock) {
    throw new Error(`another host-service port registry operation is in progress (${lockDirPath(stateRoot)})`);
  }
  try {
    return action();
  } finally {
    lock.release();
  }
}

// ---------------------------------------------------------------------------
// Registry file shape and validation.
// ---------------------------------------------------------------------------

type RegistryProjectRow = Readonly<{
  projectRoot: string;
  ports: readonly number[];
  owners?: Readonly<Record<string, string>>;
  updatedAt: string;
}>;

type RegistryFile = Readonly<{
  schemaVersion: 1;
  projects: Readonly<Record<string, RegistryProjectRow>>;
}>;

function parseRegistryFile(parsed: unknown): RegistryFile {
  if (!isRecord(parsed)) throw new Error("host service port registry must be a JSON object");
  if (parsed.schemaVersion !== 1) throw new Error("host service port registry has an unsupported schema version");
  if (!isRecord(parsed.projects)) throw new Error("host service port registry is missing a projects object");

  const projects: Record<string, RegistryProjectRow> = {};
  const seenPorts = new Map<number, string>();
  for (const [projectId, rawRow] of Object.entries(parsed.projects)) {
    if (!PROJECT_ID_RE.test(projectId)) {
      throw new Error(`host service port registry has an invalid project id: ${projectId}`);
    }
    if (!isRecord(rawRow)) throw new Error(`host service port registry row for ${projectId} must be an object`);
    if (typeof rawRow.projectRoot !== "string" || rawRow.projectRoot === "") {
      throw new Error(`host service port registry row for ${projectId} is missing a project root`);
    }
    if (!Array.isArray(rawRow.ports) || rawRow.ports.length === 0 || !rawRow.ports.every(isValidPort)) {
      throw new Error(`host service port registry row for ${projectId} has an invalid ports list`);
    }
    const ports = rawRow.ports as number[];
    const uniquePorts = new Set(ports);
    if (uniquePorts.size !== ports.length) {
      throw new Error(`host service port registry row for ${projectId} has duplicate ports`);
    }
    for (const port of ports) {
      const existing = seenPorts.get(port);
      if (existing !== undefined && existing !== projectId) {
        throw new Error(`host service port registry has port ${port} registered by more than one project`);
      }
      seenPorts.set(port, projectId);
    }
    let owners: Record<string, string> | undefined;
    if (rawRow.owners !== undefined) {
      if (!isRecord(rawRow.owners)) {
        throw new Error(`host service port registry row for ${projectId} has an invalid owners map`);
      }
      owners = {};
      for (const [key, value] of Object.entries(rawRow.owners)) {
        if (!PORT_KEY_RE.test(key) || !ports.includes(Number(key))) {
          throw new Error(`host service port registry row for ${projectId} has an owner for an unregistered port: ${key}`);
        }
        if (typeof value !== "string" || value === "") {
          throw new Error(`host service port registry row for ${projectId} has an invalid owner for port ${key}`);
        }
        owners[key] = value;
      }
    }
    if (typeof rawRow.updatedAt !== "string" || Number.isNaN(Date.parse(rawRow.updatedAt))) {
      throw new Error(`host service port registry row for ${projectId} has an invalid updatedAt`);
    }
    projects[projectId] = Object.freeze({
      projectRoot: rawRow.projectRoot,
      ports: Object.freeze([...ports]),
      ...(owners ? { owners: Object.freeze(owners) } : {}),
      updatedAt: rawRow.updatedAt,
    });
  }
  return Object.freeze({ schemaVersion: 1, projects: Object.freeze(projects) });
}

/** Reads the registry for a mutation: missing is empty, anything unsafe or invalid throws. */
function readRegistryFileForMutation(stateRoot: string): RegistryFile {
  const filePath = registryFilePath(stateRoot);
  assertOptionalNormalProjectDirectory(stateRoot, stateRoot, "host service port registry state root");
  assertNoSymlinkPath(stateRoot, filePath, { allowMissingPath: true });
  const read = readBoundedRegularFile(filePath, {
    maxBytes: MAX_REGISTRY_BYTES,
    sizeRecheck: "exact",
    notFileMessage: (file) => `host service port registry is not a bounded regular single-link file: ${file}`,
    changedMessage: (file) => `host service port registry changed during read: ${file}`,
  });
  if (!read) return { schemaVersion: 1, projects: {} };
  return parseRegistryFile(parseStrictJson(read.source));
}

function writeRegistryFile(stateRoot: string, file: RegistryFile): void {
  const filePath = registryFilePath(stateRoot);
  if (!fs.existsSync(stateRoot)) fs.mkdirSync(stateRoot, { recursive: true, mode: 0o700 });
  ensureSafeProjectDir(stateRoot, path.dirname(filePath), 0o700);
  safeReplaceProjectFile(stateRoot, filePath, `${JSON.stringify(file, null, 2)}\n`, 0o600);
}

// ---------------------------------------------------------------------------
// Known-project discovery for repair, mirroring the enumeration in
// `runtime/recovery.ts` (`scanRecoveryInventory`/`projectMapping`): every
// `<runfreeStateRoot>/projects/<projectId>/project.json` pointer whose
// recorded root still hashes back to its own directory name.
// ---------------------------------------------------------------------------

function knownProjectPointers(stateRoot: string): Array<{ id: string; root: string }> {
  const projectsRoot = path.join(stateRoot, "projects");
  let directory: fs.Dir;
  try {
    directory = fs.opendirSync(projectsRoot);
  } catch {
    return [];
  }
  const result: Array<{ id: string; root: string }> = [];
  try {
    while (true) {
      const entry = directory.readSync();
      if (!entry) break;
      if (!entry.isDirectory() || !PROJECT_ID_RE.test(entry.name)) continue;
      const pointerPath = path.join(projectsRoot, entry.name, "project.json");
      let parsed: unknown;
      try {
        const stat = fs.lstatSync(pointerPath);
        if (!stat.isFile() || stat.isSymbolicLink()) continue;
        parsed = parseStrictJson(fs.readFileSync(pointerPath, "utf8"));
      } catch {
        continue;
      }
      if (!isRecord(parsed) || typeof parsed.projectRoot !== "string" || parsed.projectRoot === "") continue;
      const root = path.resolve(parsed.projectRoot);
      if (projectHash(root) !== entry.name) continue;
      result.push({ id: entry.name, root });
    }
  } finally {
    directory.closeSync();
  }
  return result;
}

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

export type HostServicePortRegistryRead =
  | { ok: true; owners: ReadonlyMap<number, { projectId: string; projectRoot: string; command?: string }> }
  | { ok: false; reason: string };

/** Read-only: never takes the lock, and the only filesystem access is this one bounded read. */
export function readHostServicePortRegistry(env: NodeJS.ProcessEnv): HostServicePortRegistryRead {
  const stateRoot = runfreeStateRoot(env);
  const filePath = registryFilePath(stateRoot);
  try {
    assertOptionalNormalProjectDirectory(stateRoot, stateRoot, "host service port registry state root");
    assertNoSymlinkPath(stateRoot, filePath, { allowMissingPath: true });
    const read = readBoundedRegularFile(filePath, {
      maxBytes: MAX_REGISTRY_BYTES,
      sizeRecheck: "exact",
      notFileMessage: (file) => `host service port registry is not a bounded regular single-link file: ${file}`,
      changedMessage: (file) => `host service port registry changed during read: ${file}`,
    });
    if (!read) return { ok: true, owners: new Map() };
    const file = parseRegistryFile(parseStrictJson(read.source));
    const owners = new Map<number, { projectId: string; projectRoot: string; command?: string }>();
    for (const [projectId, row] of Object.entries(file.projects)) {
      for (const port of row.ports) {
        const command = row.owners?.[String(port)];
        owners.set(port, {
          projectId,
          projectRoot: row.projectRoot,
          ...(command !== undefined ? { command } : {}),
        });
      }
    }
    return { ok: true, owners };
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : String(error) };
  }
}

/** Runs under the lock. An empty `ports` list removes the project's row. */
export function recordProjectHostServicePorts(
  env: NodeJS.ProcessEnv,
  project: { id: string; root: string },
  ports: readonly number[],
  owners?: Readonly<Record<number, string>>,
): void {
  if (!PROJECT_ID_RE.test(project.id)) {
    throw new Error(`invalid project id for the host service port registry: ${project.id}`);
  }
  for (const port of ports) {
    if (!isValidPort(port)) throw new Error(`invalid host service port: ${port}`);
  }
  const stateRoot = runfreeStateRoot(env);
  withRegistryLock(stateRoot, env, () => {
    const current = readRegistryFileForMutation(stateRoot);
    const projects: Record<string, RegistryProjectRow> = { ...current.projects };
    if (ports.length === 0) {
      delete projects[project.id];
    } else {
      const previousRow = current.projects[project.id];
      const sortedPorts = [...new Set(ports)].sort((left, right) => left - right);
      const ownersMap: Record<string, string> = {};
      for (const port of sortedPorts) {
        const key = String(port);
        const supplied = owners?.[port];
        if (supplied !== undefined) {
          ownersMap[key] = supplied;
        } else if (previousRow?.owners?.[key] !== undefined) {
          ownersMap[key] = previousRow.owners[key];
        }
      }
      projects[project.id] = {
        projectRoot: project.root,
        ports: sortedPorts,
        ...(Object.keys(ownersMap).length > 0 ? { owners: ownersMap } : {}),
        updatedAt: new Date().toISOString(),
      };
    }
    writeRegistryFile(stateRoot, { schemaVersion: 1, projects });
  });
}

/** Runs under the lock. Idempotent: a project with no row is left alone. */
export function removeProjectHostServicePorts(env: NodeJS.ProcessEnv, projectId: string): void {
  const stateRoot = runfreeStateRoot(env);
  withRegistryLock(stateRoot, env, () => {
    const current = readRegistryFileForMutation(stateRoot);
    if (!(projectId in current.projects)) return;
    const projects: Record<string, RegistryProjectRow> = { ...current.projects };
    delete projects[projectId];
    writeRegistryFile(stateRoot, { schemaVersion: 1, projects });
  });
}

/**
 * Reclaim: rebuilds the whole registry from each known project's own answer
 * (typically its selected effective generation's `hostServices`), discarding
 * whatever the file on disk said — including a corrupt file, which this never
 * reads. A project `readProjectPorts` reports no ports for is simply absent
 * from the rebuilt file.
 */
export function repairHostServicePortRegistry(
  env: NodeJS.ProcessEnv,
  readProjectPorts: (projectRoot: string, projectId: string) => readonly number[] | undefined,
): { projects: number; ports: number } {
  const stateRoot = runfreeStateRoot(env);
  return withRegistryLock(stateRoot, env, () => {
    const projects: Record<string, RegistryProjectRow> = {};
    let projectCount = 0;
    let portCount = 0;
    for (const { id, root } of knownProjectPointers(stateRoot)) {
      const ports = readProjectPorts(root, id);
      if (!ports || ports.length === 0) continue;
      const sortedPorts = [...new Set(ports)].sort((left, right) => left - right);
      projects[id] = { projectRoot: root, ports: sortedPorts, updatedAt: new Date().toISOString() };
      projectCount += 1;
      portCount += sortedPorts.length;
    }
    writeRegistryFile(stateRoot, { schemaVersion: 1, projects });
    return { projects: projectCount, ports: portCount };
  });
}

/**
 * Whether `port` is off-limits to this (optional) project's own runfree-managed
 * publications: approved by a *different* project, or unknown because the
 * registry could not be read (fails closed). `undefined` means the port is
 * free to use.
 */
export function registeredHostServicePortRefusal(
  env: NodeJS.ProcessEnv,
  port: number,
  ownProjectId?: string,
): string | undefined {
  const read = readHostServicePortRegistry(env);
  if (!read.ok) {
    return `the host-service port registry could not be read (${read.reason}); `
      + `refusing to risk a port another project approved as a host service - run \`${remedy.hostServiceRepair()}\``;
  }
  const owner = read.owners.get(port);
  if (!owner || owner.projectId === ownProjectId) return undefined;
  return `port ${port} is already approved as a host service for the project at ${owner.projectRoot}; `
    + "pick a different port, or remove that approval there before reusing it here";
}
