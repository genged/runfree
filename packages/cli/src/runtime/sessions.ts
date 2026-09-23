import { RuntimeObservationError } from "./observation-failure.ts";
import crypto from "node:crypto";
import { enqueueSessionRenewal, sessionRenewalQueueHead, SESSION_RENEWAL_WAIT_BUDGET_MS } from "./session-renewal-queue.ts";
import fs from "node:fs";
import path from "node:path";

import { SESSION_DISPLAY_NAME_MAX_CHARACTERS } from "@runfree/runtime-contracts/session-registry";

import {
  BUILTIN_AGENT_DESCRIPTORS,
  builtinAgent,
  type BuiltinAgentDescriptor,
} from "../agents.ts";
import { inboxContainerDir } from "../inbox.ts";
import { formatTerminalTable } from "../terminal-table.ts";
import { flushWarnings, runfreeLog, warn } from "../warnings.ts";
import { AGENT_UID_GID, RECENT_SESSION_START_MS } from "./constants.ts";
import {
  dockerClientEnvOptions,
  envOptions,
  serviceContainerId,
  type RuntimeDocker,
} from "./docker.ts";
import { composeProjectName, projectHash } from "./env.ts";
import {
  compareHostBootId,
  compareHostProcessStart,
  hostBootId,
  hostProcessStart,
  processAlive,
  recordedOnPreviousBoot,
} from "./host-identity.ts";
export { processAlive } from "./host-identity.ts";
import { readEffectiveControlPlaneV2 } from "./component-state-v2.ts";
import {
  peekSessionContainerRecordsV2,
  SESSION_CONTAINER_LEASE_MAX_DURATION_MS,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import { reportSessionReconciliation } from "./session-reconcile.ts";
import { readSessionHostStatus, type SessionHostStatusV1 } from "./session-host-status.ts";
import { classifySessionRecordLiveness } from "./session-record-liveness.ts";
import type {
  ActiveAgentSession,
  RuntimeContext,
  RuntimeIO,
  SessionMetadata,
  SessionProcess,
} from "./types.ts";
import { remedy } from "../remedies.ts";

export type ProjectLifecycleLock = {
  readonly ownerToken: string;
  assertHeld(): void;
  release(): void;
};

/**
 * Owns the project lifecycle lock for one foreground session driver.
 *
 * Admission and teardown run while `lock` is held. Once the session is
 * attached, the manager releases the underlying directory lock so other
 * sessions and control-plane operations can use the project. Session lease renewal
 * temporarily reacquires the same lock through `withLock`, and `reacquire`
 * restores it before teardown.
 */
export type SessionLockManager = Readonly<{
  lock: ProjectLifecycleLock;
  releaseForWait(): void;
  withLock<T>(
    operation: () => Promise<T>,
    signal: AbortSignal,
  ): Promise<T>;
  reacquire(): Promise<void>;
  close(): void;
}>;

export class SessionLockAcquisitionAbortedError extends Error {
  constructor(lockPath: string) {
    super(`session lifecycle lock acquisition was cancelled after foreground completion (lock: ${lockPath})`);
    this.name = "SessionLockAcquisitionAbortedError";
  }
}

export class SessionLockAcquisitionTimeoutError extends Error {
  constructor(lockPath: string, timeoutMs: number) {
    super(`timed out after ${timeoutMs}ms waiting to reacquire the project lifecycle lock (lock: ${lockPath})`);
    this.name = "SessionLockAcquisitionTimeoutError";
  }
}

export type RebuildOptions = {
  recoveryRetry?: boolean;
  assumeYes?: boolean;
  useApprovedPolicy?: boolean;
  verbose?: boolean;
};

export type CreateSessionMetadataOptions = {
  name?: string;
  now?: Date;
  /**
   * Reuses an already-minted Runfree session id instead of minting one, so a
   * per-session container's host evidence carries the exact lifecycle record
   * `sessionId`. Must match the current session id format.
   */
  id?: string;
  /** Exact session container name for per-session launches; provenance only. */
  sessionContainerName?: string;
  /** Exact conversation a resume launch targets; lineage for re-crash evidence. */
  resumeConversationId?: string;
};

const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/u;
const SAFE_SESSION_RECORD_ID = /^rf-[a-z0-9][a-z0-9-]{0,79}$/;
const CURRENT_SESSION_ID = /^rf-[0-9]{8}-[a-z0-9]{6,32}$/;
const MAX_SESSION_METADATA_BYTES = 64 * 1024;

function compactCommand(command: string): string {
  const compact = command.replace(/\s+/g, " ").trim();
  if (compact.length <= 120) return compact;
  return `${compact.slice(0, 117)}...`;
}

function basename(value: string): string {
  return value.split("/").filter(Boolean).at(-1) ?? value;
}

export function normalizeSessionName(value: unknown): string {
  if (typeof value !== "string") throw new Error("session name must be a string");
  if (CONTROL_CHARACTERS.test(value)) throw new Error("session name must not contain control characters");
  const normalized = value.trim();
  const length = Array.from(normalized).length;
  if (length === 0) throw new Error("session name must not be empty");
  if (length > SESSION_DISPLAY_NAME_MAX_CHARACTERS) {
    throw new Error(`session name must be at most ${SESSION_DISPLAY_NAME_MAX_CHARACTERS} characters`);
  }
  return normalized;
}

function fallbackPart(value: string | undefined, maximum: number): string | undefined {
  if (!value) return undefined;
  const compact = value.replace(/[\u0000-\u001f\u007f-\u009f]/gu, " ").replace(/\s+/g, " ").trim();
  if (!compact) return undefined;
  return Array.from(compact).slice(0, maximum).join("");
}

function fallbackCommand(command: string): string {
  const normalized = command.trim().toLowerCase();
  return builtinAgent(normalized)?.id
    ?? (normalized === "shell" ? "shell" : fallbackPart(normalized, 24))
    ?? "session";
}

function fallbackTerminal(hostTty: string | undefined, termProgram: string | undefined): string | undefined {
  const tty = fallbackPart(hostTty ? basename(hostTty) : undefined, 24);
  if (tty) return tty;
  const terminal = termProgram?.replace(/^Apple_/, "").replaceAll("_", " ");
  return fallbackPart(terminal, 24);
}

function fallbackTime(startedAt: string | undefined): string | undefined {
  if (!startedAt) return undefined;
  const timestamp = Date.parse(startedAt);
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString().slice(11, 16) : undefined;
}

export function synthesizeSessionName(input: {
  command: string;
  hostTty?: string;
  termProgram?: string;
  startedAt?: string;
}): string {
  return normalizeSessionName([
    fallbackCommand(input.command),
    fallbackTerminal(input.hostTty, input.termProgram),
    fallbackTime(input.startedAt),
  ].filter((part): part is string => part !== undefined).join(" "));
}

function displayCommandFromTokens(tokens: string[], startIndex: number): string {
  const command = basename(tokens[startIndex] ?? "");
  const args = tokens.slice(startIndex + 1);
  return compactCommand([command, ...args].filter(Boolean).join(" "));
}

export function sessionCommandLabel(command: string): string {
  const normalized = command.trim().toLowerCase();
  const descriptor = builtinAgent(normalized);
  if (descriptor) return descriptor.label;
  if (normalized === "shell") return "Shell";
  return command.trim() || "<unknown command>";
}

function descriptorForProcessName(name: string): BuiltinAgentDescriptor | undefined {
  return BUILTIN_AGENT_DESCRIPTORS.find((descriptor) => descriptor.processNames.includes(name));
}

export function sessionProcessDescription(command: string): { command: string; score: number } {
  const tokens = command.replace(/\s+/g, " ").trim().split(" ").filter(Boolean);
  for (const [index, token] of tokens.entries()) {
    const name = basename(token);
    const descriptor = descriptorForProcessName(name);
    if (descriptor) {
      return { command: `${descriptor.label}: ${displayCommandFromTokens(tokens, index)}`, score: 100 };
    }
  }

  const first = basename(tokens[0] ?? "");
  if (["bash", "fish", "sh", "zsh"].includes(first)) {
    return { command: `Shell: ${first}`, score: 10 };
  }

  return {
    command: compactCommand(tokens.length === 0 ? command : [first, ...tokens.slice(1)].join(" ")),
    score: 50,
  };
}

function sessionStatePath(context: RuntimeContext, sessionId: string): string {
  assertSafeSessionId(sessionId);
  return path.join(context.project.paths.sessionsDir, `${sessionId}.json`);
}

function randomSessionSuffix(context: RuntimeContext): string {
  const testValue = context.env?.RUNFREE_TEST_SESSION_RANDOM ?? process.env.RUNFREE_TEST_SESSION_RANDOM;
  if (testValue && /^[a-z0-9]{6,32}$/.test(testValue)) return testValue;
  return crypto.randomBytes(3).toString("hex");
}

export function createSessionId(context: RuntimeContext, now = new Date()): string {
  const date = now.toISOString().slice(0, 10).replaceAll("-", "");
  return `rf-${date}-${randomSessionSuffix(context)}`;
}

export function captureHostTty(context: RuntimeContext, io: RuntimeIO): string | undefined {
  if (!process.stdin.isTTY) return undefined;
  const result = io.capture("tty", [], {
    ...envOptions(context.env),
    stdio: ["inherit", "pipe", "ignore"],
  });
  if (result.status !== 0) return undefined;
  const value = result.stdout.trim();
  return value === "" || value === "not a tty" ? undefined : value;
}

function optionalEnv(env: NodeJS.ProcessEnv | undefined, name: string): string | undefined {
  const value = env?.[name];
  return value && value.trim() !== "" ? value : undefined;
}

export function createSessionMetadata(
  context: RuntimeContext,
  io: RuntimeIO,
  command: string,
  agentCommand?: string,
  options: CreateSessionMetadataOptions = {},
): SessionMetadata {
  const now = (options.now ?? new Date()).toISOString();
  const bootId = hostBootId(context.env);
  const processStart = hostProcessStart(process.pid, context.env);
  const hostTty = captureHostTty(context, io);
  const termProgram = optionalEnv(context.env, "TERM_PROGRAM");
  const termProgramVersion = optionalEnv(context.env, "TERM_PROGRAM_VERSION");
  const termSessionId = optionalEnv(context.env, "TERM_SESSION_ID");
  const itermSessionId = optionalEnv(context.env, "ITERM_SESSION_ID");
  const wtSession = optionalEnv(context.env, "WT_SESSION");
  const requestedName = options.name ?? optionalEnv(context.env, "RUNFREE_SESSION_NAME");
  const name = requestedName === undefined
    ? synthesizeSessionName({ command, hostTty, termProgram, startedAt: now })
    : normalizeSessionName(requestedName);
  if (options.id !== undefined) assertSafeSessionId(options.id, true);
  const metadata: SessionMetadata = {
    id: options.id ?? createSessionId(context),
    projectRoot: context.projectRoot,
    composeProject: composeProjectName(context.projectRoot),
    command,
    name,
    ...(agentCommand ? { agentCommand } : {}),
    hostPid: process.pid,
    ...(bootId ? { hostBootId: bootId } : {}),
    ...(processStart ? { hostProcessStart: processStart } : {}),
    ...(options.sessionContainerName !== undefined ? { sessionContainerName: options.sessionContainerName } : {}),
    ...(options.resumeConversationId !== undefined ? { resumeConversationId: options.resumeConversationId } : {}),
    hostInbox: context.project.paths.inboxDir,
    containerInbox: inboxContainerDir(),
    ...(process.ppid ? { hostParentPid: process.ppid } : {}),
    ...(hostTty ? { hostTty } : {}),
    ...(termProgram ? { termProgram } : {}),
    ...(termProgramVersion ? { termProgramVersion } : {}),
    ...(termSessionId ? { termSessionId } : {}),
    ...(itermSessionId ? { itermSessionId } : {}),
    ...(wtSession ? { wtSession } : {}),
    startedAt: now,
    lastSeenAt: now,
  };
  return metadata;
}

function assertSafeSessionId(sessionId: string, currentOnly = false): void {
  const pattern = currentOnly ? CURRENT_SESSION_ID : SAFE_SESSION_RECORD_ID;
  if (!pattern.test(sessionId)) throw new Error(`invalid Runfree session id: ${sessionId || "<empty>"}`);
}

function ensureSafeSessionsDirectory(context: RuntimeContext): void {
  const sessionsDir = context.project.paths.sessionsDir;
  try {
    fs.mkdirSync(sessionsDir, { recursive: true, mode: 0o700 });
  } catch (error) {
    if (!error || typeof error !== "object" || !("code" in error) || error.code !== "EEXIST") throw error;
  }
  const stat = fs.lstatSync(sessionsDir);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error("Runfree sessions state path is not a safe directory");
  }
}

function readSessionMetadataSource(context: RuntimeContext, sessionId: string): string | undefined {
  assertSafeSessionId(sessionId);
  const sourcePath = sessionStatePath(context, sessionId);
  let before: fs.Stats;
  try {
    before = fs.lstatSync(sourcePath);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
  if (!before.isFile()
    || before.isSymbolicLink()
    || before.nlink !== 1
    || before.size > MAX_SESSION_METADATA_BYTES) {
    throw new Error("Runfree session metadata is not a bounded normal file");
  }
  const descriptor = fs.openSync(sourcePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile()
      || opened.nlink !== 1
      || opened.dev !== before.dev
      || opened.ino !== before.ino
      || opened.size > MAX_SESSION_METADATA_BYTES) {
      throw new Error("Runfree session metadata changed during read");
    }
    return fs.readFileSync(descriptor, "utf8");
  } finally {
    fs.closeSync(descriptor);
  }
}

function writeSessionMetadataExact(
  context: RuntimeContext,
  metadata: SessionMetadata,
  expectedSource?: string,
): void {
  assertSafeSessionId(metadata.id);
  const normalized: SessionMetadata = { ...metadata, name: normalizeSessionName(metadata.name) };
  ensureSafeSessionsDirectory(context);
  const destination = sessionStatePath(context, normalized.id);
  if (expectedSource !== undefined && readSessionMetadataSource(context, normalized.id) !== expectedSource) {
    throw new Error("Runfree session metadata changed before replacement");
  }
  const tmpPath = `${destination}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  const descriptor = fs.openSync(
    tmpPath,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(normalized, null, 2)}\n`);
    fs.fchmodSync(descriptor, 0o600);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  try {
    if (expectedSource !== undefined && readSessionMetadataSource(context, normalized.id) !== expectedSource) {
      throw new Error("Runfree session metadata changed before replacement");
    }
    if (expectedSource === undefined) {
      // Validate an existing destination's regular-file and single-link shape
      // before replacing it. Its old contents are not authority for this write.
      readSessionMetadataSource(context, normalized.id);
    }
    fs.renameSync(tmpPath, destination);
  } finally {
    try {
      fs.unlinkSync(tmpPath);
    } catch {
      // A successful rename consumes the temporary file. A failed write leaves
      // only a randomized, non-authoritative file for later state cleanup.
    }
  }
}

export function writeSessionMetadata(context: RuntimeContext, metadata: SessionMetadata): void {
  writeSessionMetadataExact(context, metadata);
}

export function removeSessionMetadata(context: RuntimeContext, sessionId: string): void {
  fs.rmSync(sessionStatePath(context, sessionId), { force: true });
}

export function markSessionInterrupted(
  context: RuntimeContext,
  metadata: SessionMetadata,
  exitStatus?: number,
  now = new Date(),
): SessionMetadata {
  const interrupted: SessionMetadata = {
    ...metadata,
    endedAt: now.toISOString(),
    ...(Number.isInteger(exitStatus) ? { exitStatus } : {}),
    outcome: "interrupted",
  };
  writeSessionMetadata(context, interrupted);
  return interrupted;
}

// Exported so the "another lifecycle change is in progress" messages can name
// the directory. A lock written before boot stamping existed carries no `boot`
// file, so after a reboot that reissues its PID to an unrelated live process it
// is never reclaimable by any check here — the operator's only remedy is to
// remove it, and they cannot do that without being told where it is.
export function projectLifecycleLockPath(context: RuntimeContext): string {
  return path.join(context.project.paths.stateDir, "runtime-lifecycle.lock");
}

// Shared with the admin token-store lock (admin-core.ts): EPERM means the
// process exists but is owned by someone else — still alive.
// mkdir is the atomic acquire primitive for both host lock directories; the pid
// and boot files inside it are owner evidence written as a second step. A lock
// that is still pid-less is therefore either mid-acquisition or crash garbage,
// and deleting it inside that window would admit two holders — the exact race
// the lock exists to prevent. Shared with the admin token-store lock.
export const LOCK_PIDLESS_GRACE_MS = 2_000;

const LIFECYCLE_LOCK_OWNER_TOKEN_FILE = "owner-token";
const LIFECYCLE_LOCK_OWNER_TOKEN = /^[a-f0-9]{64}$/;

type LifecycleLockIdentity = Readonly<{
  device: bigint;
  inode: bigint;
}>;

function lifecycleLockIdentity(lockPath: string): LifecycleLockIdentity | undefined {
  try {
    const stat = fs.lstatSync(lockPath, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) return undefined;
    return { device: stat.dev, inode: stat.ino };
  } catch {
    return undefined;
  }
}

function sameLifecycleLockIdentity(
  left: LifecycleLockIdentity | undefined,
  right: LifecycleLockIdentity | undefined,
): boolean {
  return left !== undefined
    && right !== undefined
    && left.device === right.device
    && left.inode === right.inode;
}

function readLifecycleLockOwnerToken(lockPath: string): string | undefined {
  try {
    const token = fs.readFileSync(path.join(lockPath, LIFECYCLE_LOCK_OWNER_TOKEN_FILE), "utf8").trim();
    return LIFECYCLE_LOCK_OWNER_TOKEN.test(token) ? token : undefined;
  } catch {
    return undefined;
  }
}

function lifecycleLockIsOwned(
  lockPath: string,
  expectedIdentity: LifecycleLockIdentity,
  expectedOwnerToken: string,
): boolean {
  const before = lifecycleLockIdentity(lockPath);
  if (!sameLifecycleLockIdentity(before, expectedIdentity)) return false;
  const ownerToken = readLifecycleLockOwnerToken(lockPath);
  const after = lifecycleLockIdentity(lockPath);
  return ownerToken === expectedOwnerToken
    && sameLifecycleLockIdentity(before, after)
    && sameLifecycleLockIdentity(after, expectedIdentity);
}

function lifecycleLockMatches(
  lockPath: string,
  expectedIdentity: LifecycleLockIdentity,
  expectedOwnerToken?: string,
): boolean {
  const before = lifecycleLockIdentity(lockPath);
  if (!sameLifecycleLockIdentity(before, expectedIdentity)) return false;
  if (expectedOwnerToken !== undefined && readLifecycleLockOwnerToken(lockPath) !== expectedOwnerToken) return false;
  return sameLifecycleLockIdentity(before, lifecycleLockIdentity(lockPath));
}

function quarantineExactLifecycleLock(
  lockPath: string,
  expectedIdentity: LifecycleLockIdentity,
  expectedOwnerToken?: string,
): string | undefined {
  const quarantinePath = `${lockPath}.quarantine-${process.pid}-${crypto.randomBytes(16).toString("hex")}`;
  try {
    fs.renameSync(lockPath, quarantinePath);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }

  const movedIdentity = lifecycleLockIdentity(quarantinePath);
  const movedOwnerToken = readLifecycleLockOwnerToken(quarantinePath);
  const identityMatches = sameLifecycleLockIdentity(movedIdentity, expectedIdentity);
  const tokenMatches = expectedOwnerToken === undefined || movedOwnerToken === expectedOwnerToken;
  if (identityMatches && tokenMatches) return quarantinePath;

  // Do not rename this object back over the canonical path. POSIX rename may
  // replace an empty directory created by an owner that is still stamping its
  // evidence, recreating the destructive race this check closes. Retaining the
  // unexpected object at its unique quarantine path is fail-closed: its owner
  // is fenced by the missing path/identity and can diagnose the preserved
  // evidence, while this contender refuses acquisition.
  return undefined;
}

function removeExactLifecycleLock(
  lockPath: string,
  expectedIdentity: LifecycleLockIdentity,
  expectedOwnerToken?: string,
): boolean {
  if (!lifecycleLockMatches(lockPath, expectedIdentity, expectedOwnerToken)) return false;
  const quarantinePath = quarantineExactLifecycleLock(lockPath, expectedIdentity, expectedOwnerToken);
  if (quarantinePath === undefined) return false;
  fs.rmSync(quarantinePath, { recursive: true, force: true });
  return true;
}

// Record who holds a lock directory: the PID, plus the boot it was taken on
// when the platform can prove one. Both locks read this back through
// `lockWrittenOnPreviousBoot`.
//
// The boot id is a parameter, not something this resolves, and that is the
// point. On macOS resolving it spawns `sysctl`; doing that here would put a
// process spawn between the caller's `mkdir` (the atomic acquire) and the `pid`
// write, leaving the lock pid-less for the length of the probe. A contender is
// entitled to steal a pid-less lock older than `LOCK_PIDLESS_GRACE_MS`, so a
// slow or hung probe would hand the critical section to two holders. Callers
// resolve the id before creating the directory; both writes here are single
// syscalls.
export function stampLockOwner(
  lockPath: string,
  bootId: string | undefined,
  processStart?: string,
  ownerToken?: string,
): void {
  // Boot first: a crash between the two writes then still leaves a lock that a
  // later boot can identify as dead outright, rather than one that has to wait
  // out the pid-less grace.
  if (bootId !== undefined) {
    fs.writeFileSync(path.join(lockPath, "boot"), `${bootId}\n`, { mode: 0o600 });
  }
  if (processStart !== undefined) {
    fs.writeFileSync(path.join(lockPath, "process-start"), `${processStart}\n`, { mode: 0o600 });
  }
  if (ownerToken !== undefined) {
    if (!LIFECYCLE_LOCK_OWNER_TOKEN.test(ownerToken)) throw new Error("invalid lifecycle lock owner token");
    fs.writeFileSync(path.join(lockPath, LIFECYCLE_LOCK_OWNER_TOKEN_FILE), `${ownerToken}\n`, { mode: 0o600 });
  }
  fs.writeFileSync(path.join(lockPath, "pid"), `${process.pid}\n`, { mode: 0o600 });
}

// A lock stamped with a different boot cannot be held: its owner did not
// survive the reboot, whatever PID it recorded. Locks predating this file carry
// no boot stamp and fall back to the PID check.
export function lockWrittenOnPreviousBoot(lockPath: string, env?: NodeJS.ProcessEnv): boolean {
  try {
    return recordedOnPreviousBoot(fs.readFileSync(path.join(lockPath, "boot"), "utf8"), env);
  } catch {
    return false;
  }
}

export function lockAgeMs(lockPath: string): number {
  try {
    return Date.now() - fs.statSync(lockPath).mtimeMs;
  } catch {
    // Already gone: nothing to remove, let the acquire loop retry mkdir.
    return Number.POSITIVE_INFINITY;
  }
}

function removeStaleLifecycleLock(lockPath: string, env?: NodeJS.ProcessEnv): boolean {
  const staleCandidateIdentity = lifecycleLockIdentity(lockPath);
  if (staleCandidateIdentity === undefined) return false;
  const staleCandidateOwnerToken = readLifecycleLockOwnerToken(lockPath);
  // The boot check runs first because PID liveness is meaningless across a
  // reboot: PIDs are reissued from low numbers, so a lock left behind by a
  // crash during `runfree up` can match an unrelated live process and defer
  // every session start and runtime start in the project indefinitely.
  if (!lockWrittenOnPreviousBoot(lockPath, env)) {
    let pid: number | undefined;
    try {
      pid = Number.parseInt(fs.readFileSync(path.join(lockPath, "pid"), "utf8").trim(), 10);
    } catch {
      pid = undefined;
    }
    if (pid !== undefined && Number.isInteger(pid) && processAlive(pid)) {
      let recordedBootId: string | undefined;
      let recordedProcessStart: string | undefined;
      try {
        recordedBootId = fs.readFileSync(path.join(lockPath, "boot"), "utf8").trim();
        recordedProcessStart = fs.readFileSync(path.join(lockPath, "process-start"), "utf8").trim();
      } catch {
        // Older or partially stamped locks retain the PID-only behavior.
      }
      const boot = compareHostBootId(recordedBootId, env);
      // The initial previous-boot check is decisive in the normal case. Repeat
      // it after reading the owner stamps so a changed stamp cannot turn a
      // proven stale lock into an unknown live-PID fallback.
      if (boot !== "mismatch" && (
        boot !== "match"
        || compareHostProcessStart(recordedProcessStart, pid, env) !== "mismatch"
      )) return false;
    }
    if ((pid === undefined || !Number.isInteger(pid)) && lockAgeMs(lockPath) < LOCK_PIDLESS_GRACE_MS) return false;
  }
  // Staleness takes several syscalls to judge. Quarantine the path and validate
  // the object that was actually moved before deleting it. If another contender
  // replaced the stale directory after the judgment, its inode/token differ and
  // it is retained at the quarantine path, never recursively deleted by this
  // contender.
  return removeExactLifecycleLock(lockPath, staleCandidateIdentity, staleCandidateOwnerToken);
}

export function tryAcquireProjectLifecycleLock(context: RuntimeContext, renewalTicket?: string): ProjectLifecycleLock | undefined {
  const renewalHead = sessionRenewalQueueHead(context.project.paths.stateDir, Date.now(), context.env);
  if (renewalHead !== undefined && renewalHead !== renewalTicket) return undefined;
  const lockPath = projectLifecycleLockPath(context);
  fs.mkdirSync(context.project.paths.stateDir, { recursive: true, mode: 0o700 });
  // Resolved before the first mkdir, never inside the acquisition window: on
  // macOS this spawns `sysctl`, and a spawn between mkdir and the pid write
  // would leave the lock pid-less for the length of the probe, which is exactly
  // when a contender may steal it. See `stampLockOwner`.
  const bootId = hostBootId(context.env);
  const processStart = hostProcessStart(process.pid, context.env);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const ownerToken = crypto.randomBytes(32).toString("hex");
    let acquiredIdentity: LifecycleLockIdentity | undefined;
    try {
      fs.mkdirSync(lockPath, { mode: 0o700 });
      acquiredIdentity = lifecycleLockIdentity(lockPath);
      if (acquiredIdentity === undefined) continue;
    } catch (error) {
      if (!(error instanceof Error) || !("code" in error) || error.code !== "EEXIST") throw error;
      if (!removeStaleLifecycleLock(lockPath, context.env)) return undefined;
      continue;
    }
    try {
      stampLockOwner(lockPath, bootId, processStart, ownerToken);
    } catch {
      // We hold the directory but could not record ownership: a contender past
      // the pid-less grace removed it, or the state dir went read-only or full.
      // Matching `acquireTokenStoreLock`, drop any remnant of our claim and
      // contend again rather than killing `runfree up`/`rebuild` with a raw fs
      // error — an unstamped lock is worse than no lock, because nothing can
      // attribute it and only the grace can ever reclaim it.
      removeExactLifecycleLock(
        lockPath,
        acquiredIdentity,
        readLifecycleLockOwnerToken(lockPath) === ownerToken ? ownerToken : undefined,
      );
      continue;
    }
    if (!lifecycleLockIsOwned(lockPath, acquiredIdentity, ownerToken)) {
      removeExactLifecycleLock(lockPath, acquiredIdentity, ownerToken);
      continue;
    }
    let released = false;
    return {
      ownerToken,
      assertHeld() {
        if (released || !lifecycleLockIsOwned(lockPath, acquiredIdentity, ownerToken)) {
          throw new Error(`project lifecycle lock ownership was lost or replaced: ${lockPath}`);
        }
      },
      release() {
        if (released) return;
        if (!removeExactLifecycleLock(lockPath, acquiredIdentity, ownerToken)) {
          throw new Error(`refusing to release a replaced project lifecycle lock: ${lockPath}`);
        }
        released = true;
      },
    };
  }
  return undefined;
}

/**
 * Acquires the project lifecycle lock, retrying for one bounded renewal-sized
 * window before giving up.
 *
 * A renewal critical section can include residual revocation, Docker liveness
 * proof, and two consumer acknowledgements. The default one-minute window
 * covers their bounded normal budgets. A lock still held after that window is
 * treated as an actual lifecycle operation and correctly defers the caller.
 */
export async function tryAcquireProjectLifecycleLockWithRetry(
  context: RuntimeContext,
  options: { attempts?: number; delayMs?: number } = {},
): Promise<ProjectLifecycleLock | undefined> {
  const attempts = options.attempts ?? 301;
  const delayMs = options.delayMs ?? 200;
  if (!Number.isSafeInteger(attempts) || attempts < 1) {
    throw new Error("project lifecycle lock retry attempts must be a positive integer");
  }
  if (!Number.isSafeInteger(delayMs) || delayMs < 1) {
    throw new Error("project lifecycle lock retry delay must be a positive integer");
  }
  let lock = tryAcquireProjectLifecycleLock(context);
  const startedAt = Date.now();
  let nextDiagnosticAt = startedAt + 5_000;
  for (let attempt = 1; !lock && attempt < attempts; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    const now = Date.now();
    if (now >= nextDiagnosticAt) {
      const elapsedSeconds = Math.max(1, Math.round((now - startedAt) / 1_000));
      runfreeLog(`waiting for the project lifecycle lock (${elapsedSeconds}s; lock: ${projectLifecycleLockPath(context)})`);
      nextDiagnosticAt = now + 5_000;
    }
    lock = tryAcquireProjectLifecycleLock(context);
  }
  return lock;
}

/**
 * Turns one acquired lifecycle lock into the required manager used by a
 * foreground session driver.
 *
 * Contention while reacquiring is not an immediate launch refusal. The session
 * already owns durable lifecycle state, so the manager waits through short
 * contention before renewal or revocation. Queued renewal acquisition is
 * cancellable after foreground completion, and teardown reacquisition is
 * bounded. Waiting also fails closed: the proxy drops expired authority before
 * a later cleanup pass settles any lifecycle residue.
 */
export function createSessionLockManager(
  context: RuntimeContext,
  initialLock: ProjectLifecycleLock,
  options: {
    retryDelayMs?: number;
    diagnosticIntervalMs?: number;
    reacquisitionTimeoutMs?: number;
  } = {},
): SessionLockManager {
  const retryDelayMs = options.retryDelayMs ?? 200;
  const diagnosticIntervalMs = options.diagnosticIntervalMs ?? 5_000;
  // If teardown cannot reacquire, exact creation authority can still remove
  // the container but cannot rewrite the whole admission registry. Do not
  // return from that fail-closed fallback before every possible current lease
  // has expired at the proxy boundary.
  const reacquisitionTimeoutMs = options.reacquisitionTimeoutMs
    ?? SESSION_CONTAINER_LEASE_MAX_DURATION_MS + 5_000;
  if (!Number.isSafeInteger(retryDelayMs) || retryDelayMs < 1) {
    throw new Error("session lock manager retry delay must be a positive integer");
  }
  if (!Number.isSafeInteger(diagnosticIntervalMs) || diagnosticIntervalMs < 1) {
    throw new Error("session lock manager diagnostic interval must be a positive integer");
  }
  if (!Number.isSafeInteger(reacquisitionTimeoutMs) || reacquisitionTimeoutMs < 1) {
    throw new Error("session lock manager reacquisition timeout must be a positive integer");
  }
  initialLock.assertHeld();

  type ManagerState = "held" | "waiting" | "acquiring-critical" | "critical" | "acquiring-held" | "closed";
  let state: ManagerState = "held";
  let current: ProjectLifecycleLock | undefined = initialLock;
  let lastOwnerToken = initialLock.ownerToken;

  const lockPath = projectLifecycleLockPath(context);

  const waitBeforeRetry = async (delayMs: number, signal?: AbortSignal): Promise<void> => {
    if (signal?.aborted) throw new SessionLockAcquisitionAbortedError(lockPath);
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      }, delayMs);
      const onAbort = (): void => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        reject(new SessionLockAcquisitionAbortedError(lockPath));
      };
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  };

  const acquireEventually = async (
    signal: AbortSignal | undefined,
    timeoutMs?: number,
    reportProgress = false,
    renewalTicket?: string,
  ): Promise<ProjectLifecycleLock> => {
    const startedAt = Date.now();
    const startedMonotonic = performance.now();
    const deadline = timeoutMs === undefined ? undefined : startedAt + timeoutMs;
    let nextDiagnosticAt = startedAt + diagnosticIntervalMs;
    for (;;) {
      if (signal?.aborted) throw new SessionLockAcquisitionAbortedError(lockPath);
      const now = Date.now();
      if (deadline !== undefined && timeoutMs !== undefined && (now >= deadline || now < startedAt || performance.now() - startedMonotonic >= timeoutMs)) {
        throw new SessionLockAcquisitionTimeoutError(lockPath, timeoutMs);
      }
      const acquired = tryAcquireProjectLifecycleLock(context, renewalTicket);
      if (acquired) return acquired;
      if (reportProgress && now >= nextDiagnosticAt) {
        const elapsedSeconds = Math.max(1, Math.round((now - startedAt) / 1_000));
        runfreeLog(`session is waiting to reacquire the project lifecycle lock for renewal or teardown (${elapsedSeconds}s; lock: ${lockPath})`);
        nextDiagnosticAt = now + diagnosticIntervalMs;
      }
      const delayMs = deadline === undefined ? retryDelayMs : Math.min(retryDelayMs, deadline - now);
      await waitBeforeRetry(delayMs, signal);
    }
  };

  const assertHeld = (): void => {
    if ((state !== "held" && state !== "critical") || !current) {
      throw new Error("session lock manager does not currently hold the project lifecycle lock");
    }
    current.assertHeld();
  };

  const close = (): void => {
    if (state === "closed") return;
    if (state === "acquiring-critical" || state === "critical" || state === "acquiring-held") {
      throw new Error("cannot close the session lock manager during reacquisition or a critical section");
    }
    if (state === "held") {
      const held = current;
      current = undefined;
      state = "closed";
      held?.release();
      return;
    }
    state = "closed";
  };

  const lock: ProjectLifecycleLock = {
    get ownerToken() {
      return current?.ownerToken ?? lastOwnerToken;
    },
    assertHeld,
    release() {
      throw new Error("the session lock manager owns project lifecycle lock release");
    },
  };

  return Object.freeze({
    lock,
    releaseForWait() {
      if (state !== "held" || !current) {
        throw new Error("session lock manager can yield only while it holds the project lifecycle lock");
      }
      const held = current;
      current = undefined;
      state = "waiting";
      held.release();
    },
    async withLock<T>(
      operation: () => Promise<T>,
      signal: AbortSignal,
    ): Promise<T> {
      if (state !== "waiting") {
        throw new Error("session lock manager critical section requires an attached wait");
      }
      state = "acquiring-critical";
      let operationEntered = false;
      let renewal: ReturnType<typeof enqueueSessionRenewal> | undefined;
      let outcome: Readonly<{ ok: true; value: T }> | Readonly<{ ok: false; error: unknown }>;
      try {
        try { renewal = enqueueSessionRenewal(context.project.paths.stateDir, Date.now(), context.env); }
        catch (cause) { throw new RuntimeObservationError({ kind: "observation-unavailable", subject: "owner",
          expectedIdentity: lockPath, phase: "renewal-lock-acquisition", observation: "renewal scheduling is unavailable; repair the host queue and retry" }, cause); }
        // Renewal waits within its scheduling budget. If another
        // lifecycle operation outlives the current lease, proxy authority
        // lapses naturally; foreground completion cancels this wait at once.
        current = await acquireEventually(signal, SESSION_RENEWAL_WAIT_BUDGET_MS, false, renewal.ticket);
        renewal.release();
        lastOwnerToken = current.ownerToken;
        state = "critical";
        assertHeld();
        operationEntered = true;
        outcome = { ok: true, value: await operation() };
      } catch (error) {
        outcome = { ok: false, error };
      }
      try { renewal?.release(); }
      catch (error) {
        // Queue cleanup grants no authority. Preserve the manager's ordinary
        // release path; stale tickets require proof of a dead requester.
        warn(`session renewal queue cleanup failed: ${error instanceof Error ? error.message : String(error)}`);
      }
      if (!outcome.ok) {
        if (state === "critical" && current && operationEntered) {
          // A failed renewal can already have compensated this session's
          // durable record to `revoking`. Retain the lock into teardown so a
          // peer cannot drain that record before this driver consumes it.
          state = "held";
        } else if (state === "critical" || state === "acquiring-critical") {
          // Acquisition validation failed before the operation ran. The
          // exact lock has been lost or replaced, so retain no false claim.
          const acquired = current;
          current = undefined;
          state = "waiting";
          if (acquired) {
            try {
              acquired.release();
            } catch (releaseFailure) {
              throw new AggregateError(
                [outcome.error, releaseFailure],
                "session lock manager validation and lock release both failed",
              );
            }
          }
        }
        throw outcome.error;
      }
      let releaseFailure: unknown;
      if (state === "critical" && current) {
        const held = current;
        current = undefined;
        state = "waiting";
        try {
          // release() performs the exact inode/token ownership check itself.
          // Reset manager state first so a refusal cannot wedge it in critical.
          held.release();
        } catch (error) {
          releaseFailure = error;
        }
      } else if (state === "acquiring-critical") {
        state = "waiting";
      }
      if (releaseFailure !== undefined) throw releaseFailure;
      return outcome.value;
    },
    async reacquire() {
      if (state === "held") {
        assertHeld();
        return;
      }
      if (state !== "waiting") {
        throw new Error("session lock manager cannot reacquire from its current state");
      }
      state = "acquiring-held";
      try {
        current = await acquireEventually(undefined, reacquisitionTimeoutMs, true);
        lastOwnerToken = current.ownerToken;
        state = "held";
        assertHeld();
      } catch (error) {
        const acquired = current;
        current = undefined;
        state = "waiting";
        if (acquired) {
          try {
            acquired.release();
          } catch (releaseFailure) {
            throw new AggregateError(
              [error, releaseFailure],
              "session lock manager reacquisition and lock release both failed",
            );
          }
        }
        throw error;
      }
    },
    close,
  });
}

function parseSessionMetadataSource(
  context: RuntimeContext,
  sessionId: string,
  source: string,
): SessionMetadata | undefined {
  try {
    const parsed = JSON.parse(source) as Partial<SessionMetadata> & {
      containerImageInbox?: unknown;
      hostImageInbox?: unknown;
    };
    if (parsed.id !== sessionId) return undefined;
    if (parsed.projectRoot !== context.projectRoot) return undefined;
    if (parsed.composeProject !== composeProjectName(context.projectRoot)) return undefined;
    if (typeof parsed.command !== "string" || typeof parsed.startedAt !== "string") return undefined;
    const hostInbox = typeof parsed.hostInbox === "string"
      ? parsed.hostInbox
      : typeof parsed.hostImageInbox === "string"
        ? parsed.hostImageInbox
        : context.project.paths.inboxDir;
    const containerInbox = typeof parsed.containerInbox === "string"
      ? parsed.containerInbox
      : typeof parsed.containerImageInbox === "string"
        ? parsed.containerImageInbox
        : inboxContainerDir();
    const { containerImageInbox: _containerImageInbox, hostImageInbox: _hostImageInbox, ...current } = parsed;
    const name = (() => {
      try {
        return normalizeSessionName(parsed.name);
      } catch {
        return synthesizeSessionName({
          command: parsed.command,
          ...(typeof parsed.hostTty === "string" ? { hostTty: parsed.hostTty } : {}),
          ...(typeof parsed.termProgram === "string" ? { termProgram: parsed.termProgram } : {}),
          startedAt: parsed.startedAt,
        });
      }
    })();
    return { ...current, name, hostInbox, containerInbox } as SessionMetadata;
  } catch {
    return undefined;
  }
}

export function readSessionMetadata(context: RuntimeContext, sessionId: string | undefined): SessionMetadata | undefined {
  if (!sessionId) return undefined;
  try {
    const source = readSessionMetadataSource(context, sessionId);
    return source === undefined ? undefined : parseSessionMetadataSource(context, sessionId, source);
  } catch {
    return undefined;
  }
}

export function renameSessionMetadata(
  context: RuntimeContext,
  sessionId: string,
  requestedName: string,
): SessionMetadata {
  // Display metadata only. Session principals, lifecycle incarnations,
  // admission records, grants, and approval subjects are deliberately absent
  // from this helper. The future CLI command must separately refresh the
  // proxy's safe display view after this exact host-record replacement.
  const name = normalizeSessionName(requestedName);
  assertSafeSessionId(sessionId, true);
  ensureSafeSessionsDirectory(context);
  const source = readSessionMetadataSource(context, sessionId);
  if (source === undefined) throw new Error(`Runfree session not found: ${sessionId}`);
  const metadata = parseSessionMetadataSource(context, sessionId, source);
  if (!metadata) throw new Error(`Runfree session metadata is invalid: ${sessionId}`);
  const renamed = { ...metadata, name };
  writeSessionMetadataExact(context, renamed, source);
  return renamed;
}

function recentSessionMetadata(context: RuntimeContext, now = Date.now()): SessionMetadata[] {
  let entries: string[];
  try {
    entries = fs.readdirSync(context.project.paths.sessionsDir);
  } catch {
    return [];
  }
  return entries.flatMap((entry) => {
    if (!entry.endsWith(".json")) return [];
    const sessionId = entry.slice(0, -".json".length);
    const metadata = readSessionMetadata(context, sessionId);
    if (!metadata) return [];
    const timestamp = Date.parse(metadata.lastSeenAt || metadata.startedAt);
    if (!Number.isFinite(timestamp) || now - timestamp > RECENT_SESSION_START_MS) return [];
    return [metadata];
  });
}

function sessionMetadataTimestamp(metadata: SessionMetadata): number | undefined {
  const timestamp = Date.parse(metadata.lastSeenAt || metadata.startedAt);
  return Number.isFinite(timestamp) ? timestamp : undefined;
}

// Whether the host `runfree` process that opened this session is still running.
// A recorded previous boot answers "no" without consulting the PID at all,
// because the recorded process did not survive the reboot whatever PID it held;
// only when the boot cannot be proved does the PID decide, and an unusable PID
// then answers "yes" so an unreadable record never silently hides a real
// session. The boot check goes first for the same reason it does in
// `removeStaleLifecycleLock`: proof outranks the value it would override.
function hostSessionProcessAlive(metadata: SessionMetadata, env?: NodeJS.ProcessEnv): boolean {
  if (recordedOnPreviousBoot(metadata.hostBootId, env)) return false;
  if (!Number.isInteger(metadata.hostPid) || metadata.hostPid <= 0) return true;
  if (!processAlive(metadata.hostPid)) return false;
  if (
    compareHostBootId(metadata.hostBootId, env) === "match"
    && compareHostProcessStart(metadata.hostProcessStart, metadata.hostPid, env) === "mismatch"
  ) return false;
  return true;
}

function hostBackedSessionStillAttached(
  metadata: SessionMetadata,
  now = Date.now(),
  env?: NodeJS.ProcessEnv,
): boolean {
  // A proven previous boot ends the question, and the recency window does not
  // get to overrule it. That window exists to cover an *unknown* — a host
  // process that has not been observed yet, or a record written moments before
  // the probe — not to override a proof. Letting a heuristic resurrect a record
  // that identity already settled would also contradict the recovery design's
  // rule that a host session is active only when every identity component
  // matches.
  //
  // Nothing live is hidden by this: a `docker exec` session cannot outlive the
  // reboot the stamp proves happened, so there is no surviving process for the
  // window to protect. What it removes is `runfree rebuild` warning about, and
  // deferring on, a session whose host client provably died on an earlier boot
  // — the same "warns about sessions that do not exist" failure
  // `activeOrStartingAgentSessions` fixes, which it would be incoherent to fix
  // there and keep here. It matters more once process-start identity lands and
  // within-boot PID reuse becomes provable too.
  if (recordedOnPreviousBoot(metadata.hostBootId, env)) return false;
  if (hostSessionProcessAlive(metadata, env)) return true;

  const timestamp = sessionMetadataTimestamp(metadata);
  return timestamp !== undefined && now - timestamp <= RECENT_SESSION_START_MS;
}

function pendingSessionFromMetadata(metadata: SessionMetadata): ActiveAgentSession {
  return {
    ...(metadata.agentCommand ? { agentCommand: metadata.agentCommand } : {}),
    command: sessionCommandLabel(metadata.command),
    containerTty: "<starting>",
    ...(metadata.termProgram ? { hostTermProgram: metadata.termProgram } : {}),
    ...(metadata.hostTty ? { hostTty: metadata.hostTty } : {}),
    name: metadata.name,
    sessionId: metadata.id,
    startedAt: metadata.startedAt,
    processCount: 1,
  };
}

/**
 * The CONTAINER TTY column text for a session-container-backed session.
 *
 * The placeholder `<session-container>` is what every consumer saw before a
 * heartbeat stamp existed, and stays exactly that whenever there is no stamp
 * to read from (a `generations` project, or a `files` project whose stamp is
 * `unknown` or absent) — the only way `printSessions`'s output stays
 * byte-identical under `generations`. Under `files`, `served` and `retrying`
 * report the same evidence `classifySessionRecordLiveness` already read for
 * this record, not a fresh claim: this only decides how to say it.
 */
function sessionContainerTtyLabel(stamp: SessionHostStatusV1 | undefined): string {
  if (stamp?.served === "served") return `attached, served until ${stamp.aliveUntil}`;
  if (stamp?.served === "retrying") return `attached, NOT served since ${stamp.lastHeartbeatAt} (heartbeat retrying)`;
  return "<session-container>";
}

function sessionFromLifecycleRecord(
  context: RuntimeContext,
  record: SessionContainerRecordV2,
  stamp?: SessionHostStatusV1,
): ActiveAgentSession {
  const metadata = readSessionMetadata(context, record.sessionId);
  return {
    ...(metadata?.agentCommand ? { agentCommand: metadata.agentCommand } : {}),
    command: sessionCommandLabel(metadata?.command ?? record.command),
    containerTty: sessionContainerTtyLabel(stamp),
    ...(metadata?.termProgram ? { hostTermProgram: metadata.termProgram } : {}),
    ...(metadata?.hostTty ? { hostTty: metadata.hostTty } : {}),
    name: metadata?.name ?? record.displayName,
    sessionId: record.sessionId,
    startedAt: metadata?.startedAt ?? record.createdAt,
    processCount: 1,
    ...(stamp?.served === "served" ? { servedUntil: stamp.aliveUntil } : {}),
    ...(stamp?.served === "retrying" ? { notServedSince: stamp.lastHeartbeatAt } : {}),
  };
}

/**
 * Reports what the proxy's session files say about this project, without
 * changing anything.
 *
 * Read-only by construction: the report takes no lock and writes nothing.
 * When there is anything to compare it issues one cheap `docker ps` check for
 * the running proxy, then one `docker exec` observation. It runs only for a
 * caller that has an `io` to make that observation with — `runfree sessions`
 * — so every other caller of the listing below reads exactly the host state
 * it reads today.
 *
 * Advisory in both directions: an observation this host could not make is
 * reported rather than raised, because a listing command must not fail
 * because the proxy is down.
 *
 * Two skips are silent rather than reported. A project with no lifecycle
 * record at all has nothing this comparison could reconcile, and a project
 * whose proxy is not running has nowhere to make the observation against —
 * neither is the "could not compare" failure the catch below exists to
 * report, and printing one for either would tell the operator to `runfree up`
 * a project they may have stopped on purpose.
 */
function reportSessionFileResidue(
  context: RuntimeContext,
  expectedProject: SessionContainerProjectIdentity,
  io: RuntimeIO | undefined,
  hasLifecycleRecords: boolean,
): void {
  if (!io || !hasLifecycleRecords) return;
  const stateDir = context.project.paths.stateDir;
  try {
    const effective = readEffectiveControlPlaneV2(stateDir);
    if (!effective) return;
    const project = composeProjectName(context.projectRoot);
    if (!serviceContainerId(project, "proxy", context, io, { runningOnly: true })) return;
    const report = reportSessionReconciliation({
      stateDir,
      expectedProject,
      io,
      proxyId: effective.selection.proxyContainerId,
      env: context.env,
      dockerOptions: dockerClientEnvOptions(context),
    });
    if (report.unknownOwners.length > 0) {
      warn(`${report.unknownOwners.length} session(s) whose owning host process cannot be proved alive or dead from this host: ${
        report.unknownOwners.join(", ")
      }; the record is left for its owner, or for \`${remedy.destroyForce()}\` to clear it`);
    }
    if (report.orphanFiles.length > 0) {
      warn(`the proxy holds ${report.orphanFiles.length} session file(s) this project has no record for; \`${
        remedy.up()
      }\` clears them`);
    }
  } catch (error) {
    const detail = compactDiagnostic(error instanceof Error ? error.message : String(error));
    warn(`could not compare the proxy's session files with this project's records${detail ? `: ${detail}` : ""}`);
  }
}

export function activeLifecycleSessions(
  context: RuntimeContext,
  nowEpochMs = Date.now(),
  io?: RuntimeIO,
): ActiveAgentSession[] {
  const projectId = projectHash(context.projectRoot);
  try {
    const peek = peekSessionContainerRecordsV2(context.project.paths.stateDir, {
      projectId,
      composeProject: `runfree-${projectId}`,
    });
    const stateDir = context.project.paths.stateDir;
    // Load-bearing for `destroy`: its own live-record gate drops a record
    // carrying a terminal host status stamp (an interrupted teardown must not
    // wedge the command that clears it), so plain destroy's refusal over a
    // teardown whose owner is still running rests entirely on this
    // classification NOT excluding those records. Adding a terminal-stamp
    // filter here would silently let destroy end a live process mid-teardown.
    const live = peek.records
      .filter((record) => record.state !== "revoking")
      .map((record) => ({ record, stamp: readSessionHostStatus(stateDir, record.sessionId) }))
      .filter(({ record, stamp }) => classifySessionRecordLiveness(record, { nowEpochMs, env: context.env, stamp }).kind === "live")
      .map(({ record, stamp }) => sessionFromLifecycleRecord(context, record, stamp));
    reportSessionFileResidue(
      context,
      { projectId, composeProject: `runfree-${projectId}` },
      io,
      peek.records.length > 0 || peek.unreadable > 0,
    );
    if (peek.unreadable === 0) return live;
    warn(`could not read ${peek.unreadable} session-container lifecycle record(s); treating session activity as live until the records are repaired`);
    return [...live, {
      command: "session-container registry",
      containerTty: "<unknown>",
      name: `${peek.unreadable} unreadable session record(s)`,
      processCount: peek.unreadable,
    }];
  } catch (error) {
    const detail = compactDiagnostic(error instanceof Error ? error.message : String(error));
    warn(`could not inspect session-container lifecycle records; treating session activity as live until inspection succeeds${
      detail ? `: ${detail}` : ""
    }`);
    return [{
      command: "session-container registry",
      containerTty: "<unknown>",
      name: "unknown session-container activity",
      processCount: 1,
    }];
  }
}

export function activeOrStartingAgentSessions(
  context: RuntimeContext,
  docker: RuntimeDocker,
  io?: RuntimeIO,
): ActiveAgentSession[] {
  const project = composeProjectName(context.projectRoot);
  const active = docker.activeAgentSessions(project);
  const lifecycle = activeLifecycleSessions(context, Date.now(), io);
  const activeIds = new Set([...active, ...lifecycle]
    .map((session) => session.sessionId)
    .filter((id): id is string => Boolean(id)));
  // A session is "starting" only while the host process that opened it is still
  // running. Without this check any crash leftover under the recency window
  // counts as pending, which warns about sessions that do not exist and defers
  // runtime upgrades for the first minutes after an unclean end — precisely
  // when the operator is trying to get back to work.
  const starting = recentSessionMetadata(context)
    .filter((metadata) => !activeIds.has(metadata.id) && hostSessionProcessAlive(metadata, context.env))
    .map(pendingSessionFromMetadata);
  return [
    ...active,
    ...lifecycle.filter((session) => session.sessionId === undefined
      || !active.some((item) => item.sessionId === session.sessionId)),
    ...starting,
  ];
}

export function sessionEnvOptions(metadata: SessionMetadata): string[] {
  // The display name remains in host/proxy state. It is not an agent-supplied
  // identity claim and is intentionally absent from the container environment.
  const entries: Array<[string, string | undefined]> = [
    ["RUNFREE_SESSION_ID", metadata.id],
    ["RUNFREE_SESSION_COMMAND", metadata.command],
    ["RUNFREE_HOST_TTY", metadata.hostTty],
    ["RUNFREE_HOST_TERM_PROGRAM", metadata.termProgram],
    ["RUNFREE_HOST_TERM_SESSION_ID", metadata.termSessionId],
    ["RUNFREE_HOST_ITERM_SESSION_ID", metadata.itermSessionId],
    ["RUNFREE_HOST_WT_SESSION", metadata.wtSession],
  ];
  return entries
    .filter((entry): entry is [string, string] => entry[1] !== undefined && entry[1] !== "")
    .flatMap(([name, value]) => ["--env", `${name}=${value}`]);
}

function baseRuntimeRoot(context: RuntimeContext): string {
  return context.runtimeRoot;
}

function activeAgentSessionProbeSource(context: RuntimeContext): { source?: string; error?: string } {
  const sourcePath = path.join(baseRuntimeRoot(context), "agent", "inspect-active-sessions.sh");
  try {
    return { source: fs.readFileSync(sourcePath, "utf8") };
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return { error: detail };
  }
}

function compactDiagnostic(value: string): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= 500) return compact;
  return `${compact.slice(0, 497)}...`;
}

function parseActiveAgentSessions(stdout: string, context: RuntimeContext): ActiveAgentSession[] {
  const groups = new Map<string, { tty: string; sessionId?: string; metadata?: SessionMetadata; processes: SessionProcess[] }>();
  for (const line of stdout.trim().split(/\n+/).filter(Boolean)) {
    const [pidRaw, tty, thirdColumn = "", ...rest] = line.split("\t");
    const pid = Number.parseInt(pidRaw ?? "", 10);
    const hasSessionColumn = rest.length > 0;
    const sessionId = hasSessionColumn && thirdColumn !== "" ? thirdColumn : undefined;
    const commandParts = hasSessionColumn ? rest : [thirdColumn, ...rest];
    const rawCommand = commandParts.join("\t").replace(/\s+/g, " ").trim();
    if (!Number.isInteger(pid) || !tty || !rawCommand) continue;
    if (rawCommand === "sleep infinity") continue;
    const description = sessionProcessDescription(rawCommand);
    const groupKey = sessionId ?? `tty:${tty}`;
    const current = groups.get(groupKey) ?? {
      tty,
      sessionId,
      metadata: readSessionMetadata(context, sessionId),
      processes: [],
    };
    current.processes.push({ pid, command: description.command, score: description.score });
    groups.set(groupKey, current);
  }

  return Array.from(groups.values()).flatMap(({ tty, sessionId, metadata, processes }) => {
    if (metadata && !hostBackedSessionStillAttached(metadata, Date.now(), context.env)) return [];
    processes.sort((left, right) => left.pid - right.pid);
    const uniqueCommands = Array.from(new Map(processes.map((process) => [process.command, process])).values());
    uniqueCommands.sort((left, right) => right.score - left.score || left.command.length - right.command.length);
    const command = metadata
      ? sessionCommandLabel(metadata.command)
      : uniqueCommands[0]?.command ?? "<unknown command>";
    return [{
      ...(metadata?.agentCommand ? { agentCommand: metadata.agentCommand } : {}),
      command,
      containerTty: tty,
      ...(metadata?.termProgram ? { hostTermProgram: metadata.termProgram } : {}),
      ...(metadata?.hostTty ? { hostTty: metadata.hostTty } : {}),
      name: metadata?.name ?? synthesizeSessionName({ command, hostTty: tty, startedAt: metadata?.startedAt }),
      ...(sessionId ? { sessionId } : {}),
      ...(metadata?.startedAt ? { startedAt: metadata.startedAt } : {}),
      processCount: processes.length,
    }];
  }).sort((left, right) => (left.sessionId ?? left.containerTty).localeCompare(right.sessionId ?? right.containerTty));
}

export function activeAgentSessions(project: string, context: RuntimeContext, io: RuntimeIO): ActiveAgentSession[] {
  const agentId = serviceContainerId(project, "agent", context, io);
  if (!agentId) return [];
  const probe = activeAgentSessionProbeSource(context);
  if (!probe.source) {
    const detail = compactDiagnostic(probe.error ?? "");
    warn(`could not load active session inspector; treating agent activity as live until inspection succeeds${
      detail ? `: ${detail}` : ""
    }`);
    return [{ containerTty: "<unknown>", command: `agent container ${agentId}`, name: "unknown session", processCount: 1 }];
  }
  const result = io.capture(
    "docker",
    ["exec", "-i", "--user", AGENT_UID_GID, agentId, "sh", "-s"],
    { ...dockerClientEnvOptions(context), input: probe.source },
  );
  if (result.status !== 0) {
    const detail = compactDiagnostic(result.stderr);
    warn(`could not inspect active agent sessions; treating agent activity as live until inspection succeeds${
      detail ? `: ${detail}` : ` (docker exec exited ${result.status})`
    }`);
    return [{ containerTty: "<unknown>", command: `agent container ${agentId}`, name: "unknown session", processCount: 1 }];
  }
  return parseActiveAgentSessions(result.stdout, context);
}

function formatSessionTime(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return undefined;
  return date.toISOString().slice(11, 16);
}

export function sessionWarningLine(session: ActiveAgentSession): string {
  const suffix = session.processCount > 1 ? ` (${session.processCount} processes)` : "";
  if (session.sessionId) {
    const terminal = session.hostTty
      ? `host tty ${session.hostTty}${session.hostTermProgram ? `, ${session.hostTermProgram}` : ""}`
      : "host terminal unknown";
    const started = formatSessionTime(session.startedAt);
    return `session ${session.sessionId} (${session.name}): ${session.command}, ${terminal}${
      started ? `, started ${started}` : ""
    }${suffix}`;
  }
  return `legacy session ${session.name} (${session.containerTty}): ${session.command}${suffix}`;
}

function printActiveSessionWarning(sessions: ActiveAgentSession[]): void {
  warn("runfree rebuild will recreate the runtime and terminate active agent sessions:");
  for (const session of sessions) {
    warn(`  ${sessionWarningLine(session)}`);
  }
}

export function printSessions(sessions: ActiveAgentSession[]): void {
  if (sessions.length === 0) {
    console.log("no active Runfree sessions");
    return;
  }
  console.log(formatTerminalTable({
    columns: [
      { label: "ID" },
      { label: "NAME" },
      { label: "COMMAND" },
      { label: "HOST TTY" },
      { label: "TERMINAL" },
      { label: "STARTED" },
      { label: "CONTAINER TTY" },
    ],
    rows: sessions.map((session) => [
      session.sessionId ?? "legacy",
      session.name,
      session.sessionId ? session.command.toLowerCase().replace(/\s+cli$/i, "") : session.command,
      session.hostTty ?? "-",
      session.hostTermProgram ?? "-",
      formatSessionTime(session.startedAt) ?? "-",
      session.containerTty,
    ]),
  }));
}

export function serviceList(services: string[]): string {
  return services.length > 0 ? services.join(", ") : "runtime";
}

export function warnDeferredRuntimeUpgrade(plan: {
  reason: "full recreate";
  services: string[];
  sessions: ActiveAgentSession[];
}): void {
  warn(`the runtime was not upgraded: ${plan.reason} is required for ${serviceList(plan.services)} but active agent sessions are running:`);
  for (const session of plan.sessions) warn(`  ${sessionWarningLine(session)}`);
  warn(`run \`${remedy.rebuild()}\` when those sessions can be stopped`);
}

export function confirmRebuildIfActiveSessions(
  context: RuntimeContext,
  docker: RuntimeDocker,
  io: RuntimeIO,
  options: RebuildOptions,
  observedSessions: readonly ActiveAgentSession[] = activeOrStartingAgentSessions(context, docker),
): number {
  if (observedSessions.length === 0) return 0;

  printActiveSessionWarning([...observedSessions]);
  if (options.assumeYes) {
    warn("continuing because --yes was provided");
    return 0;
  }

  warn("continue only if those sessions can be stopped");
  flushWarnings();
  if (io.confirm("Continue with rebuild? [y/N] ")) return 0;

  warn("rebuild aborted; no containers were recreated");
  return 1;
}

export const parseActiveAgentSessionsForTest = parseActiveAgentSessions;
export const sessionCommandLabelForTest = sessionCommandLabel;
