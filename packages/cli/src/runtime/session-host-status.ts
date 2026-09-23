// The host's own answer to "is this session still beating?", one small file
// per session under the project state directory.
//
// The durable lifecycle record freezes its admission lease. This stamp reports
// the last heartbeat and whether it was served, but it is not owner-death
// evidence. A stale or missing stamp never authorizes automatic destruction.
// Owner intent or positive process/boot/start evidence governs reclamation;
// proxy-side session files independently govern the egress lease.
//
// The path is project state, so the same rule as every other host-side write
// applies: writes go through `safe-fs` (symlinks, hard links, and special files
// refused before any byte is written), and a read refuses the same shapes
// rather than following them.

import fs from "node:fs";
import path from "node:path";

import { parseStrictJson } from "../control/strict-json.ts";
import {
  assertNoSymlinkPath,
  assertOptionalNormalProjectDirectory,
  ensureSafeProjectDir,
  fsyncDirectory,
  safeReplaceProjectFile,
} from "../safe-fs.ts";
import { exactKeySet, isRecord, readBoundedRegularFile } from "../strict-primitives.ts";
import { SESSION_ID_PATTERN } from "./session-containers.ts";

export const SESSION_HOST_STATUS_SCHEMA_VERSION = 1 as const;
/** A stamp is a few hundred bytes; anything larger is not one. */
export const SESSION_HOST_STATUS_MAX_BYTES = 4 * 1024;
const SERVED_STATES = ["served", "retrying", "unknown"] as const;
const REQUIRED_KEYS = ["v", "sessionId", "lastHeartbeatAt", "aliveUntil", "served"] as const;

export type SessionHostStatusServed = typeof SERVED_STATES[number];

export type SessionHostStatusV1 = {
  v: 1;
  sessionId: string;
  lastHeartbeatAt: string;
  aliveUntil: string;
  served: SessionHostStatusServed;
  terminal?: "revoking";
};

function validIsoTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function parseSessionHostStatusV1(value: unknown): SessionHostStatusV1 | undefined {
  if (!isRecord(value)) return undefined;
  // Exact key set, not an allow-list: a stamp carrying a field this version
  // does not define was written by something that is not this writer, and
  // guessing which half of it to trust is how a parser becomes an attack
  // surface.
  const expected = Object.hasOwn(value, "terminal") ? [...REQUIRED_KEYS, "terminal"] : REQUIRED_KEYS;
  if (!exactKeySet(value, expected)) return undefined;
  if (value.v !== SESSION_HOST_STATUS_SCHEMA_VERSION) return undefined;
  if (typeof value.sessionId !== "string" || !SESSION_ID_PATTERN.test(value.sessionId)) return undefined;
  if (!validIsoTimestamp(value.lastHeartbeatAt) || !validIsoTimestamp(value.aliveUntil)) return undefined;
  if (typeof value.served !== "string" || !SERVED_STATES.includes(value.served as SessionHostStatusServed)) {
    return undefined;
  }
  if (value.terminal !== undefined && value.terminal !== "revoking") return undefined;
  return Object.freeze({
    v: SESSION_HOST_STATUS_SCHEMA_VERSION,
    sessionId: value.sessionId,
    lastHeartbeatAt: value.lastHeartbeatAt,
    aliveUntil: value.aliveUntil,
    served: value.served as SessionHostStatusServed,
    ...(value.terminal === "revoking" ? { terminal: "revoking" as const } : {}),
  });
}

function sessionHostStatusRoot(stateDir: string): string {
  return path.join(stateDir, "runtime", "v2", "session-status");
}

export function sessionHostStatusPath(stateDir: string, sessionId: string): string {
  if (!SESSION_ID_PATTERN.test(sessionId)) throw new Error("invalid session id");
  return path.join(sessionHostStatusRoot(stateDir), `${sessionId}.json`);
}

function serializeSessionHostStatus(status: SessionHostStatusV1): string {
  // Serialized from the parsed value, so a stamp this reader would reject can
  // never be written: the write and the read agree on one shape by
  // construction.
  const parsed = parseSessionHostStatusV1(status);
  if (!parsed) throw new Error("invalid session host status stamp");
  return `${JSON.stringify(parsed)}\n`;
}

/**
 * Replaces this session's stamp.
 *
 * Refuses before writing anything: an invalid stamp, and — through
 * `safe-fs` — a symlinked, hard-linked, or special path anywhere between the
 * state directory and the file.
 */
export function writeSessionHostStatus(stateDir: string, status: SessionHostStatusV1): void {
  const contents = serializeSessionHostStatus(status);
  const filePath = sessionHostStatusPath(stateDir, status.sessionId);
  // The state directory root is created the same way the other v2 runtime
  // state families create it; `ensureSafeProjectDir` then proves every
  // component below it is a real directory this host may write through.
  if (!fs.existsSync(stateDir)) fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  ensureSafeProjectDir(stateDir, path.dirname(filePath), 0o700);
  safeReplaceProjectFile(stateDir, filePath, contents, 0o600);
}

/**
 * This session's stamp, or `undefined` when there is no usable one.
 *
 * Never throws. Every deviation — a missing file, an unsafe path, an over-size
 * or unparseable file, an unknown key, a wrong version, a non-ISO timestamp, a
 * `served` value outside the enum, or a stamp naming another session — reads as
 * absent, which is exactly the pre-stamp behavior at every consumer.
 */
export function readSessionHostStatus(stateDir: string, sessionId: string): SessionHostStatusV1 | undefined {
  try {
    const filePath = sessionHostStatusPath(stateDir, sessionId);
    // `assertNoSymlinkPath` proves every path component BELOW `stateDir` but
    // never lstats `stateDir` itself, so a symlinked or non-directory state
    // root would otherwise never be checked on this read path (unlike the
    // write path's `ensureSafeProjectDir` and the sibling reader
    // `session-containers.ts`'s `assertExistingSafeDirectoryTree`, both of
    // which check the root first). This proves the root the same way before
    // trusting anything below it.
    assertOptionalNormalProjectDirectory(stateDir, stateDir, "session status state directory");
    // `readBoundedRegularFile` proves the final component; this proves the
    // directories above it, so a symlinked `session-status` cannot redirect the
    // read outside the project's own state.
    assertNoSymlinkPath(stateDir, filePath, { allowMissingPath: true });
    const read = readBoundedRegularFile(filePath, {
      maxBytes: SESSION_HOST_STATUS_MAX_BYTES,
      sizeRecheck: "exact",
      notFileMessage: (file) => `session host status path is not a bounded regular single-link file: ${file}`,
      changedMessage: (file) => `session host status path changed during read: ${file}`,
    });
    if (!read) return undefined;
    const status = parseSessionHostStatusV1(parseStrictJson(read.source));
    return status?.sessionId === sessionId ? status : undefined;
  } catch {
    return undefined;
  }
}

/** Clears this session's stamp. Idempotent, and never follows a link. */
export function removeSessionHostStatus(stateDir: string, sessionId: string): void {
  const filePath = sessionHostStatusPath(stateDir, sessionId);
  // `rm` unlinks the named entry itself, so a planted symlink is removed rather
  // than followed to its target.
  fs.rmSync(filePath, { force: true });
  const parent = path.dirname(filePath);
  try {
    fsyncDirectory(parent);
  } catch {
    // The directory may not exist (nothing was ever stamped) and durability of
    // a cleared advisory stamp is not worth a teardown failure.
  }
}
