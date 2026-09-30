// Small host-state records that let a warm launch choose a cheaper path.
//
// Both users (the warm-proof fingerprint and the image-cleanup stamp) follow
// one rule: a record selects a path and never authorizes. Every fact a record
// names is observed live again before the cheap path is taken, and an absent,
// unreadable, or malformed record means "take the full path". So the reader
// here fails soft — any deviation reads as `undefined` — while the writer is
// strict: it goes through `safe-fs`, which refuses symlinks, hard links, and
// special files before a byte is written, exactly like every other write under
// the project state directory.

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
import { readBoundedRegularFile } from "../strict-primitives.ts";

const RECORD_NAME = /^[a-z][a-z0-9-]*\.json$/;

export function launchHostRecordPath(stateDir: string, name: string): string {
  if (!RECORD_NAME.test(name)) throw new Error("invalid launch host record name");
  return path.join(stateDir, "runtime", "v2", "launch", name);
}

/**
 * Reads one record, or `undefined` for anything that is not exactly a bounded,
 * single-link regular file holding strict JSON the parser accepts.
 */
export function readLaunchHostRecord<T>(
  stateDir: string,
  name: string,
  maxBytes: number,
  parse: (value: unknown) => T | undefined,
): T | undefined {
  try {
    const filePath = launchHostRecordPath(stateDir, name);
    assertOptionalNormalProjectDirectory(stateDir, stateDir, "launch record state directory");
    assertNoSymlinkPath(stateDir, filePath, { allowMissingPath: true });
    const read = readBoundedRegularFile(filePath, {
      maxBytes,
      sizeRecheck: "exact",
      notFileMessage: (file) => `launch host record is not a bounded regular single-link file: ${file}`,
      changedMessage: (file) => `launch host record changed during read: ${file}`,
    });
    if (!read) return undefined;
    return parse(parseStrictJson(read.source));
  } catch {
    return undefined;
  }
}

/** Replaces one record atomically; throws when the path is unsafe. */
export function writeLaunchHostRecord(stateDir: string, name: string, contents: string): void {
  const filePath = launchHostRecordPath(stateDir, name);
  if (!fs.existsSync(stateDir)) fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  ensureSafeProjectDir(stateDir, path.dirname(filePath), 0o700);
  safeReplaceProjectFile(stateDir, filePath, contents, 0o600);
}

/** Removes one record. Idempotent, and unlinks a planted link rather than following it. */
export function removeLaunchHostRecord(stateDir: string, name: string): void {
  const filePath = launchHostRecordPath(stateDir, name);
  // The directories above the record must be real: a symlinked parent would
  // redirect the unlink outside the project's own state.
  assertNoSymlinkPath(stateDir, filePath, { allowMissingPath: true });
  fs.rmSync(filePath, { force: true });
  try {
    fsyncDirectory(path.dirname(filePath));
  } catch {
    // The directory may not exist; nothing was ever recorded.
  }
}
