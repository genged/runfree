// The headless run's prompt file (headless-run spec §3.2, plan Task 13).
//
// `--prompt-file` is read on the host with a bound, never following a
// symlink and never opening a special file, then copied into the project
// inbox, which every session mounts read-only at `/runfree/inbox`. The session
// entry opens the copy as the agent's stdin; the prompt is never argv. The
// stop routine deletes the copy.

import fs from "node:fs";
import path from "node:path";

import { CONTAINER_INBOX_DIR, ensureInbox } from "../inbox.ts";
import { statKind } from "../safe-fs.ts";
import { HEADLESS_RUN_ID_PATTERN } from "./headless-run-record.ts";
import { HEADLESS_PROMPT_CONTAINER_PATH_PATTERN } from "./session-launch.ts";

export const HEADLESS_PROMPT_CAP_BYTES = 1024 * 1024;

/** A prompt file `run` refuses before any side effect (usage, exit 64). */
export class HeadlessPromptFileError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "HeadlessPromptFileError";
  }
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Reads at most `capBytes` from a regular file. Refused: a symlink, anything
 * that is not a regular file, a file larger than the cap, and a file that is
 * not the one `lstat` saw when it is opened. `O_NONBLOCK` keeps a FIFO swapped
 * in after the `lstat` from blocking the open; the `fstat` then refuses it.
 */
export function readPromptFileBounded(filePath: string, capBytes = HEADLESS_PROMPT_CAP_BYTES): Buffer {
  let linkStat: fs.Stats;
  try {
    linkStat = fs.lstatSync(filePath);
  } catch (error) {
    throw new HeadlessPromptFileError(`the prompt file could not be read: ${filePath}: ${errorText(error)}`, error);
  }
  if (linkStat.isSymbolicLink()) throw new HeadlessPromptFileError(`the prompt file must not be a symlink: ${filePath}`);
  if (!linkStat.isFile()) {
    throw new HeadlessPromptFileError(`the prompt file is not a regular file: ${filePath} (${statKind(linkStat)})`);
  }
  if (linkStat.size > capBytes) {
    throw new HeadlessPromptFileError(`the prompt file is larger than ${capBytes} bytes: ${filePath}`);
  }
  let fd: number;
  try {
    fd = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0),
    );
  } catch (error) {
    throw new HeadlessPromptFileError(`the prompt file could not be read: ${filePath}: ${errorText(error)}`, error);
  }
  try {
    const openStat = fs.fstatSync(fd);
    if (!openStat.isFile() || openStat.dev !== linkStat.dev || openStat.ino !== linkStat.ino) {
      throw new HeadlessPromptFileError(`the prompt file changed while it was read: ${filePath}`);
    }
    // One byte past the cap tells a file that grew after its stat from one
    // that fits; nothing past that byte is ever read.
    const buffer = Buffer.alloc(capBytes + 1);
    let length = 0;
    while (length < buffer.length) {
      const read = fs.readSync(fd, buffer, length, buffer.length - length, null);
      if (read === 0) break;
      length += read;
    }
    if (length > capBytes) {
      throw new HeadlessPromptFileError(`the prompt file is larger than ${capBytes} bytes: ${filePath}`);
    }
    return Buffer.from(buffer.subarray(0, length));
  } catch (error) {
    if (error instanceof HeadlessPromptFileError) throw error;
    throw new HeadlessPromptFileError(`the prompt file could not be read: ${filePath}: ${errorText(error)}`, error);
  } finally {
    fs.closeSync(fd);
  }
}

function promptName(runId: string): string {
  if (!HEADLESS_RUN_ID_PATTERN.test(runId)) throw new Error(`headless prompt run id is malformed: ${JSON.stringify(runId)}`);
  return `${runId}.prompt`;
}

/**
 * Writes the prompt as `<inbox>/<runId>.prompt` (0600, never over an existing
 * entry, symlinks included) and returns the path the session sees.
 */
export function writeInboxPrompt(inboxDir: string, runId: string, bytes: Buffer): string {
  const name = promptName(runId);
  const containerPath = `${CONTAINER_INBOX_DIR}/${name}`;
  if (!HEADLESS_PROMPT_CONTAINER_PATH_PATTERN.test(containerPath)) {
    throw new Error(`headless prompt container path is malformed: ${containerPath}`);
  }
  ensureInbox(inboxDir);
  fs.writeFileSync(path.join(inboxDir, name), bytes, { flag: "wx", mode: 0o600 });
  return containerPath;
}

/** Removes this run's prompt if it is a regular file; absence is fine, anything else is refused. */
export function deleteInboxPrompt(inboxDir: string, runId: string): void {
  const filePath = path.join(inboxDir, promptName(runId));
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(filePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (!stat.isFile()) throw new Error(`headless prompt is not a regular file; left in place: ${filePath} (${statKind(stat)})`);
  try {
    fs.unlinkSync(filePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}
