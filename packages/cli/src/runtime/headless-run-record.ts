// The host-only run record of a headless run and its stdout summary
// (headless-run spec §3.4, plan Task 9).
//
// The record lives under `<stateDir>/runs/<runId>/` and nowhere else: Runfree
// writes nothing into the project tree, because a host write into the agent's
// tree can be raced (spec §7 decision 3). No session mounts `runs/`.
//
//   transcript.jsonl  the agent's stdout, byte-for-byte up to a cap
//   stderr.log        the agent's and Runfree's own stderr, up to a cap
//   result.md         the final assistant message
//   run.json          the run's facts (`HeadlessRunJson`)

import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { atomicReplaceFile, isPathInsideByRealpath, statKind } from "../safe-fs.ts";
import { HEADLESS_TRANSCRIPT_CAP_BYTES } from "./headless-agent-output.ts";

export const HEADLESS_RUN_ID_PATTERN = /^run-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$/;
export const HEADLESS_STDERR_CAP_BYTES = 16 * 1024 * 1024;

export type HeadlessRunOutcome = "success" | "failed" | "unverified" | "refused" | "skipped" | "timeout" | "signal";
export type HeadlessRunTeardown = "confirmed" | "unconfirmed" | "not-started";

export type HeadlessUncheckedAuthoritySource = "hostServices" | "oauthExchanges" | "localMcpServers";

/** Authority a headless run allows without write posture (spec §3.5); names only. */
export type HeadlessUncheckedAuthority = Readonly<{
  hostServices: readonly string[];
  oauthExchanges: readonly string[];
  localMcpServers: readonly string[];
  /** Sources that could not be read, so their list is unknown rather than empty. */
  unreadable: readonly HeadlessUncheckedAuthoritySource[];
}>;

export type HeadlessRunJson = Readonly<{
  v: 1;
  runId: string;
  agent: string;
  startedAt: string;
  endedAt: string;
  /** The raw agent status, or `null` when the host lost it. */
  agentStatus: number | null;
  outcome: HeadlessRunOutcome;
  exitCode: number;
  teardown: HeadlessRunTeardown;
  sessionId?: string;
  containerId?: string;
  /** This session's `headless-denied` writes, or `null` when they could not be counted. */
  headlessDenials: number | null;
  acceptDeniedWrites: boolean;
  /** `null` when the run ended before the listing was made. */
  uncheckedAuthority: HeadlessUncheckedAuthority | null;
  streamsDrained: boolean;
  reattached: boolean;
  transcriptBytes: number;
  transcriptTruncated: boolean;
  stderrTruncated: boolean;
  malformedLines: number;
}>;

export type HeadlessRunRecord = Readonly<{
  dir: string;
  appendTranscript(chunk: Buffer): void;
  appendStderr(chunk: Buffer): void;
  transcriptBytes(): number;
  transcriptTruncated(): boolean;
  stderrTruncated(): boolean;
  /** Tees `stream.write` into stderr.log until `finalize`. */
  startStderrTee(stream?: NodeJS.WriteStream): void;
  /** Closes the streams, writes result.md and run.json; once only. */
  finalize(run: HeadlessRunJson, result: Readonly<{ finalMessage?: string }>): void;
}>;

/** `run-YYYYMMDDTHHMMSSZ-<8 hex>` in UTC, the inbox prompt name's stem. */
export function createHeadlessRunId(now: Date = new Date(), random: (size: number) => Buffer = randomBytes): string {
  const stamp = now.toISOString().replace(/\.\d{3}Z$/, "Z").replace(/[-:]/g, "");
  return `run-${stamp}-${random(4).toString("hex")}`;
}

function recordError(message: string, cause?: unknown): Error {
  return new Error(`headless run record ${message}`, cause === undefined ? undefined : { cause });
}

function ensureRunsDirectory(runsDir: string): void {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(runsDir);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw recordError(`directory is unreadable: ${runsDir}`, error);
    try {
      fs.mkdirSync(runsDir, { mode: 0o700 });
    } catch (mkdirError) {
      throw recordError(`directory could not be created: ${runsDir}`, mkdirError);
    }
    stat = fs.lstatSync(runsDir);
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw recordError(`directory is not a plain directory: ${runsDir} (${statKind(stat)})`);
  }
}

function openNewFile(filePath: string): number {
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_APPEND
    | (fs.constants.O_NOFOLLOW ?? 0);
  return fs.openSync(filePath, flags, 0o600);
}

type CappedFile = { fd?: number; bytes: number; truncated: boolean; failed: boolean };

/**
 * Creates `<stateDir>/runs/<runId>/` and opens its stream files. Everything
 * is refused before a write when the run id is malformed, the record would
 * land inside `projectRoot`, `runs/` is not a plain directory, or the run
 * directory already exists (so nothing pre-planted in it is ever followed).
 */
/**
 * Refuses a run record that would land in the project (a state directory
 * under the workspace). The run calls it before the lock too, so the refusal
 * comes before any host write or delete under the state directory.
 */
export function assertRunRecordOutsideProject(stateDir: string, runId: string, projectRoot: string): void {
  const dir = path.join(stateDir, "runs", runId);
  if (isPathInsideByRealpath(projectRoot, dir)) {
    throw recordError(`must be outside the project: ${dir}`);
  }
}

export function createRunRecord(
  stateDir: string,
  runId: string,
  options: Readonly<{ projectRoot: string; transcriptCapBytes?: number; stderrCapBytes?: number }>,
): HeadlessRunRecord {
  if (!HEADLESS_RUN_ID_PATTERN.test(runId)) throw recordError(`run id is malformed: ${JSON.stringify(runId)}`);
  const runsDir = path.join(stateDir, "runs");
  const dir = path.join(runsDir, runId);
  assertRunRecordOutsideProject(stateDir, runId, options.projectRoot);
  ensureRunsDirectory(runsDir);
  try {
    fs.mkdirSync(dir, { mode: 0o700 });
  } catch (error) {
    throw recordError(`directory could not be created (it must not exist): ${dir}`, error);
  }
  const transcriptCap = options.transcriptCapBytes ?? HEADLESS_TRANSCRIPT_CAP_BYTES;
  const stderrCap = options.stderrCapBytes ?? HEADLESS_STDERR_CAP_BYTES;
  const transcript: CappedFile = { fd: openNewFile(path.join(dir, "transcript.jsonl")), bytes: 0, truncated: false, failed: false };
  let stderr: CappedFile;
  try {
    stderr = { fd: openNewFile(path.join(dir, "stderr.log")), bytes: 0, truncated: false, failed: false };
  } catch (error) {
    fs.closeSync(transcript.fd as number);
    throw error;
  }

  let finalized = false;
  let restoreTee: (() => void) | undefined;

  const append = (file: CappedFile, cap: number, chunk: Buffer): void => {
    if (file.fd === undefined || file.failed || chunk.length === 0) return;
    const room = cap - file.bytes;
    const part = chunk.length > room ? chunk.subarray(0, Math.max(room, 0)) : chunk;
    if (part.length < chunk.length) file.truncated = true;
    if (part.length === 0) return;
    let offset = 0;
    try {
      while (offset < part.length) offset += fs.writeSync(file.fd, part, offset);
    } catch (error) {
      file.failed = true;
      throw recordError("write failed", error);
    } finally {
      file.bytes += offset;
    }
  };

  const close = (file: CappedFile): void => {
    if (file.fd === undefined) return;
    const fd = file.fd;
    file.fd = undefined;
    try {
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  };

  return Object.freeze({
    dir,
    appendTranscript: (chunk: Buffer) => append(transcript, transcriptCap, chunk),
    appendStderr: (chunk: Buffer) => append(stderr, stderrCap, chunk),
    transcriptBytes: () => transcript.bytes,
    transcriptTruncated: () => transcript.truncated,
    stderrTruncated: () => stderr.truncated,
    startStderrTee(stream: NodeJS.WriteStream = process.stderr): void {
      if (finalized || restoreTee) return;
      const original = stream.write;
      const tee = function (this: NodeJS.WriteStream, ...args: Parameters<NodeJS.WriteStream["write"]>): boolean {
        const [chunk, encoding] = args;
        try {
          if (typeof chunk === "string") {
            append(stderr, stderrCap, Buffer.from(chunk, typeof encoding === "string" ? encoding : "utf8"));
          } else if (chunk instanceof Uint8Array) {
            append(stderr, stderrCap, Buffer.from(chunk));
          }
        } catch {
          // The record write failed; Runfree's own stderr still goes out.
        }
        return original.apply(this, args);
      } as NodeJS.WriteStream["write"];
      stream.write = tee;
      restoreTee = () => {
        if (stream.write === tee) stream.write = original;
      };
    },
    finalize(run: HeadlessRunJson, result: Readonly<{ finalMessage?: string }>): void {
      if (finalized) throw recordError("already finalized");
      finalized = true;
      restoreTee?.();
      restoreTee = undefined;
      close(transcript);
      close(stderr);
      atomicReplaceFile(path.join(dir, "result.md"), result.finalMessage === undefined ? "" : `${result.finalMessage}\n`);
      atomicReplaceFile(path.join(dir, "run.json"), `${JSON.stringify(run, null, 2)}\n`);
    },
  });
}

/**
 * The text `run` prints to stdout on exit (spec §3.4), so a scheduler's log
 * or mail shows it: the final message (or a one-line note), any warning, and
 * the record path last.
 */
export function summaryLines(input: Readonly<{
  run: HeadlessRunJson;
  finalMessage?: string;
  recordDir: string;
}>): string[] {
  const lines: string[] = [];
  lines.push(input.finalMessage ?? `(no final message from the agent; outcome: ${input.run.outcome})`);
  const denials = input.run.headlessDenials;
  if (denials === null && input.run.teardown !== "not-started") {
    lines.push("warning: the headless write denials could not be counted");
  } else if (denials !== null && denials > 0) {
    lines.push(`warning: ${denials} ${denials === 1 ? "write was" : "writes were"} denied (headless)`);
  }
  if (input.run.teardown === "unconfirmed") {
    lines.push("warning: the session container stop was not confirmed; the run lock is kept until it is gone");
  }
  lines.push(`run record: ${input.recordDir}`);
  return lines;
}
