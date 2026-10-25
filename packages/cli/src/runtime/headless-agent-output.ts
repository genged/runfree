// Bounded, tolerant parsers for a headless agent's stdout event stream, and
// the outcome rule (headless-run spec §3.1).
//
// Agent stdout is hostile input. Every parser here bounds the line it buffers
// (`HEADLESS_OUTPUT_LINE_CAP_BYTES`), the final message it keeps
// (`HEADLESS_FINAL_MESSAGE_CAP_BYTES`), and the total it reads
// (`HEADLESS_TRANSCRIPT_CAP_BYTES` by default). It only ever `JSON.parse`s one
// bounded line, and `push`/`endStream`/`result` never throw.
//
// The per-agent event field names are unverified hypotheses (spec §3.1
// "Hypothesis") until the agent-CLI contract (plan Task 16) pins them. Each
// agent's names live in one exported constant so the contract can import and
// check them. A mismatch means the parser sees no final success event, and the
// outcome rule turns that into `unverified`, never into success.

import type { HeadlessOutputFormat } from "../agents.ts";

export const HEADLESS_OUTPUT_LINE_CAP_BYTES = 1024 * 1024;
export const HEADLESS_FINAL_MESSAGE_CAP_BYTES = 256 * 1024;
export const HEADLESS_TRANSCRIPT_CAP_BYTES = 64 * 1024 * 1024;

/**
 * Claude Code `--output-format stream-json` final event (hypothesis until
 * plan Task 16 pins it): the last line whose `type` is `result`.
 * It is a success only when `subtype` is `success`, `is_error` is exactly
 * `false`, and `result` (the final assistant message) is a string.
 */
export const CLAUDE_STREAM_JSON_RESULT_EVENT = Object.freeze({
  typeField: "type",
  typeValue: "result",
  subtypeField: "subtype",
  successSubtype: "success",
  isErrorField: "is_error",
  messageField: "result",
} as const);

export type HeadlessOutputParserResult = Readonly<{
  /** The last stream ended (`endStream`) and no byte was dropped past the total cap. */
  complete: boolean;
  /** The last final event the agent emitted was a success. */
  finalSuccess: boolean;
  finalMessage?: string;
  finalMessageTruncated: boolean;
  malformedLines: number;
  overflowed: boolean;
}>;

export type HeadlessOutputParser = Readonly<{
  push(chunk: Buffer): void;
  /** One captured stream ended; a later `push` starts a new (re-attached) stream. */
  endStream(): void;
  result(): HeadlessOutputParserResult;
}>;

type FinalEvent = Readonly<{ success: boolean; message?: string }>;

/** Reads one parsed JSON object; `undefined` when it is not a final event. */
type FinalEventReader = (event: Readonly<Record<string, unknown>>) => FinalEvent | undefined;

function readClaudeFinalEvent(event: Readonly<Record<string, unknown>>): FinalEvent | undefined {
  const names = CLAUDE_STREAM_JSON_RESULT_EVENT;
  if (event[names.typeField] !== names.typeValue) return undefined;
  const message = event[names.messageField];
  const success = event[names.subtypeField] === names.successSubtype
    && event[names.isErrorField] === false
    && typeof message === "string";
  return typeof message === "string" ? { success, message } : { success };
}

// Codex and Pi get their readers with their headless argv (plan Task 15).
// Until then nothing they print is a final success, so a run is unverified.
const FINAL_EVENT_READERS: Readonly<Record<HeadlessOutputFormat, FinalEventReader>> = Object.freeze({
  "claude-stream-json": readClaudeFinalEvent,
  "codex-exec-json": () => undefined,
  "pi-json": () => undefined,
});

function truncateUtf8(value: string, capBytes: number): { value: string; truncated: boolean } {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length <= capBytes) return { value, truncated: false };
  let end = capBytes;
  // Back off continuation bytes (10xxxxxx) so the cut is on a code point.
  while (end > 0 && ((bytes[end] ?? 0) & 0xc0) === 0x80) end -= 1;
  return { value: bytes.subarray(0, end).toString("utf8"), truncated: true };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function createHeadlessOutputParser(
  format: HeadlessOutputFormat,
  options: Readonly<{ totalCapBytes?: number }> = {},
): HeadlessOutputParser {
  const readFinal = Object.hasOwn(FINAL_EVENT_READERS, format) ? FINAL_EVENT_READERS[format] : () => undefined;
  const totalCapBytes = options.totalCapBytes ?? HEADLESS_TRANSCRIPT_CAP_BYTES;
  const decoder = new TextDecoder("utf-8", { fatal: true });

  let pending: Buffer[] = [];
  let pendingBytes = 0;
  let discarding = false;
  let totalBytes = 0;
  let overflowed = false;
  let ended = false;
  let malformedLines = 0;
  let final: FinalEvent | undefined;

  const parseLine = (line: Buffer): void => {
    let end = line.length;
    if (end > 0 && line[end - 1] === 0x0d) end -= 1;
    if (end === 0) return;
    try {
      const value: unknown = JSON.parse(decoder.decode(line.subarray(0, end)));
      if (!isPlainObject(value)) {
        malformedLines += 1;
        return;
      }
      const event = readFinal(value);
      if (event) final = event;
    } catch {
      malformedLines += 1;
    }
  };

  const takePending = (): Buffer => {
    const line = pending.length === 1 ? pending[0] as Buffer : Buffer.concat(pending, pendingBytes);
    pending = [];
    pendingBytes = 0;
    return line;
  };

  const append = (part: Buffer): void => {
    if (part.length === 0 || discarding) return;
    if (pendingBytes + part.length > HEADLESS_OUTPUT_LINE_CAP_BYTES) {
      pending = [];
      pendingBytes = 0;
      discarding = true;
      malformedLines += 1;
      return;
    }
    pending.push(part);
    pendingBytes += part.length;
  };

  const consume = (chunk: Buffer): void => {
    let start = 0;
    while (start < chunk.length) {
      const newline = chunk.indexOf(0x0a, start);
      if (newline === -1) {
        append(chunk.subarray(start));
        return;
      }
      append(chunk.subarray(start, newline));
      if (discarding) {
        discarding = false;
      } else if (pendingBytes > 0) {
        parseLine(takePending());
      }
      start = newline + 1;
    }
  };

  return Object.freeze({
    push(chunk: Buffer): void {
      try {
        ended = false;
        if (overflowed || !Buffer.isBuffer(chunk) || chunk.length === 0) return;
        const room = totalCapBytes - totalBytes;
        const accepted = chunk.length > room ? chunk.subarray(0, Math.max(room, 0)) : chunk;
        totalBytes += accepted.length;
        consume(accepted);
        if (accepted.length < chunk.length) {
          overflowed = true;
          pending = [];
          pendingBytes = 0;
        }
      } catch {
        // Unreachable by construction; a parser never throws into the run.
        overflowed = true;
      }
    },
    endStream(): void {
      try {
        if (!overflowed && !discarding && pendingBytes > 0) parseLine(takePending());
        pending = [];
        pendingBytes = 0;
        discarding = false;
      } catch {
        overflowed = true;
      }
      ended = true;
    },
    result(): HeadlessOutputParserResult {
      const truncated = final?.message === undefined
        ? undefined
        : truncateUtf8(final.message, HEADLESS_FINAL_MESSAGE_CAP_BYTES);
      return Object.freeze({
        complete: ended && !overflowed,
        finalSuccess: final?.success === true,
        ...(truncated ? { finalMessage: truncated.value } : {}),
        finalMessageTruncated: truncated?.truncated ?? false,
        malformedLines,
        overflowed,
      });
    },
  });
}

export type HeadlessOutcome = Readonly<{
  outcome: "success" | "failed" | "unverified";
  exitCode: number;
}>;

/**
 * The outcome rule (spec §3.1, §3.6): status 0 with drained streams, a
 * complete parse, and a final success event is success (0); a nonzero agent
 * status is a failure with that status, or 1 above 63 so it never collides
 * with Runfree's reserved 64-68; anything else (a lost status, a stream that
 * did not drain, no final success) is `unverified` with 1.
 */
export function decideHeadlessOutcome(input: Readonly<{
  agentStatus: number | null;
  streamsDrained: boolean;
  parser: HeadlessOutputParserResult;
}>): HeadlessOutcome {
  const status = input.agentStatus;
  if (typeof status === "number" && Number.isSafeInteger(status) && status > 0) {
    return { outcome: "failed", exitCode: status <= 63 ? status : 1 };
  }
  if (status === 0 && input.streamsDrained && input.parser.complete && input.parser.finalSuccess) {
    return { outcome: "success", exitCode: 0 };
  }
  return { outcome: "unverified", exitCode: 1 };
}
