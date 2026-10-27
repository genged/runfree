// Bounded, tolerant parsers for a headless agent's stdout event stream, and
// the outcome rule (headless-run spec §3.1).
//
// Agent stdout is hostile input. Every parser here bounds the line it buffers
// (`HEADLESS_OUTPUT_LINE_CAP_BYTES`), the final message it keeps
// (`HEADLESS_FINAL_MESSAGE_CAP_BYTES`), and the total it reads
// (`HEADLESS_TRANSCRIPT_CAP_BYTES` by default). It only ever `JSON.parse`s one
// bounded line, and `push`/`endStream`/`result` never throw.
//
// The per-agent event field names are hypotheses (spec §3.1 "Hypothesis")
// that the agent-CLI contract (plan Task 16) checks against the pinned tools.
// Each agent's names live in one exported constant so the contract can import
// and check them. A mismatch means the parser sees no final success event, and the
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
  /** The last stream ended (`endStream`) on a parsed line, and no byte was dropped past the total cap. */
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

/**
 * Codex `exec --json` events (plan Task 15; event names recorded from the
 * pinned 0.156.1 run offline, field names pinned by the agent-tool contract,
 * plan Task 16). A run is a success only when a `turn.completed` arrives, no
 * `turn.failed` appears anywhere, and no top-level `error` follows the last
 * `turn.completed`. The final message is the `text` of the last completed
 * `agent_message` item.
 *
 * Codex also emits `error` for a transient reconnect ("Reconnecting... 2/5")
 * it later recovers from; a `turn.completed` after it is a success
 * (maintainer decision, 2026-10-27).
 */
export const CODEX_EXEC_JSON_EVENTS = Object.freeze({
  typeField: "type",
  turnCompletedType: "turn.completed",
  turnFailedType: "turn.failed",
  errorType: "error",
  itemCompletedType: "item.completed",
  itemField: "item",
  itemTypeField: "type",
  agentMessageItemType: "agent_message",
  agentMessageTextField: "text",
} as const);

/**
 * Pi `--mode json` final event (plan Task 15; shapes recorded from the pinned
 * 0.87.1 run offline). Pi emits one `agent_end` per agent run, including each
 * auto-retry, and exits 0 in JSON mode even after a failed request (its
 * `print-mode.ts` sets a nonzero code only in text mode). The last
 * `agent_end` is a success only when `willRetry` is exactly `false` and its
 * last assistant message has a `stopReason` in `successStopReasons`; `error`,
 * `aborted`, `length` (a cut-off reply), and anything unknown are not. The
 * final message is that message's `text` parts, joined by newlines.
 */
export const PI_JSON_AGENT_END_EVENT = Object.freeze({
  typeField: "type",
  typeValue: "agent_end",
  messagesField: "messages",
  willRetryField: "willRetry",
  roleField: "role",
  assistantRole: "assistant",
  stopReasonField: "stopReason",
  successStopReasons: Object.freeze(["stop"] as const),
  contentField: "content",
  textPartType: "text",
  textField: "text",
} as const);

type FinalEvent = Readonly<{ success: boolean; message?: string }>;

type JsonEvent = Readonly<Record<string, unknown>>;

/**
 * Per-stream state for one agent format: `observe` sees every parsed JSON
 * object in order and answers whether it was a final event, `final` gives the
 * final event so far (`undefined` while none has arrived). Neither may throw;
 * the parser guards them anyway.
 */
type FinalEventTracker = Readonly<{
  observe(event: JsonEvent): boolean;
  final(): FinalEvent | undefined;
}>;

function readClaudeFinalEvent(event: JsonEvent): FinalEvent | undefined {
  const names = CLAUDE_STREAM_JSON_RESULT_EVENT;
  if (event[names.typeField] !== names.typeValue) return undefined;
  const message = event[names.messageField];
  const success = event[names.subtypeField] === names.successSubtype
    && event[names.isErrorField] === false
    && typeof message === "string";
  return typeof message === "string" ? { success, message } : { success };
}

function claudeTracker(): FinalEventTracker {
  let final: FinalEvent | undefined;
  return {
    observe(event) {
      const read = readClaudeFinalEvent(event);
      final = read ?? final;
      return read !== undefined;
    },
    final: () => final,
  };
}

function codexTracker(): FinalEventTracker {
  const names = CODEX_EXEC_JSON_EVENTS;
  // `turn.failed` anywhere is final. An `error` counts only when no later
  // `turn.completed` follows it, so a recovered reconnect is still a success.
  let completed = false;
  let turnFailed = false;
  let errorAfterCompleted = false;
  let message: string | undefined;
  return {
    observe(event) {
      const type = event[names.typeField];
      if (type === names.turnFailedType) {
        turnFailed = true;
        return true;
      }
      if (type === names.errorType) {
        errorAfterCompleted = true;
        return true;
      }
      if (type === names.turnCompletedType) {
        completed = true;
        errorAfterCompleted = false;
        return true;
      }
      if (type === names.itemCompletedType) {
        const item = event[names.itemField];
        if (isPlainObject(item) && item[names.itemTypeField] === names.agentMessageItemType) {
          const text = item[names.agentMessageTextField];
          if (typeof text === "string") message = text;
        }
      }
      return false;
    },
    final() {
      const failed = turnFailed || errorAfterCompleted;
      if (!completed && !failed) return undefined;
      const success = completed && !failed;
      return message === undefined ? { success } : { success, message };
    },
  };
}

function readPiFinalEvent(event: JsonEvent): FinalEvent | undefined {
  const names = PI_JSON_AGENT_END_EVENT;
  if (event[names.typeField] !== names.typeValue) return undefined;
  const messages = event[names.messagesField];
  if (!Array.isArray(messages)) return { success: false };
  let assistant: Record<string, unknown> | undefined;
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const candidate: unknown = messages[index];
    if (isPlainObject(candidate) && candidate[names.roleField] === names.assistantRole) {
      assistant = candidate;
      break;
    }
  }
  if (!assistant) return { success: false };
  const stopReason = assistant[names.stopReasonField];
  const success = event[names.willRetryField] === false
    && (names.successStopReasons as readonly unknown[]).includes(stopReason);
  const content = assistant[names.contentField];
  const texts = Array.isArray(content)
    ? content.flatMap((part: unknown) =>
      isPlainObject(part) && part.type === names.textPartType && typeof part[names.textField] === "string"
        ? [part[names.textField] as string]
        : [])
    : [];
  return texts.length > 0 ? { success, message: texts.join("\n") } : { success };
}

function piTracker(): FinalEventTracker {
  let final: FinalEvent | undefined;
  return {
    observe(event) {
      const read = readPiFinalEvent(event);
      final = read ?? final;
      return read !== undefined;
    },
    final: () => final,
  };
}

const FINAL_EVENT_TRACKERS: Readonly<Record<HeadlessOutputFormat, () => FinalEventTracker>> = Object.freeze({
  "claude-stream-json": claudeTracker,
  "codex-exec-json": codexTracker,
  "pi-json": piTracker,
});

const NO_FINAL_EVENT: FinalEventTracker = Object.freeze({ observe: () => false, final: () => undefined });

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
  const tracker = Object.hasOwn(FINAL_EVENT_TRACKERS, format) ? FINAL_EVENT_TRACKERS[format]() : NO_FINAL_EVENT;
  const totalCapBytes = options.totalCapBytes ?? HEADLESS_TRANSCRIPT_CAP_BYTES;
  const decoder = new TextDecoder("utf-8", { fatal: true });

  let pending: Buffer[] = [];
  let pendingBytes = 0;
  let discarding = false;
  let totalBytes = 0;
  let overflowed = false;
  let ended = false;
  // The last stream ended inside a line that did not parse: a truncated tail.
  let brokenTail = false;
  let malformedLines = 0;
  // A dropped line may have been the event that changed the outcome, so it
  // voids the success so far until a later final event re-establishes one.
  let droppedSinceFinal = false;
  const drop = (): void => {
    malformedLines += 1;
    droppedSinceFinal = true;
  };

  const parseLine = (line: Buffer): void => {
    let end = line.length;
    if (end > 0 && line[end - 1] === 0x0d) end -= 1;
    if (end === 0) return;
    try {
      const value: unknown = JSON.parse(decoder.decode(line.subarray(0, end)));
      if (!isPlainObject(value)) {
        drop();
        return;
      }
      if (tracker.observe(value)) droppedSinceFinal = false;
    } catch {
      drop();
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
      drop();
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
        brokenTail = false;
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
        const malformedBefore = malformedLines;
        if (!overflowed && !discarding && pendingBytes > 0) parseLine(takePending());
        brokenTail = discarding || malformedLines > malformedBefore;
        pending = [];
        pendingBytes = 0;
        discarding = false;
      } catch {
        overflowed = true;
      }
      ended = true;
    },
    result(): HeadlessOutputParserResult {
      let final: FinalEvent | undefined;
      try {
        final = tracker.final();
      } catch {
        final = undefined;
      }
      const truncated = final?.message === undefined
        ? undefined
        : truncateUtf8(final.message, HEADLESS_FINAL_MESSAGE_CAP_BYTES);
      return Object.freeze({
        complete: ended && !overflowed && !brokenTail,
        finalSuccess: final?.success === true && !droppedSinceFinal,
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
