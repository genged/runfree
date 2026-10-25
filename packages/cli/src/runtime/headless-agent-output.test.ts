import fc from "fast-check";
import { describe, expect, test } from "vitest";

import type { HeadlessOutputFormat } from "../agents.ts";
import {
  CLAUDE_STREAM_JSON_RESULT_EVENT,
  CODEX_EXEC_JSON_EVENTS,
  createHeadlessOutputParser,
  decideHeadlessOutcome,
  HEADLESS_FINAL_MESSAGE_CAP_BYTES,
  HEADLESS_OUTPUT_LINE_CAP_BYTES,
  type HeadlessOutputParserResult,
  PI_JSON_AGENT_END_EVENT,
} from "./headless-agent-output.ts";

// Headless-run spec §3.1 and §5 "the outcome rule": agent stdout is hostile
// data. The parser never throws, bounds every buffer, and only an explicit
// final success event together with status 0 and a drained stream is success.

const SUCCESS_EVENT = JSON.stringify({
  type: "result",
  subtype: "success",
  is_error: false,
  result: "All done: wrote report.md",
  session_id: "3f1c2b9e-8a4d-4c1e-9f2a-0b6d7e8f9a10",
});

function claudeStream(...lines: string[]): Buffer {
  return Buffer.from(lines.map((line) => `${line}\n`).join(""));
}

function parse(bytes: Buffer, chunkSize = bytes.length || 1): HeadlessOutputParserResult {
  const parser = createHeadlessOutputParser("claude-stream-json");
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    parser.push(bytes.subarray(offset, offset + chunkSize));
  }
  parser.endStream();
  return parser.result();
}

describe("claude stream-json parser", () => {
  test("reads the final success event and its message", () => {
    const result = parse(claudeStream(
      JSON.stringify({ type: "system", subtype: "init" }),
      JSON.stringify({ type: "assistant", message: { content: [] } }),
      SUCCESS_EVENT,
    ));
    expect(result).toMatchObject({
      complete: true,
      finalSuccess: true,
      finalMessage: "All done: wrote report.md",
      malformedLines: 0,
    });
  });

  test("the field names it reads are one pinned hypothesis", () => {
    expect(CLAUDE_STREAM_JSON_RESULT_EVENT).toEqual({
      typeField: "type",
      typeValue: "result",
      subtypeField: "subtype",
      successSubtype: "success",
      isErrorField: "is_error",
      messageField: "result",
    });
  });

  test.each([
    ["is_error true", { type: "result", subtype: "success", is_error: true, result: "x" }],
    ["error subtype", { type: "result", subtype: "error_during_execution", is_error: false, result: "x" }],
    ["missing is_error", { type: "result", subtype: "success", result: "x" }],
    ["is_error as a string", { type: "result", subtype: "success", is_error: "false", result: "x" }],
    ["non-string result", { type: "result", subtype: "success", is_error: false, result: 7 }],
  ])("a result event with %s is not a final success", (_label, event) => {
    expect(parse(claudeStream(JSON.stringify(event))).finalSuccess).toBe(false);
  });

  test("only the last result event counts", () => {
    const failure = JSON.stringify({ type: "result", subtype: "error_max_turns", is_error: true });
    expect(parse(claudeStream(SUCCESS_EVENT, failure)).finalSuccess).toBe(false);
    expect(parse(claudeStream(failure, SUCCESS_EVENT)).finalSuccess).toBe(true);
  });

  test("garbage, arrays, scalars and invalid UTF-8 count as malformed and never throw", () => {
    const bytes = Buffer.concat([
      Buffer.from("not json at all\n[1,2,3]\n42\nnull\n\"str\"\n{\"type\":\n"),
      Buffer.from([0xff, 0xfe, 0x7b, 0x7d, 0x0a]),
      Buffer.from("\n\r\n"),
    ]);
    const result = parse(bytes);
    expect(result).toMatchObject({ complete: true, finalSuccess: false, malformedLines: 7 });
    expect(result.finalMessage).toBeUndefined();
  });

  // A dropped line may have been the event that changed the outcome, so it
  // voids an earlier success until a later final event re-establishes one.
  test("a success followed by a dropped line is not a success until a later final event", () => {
    const oversized = "a".repeat(HEADLESS_OUTPUT_LINE_CAP_BYTES + 1);
    for (const dropped of [oversized, "{\"type\":\"result\",\"subtype\":"]) {
      const result = parse(claudeStream(SUCCESS_EVENT, dropped));
      expect(result).toMatchObject({ complete: true, finalSuccess: false, malformedLines: 1 });
      expect(decideHeadlessOutcome({ agentStatus: 0, streamsDrained: true, parser: result }).outcome).toBe("unverified");
    }
    expect(parse(claudeStream("not json", SUCCESS_EVENT))).toMatchObject({ complete: true, finalSuccess: true, malformedLines: 1 });
    expect(parse(claudeStream(SUCCESS_EVENT, "not json", SUCCESS_EVENT)).finalSuccess).toBe(true);
    expect(parseAs("codex-exec-json", Buffer.concat([CODEX_SUCCESS, Buffer.from("not json\n")])).finalSuccess).toBe(false);
    expect(parseAs("pi-json", Buffer.concat([PI_SUCCESS, Buffer.from("not json\n")])).finalSuccess).toBe(false);
  });

  test("a line over the line cap is discarded to the next newline and counted", () => {
    const parser = createHeadlessOutputParser("claude-stream-json");
    const huge = Buffer.alloc(2 * 1024 * 1024, 0x61);
    // A success event hidden inside the oversized line must not be parsed.
    parser.push(Buffer.from(SUCCESS_EVENT));
    for (let offset = 0; offset < huge.length; offset += 64 * 1024) {
      expect(() => parser.push(huge.subarray(offset, offset + 64 * 1024))).not.toThrow();
    }
    parser.push(Buffer.from(`${SUCCESS_EVENT}\n`));
    expect(parser.result()).toMatchObject({ finalSuccess: false, malformedLines: 1 });
    parser.push(Buffer.from(`${SUCCESS_EVENT}\n`));
    parser.endStream();
    expect(parser.result()).toMatchObject({ complete: true, finalSuccess: true, malformedLines: 1 });
  });

  test("a line of exactly the cap is parsed", () => {
    const event = { type: "result", subtype: "success", is_error: false, result: "" };
    const overhead = Buffer.byteLength(JSON.stringify(event));
    event.result = "b".repeat(HEADLESS_OUTPUT_LINE_CAP_BYTES - overhead);
    const line = JSON.stringify(event);
    expect(Buffer.byteLength(line)).toBe(HEADLESS_OUTPUT_LINE_CAP_BYTES);
    const result = parse(claudeStream(line), 4096);
    expect(result.finalSuccess).toBe(true);
    expect(Buffer.byteLength(result.finalMessage ?? "")).toBe(HEADLESS_FINAL_MESSAGE_CAP_BYTES);
    expect(result.finalMessageTruncated).toBe(true);
  });

  test("a final message is truncated on a UTF-8 boundary", () => {
    const message = "é".repeat(HEADLESS_FINAL_MESSAGE_CAP_BYTES);
    const result = parse(claudeStream(JSON.stringify({ type: "result", subtype: "success", is_error: false, result: message })));
    const bytes = Buffer.byteLength(result.finalMessage ?? "");
    expect(bytes).toBeLessThanOrEqual(HEADLESS_FINAL_MESSAGE_CAP_BYTES);
    expect(bytes).toBeGreaterThan(HEADLESS_FINAL_MESSAGE_CAP_BYTES - 2);
    expect(result.finalMessage).not.toContain("�");
    expect(result.finalMessageTruncated).toBe(true);
  });

  test("a final event without a trailing newline is parsed at the end of the stream", () => {
    expect(parse(Buffer.from(SUCCESS_EVENT)).finalSuccess).toBe(true);
  });

  test("a success event followed by a truncated trailing event is incomplete", () => {
    const result = parse(Buffer.concat([claudeStream(SUCCESS_EVENT), Buffer.from(SUCCESS_EVENT.slice(0, 20))]));
    expect(result).toMatchObject({ complete: false, malformedLines: 1 });
    expect(decideHeadlessOutcome({ agentStatus: 0, streamsDrained: true, parser: result }).outcome).toBe("unverified");
  });

  test("an over-cap trailing line without a newline makes the stream incomplete", () => {
    const parser = createHeadlessOutputParser("claude-stream-json");
    parser.push(claudeStream(SUCCESS_EVENT));
    parser.push(Buffer.alloc(HEADLESS_OUTPUT_LINE_CAP_BYTES + 1, 0x61));
    parser.endStream();
    expect(parser.result().complete).toBe(false);
  });

  test("a stream that has not ended is incomplete", () => {
    const parser = createHeadlessOutputParser("claude-stream-json");
    parser.push(claudeStream(SUCCESS_EVENT));
    expect(parser.result().complete).toBe(false);
    parser.endStream();
    expect(parser.result().complete).toBe(true);
  });

  test("a re-attached stream drops the partial line and keeps parsing", () => {
    const parser = createHeadlessOutputParser("claude-stream-json");
    parser.push(Buffer.from(SUCCESS_EVENT.slice(0, 20)));
    parser.endStream();
    parser.push(Buffer.from(SUCCESS_EVENT.slice(20)));
    expect(parser.result().complete).toBe(false);
    parser.push(Buffer.from(`\n${SUCCESS_EVENT}\n`));
    parser.endStream();
    // The first stream's fragment became one malformed line, the second
    // stream's leading fragment another; the whole event after it parses.
    expect(parser.result()).toMatchObject({ complete: true, finalSuccess: true, malformedLines: 2 });
  });

  test("bytes past the total cap stop parsing and make the stream incomplete", () => {
    const parser = createHeadlessOutputParser("claude-stream-json", { totalCapBytes: 1024 });
    parser.push(Buffer.alloc(1000, 0x0a));
    parser.push(claudeStream(SUCCESS_EVENT));
    parser.endStream();
    expect(parser.result()).toMatchObject({ complete: false, finalSuccess: false, overflowed: true });
  });

  test("a success event split at every byte offset parses (property)", () => {
    const stream = claudeStream(JSON.stringify({ type: "system", subtype: "init" }), SUCCESS_EVENT);
    fc.assert(fc.property(
      fc.uniqueArray(fc.integer({ min: 1, max: stream.length - 1 }), { maxLength: 12 }),
      (cuts) => {
        const sorted = [...cuts].sort((left, right) => left - right);
        const parser = createHeadlessOutputParser("claude-stream-json");
        let previous = 0;
        for (const cut of [...sorted, stream.length]) {
          parser.push(stream.subarray(previous, cut));
          previous = cut;
        }
        parser.endStream();
        const result = parser.result();
        return result.finalSuccess && result.finalMessage === "All done: wrote report.md" && result.malformedLines === 0;
      },
    ), { numRuns: 300 });
    for (let cut = 1; cut < stream.length; cut += 1) {
      const parser = createHeadlessOutputParser("claude-stream-json");
      parser.push(stream.subarray(0, cut));
      parser.push(stream.subarray(cut));
      parser.endStream();
      expect(parser.result().finalSuccess).toBe(true);
    }
  });

  test("random bytes never throw and never yield a final success (property)", () => {
    fc.assert(fc.property(fc.array(fc.uint8Array({ maxLength: 512 }), { maxLength: 8 }), (chunks) => {
      const parser = createHeadlessOutputParser("claude-stream-json");
      for (const chunk of chunks) parser.push(Buffer.from(chunk));
      parser.endStream();
      return parser.result().finalSuccess === false;
    }), { numRuns: 300 });
  });
});

// Recorded shapes (2026-10-25, the pinned Codex 0.156.1 and Pi 0.87.1 run
// offline against loopback fake model servers): plan Task 15. Long fields are
// trimmed; the field names and values the parsers read are as recorded.

function jsonLines(events: readonly unknown[]): Buffer {
  return Buffer.from(events.map((event) => `${JSON.stringify(event)}\n`).join(""));
}

function parseAs(format: HeadlessOutputFormat, bytes: Buffer, chunkSize = bytes.length || 1): HeadlessOutputParserResult {
  const parser = createHeadlessOutputParser(format);
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    parser.push(bytes.subarray(offset, offset + chunkSize));
  }
  parser.endStream();
  return parser.result();
}

function splitEverywhere(format: HeadlessOutputFormat, stream: Buffer, expectedMessage: string): void {
  fc.assert(fc.property(
    fc.uniqueArray(fc.integer({ min: 1, max: stream.length - 1 }), { maxLength: 12 }),
    (cuts) => {
      const parser = createHeadlessOutputParser(format);
      let previous = 0;
      for (const cut of [...cuts].sort((left, right) => left - right).concat(stream.length)) {
        parser.push(stream.subarray(previous, cut));
        previous = cut;
      }
      parser.endStream();
      const result = parser.result();
      return result.finalSuccess && result.finalMessage === expectedMessage && result.malformedLines === 0;
    },
  ), { numRuns: 200 });
  for (let cut = 1; cut < stream.length; cut += 1) {
    const parser = createHeadlessOutputParser(format);
    parser.push(stream.subarray(0, cut));
    parser.push(stream.subarray(cut));
    parser.endStream();
    expect(parser.result().finalSuccess).toBe(true);
  }
}

const CODEX_THREAD_START = [
  { type: "thread.started", thread_id: "01a173ba-8959-7542-bbcc-85d56970fbb1" },
  { type: "turn.started" },
];
const CODEX_AGENT_MESSAGE = { type: "item.completed", item: { id: "item_0", type: "agent_message", text: "contract-ok" } };
const CODEX_TURN_COMPLETED = {
  type: "turn.completed",
  usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1, reasoning_output_tokens: 0 },
};
const CODEX_PROVIDER_ERROR = "{\"error\":{\"message\":\"contract probe\",\"type\":\"invalid_request_error\"}}";
const CODEX_SUCCESS = jsonLines([...CODEX_THREAD_START, CODEX_AGENT_MESSAGE, CODEX_TURN_COMPLETED]);
const CODEX_FAILURE = jsonLines([
  ...CODEX_THREAD_START,
  { type: "error", message: CODEX_PROVIDER_ERROR },
  { type: "turn.failed", error: { message: CODEX_PROVIDER_ERROR } },
]);

describe("codex exec --json parser", () => {
  test("reads turn.completed as success and the last agent message as the final message", () => {
    expect(parseAs("codex-exec-json", CODEX_SUCCESS)).toMatchObject({
      complete: true,
      finalSuccess: true,
      finalMessage: "contract-ok",
      malformedLines: 0,
    });
  });

  test("the field names it reads are one pinned constant", () => {
    expect(CODEX_EXEC_JSON_EVENTS).toEqual({
      typeField: "type",
      turnCompletedType: "turn.completed",
      turnFailedType: "turn.failed",
      errorType: "error",
      itemCompletedType: "item.completed",
      itemField: "item",
      itemTypeField: "type",
      agentMessageItemType: "agent_message",
      agentMessageTextField: "text",
    });
  });

  test("the recorded failed request (error, then turn.failed) is not a success", () => {
    const result = parseAs("codex-exec-json", CODEX_FAILURE);
    expect(result).toMatchObject({ complete: true, finalSuccess: false, malformedLines: 0 });
    expect(result.finalMessage).toBeUndefined();
    // Codex exits 1 here; with a 0 status the run is still never a success.
    expect(decideHeadlessOutcome({ agentStatus: 0, streamsDrained: true, parser: result }))
      .toEqual({ outcome: "unverified", exitCode: 1 });
    expect(decideHeadlessOutcome({ agentStatus: 1, streamsDrained: true, parser: result }))
      .toEqual({ outcome: "failed", exitCode: 1 });
  });

  test.each([
    ["turn.failed after turn.completed", [CODEX_AGENT_MESSAGE, CODEX_TURN_COMPLETED, { type: "turn.failed", error: { message: "x" } }]],
    ["turn.failed before turn.completed", [{ type: "turn.failed", error: { message: "x" } }, CODEX_AGENT_MESSAGE, CODEX_TURN_COMPLETED]],
    ["an error event before turn.completed", [{ type: "error", message: "Reconnecting... 2/5" }, CODEX_AGENT_MESSAGE, CODEX_TURN_COMPLETED]],
    ["no turn.completed", [CODEX_AGENT_MESSAGE]],
    ["a turn.completed spelled differently", [CODEX_AGENT_MESSAGE, { ...CODEX_TURN_COMPLETED, type: "turn.complete" }]],
    ["only a Claude result event", [{ type: "result", subtype: "success", is_error: false, result: "x" }]],
  ])("%s is not a final success", (_label, events) => {
    expect(parseAs("codex-exec-json", jsonLines([...CODEX_THREAD_START, ...events])).finalSuccess).toBe(false);
  });

  test("an error item is not the final message, and the last agent message wins", () => {
    const result = parseAs("codex-exec-json", jsonLines([
      ...CODEX_THREAD_START,
      { type: "item.completed", item: { id: "item_0", type: "agent_message", text: "first" } },
      { type: "item.completed", item: { id: "item_1", type: "error", message: "Falling back from WebSockets" } },
      { type: "item.completed", item: { id: "item_2", type: "agent_message", text: "second" } },
      { type: "item.completed", item: { id: "item_3", type: "agent_message", text: 7 } },
      { type: "item.completed", item: "not an object" },
      CODEX_TURN_COMPLETED,
    ]));
    expect(result).toMatchObject({ finalSuccess: true, finalMessage: "second" });
  });

  test("a truncated stream (cut inside turn.completed) is not a success", () => {
    const cut = CODEX_SUCCESS.length - 20;
    const result = parseAs("codex-exec-json", CODEX_SUCCESS.subarray(0, cut));
    expect(result).toMatchObject({ finalSuccess: false, malformedLines: 1 });
  });

  test("a turn.completed split at every byte offset parses (property)", () => {
    splitEverywhere("codex-exec-json", CODEX_SUCCESS, "contract-ok");
  });

  test("malformed lines never throw and never yield success", () => {
    const result = parseAs("codex-exec-json", Buffer.concat([
      Buffer.from("garbage\n[\"turn.completed\"]\n\"turn.completed\"\n"),
      Buffer.from([0xff, 0x0a]),
      Buffer.from("{\"type\":\"turn.completed\"\n"),
    ]));
    expect(result).toMatchObject({ complete: true, finalSuccess: false, malformedLines: 5 });
  });
});

const PI_HEADER = { type: "session", version: 3, id: "3f1c2b9e-8a4d-4c1e-9f2a-0b6d7e8f9a12", timestamp: "2026-10-25T15:43:45.920Z", cwd: "/workspace" };
const PI_SYSTEM = { role: "system", content: "", sections: { preamble: "You are an expert coding assistant operating inside pi." }, timestamp: 1792943025910 };
const PI_USER = { role: "user", content: [{ type: "text", text: "say hi" }], timestamp: 1792943025920 };
const PI_USAGE = { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } };

function piAssistant(fields: Readonly<Record<string, unknown>>): Record<string, unknown> {
  return {
    role: "assistant",
    content: [{ type: "text", text: "contract-ok" }],
    api: "anthropic-messages",
    provider: "probe",
    model: "probe-model",
    usage: PI_USAGE,
    stopReason: "stop",
    timestamp: 1792943025928,
    ...fields,
  };
}

function piRun(assistant: Record<string, unknown>, willRetry: unknown = false): unknown[] {
  return [
    { type: "agent_start" },
    { type: "turn_start" },
    { type: "message_end", message: PI_USER },
    { type: "message_end", message: assistant },
    { type: "turn_end", message: assistant, toolResults: [] },
    { type: "agent_end", messages: [PI_SYSTEM, PI_USER, assistant], willRetry },
  ];
}

const PI_FAILED_ASSISTANT = piAssistant({ content: [], usage: { ...PI_USAGE, input: 0, output: 0, totalTokens: 0 }, stopReason: "error", errorMessage: "Connection error." });
const PI_SUCCESS = jsonLines([PI_HEADER, ...piRun(piAssistant({})), { type: "agent_settled" }]);
// Recorded: Pi retries a connection error, emitting an `agent_end` with
// `willRetry: true` each time, then a last one with `willRetry: false`, and
// still exits 0 (print-mode.ts sets a nonzero code only in text mode).
const PI_FAILURE = jsonLines([
  PI_HEADER,
  ...piRun(PI_FAILED_ASSISTANT, true),
  { type: "auto_retry_start", attempt: 1, maxAttempts: 3, delayMs: 2000, errorMessage: "Connection error." },
  ...piRun(PI_FAILED_ASSISTANT, false),
  { type: "auto_retry_end", success: false, attempt: 3, finalError: "Connection error." },
  { type: "agent_settled" },
]);

describe("pi --mode json parser", () => {
  test("reads the last agent_end whose last assistant message stopped normally", () => {
    expect(parseAs("pi-json", PI_SUCCESS)).toMatchObject({
      complete: true,
      finalSuccess: true,
      finalMessage: "contract-ok",
      malformedLines: 0,
    });
  });

  test("the field names it reads are one pinned constant", () => {
    expect(PI_JSON_AGENT_END_EVENT).toEqual({
      typeField: "type",
      typeValue: "agent_end",
      messagesField: "messages",
      willRetryField: "willRetry",
      roleField: "role",
      assistantRole: "assistant",
      stopReasonField: "stopReason",
      successStopReasons: ["stop"],
      contentField: "content",
      textPartType: "text",
      textField: "text",
    });
  });

  test("Pi exit 0 after a failed request (stopReason error) is unverified, not success", () => {
    const result = parseAs("pi-json", PI_FAILURE);
    expect(result).toMatchObject({ complete: true, finalSuccess: false, malformedLines: 0 });
    expect(decideHeadlessOutcome({ agentStatus: 0, streamsDrained: true, parser: result }))
      .toEqual({ outcome: "unverified", exitCode: 1 });
  });

  test.each([
    ["stopReason aborted", piRun(piAssistant({ stopReason: "aborted", errorMessage: "Request aborted" }))],
    ["stopReason length", piRun(piAssistant({ stopReason: "length" }))],
    ["stopReason toolUse", piRun(piAssistant({ stopReason: "toolUse" }))],
    ["a missing stopReason", piRun(piAssistant({ stopReason: undefined }))],
    ["willRetry true on the last agent_end", piRun(piAssistant({}), true)],
    ["a missing willRetry", [{ type: "agent_end", messages: [PI_SYSTEM, PI_USER, piAssistant({})] }]],
    ["no assistant message", [{ type: "agent_end", messages: [PI_SYSTEM, PI_USER], willRetry: false }]],
    ["messages not an array", [{ type: "agent_end", messages: "x", willRetry: false }]],
    ["no agent_end at all", piRun(piAssistant({})).slice(0, -1)],
    ["a success followed by a failed run", [...piRun(piAssistant({})), ...piRun(PI_FAILED_ASSISTANT)]],
  ])("%s is not a final success", (_label, events) => {
    expect(parseAs("pi-json", jsonLines([PI_HEADER, ...events])).finalSuccess).toBe(false);
  });

  test("a failed run followed by a successful retry is a success", () => {
    const result = parseAs("pi-json", jsonLines([PI_HEADER, ...piRun(PI_FAILED_ASSISTANT, true), ...piRun(piAssistant({}))]));
    expect(result).toMatchObject({ finalSuccess: true, finalMessage: "contract-ok" });
  });

  test("the final message joins the last assistant message's text parts only", () => {
    const assistant = piAssistant({
      content: [
        { type: "thinking", thinking: "hidden" },
        { type: "text", text: "line one" },
        { type: "toolCall", id: "t1", name: "bash", arguments: {} },
        { type: "text", text: "line two" },
        { type: "text", text: 9 },
      ],
    });
    // A tool result after the assistant message does not hide it.
    const toolResult = { role: "toolResult", toolCallId: "t1", content: [], isError: false, timestamp: 1 };
    const result = parseAs("pi-json", jsonLines([{ type: "agent_end", messages: [PI_USER, assistant, toolResult], willRetry: false }]));
    expect(result).toMatchObject({ finalSuccess: true, finalMessage: "line one\nline two" });
  });

  test("a truncated stream (cut inside agent_end) is not a success", () => {
    const withoutSettled = jsonLines([PI_HEADER, ...piRun(piAssistant({}))]);
    const result = parseAs("pi-json", withoutSettled.subarray(0, withoutSettled.length - 30));
    expect(result).toMatchObject({ finalSuccess: false, malformedLines: 1 });
  });

  test("an agent_end split at every byte offset parses (property)", () => {
    splitEverywhere("pi-json", jsonLines([...piRun(piAssistant({})).slice(-1)]), "contract-ok");
  });

  test("random bytes never throw and never yield a final success for any format (property)", () => {
    for (const format of ["codex-exec-json", "pi-json"] as const) {
      fc.assert(fc.property(fc.array(fc.uint8Array({ maxLength: 512 }), { maxLength: 8 }), (chunks) => {
        const parser = createHeadlessOutputParser(format);
        for (const chunk of chunks) parser.push(Buffer.from(chunk));
        parser.endStream();
        return parser.result().finalSuccess === false;
      }), { numRuns: 200 });
    }
  });

  test("a Claude success event is not a Pi or Codex success", () => {
    for (const format of ["codex-exec-json", "pi-json"] as const) {
      expect(parseAs(format, claudeStream(SUCCESS_EVENT)).finalSuccess).toBe(false);
    }
    expect(parseAs("claude-stream-json", PI_SUCCESS).finalSuccess).toBe(false);
    expect(parseAs("claude-stream-json", CODEX_SUCCESS).finalSuccess).toBe(false);
  });
});

describe("decideHeadlessOutcome", () => {
  const success = parse(claudeStream(SUCCESS_EVENT));
  const noResult = parse(claudeStream(JSON.stringify({ type: "assistant" })));
  const malformed = parse(Buffer.from("garbage\n[1]\n"));
  const errorResult = parse(claudeStream(JSON.stringify({ type: "result", subtype: "success", is_error: true, result: "x" })));

  test.each([
    ["status 0, drained, final success", 0, true, success, { outcome: "success", exitCode: 0 }],
    ["status 0, no result event", 0, true, noResult, { outcome: "unverified", exitCode: 1 }],
    ["status 0, malformed stream", 0, true, malformed, { outcome: "unverified", exitCode: 1 }],
    ["status 0, is_error result", 0, true, errorResult, { outcome: "unverified", exitCode: 1 }],
    ["status 0, exit before the last chunk", 0, false, success, { outcome: "unverified", exitCode: 1 }],
    ["lost status", null, true, success, { outcome: "unverified", exitCode: 1 }],
    ["status 2", 2, true, success, { outcome: "failed", exitCode: 2 }],
    ["status 63", 63, false, noResult, { outcome: "failed", exitCode: 63 }],
    ["status 64", 64, true, noResult, { outcome: "failed", exitCode: 1 }],
    ["status 137", 137, true, noResult, { outcome: "failed", exitCode: 1 }],
    ["status -1", -1, true, success, { outcome: "unverified", exitCode: 1 }],
    ["status 1.5", 1.5, true, success, { outcome: "unverified", exitCode: 1 }],
  ] as const)("%s", (_label, agentStatus, streamsDrained, parser, expected) => {
    expect(decideHeadlessOutcome({ agentStatus, streamsDrained, parser })).toEqual(expected);
  });

  test("a stream that never ended is unverified even with a success event", () => {
    const parser = createHeadlessOutputParser("claude-stream-json");
    parser.push(claudeStream(SUCCESS_EVENT));
    expect(decideHeadlessOutcome({ agentStatus: 0, streamsDrained: true, parser: parser.result() }))
      .toEqual({ outcome: "unverified", exitCode: 1 });
  });
});
