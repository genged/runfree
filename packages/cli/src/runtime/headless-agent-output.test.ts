import fc from "fast-check";
import { describe, expect, test } from "vitest";

import {
  CLAUDE_STREAM_JSON_RESULT_EVENT,
  createHeadlessOutputParser,
  decideHeadlessOutcome,
  HEADLESS_FINAL_MESSAGE_CAP_BYTES,
  HEADLESS_OUTPUT_LINE_CAP_BYTES,
  type HeadlessOutputParserResult,
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

  test.each(["codex-exec-json", "pi-json"] as const)("%s has no recognized final event yet (plan Task 15)", (format) => {
    const parser = createHeadlessOutputParser(format);
    parser.push(claudeStream(SUCCESS_EVENT));
    parser.endStream();
    expect(parser.result().finalSuccess).toBe(false);
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
