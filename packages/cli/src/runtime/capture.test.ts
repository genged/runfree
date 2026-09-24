import { expect, test } from "vitest";

import { runCapture } from "../admin/admin-core.ts";
import { nodeRuntimeIO } from "../runtime.ts";
import { failClosedSpawnStatus } from "./spawn-status.ts";

// Real child processes, not Docker: the fault is in how a spawnSync result is
// mapped to a status, so a `node -e` child that behaves like a wedged Docker
// client reproduces it exactly.
const IGNORE_TERM_THEN_EXIT_ZERO = "process.on('SIGTERM', () => {}); setTimeout(() => process.exit(0), 1500);";
const FLOOD_IGNORING_TERM = "process.on('SIGTERM', () => {}); process.stdout.write('x'.repeat(65536)); setTimeout(() => process.exit(0), 300);";
const FLOOD = "process.stdout.write('x'.repeat(65536));";

const captures = [
  ["runtime capture", (script: string, options: object) => nodeRuntimeIO.capture(process.execPath, ["-e", script], options)],
  ["admin runCapture", (script: string, options: object) => runCapture(process.execPath, ["-e", script], { env: process.env, ...options })],
] as const;

test.each(captures)("%s: a timed-out child that ignores SIGTERM and exits 0 is not success", (_name, capture) => {
  const result = capture(IGNORE_TERM_THEN_EXIT_ZERO, { timeout: 500 });
  expect(result.stdout).toBe("");
  expect(result.status).not.toBe(0);
  expect(result).toMatchObject({ timedOut: true });
});

test.each(captures)("%s: an output flood past maxBuffer (ENOBUFS) is not success", (_name, capture) => {
  // Whether Node's kill or the child's own exit ends the call depends on load,
  // so assert only that the result is an unfinished call, never an answer.
  for (const script of [FLOOD_IGNORING_TERM, FLOOD]) {
    const result = capture(script, { maxBuffer: 1024 });
    expect(result.status).not.toBe(0);
    expect(result.status).not.toBe(1);
  }
});

test.each(captures)("%s: a timed-out child that later exits 1 is a timeout, not a definite no", (_name, capture) => {
  const result = capture("process.on('SIGTERM', () => {}); setTimeout(() => process.exit(1), 1500);", { timeout: 500 });
  expect(result).toMatchObject({ status: 124, timedOut: true });
});

test.each([
  ["runtime capture", () => nodeRuntimeIO.capture("/nonexistent/runfree-no-such-binary", [])],
  ["admin runCapture", () => runCapture("/nonexistent/runfree-no-such-binary", [], { env: process.env })],
] as const)("%s: a spawn error (ENOENT) is 125, never 1", (_name, capture) => {
  expect(capture().status).toBe(125);
});

test.each([
  ["timeout, then exit 0", { status: 0, signal: null, error: Object.assign(new Error("t"), { code: "ETIMEDOUT" }) }, { status: 124, timedOut: true }],
  ["timeout, then exit 1", { status: 1, signal: null, error: Object.assign(new Error("t"), { code: "ETIMEDOUT" }) }, { status: 124, timedOut: true }],
  ["timeout, then SIGTERM", { status: null, signal: "SIGTERM", error: Object.assign(new Error("t"), { code: "ETIMEDOUT" }) }, { status: 124, timedOut: true, signal: "SIGTERM" }],
  ["ENOBUFS, then exit 0", { status: 0, signal: null, error: Object.assign(new Error("b"), { code: "ENOBUFS" }) }, { status: 125 }],
  ["ENOBUFS, then exit 1", { status: 1, signal: null, error: Object.assign(new Error("b"), { code: "ENOBUFS" }) }, { status: 125 }],
  ["ENOENT", { status: null, signal: null, error: Object.assign(new Error("n"), { code: "ENOENT" }) }, { status: 125 }],
  ["SIGKILL", { status: null, signal: "SIGKILL", error: undefined }, { status: 137, signal: "SIGKILL" }],
  ["clean exit 1", { status: 1, signal: null, error: undefined }, { status: 1 }],
  ["clean exit 0", { status: 0, signal: null, error: undefined }, { status: 0 }],
] as const)("failClosedSpawnStatus: %s", (_name, result, expected) => {
  expect(failClosedSpawnStatus(result as Parameters<typeof failClosedSpawnStatus>[0])).toEqual(expected);
});

test.each(captures)("%s: a child killed by a signal is not success", (_name, capture) => {
  const result = capture("process.kill(process.pid, 'SIGKILL')", {});
  expect(result.status).not.toBe(0);
  expect(result.signal).toBe("SIGKILL");
});

test.each(captures)("%s: a normal exit keeps its status and output with no diagnostics", (_name, capture) => {
  const ok = capture("process.stdout.write('ok')", { timeout: 10_000 });
  expect(ok).toEqual({ status: 0, stdout: "ok", stderr: "" });
  expect(capture("process.exit(3)", {}).status).toBe(3);
});
