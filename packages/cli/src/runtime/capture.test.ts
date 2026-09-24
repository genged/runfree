import { expect, test } from "vitest";

import { runCapture } from "../admin/admin-core.ts";
import { nodeRuntimeIO } from "../runtime.ts";

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
  expect(capture(FLOOD_IGNORING_TERM, { maxBuffer: 1024 }).status).not.toBe(0);
  const killed = capture(FLOOD, { maxBuffer: 1024 });
  expect(killed.status).not.toBe(0);
  expect(killed.signal).toBe("SIGTERM");
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
