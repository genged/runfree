import { expect, test } from "vitest";

import { createRuntimeTimings, formatRuntimeTimingLine, runtimeTimingsEnabled } from "./timings.ts";

test("timings are inert unless RUNFREE_TIMINGS=1", () => {
  const lines: string[] = [];
  for (const env of [undefined, {}, { RUNFREE_TIMINGS: "" }, { RUNFREE_TIMINGS: "0" }, { RUNFREE_TIMINGS: "true" }]) {
    expect(runtimeTimingsEnabled(env)).toBe(false);
    const timings = createRuntimeTimings(env, (line) => lines.push(line));
    expect(timings.enabled).toBe(false);
    expect(timings.time("phase", () => 7)).toBe(7);
    timings.report("phase", "docker-operations=3");
  }
  expect(lines).toEqual([]);
});

test("enabled timings emit one line per phase and preserve results and failures", async () => {
  const lines: string[] = [];
  const timings = createRuntimeTimings({ RUNFREE_TIMINGS: "1" }, (line) => lines.push(line));
  expect(timings.enabled).toBe(true);

  expect(timings.time("sync-phase", () => "value")).toBe("value");
  await expect(timings.timeAsync("async-phase", async () => 42)).resolves.toBe(42);
  expect(() => timings.time("failing-phase", () => {
    throw new Error("phase failed");
  })).toThrow("phase failed");
  timings.report("session-admission", "docker-operations=12");

  expect(lines).toHaveLength(4);
  expect(lines[0]).toMatch(/^timing: sync-phase \d+(\.\d+)?ms$/);
  expect(lines[1]).toMatch(/^timing: async-phase \d+(\.\d+)?ms$/);
  // A throwing phase still reports its duration; instrumentation never eats
  // or replaces the failure.
  expect(lines[2]).toMatch(/^timing: failing-phase \d+(\.\d+)?ms$/);
  expect(lines[3]).toBe("timing: session-admission docker-operations=12");
});

test("timing line format is stable for operators", () => {
  expect(formatRuntimeTimingLine("compose-up", 1234.5678)).toBe("timing: compose-up 1234.6ms");
});
