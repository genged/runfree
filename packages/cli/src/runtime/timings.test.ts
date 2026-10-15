import { expect, test } from "vitest";

import { createOperationHistogram, withOperationHistogram } from "./operation-histogram.ts";
import { createSessionAdmissionDockerGateway } from "./session-admission-docker-gateway.ts";
import type { RuntimeIO } from "./types.ts";

import { createRuntimeTimings, formatRuntimeTimingLine, runtimeTimingsEnabled } from "./timings.ts";

test("timings are inert unless RUNFREE_TIMINGS=1", () => {
  const lines: string[] = [];
  for (const env of [undefined, {}, { RUNFREE_TIMINGS: "" }, { RUNFREE_TIMINGS: "0" }, { RUNFREE_TIMINGS: "true" }]) {
    expect(runtimeTimingsEnabled(env)).toBe(false);
    const timings = createRuntimeTimings(env, (line) => lines.push(line));
    expect(timings.enabled).toBe(false);
    expect(timings.time("phase", () => 7)).toBe(7);
    timings.report("phase", "docker-operations=3");
    timings.operation("docker inspect", 1, 2);
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

  const timeline = lines.filter((line) => line.startsWith("timing: timeline "));
  expect(timeline).toHaveLength(3);
  for (const line of timeline) {
    const span = JSON.parse(line.slice("timing: timeline ".length));
    expect(span.endMs).toBeGreaterThanOrEqual(span.startMs);
  }
  lines.splice(0, lines.length, ...lines.filter((line) => !line.startsWith("timing: timeline ")));
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

for (const gateway of [false, true]) {
  test(`timeline preserves overlapping phase ownership through ${gateway ? "admission" : "startup"} IO`, async () => {
    const lines: string[] = [];
    const timings = createRuntimeTimings({ RUNFREE_TIMINGS: "1" }, (line) => lines.push(line));
    const histogram = createOperationHistogram(timings.operation);
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    const failure = new Error("secret-error");
    const inner = {
      capture: () => { throw failure; },
      captureAsync: async () => { await held; return { status: 7, stdout: "secret-output", stderr: "" }; },
    } as unknown as RuntimeIO;
    const io = gateway ? createSessionAdmissionDockerGateway({ io: inner, histogram }).io : withOperationHistogram(inner, histogram);
    const first = timings.timeAsync("callback-reserve", async () => io.captureAsync?.("docker", ["run", "secret-argument"]));
    timings.time("running-proof", () => {
      expect(() => io.capture("docker", ["container", "inspect", "secret-id"])).toThrow(failure);
    });
    release();
    await expect(first).resolves.toEqual({ status: 7, stdout: "secret-output", stderr: "" });
    const spans = lines.filter((line) => line.startsWith("timing: timeline "))
      .map((line) => JSON.parse(line.slice("timing: timeline ".length)));
    const operations = spans.filter((span) => span.kind === "operation");
    expect(operations).toHaveLength(2);
    const run = operations.find((span) => span.category === "docker run");
    const inspect = operations.find((span) => span.category === "docker container inspect");
    expect(run.phase).toBe("callback-reserve");
    expect(inspect.phase).toBe("running-proof");
    expect(run.startMs).toBeLessThanOrEqual(inspect.startMs);
    expect(run.endMs).toBeGreaterThanOrEqual(inspect.endMs);
    for (const operation of operations) {
      const parent = spans.find((span) => span.id === operation.parentId);
      expect(parent.kind).toBe("phase");
      expect(parent.phase).toBe(operation.phase);
      expect(parent.startMs).toBeLessThanOrEqual(operation.startMs);
      expect(parent.endMs).toBeGreaterThanOrEqual(operation.endMs);
    }
    expect(lines.join("\n")).not.toContain("secret");
    expect(Object.values(histogram.snapshot()).reduce((count, bucket) => count + bucket.count, 0)).toBe(2);
  });
}

test("nested spans share parent IDs across recorders and restore context after rejection", async () => {
  const lines: string[] = [];
  const log = (line: string) => lines.push(line);
  const outer = createRuntimeTimings({ RUNFREE_TIMINGS: "1" }, log);
  const inner = createRuntimeTimings({ RUNFREE_TIMINGS: "1" }, log);
  const failure = new Error("failed");
  await expect(outer.timeAsync("outer", () => inner.timeAsync("inner", async () => { throw failure; }))).rejects.toBe(failure);
  inner.operation("docker ps", 1, 2);
  const spans = lines.filter((line) => line.startsWith("timing: timeline "))
    .map((line) => JSON.parse(line.slice("timing: timeline ".length)));
  expect(spans[0].phase).toBe("inner");
  expect(spans[0].parentId).toBe(spans[1].id);
  expect(spans[1].phase).toBe("outer");
  expect(spans[1].parentId).toBeNull();
  expect(spans[2].phase).toBe("unscoped");
  expect(spans[2].parentId).toBeNull();
});
