import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { nodeRuntimeIO } from "../runtime.ts";

import { captureAsync } from "./async-capture.ts";
import { failClosedSpawnStatus } from "./spawn-status.ts";

const node = process.execPath;

// The host sync capture's status mapping, for comparison.
function capture(command: string, args: string[], options: childProcess.SpawnSyncOptions) {
  return failClosedSpawnStatus(childProcess.spawnSync(command, args, { encoding: "utf8", ...options }));
}

describe("captureAsync", () => {
  test("returns output and exit 0", async () => {
    const result = await captureAsync(node, ["-e", "process.stdout.write('out'); process.stderr.write('err')"]);
    expect(result).toEqual({ status: 0, stdout: "out", stderr: "err" });
  });

  test("returns the child's own non-zero exit status", async () => {
    const result = await captureAsync(node, ["-e", "process.exit(3)"]);
    expect(result.status).toBe(3);
    expect(result.timedOut).toBeUndefined();
  });

  test("a timeout is status 124 with timedOut, whatever the child would have exited with", async () => {
    const result = await captureAsync(node, ["-e", "setTimeout(() => process.exit(0), 10_000)"], { timeout: 100 });
    expect(result.status).toBe(124);
    expect(result.timedOut).toBe(true);
  });

  // spawnSync reports an overrun as ENOBUFS beside the kill signal it sent, so
  // the sync capture's status is 128 + killSignal when the kill ended the
  // child, or 125 when the child had already exited; never the child's own.
  const overrun = (signal = "SIGTERM" as const) => [125, 128 + os.constants.signals[signal]];

  test("output over maxBuffer ends the child and fails closed, as the sync capture does", async () => {
    const script = "process.stdout.write('x'.repeat(4096)); setTimeout(() => {}, 10_000)";
    const result = await captureAsync(node, ["-e", script], { maxBuffer: 1024 });
    expect(overrun()).toContain(result.status);
    expect(result.signal).toBe("SIGTERM");
    expect(capture(node, ["-e", script], { maxBuffer: 1024 }).status).toBe(result.status);
  });

  test("an overrun by a child that exits at once is never status 0", async () => {
    const result = await captureAsync(node, ["-e", "process.stdout.write('x'.repeat(4096))"], { maxBuffer: 1024 });
    expect(overrun()).toContain(result.status);
  });

  test("output over maxBuffer on stderr fails closed with the given kill signal", async () => {
    const script = "process.stderr.write('x'.repeat(4096)); setTimeout(() => {}, 10_000)";
    const result = await captureAsync(node, ["-e", script], { maxBuffer: 1024, killSignal: "SIGKILL" });
    expect(result.status).toBe(128 + os.constants.signals.SIGKILL);
    expect(result.signal).toBe("SIGKILL");
  });

  test("the default maxBuffer is 1 MiB, as spawnSync's", async () => {
    const fits = await captureAsync(node, ["-e", "process.stdout.write('x'.repeat(1024 * 1024))"]);
    expect(fits.status).toBe(0);
    expect(fits.stdout).toHaveLength(1024 * 1024);
    const over = await captureAsync(node, ["-e", "process.stdout.write('x'.repeat(1024 * 1024 + 1)); setTimeout(() => {}, 10_000)"]);
    expect(overrun()).toContain(over.status);
  });

  test("a missing executable is status 125 and never rejects", async () => {
    const result = await captureAsync("/nonexistent/runfree-no-such-binary", []);
    expect(result).toMatchObject({ status: 125, stdout: "", stderr: "" });
  });

  test("input reaches stdin and stdin is then closed", async () => {
    const result = await captureAsync(node, ["-e", "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>process.stdout.write(s.toUpperCase()))"], {
      input: "hello",
    });
    expect(result).toMatchObject({ status: 0, stdout: "HELLO" });
  });

  test("stdin is closed with no input, so a reader of stdin finishes", async () => {
    const result = await captureAsync(node, ["-e", "process.stdin.resume().on('end',()=>process.stdout.write('eof'))"], { timeout: 5_000 });
    expect(result).toMatchObject({ status: 0, stdout: "eof" });
  });

  test("killSignal is honored on timeout: a child that ignores SIGTERM is still ended", async () => {
    const script = "process.on('SIGTERM',()=>{});setInterval(()=>{},1000)";
    const startedAt = performance.now();
    const result = await captureAsync(node, ["-e", script], { timeout: 200, killSignal: "SIGKILL" });
    expect(result.status).toBe(124);
    expect(result.timedOut).toBe(true);
    expect(result.signal).toBe("SIGKILL");
    expect(performance.now() - startedAt).toBeLessThan(5_000);
  });

  test("the default kill signal on timeout is SIGTERM", async () => {
    const result = await captureAsync(node, ["-e", "setInterval(()=>{},1000)"], { timeout: 100 });
    expect(result).toMatchObject({ status: 124, timedOut: true, signal: "SIGTERM" });
  });

  test("passes cwd and env to the child", async () => {
    const result = await captureAsync(node, ["-e", "process.stdout.write(process.cwd() + '|' + process.env.RUNFREE_ASYNC_PROBE)"], {
      cwd: "/",
      env: { ...process.env, RUNFREE_ASYNC_PROBE: "seen" },
    });
    expect(result.stdout).toBe("/|seen");
  });

  test("two calls run concurrently", async () => {
    const sleep = ["-e", "setTimeout(() => {}, 1_000)"];
    const startedAt = performance.now();
    const results = await Promise.all([captureAsync(node, sleep), captureAsync(node, sleep)]);
    expect(results.map((result) => result.status)).toEqual([0, 0]);
    expect(performance.now() - startedAt).toBeLessThan(1_800);
  });

  test("large input to a child that exits without reading stdin still resolves", async () => {
    const result = await captureAsync(node, ["-e", "process.exit(0)"], { input: "x".repeat(8 * 1024 * 1024), timeout: 10_000 });
    expect(result.status).toBe(0);
  });

  test("a timeout past the timer's 32-bit range is honored, not fired at once", async () => {
    const result = await captureAsync(node, ["-e", "setTimeout(() => {}, 200)"], { timeout: 2 ** 31 });
    expect(result).toMatchObject({ status: 0 });
    expect(result.timedOut).toBeUndefined();
  });
});

describe("captureAsync refuses invalid options before spawning", () => {
  let directory: string;
  beforeEach(() => { directory = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-async-capture-")); });
  afterEach(() => { fs.rmSync(directory, { recursive: true, force: true }); });

  const markerScript = (marker: string) => ["-e", `require("fs").writeFileSync(${JSON.stringify(marker)}, "spawned")`];
  const invalid: Array<[string, childProcess.SpawnSyncOptions]> = [
    ["NaN timeout", { timeout: Number.NaN }],
    ["Infinity timeout", { timeout: Number.POSITIVE_INFINITY }],
    ["negative timeout", { timeout: -1 }],
    ["negative fractional timeout", { timeout: -0.5 }],
    ["NaN maxBuffer", { maxBuffer: Number.NaN }],
    ["negative maxBuffer", { maxBuffer: -1 }],
    ["unknown kill signal", { killSignal: "SIGBOGUS" as NodeJS.Signals }],
  ];
  for (const [name, options] of invalid) {
    test(`${name} is status 125 and no child runs`, async () => {
      const marker = path.join(directory, "marker");
      const result = await captureAsync(node, markerScript(marker), options);
      expect(result).toMatchObject({ status: 125, stdout: "", stderr: "" });
      // Give a wrongly spawned child time to write its marker.
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(fs.existsSync(marker)).toBe(false);
    });
  }

  test("each timeout the sync capture refuses, the async capture refuses; each it runs, it runs the same", async () => {
    // A finite timeout neither run can reach: a short one races node startup
    // on a loaded host, so the two runs could disagree on timing alone.
    for (const timeout of [Number.NaN, Number.POSITIVE_INFINITY, -1, 0, undefined, 1.5, 30_000]) {
      const options = timeout === undefined ? {} : { timeout };
      let sync: { status: number } | "refused";
      try { sync = nodeRuntimeIO.capture(node, ["-e", "0"], options); } catch { sync = "refused"; }
      const result = await captureAsync(node, ["-e", "0"], options);
      expect([timeout, result.status]).toEqual([timeout, sync === "refused" ? 125 : sync.status]);
    }
  });
});
