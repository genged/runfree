import { expect, test, vi } from "vitest";
import { wasRefusedBeforeSpawn } from "./io-refusal.ts";
import { withLifecycleOperationBudget } from "./lifecycle-operation-budget.ts";
import type { RuntimeIO } from "./types.ts";

test("successive subprocesses spend the remaining lock budget and a new span permits recovery", () => {
  let remaining = 90_000;
  const capture = vi.fn(() => { remaining -= 50_000; return { status: 0, stdout: "", stderr: "" }; });
  const io = withLifecycleOperationBudget({ capture } as unknown as RuntimeIO, () => remaining);
  io.capture("docker", ["inspect", "exact"], { timeout: 100_000 });
  expect(capture.mock.calls[0]).toEqual(["docker", ["inspect", "exact"], { timeout: 90_000 }]);
  expect(() => io.capture("docker", ["inspect", "exact"])).toThrow("budget ended");
  expect(capture.mock.calls[1]).toEqual(["docker", ["inspect", "exact"], { timeout: 40_000 }]);
  expect(() => io.capture("docker", ["restart", "exact"])).toThrow("budget ended");
  expect(capture).toHaveBeenCalledTimes(2);
  remaining = 90_000;
  io.capture("docker", ["inspect", "exact"]);
  expect(capture).toHaveBeenCalledTimes(3);
});

// A caller that must reclaim what a spawn may have created needs to know when
// the wrapper refused before delegating: that refusal spawned nothing.
test("a spent budget refuses before delegating, and says so; a refusal after the call does not", () => {
  let remaining = 0;
  const capture = vi.fn(() => { remaining = 0; return { status: 0, stdout: "", stderr: "" }; });
  const io = withLifecycleOperationBudget({ capture, run: capture } as unknown as RuntimeIO, () => remaining);
  const refusal = (call: () => unknown): unknown => { try { call(); } catch (error) { return error; } throw new Error("expected a refusal"); };
  const before = refusal(() => io.capture("docker", ["run", "image"]));
  expect(capture).not.toHaveBeenCalled();
  expect(wasRefusedBeforeSpawn(before)).toBe(true);
  expect(wasRefusedBeforeSpawn(refusal(() => io.run("docker", ["run", "image"])))).toBe(true);
  remaining = 1_000;
  const after = refusal(() => io.capture("docker", ["run", "image"]));
  expect(capture).toHaveBeenCalledOnce();
  expect(wasRefusedBeforeSpawn(after)).toBe(false);
});

test("a captureAsync call is cut to the remaining budget exactly as capture is", async () => {
  let remaining = 90_000;
  const captureAsync = vi.fn(async () => { remaining -= 50_000; return { status: 0, stdout: "", stderr: "" }; });
  const io = withLifecycleOperationBudget({ captureAsync } as unknown as RuntimeIO, () => remaining);
  await io.captureAsync?.("docker", ["inspect", "exact"], { timeout: 100_000, killSignal: "SIGKILL" });
  expect(captureAsync.mock.calls[0]).toEqual(["docker", ["inspect", "exact"], { timeout: 90_000, killSignal: "SIGKILL" }]);
  // Spent after the call settles: refused, but the call did run.
  await expect(io.captureAsync?.("docker", ["inspect", "exact"])).rejects.toThrow("budget ended");
  expect(captureAsync.mock.calls[1]).toEqual(["docker", ["inspect", "exact"], { timeout: 40_000 }]);
  // Spent before the call: refused before delegating, and marked as never spawned.
  const refusal = await io.captureAsync?.("docker", ["restart", "exact"]).then(() => undefined, (error: unknown) => error);
  expect(wasRefusedBeforeSpawn(refusal)).toBe(true);
  expect(captureAsync).toHaveBeenCalledTimes(2);
});

test("the lifecycle budget exposes no captureAsync when the inner IO has none", () => {
  const io = withLifecycleOperationBudget({ capture: vi.fn(), run: vi.fn() } as unknown as RuntimeIO, () => 1_000);
  expect("captureAsync" in io).toBe(false);
});
