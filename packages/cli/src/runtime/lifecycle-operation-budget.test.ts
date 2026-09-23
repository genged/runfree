import { expect, test, vi } from "vitest";
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
