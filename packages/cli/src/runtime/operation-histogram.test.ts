import { expect, test } from "vitest";

import { createOperationHistogram, subprocessCategory, withOperationHistogram } from "./operation-histogram.ts";
import type { CaptureResult, RuntimeIO } from "./types.ts";

test("categories keep only Docker subcommand verbs", () => {
  expect(subprocessCategory("docker", ["exec", "--user", "0:0", "abc", "cat", "/secret"])).toBe("docker exec");
  expect(subprocessCategory("docker", ["container", "inspect", "abc"])).toBe("docker container inspect");
  expect(subprocessCategory("docker", ["network", "--help"])).toBe("docker network");
  expect(subprocessCategory("docker", ["compose", "-p", "x", "up"])).toBe("docker compose");
  expect(subprocessCategory("docker", ["ps", "-q"])).toBe("docker ps");
  expect(subprocessCategory("docker", ["TOKEN=abc"])).toBe("docker ?");
  expect(subprocessCategory("git", ["config", "--get", "user.email"])).toBe("git");
  expect(subprocessCategory("/usr/bin/git", ["config", "--get", "user.email"])).toBe("git");
  expect(subprocessCategory("/opt/My Tools/Git.exe", [])).toBe("?");
});

test("the wrapper counts and times capture and run without changing results", () => {
  const histogram = createOperationHistogram();
  const inner = {
    capture: (): CaptureResult => ({ status: 3, stdout: "out", stderr: "" }),
    run: () => 4,
  } as unknown as RuntimeIO;
  const io = withOperationHistogram(inner, histogram);
  expect(io.capture("docker", ["ps"])).toEqual({ status: 3, stdout: "out", stderr: "" });
  expect(io.capture("docker", ["ps", "-a"])).toEqual({ status: 3, stdout: "out", stderr: "" });
  expect(io.run("docker", ["exec", "id"])).toBe(4);
  const lines = histogram.lines();
  expect(lines).toHaveLength(2);
  expect(lines[0]).toMatch(/^docker exec count=1 total=\d+\.\dms$/);
  expect(lines[1]).toMatch(/^docker ps count=2 total=\d+\.\dms$/);
});

test("a throwing call is still recorded and the error propagates", () => {
  const histogram = createOperationHistogram();
  const io = withOperationHistogram({
    capture: () => { throw new Error("budget ended"); },
  } as unknown as RuntimeIO, histogram);
  expect(() => io.capture("docker", ["inspect", "x"])).toThrow("budget ended");
  expect(histogram.lines()[0]).toMatch(/^docker inspect count=1 /);
});

test("snapshot exposes per-category counts and totals without argv", () => {
  const histogram = createOperationHistogram();
  histogram.record("docker exec", 2.5);
  histogram.record("docker exec", 1.5);
  histogram.record("docker ps", 1);
  const snapshot = histogram.snapshot();
  expect(snapshot).toEqual({
    "docker exec": { count: 2, totalMs: 4 },
    "docker ps": { count: 1, totalMs: 1 },
  });
  // A snapshot is a copy: later records do not change it.
  histogram.record("docker ps", 1);
  expect(snapshot["docker ps"]).toEqual({ count: 1, totalMs: 1 });
});
