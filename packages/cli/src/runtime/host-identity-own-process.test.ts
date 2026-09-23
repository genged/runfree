import { afterEach, expect, test, vi } from "vitest";

const { execFileSync } = vi.hoisted(() => ({ execFileSync: vi.fn() }));
vi.mock("node:child_process", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:child_process")>()),
  execFileSync,
}));

const platform = Object.getOwnPropertyDescriptor(process, "platform") as PropertyDescriptor;
afterEach(() => {
  Object.defineProperty(process, "platform", platform);
  execFileSync.mockReset();
  vi.resetModules();
});

test("darwin probes this process's start time once per process", async () => {
  Object.defineProperty(process, "platform", { value: "darwin" });
  execFileSync.mockReturnValue("Mon Sep 22 10:00:00 2026\n");
  const { hostProcessStart } = await import("./host-identity.ts");
  const first = hostProcessStart(process.pid, {});
  expect(first).toMatch(/^darwin:\d+$/);
  expect(hostProcessStart(process.pid, {})).toBe(first);
  expect(execFileSync).toHaveBeenCalledTimes(1);
  hostProcessStart(process.pid + 1, {});
  hostProcessStart(process.pid + 1, {});
  expect(execFileSync).toHaveBeenCalledTimes(3);
});

test("a failed own-process probe is retried, not cached", async () => {
  Object.defineProperty(process, "platform", { value: "darwin" });
  execFileSync.mockReturnValue("");
  const { hostProcessStart } = await import("./host-identity.ts");
  expect(hostProcessStart(process.pid, {})).toBeUndefined();
  execFileSync.mockReturnValue("Mon Sep 22 10:00:00 2026\n");
  expect(hostProcessStart(process.pid, {})).toMatch(/^darwin:\d+$/);
});
