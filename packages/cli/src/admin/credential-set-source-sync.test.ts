// `credential set-source` saves the binding before its sync. When the sync's
// precheck refuses because the proxy does not run the selected policy, the
// command reports the saved binding and a pending sync instead of failing.

import { afterEach, beforeEach, expect, test, vi } from "vitest";

const state = vi.hoisted(() => ({
  saved: [] as string[],
  sync: undefined as undefined | (() => unknown),
}));

vi.mock("./admin-core.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./admin-core.ts")>();
  return {
    ...actual,
    assertNotReservedUserTokenName: vi.fn(),
    assertTokenSourceCanBeSaved: vi.fn(),
    loadPolicy: vi.fn(() => ({ tokens: { gemini: { credentials: [{ host: "generativelanguage.googleapis.com" }] } } })),
    tokenSourceFromSelection: vi.fn(() => ({ source: "env", env: "GEMINI_KEY" })),
    effectiveTokenRefresh: vi.fn(() => ({ mode: "manual" })),
    withTokenStoreLock: vi.fn((fn: () => unknown) => fn()),
    saveTokenSource: vi.fn((name: string) => {
      state.saved.push(name);
      return { changed: true };
    }),
    syncTokensSettlingSignals: vi.fn(async () => state.sync?.()),
  };
});

const { credentialSetSourceIntent } = await import("./credential-policy.ts");
const { CredentialSyncNotConvergedError } = await import("./admin-core.ts");

const input = {
  name: "gemini",
  tokenSource: { kind: "env", env: "GEMINI_KEY" },
  replaceSource: true,
  sync: true,
} as unknown as Parameters<typeof credentialSetSourceIntent>[0];

let logs: string[];

beforeEach(() => {
  state.saved = [];
  state.sync = undefined;
  logs = [];
  vi.spyOn(console, "log").mockImplementation((line: unknown) => {
    logs.push(String(line));
  });
  vi.spyOn(console, "error").mockImplementation(() => {});
  process.exitCode = undefined;
});

afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = undefined;
});

test("a proxy that does not run the selected policy leaves the binding saved and the sync pending", async () => {
  state.sync = () => {
    throw new CredentialSyncNotConvergedError("credential resolution requires a selected effective policy generation with complete convergence");
  };

  await credentialSetSourceIntent(input);

  expect(state.saved).toEqual(["gemini"]);
  expect(logs).toContain("gemini credential configured");
  expect(logs.find((line) => line.startsWith("proxy sync: "))).toMatch(/^proxy sync: pending \(the proxy does not run the project's current policy/);
  expect(logs).toContain("  check: runfree status");
  expect(process.exitCode).toBeUndefined();
});

test("any other sync error still fails the command", async () => {
  state.sync = () => {
    throw new Error("selected effective controls changed during credential preflight");
  };

  await expect(credentialSetSourceIntent(input)).rejects.toThrow("selected effective controls changed");
  expect(state.saved).toEqual(["gemini"]);
  expect(logs.some((line) => line.startsWith("proxy sync: "))).toBe(false);
});

test("a ready proxy reports the sync done", async () => {
  state.sync = () => ({ failed: [], stale: [], failedMessages: {}, runtimeState: "ready", receipts: [], changed: true, unprepared: [] });

  await credentialSetSourceIntent(input);

  expect(logs).toContain("proxy sync: done");
  expect(logs.some((line) => line.startsWith("  check: "))).toBe(false);
  expect(process.exitCode).toBeUndefined();
});
