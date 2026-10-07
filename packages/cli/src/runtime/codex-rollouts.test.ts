import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import {
  CODEX_ROLLOUT_LIMITS,
  scanCodexThreads,
  setCodexRolloutAfterOpenHookForTest,
  type CodexWindow,
} from "./codex-rollouts.ts";

// Real uuids captured from a local Codex home (session_meta.payload.id /
// rollout filename), shaped exactly like Codex's own (uuid v7-ish: version
// nibble in [1-8], variant nibble in [89ab]) so they exercise `ROLLOUT_RE`
// the way real files do.
const VALID_UUID_1 = "01a0692c-7f74-7750-ad42-fb36200a005e";
const VALID_UUID_2 = "01a068dd-e702-7d92-8298-093f384085c6";

const HAS_MKFIFO = (() => {
  if (process.platform === "win32") return false;
  const probeDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mkfifo-probe-"));
  try {
    execFileSync("mkfifo", [path.join(probeDir, "p")], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  } finally {
    fs.rmSync(probeDir, { recursive: true, force: true });
  }
})();

let tmp: string;
let stateDir: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-codex-rollouts-"));
  stateDir = path.join(tmp, "state");
  fs.mkdirSync(stateDir, { recursive: true });
});

afterEach(() => {
  setCodexRolloutAfterOpenHookForTest(undefined);
  fs.rmSync(tmp, { recursive: true, force: true });
});

/** Writes `<stateDir>/codex/sessions/<date>/rollout-...-<uuid>.jsonl` with a `session_meta` first line built from `meta` (the `payload`), plus any `rest` content after it. Returns the file path. */
function rollout(date: string, uuid: string, meta: Record<string, unknown>, rest = ""): string {
  const [year, month, day] = date.split("/");
  const dir = path.join(stateDir, "codex", "sessions", year as string, month as string, day as string);
  fs.mkdirSync(dir, { recursive: true });
  const filePath = path.join(dir, `rollout-${date.replace(/\//g, "-")}T00-00-00-${uuid}.jsonl`);
  const firstLine = JSON.stringify({ type: "session_meta", payload: meta });
  fs.writeFileSync(filePath, `${firstLine}\n${rest}`);
  return filePath;
}

function writeIndex(rows: readonly Readonly<{ id: string; thread_name: string }>[]): void {
  const dir = path.join(stateDir, "codex");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "session_index.jsonl"), `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`);
}

function swapForSymlink(targetPath: string): void {
  const real = `${targetPath}.real`;
  fs.renameSync(targetPath, real);
  fs.symlinkSync(real, targetPath);
}

function windowAround(iso: string): CodexWindow[] {
  const ms = Date.parse(iso);
  return [{ startMs: ms - 60 * 60 * 1000, endMs: ms + 60 * 60 * 1000 }];
}

function fakeUuid(n: number): string {
  // Only the last, unconstrained 12-hex group varies; version/variant
  // nibbles stay fixed so every generated id still matches `ROLLOUT_RE`.
  return `00000000-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
}

describe("scanCodexThreads", () => {
  test("a valid rollout inside a window gives one thread with id, startedAtMs, and name", () => {
    const startedAt = "2026-10-04T12:00:00.000Z";
    rollout("2026/10/04", VALID_UUID_1, { id: VALID_UUID_1, timestamp: startedAt });
    writeIndex([
      { id: VALID_UUID_1, thread_name: "older name" },
      { id: VALID_UUID_1, thread_name: "Fix the bounded Codex reader" },
    ]);

    const scan = scanCodexThreads({ stateDir, windows: windowAround(startedAt) });

    expect(scan).toEqual({
      threads: [{ id: VALID_UUID_1, startedAtMs: Date.parse(startedAt), name: "Fix the bounded Codex reader" }],
      complete: true,
    });
  });

  test("a date directory outside every window is not opened", () => {
    rollout("2026/10/04", VALID_UUID_1, { id: VALID_UUID_1, timestamp: "2026-10-04T12:00:00.000Z" });
    rollout("2026/01/01", VALID_UUID_2, { id: VALID_UUID_2, timestamp: "2026-01-01T12:00:00.000Z" });

    const openSpy = vi.spyOn(fs, "openSync");
    const scan = scanCodexThreads({ stateDir, windows: windowAround("2026-10-04T12:00:00.000Z") });

    expect(scan.threads.map((thread) => thread.id)).toEqual([VALID_UUID_1]);
    const outsideDay = path.join("2026", "01", "01");
    for (const call of openSpy.mock.calls) expect(String(call[0])).not.toContain(outsideDay);
    openSpy.mockRestore();
  });

  test("a filename uuid that does not match payload.id gives no thread", () => {
    rollout("2026/10/04", VALID_UUID_1, { id: VALID_UUID_2, timestamp: "2026-10-04T12:00:00.000Z" });

    const scan = scanCodexThreads({ stateDir, windows: windowAround("2026-10-04T12:00:00.000Z") });

    expect(scan).toEqual({ threads: [], complete: true });
  });

  test("a first line over maxFirstLineBytes with no newline gives no thread, complete still true", () => {
    const dir = path.join(stateDir, "codex", "sessions", "2026", "10", "04");
    fs.mkdirSync(dir, { recursive: true });
    const filePath = path.join(dir, `rollout-2026-10-04T00-00-00-${VALID_UUID_1}.jsonl`);
    fs.writeFileSync(filePath, "x".repeat(CODEX_ROLLOUT_LIMITS.maxFirstLineBytes + 1_000));

    const scan = scanCodexThreads({ stateDir, windows: windowAround("2026-10-04T12:00:00.000Z") });

    expect(scan).toEqual({ threads: [], complete: true });
  });

  describe("every level between the state dir and the file rejects a symlink or hard link", () => {
    test("a symlinked sessions directory gives no thread", () => {
      rollout("2026/10/04", VALID_UUID_1, { id: VALID_UUID_1, timestamp: "2026-10-04T12:00:00.000Z" });
      swapForSymlink(path.join(stateDir, "codex", "sessions"));

      expect(scanCodexThreads({ stateDir, windows: windowAround("2026-10-04T12:00:00.000Z") }))
        .toEqual({ threads: [], complete: true });
    });

    test("a symlinked year directory gives no thread", () => {
      rollout("2026/10/04", VALID_UUID_1, { id: VALID_UUID_1, timestamp: "2026-10-04T12:00:00.000Z" });
      swapForSymlink(path.join(stateDir, "codex", "sessions", "2026"));

      expect(scanCodexThreads({ stateDir, windows: windowAround("2026-10-04T12:00:00.000Z") }))
        .toEqual({ threads: [], complete: true });
    });

    test("a symlinked month directory gives no thread", () => {
      rollout("2026/10/04", VALID_UUID_1, { id: VALID_UUID_1, timestamp: "2026-10-04T12:00:00.000Z" });
      swapForSymlink(path.join(stateDir, "codex", "sessions", "2026", "10"));

      expect(scanCodexThreads({ stateDir, windows: windowAround("2026-10-04T12:00:00.000Z") }))
        .toEqual({ threads: [], complete: true });
    });

    test("a symlinked day directory gives no thread", () => {
      rollout("2026/10/04", VALID_UUID_1, { id: VALID_UUID_1, timestamp: "2026-10-04T12:00:00.000Z" });
      swapForSymlink(path.join(stateDir, "codex", "sessions", "2026", "10", "04"));

      expect(scanCodexThreads({ stateDir, windows: windowAround("2026-10-04T12:00:00.000Z") }))
        .toEqual({ threads: [], complete: true });
    });

    test("a symlinked rollout file gives no thread", () => {
      const filePath = rollout("2026/10/04", VALID_UUID_1, { id: VALID_UUID_1, timestamp: "2026-10-04T12:00:00.000Z" });
      swapForSymlink(filePath);

      expect(scanCodexThreads({ stateDir, windows: windowAround("2026-10-04T12:00:00.000Z") }))
        .toEqual({ threads: [], complete: true });
    });

    test("a hard-linked rollout file gives no thread", () => {
      const filePath = rollout("2026/10/04", VALID_UUID_1, { id: VALID_UUID_1, timestamp: "2026-10-04T12:00:00.000Z" });
      fs.linkSync(filePath, `${filePath}.hardlink`);

      expect(scanCodexThreads({ stateDir, windows: windowAround("2026-10-04T12:00:00.000Z") }))
        .toEqual({ threads: [], complete: true });
    });
  });

  test.skipIf(!HAS_MKFIFO)("a FIFO named like a rollout gives no thread and returns under 1s (no blocking open)", () => {
    const dir = path.join(stateDir, "codex", "sessions", "2026", "10", "04");
    fs.mkdirSync(dir, { recursive: true });
    execFileSync("mkfifo", [path.join(dir, `rollout-2026-10-04T00-00-00-${VALID_UUID_1}.jsonl`)]);

    const start = Date.now();
    const scan = scanCodexThreads({ stateDir, windows: windowAround("2026-10-04T12:00:00.000Z") });

    expect(Date.now() - start).toBeLessThan(1_000);
    expect(scan).toEqual({ threads: [], complete: true });
  });

  test("more rollout files than maxFilesTotal gives complete:false and returns quickly", { timeout: 15_000 }, () => {
    const dir = path.join(stateDir, "codex", "sessions", "2026", "10", "04");
    fs.mkdirSync(dir, { recursive: true });
    const total = CODEX_ROLLOUT_LIMITS.maxFilesTotal + 50;
    for (let i = 0; i < total; i += 1) {
      const uuid = fakeUuid(i);
      const filePath = path.join(dir, `rollout-2026-10-04T00-00-00-${uuid}.jsonl`);
      const line = JSON.stringify({ type: "session_meta", payload: { id: uuid, timestamp: "2026-10-04T12:00:00.000Z" } });
      fs.writeFileSync(filePath, `${line}\n`);
    }

    const start = Date.now();
    const scan = scanCodexThreads({ stateDir, windows: windowAround("2026-10-04T12:00:00.000Z") });

    expect(Date.now() - start).toBeLessThan(5_000);
    expect(scan.complete).toBe(false);
  });

  test(
    "junk entries count against maxEntriesPerDir and never make the scan expensive by volume (F4)",
    { timeout: 30_000 },
    () => {
      const dir = path.join(stateDir, "codex", "sessions", "2026", "10", "04");
      fs.mkdirSync(dir, { recursive: true });
      for (let i = 0; i < 100_000; i += 1) fs.writeFileSync(path.join(dir, `junk-${i}`), "");
      const sessionsDir = path.join(stateDir, "codex", "sessions");
      for (let i = 0; i < 10_000; i += 1) fs.mkdirSync(path.join(sessionsDir, `junkdir-${i}`));

      const start = Date.now();
      const scan = scanCodexThreads({ stateDir, windows: windowAround("2026-10-04T12:00:00.000Z") });

      expect(Date.now() - start).toBeLessThan(3_000);
      expect(scan).toEqual({ threads: [], complete: false });
    },
  );

  test("a directory swapped for a symlink between open and the containment check gives no thread (F8)", () => {
    const dir = path.join(stateDir, "codex", "sessions", "2026", "10", "04");
    const filePath = rollout("2026/10/04", VALID_UUID_1, { id: VALID_UUID_1, timestamp: "2026-10-04T12:00:00.000Z" });
    const decoyDir = path.join(stateDir, "decoy");
    fs.mkdirSync(decoyDir, { recursive: true });
    const decoyLine = JSON.stringify({
      type: "session_meta",
      payload: { id: VALID_UUID_1, timestamp: "2026-10-04T12:00:00.000Z" },
    });
    fs.writeFileSync(path.join(decoyDir, path.basename(filePath)), `${decoyLine}\n`);

    setCodexRolloutAfterOpenHookForTest(() => swapForSymlink(dir));

    const scan = scanCodexThreads({ stateDir, windows: windowAround("2026-10-04T12:00:00.000Z") });

    expect(scan).toEqual({ threads: [], complete: true });
  });

  test("a thread_name with terminal escapes and a bidi override is returned raw (sanitizing is Task 10's job)", () => {
    const startedAt = "2026-10-04T12:00:00.000Z";
    const rawName = "\u001b[2Jrm -rf‮";
    rollout("2026/10/04", VALID_UUID_1, { id: VALID_UUID_1, timestamp: startedAt });
    writeIndex([{ id: VALID_UUID_1, thread_name: rawName }]);

    const scan = scanCodexThreads({ stateDir, windows: windowAround(startedAt) });

    expect(scan.threads).toEqual([{ id: VALID_UUID_1, startedAtMs: Date.parse(startedAt), name: rawName }]);
  });

  test("an empty window list does no I/O at all", () => {
    const openSpy = vi.spyOn(fs, "openSync");
    const opendirSpy = vi.spyOn(fs, "opendirSync");
    const lstatSpy = vi.spyOn(fs, "lstatSync");

    const scan = scanCodexThreads({ stateDir, windows: [] });

    expect(scan).toEqual({ threads: [], complete: true });
    expect(openSpy).not.toHaveBeenCalled();
    expect(opendirSpy).not.toHaveBeenCalled();
    expect(lstatSpy).not.toHaveBeenCalled();
    openSpy.mockRestore();
    opendirSpy.mockRestore();
    lstatSpy.mockRestore();
  });

  test("a missing codex home gives threads: [], complete: true (no data, not an error)", () => {
    // No `<stateDir>/codex` at all: every candidate day directory is simply
    // absent, which is ordinary "nothing to report", not a scan failure.
    expect(scanCodexThreads({ stateDir, windows: windowAround("2026-10-04T12:00:00.000Z") }))
      .toEqual({ threads: [], complete: true });
  });

  test("never throws: an unexpected internal failure gives threads: [], complete: false", () => {
    const dateNowSpy = vi.spyOn(Date, "now").mockImplementation(() => {
      throw new Error("boom");
    });
    try {
      const scan = scanCodexThreads({ stateDir, windows: windowAround("2026-10-04T12:00:00.000Z") });
      expect(scan).toEqual({ threads: [], complete: false });
    } finally {
      dateNowSpy.mockRestore();
    }
  });
});
