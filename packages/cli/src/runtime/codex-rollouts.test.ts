import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import {
  CODEX_ROLLOUT_LIMITS,
  codexWindowForItem,
  matchCodexThreads,
  scanCodexThreads,
  setCodexRolloutAfterOpenHookForTest,
  type CodexMatchInput,
  type CodexThread,
  type CodexWindow,
} from "./codex-rollouts.ts";
import {
  SESSION_CONTAINER_RECORD_SCHEMA_VERSION,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import type { RecoveryItem } from "./recovery.ts";
import type { SessionMetadata } from "./types.ts";

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

function minimalSessionMetadata(overrides: Partial<SessionMetadata> = {}): SessionMetadata {
  return {
    id: "rf-20260731-abcdef",
    projectRoot: "/tmp/project",
    composeProject: "runfree-000000000000",
    command: "codex",
    name: "codex",
    hostPid: 1,
    hostInbox: "/tmp/inbox",
    containerInbox: "/container/inbox",
    startedAt: "2026-10-04T10:00:00.000Z",
    lastSeenAt: "2026-10-04T10:01:00.000Z",
    ...overrides,
  };
}

function minimalRecoveryItem(overrides: Partial<RecoveryItem> = {}): RecoveryItem {
  const sourceId = (overrides.sourceId as string | undefined) ?? "rf-20260731-abcdef";
  return {
    id: "rfr-000000000000000000000000",
    projectId: "000000000000",
    projectName: "test",
    stateDir,
    state: "unverified",
    evidenceKind: "host",
    evidencePath: path.join(stateDir, "sessions", `${sourceId}.json`),
    fingerprint: { dev: 0, ino: 0, size: 0, mtimeMs: 0, schemaId: sourceId, sha256: "x" },
    sourceId,
    agent: "codex",
    startedAt: "2026-10-04T10:00:00.000Z",
    ...overrides,
  };
}

function minimalSessionContainerRecord(overrides: Partial<SessionContainerRecordV2> = {}): SessionContainerRecordV2 {
  const sessionId = (overrides.sessionId as string | undefined) ?? "rf-20260731-abcdef";
  return {
    schemaVersion: SESSION_CONTAINER_RECORD_SCHEMA_VERSION,
    projectId: "000000000000",
    composeProject: "runfree-000000000000",
    sessionId,
    sessionIncarnation: "1".repeat(64),
    sessionPrincipal: "2".repeat(64),
    displayName: "Codex session",
    command: "codex",
    launchPath: "/usr/local/bin/codex",
    launchArgs: [],
    interactive: true,
    tty: true,
    state: "attached",
    containerName: `runfree-000000000000-session-${sessionId}`,
    sourceIp: "172.31.90.20",
    selectedAgentImageRef: "runfree/agent-project:test",
    selectedAgentImageId: `sha256:${"a".repeat(64)}`,
    sessionAgentMaterializationDigest: `sha256:${"b".repeat(64)}`,
    selectedAgentImageInputDigest: `sha256:${"c".repeat(64)}`,
    sessionTemplateDigest: `sha256:${"d".repeat(64)}`,
    sessionAgentGenerationDigest: `sha256:${"e".repeat(64)}`,
    controlPlaneGenerationDigest: `sha256:${"f".repeat(64)}`,
    admissionContractEpoch: 1,
    hostPid: 1,
    createdAt: "2026-10-04T10:00:00.000Z",
    ...overrides,
  };
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

  test("two rollout files that share a session id collapse to one thread, keeping the newest startedAtMs (dedupe)", () => {
    const dir = path.join(stateDir, "codex", "sessions", "2026", "10", "04");
    fs.mkdirSync(dir, { recursive: true });
    const olderLine = JSON.stringify({ type: "session_meta", payload: { id: VALID_UUID_1, timestamp: "2026-10-04T10:00:00.000Z" } });
    const newerLine = JSON.stringify({ type: "session_meta", payload: { id: VALID_UUID_1, timestamp: "2026-10-04T11:00:00.000Z" } });
    fs.writeFileSync(path.join(dir, `rollout-2026-10-04T10-00-00-${VALID_UUID_1}.jsonl`), `${olderLine}\n`);
    fs.writeFileSync(path.join(dir, `rollout-2026-10-04T11-00-00-${VALID_UUID_1}.jsonl`), `${newerLine}\n`);

    const scan = scanCodexThreads({ stateDir, windows: windowAround("2026-10-04T12:00:00.000Z") });

    expect(scan.threads).toEqual([{ id: VALID_UUID_1, startedAtMs: Date.parse("2026-10-04T11:00:00.000Z") }]);
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

  // The naive version of this pair (symlinking the whole day *directory*
  // back to itself) is caught by `entryResolvesInsideDirectory`'s first,
  // cheapest check — "is this still a real directory with the identity we
  // captured before opening" — without ever reaching the realpath or
  // dev/ino comparisons. These two swap only the already-opened *file*, so
  // the day directory itself still passes that first check and the swap is
  // caught only by the deeper checks: a symlink into another directory is
  // caught by the realpath comparison, and an in-place replacement is caught
  // by the dev/ino comparison (review F8; both verified by hand, temporarily
  // deleting the `entryResolvesInsideDirectory` call from `scanDayDirectory`
  // and confirming each case then returns the decoy's/original's thread
  // instead of `[]`, before restoring it).
  test("a rollout file swapped for a symlink into a decoy directory after open is rejected by the realpath check (F8)", () => {
    const filePath = rollout("2026/10/04", VALID_UUID_1, { id: VALID_UUID_1, timestamp: "2026-10-04T12:00:00.000Z" });
    const decoyDir = path.join(stateDir, "decoy");
    fs.mkdirSync(decoyDir, { recursive: true });
    const decoyPath = path.join(decoyDir, path.basename(filePath));
    const decoyLine = JSON.stringify({
      type: "session_meta",
      payload: { id: VALID_UUID_1, timestamp: "2026-10-04T12:00:00.000Z" },
    });
    fs.writeFileSync(decoyPath, `${decoyLine}\n`);

    setCodexRolloutAfterOpenHookForTest(() => {
      fs.unlinkSync(filePath);
      fs.symlinkSync(decoyPath, filePath);
    });

    const scan = scanCodexThreads({ stateDir, windows: windowAround("2026-10-04T12:00:00.000Z") });

    expect(scan).toEqual({ threads: [], complete: true });
  });

  test("a rollout file replaced by a different file at the same path after open is rejected by the dev/ino check (F8)", () => {
    const filePath = rollout("2026/10/04", VALID_UUID_1, { id: VALID_UUID_1, timestamp: "2026-10-04T12:00:00.000Z" });
    const decoyPath = `${filePath}.decoy`;
    const decoyLine = JSON.stringify({
      type: "session_meta",
      payload: { id: VALID_UUID_1, timestamp: "2026-10-04T12:00:00.000Z" },
    });
    fs.writeFileSync(decoyPath, `${decoyLine}\n`);

    setCodexRolloutAfterOpenHookForTest(() => fs.renameSync(decoyPath, filePath));

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

describe("matchCodexThreads", () => {
  const thread: CodexThread = { id: VALID_UUID_1, startedAtMs: Date.parse("2026-10-04T12:00:00.000Z") };
  const window: CodexWindow = {
    startMs: Date.parse("2026-10-04T11:00:00.000Z"),
    endMs: Date.parse("2026-10-04T13:00:00.000Z"),
  };

  test("a thread inside one item's window gives one match with tabs: 1", () => {
    const records: CodexMatchInput[] = [{ itemId: "item-a", window }];

    expect(matchCodexThreads(records, [thread])).toEqual([{ itemId: "item-a", thread, tabs: 1 }]);
  });

  test("a thread inside two items' windows gives a match for each item, both stamped tabs: 2", () => {
    const records: CodexMatchInput[] = [{ itemId: "item-a", window }, { itemId: "item-b", window }];

    expect(matchCodexThreads(records, [thread])).toEqual([
      { itemId: "item-a", thread, tabs: 2 },
      { itemId: "item-b", thread, tabs: 2 },
    ]);
  });

  test("an item with window: undefined never matches", () => {
    const records: CodexMatchInput[] = [{ itemId: "item-a" }];

    expect(matchCodexThreads(records, [thread])).toEqual([]);
  });

  test("a thread outside every window matches nothing", () => {
    const records: CodexMatchInput[] = [{ itemId: "item-a", window }];
    const farThread: CodexThread = { id: VALID_UUID_2, startedAtMs: Date.parse("2026-10-01T00:00:00.000Z") };

    expect(matchCodexThreads(records, [farThread])).toEqual([]);
  });
});

describe("codexWindowForItem", () => {
  test("endedAt wins over the lifecycle record's leaseExpiresAt", () => {
    const item = minimalRecoveryItem({
      startedAt: "2026-10-04T10:00:00.000Z",
      hostMetadata: minimalSessionMetadata({ endedAt: "2026-10-04T10:10:00.000Z", lastSeenAt: "2026-10-04T10:05:00.000Z" }),
    });
    const records = [minimalSessionContainerRecord({ sessionId: item.sourceId, leaseExpiresAt: "2026-10-04T10:30:00.000Z" })];

    expect(codexWindowForItem(item, records)).toEqual({
      startMs: Date.parse("2026-10-04T10:00:00.000Z"),
      endMs: Date.parse("2026-10-04T10:10:00.000Z"),
    });
  });

  test("falls back to the lifecycle record's leaseExpiresAt when endedAt is absent", () => {
    const item = minimalRecoveryItem({
      startedAt: "2026-10-04T10:00:00.000Z",
      hostMetadata: minimalSessionMetadata({ lastSeenAt: "2026-10-04T10:05:00.000Z" }),
    });
    const records = [minimalSessionContainerRecord({ sessionId: item.sourceId, leaseExpiresAt: "2026-10-04T10:30:00.000Z" })];

    expect(codexWindowForItem(item, records)).toEqual({
      startMs: Date.parse("2026-10-04T10:00:00.000Z"),
      endMs: Date.parse("2026-10-04T10:30:00.000Z"),
    });
  });

  test("lastSeenAt is never used: with only lastSeenAt set and no lifecycle record, the window is undefined", () => {
    const item = minimalRecoveryItem({
      startedAt: "2026-10-04T10:00:00.000Z",
      hostMetadata: minimalSessionMetadata({ lastSeenAt: "2026-10-04T10:05:00.000Z" }),
    });

    expect(codexWindowForItem(item, [])).toBeUndefined();
  });

  test("no endedAt, no matching lifecycle record: the window is undefined", () => {
    const item = minimalRecoveryItem({
      startedAt: "2026-10-04T10:00:00.000Z",
      hostMetadata: minimalSessionMetadata(),
    });
    const records = [minimalSessionContainerRecord({ sessionId: "a different session" })];

    expect(codexWindowForItem(item, records)).toBeUndefined();
  });
});
