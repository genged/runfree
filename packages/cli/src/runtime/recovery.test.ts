import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { defaultConfig } from "../config.ts";
import { composeProjectName, projectHash } from "../project-identity.ts";
import { CODEX_MATCH_LIMITS } from "./codex-rollouts.ts";
import {
  acquireRecoveryClaim,
  buildResumeLaunchPlan,
  classifyRecoveryItemLive,
  consumeRecoveryEvidence,
  dismissRecoveryItem,
  formatRecoveryInventory,
  liveClaudeSessionBlocksPicker,
  RECOVERY_LIMITS,
  recoveryClaimScope,
  recoveryIdIsValid,
  recoveryInventoryJson,
  runWithRecoveryClaim,
  scanRecoveryInventory,
  sessionContainerRecoveryLiveInputs,
  UNPROVABLE_CLAIM_MAX_AGE_MS,
  writeProjectRecoveryPointer,
  type RecoveryItem,
} from "./recovery.ts";
import type { SessionContainerRecordV2 } from "./session-containers.ts";
import { tryAcquireProjectLifecycleLock } from "./sessions.ts";
import { matchTerminal, type TerminalSide } from "./terminal-identity.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

const BOOT = "linux:11111111-2222-3333-4444-555555555555";
const PROCESS_START = "linux:12345";
const CLAUDE_SESSION = "11111111-2222-4333-8444-555555555555";
// Above any platform's real pid_max, so `processAlive` is always false for it.
const DEAD_PID = 4_194_305;

let tmp: string;
let projectRoot: string;
let stateDir: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-recovery-"));
  projectRoot = path.join(tmp, "project");
  fs.mkdirSync(projectRoot, { recursive: true });
  env = {
    XDG_STATE_HOME: path.join(tmp, "xdg-state"),
    RUNFREE_TEST_FAKE_DOCKER: "1",
    RUNFREE_TEST_HOST_BOOT_ID: BOOT,
    RUNFREE_TEST_HOST_PROCESS_START: PROCESS_START,
  };
  stateDir = path.join(env.XDG_STATE_HOME as string, "runfree", "projects", projectHash(projectRoot));
  fs.mkdirSync(path.join(stateDir, "sessions"), { recursive: true });
  fs.writeFileSync(
    path.join(stateDir, "project.json"),
    `${JSON.stringify({ projectRoot, updatedAt: "2026-07-31T00:00:00.000Z" })}\n`,
    { mode: 0o600 },
  );
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function hostEvidence(id = "rf-20260731-abcdef", overrides: Record<string, unknown> = {}): string {
  const filePath = path.join(stateDir, "sessions", `${id}.json`);
  fs.writeFileSync(filePath, `${JSON.stringify({
    id,
    projectRoot,
    composeProject: composeProjectName(projectRoot),
    command: "claude",
    hostPid: process.pid,
    hostBootId: BOOT,
    hostProcessStart: PROCESS_START,
    startedAt: "2026-07-31T00:00:00.000Z",
    lastSeenAt: "2026-07-31T00:01:00.000Z",
    ...overrides,
  })}\n`, { mode: 0o600 });
  return filePath;
}

// `pid` controls the registry filename (`claude/sessions/<pid>.json`) as well
// as the default `pid` field, so a caller can write a *second*, distinct
// registry file for the same (or a different) conversation — e.g. a crashed
// original process and a crashed resumed process each leaving their own
// file for one conversation.
function claudeEvidence(overrides: Record<string, unknown> = {}, pid = 4242): string {
  const dir = path.join(stateDir, "claude", "sessions");
  fs.mkdirSync(dir, { recursive: true });
  const filePath = path.join(dir, `${pid}.json`);
  fs.writeFileSync(filePath, `${JSON.stringify({
    pid,
    sessionId: CLAUDE_SESSION,
    cwd: "/workspace",
    startedAt: Date.parse("2026-07-31T00:00:00.000Z"),
    procStart: "98765",
    name: "fix recovery",
    status: "idle",
    updatedAt: Date.parse("2026-07-31T00:02:00.000Z"),
    ...overrides,
  })}\n`, { mode: 0o600 });
  return filePath;
}

/** Writes `<stateDir>/codex/sessions/<date>/rollout-...-<uuid>.jsonl` with a minimal `session_meta` first line, matching the fixture builder in `codex-rollouts.test.ts`. */
function codexRollout(date: string, uuid: string, timestamp: string): void {
  const [year, month, day] = date.split("/");
  const dir = path.join(stateDir, "codex", "sessions", year as string, month as string, day as string);
  fs.mkdirSync(dir, { recursive: true });
  const filePath = path.join(dir, `rollout-${date.replace(/\//g, "-")}T00-00-00-${uuid}.jsonl`);
  fs.writeFileSync(filePath, `${JSON.stringify({ type: "session_meta", payload: { id: uuid, timestamp } })}\n`);
}

function fakeUuid(n: number): string {
  // Only the last, unconstrained 12-hex group varies; version/variant
  // nibbles stay fixed so every generated id still matches the rollout
  // reader's filename pattern.
  return `00000000-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
}

/** The `n`th UTC calendar day after 2026-01-01, as both a `codexRollout` path and an ISO-timestamp builder for a given `HH:MM`, so a test can build many non-overlapping single-day windows without hand-computing month/day rollovers. */
function dayAt(n: number): { path: string; iso: (hm: string) => string } {
  const d = new Date(Date.UTC(2026, 0, 1) + n * 24 * 60 * 60 * 1000);
  const year = String(d.getUTCFullYear());
  const month = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  return {
    path: `${year}/${month}/${day}`,
    iso: (hm: string) => `${year}-${month}-${day}T${hm}:00.000Z`,
  };
}

function runtimeContext(): RuntimeContext {
  const policyPath = path.join(projectRoot, ".runfree", "network-policy.json");
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  if (!fs.existsSync(policyPath)) {
    fs.writeFileSync(policyPath, `${JSON.stringify({ hosts: [], requests: {}, tokens: {} })}\n`);
  }
  return {
    projectRoot,
    project: {
      config: { ...defaultConfig(), version: 3 },
      paths: {
        stateDir,
        sessionsDir: path.join(stateDir, "sessions"),
        policyPath,
        controlProxyDir: path.join(stateDir, "control", "proxy"),
      },
    },
    runtimeRoot: path.join(tmp, "runtime"),
    env,
  } as unknown as RuntimeContext;
}

function firstItem(): RecoveryItem {
  const item = scanRecoveryInventory({ env }).items[0];
  if (!item) throw new Error("missing recovery item fixture");
  return item;
}

// Writes a claim file directly at `item`'s own claim scope path, bypassing
// `acquireRecoveryClaim`, to seed a stuck, dead, or unprovable claim for the
// reclaim tests. Fields set to `undefined` are omitted by `JSON.stringify`,
// which is how the "no identity fields" unprovable fixtures are built.
function writeClaimFile(item: RecoveryItem, overrides: Record<string, unknown> = {}): string {
  const scope = recoveryClaimScope(item);
  fs.mkdirSync(path.dirname(scope.path), { recursive: true, mode: 0o700 });
  fs.writeFileSync(scope.path, `${JSON.stringify({
    v: 1,
    recoveryId: item.id,
    action: "resume",
    ownerPid: process.pid,
    hostBootId: BOOT,
    hostProcessStart: PROCESS_START,
    createdAt: new Date().toISOString(),
    evidence: item.fingerprint,
    ...overrides,
  })}\n`, { mode: 0o600 });
  return scope.path;
}

describe("bounded offline recovery inventory", () => {
  test("unions host and Claude evidence without Docker and emits stable machine ids", () => {
    hostEvidence();
    claudeEvidence();

    const first = scanRecoveryInventory({ env });
    const second = scanRecoveryInventory({ env });

    expect(first.items).toHaveLength(2);
    expect(first.items.map((item) => item.id)).toEqual(second.items.map((item) => item.id));
    expect(first.items.every((item) => item.state === "active" || item.state === "unverified")).toBe(true);
    expect(JSON.parse(recoveryInventoryJson(first))).toMatchObject({ truncated: false, invalidFiles: 0 });
  });

  test("skips symlinks, hard links, oversized files, malformed schemas, and unsafe conversation ids", () => {
    const valid = claudeEvidence();
    fs.symlinkSync(valid, path.join(path.dirname(valid), "4243.json"));
    fs.linkSync(valid, path.join(path.dirname(valid), "4244.json"));
    fs.writeFileSync(path.join(path.dirname(valid), "4245.json"), "x".repeat(70 * 1024));
    fs.writeFileSync(path.join(path.dirname(valid), "4246.json"), JSON.stringify({ sessionId: "$(touch /tmp/no)" }));

    const inventory = scanRecoveryInventory({ env });

    // The hard link makes both names unsafe; no registry entry survives.
    expect(inventory.items).toEqual([]);
    expect(inventory.invalidFiles).toBeGreaterThanOrEqual(4);
  });

  test("rejects invalid same-terminal resume fields on host evidence", () => {
    hostEvidence("rf-20260731-badterm", { terminalIds: { iterm: 5 } });
    hostEvidence("rf-20260731-badver", { recordVersion: 3 });
    hostEvidence("rf-20260731-baduuid", { launchConversationId: "not-a-uuid" });

    const inventory = scanRecoveryInventory({ env });

    expect(inventory.items).toEqual([]);
    expect(inventory.invalidFiles).toBe(3);
  });

  test("rejects a symlinked agent-writable registry directory ancestor", () => {
    claudeEvidence();
    const claudeDir = path.join(stateDir, "claude");
    const outside = path.join(tmp, "outside-claude-state");
    fs.renameSync(claudeDir, outside);
    fs.symlinkSync(outside, claudeDir, "dir");

    expect(scanRecoveryInventory({ env }).items).toEqual([]);
  });

  test("sanitizes agent-controlled names in text output", () => {
    claudeEvidence({ name: "safe\u001b[2J\nFAKE PROMPT" });

    const output = formatRecoveryInventory(scanRecoveryInventory({ env }));

    expect(output).toContain("safeFAKE PROMPT");
    expect(output).not.toContain("\u001b");
    expect(output).not.toContain("\nFAKE PROMPT");
  });

  // Review F5: `formatRecoveryInventory` and `recoveryInventoryJson` sanitize
  // agent-supplied names with `sanitizeAgentText` (resume-selection.ts), not
  // the plainer `sanitizeForTerminal` — so a bidi override and a zero-width
  // space (neither of which is a C0/C1 control or an ANSI sequence) are
  // stripped too, in both the table Runfree prints and the JSON it emits.
  test("strips a bidi override and a zero-width space from an agent-supplied conversation name", () => {
    claudeEvidence({ name: "safe‮name​here" });

    const inventory = scanRecoveryInventory({ env });
    const textOutput = formatRecoveryInventory(inventory);
    const jsonOutput = JSON.parse(recoveryInventoryJson(inventory)) as { items: Array<{ conversationName?: string }> };

    expect(textOutput).toContain("safenamehere");
    expect(textOutput).not.toContain("‮");
    expect(textOutput).not.toContain("​");
    expect(jsonOutput.items[0]?.conversationName).toBe("safenamehere");
  });

  test("invalid project mappings are listable but never actionable", () => {
    hostEvidence();
    fs.writeFileSync(
      path.join(stateDir, "project.json"),
      `${JSON.stringify({ projectRoot: path.join(tmp, "other"), updatedAt: "2026-07-31T00:00:00.000Z" })}\n`,
    );

    expect(firstItem()).toMatchObject({ state: "unrecoverable", reason: expect.stringContaining("mapping") });
  });

  test("stops before reading past the per-kind file budget and reports truncation", () => {
    // Exercise the boundary with real files without thousands of synchronous
    // writes, secure reads, and unlinks competing with the parallel suite.
    const originalLimit = RECOVERY_LIMITS.maxFilesPerKindPerProject;
    Object.assign(RECOVERY_LIMITS, { maxFilesPerKindPerProject: 2 });
    const open = vi.spyOn(fs, "openSync");
    try {
      const files = [hostEvidence("rf-20260731-000000"), hostEvidence("rf-20260731-000001")];
      const atLimit = scanRecoveryInventory({ env });
      expect(atLimit.items).toHaveLength(2);
      expect(atLimit.truncated).toBe(false);
      files.push(hostEvidence("rf-20260731-000002"));
      claudeEvidence();
      open.mockClear();

      const inventory = scanRecoveryInventory({ env });
      const hostItems = inventory.items.filter((item) => item.evidenceKind === "host");

      expect(hostItems).toHaveLength(2);
      expect(inventory.items.filter((item) => item.evidenceKind === "claude")).toHaveLength(1);
      expect(inventory.truncated).toBe(true);
      // The excess file must never be opened, even if its result is discarded.
      expect(open.mock.calls.map(([file]) => file).filter((file) => files.includes(String(file))).sort())
        .toEqual(hostItems.map((item) => item.evidencePath).sort());
    } finally {
      open.mockRestore();
      Object.assign(RECOVERY_LIMITS, { maxFilesPerKindPerProject: originalLimit });
    }
  });

  test("keeps the newest files when the per-kind cap truncates a project", () => {
    // Sort-before-cap: a truncation must keep the most recently active
    // evidence, never whichever files the filesystem happens to enumerate
    // first.
    const originalLimit = RECOVERY_LIMITS.maxFilesPerKindPerProject;
    const cap = 5;
    Object.assign(RECOVERY_LIMITS, { maxFilesPerKindPerProject: cap });
    try {
      const ids = Array.from({ length: cap + 5 }, (_, index) => `rf-20260731-sess${String(index).padStart(2, "0")}`);
      const files = ids.map((id) => hostEvidence(id, { outcome: "interrupted", endedAt: "2026-07-31T00:02:00.000Z" }));
      // Explicit mtimes, newest last, regardless of write order: the last 5
      // ids are the 5 newest files.
      files.forEach((filePath, index) => {
        const stamp = new Date((1_700_000_000 + index) * 1000);
        fs.utimesSync(filePath, stamp, stamp);
      });
      const newestIds = ids.slice(-cap);

      const inventory = scanRecoveryInventory({ env });

      expect(inventory.truncated).toBe(true);
      expect(inventory.items.map((item) => item.sourceId).sort()).toEqual([...newestIds].sort());
    } finally {
      Object.assign(RECOVERY_LIMITS, { maxFilesPerKindPerProject: originalLimit });
    }
  });

  test("bounds a directory flooded with non-matching junk entries", () => {
    // Review F4: every directory entry counts against the name budget,
    // matching or not, so a flood of junk names must not make the scan
    // iterate (or stat) all of them.
    const dir = path.join(stateDir, "claude", "sessions");
    fs.mkdirSync(dir, { recursive: true });
    for (let index = 0; index < 100_000; index += 1) {
      fs.writeFileSync(path.join(dir, `junk-${index}.txt`), "x");
    }

    const startedAtMs = Date.now();
    const inventory = scanRecoveryInventory({ env });
    const elapsedMs = Date.now() - startedAtMs;

    expect(elapsedMs).toBeLessThan(3_000);
    expect(inventory.truncated).toBe(true);
    expect(inventory.items).toEqual([]);
  }, 30_000);

  test("bounds a directory scan by wall-clock deadline, independent of the name budget", () => {
    // Tells the two F4 budgets apart: this flood is far too small to ever hit
    // `maxNamesPerKindPerProject` (16_384) on its own, so only the deadline
    // can explain a truncation here.
    const dir = path.join(stateDir, "claude", "sessions");
    fs.mkdirSync(dir, { recursive: true });
    for (let index = 0; index < 10; index += 1) {
      fs.writeFileSync(path.join(dir, `junk-${index}.txt`), "x");
    }
    const realNow = Date.now.bind(Date);
    let calls = 0;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => {
      calls += 1;
      // Let the first few deadline checks through at the real time (enough
      // to start reading real entries), then jump straight past the
      // deadline so the scan truncates after only a handful of entries.
      return calls <= 5 ? realNow() : realNow() + RECOVERY_LIMITS.scanDeadlineMs + 1;
    });
    try {
      const inventory = scanRecoveryInventory({ env });

      expect(inventory.truncated).toBe(true);
      // Far fewer directory reads than the name budget: the deadline, not
      // the name count, is what stopped this scan.
      expect(calls).toBeLessThan(RECOVERY_LIMITS.maxNamesPerKindPerProject);
    } finally {
      nowSpy.mockRestore();
    }
  });

  test("mints a host-chosen exact id from a fresh launch's own host record", () => {
    hostEvidence(undefined, { recordVersion: 2, launchConversationId: CLAUDE_SESSION, outcome: "interrupted" });

    expect(firstItem()).toMatchObject({
      recordVersion: 2,
      conversationId: CLAUDE_SESSION,
      conversationSource: "host-chosen",
    });
  });

  test("carries resume lineage from a resumed launch's own host record", () => {
    hostEvidence(undefined, { recordVersion: 2, resumeConversationId: CLAUDE_SESSION, outcome: "interrupted" });

    expect(firstItem()).toMatchObject({
      conversationId: CLAUDE_SESSION,
      conversationSource: "resume-lineage",
    });
  });

  test("resume lineage wins over a host-chosen id when a record somehow carries both", () => {
    const OTHER_SESSION = "22222222-3333-4333-8444-555555555555";
    hostEvidence(undefined, {
      recordVersion: 2,
      launchConversationId: OTHER_SESSION,
      resumeConversationId: CLAUDE_SESSION,
      outcome: "interrupted",
    });

    expect(firstItem()).toMatchObject({
      conversationId: CLAUDE_SESSION,
      conversationSource: "resume-lineage",
    });
  });

  test("joins a host item to its own reported Claude registry evidence into exactly one item", () => {
    claudeEvidence({ sessionId: CLAUDE_SESSION });
    const standaloneClaudeItem = firstItem();

    hostEvidence(undefined, { recordVersion: 2, launchConversationId: CLAUDE_SESSION, outcome: "interrupted" });

    const inventory = scanRecoveryInventory({ env });

    expect(inventory.items).toHaveLength(1);
    const [item] = inventory.items;
    expect(item).toMatchObject({
      evidenceKind: "host",
      conversationName: "fix recovery",
      conversationNameSource: "claude-reported",
    });
    expect(item?.linkedClaude).toEqual([{
      id: standaloneClaudeItem.id,
      evidencePath: standaloneClaudeItem.evidencePath,
      fingerprint: standaloneClaudeItem.fingerprint,
    }]);
  });

  test("joins every unconsumed duplicate Claude registry file for one conversation, newest first", () => {
    // Two registry files can legitimately name the same conversation (a
    // crashed original process plus a crashed resumed process), and an agent
    // can also forge a duplicate. `recoveryId` hashes only the conversation,
    // so both get the same recovery id; joining must gather both or one
    // survives as a standalone row with an id equal to the linked id.
    // Deliberately not read standalone before the host item exists: both
    // files share one recovery id (see above), so the pre-existing id-keyed
    // dedup in `scanRecoveryInventory` would already collapse them to one
    // entry with nothing yet to join against, which would prove nothing
    // about the join itself.
    const older = claudeEvidence({
      sessionId: CLAUDE_SESSION,
      name: "older generation",
      updatedAt: Date.parse("2026-07-31T00:01:00.000Z"),
    }, 4242);
    const newer = claudeEvidence({
      sessionId: CLAUDE_SESSION,
      name: "newer generation",
      updatedAt: Date.parse("2026-07-31T00:05:00.000Z"),
    }, 4343);

    hostEvidence(undefined, { recordVersion: 2, launchConversationId: CLAUDE_SESSION, outcome: "interrupted" });

    const inventory = scanRecoveryInventory({ env });

    expect(inventory.items).toHaveLength(1);
    const [item] = inventory.items;
    expect(item?.evidenceKind).toBe("host");
    expect(item?.conversationName).toBe("newer generation");
    expect(item?.conversationNameSource).toBe("claude-reported");
    // Newest first, by evidencePath (both links share one `id`, which is the
    // accepted consequence of the shared-conversation hash above).
    expect(item?.linkedClaude).toHaveLength(2);
    expect(item?.linkedClaude?.map((link) => link.evidencePath)).toEqual([newer, older]);
    const [newestLink, olderLink] = item?.linkedClaude ?? [];
    expect(recoveryIdIsValid(newestLink?.id ?? "")).toBe(true);
    expect(newestLink?.id).toBe(olderLink?.id);
    // No standalone Claude row leaked out at all, so none can carry an id
    // equal to a linked id.
    expect(inventory.items.some((candidate) => candidate.evidenceKind === "claude")).toBe(false);
  });

  test("a host item whose only linked Claude evidence was consumed keeps no link", async () => {
    claudeEvidence({ sessionId: CLAUDE_SESSION });
    const claudeItem = firstItem();
    await expect(runWithRecoveryClaim(runtimeContext(), claudeItem, () => 0)).resolves.toEqual({
      status: 0,
      consumed: true,
    });

    hostEvidence(undefined, { recordVersion: 2, launchConversationId: CLAUDE_SESSION, outcome: "interrupted" });

    const inventory = scanRecoveryInventory({ env });

    expect(inventory.items).toHaveLength(1);
    const [item] = inventory.items;
    expect(item?.evidenceKind).toBe("host");
    expect(item?.linkedClaude).toBeUndefined();
    expect(inventory.items.some((candidate) => candidate.evidenceKind === "claude")).toBe(false);
  });

  test("consuming one of two duplicate Claude registry files leaves only the unconsumed one linked", async () => {
    // Consume the first duplicate while it is still the *only* claude item,
    // so its own scan is never subject to the id-collision dedup above; only
    // then does the second (unconsumed) duplicate for the same conversation
    // appear.
    claudeEvidence({ sessionId: CLAUDE_SESSION, name: "older generation" }, 4242);
    const olderItem = firstItem();
    await expect(runWithRecoveryClaim(runtimeContext(), olderItem, () => 0)).resolves.toEqual({
      status: 0,
      consumed: true,
    });

    const newer = claudeEvidence({
      sessionId: CLAUDE_SESSION,
      name: "newer generation",
      updatedAt: Date.parse("2026-07-31T00:05:00.000Z"),
    }, 4343);
    hostEvidence(undefined, { recordVersion: 2, launchConversationId: CLAUDE_SESSION, outcome: "interrupted" });

    const inventory = scanRecoveryInventory({ env });

    expect(inventory.items).toHaveLength(1);
    const [item] = inventory.items;
    expect(item?.linkedClaude).toHaveLength(1);
    expect(item?.linkedClaude?.[0]?.evidencePath).toBe(newer);
    expect(inventory.items.some((candidate) => candidate.evidenceKind === "claude")).toBe(false);
  });

  test("the exact-recovery epoch does not block a host Claude record that names its own conversation", () => {
    // H2: the epoch only protects imprecise host-only evidence; a host record
    // with an exact id (host-chosen or resume lineage) can never be shadowed
    // by a different exact Claude recovery completing.
    fs.mkdirSync(path.join(stateDir, "sessions", "recovery-consumed"), { recursive: true, mode: 0o700 });
    fs.writeFileSync(
      path.join(stateDir, "sessions", "recovery-consumed", "agent-claude.json"),
      `${JSON.stringify({ v: 1, agent: "claude", consumedAt: "2026-07-31T00:03:00.000Z" })}\n`,
      { mode: 0o600 },
    );
    hostEvidence("rf-20260731-withid", {
      recordVersion: 2,
      launchConversationId: CLAUDE_SESSION,
      outcome: "interrupted",
      endedAt: "2026-07-31T00:02:00.000Z",
    });
    hostEvidence("rf-20260731-noidrec", { outcome: "interrupted", endedAt: "2026-07-31T00:02:00.000Z" });

    const inventory = scanRecoveryInventory({ env });
    const withId = inventory.items.find((item) => item.sourceId === "rf-20260731-withid");
    const noId = inventory.items.find((item) => item.sourceId === "rf-20260731-noidrec");

    expect(withId).toBeDefined();
    expect(noId).toBeDefined();
    expect(withId?.resumeBlockedReason).toBeUndefined();
    expect(noId?.resumeBlockedReason).toContain("exact Claude recovery");
  });

  test("carries terminal ids, tty, term program, boot id, and a dead owner state for interrupted host evidence", () => {
    hostEvidence(undefined, {
      outcome: "interrupted",
      terminalIds: { iterm: "w0t0p0" },
      hostTty: "/dev/ttys003",
      termProgram: "iTerm.app",
    });

    const item = firstItem();

    expect(item.ownerState).toBe("dead");
    expect(item.terminal?.ids).toEqual({ iterm: "w0t0p0" });
    expect(item.terminal?.bootId).toBe(BOOT);
    expect(item.terminal?.tty).toBe("/dev/ttys003");
    expect(item.terminal?.termProgram).toBe("iTerm.app");
  });

  test("the final id-keyed dedup keeps the newest of two orphan Claude files sharing a sessionId (ruling A)", () => {
    // No host record exists, so these two duplicate registry files for one
    // conversation have nothing to join against (`joinHostAndClaudeItems`
    // only folds Claude items into a *host* item): the id-keyed dedup at the
    // end of `scanRecoveryInventory` is what collapses the two into one row,
    // and it must keep the newer file — a `Map` built from `[id, item]`
    // pairs over a newest-first array keeps the *last* `set`, which is the
    // oldest, the opposite of what the prompt and picker must show.
    const older = claudeEvidence({
      sessionId: CLAUDE_SESSION,
      name: "older generation",
      updatedAt: Date.parse("2026-07-31T00:01:00.000Z"),
    }, 4242);
    const newer = claudeEvidence({
      sessionId: CLAUDE_SESSION,
      name: "newer generation",
      updatedAt: Date.parse("2026-07-31T00:05:00.000Z"),
    }, 4343);

    const inventory = scanRecoveryInventory({ env });

    expect(inventory.items).toHaveLength(1);
    expect(inventory.items[0]?.evidencePath).toBe(newer);
    expect(inventory.items[0]?.evidencePath).not.toBe(older);
    expect(inventory.items[0]?.conversationName).toBe("newer generation");
  });
});

describe("host-host join for one conversation (decision 10, security review F3)", () => {
  test("two host records naming the same exact conversation join into one item, built from the newer, naming the older linkedHost", () => {
    const olderPath = hostEvidence("rf-20260731-original", {
      recordVersion: 2,
      launchConversationId: CLAUDE_SESSION,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:00:00.000Z",
      terminalIds: { appleTerminal: "tab-1" },
      hostTty: "/dev/ttys001",
      termProgram: "Apple_Terminal",
    });
    // What a killed host client leaves: the original launch's own record,
    // plus a later resume's record for the same conversation, carrying
    // tab 2's own terminal ids.
    const newerPath = hostEvidence("rf-20260731-resumed", {
      recordVersion: 2,
      resumeConversationId: CLAUDE_SESSION,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:10:00.000Z",
      terminalIds: { appleTerminal: "tab-2" },
      hostTty: "/dev/ttys002",
      termProgram: "Apple_Terminal",
    });

    const inventory = scanRecoveryInventory({ env });

    expect(inventory.items).toHaveLength(1);
    const [item] = inventory.items;
    expect(item?.evidencePath).toBe(newerPath);
    expect(item?.terminal?.ids).toEqual({ appleTerminal: "tab-2" });
    expect(item?.linkedHost).toHaveLength(1);
    expect(item?.linkedHost?.[0]?.evidencePath).toBe(olderPath);
    expect(item?.linkedHost?.[0]?.sourceId).toBe("rf-20260731-original");
  });

  test("the merged primary inherits a linkedClaude list the *other* grouped host item was the one joined to", () => {
    // `joinHostAndClaudeItems` (Task 5) attaches every match for a key to
    // whichever host item it meets first by scan order (file mtime), not by
    // `startedAt` content — so the member holding the Claude link and the
    // member kept as the primary (newest `startedAt`) can be two different
    // items. `joinHostItemsBySameConversation` must still carry the link
    // forward onto the kept primary rather than losing it.
    const claudePath = claudeEvidence({ sessionId: CLAUDE_SESSION });
    const olderPath = hostEvidence("rf-20260731-original", {
      recordVersion: 2,
      launchConversationId: CLAUDE_SESSION,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:00:00.000Z",
    });
    const newerPath = hostEvidence("rf-20260731-resumed", {
      recordVersion: 2,
      resumeConversationId: CLAUDE_SESSION,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:10:00.000Z",
    });
    // Force the scan to see the *older* (by `startedAt`) host record first,
    // so the Claude join above lands on it instead of on the kept primary.
    const olderFileMtime = new Date("2026-07-31T00:20:00.000Z");
    const newerFileMtime = new Date("2026-07-31T00:15:00.000Z");
    fs.utimesSync(olderPath, olderFileMtime, olderFileMtime);
    fs.utimesSync(newerPath, newerFileMtime, newerFileMtime);

    const inventory = scanRecoveryInventory({ env });

    expect(inventory.items).toHaveLength(1);
    const [item] = inventory.items;
    expect(item?.evidencePath).toBe(newerPath);
    expect(item?.linkedHost).toHaveLength(1);
    expect(item?.linkedHost?.[0]?.evidencePath).toBe(olderPath);
    expect(item?.linkedClaude).toHaveLength(1);
    expect(item?.linkedClaude?.[0]?.evidencePath).toBe(claudePath);
  });

  test("consuming the joined item deletes both host records", async () => {
    const olderPath = hostEvidence("rf-20260731-original", {
      recordVersion: 2,
      launchConversationId: CLAUDE_SESSION,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:00:00.000Z",
    });
    const newerPath = hostEvidence("rf-20260731-resumed", {
      recordVersion: 2,
      resumeConversationId: CLAUDE_SESSION,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:10:00.000Z",
    });
    const item = firstItem();

    await expect(runWithRecoveryClaim(runtimeContext(), item, () => 0)).resolves.toEqual({ status: 0, consumed: true });

    expect(fs.existsSync(newerPath)).toBe(false);
    expect(fs.existsSync(olderPath)).toBe(false);
  });

  test("dismissing the joined item deletes both host records", async () => {
    const olderPath = hostEvidence("rf-20260731-original", {
      recordVersion: 2,
      launchConversationId: CLAUDE_SESSION,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:00:00.000Z",
    });
    const newerPath = hostEvidence("rf-20260731-resumed", {
      recordVersion: 2,
      resumeConversationId: CLAUDE_SESSION,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:10:00.000Z",
    });
    const item = firstItem();

    const result = await dismissRecoveryItem(runtimeContext(), item);

    expect(result).toBe("dismissed");
    expect(fs.existsSync(newerPath)).toBe(false);
    expect(fs.existsSync(olderPath)).toBe(false);
  });

  test("a stale linkedHost entry is left alone and does not fail consumption of the primary", async () => {
    const olderPath = hostEvidence("rf-20260731-original", {
      recordVersion: 2,
      launchConversationId: CLAUDE_SESSION,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:00:00.000Z",
    });
    hostEvidence("rf-20260731-resumed", {
      recordVersion: 2,
      resumeConversationId: CLAUDE_SESSION,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:10:00.000Z",
    });
    const item = firstItem();
    // Changed after the scan built `linkedHost`, before consumption runs.
    const replacement = JSON.parse(fs.readFileSync(olderPath, "utf8"));
    replacement.lastSeenAt = "2026-07-31T00:09:00.000Z";
    fs.writeFileSync(olderPath, `${JSON.stringify(replacement)}\n`);

    await expect(runWithRecoveryClaim(runtimeContext(), item, () => 0)).resolves.toEqual({ status: 0, consumed: true });

    expect(fs.existsSync(olderPath)).toBe(true);
  });

  test("a terminal match against the newer record's ids is strong, and against the older record's ids is not", () => {
    // After test 5's join, the second crash prompts in tab 2: the kept
    // item's own `terminal` field is the newer (resuming) record's.
    hostEvidence("rf-20260731-original", {
      recordVersion: 2,
      launchConversationId: CLAUDE_SESSION,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:00:00.000Z",
      terminalIds: { appleTerminal: "tab-1" },
      hostTty: "/dev/ttys001",
      termProgram: "Apple_Terminal",
    });
    hostEvidence("rf-20260731-resumed", {
      recordVersion: 2,
      resumeConversationId: CLAUDE_SESSION,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:10:00.000Z",
      terminalIds: { appleTerminal: "tab-2" },
      hostTty: "/dev/ttys002",
      termProgram: "Apple_Terminal",
    });
    const item = firstItem();
    if (!item.terminal) throw new Error("missing terminal fixture");
    const tab2: TerminalSide = {
      ids: { appleTerminal: "tab-2" },
      tty: "/dev/ttys002",
      termProgram: "Apple_Terminal",
      bootId: BOOT,
    };
    const tab1: TerminalSide = {
      ids: { appleTerminal: "tab-1" },
      tty: "/dev/ttys001",
      termProgram: "Apple_Terminal",
      bootId: BOOT,
    };

    expect(matchTerminal(tab2, item.terminal)).toBe("strong");
    expect(matchTerminal(tab1, item.terminal)).not.toBe("strong");
  });
});

describe("live classification and launch plans", () => {
  test("requires a successful container-session probe before host evidence becomes interrupted", () => {
    hostEvidence(undefined, { outcome: "interrupted", exitStatus: 137, endedAt: "2026-07-31T00:02:00.000Z" });
    const item = firstItem();
    const context = runtimeContext();
    const io = { capture: () => ({ status: 1, stdout: "", stderr: "" }) } as unknown as RuntimeIO;

    expect(classifyRecoveryItemLive(item, context, io, {
      activeSessions: [],
      agentContainerId: "agent-id",
    }).state).toBe("unverified");
    expect(classifyRecoveryItemLive(item, context, io, {
      activeSessions: [],
    }).state).toBe("interrupted");
    expect(classifyRecoveryItemLive(item, context, io, {
      activeSessions: [{
        sessionId: item.sourceId,
        command: "Claude",
        containerTty: "pts/0",
        name: "Claude recovery",
        processCount: 1,
      }],
    }).state).toBe("active");
  });

  test("a live PID with incomplete identity remains unverified even when no container is running", () => {
    hostEvidence(undefined, { hostProcessStart: undefined });
    const item = firstItem();

    expect(classifyRecoveryItemLive(
      item,
      runtimeContext(),
      { capture: () => ({ status: 1, stdout: "", stderr: "" }) } as unknown as RuntimeIO,
      { activeSessions: [] },
    )).toMatchObject({ state: "unverified", reason: expect.stringContaining("identity") });
  });

  test("a stopped or absent agent container makes valid Claude registry evidence interrupted", () => {
    claudeEvidence();
    const item = firstItem();
    const classified = classifyRecoveryItemLive(
      item,
      runtimeContext(),
      { capture: () => ({ status: 1, stdout: "", stderr: "" }) } as unknown as RuntimeIO,
      { activeSessions: [] },
    );

    expect(classified.state).toBe("interrupted");
  });

  test("a killed host client never makes its still-running container session resumable", () => {
    hostEvidence(undefined, { outcome: "interrupted", exitStatus: 137, endedAt: "2026-07-31T00:02:00.000Z" });
    const item = firstItem();
    const context = runtimeContext();
    fs.mkdirSync(path.join(context.runtimeRoot, "agent"), { recursive: true });
    fs.writeFileSync(path.join(context.runtimeRoot, "agent", "inspect-active-sessions.sh"), "probe");
    const io = {
      capture: () => ({
        status: 0,
        stdout: `123\tpts/0\t${item.sourceId}\tclaude --resume\n`,
        stderr: "",
      }),
    } as unknown as RuntimeIO;

    expect(classifyRecoveryItemLive(item, context, io, {
      activeSessions: [],
      agentContainerId: "agent-id",
    }).state).toBe("active");
  });

  test("builds descriptor-owned argv and never interpolates the conversation id into shell source", () => {
    claudeEvidence();
    const item = firstItem();
    const plan = buildResumeLaunchPlan(runtimeContext(), item);

    expect(plan).toMatchObject({ precision: "exact", env: {} });
    expect(plan?.argv).toEqual([
      "claude",
      "--dangerously-skip-permissions",
      "--add-dir",
      "/runfree/inbox",
      "--resume",
      CLAUDE_SESSION,
    ]);
    expect(plan?.argv.at(-1)).toBe(item.conversationId);
  });

  test("preserves the managed Claude inbox grant in picker-based recovery", () => {
    hostEvidence(undefined, { outcome: "interrupted", exitStatus: 137, endedAt: "2026-07-31T00:02:00.000Z" });

    expect(buildResumeLaunchPlan(runtimeContext(), firstItem())).toMatchObject({
      precision: "picker",
      argv: [
        "claude",
        "--dangerously-skip-permissions",
        "--add-dir",
        "/runfree/inbox",
        "--resume",
      ],
    });
  });

  test("recognizes the previous built-in Claude command as managed", () => {
    claudeEvidence();
    const context = runtimeContext();
    context.project.config.agents.claude = { command: "claude --dangerously-skip-permissions" };

    expect(buildResumeLaunchPlan(context, firstItem())).toMatchObject({
      precision: "exact",
      argv: expect.arrayContaining(["--add-dir", "/runfree/inbox", "--resume", CLAUDE_SESSION]),
    });
  });

  test("requires an explicit resumeCommand for a customized built-in command", () => {
    hostEvidence(undefined, { command: "codex", agentCommand: "codex --custom" });
    const item = firstItem();
    const context = runtimeContext();
    context.project.config.agents.codex = { command: "codex --custom" };

    expect(buildResumeLaunchPlan(context, item)).toBeUndefined();

    context.project.config.agents.codex = { command: "codex --custom", resumeCommand: "codex custom-resume" };
    expect(buildResumeLaunchPlan(context, item)).toMatchObject({
      argv: ["zsh", "-c", "exec zsh -c \"$RUNFREE_RESUME_COMMAND\""],
      env: { RUNFREE_RESUME_COMMAND: "codex custom-resume" },
    });
  });
});

function sessionRecord(overrides: Partial<SessionContainerRecordV2> = {}): SessionContainerRecordV2 {
  const projectId = projectHash(projectRoot);
  const sessionId = (overrides.sessionId as string | undefined) ?? "rf-20260731-abcdef";
  return {
    schemaVersion: 4,
    projectId,
    composeProject: `runfree-${projectId}`,
    sessionId,
    sessionIncarnation: "1".repeat(64),
    sessionPrincipal: "2".repeat(64),
    displayName: "Claude Code resume",
    command: "claude",
    launchPath: "/usr/local/bin/claude",
    launchArgs: ["--dangerously-skip-permissions", "--add-dir", "/runfree/inbox"],
    interactive: true,
    tty: true,
    state: "attached",
    containerName: `runfree-${projectId}-session-${sessionId}`,
    containerId: "3".repeat(64),
    sourceIp: "172.31.90.20",
    selectedAgentImageRef: "runfree/agent-project:test",
    selectedAgentImageId: `sha256:${"a".repeat(64)}`,
    sessionAgentMaterializationDigest: `sha256:${"b".repeat(64)}`,
    selectedAgentImageInputDigest: `sha256:${"c".repeat(64)}`,
    sessionTemplateDigest: `sha256:${"d".repeat(64)}`,
    sessionAgentGenerationDigest: `sha256:${"e".repeat(64)}`,
    controlPlaneGenerationDigest: `sha256:${"f".repeat(64)}`,
    admissionContractEpoch: 3,
    hostPid: process.pid,
    hostBootId: BOOT,
    hostProcessStart: PROCESS_START,
    createdAt: "2026-07-31T00:00:00.000Z",
    admittedAt: "2026-07-31T00:00:10.000Z",
    leaseGeneration: "4".repeat(32),
    leaseExpiresAt: "2026-07-31T00:05:10.000Z",
    ...overrides,
  } as SessionContainerRecordV2;
}

describe("per-session lifecycle registry classification", () => {
  const failingIo = { capture: () => ({ status: 1, stdout: "", stderr: "" }) } as unknown as RuntimeIO;

  test("a live lifecycle record makes its host evidence active without probing any container", () => {
    hostEvidence(undefined, { outcome: "interrupted", exitStatus: 137, endedAt: "2026-07-31T00:02:00.000Z" });
    const io = {
      capture: () => {
        throw new Error("classification must not exec into a session container");
      },
    } as unknown as RuntimeIO;

    expect(classifyRecoveryItemLive(firstItem(), runtimeContext(), io, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: false },
    }).state).toBe("active");
  });

  test("a stale lifecycle record proves interruption where the legacy probe could not", () => {
    hostEvidence(undefined, { outcome: "interrupted", exitStatus: 137, endedAt: "2026-07-31T00:02:00.000Z" });
    const stale = sessionRecord({ hostBootId: "linux:99999999-8888-7777-6666-555555555555" });

    // Without the registry decision this item would be unverified: the shared
    // agent inspector asset is absent, so the legacy probe answers "unknown".
    expect(classifyRecoveryItemLive(firstItem(), runtimeContext(), failingIo, {
      activeSessions: [],
      agentContainerId: "agent-id",
      sessionContainers: { records: [stale], unreadable: false },
    }).state).toBe("interrupted");
  });

  test("session-world evidence with no surviving record is interrupted, and unverified when the registry is partial", () => {
    hostEvidence(undefined, {
      outcome: "interrupted",
      exitStatus: 137,
      endedAt: "2026-07-31T00:02:00.000Z",
      sessionContainerName: `runfree-${projectHash(projectRoot)}-session-rf-20260731-abcdef`,
    });
    const item = firstItem();
    const context = runtimeContext();

    expect(classifyRecoveryItemLive(item, context, failingIo, {
      activeSessions: [],
      agentContainerId: "agent-id",
      sessionContainers: { records: [], unreadable: false },
    }).state).toBe("interrupted");
    expect(classifyRecoveryItemLive(item, context, failingIo, {
      activeSessions: [],
      sessionContainers: { records: [], unreadable: true },
    })).toMatchObject({ state: "unverified", reason: expect.stringContaining("registry") });
  });

  test("a revoking record is teardown in progress while its owner lives, interrupted once the owner is gone", () => {
    hostEvidence(undefined, { outcome: "interrupted", exitStatus: 137, endedAt: "2026-07-31T00:02:00.000Z" });
    const item = firstItem();
    const context = runtimeContext();

    expect(classifyRecoveryItemLive(item, context, failingIo, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord({ state: "revoking" })], unreadable: false },
    })).toMatchObject({ state: "unverified", reason: expect.stringContaining("teardown") });
    expect(classifyRecoveryItemLive(item, context, failingIo, {
      activeSessions: [],
      sessionContainers: {
        records: [sessionRecord({ state: "revoking", hostBootId: "linux:99999999-8888-7777-6666-555555555555" })],
        unreadable: false,
      },
    }).state).toBe("interrupted");
  });

  test("Claude registry evidence is probed inside record-bound claude session containers", () => {
    claudeEvidence();
    const item = firstItem();
    const context = runtimeContext();
    const containerId = "3".repeat(64);
    const io = {
      capture: (_command: string, args: string[]) => {
        if (args[0] === "inspect") {
          expect(args.at(-1)).toBe(containerId);
          return { status: 0, stdout: "true\t2026-07-31T00:00:30.000000000Z", stderr: "" };
        }
        expect(args).toContain(containerId);
        return { status: 0, stdout: "98765", stderr: "" };
      },
    } as unknown as RuntimeIO;

    expect(classifyRecoveryItemLive(item, context, io, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: false },
    }).state).toBe("active");
  });

  test("Claude registry evidence with a dead pid in every candidate container is interrupted, and a partial registry is not", () => {
    claudeEvidence();
    const item = firstItem();
    const context = runtimeContext();
    const io = {
      capture: (_command: string, args: string[]) => {
        if (args[0] === "inspect") return { status: 0, stdout: "true\t2026-07-31T00:00:30.000000000Z", stderr: "" };
        return { status: 2, stdout: "", stderr: "" };
      },
    } as unknown as RuntimeIO;

    expect(classifyRecoveryItemLive(item, context, io, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: false },
    }).state).toBe("interrupted");
    expect(classifyRecoveryItemLive(item, context, io, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: true },
    }).state).toBe("unverified");
  });

  test("a record whose container Docker confirms absent is decisively gone, not indecisive", () => {
    claudeEvidence();
    const item = firstItem();
    const context = runtimeContext();
    // The residue a crash between container removal and record deletion
    // leaves: a stale record naming a container the daemon no longer knows.
    const absentIo = {
      capture: () => ({ status: 1, stdout: "", stderr: `Error: No such object: ${"3".repeat(64)}` }),
    } as unknown as RuntimeIO;
    const daemonDownIo = {
      capture: () => ({ status: 1, stdout: "", stderr: "Cannot connect to the Docker daemon" }),
    } as unknown as RuntimeIO;

    expect(classifyRecoveryItemLive(item, context, absentIo, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: false },
    }).state).toBe("interrupted");
    expect(classifyRecoveryItemLive(item, context, daemonDownIo, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: false },
    }).state).toBe("unverified");
  });

  test("resume lineage on crashed resume evidence yields an exact item; a corrupted value degrades to picker", () => {
    hostEvidence(undefined, {
      outcome: "interrupted",
      exitStatus: 137,
      endedAt: "2026-07-31T00:02:00.000Z",
      resumeConversationId: CLAUDE_SESSION,
    });
    const context = runtimeContext();
    const exact = firstItem();
    expect(exact.conversationId).toBe(CLAUDE_SESSION);
    expect(buildResumeLaunchPlan(context, exact)).toMatchObject({
      precision: "exact",
      argv: expect.arrayContaining(["--resume", CLAUDE_SESSION]),
    });

    hostEvidence(undefined, {
      outcome: "interrupted",
      exitStatus: 137,
      endedAt: "2026-07-31T00:02:00.000Z",
      resumeConversationId: "../../etc/passwd",
    });
    const degraded = firstItem();
    expect(degraded.conversationId).toBeUndefined();
    expect(buildResumeLaunchPlan(context, degraded)).toMatchObject({ precision: "picker" });
  });

  test("one classification pass spends a bounded probe budget and degrades to unverified when it runs out", () => {
    claudeEvidence();
    const item = firstItem();
    const context = runtimeContext();
    const records = Array.from({ length: 20 }, (_, index) => sessionRecord({
      sessionId: `rf-20260731-c${String(index).padStart(5, "0")}`,
      containerId: index.toString(16).padStart(64, "0"),
    }));
    let captures = 0;
    const io = {
      capture: (_command: string, args: string[]) => {
        captures += 1;
        if (args[0] === "inspect") return { status: 0, stdout: "true\t2026-07-31T00:00:30.000000000Z", stderr: "" };
        return { status: 2, stdout: "", stderr: "" };
      },
    } as unknown as RuntimeIO;

    const classified = classifyRecoveryItemLive(item, context, io, {
      activeSessions: [],
      sessionContainers: { records, unreadable: false },
    });

    // 20 candidates want 40 captures; the pass budget refuses the tail, and a
    // refused probe proves nothing — so the item is unverified, not guessed
    // interrupted from a partial sweep.
    expect(captures).toBe(32);
    expect(classified.state).toBe("unverified");
  });

  test("one pass inspects each candidate container once, however many items name it", () => {
    claudeEvidence();
    const secondRegistry = path.join(stateDir, "claude", "sessions", "4343.json");
    fs.writeFileSync(secondRegistry, `${JSON.stringify({
      pid: 4343,
      sessionId: "22222222-3333-4444-8555-666666666666",
      cwd: "/workspace",
      startedAt: Date.parse("2026-07-31T00:00:00.000Z"),
      procStart: "13579",
      updatedAt: Date.parse("2026-07-31T00:02:00.000Z"),
    })}\n`, { mode: 0o600 });
    const context = runtimeContext();
    const items = scanRecoveryInventory({ env }).items;
    expect(items).toHaveLength(2);
    let inspects = 0;
    const io = {
      capture: (_command: string, args: string[]) => {
        if (args[0] === "inspect") {
          inspects += 1;
          return { status: 0, stdout: "true\t2026-07-31T00:00:30.000000000Z", stderr: "" };
        }
        return { status: 2, stdout: "", stderr: "" };
      },
    } as unknown as RuntimeIO;
    const live = {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: false },
    };

    for (const item of items) classifyRecoveryItemLive(item, context, io, live);

    expect(inspects).toBe(1);
  });

  test("a codex session container is never a Claude probe candidate", () => {
    claudeEvidence();
    const codexRecord = sessionRecord({
      command: "codex",
      launchPath: "/usr/local/bin/codex",
      launchArgs: ["--dangerously-bypass-approvals-and-sandbox"],
    });
    const io = {
      capture: () => {
        throw new Error("no candidate container should be probed");
      },
    } as unknown as RuntimeIO;

    expect(classifyRecoveryItemLive(firstItem(), runtimeContext(), io, {
      activeSessions: [],
      sessionContainers: { records: [codexRecord], unreadable: false },
    }).state).toBe("interrupted");
  });

  test("the Claude picker is blocked by live and stale claude records and by a partial registry", () => {
    const context = runtimeContext();
    const stale = sessionRecord({ hostBootId: "linux:99999999-8888-7777-6666-555555555555" });

    expect(liveClaudeSessionBlocksPicker(context, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: false },
    })).toBe(true);
    expect(liveClaudeSessionBlocksPicker(context, {
      activeSessions: [],
      sessionContainers: { records: [], unreadable: true },
    })).toBe(true);
    // A dead host owner is not proof the container died with it: the ordinary
    // attached-crash residue is a stale record whose claude still runs, so by
    // default it blocks exactly like a live one.
    expect(liveClaudeSessionBlocksPicker(context, {
      activeSessions: [],
      sessionContainers: { records: [stale], unreadable: false },
    })).toBe(true);
    // Only a caller whose launch reclaims residue first may ignore stale
    // records — and even it must still be blocked by a live one.
    expect(liveClaudeSessionBlocksPicker(context, {
      activeSessions: [],
      sessionContainers: { records: [stale], unreadable: false },
    }, { staleRecordsReclaimedBeforeLaunch: true })).toBe(false);
    expect(liveClaudeSessionBlocksPicker(context, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: false },
    }, { staleRecordsReclaimedBeforeLaunch: true })).toBe(true);
    expect(liveClaudeSessionBlocksPicker(context, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord({ state: "revoking" })], unreadable: false },
    })).toBe(false);
  });

  test("a symlinked records root reads as an unprovable registry, not an empty one", () => {
    const context = runtimeContext();
    const runtimeV2 = path.join(stateDir, "runtime", "v2");
    fs.mkdirSync(runtimeV2, { recursive: true });
    const outside = path.join(tmp, "outside-records");
    fs.mkdirSync(outside, { recursive: true });
    fs.symlinkSync(outside, path.join(runtimeV2, "session-containers"), "dir");

    const inputs = sessionContainerRecoveryLiveInputs(context);

    expect(inputs.unreadable).toBe(true);
    expect(inputs.records).toEqual([]);
  });

  test("building the registry inputs is strictly read-only, even over an unreadable record", () => {
    const context = runtimeContext();
    const recordsRoot = path.join(stateDir, "runtime", "v2", "session-containers");
    fs.mkdirSync(recordsRoot, { recursive: true });
    const record = sessionRecord();
    fs.writeFileSync(path.join(recordsRoot, `${record.sessionId}.json`), `${JSON.stringify(record)}\n`);
    fs.writeFileSync(path.join(recordsRoot, "rf-20260731-zz9999.json"), "not json");

    const inputs = sessionContainerRecoveryLiveInputs(context);

    expect(inputs.unreadable).toBe(true);
    expect(inputs.records.map((entry) => entry.sessionId)).toEqual([record.sessionId]);
    // The corrupted record stays exactly where it was: no quarantine, no unlink.
    expect(fs.readFileSync(path.join(recordsRoot, "rf-20260731-zz9999.json"), "utf8")).toBe("not json");
    expect(fs.existsSync(path.join(stateDir, "runtime", "v2", "session-containers-quarantine"))).toBe(false);
  });
});

describe("transactional claims and evidence consumption", () => {
  test("only one selector can claim an item", async () => {
    hostEvidence(undefined, { outcome: "interrupted", exitStatus: 137, endedAt: "2026-07-31T00:02:00.000Z" });
    const item = firstItem();
    const context = runtimeContext();

    const first = await acquireRecoveryClaim(context, item);
    const second = await acquireRecoveryClaim(context, item);

    expect(first).toBeDefined();
    expect(second).toBeUndefined();
    expect(fs.existsSync(first?.path ?? "")).toBe(true);
    first?.release();
    expect(fs.existsSync(first?.path ?? "")).toBe(false);
  });

  test("a selector waiting on the lifecycle lock cannot claim Claude evidence consumed meanwhile", async () => {
    claudeEvidence();
    const item = firstItem();
    const context = runtimeContext();
    const held = tryAcquireProjectLifecycleLock(context);
    expect(held).toBeDefined();
    let actionCalls = 0;

    try {
      const waiting = runWithRecoveryClaim(context, item, () => {
        actionCalls += 1;
        return 0;
      });
      expect(consumeRecoveryEvidence(item)).toBe(true);
      held?.release();

      await expect(waiting).resolves.toBeUndefined();
      expect(actionCalls).toBe(0);
    } finally {
      held?.release();
    }
  });

  test("claims serialize within one conversation and stay concurrent across different conversations", async () => {
    // Per-conversation claim keys (section 4, H1): a host record and a Claude
    // record kept unjoined (different conversations here) claim
    // independently; only sharing one conversation's scope serializes them.
    const OTHER_SESSION = "22222222-3333-4333-8444-555555555555";
    hostEvidence(undefined, {
      recordVersion: 2,
      launchConversationId: OTHER_SESSION,
      outcome: "interrupted",
      exitStatus: 137,
      endedAt: "2026-07-31T00:02:00.000Z",
    });
    claudeEvidence();
    const items = scanRecoveryInventory({ env }).items;
    const host = items.find((item) => item.evidenceKind === "host");
    const registry = items.find((item) => item.evidenceKind === "claude");
    if (!host || !registry) throw new Error("missing paired recovery fixtures");
    expect(host.conversationId).toBe(OTHER_SESSION);
    expect(registry.conversationId).toBe(CLAUDE_SESSION);

    const hostClaim = await acquireRecoveryClaim(runtimeContext(), host);
    const registryClaim = await acquireRecoveryClaim(runtimeContext(), registry);
    expect(hostClaim).toBeDefined();
    expect(registryClaim).toBeDefined();
    hostClaim?.release();
    registryClaim?.release();

    // Hand-built to share one conversation's exact scope (same agent, same
    // conversation id) without going through the scan's own join, proving
    // the claim layer itself — not just the dedup — enforces one claim per
    // conversation.
    const sameConversationHost: RecoveryItem = { ...host, conversationId: registry.conversationId };
    const first = await acquireRecoveryClaim(runtimeContext(), sameConversationHost);
    expect(first).toBeDefined();
    expect(await acquireRecoveryClaim(runtimeContext(), registry)).toBeUndefined();
    first?.release();
    expect(await acquireRecoveryClaim(runtimeContext(), registry)).toBeDefined();
  });

  test("never unlinks evidence replaced after the claim", async () => {
    const evidencePath = hostEvidence(undefined, {
      outcome: "interrupted",
      exitStatus: 137,
      endedAt: "2026-07-31T00:02:00.000Z",
    });
    const item = firstItem();
    const claim = await acquireRecoveryClaim(runtimeContext(), item);
    const replacement = `${evidencePath}.replacement`;
    fs.writeFileSync(replacement, fs.readFileSync(evidencePath));
    fs.renameSync(replacement, evidencePath);

    expect(consumeRecoveryEvidence(item)).toBe(false);
    expect(fs.existsSync(evidencePath)).toBe(true);
    claim?.release();
  });

  test("failed and thrown resume actions release the claim but keep retryable evidence", async () => {
    const evidencePath = hostEvidence(undefined, {
      outcome: "interrupted",
      exitStatus: 137,
      endedAt: "2026-07-31T00:02:00.000Z",
    });
    const item = firstItem();
    const context = runtimeContext();
    // No failure marker (spec decision 6): the only thing a failed attempt
    // may leave behind, after the claim releases, is exactly what was there
    // before it — nothing written outside `recovery-claims/` (its own
    // emptiness is asserted separately below, so it is excluded here).
    const otherSessionEntries = () => fs.readdirSync(path.join(stateDir, "sessions"))
      .filter((name) => name !== "recovery-claims")
      .sort();
    const beforeSessions = otherSessionEntries();

    await expect(runWithRecoveryClaim(context, item, () => 17)).resolves.toEqual({ status: 17, consumed: false });
    expect(fs.existsSync(evidencePath)).toBe(true);
    expect(fs.readdirSync(path.join(stateDir, "sessions", "recovery-claims"))).toEqual([]);
    expect(otherSessionEntries()).toEqual(beforeSessions);

    await expect(runWithRecoveryClaim(context, item, () => {
      throw new Error("startup failed");
    })).rejects.toThrow("startup failed");
    expect(fs.existsSync(evidencePath)).toBe(true);
    expect(fs.readdirSync(path.join(stateDir, "sessions", "recovery-claims"))).toEqual([]);
    expect(otherSessionEntries()).toEqual(beforeSessions);

    // The next scan offers the same item again.
    expect(scanRecoveryInventory({ env }).items.map((candidate) => candidate.id)).toContain(item.id);
  });

  test("status zero consumes exactly the claimed evidence", async () => {
    const evidencePath = hostEvidence(undefined, {
      outcome: "interrupted",
      exitStatus: 137,
      endedAt: "2026-07-31T00:02:00.000Z",
    });
    const item = firstItem();

    await expect(runWithRecoveryClaim(runtimeContext(), item, () => 0)).resolves.toEqual({
      status: 0,
      consumed: true,
    });
    expect(fs.existsSync(evidencePath)).toBe(false);
  });

  test("Claude consumption leaves agent state untouched and hides only the exact fingerprint", async () => {
    const evidencePath = claudeEvidence();
    const item = firstItem();

    await expect(runWithRecoveryClaim(runtimeContext(), item, () => 0)).resolves.toEqual({
      status: 0,
      consumed: true,
    });
    expect(fs.existsSync(evidencePath)).toBe(true);
    expect(scanRecoveryInventory({ env }).items).toEqual([]);

    const replacement = JSON.parse(fs.readFileSync(evidencePath, "utf8"));
    replacement.name = "new registry generation";
    fs.writeFileSync(evidencePath, `${JSON.stringify(replacement)}\n`);
    expect(scanRecoveryInventory({ env }).items).toHaveLength(1);
  });

  test("an exact Claude recovery leaves older host-only fallback evidence non-actionable", async () => {
    hostEvidence(undefined, { outcome: "interrupted", exitStatus: 137, endedAt: "2026-07-31T00:02:00.000Z" });
    claudeEvidence();
    const exact = scanRecoveryInventory({ env }).items.find((item) => item.evidenceKind === "claude");
    if (!exact) throw new Error("missing exact Claude recovery fixture");
    await runWithRecoveryClaim(runtimeContext(), exact, () => 0);

    const host = scanRecoveryInventory({ env }).items.find((item) => item.evidenceKind === "host");
    if (!host) throw new Error("missing host recovery fixture");
    expect(classifyRecoveryItemLive(
      host,
      runtimeContext(),
      { capture: () => ({ status: 1, stdout: "", stderr: "" }) } as unknown as RuntimeIO,
      { activeSessions: [] },
    )).toMatchObject({ state: "unverified", reason: expect.stringContaining("exact Claude recovery") });
  });

  test("host evidence updated after the exact-recovery epoch remains actionable", async () => {
    claudeEvidence();
    const exact = firstItem();
    await runWithRecoveryClaim(runtimeContext(), exact, () => 0);
    hostEvidence("rf-20260731-overlap", {
      startedAt: "2026-07-31T00:00:00.000Z",
      lastSeenAt: "2026-07-31T00:01:00.000Z",
      outcome: "interrupted",
      exitStatus: 137,
      endedAt: "2100-07-31T00:02:00.000Z",
    });
    const host = firstItem();

    expect(classifyRecoveryItemLive(
      host,
      runtimeContext(),
      { capture: () => ({ status: 1, stdout: "", stderr: "" }) } as unknown as RuntimeIO,
      { activeSessions: [] },
    ).state).toBe("interrupted");
  });

  test("refuses recovery pointer publication without a selected effective control", () => {
    // Negative-before-side-effect: recovery state publication requires the
    // selected effective control's policy to validate first; with no selection
    // at all it must fail closed and write nothing.
    const context = runtimeContext();
    const pointerPath = path.join(stateDir, "project.json");
    fs.rmSync(pointerPath);

    expect(() => writeProjectRecoveryPointer(context)).toThrow("selected effective controls are required");
    expect(fs.existsSync(pointerPath)).toBe(false);
  });
});

describe("per-conversation claim scope (section 4, H1)", () => {
  test("two exact claims of different conversations stay concurrent", async () => {
    const CONVERSATION_A = CLAUDE_SESSION;
    const CONVERSATION_B = "22222222-3333-4333-8444-555555555555";
    hostEvidence("rf-20260731-aaaaaa", { recordVersion: 2, launchConversationId: CONVERSATION_A, outcome: "interrupted" });
    hostEvidence("rf-20260731-bbbbbb", { recordVersion: 2, launchConversationId: CONVERSATION_B, outcome: "interrupted" });
    const items = scanRecoveryInventory({ env }).items;
    const itemA = items.find((item) => item.conversationId === CONVERSATION_A);
    const itemB = items.find((item) => item.conversationId === CONVERSATION_B);
    if (!itemA || !itemB) throw new Error("missing fixtures");
    const context = runtimeContext();

    const claimA = await acquireRecoveryClaim(context, itemA);
    const claimB = await acquireRecoveryClaim(context, itemB);

    expect(claimA).toBeDefined();
    expect(claimB).toBeDefined();
    claimA?.release();
    claimB?.release();
  });

  test("two exact claims of the same conversation cannot both succeed, even built independently", async () => {
    const OTHER_SESSION = "33333333-4444-4333-8444-555555555555";
    hostEvidence(undefined, { recordVersion: 2, launchConversationId: OTHER_SESSION, outcome: "interrupted" });
    claudeEvidence(); // sessionId defaults to CLAUDE_SESSION; kept unjoined by the differing id above
    const items = scanRecoveryInventory({ env }).items;
    const host = items.find((item) => item.evidenceKind === "host");
    const registry = items.find((item) => item.evidenceKind === "claude");
    if (!host || !registry) throw new Error("missing fixtures");
    const context = runtimeContext();

    // Built by hand to share one conversation's exact scope, simulating the
    // case the scan's own join exists to prevent, so the claim layer itself
    // is proven to enforce it too.
    const itemA: RecoveryItem = { ...host, conversationId: registry.conversationId };
    const itemB = registry;
    const action = vi.fn().mockResolvedValue(0);

    const claimA = await acquireRecoveryClaim(context, itemA);
    expect(claimA).toBeDefined();

    const second = await runWithRecoveryClaim(context, itemB, action);

    expect(second).toBeUndefined();
    expect(action).not.toHaveBeenCalled();
    expect(fs.readdirSync(path.join(stateDir, "sessions", "recovery-claims"))).toHaveLength(1);
    claimA?.release();
  });

  test("a picker claim and an exact claim of the same agent block each other; another agent's exact claim is unaffected", async () => {
    claudeEvidence(); // exact scope: agent claude, conversationId CLAUDE_SESSION
    hostEvidence("rf-20260731-picker", { outcome: "interrupted" }); // picker scope: agent claude, no conversation id
    hostEvidence("rf-20260731-piexact", {
      command: "pi",
      recordVersion: 2,
      launchConversationId: CLAUDE_SESSION,
      outcome: "interrupted",
    });
    const items = scanRecoveryInventory({ env }).items;
    const exactClaude = items.find((item) => item.evidenceKind === "claude");
    const pickerClaude = items.find((item) => item.sourceId === "rf-20260731-picker");
    const exactPi = items.find((item) => item.sourceId === "rf-20260731-piexact");
    if (!exactClaude || !pickerClaude || !exactPi) throw new Error("missing fixtures");
    const context = runtimeContext();

    const exactClaim = await acquireRecoveryClaim(context, exactClaude);
    expect(exactClaim).toBeDefined();
    expect(await acquireRecoveryClaim(context, pickerClaude)).toBeUndefined();
    const piClaim = await acquireRecoveryClaim(context, exactPi);
    expect(piClaim).toBeDefined();
    piClaim?.release();
    exactClaim?.release();

    const pickerClaim = await acquireRecoveryClaim(context, pickerClaude);
    expect(pickerClaim).toBeDefined();
    expect(await acquireRecoveryClaim(context, exactClaude)).toBeUndefined();
    pickerClaim?.release();
  });
});

describe("stuck-claim reclaim (section 4, review F2, decision 9)", () => {
  test("a dead-pid claim is reclaimed and replaced", async () => {
    hostEvidence(undefined, { outcome: "interrupted" });
    const item = firstItem();
    const context = runtimeContext();
    writeClaimFile(item, { ownerPid: DEAD_PID });

    const claim = await acquireRecoveryClaim(context, item);

    expect(claim).toBeDefined();
    claim?.release();
  });

  test("a claim whose hostBootId differs from the current boot is reclaimed", async () => {
    hostEvidence(undefined, { outcome: "interrupted" });
    const item = firstItem();
    const context = runtimeContext();
    writeClaimFile(item, { hostBootId: "linux:99999999-8888-7777-6666-555555555555" });

    const claim = await acquireRecoveryClaim(context, item);

    expect(claim).toBeDefined();
    claim?.release();
  });

  test("a live pid with no boot or process-start identity is unprovable, not live, and hides only that item", () => {
    hostEvidence(undefined, { outcome: "interrupted" });
    const item = firstItem();
    writeClaimFile(item, { ownerPid: process.pid, hostBootId: undefined, hostProcessStart: undefined });

    const inventory = scanRecoveryInventory({ env });
    const scanned = inventory.items.find((candidate) => candidate.id === item.id);

    expect(scanned?.claimUnprovable).toBe("a recovery claim's owner could not be proved alive or dead");
    expect(scanned?.state).not.toBe("claimed");
  });

  test("an unprovable claim refuses a fresh claim of the same scope until it ages out", async () => {
    hostEvidence(undefined, { outcome: "interrupted" });
    const item = firstItem();
    const context = runtimeContext();
    const createdAt = new Date("2026-08-01T00:00:00.000Z");
    writeClaimFile(item, {
      ownerPid: process.pid,
      hostBootId: undefined,
      hostProcessStart: undefined,
      createdAt: createdAt.toISOString(),
    });

    const almostExpired = new Date(createdAt.getTime() + UNPROVABLE_CLAIM_MAX_AGE_MS - 60_000);
    expect(await acquireRecoveryClaim(context, item, almostExpired)).toBeUndefined();

    const expired = new Date(createdAt.getTime() + UNPROVABLE_CLAIM_MAX_AGE_MS + 60_000);
    const claim = await acquireRecoveryClaim(context, item, expired);
    expect(claim).toBeDefined();
    claim?.release();
  });

  test("a malformed claim file uses its mtime for the same age boundary", async () => {
    hostEvidence(undefined, { outcome: "interrupted" });
    const item = firstItem();
    const context = runtimeContext();
    const scope = recoveryClaimScope(item);
    fs.mkdirSync(path.dirname(scope.path), { recursive: true, mode: 0o700 });
    fs.writeFileSync(scope.path, "not valid json {{{", { mode: 0o600 });
    const mtime = new Date("2026-08-01T00:00:00.000Z");
    fs.utimesSync(scope.path, mtime, mtime);

    const almostExpired = new Date(mtime.getTime() + UNPROVABLE_CLAIM_MAX_AGE_MS - 60_000);
    expect(await acquireRecoveryClaim(context, item, almostExpired)).toBeUndefined();

    const expired = new Date(mtime.getTime() + UNPROVABLE_CLAIM_MAX_AGE_MS + 60_000);
    const claim = await acquireRecoveryClaim(context, item, expired);
    expect(claim).toBeDefined();
    claim?.release();
  });

  test("malformed claim JSON younger than the age limit is unprovable and hides only that row", () => {
    hostEvidence(undefined, { outcome: "interrupted" });
    const item = firstItem();
    const scope = recoveryClaimScope(item);
    fs.mkdirSync(path.dirname(scope.path), { recursive: true, mode: 0o700 });
    fs.writeFileSync(scope.path, "not valid json {{{", { mode: 0o600 });

    const inventory = scanRecoveryInventory({ env });
    const scanned = inventory.items.find((candidate) => candidate.id === item.id);

    expect(scanned?.claimUnprovable).toBe("a recovery claim's owner could not be proved alive or dead");
    expect(scanned?.state).not.toBe("claimed");
  });

  test("a 0-byte claim file (interrupted mid-write) is unprovable and hides only that row", () => {
    // `safeReadBytes` refuses an empty file outright — exactly what a crash
    // between the claim's direct `wx` open and its write leaves — so this
    // exercises the `malformedStat` branch of `claimFileLiveness`, not the
    // content-fingerprint one. Real (fresh) mtime: the scan has no injected
    // clock, so age boundary cases are covered separately below through
    // `acquireRecoveryClaim`'s injected `now`.
    hostEvidence(undefined, { outcome: "interrupted" });
    const item = firstItem();
    const scope = recoveryClaimScope(item);
    fs.mkdirSync(path.dirname(scope.path), { recursive: true, mode: 0o700 });
    fs.writeFileSync(scope.path, "", { mode: 0o600 });

    const scanned = scanRecoveryInventory({ env }).items.find((candidate) => candidate.id === item.id);

    expect(scanned?.claimUnprovable).toBe("a recovery claim's owner could not be proved alive or dead");
    expect(scanned?.state).not.toBe("claimed");
  });

  test("a 0-byte claim file uses its mtime for the 24h age boundary, then is reclaimed by stat match", async () => {
    hostEvidence(undefined, { outcome: "interrupted" });
    const item = firstItem();
    const context = runtimeContext();
    const scope = recoveryClaimScope(item);
    fs.mkdirSync(path.dirname(scope.path), { recursive: true, mode: 0o700 });
    fs.writeFileSync(scope.path, "", { mode: 0o600 });
    const mtime = new Date("2026-08-01T00:00:00.000Z");
    fs.utimesSync(scope.path, mtime, mtime);

    const almostExpired = new Date(mtime.getTime() + UNPROVABLE_CLAIM_MAX_AGE_MS - 60_000);
    expect(await acquireRecoveryClaim(context, item, almostExpired)).toBeUndefined();

    const expired = new Date(mtime.getTime() + UNPROVABLE_CLAIM_MAX_AGE_MS + 60_000);
    const claim = await acquireRecoveryClaim(context, item, expired);
    expect(claim).toBeDefined();
    const written = JSON.parse(fs.readFileSync(scope.path, "utf8"));
    expect(written.ownerPid).toBe(process.pid);
    expect(written.createdAt).toBe(expired.toISOString());
    claim?.release();
  });
});

describe("unprovable claims block only their own scope (review F2)", () => {
  test("an unprovable picker claim does not block an exact claim of the same agent", async () => {
    claudeEvidence();
    hostEvidence(undefined, { outcome: "interrupted" });
    const items = scanRecoveryInventory({ env }).items;
    const exact = items.find((item) => item.evidenceKind === "claude");
    const picker = items.find((item) => item.evidenceKind === "host");
    if (!exact || !picker) throw new Error("missing fixtures");
    const context = runtimeContext();
    writeClaimFile(picker, { ownerPid: process.pid, hostBootId: undefined, hostProcessStart: undefined });

    const claim = await acquireRecoveryClaim(context, exact);

    expect(claim).toBeDefined();
    claim?.release();
  });

  test("an unprovable exact claim does not block the picker claim or another conversation's exact claim", async () => {
    claudeEvidence({ sessionId: CLAUDE_SESSION });
    const exactA = firstItem();
    hostEvidence("rf-20260731-picker", { outcome: "interrupted" });
    const OTHER_SESSION = "44444444-5555-4333-8444-555555555555";
    hostEvidence("rf-20260731-exactb", { recordVersion: 2, launchConversationId: OTHER_SESSION, outcome: "interrupted" });
    const items = scanRecoveryInventory({ env }).items;
    const picker = items.find((item) => item.sourceId === "rf-20260731-picker");
    const exactB = items.find((item) => item.sourceId === "rf-20260731-exactb");
    if (!picker || !exactB) throw new Error("missing fixtures");
    const context = runtimeContext();
    writeClaimFile(exactA, { ownerPid: process.pid, hostBootId: undefined, hostProcessStart: undefined });

    const pickerClaim = await acquireRecoveryClaim(context, picker);
    expect(pickerClaim).toBeDefined();
    pickerClaim?.release();

    const exactBClaim = await acquireRecoveryClaim(context, exactB);
    expect(exactBClaim).toBeDefined();
    exactBClaim?.release();
  });
});

describe("linked consumption and dismiss (section 5)", () => {
  test("a status-zero resume of a joined item deletes the host record and consumes the linked Claude id, never the epoch", async () => {
    claudeEvidence({ sessionId: CLAUDE_SESSION });
    const hostPath = hostEvidence(undefined, { recordVersion: 2, launchConversationId: CLAUDE_SESSION, outcome: "interrupted" });
    const item = firstItem();
    const linkedId = item.linkedClaude?.[0]?.id;
    if (!linkedId) throw new Error("missing linked claude fixture");

    await expect(runWithRecoveryClaim(runtimeContext(), item, () => 0)).resolves.toEqual({ status: 0, consumed: true });

    expect(fs.existsSync(hostPath)).toBe(false);
    expect(fs.existsSync(path.join(stateDir, "sessions", "recovery-consumed", `${linkedId}.json`))).toBe(true);
    expect(fs.existsSync(path.join(stateDir, "sessions", "recovery-consumed", "agent-claude.json"))).toBe(false);
  });

  test("dismiss deletes the host record and consumes every linked Claude id", async () => {
    const claudePath = claudeEvidence({ sessionId: CLAUDE_SESSION });
    const hostPath = hostEvidence(undefined, { recordVersion: 2, launchConversationId: CLAUDE_SESSION, outcome: "interrupted" });
    const item = firstItem();
    const linkedId = item.linkedClaude?.[0]?.id;
    if (!linkedId) throw new Error("missing linked claude fixture");

    const result = await dismissRecoveryItem(runtimeContext(), item);

    expect(result).toBe("dismissed");
    expect(fs.existsSync(hostPath)).toBe(false);
    // The agent-writable registry file itself is never unlinked, only marked
    // consumed by fingerprint.
    expect(fs.existsSync(claudePath)).toBe(true);
    expect(fs.existsSync(path.join(stateDir, "sessions", "recovery-consumed", `${linkedId}.json`))).toBe(true);
    expect(fs.existsSync(path.join(stateDir, "sessions", "recovery-consumed", "agent-claude.json"))).toBe(false);
  });

  test("dismiss returns 'claimed' and deletes nothing while another claim on the same scope is live", async () => {
    hostEvidence(undefined, { outcome: "interrupted" });
    const item = firstItem();
    const context = runtimeContext();
    const claim = await acquireRecoveryClaim(context, item);
    expect(claim).toBeDefined();

    const result = await dismissRecoveryItem(context, item);

    expect(result).toBe("claimed");
    expect(fs.existsSync(item.evidencePath)).toBe(true);
    claim?.release();
  });

  test("dismiss returns 'changed' when the evidence changed after the scan", async () => {
    const evidencePath = hostEvidence(undefined, { outcome: "interrupted" });
    const item = firstItem();
    const replacement = JSON.parse(fs.readFileSync(evidencePath, "utf8"));
    replacement.lastSeenAt = "2026-07-31T00:09:00.000Z";
    fs.writeFileSync(evidencePath, `${JSON.stringify(replacement)}\n`);

    const result = await dismissRecoveryItem(runtimeContext(), item);

    expect(result).toBe("changed");
    expect(fs.existsSync(evidencePath)).toBe(true);
  });

  test("dismiss returns 'deferred', not 'claimed', when the lifecycle lock cannot be taken (review F9)", async () => {
    hostEvidence(undefined, { outcome: "interrupted" });
    const item = firstItem();
    const context = runtimeContext();
    const held = tryAcquireProjectLifecycleLock(context);
    expect(held).toBeDefined();

    try {
      const result = await dismissRecoveryItem(context, item, { lifecycleLockRetry: { attempts: 2, delayMs: 5 } });

      expect(result).toBe("deferred");
      expect(fs.existsSync(item.evidencePath)).toBe(true);
    } finally {
      held?.release();
    }
  });

  test("dismiss returns 'claimed' and deletes nothing when its own-scope claim is unprovable", async () => {
    hostEvidence(undefined, { outcome: "interrupted" });
    const item = firstItem();
    writeClaimFile(item, { ownerPid: process.pid, hostBootId: undefined, hostProcessStart: undefined });

    const result = await dismissRecoveryItem(runtimeContext(), item);

    expect(result).toBe("claimed");
    expect(fs.existsSync(item.evidencePath)).toBe(true);
  });

  test("dismiss returns 'claimed' and deletes nothing when a live cross-scope (exact) claim exists", async () => {
    claudeEvidence(); // exact scope: agent claude, conversationId CLAUDE_SESSION
    hostEvidence(undefined, { outcome: "interrupted" }); // picker scope, same agent
    const items = scanRecoveryInventory({ env }).items;
    const exact = items.find((candidate) => candidate.evidenceKind === "claude");
    const picker = items.find((candidate) => candidate.evidenceKind === "host");
    if (!exact || !picker) throw new Error("missing fixtures");
    const context = runtimeContext();
    const exactClaim = await acquireRecoveryClaim(context, exact);
    expect(exactClaim).toBeDefined();

    const result = await dismissRecoveryItem(context, picker);

    expect(result).toBe("claimed");
    expect(fs.existsSync(picker.evidencePath)).toBe(true);
    exactClaim?.release();
  });

  test("linked consumption with one entry whose fingerprint no longer matches consumes the primary and the matching entry, leaving the other alone", async () => {
    const MATCHING_SESSION = CLAUDE_SESSION;
    const STALE_SESSION = "55555555-6666-4333-8444-555555555555";
    claudeEvidence({ sessionId: MATCHING_SESSION }, 4242);
    const staleEvidencePath = claudeEvidence({ sessionId: STALE_SESSION }, 4343);
    hostEvidence(undefined, { recordVersion: 2, launchConversationId: "66666666-7777-4333-8444-555555555555", outcome: "interrupted" });
    const items = scanRecoveryInventory({ env }).items;
    const host = items.find((candidate) => candidate.evidenceKind === "host");
    const matchingClaude = items.find((candidate) => candidate.conversationId === MATCHING_SESSION);
    const staleClaude = items.find((candidate) => candidate.conversationId === STALE_SESSION);
    if (!host || !matchingClaude || !staleClaude) throw new Error("missing fixtures");
    expect(matchingClaude.id).not.toBe(staleClaude.id);

    // Hand-built link list: two distinct linked ids, one of which (`stale`)
    // will no longer match its on-disk fingerprint by the time consumption
    // runs.
    const joinedItem: RecoveryItem = {
      ...host,
      linkedClaude: [
        { id: matchingClaude.id, evidencePath: matchingClaude.evidencePath, fingerprint: matchingClaude.fingerprint },
        { id: staleClaude.id, evidencePath: staleClaude.evidencePath, fingerprint: staleClaude.fingerprint },
      ],
    };
    const staleContent = JSON.parse(fs.readFileSync(staleEvidencePath, "utf8"));
    staleContent.name = "changed after join";
    fs.writeFileSync(staleEvidencePath, `${JSON.stringify(staleContent)}\n`);

    await expect(runWithRecoveryClaim(runtimeContext(), joinedItem, () => 0)).resolves.toEqual({ status: 0, consumed: true });

    expect(fs.existsSync(host.evidencePath)).toBe(false);
    expect(fs.existsSync(path.join(stateDir, "sessions", "recovery-consumed", `${matchingClaude.id}.json`))).toBe(true);
    expect(fs.existsSync(path.join(stateDir, "sessions", "recovery-consumed", `${staleClaude.id}.json`))).toBe(false);
  });
});

describe("claim writer identity (controller ruling, fix round 1)", () => {
  test("refuses to write a claim when its own boot id or process start cannot be read", async () => {
    hostEvidence(undefined, { outcome: "interrupted" });
    const item = firstItem();
    // Non-empty but invalid overrides return `undefined` directly from
    // `hostBootId`/`hostProcessStart` (host-identity.ts) without falling
    // through to a real platform probe, so this is deterministic regardless
    // of what boot id or process start this host actually has.
    env.RUNFREE_TEST_HOST_BOOT_ID = "not-a-boot-id";
    env.RUNFREE_TEST_HOST_PROCESS_START = "not-a-start-time";
    const context = runtimeContext();

    await expect(acquireRecoveryClaim(context, item)).rejects.toThrow(/boot id or start time/);
    expect(fs.existsSync(path.join(stateDir, "sessions", "recovery-claims"))).toBe(false);
  });

  test("runWithRecoveryClaim's action is never called when the writer's identity cannot be read", async () => {
    hostEvidence(undefined, { outcome: "interrupted" });
    const item = firstItem();
    env.RUNFREE_TEST_HOST_BOOT_ID = "not-a-boot-id";
    env.RUNFREE_TEST_HOST_PROCESS_START = "not-a-start-time";
    const context = runtimeContext();
    const action = vi.fn().mockResolvedValue(0);

    await expect(runWithRecoveryClaim(context, item, action)).rejects.toThrow(/boot id or start time/);
    expect(action).not.toHaveBeenCalled();
    expect(fs.existsSync(item.evidencePath)).toBe(true);
  });
});

describe("cross-scope listing fails closed (review F2, availability)", () => {
  test("a truncated exact-claim listing refuses a picker claim and reports it claimed, not free", async () => {
    hostEvidence(undefined, { outcome: "interrupted" }); // picker item, agent claude
    const item = firstItem();
    const context = runtimeContext();
    const pickerScope = recoveryClaimScope(item);
    const agentScopeMatch = /agent-([0-9a-f]{24})\.json$/.exec(pickerScope.path);
    if (!agentScopeMatch?.[1]) throw new Error("unexpected picker scope path");
    const agentScope = agentScopeMatch[1];
    const claimsDir = path.dirname(pickerScope.path);
    fs.mkdirSync(claimsDir, { recursive: true, mode: 0o700 });

    // A live exact claim, deliberately the *older* of two candidates so a
    // files-per-kind cap of 1 scans the other one first and truncates this
    // one away — proving the listing itself, not just its presence, is what
    // must fail closed.
    const liveConvPath = path.join(claimsDir, `conv-${agentScope}-${"a".repeat(24)}.json`);
    fs.writeFileSync(liveConvPath, `${JSON.stringify({
      v: 1,
      recoveryId: `rfr-${"a".repeat(24)}`,
      action: "resume",
      ownerPid: process.pid,
      hostBootId: BOOT,
      hostProcessStart: PROCESS_START,
      createdAt: new Date().toISOString(),
      evidence: item.fingerprint,
    })}\n`, { mode: 0o600 });
    const olderStamp = new Date("2026-01-01T00:00:00.000Z");
    fs.utimesSync(liveConvPath, olderStamp, olderStamp);

    const deadConvPath = path.join(claimsDir, `conv-${agentScope}-${"b".repeat(24)}.json`);
    fs.writeFileSync(deadConvPath, `${JSON.stringify({
      v: 1,
      recoveryId: `rfr-${"b".repeat(24)}`,
      action: "resume",
      ownerPid: DEAD_PID,
      hostBootId: BOOT,
      hostProcessStart: PROCESS_START,
      createdAt: new Date().toISOString(),
      evidence: item.fingerprint,
    })}\n`, { mode: 0o600 });

    const originalLimit = RECOVERY_LIMITS.maxFilesPerKindPerProject;
    Object.assign(RECOVERY_LIMITS, { maxFilesPerKindPerProject: 1 });
    try {
      const claim = await acquireRecoveryClaim(context, item);
      expect(claim).toBeUndefined();

      const scanned = scanRecoveryInventory({ env }).items.find((candidate) => candidate.id === item.id);
      expect(scanned?.state).toBe("claimed");
    } finally {
      Object.assign(RECOVERY_LIMITS, { maxFilesPerKindPerProject: originalLimit });
    }
  });

  test("a claims directory replaced by a symlink is unverifiable and refuses a picker claim", async () => {
    hostEvidence(undefined, { outcome: "interrupted" });
    const item = firstItem();
    const context = runtimeContext();
    const claimsDir = path.dirname(recoveryClaimScope(item).path);
    const outside = path.join(tmp, "outside-claims");
    fs.mkdirSync(outside, { recursive: true });
    fs.mkdirSync(path.dirname(claimsDir), { recursive: true });
    fs.symlinkSync(outside, claimsDir, "dir");

    expect(await acquireRecoveryClaim(context, item)).toBeUndefined();
  });
});

describe("dead-claim sweep (AGENTS.md: every fail-closed refusal ships its reclaim path)", () => {
  test("3 dead conv claims of the agent are removed by the next picker claim, which then succeeds", async () => {
    const CONVERSATION_A = CLAUDE_SESSION;
    const CONVERSATION_B = "22222222-3333-4333-8444-555555555555";
    const CONVERSATION_C = "33333333-4444-4333-8444-555555555555";
    hostEvidence("rf-20260731-aaaaaa", { recordVersion: 2, launchConversationId: CONVERSATION_A, outcome: "interrupted" });
    hostEvidence("rf-20260731-bbbbbb", { recordVersion: 2, launchConversationId: CONVERSATION_B, outcome: "interrupted" });
    hostEvidence("rf-20260731-cccccc", { recordVersion: 2, launchConversationId: CONVERSATION_C, outcome: "interrupted" });
    hostEvidence("rf-20260731-picker", { outcome: "interrupted" });
    const items = scanRecoveryInventory({ env }).items;
    const itemA = items.find((item) => item.conversationId === CONVERSATION_A);
    const itemB = items.find((item) => item.conversationId === CONVERSATION_B);
    const itemC = items.find((item) => item.conversationId === CONVERSATION_C);
    const picker = items.find((item) => item.sourceId === "rf-20260731-picker");
    if (!itemA || !itemB || !itemC || !picker) throw new Error("missing fixtures");
    // Dead: a pid above any real pid_max, written directly at each exact
    // scope's own claim path, bypassing `acquireRecoveryClaim`.
    const pathA = writeClaimFile(itemA, { ownerPid: DEAD_PID });
    const pathB = writeClaimFile(itemB, { ownerPid: DEAD_PID });
    const pathC = writeClaimFile(itemC, { ownerPid: DEAD_PID });
    const context = runtimeContext();

    const claim = await acquireRecoveryClaim(context, picker);

    expect(claim).toBeDefined();
    expect(fs.existsSync(pathA)).toBe(false);
    expect(fs.existsSync(pathB)).toBe(false);
    expect(fs.existsSync(pathC)).toBe(false);
    claim?.release();
  });

  test("a live conv claim is not removed by the sweep and still blocks the picker", async () => {
    hostEvidence("rf-20260731-exactxx", { recordVersion: 2, launchConversationId: CLAUDE_SESSION, outcome: "interrupted" });
    hostEvidence("rf-20260731-picker", { outcome: "interrupted" });
    const items = scanRecoveryInventory({ env }).items;
    const exact = items.find((item) => item.conversationId === CLAUDE_SESSION);
    const picker = items.find((item) => item.sourceId === "rf-20260731-picker");
    if (!exact || !picker) throw new Error("missing fixtures");
    const context = runtimeContext();
    const exactClaim = await acquireRecoveryClaim(context, exact);
    expect(exactClaim).toBeDefined();
    const exactClaimPath = recoveryClaimScope(exact).path;

    const pickerClaim = await acquireRecoveryClaim(context, picker);

    expect(pickerClaim).toBeUndefined();
    expect(fs.existsSync(exactClaimPath)).toBe(true);
    exactClaim?.release();
  });

  test("a dead claim of another agent is untouched by this agent's sweep", async () => {
    const OTHER_SESSION = "44444444-5555-4333-8444-555555555555";
    hostEvidence("rf-20260731-piexactxx", {
      command: "pi",
      recordVersion: 2,
      launchConversationId: OTHER_SESSION,
      outcome: "interrupted",
    });
    hostEvidence("rf-20260731-picker", { outcome: "interrupted" }); // agent claude
    const items = scanRecoveryInventory({ env }).items;
    const piItem = items.find((item) => item.agent === "pi");
    const picker = items.find((item) => item.sourceId === "rf-20260731-picker");
    if (!piItem || !picker) throw new Error("missing fixtures");
    const piClaimPath = writeClaimFile(piItem, { ownerPid: DEAD_PID });
    const context = runtimeContext();

    const claim = await acquireRecoveryClaim(context, picker);

    expect(claim).toBeDefined();
    expect(fs.existsSync(piClaimPath)).toBe(true);
    claim?.release();
  });
});

function writeCodexIndex(rows: readonly Readonly<{ id: string; thread_name: string }>[]): void {
  const dir = path.join(stateDir, "codex");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "session_index.jsonl"), `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`);
}

describe("Codex C1 time-match rows (scanRecoveryInventory)", () => {
  const CODEX_UUID = "01a0692c-7f74-7750-ad42-fb36200a005e";

  test("includeCodexMatches adds a codex-match row for a thread inside the host record's window, named from the Codex index", () => {
    hostEvidence("rf-20260731-cdx001", {
      command: "codex",
      recordVersion: 2,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:00:00.000Z",
      endedAt: "2026-07-31T00:10:00.000Z",
    });
    codexRollout("2026/07/31", CODEX_UUID, "2026-07-31T00:05:00.000Z");
    writeCodexIndex([{ id: CODEX_UUID, thread_name: "fix the picker" }]);

    const inventory = scanRecoveryInventory({ env, projectRoot, includeCodexMatches: true });
    const hostRow = inventory.items.find(
      (item) => item.sourceId === "rf-20260731-cdx001" && item.conversationSource !== "codex-match",
    );
    const matchRow = inventory.items.find((item) => item.conversationSource === "codex-match");
    if (!hostRow || !matchRow) throw new Error("missing fixtures");

    expect(matchRow.conversationId).toBe(CODEX_UUID);
    expect(matchRow.conversationName).toBe("fix the picker");
    expect(matchRow.conversationNameSource).toBe("codex-index");
    expect(matchRow.codexMatchTabs).toBe(1);
    expect(matchRow.codexMatchOf).toBe(hostRow.id);
    expect(matchRow.id).not.toBe(hostRow.id);
    // Resuming the match row consumes the *same* host evidence — same
    // evidence path and fingerprint — never a Codex file of its own.
    expect(matchRow.evidencePath).toBe(hostRow.evidencePath);
    expect(matchRow.fingerprint).toEqual(hostRow.fingerprint);
    // A time match is never the one question's default (decision 4).
    expect(matchRow.conversationSource).not.toBe("host-chosen");
  });

  test("a thread with no name in the Codex index gets a codex-match row with no conversationName", () => {
    hostEvidence("rf-20260731-cdx000", {
      command: "codex",
      recordVersion: 2,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:00:00.000Z",
      endedAt: "2026-07-31T00:10:00.000Z",
    });
    codexRollout("2026/07/31", CODEX_UUID, "2026-07-31T00:05:00.000Z");

    const inventory = scanRecoveryInventory({ env, projectRoot, includeCodexMatches: true });
    const matchRow = inventory.items.find((item) => item.conversationSource === "codex-match");

    expect(matchRow?.conversationName).toBeUndefined();
    expect(matchRow?.conversationNameSource).toBeUndefined();
  });

  test("a thread inside two host records' windows gives both a match row, each stamped matches 2 tabs", () => {
    hostEvidence("rf-20260731-cdx010", {
      command: "codex",
      recordVersion: 2,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:00:00.000Z",
      endedAt: "2026-07-31T00:30:00.000Z",
    });
    hostEvidence("rf-20260731-cdx011", {
      command: "codex",
      recordVersion: 2,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:05:00.000Z",
      endedAt: "2026-07-31T00:40:00.000Z",
    });
    codexRollout("2026/07/31", CODEX_UUID, "2026-07-31T00:10:00.000Z");

    const inventory = scanRecoveryInventory({ env, projectRoot, includeCodexMatches: true });
    const matches = inventory.items.filter((item) => item.conversationSource === "codex-match");

    expect(matches).toHaveLength(2);
    expect(matches.every((item) => item.codexMatchTabs === 2)).toBe(true);
    expect(new Set(matches.map((item) => item.codexMatchOf)).size).toBe(2);
  });

  test("a thread also inside a *second* record's window still counts toward tabs even when that second record's own scan is incomplete (round-1 finding 1a)", () => {
    // A: a narrow window; its own scan completes normally and gets a row.
    hostEvidence("rf-20260731-cdxaaa", {
      command: "codex",
      recordVersion: 2,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:00:00.000Z",
      endedAt: "2026-07-31T00:10:00.000Z",
    });
    // B: the same thread's timestamp also falls inside B's own window, but
    // B's window is deliberately so wide (70+ days) that `candidateDayStarts`
    // hits its own `maxDateDirs` cap and reports `complete: false` for B's
    // call — cheaply, with no filesystem cost, purely from the day-count
    // arithmetic. B must still count toward the shared thread's tab total
    // even though B itself never gets a row.
    hostEvidence("rf-20260731-cdxbbb", {
      command: "codex",
      recordVersion: 2,
      outcome: "interrupted",
      startedAt: "2026-05-22T00:00:00.000Z",
      endedAt: "2026-07-31T00:10:00.000Z",
    });
    codexRollout("2026/07/31", CODEX_UUID, "2026-07-31T00:05:00.000Z");

    const inventory = scanRecoveryInventory({ env, projectRoot, includeCodexMatches: true });
    const matches = inventory.items.filter((item) => item.conversationSource === "codex-match");
    const hostA = inventory.items.find((item) => item.sourceId === "rf-20260731-cdxaaa" && item.conversationSource !== "codex-match");
    const hostB = inventory.items.find((item) => item.sourceId === "rf-20260731-cdxbbb" && item.conversationSource !== "codex-match");

    // Only A gets a row (B's own scan never completed), but it is correctly
    // marked ambiguous: the same thread also sits inside B's window.
    expect(matches).toHaveLength(1);
    expect(matches[0]?.codexMatchOf).toBe(hostA?.id);
    expect(matches[0]?.codexMatchTabs).toBe(2);
    expect(matches.some((item) => item.codexMatchOf === hostB?.id)).toBe(false);
  });

  test("an active record's window overlapping a guessed thread marks it ambiguous even though the active record never gets a row (round-1 finding 1b)", () => {
    // D: dead, narrow window; gets the row.
    hostEvidence("rf-20260731-cdxddd", {
      command: "codex",
      recordVersion: 2,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:00:00.000Z",
      endedAt: "2026-07-31T00:10:00.000Z",
    });
    // L: a live (active) Codex record whose own lease window also covers
    // the same thread's timestamp. No `endedAt` yet (still running), so its
    // window end comes from the lifecycle record's `leaseExpiresAt`.
    hostEvidence("rf-20260731-cdxlll", {
      command: "codex",
      recordVersion: 2,
      startedAt: "2026-07-31T00:00:00.000Z",
    });
    const recordsRoot = path.join(stateDir, "runtime", "v2", "session-containers");
    fs.mkdirSync(recordsRoot, { recursive: true });
    const liveRecord = sessionRecord({
      sessionId: "rf-20260731-cdxlll",
      command: "codex",
      launchPath: "/usr/local/bin/codex",
      leaseExpiresAt: "2026-07-31T00:20:00.000Z",
    });
    fs.writeFileSync(path.join(recordsRoot, `${liveRecord.sessionId}.json`), `${JSON.stringify(liveRecord)}\n`);
    codexRollout("2026/07/31", CODEX_UUID, "2026-07-31T00:05:00.000Z");

    const inventory = scanRecoveryInventory({ env, projectRoot, includeCodexMatches: true });
    const matches = inventory.items.filter((item) => item.conversationSource === "codex-match");
    const hostD = inventory.items.find((item) => item.sourceId === "rf-20260731-cdxddd" && item.conversationSource !== "codex-match");
    const hostL = inventory.items.find((item) => item.sourceId === "rf-20260731-cdxlll" && item.conversationSource !== "codex-match");
    expect(hostL?.ownerState).toBe("active");

    expect(matches).toHaveLength(1);
    expect(matches[0]?.codexMatchOf).toBe(hostD?.id);
    expect(matches[0]?.codexMatchTabs).toBe(2);
  });

  test("a host item that already has an exact conversationId (e.g. resume-lineage) never gets a guessed row, but still counts toward another row's tabs (minor: skip exact-id items)", () => {
    // E: dead, narrow window, no exact id of its own; gets the guessed row.
    hostEvidence("rf-20260731-cdxeee", {
      command: "codex",
      recordVersion: 2,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:00:00.000Z",
      endedAt: "2026-07-31T00:10:00.000Z",
    });
    // X: already names its own exact conversation (resume-lineage) and also
    // overlaps the same thread's timestamp. It must never get a *second*,
    // guessed row for a thread it did not itself claim.
    const exactConversationId = "99999999-8888-4333-8444-555555555555";
    hostEvidence("rf-20260731-cdxxxx", {
      command: "codex",
      recordVersion: 2,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:00:00.000Z",
      endedAt: "2026-07-31T00:30:00.000Z",
      resumeConversationId: exactConversationId,
    });
    codexRollout("2026/07/31", CODEX_UUID, "2026-07-31T00:05:00.000Z");

    const inventory = scanRecoveryInventory({ env, projectRoot, includeCodexMatches: true });
    const matches = inventory.items.filter((item) => item.conversationSource === "codex-match");
    const hostE = inventory.items.find((item) => item.sourceId === "rf-20260731-cdxeee" && item.conversationSource !== "codex-match");
    const hostX = inventory.items.find((item) => item.sourceId === "rf-20260731-cdxxxx");
    expect(hostX?.conversationId).toBe(exactConversationId);

    expect(matches).toHaveLength(1);
    expect(matches[0]?.codexMatchOf).toBe(hostE?.id);
    // X's own overlapping window still makes E's row ambiguous.
    expect(matches[0]?.codexMatchTabs).toBe(2);
    expect(matches.some((item) => item.codexMatchOf === hostX?.id)).toBe(false);
  });

  test("the default (includeCodexMatches omitted) and --all (no projectRoot) add no Codex rows and never open codex/", () => {
    hostEvidence("rf-20260731-cdx001", {
      command: "codex",
      recordVersion: 2,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:00:00.000Z",
      endedAt: "2026-07-31T00:10:00.000Z",
    });
    codexRollout("2026/07/31", CODEX_UUID, "2026-07-31T00:05:00.000Z");
    const codexSegment = `${path.sep}codex${path.sep}`;
    const opendirSpy = vi.spyOn(fs, "opendirSync");

    const scoped = scanRecoveryInventory({ env, projectRoot });
    expect(scoped.items.some((item) => item.conversationSource === "codex-match")).toBe(false);

    const all = scanRecoveryInventory({ env, includeCodexMatches: true });
    expect(all.items.some((item) => item.conversationSource === "codex-match")).toBe(false);

    for (const call of opendirSpy.mock.calls) expect(String(call[0])).not.toContain(codexSegment);
    opendirSpy.mockRestore();
  });

  test("caps Codex rows at 5 per host item (F5)", () => {
    hostEvidence("rf-20260731-cdx002", {
      command: "codex",
      recordVersion: 2,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:00:00.000Z",
      endedAt: "2026-07-31T01:00:00.000Z",
    });
    for (let i = 0; i < 8; i += 1) {
      codexRollout("2026/07/31", fakeUuid(i), `2026-07-31T00:${String(10 + i).padStart(2, "0")}:00.000Z`);
    }

    const inventory = scanRecoveryInventory({ env, projectRoot, includeCodexMatches: true });
    const matches = inventory.items.filter((item) => item.conversationSource === "codex-match");

    expect(matches).toHaveLength(CODEX_MATCH_LIMITS.maxRowsPerHostItem);
  });

  test("caps Codex rows at 50 in total across many host items, dropping the oldest item's rows first (F5)", () => {
    const ids: string[] = [];
    for (let i = 0; i < 12; i += 1) {
      const hour = i * 2;
      const id = `rf-20260731-cdx1${String(i).padStart(2, "0")}`;
      ids.push(id);
      hostEvidence(id, {
        command: "codex",
        recordVersion: 2,
        outcome: "interrupted",
        startedAt: `2026-07-31T${String(hour).padStart(2, "0")}:00:00.000Z`,
        endedAt: `2026-07-31T${String(hour).padStart(2, "0")}:50:00.000Z`,
      });
      for (let j = 0; j < 5; j += 1) {
        codexRollout("2026/07/31", fakeUuid(i * 10 + j), `2026-07-31T${String(hour).padStart(2, "0")}:1${j}:00.000Z`);
      }
    }

    const inventory = scanRecoveryInventory({ env, projectRoot, includeCodexMatches: true });
    const matches = inventory.items.filter((item) => item.conversationSource === "codex-match");
    const oldestHostRow = inventory.items.find(
      (item) => item.sourceId === ids[0] && item.conversationSource !== "codex-match",
    );

    expect(matches).toHaveLength(CODEX_MATCH_LIMITS.maxRowsTotal);
    expect(matches.some((item) => item.codexMatchOf === oldestHostRow?.id)).toBe(false);
  });

  test("the cross-scan thread merge keeps the newest startedAtMs, not the first one seen (minor: threadsById collision policy)", () => {
    const sharedUuid = "01a0692c-7f74-7750-ad42-fb36200a005e";
    // Processed first (newest own `startedAt`): its window physically
    // reaches a file carrying the shared uuid, but one stamped with an
    // *old* `session_meta.timestamp` that belongs inside neither item's own
    // window — on its own it would never produce a row.
    hostEvidence("rf-20260731-cdxfirst", {
      command: "codex",
      recordVersion: 2,
      outcome: "interrupted",
      startedAt: "2026-08-15T00:00:00.000Z",
      endedAt: "2026-08-15T00:10:00.000Z",
    });
    codexRollout("2026/08/14", sharedUuid, "2026-01-01T00:00:00.000Z");
    // Processed second (older own `startedAt`): its own window reaches the
    // *same* uuid's genuinely current file, stamped inside its own window.
    hostEvidence("rf-20260731-cdxsecond", {
      command: "codex",
      recordVersion: 2,
      outcome: "interrupted",
      startedAt: "2026-01-05T00:00:00.000Z",
      endedAt: "2026-01-05T00:10:00.000Z",
    });
    codexRollout("2026/01/05", sharedUuid, "2026-01-05T00:05:00.000Z");

    const inventory = scanRecoveryInventory({ env, projectRoot, includeCodexMatches: true });
    const matches = inventory.items.filter((item) => item.conversationSource === "codex-match");
    const hostSecond = inventory.items.find(
      (item) => item.sourceId === "rf-20260731-cdxsecond" && item.conversationSource !== "codex-match",
    );

    // Keeping the first-seen (older, out-of-window) value would leave this
    // thread matching no window at all, so the row would be missing.
    expect(matches).toHaveLength(1);
    expect(matches[0]?.conversationId).toBe(sharedUuid);
    expect(matches[0]?.codexMatchOf).toBe(hostSecond?.id);
  });

  test("ten stale records whose windows all reach the same day share one pass: that day directory is opened only once (round-1 finding 4)", () => {
    for (let i = 0; i < 10; i += 1) {
      hostEvidence(`rf-20260731-cdxp${String(i).padStart(2, "0")}`, {
        command: "codex",
        recordVersion: 2,
        outcome: "interrupted",
        startedAt: "2026-07-31T00:00:00.000Z",
        endedAt: "2026-07-31T00:10:00.000Z",
      });
    }
    codexRollout("2026/07/31", CODEX_UUID, "2026-07-31T00:05:00.000Z");
    const opendirSpy = vi.spyOn(fs, "opendirSync");

    const inventory = scanRecoveryInventory({ env, projectRoot, includeCodexMatches: true });

    const dayDir = path.join(stateDir, "codex", "sessions", "2026", "07", "31");
    expect(opendirSpy.mock.calls.filter((call) => call[0] === dayDir)).toHaveLength(1);
    const matches = inventory.items.filter((item) => item.conversationSource === "codex-match");
    expect(matches).toHaveLength(10);
    expect(matches.every((item) => item.codexMatchTabs === 10)).toBe(true);
    opendirSpy.mockRestore();
  });

  test("a pass whose deadline is exceeded partway through still returns promptly, giving no rows to the records not yet reached (round-1 finding 4)", () => {
    const TOTAL = 20;
    for (let i = 0; i < TOTAL; i += 1) {
      const day = dayAt(i);
      hostEvidence(`rf-20260731-cdxq${String(i).padStart(2, "0")}`, {
        command: "codex",
        recordVersion: 2,
        outcome: "interrupted",
        startedAt: day.iso("00:00"),
        endedAt: day.iso("00:10"),
      });
      codexRollout(day.path, fakeUuid(i), day.iso("00:05"));
    }

    // A deterministic virtual clock that advances a fixed, small amount on
    // *every* `Date.now()` read anywhere in the scan (never frozen, never
    // jumped). This is the discriminating shape: a deadline recomputed
    // fresh per record (today's un-shared behavior) always gets a full,
    // renewed budget relative to wherever the clock currently is, so it
    // would never trip no matter how many records came before it — only a
    // *single* deadline fixed once, at the start of the whole pass, is
    // eventually overtaken by a clock that keeps advancing underneath it.
    let calls = 0;
    const base = Date.now();
    const dateNowSpy = vi.spyOn(Date, "now").mockImplementation(() => {
      calls += 1;
      return base + calls * 50;
    });

    try {
      const inventory = scanRecoveryInventory({ env, projectRoot, includeCodexMatches: true });
      const matches = inventory.items.filter((item) => item.conversationSource === "codex-match");

      // Some records were read before the shared deadline hit...
      expect(matches.length).toBeGreaterThan(0);
      // ...but not every one of them — the whole point of a *shared*
      // deadline is that it is not re-armed per record.
      expect(matches.length).toBeLessThan(TOTAL);
      // Every host row is present regardless of whether it got a guess.
      for (let i = 0; i < TOTAL; i += 1) {
        const id = `rf-20260731-cdxq${String(i).padStart(2, "0")}`;
        expect(inventory.items.some((item) => item.sourceId === id && item.conversationSource !== "codex-match")).toBe(true);
      }
    } finally {
      dateNowSpy.mockRestore();
    }
  });

  test("a Codex scan error leaves no Codex rows but keeps the host row", () => {
    hostEvidence("rf-20260731-cdx003", {
      command: "codex",
      recordVersion: 2,
      outcome: "interrupted",
      startedAt: "2026-07-31T00:00:00.000Z",
      endedAt: "2026-07-31T00:10:00.000Z",
    });
    const codexDir = path.join(stateDir, "codex");
    fs.mkdirSync(codexDir, { recursive: true });
    // `sessions` must be a directory; replacing it with a file makes every
    // day-directory lookup fail, the same shape of failure a real scan error
    // (or an exhausted budget) produces.
    fs.writeFileSync(path.join(codexDir, "sessions"), "");

    const inventory = scanRecoveryInventory({ env, projectRoot, includeCodexMatches: true });

    expect(inventory.items.some((item) => item.conversationSource === "codex-match")).toBe(false);
    expect(
      inventory.items.some((item) => item.sourceId === "rf-20260731-cdx003" && item.conversationSource !== "codex-match"),
    ).toBe(true);
  });
});
