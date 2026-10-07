// Bounded Codex rollout reader (same-terminal resume, spec section 2,
// "Codex: time match (C1), picker only" / "New bounded reader").
//
// Codex rollout files live under the agent-writable Codex home
// (`<stateDir>/codex`, Codex `hostSubdir`, `agents.ts`). The untrusted agent
// container can put anything there: symlinks, FIFOs, hard links, huge files,
// or millions of junk entries. This reader runs on the host during an
// interactive `runfree resume` and must never stall, never follow a link out
// of the walked tree, and never read without a bound. It returns raw thread
// names; sanitizing them for display is a later task's job.
//
// The walk is fixed-depth and computed, not discovered: candidate
// `sessions/<year>/<month>/<day>` directories come only from the caller's
// windows (never from listing `sessions/` or any year/month directory), so
// an attacker who fills `sessions/` with junk directory names cannot make
// this reader visit them at all. Every entry *within* a visited day
// directory still counts against `maxEntriesPerDir`, matching or not
// (security review F4), and the whole scan has a `deadlineMs` wall-clock
// backstop independent of any count.
import fs from "node:fs";
import path from "node:path";

import { entryResolvesInsideDirectory, verifiedDirectoryIdentity, type DirectoryIdentity, type RecoveryItem } from "./recovery.ts";
import type { SessionContainerRecordV2 } from "./session-containers.ts";
import { isRecord } from "../strict-primitives.ts";

export const CODEX_ROLLOUT_LIMITS = {
  maxDateDirs: 64,
  maxEntriesPerDir: 4096,
  maxFilesTotal: 2048,
  deadlineMs: 2000,
  maxFirstLineBytes: 262_144,
  maxTotalBytes: 33_554_432,
  maxIndexTailBytes: 1_048_576,
} as const;

export type CodexWindow = Readonly<{ startMs: number; endMs: number }>;
export type CodexThread = Readonly<{ id: string; startedAtMs: number; name?: string }>;
export type CodexScan = Readonly<{ threads: readonly CodexThread[]; complete: boolean }>;

// Spec section 2, "Codex: time match (C1), picker only", and decision 4: a
// time match only adds picker rows, never the one question, so the picker
// can show more than one candidate row per record ("matches N tabs") without
// ever being asked to resolve the ambiguity itself.
export type CodexMatchInput = Readonly<{ itemId: string; window?: CodexWindow }>;
export type CodexMatch = Readonly<{ itemId: string; thread: CodexThread; tabs: number }>;

export const CODEX_MATCH_LIMITS = {
  maxRowsPerHostItem: 5,
  maxRowsTotal: 50,
} as const;

/**
 * Shared state across every `scanCodexThreads` call that makes up one
 * Codex-match pass over several host records (`codexMatchItemsForProject`,
 * `recovery.ts`): one deadline and one pair of byte/file budgets for the
 * *whole* pass, not one each per call, so N stale records cannot stall a
 * resume for about N × `deadlineMs` (security review, task 9 round-1 finding
 * 4). `days` caches each UTC day-start already read during this pass —
 * `readonly CodexThread[]` for a day that was read to completion (possibly
 * empty), or `"incomplete"` for one a budget or the deadline cut off midway
 * — so two records whose windows overlap the same day never pay to open it
 * twice. Construct with `createCodexScanPass`; a caller that does not pass
 * one gets today's single-call behavior (its own fresh deadline and
 * budgets, scoped to that one call).
 */
export type CodexScanPass = {
  readonly deadlineAt: number;
  readonly byteBudget: { bytes: number };
  readonly fileBudget: { attempted: number };
  readonly days: Map<string, readonly CodexThread[] | "incomplete">;
};

export function createCodexScanPass(): CodexScanPass {
  return {
    deadlineAt: Date.now() + CODEX_ROLLOUT_LIMITS.deadlineMs,
    byteBudget: { bytes: 0 },
    fileBudget: { attempted: 0 },
    days: new Map(),
  };
}

const DATE_PART = { year: /^\d{4}$/, month: /^\d{2}$/, day: /^\d{2}$/ };
const ROLLOUT_RE =
  /^rollout-[0-9T:-]+-([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.jsonl$/;

const MS_PER_DAY = 24 * 60 * 60 * 1000;

// Test-only seam (step 7c / security review F8): a test sets this to run
// code between a file's open (fd pinned to its original inode, `fstat`
// already proved it regular with `nlink === 1`) and this module's post-open
// containment re-check, to prove the check — not the open — is what rejects
// a directory swapped out from under an already-open file. No production
// code path ever calls the setter, so it has no effect outside tests.
let afterOpenForTest: (() => void) | undefined;
export function setCodexRolloutAfterOpenHookForTest(hook: (() => void) | undefined): void {
  afterOpenForTest = hook;
}

type OpenedFile = { fd: number; stat: fs.Stats };

function openRegular(filePath: string): OpenedFile | undefined {
  let fd: number | undefined;
  try {
    // O_NONBLOCK: a FIFO planted by the agent must not stall the launch.
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1) {
      fs.closeSync(fd);
      return undefined;
    }
    afterOpenForTest?.();
    return { fd, stat };
  } catch {
    if (fd !== undefined) fs.closeSync(fd);
    return undefined;
  }
}

/** Reads only the first line (up to `maxFirstLineBytes`), tracking total bytes read against the scan-wide `budget` (`maxTotalBytes`). No newline within budget, or the shared budget already exhausted, gives `undefined`. */
function readFirstLine(fd: number, budget: { bytes: number }): string | undefined {
  const chunk = Buffer.alloc(16_384);
  const parts: Buffer[] = [];
  let total = 0;
  while (total < CODEX_ROLLOUT_LIMITS.maxFirstLineBytes) {
    const read = fs.readSync(fd, chunk, 0, chunk.length, null);
    if (read === 0) return undefined;
    budget.bytes += read;
    if (budget.bytes > CODEX_ROLLOUT_LIMITS.maxTotalBytes) return undefined;
    const newline = chunk.subarray(0, read).indexOf(0x0a);
    parts.push(Buffer.from(chunk.subarray(0, newline === -1 ? read : newline)));
    total += newline === -1 ? read : newline;
    if (newline !== -1) return Buffer.concat(parts).toString("utf8");
  }
  return undefined;
}

function parseSessionMetaLine(line: string, fileUuid: string): { id: string; startedAtMs: number } | undefined {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return undefined;
  }
  if (!isRecord(value) || value.type !== "session_meta" || !isRecord(value.payload)) return undefined;
  const payload = value.payload;
  if (typeof payload.id !== "string" || payload.id.toLowerCase() !== fileUuid) return undefined;
  if (typeof payload.timestamp !== "string") return undefined;
  const startedAtMs = Date.parse(payload.timestamp);
  if (!Number.isFinite(startedAtMs)) return undefined;
  return { id: fileUuid, startedAtMs };
}

function utcDayStart(ms: number): number {
  const d = new Date(ms);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
}

/** Whether a day's rollout directory, read as covering `[dayStartUtc, dayStartUtc + 2 days)` (the extra day absorbs Codex's local-time directory naming vs. UTC payload timestamps — spec section 2), overlaps `window`. */
function dayOverlapsWindow(dayStartUtc: number, window: CodexWindow): boolean {
  const extendedEnd = dayStartUtc + 2 * MS_PER_DAY;
  return dayStartUtc < window.endMs && extendedEnd > window.startMs;
}

/** The set of UTC day-starts to visit for `windows`, most recent first, capped at `maxDateDirs` and at the scan deadline. Computed purely from the windows' own timestamps — never by listing `sessions/` or any year/month directory — so junk directory names there cost nothing. */
function candidateDayStarts(windows: readonly CodexWindow[], deadlineAt: number): { days: number[]; truncated: boolean } {
  const days = new Set<number>();
  let truncated = false;
  windowLoop: for (const window of windows) {
    if (!Number.isFinite(window.startMs) || !Number.isFinite(window.endMs)) continue;
    // Start two days before the window's own day: a day's extended coverage
    // reaches one day past its nominal end, so a day as early as
    // `window.startMs - 2 days` can still overlap (see `dayOverlapsWindow`).
    let day = utcDayStart(window.startMs) - 2 * MS_PER_DAY;
    while (day < window.endMs) {
      if (Date.now() >= deadlineAt) {
        truncated = true;
        break windowLoop;
      }
      if (dayOverlapsWindow(day, window)) {
        if (!days.has(day) && days.size >= CODEX_ROLLOUT_LIMITS.maxDateDirs) {
          truncated = true;
          break windowLoop;
        }
        days.add(day);
      }
      day += MS_PER_DAY;
    }
  }
  return { days: Array.from(days).sort((left, right) => right - left), truncated };
}

function dayDirSegments(dayStartUtc: number): { year: string; month: string; day: string } | undefined {
  const d = new Date(dayStartUtc);
  const year = String(d.getUTCFullYear()).padStart(4, "0");
  const month = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  if (!DATE_PART.year.test(year) || !DATE_PART.month.test(month) || !DATE_PART.day.test(day)) return undefined;
  return { year, month, day };
}

/** Reads the last `maxIndexTailBytes` of `session_index.jsonl` (if present and safe to open), dropping the first partial line, and returns the newest `thread_name` seen per `id` (later lines in file order win). `undefined` means the shared byte budget was exhausted — a scan-wide signal, not "no index" (which is an empty map). */
function readThreadNames(
  codexRoot: string,
  budget: { bytes: number },
): Map<string, string> | undefined {
  const indexPath = path.join(codexRoot, "session_index.jsonl");
  const rootIdentity = verifiedDirectoryIdentity(codexRoot, codexRoot);
  if (!rootIdentity) return new Map();
  const opened = openRegular(indexPath);
  if (!opened) return new Map();
  try {
    if (!entryResolvesInsideDirectory(codexRoot, indexPath, rootIdentity, opened.stat)) return new Map();
    const size = opened.stat.size;
    const want = Math.min(size, CODEX_ROLLOUT_LIMITS.maxIndexTailBytes);
    if (want <= 0) return new Map();
    const offset = size - want;
    const buf = Buffer.alloc(want);
    let readTotal = 0;
    while (readTotal < want) {
      const read = fs.readSync(opened.fd, buf, readTotal, want - readTotal, offset + readTotal);
      if (read === 0) break;
      readTotal += read;
    }
    budget.bytes += readTotal;
    if (budget.bytes > CODEX_ROLLOUT_LIMITS.maxTotalBytes) return undefined;
    const rawLines = buf.subarray(0, readTotal).toString("utf8").split("\n");
    const lines = offset > 0 ? rawLines.slice(1) : rawLines;
    const names = new Map<string, string>();
    for (const line of lines) {
      if (!line) continue;
      let value: unknown;
      try {
        value = JSON.parse(line);
      } catch {
        continue;
      }
      if (isRecord(value) && typeof value.id === "string" && typeof value.thread_name === "string") {
        names.set(value.id.toLowerCase(), value.thread_name);
      }
    }
    return names;
  } finally {
    fs.closeSync(opened.fd);
  }
}

// `fileName` is carried only for `dedupeCandidatesById`'s tie-break; it never
// reaches `CodexThread`.
type RolloutCandidate = { id: string; startedAtMs: number; fileName: string };

/**
 * Collapses `candidates` so each session id appears at most once: a thread
 * id can legitimately come from more than one rollout file (for example, a
 * continued session, or two files an attacker crafted to collide on
 * `payload.id`), and the picker must show one row for it, not one per file.
 * The newest `startedAtMs` wins; a tie breaks on the lexically greatest
 * filename, so the result is deterministic rather than depending on
 * directory enumeration order.
 */
function dedupeCandidatesById(candidates: readonly RolloutCandidate[]): RolloutCandidate[] {
  const byId = new Map<string, RolloutCandidate>();
  for (const candidate of candidates) {
    const existing = byId.get(candidate.id);
    if (!existing
      || candidate.startedAtMs > existing.startedAtMs
      || (candidate.startedAtMs === existing.startedAtMs && candidate.fileName > existing.fileName)) {
      byId.set(candidate.id, candidate);
    }
  }
  return Array.from(byId.values());
}

function scanDayDirectory(
  dayDir: string,
  dayIdentity: DirectoryIdentity,
  deadlineAt: number,
  byteBudget: { bytes: number },
  fileBudget: { attempted: number },
  out: RolloutCandidate[],
): "ok" | "truncated" {
  const names: string[] = [];
  let entries = 0;
  let directory: fs.Dir | undefined;
  try {
    directory = fs.opendirSync(dayDir);
    while (true) {
      if (Date.now() >= deadlineAt) return "truncated";
      const entry = directory.readSync();
      if (!entry) break;
      entries += 1;
      if (entries > CODEX_ROLLOUT_LIMITS.maxEntriesPerDir) return "truncated";
      if (ROLLOUT_RE.test(entry.name)) names.push(entry.name);
    }
  } catch {
    return "ok"; // gone or unreadable: no entries here, not a budget failure
  } finally {
    directory?.closeSync();
  }

  // Filenames embed a sortable timestamp, so a plain descending name sort is
  // newest-first without an extra `lstat` per candidate (unlike the
  // analogous pass in `recovery.ts`, which has no such ordering in the name).
  names.sort((left, right) => (left < right ? 1 : left > right ? -1 : 0));

  for (const name of names) {
    if (Date.now() >= deadlineAt) return "truncated";
    if (fileBudget.attempted >= CODEX_ROLLOUT_LIMITS.maxFilesTotal) return "truncated";
    fileBudget.attempted += 1;
    const match = ROLLOUT_RE.exec(name);
    if (!match || !match[1]) continue;
    const fileUuid = match[1];
    const filePath = path.join(dayDir, name);
    const opened = openRegular(filePath);
    if (!opened) continue;
    try {
      if (!entryResolvesInsideDirectory(dayDir, filePath, dayIdentity, opened.stat)) continue;
      const firstLine = readFirstLine(opened.fd, byteBudget);
      if (byteBudget.bytes > CODEX_ROLLOUT_LIMITS.maxTotalBytes) return "truncated";
      if (!firstLine) continue;
      const parsed = parseSessionMetaLine(firstLine, fileUuid);
      if (parsed) out.push({ ...parsed, fileName: name });
    } finally {
      fs.closeSync(opened.fd);
    }
  }
  return "ok";
}

function scanCodexThreadsUnsafe(
  input: Readonly<{ stateDir: string; windows: readonly CodexWindow[]; pass?: CodexScanPass }>,
): CodexScan {
  if (input.windows.length === 0) return { threads: [], complete: true };

  const pass = input.pass ?? createCodexScanPass();
  const deadlineAt = pass.deadlineAt;
  const codexRoot = path.join(input.stateDir, "codex");
  const byteBudget = pass.byteBudget;
  const fileBudget = pass.fileBudget;
  const candidates: RolloutCandidate[] = [];
  let complete = true;

  const { days, truncated: daysTruncated } = candidateDayStarts(input.windows, deadlineAt);
  if (daysTruncated) complete = false;

  for (const dayStartUtc of days) {
    if (Date.now() >= deadlineAt) {
      complete = false;
      break;
    }

    // Shared across every call in one pass: a day already read (by this
    // call's own earlier window, or by an earlier record's call) is never
    // opened a second time (security review, task 9 round-1 finding 4).
    const dayKey = String(dayStartUtc);
    const cached = pass.days.get(dayKey);
    if (cached === "incomplete") {
      complete = false;
      continue; // known-bad from an earlier call; cheap to keep checking other days
    }
    if (cached !== undefined) {
      for (const thread of cached) candidates.push({ id: thread.id, startedAtMs: thread.startedAtMs, fileName: "" });
      continue;
    }

    const segments = dayDirSegments(dayStartUtc);
    if (!segments) {
      pass.days.set(dayKey, []);
      continue;
    }
    const dayDir = path.join(codexRoot, "sessions", segments.year, segments.month, segments.day);
    const dayIdentity = verifiedDirectoryIdentity(codexRoot, dayDir);
    if (!dayIdentity) {
      pass.days.set(dayKey, []); // no such day, or a symlink somewhere in the chain
      continue;
    }

    const dayCandidates: RolloutCandidate[] = [];
    const result = scanDayDirectory(dayDir, dayIdentity, deadlineAt, byteBudget, fileBudget, dayCandidates);
    if (result === "truncated") {
      complete = false;
      pass.days.set(dayKey, "incomplete");
      break;
    }
    pass.days.set(dayKey, dayCandidates.map((candidate) => ({ id: candidate.id, startedAtMs: candidate.startedAtMs })));
    candidates.push(...dayCandidates);
  }

  if (candidates.length === 0) return { threads: [], complete };

  const deduped = dedupeCandidatesById(candidates);
  const names = Date.now() < deadlineAt ? readThreadNames(codexRoot, byteBudget) : undefined;
  if (names === undefined) complete = false;

  const threads: CodexThread[] = deduped.map((candidate) => {
    const name = names?.get(candidate.id);
    return name !== undefined
      ? { id: candidate.id, startedAtMs: candidate.startedAtMs, name }
      : { id: candidate.id, startedAtMs: candidate.startedAtMs };
  });

  return { threads, complete };
}

/**
 * Scans `<stateDir>/codex` for every valid rollout thread in the day
 * directories that overlap one of `windows` (each day's coverage widened by
 * one day for time-zone skew — see `dayOverlapsWindow`). The windows choose
 * *which day directories get opened*; they do not filter individual
 * threads — a thread whose own `startedAtMs` falls outside every window can
 * still come back if its file lives in a visited day (the widened coverage
 * means a visited day can reach past a window's nominal edge). Matching a
 * thread to the window(s) it actually belongs to is the caller's job
 * (`matchCodexThreads`). Never throws: any unexpected failure gives
 * `{ threads: [], complete: false }`, same as an exhausted budget or the
 * wall-clock deadline. An empty `windows` list does no filesystem I/O at
 * all.
 *
 * `pass` (optional) shares one deadline, one pair of byte/file budgets, and
 * one per-day cache across several calls — see `CodexScanPass`. Without it,
 * this call gets its own fresh deadline and budgets, exactly as before.
 */
export function scanCodexThreads(
  input: Readonly<{ stateDir: string; windows: readonly CodexWindow[]; pass?: CodexScanPass }>,
): CodexScan {
  try {
    return scanCodexThreadsUnsafe(input);
  } catch {
    return { threads: [], complete: false };
  }
}

/**
 * The time window a host Codex record's own evidence bounds a thread search
 * to (spec section 2, "Window end"). `item`'s own `hostMetadata.endedAt`
 * wins; else the per-session lifecycle record matching `item.sourceId`
 * gives `leaseExpiresAt`, an upper bound on the last lease renewal (decision
 * 4: it can only widen the window, so it can only add "matches N tabs"
 * marks, never remove a real match); else `undefined` — no window, so
 * `matchCodexThreads` never matches this item to anything. `lastSeenAt` is
 * deliberately never read here: it is written only at session creation
 * (`sessions.ts`), so by itself it carries no information about when the
 * session actually ended.
 */
export function codexWindowForItem(
  item: RecoveryItem,
  records: readonly SessionContainerRecordV2[],
): CodexWindow | undefined {
  const startMs = Date.parse(item.startedAt ?? "");
  if (!Number.isFinite(startMs)) return undefined;

  const endedAt = item.hostMetadata?.endedAt;
  if (endedAt !== undefined) {
    const endMs = Date.parse(endedAt);
    if (Number.isFinite(endMs)) return { startMs, endMs };
  }

  const leaseExpiresAt = records.find((record) => record.sessionId === item.sourceId)?.leaseExpiresAt;
  if (leaseExpiresAt !== undefined) {
    const endMs = Date.parse(leaseExpiresAt);
    if (Number.isFinite(endMs)) return { startMs, endMs };
  }

  return undefined;
}

/**
 * Matches scanned Codex threads to picker rows (spec section 2, "Codex:
 * time match (C1), picker only"). A thread whose `startedAtMs` falls inside
 * one item's window gives that item a match; a thread inside more than one
 * item's window gives every one of those items a match, each stamped with
 * the total count — the ambiguity itself is useful picker information
 * ("matches N tabs"), never a reason to guess a single owner (decision 4,
 * security review M2). An item with no window (`window` absent, meaning
 * `codexWindowForItem` returned `undefined` for it) never matches anything.
 * The caller decides row ordering and the `CODEX_MATCH_LIMITS` caps; this
 * function only answers "which item(s) does each thread belong to".
 */
export function matchCodexThreads(
  records: readonly CodexMatchInput[],
  threads: readonly CodexThread[],
): CodexMatch[] {
  const matches: CodexMatch[] = [];
  for (const thread of threads) {
    const inWindow = records.filter((record) =>
      record.window !== undefined
      && thread.startedAtMs >= record.window.startMs
      && thread.startedAtMs <= record.window.endMs);
    for (const record of inWindow) {
      matches.push({ itemId: record.itemId, thread, tabs: inWindow.length });
    }
  }
  return matches;
}
