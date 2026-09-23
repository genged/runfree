import fs from "node:fs";
import path from "node:path";

import {
  SESSION_ADMISSION_ROOT,
  parseSessionAdmissionEligibility,
  type SessionAdmissionEligibility,
} from "@runfree/runtime-contracts/session-admission";
import {
  SESSION_ELIGIBILITY_PATH,
  SESSION_FILES_DIR,
  SESSION_FILE_MAX_BYTES,
  isSessionFileEligible,
  parseSessionFileV1,
  type SessionFileV1,
  type SessionIpAssignment,
} from "@runfree/runtime-contracts/session-file";

// Pure, synchronous reader for the per-session file directory
// (`/run/runfree-sessions/sessions/<sessionKey>.json`) and its sibling
// eligibility file. Nothing consumes this yet (Task 2 of the session-file
// heartbeat admission plan) — later tasks call `scanSessionFiles` from the
// request proxy's and firewall's independent 100 ms loops. No side effects,
// no caching: every call re-reads the directory.
//
// `root` stands in for `/run/runfree-sessions` (production callers pass the
// same root used for the legacy session-admission tree; tests pass a tmpdir)
// so the two well-known children are addressed relative to it, the same way
// `session-admission.ts` remaps `SESSION_ADMISSION_ROOT`-relative paths onto
// a caller-supplied root.
const SESSIONS_DIR_RELATIVE = path.relative(SESSION_ADMISSION_ROOT, SESSION_FILES_DIR);
const ELIGIBILITY_PATH_RELATIVE = path.relative(SESSION_ADMISSION_ROOT, SESSION_ELIGIBILITY_PATH);

// The eligibility file is a handful of digests, an epoch, a network id, and
// up to `SESSION_ADMISSION_MAX_RECORDS` (256) agent-generation pairs of two
// sha256 strings each — a few tens of KB at the extreme. This bound exists
// only to keep a corrupt or hostile file from being read unbounded before
// `JSON.parse` even runs; it is not a wire contract.
const ELIGIBILITY_MAX_BYTES = 64 * 1024;

const JSON_SUFFIX = ".json";

export type SessionFileScan =
  | { kind: "unreadable" }
  | {
      kind: "ok";
      eligibility: SessionAdmissionEligibility;
      files: Map<string, SessionFileV1>;
      dropped: Array<{ name: string; reason: string }>;
      // Every session key a well-formed file in the directory claimed on this
      // pass, whether it ended up served or dropped by a rule
      // (ineligible, duplicate-address). `files` is the served subset, so it
      // answers "is this session admitted right now"; this answers "is this
      // session's file still on disk", which is the only question observation
      // pruning may ask (`session-file-validity.ts`). A file that fails to
      // parse names no key it can be trusted with and is in neither.
      presentKeys: Set<string>;
    };

type UnsafeReason = "symlink" | "not-regular" | "not-root" | "multi-link" | "oversize";

type OwnedFileRead =
  | { kind: "ok"; content: string }
  | { kind: "missing" }
  | { kind: "unsafe"; reason: UnsafeReason };

function errnoCode(error: unknown): string | undefined {
  return error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
}

// Shared by the lstat pre-check and the fstat post-open re-check (TOCTOU
// defense, same as `readRootOwnedFile` in session-admission.ts): whichever
// condition trips first names the reason. `isSymbolicLink()` is only
// meaningful on the pre-open lstat — a successful O_NOFOLLOW open can never
// land on a symlink, so the post-open call never reaches that branch.
function classifyUnsafeStat(stat: fs.Stats, ownerUid: number, maxBytes: number): UnsafeReason | undefined {
  if (stat.isSymbolicLink()) return "symlink";
  if (!stat.isFile()) return "not-regular";
  if (stat.uid !== ownerUid) return "not-root";
  if (stat.nlink !== 1) return "multi-link";
  if (stat.size > maxBytes) return "oversize";
  return undefined;
}

export function isSafeDirectory(directory: string, ownerUid: number): boolean {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(directory);
  } catch {
    return false;
  }
  return stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === ownerUid && (stat.mode & 0o022) === 0;
}

// Reads a file the same defended way `loadSelectedSessionAdmission` does
// (session-admission.ts:15-44): lstat first to decide it is safe to open,
// open with O_NOFOLLOW so a symlink swapped in after the lstat cannot be
// followed, then fstat the open descriptor and compare it against the
// pre-open lstat so a file swapped for a different one in that window is
// caught too. Unlike that function, failures are returned as data (this
// scanner never throws) so callers can report a per-file drop reason.
export function readOwnedRegularFile(filePath: string, ownerUid: number, maxBytes: number): OwnedFileRead {
  let before: fs.Stats;
  try {
    before = fs.lstatSync(filePath);
  } catch (error) {
    if (errnoCode(error) === "ENOENT") return { kind: "missing" };
    return { kind: "unsafe", reason: "not-regular" };
  }
  const beforeReason = classifyUnsafeStat(before, ownerUid, maxBytes);
  if (beforeReason) return { kind: "unsafe", reason: beforeReason };

  let descriptor: number;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  } catch (error) {
    const code = errnoCode(error);
    if (code === "ENOENT") return { kind: "missing" };
    if (code === "ELOOP") return { kind: "unsafe", reason: "symlink" };
    return { kind: "unsafe", reason: "not-regular" };
  }
  try {
    const opened = fs.fstatSync(descriptor);
    const openedReason = classifyUnsafeStat(opened, ownerUid, maxBytes);
    if (openedReason) return { kind: "unsafe", reason: openedReason };
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) {
      return { kind: "unsafe", reason: "not-regular" };
    }
    return { kind: "ok", content: fs.readFileSync(descriptor, "utf8") };
  } finally {
    fs.closeSync(descriptor);
  }
}

// `parseSessionFileV1` (Task 1) collapses every failure, including a
// name/key mismatch, to `undefined` — it cannot tell the scanner which rule
// tripped. So the scanner reads the embedded `sessionKey` itself, leniently
// (a bare `JSON.parse`, not the full contract parse), only to distinguish
// "this file names the wrong session" from every other way a file can fail
// to parse. If the lenient parse cannot even find a string `sessionKey`
// field, this returns `undefined` and the caller falls through to the full
// parse, which will fail for the same underlying reason and be reported
// "malformed".
function lenientSessionKey(raw: string): string | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const value = (parsed as Record<string, unknown>).sessionKey;
  return typeof value === "string" ? value : undefined;
}

export function scanSessionFiles(input: { root: string; ownerUid: number; projectId: string; assignments?: ReadonlyMap<string, SessionIpAssignment> }): SessionFileScan {
  if (!isSafeDirectory(input.root, input.ownerUid)) return { kind: "unreadable" };

  const eligibilityPath = path.join(input.root, ELIGIBILITY_PATH_RELATIVE);
  const eligibilityRead = readOwnedRegularFile(eligibilityPath, input.ownerUid, ELIGIBILITY_MAX_BYTES);
  if (eligibilityRead.kind !== "ok") return { kind: "unreadable" };

  let eligibility: SessionAdmissionEligibility | undefined;
  try {
    eligibility = parseSessionAdmissionEligibility(JSON.parse(eligibilityRead.content) as unknown);
  } catch {
    eligibility = undefined;
  }
  // The eligibility file must also actually be this proxy's — a file that
  // parses but names a different project is exactly as untrustworthy as one
  // that fails to parse (mirrors `loadSelectedSessionAdmission`'s "belongs
  // to another project" rejection for the equivalent snapshot/selection
  // pair, and spec invariant 8: "a file whose project ... binding does not
  // match the proxy's" is a fail-closed contradiction).
  if (!eligibility || eligibility.projectId !== input.projectId) return { kind: "unreadable" };

  const sessionsDir = path.join(input.root, SESSIONS_DIR_RELATIVE);
  let entryNames: string[];
  try {
    // Same directory-safety shape as `isSafeDirectory` above (and
    // `assertSafeDirectory` in session-admission.ts): a symlinked, wrongly
    // owned, or group/other-writable `sessions/` would let an unprivileged
    // party redirect or rename what this scan trusts as root-owned.
    const dirStat = fs.lstatSync(sessionsDir);
    if (!dirStat.isDirectory() || dirStat.isSymbolicLink() || dirStat.uid !== input.ownerUid || (dirStat.mode & 0o022) !== 0) {
      return { kind: "unreadable" };
    }
    entryNames = fs.readdirSync(sessionsDir);
  } catch (error) {
    if (errnoCode(error) === "ENOENT") {
      return { kind: "ok", eligibility, files: new Map(), dropped: [], presentKeys: new Set() };
    }
    return { kind: "unreadable" };
  }

  const dropped: Array<{ name: string; reason: string }> = [];
  const candidates = new Map<string, { name: string; file: SessionFileV1 }>();
  const presentKeys = new Set<string>();

  for (const name of entryNames) {
    // Review fix F12: the only skip rule is "does not end in .json" — it
    // covers both the plan's illustrative "sk-1.json.123.tmp" spelling and
    // today's real `.runfree-<pid>-<rand8>.tmp` interrupted-rename name.
    // Skipped names are neither served nor reported as dropped.
    if (!name.endsWith(JSON_SUFFIX)) continue;
    const expectedKey = name.slice(0, -JSON_SUFFIX.length);
    const filePath = path.join(sessionsDir, name);

    const read = readOwnedRegularFile(filePath, input.ownerUid, SESSION_FILE_MAX_BYTES);
    if (read.kind === "missing") continue; // vanished between readdir and read: benign race, not a drop
    if (read.kind === "unsafe") {
      dropped.push({ name, reason: read.reason });
      continue;
    }

    const embeddedKey = lenientSessionKey(read.content);
    if (embeddedKey !== undefined && embeddedKey !== expectedKey) {
      dropped.push({ name, reason: "name-mismatch" });
      continue;
    }

    const parsed = parseSessionFileV1(read.content, expectedKey);
    if (!parsed) {
      dropped.push({ name, reason: "malformed" });
      continue;
    }

    // Recorded before the eligibility rule, not after it: a dropped file is
    // still a file on disk, and everything below this line decides service,
    // not presence.
    presentKeys.add(parsed.sessionKey);

    if (!isSessionFileEligible(parsed, eligibility)) {
      dropped.push({ name, reason: "ineligible" });
      continue;
    }

    const assignment = input.assignments?.get(parsed.sourceIp);
    if (assignment !== undefined && (assignment.state !== "ready" || assignment.sessionKey !== parsed.sessionKey)) {
      dropped.push({ name, reason: "IP assigned to another session or being drained" });
      continue;
    }
    candidates.set(parsed.sessionKey, { name, file: parsed });
  }

  const claimantsByAddress = new Map<string, string[]>();
  for (const [sessionKey, entry] of candidates) {
    const claimants = claimantsByAddress.get(entry.file.sourceIp) ?? [];
    claimants.push(sessionKey);
    claimantsByAddress.set(entry.file.sourceIp, claimants);
  }

  const files = new Map<string, SessionFileV1>();
  for (const [sessionKey, entry] of candidates) {
    const claimants = claimantsByAddress.get(entry.file.sourceIp);
    if (claimants && claimants.length > 1) {
      dropped.push({ name: entry.name, reason: "duplicate-address" });
    } else {
      files.set(sessionKey, entry.file);
    }
  }

  return { kind: "ok", eligibility, files, dropped, presentKeys };
}
