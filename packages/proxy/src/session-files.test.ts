import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  createSessionAdmissionEligibility,
  serializeSessionAdmissionEligibility,
} from "@runfree/runtime-contracts/session-admission";
import {
  mintSessionFileNonce,
  serializeSessionFileV1,
  SESSION_FILE_MAX_BYTES,
  type SessionFileV1,
} from "@runfree/runtime-contracts/session-file";
import { afterEach, describe, expect, test, vi } from "vitest";

import { scanSessionFiles } from "./session-files.ts";
import { SessionIpAssignments } from "./session-ip-reuse.ts";

const PROJECT_ID = "abcdef012345";
const NETWORK_ID = "e".repeat(64);
const IMAGE_DIGEST = `sha256:${"a".repeat(64)}`;
const AGENT_DIGEST = `sha256:${"b".repeat(64)}`;
const CONTROL_DIGEST = `sha256:${"d".repeat(64)}`;
const EPOCH = 3;
const OWNER_UID = process.getuid?.() ?? 0;

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function makeRoot(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-session-files-"));
  roots.push(root);
  fs.chmodSync(root, 0o755);
  return root;
}

function eligibility() {
  return createSessionAdmissionEligibility({
    projectId: PROJECT_ID,
    controlPlaneGenerationDigest: CONTROL_DIGEST,
    admissionContractEpoch: EPOCH,
    agentInternalNetworkId: NETWORK_ID,
    allowedSessionAgents: [{ selectedAgentImageId: IMAGE_DIGEST, sessionAgentGenerationDigest: AGENT_DIGEST }],
  });
}

function writeEligibility(root: string): void {
  fs.writeFileSync(path.join(root, "eligibility.json"), serializeSessionAdmissionEligibility(eligibility()), {
    mode: 0o644,
  });
}

function sessionsDir(root: string): string {
  const dir = path.join(root, "sessions");
  fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
  return dir;
}

function makeFile(overrides: Partial<SessionFileV1> = {}): SessionFileV1 {
  return {
    v: 1,
    projectId: PROJECT_ID,
    sessionKey: "1".repeat(64),
    sessionId: "rf-20260907-abc123",
    sessionIncarnation: "2".repeat(64),
    sourceIp: "172.30.194.20",
    containerId: "c".repeat(64),
    networkId: NETWORK_ID,
    selectedAgentImageId: IMAGE_DIGEST,
    sessionAgentGenerationDigest: AGENT_DIGEST,
    controlPlaneGenerationDigest: CONTROL_DIGEST,
    admissionContractEpoch: EPOCH,
    name: "claude",
    command: "claude",
    startedAt: "2026-09-07T07:00:00.000Z",
    nonce: mintSessionFileNonce(),
    inspectedAt: "2026-09-07T07:00:03.090Z",
    aliveUntil: "2026-09-07T07:05:03.090Z",
    ...overrides,
  };
}

function writeSessionFile(root: string, file: SessionFileV1, nameOverride?: string): string {
  const name = nameOverride ?? `${file.sessionKey}.json`;
  const target = path.join(sessionsDir(root), name);
  fs.writeFileSync(target, serializeSessionFileV1(file), { mode: 0o644 });
  return target;
}

test("no eligibility ⇒ unreadable, even with valid session files", () => {
  const root = makeRoot();
  writeSessionFile(root, makeFile());
  const scan = scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID });
  expect(scan).toEqual({ kind: "unreadable" });
});

test("sessions/ missing ⇒ ok with no files", () => {
  const root = makeRoot();
  writeEligibility(root);
  const scan = scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID });
  expect(scan.kind).toBe("ok");
  if (scan.kind !== "ok") throw new Error("unreachable");
  expect(scan.files.size).toBe(0);
  expect(scan.dropped).toEqual([]);
});

test("a file whose name differs from its sessionKey is dropped", () => {
  const root = makeRoot();
  writeEligibility(root);
  const file = makeFile({ sessionKey: "3".repeat(64) });
  writeSessionFile(root, file, `${"4".repeat(64)}.json`);
  const scan = scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID });
  expect(scan.kind).toBe("ok");
  if (scan.kind !== "ok") throw new Error("unreachable");
  expect(scan.files.size).toBe(0);
  expect(scan.dropped).toEqual([{ name: `${"4".repeat(64)}.json`, reason: "name-mismatch" }]);
});

test("two files claiming one address drop both", () => {
  const root = makeRoot();
  writeEligibility(root);
  const first = makeFile({ sessionKey: "5".repeat(64), sourceIp: "172.30.194.21" });
  const second = makeFile({ sessionKey: "6".repeat(64), sourceIp: "172.30.194.21" });
  writeSessionFile(root, first);
  writeSessionFile(root, second);
  const scan = scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID });
  expect(scan.kind).toBe("ok");
  if (scan.kind !== "ok") throw new Error("unreachable");
  expect(scan.files.size).toBe(0);
  expect(scan.dropped).toHaveLength(2);
  expect(scan.dropped.every((entry) => entry.reason === "duplicate-address")).toBe(true);
  expect(new Set(scan.dropped.map((entry) => entry.name))).toEqual(
    new Set([`${first.sessionKey}.json`, `${second.sessionKey}.json`]),
  );
});

test("a temp file from an interrupted rename is ignored", () => {
  const root = makeRoot();
  writeEligibility(root);
  const good = makeFile({ sessionKey: "7".repeat(64), sourceIp: "172.30.194.22" });
  writeSessionFile(root, good);
  fs.writeFileSync(path.join(sessionsDir(root), "sk-1.json.123.tmp"), "not a real session file");
  const scan = scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID });
  expect(scan.kind).toBe("ok");
  if (scan.kind !== "ok") throw new Error("unreachable");
  expect(scan.files.size).toBe(1);
  expect(scan.files.has(good.sessionKey)).toBe(true);
  expect(scan.dropped.some((entry) => entry.name.includes(".tmp"))).toBe(false);
});

test("wrong digest, epoch, or network id is dropped as ineligible", () => {
  const root = makeRoot();
  writeEligibility(root);
  const wrongDigest = makeFile({
    sessionKey: "8".repeat(64),
    sourceIp: "172.30.194.23",
    controlPlaneGenerationDigest: `sha256:${"9".repeat(64)}`,
  });
  const wrongEpoch = makeFile({ sessionKey: `${"9".repeat(63)}0`, sourceIp: "172.30.194.24", admissionContractEpoch: 9 });
  const wrongNetwork = makeFile({ sessionKey: "0".repeat(64), sourceIp: "172.30.194.25", networkId: "f".repeat(64) });
  writeSessionFile(root, wrongDigest);
  writeSessionFile(root, wrongEpoch);
  writeSessionFile(root, wrongNetwork);
  const scan = scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID });
  expect(scan.kind).toBe("ok");
  if (scan.kind !== "ok") throw new Error("unreachable");
  expect(scan.files.size).toBe(0);
  expect(scan.dropped).toHaveLength(3);
  expect(scan.dropped.every((entry) => entry.reason === "ineligible")).toBe(true);
});

test("a symlinked file is dropped", () => {
  const root = makeRoot();
  writeEligibility(root);
  const file = makeFile({ sessionKey: `${"1".repeat(63)}2`, sourceIp: "172.30.194.26" });
  const realPath = path.join(root, "outside-real.json");
  fs.writeFileSync(realPath, serializeSessionFileV1(file), { mode: 0o644 });
  const linkPath = path.join(sessionsDir(root), `${file.sessionKey}.json`);
  fs.symlinkSync(realPath, linkPath);
  const scan = scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID });
  expect(scan.kind).toBe("ok");
  if (scan.kind !== "ok") throw new Error("unreachable");
  expect(scan.files.size).toBe(0);
  expect(scan.dropped).toEqual([{ name: `${file.sessionKey}.json`, reason: "symlink" }]);
});

test("a malformed file (fails the contract parse) is dropped as malformed", () => {
  const root = makeRoot();
  writeEligibility(root);
  const key = `${"1".repeat(63)}3`;
  const file = makeFile({ sessionKey: key, sourceIp: "172.30.194.27", nonce: "zz" });
  writeSessionFile(root, file);
  const scan = scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID });
  expect(scan.kind).toBe("ok");
  if (scan.kind !== "ok") throw new Error("unreachable");
  expect(scan.files.size).toBe(0);
  expect(scan.dropped).toEqual([{ name: `${key}.json`, reason: "malformed" }]);
});

test("a directory entry in place of a session file is dropped as not-regular", () => {
  const root = makeRoot();
  writeEligibility(root);
  const key = `${"1".repeat(63)}4`;
  fs.mkdirSync(path.join(sessionsDir(root), `${key}.json`));
  const scan = scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID });
  expect(scan.kind).toBe("ok");
  if (scan.kind !== "ok") throw new Error("unreachable");
  expect(scan.files.size).toBe(0);
  expect(scan.dropped).toEqual([{ name: `${key}.json`, reason: "not-regular" }]);
});

test("a hard-linked file is dropped as multi-link", () => {
  const root = makeRoot();
  writeEligibility(root);
  const key = `${"1".repeat(63)}5`;
  const file = makeFile({ sessionKey: key, sourceIp: "172.30.194.28" });
  const target = writeSessionFile(root, file);
  fs.linkSync(target, path.join(root, "hardlink-outside.json"));
  const scan = scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID });
  expect(scan.kind).toBe("ok");
  if (scan.kind !== "ok") throw new Error("unreachable");
  expect(scan.files.size).toBe(0);
  expect(scan.dropped).toEqual([{ name: `${key}.json`, reason: "multi-link" }]);
});

test("an oversize file is dropped as oversize", () => {
  const root = makeRoot();
  writeEligibility(root);
  const key = `${"1".repeat(63)}6`;
  fs.writeFileSync(path.join(sessionsDir(root), `${key}.json`), "x".repeat(SESSION_FILE_MAX_BYTES + 1));
  const scan = scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID });
  expect(scan.kind).toBe("ok");
  if (scan.kind !== "ok") throw new Error("unreachable");
  expect(scan.files.size).toBe(0);
  expect(scan.dropped).toEqual([{ name: `${key}.json`, reason: "oversize" }]);
});

// "not-root" (a session file owned by a uid different from the trusted
// ownerUid) cannot be simulated here: this suite runs unprivileged, so every
// file this process creates is owned by its own real uid, and chowning a
// file to a *different* arbitrary uid requires CAP_CHOWN/root. Skipped per
// the task brief's explicit allowance.

// `presentKeys` answers a different question from `files`: what is on disk,
// not what is served. Observation pruning is its only consumer
// (`session-file-validity.ts`), and pruning on the served set instead would
// hand a file that leaves and re-enters eligibility under one nonce a fresh
// monotonic bound.
test("presentKeys holds every well-formed key on disk, served or dropped by rule", () => {
  const root = makeRoot();
  writeEligibility(root);
  const served = makeFile({ sessionKey: "a".repeat(64), sourceIp: "172.30.194.31" });
  const ineligible = makeFile({
    sessionKey: "b".repeat(64),
    sourceIp: "172.30.194.32",
    controlPlaneGenerationDigest: `sha256:${"9".repeat(64)}`,
  });
  const duplicateOne = makeFile({ sessionKey: "c".repeat(64), sourceIp: "172.30.194.33" });
  const duplicateTwo = makeFile({ sessionKey: "d".repeat(64), sourceIp: "172.30.194.33" });
  const malformed = makeFile({ sessionKey: "e".repeat(64), sourceIp: "172.30.194.34", nonce: "zz" });
  const misnamed = makeFile({ sessionKey: "f".repeat(64), sourceIp: "172.30.194.35" });
  for (const file of [served, ineligible, duplicateOne, duplicateTwo, malformed]) writeSessionFile(root, file);
  writeSessionFile(root, misnamed, `${"0".repeat(64)}.json`);

  const scan = scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID });
  expect(scan.kind).toBe("ok");
  if (scan.kind !== "ok") throw new Error("unreachable");
  expect(Array.from(scan.files.keys())).toEqual([served.sessionKey]);
  // Dropped by a service rule but still on disk: present.
  expect(Array.from(scan.presentKeys).sort()).toEqual([
    served.sessionKey,
    ineligible.sessionKey,
    duplicateOne.sessionKey,
    duplicateTwo.sessionKey,
  ].sort());
  // A file that did not parse, and one that does not own the name it sits
  // under, name no key this scan may trust: neither is present.
  expect(scan.presentKeys.has(malformed.sessionKey)).toBe(false);
  expect(scan.presentKeys.has(misnamed.sessionKey)).toBe(false);
});

// I8 (launch plan Task 7, cadence change): the consumers now rescan on an
// inotify event, and the host's atomic write creates its temp file in the
// watched directory before the rename, so a scan lands inside the write window
// on every publication. A rename between the scanner's `lstat` and its `open`
// is the host replacing the file, not an attack on it: the scan must read the
// replacement, and must neither drop the session nor fail the whole scan.
function renameBeforeOpen(target: string, replacement: () => string, times: number): void {
  const realOpen = fs.openSync.bind(fs) as (...args: unknown[]) => number;
  let remaining = times;
  vi.spyOn(fs, "openSync").mockImplementation(((filePath: fs.PathLike, ...rest: unknown[]) => {
    if (remaining > 0 && String(filePath) === target) {
      remaining -= 1;
      const temporary = `${target}.${remaining}.tmp`;
      fs.writeFileSync(temporary, replacement(), { mode: 0o644 });
      fs.renameSync(temporary, target);
    }
    return realOpen(filePath, ...rest);
  }) as typeof fs.openSync);
}

describe("a host rename between lstat and open (I8)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  test("a session file replaced mid-read is read again, served, and kept present", () => {
    const root = makeRoot();
    writeEligibility(root);
    const file = makeFile({ sessionKey: "a".repeat(64), sourceIp: "172.30.194.41" });
    const target = writeSessionFile(root, file);
    const renewed = { ...file, nonce: mintSessionFileNonce() };
    renameBeforeOpen(target, () => serializeSessionFileV1(renewed), 1);

    const scan = scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID });
    expect(scan.kind).toBe("ok");
    if (scan.kind !== "ok") throw new Error("unreachable");
    expect(scan.dropped).toEqual([]);
    expect(scan.files.get(file.sessionKey)?.nonce).toBe(renewed.nonce);
    expect(scan.presentKeys.has(file.sessionKey)).toBe(true);
  });

  test("eligibility.json replaced mid-read does not make the scan unreadable", () => {
    const root = makeRoot();
    writeEligibility(root);
    const file = makeFile({ sessionKey: "b".repeat(64), sourceIp: "172.30.194.42" });
    writeSessionFile(root, file);
    renameBeforeOpen(path.join(root, "eligibility.json"), () => serializeSessionAdmissionEligibility(eligibility()), 1);

    const scan = scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID });
    expect(scan.kind).toBe("ok");
    if (scan.kind !== "ok") throw new Error("unreachable");
    expect(Array.from(scan.files.keys())).toEqual([file.sessionKey]);
  });

  test("an IP assignment replaced mid-read still yields the assignment map", () => {
    const root = makeRoot();
    const requests = path.join(root, "ip-reuse", "requests");
    fs.mkdirSync(requests, { recursive: true, mode: 0o755 });
    fs.chmodSync(path.join(root, "ip-reuse"), 0o755);
    fs.chmodSync(requests, 0o755);
    const target = path.join(requests, "172.30.194.43.json");
    const assignment = (nonce: string, state: "draining" | "ready") => `${JSON.stringify({
      v: 1,
      sourceIp: "172.30.194.43",
      sessionKey: "c".repeat(64),
      nonce,
      state,
    })}\n`;
    fs.writeFileSync(target, assignment("1".repeat(32), "draining"), { mode: 0o644 });
    renameBeforeOpen(target, () => assignment("2".repeat(32), "ready"), 1);

    const read = new SessionIpAssignments(root, OWNER_UID).read();
    expect(read).toBeDefined();
    expect(read?.get("172.30.194.43")).toMatchObject({ nonce: "2".repeat(32), state: "ready" });
  });

  test("a link count caught mid-replace (the old inode being unlinked) is read again", () => {
    // Measured on tmpfs and overlayfs: a reader racing `rename(tmp, name)`
    // sees `nlink` 0 or 2 on the name for a moment.
    const root = makeRoot();
    writeEligibility(root);
    const file = makeFile({ sessionKey: "e".repeat(64), sourceIp: "172.30.194.45" });
    const target = writeSessionFile(root, file);
    const realLstat = fs.lstatSync.bind(fs) as (...args: unknown[]) => fs.Stats;
    let transient = 1;
    vi.spyOn(fs, "lstatSync").mockImplementation(((filePath: fs.PathLike, ...rest: unknown[]) => {
      const stat = realLstat(filePath, ...rest);
      if (transient > 0 && String(filePath) === target) {
        transient -= 1;
        return Object.assign(Object.create(Object.getPrototypeOf(stat)), stat, { nlink: 0 });
      }
      return stat;
    }) as typeof fs.lstatSync);

    const scan = scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID });
    expect(scan.kind).toBe("ok");
    if (scan.kind !== "ok") throw new Error("unreachable");
    expect(scan.dropped).toEqual([]);
    expect(Array.from(scan.files.keys())).toEqual([file.sessionKey]);
  });

  test("a file that keeps changing under every bounded re-read still fails closed", () => {
    const root = makeRoot();
    writeEligibility(root);
    const file = makeFile({ sessionKey: "d".repeat(64), sourceIp: "172.30.194.44" });
    const target = writeSessionFile(root, file);
    let generation = 0;
    renameBeforeOpen(target, () => `${serializeSessionFileV1(file)}${" ".repeat(++generation)}`, 100);

    const scan = scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID });
    expect(scan.kind).toBe("ok");
    if (scan.kind !== "ok") throw new Error("unreachable");
    expect(scan.files.size).toBe(0);
    expect(scan.dropped).toEqual([{ name: `${file.sessionKey}.json`, reason: "not-regular" }]);
    // Bounded: the scanner gave up rather than chasing the writer.
    expect(generation).toBeLessThanOrEqual(4);
  });
});
