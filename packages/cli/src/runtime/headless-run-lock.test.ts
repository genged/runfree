import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, expect, test, vi } from "vitest";

import {
  acquireHeadlessRunLock,
  HEADLESS_SESSION_EVIDENCE_RETENTION_MS,
  HeadlessRunLockHeldError,
  headlessRunLockPath,
  type AcquireHeadlessRunLockInput,
} from "./headless-run-lock.ts";
import { lockHolderIsDead } from "./sessions.ts";
import type { CaptureResult } from "./types.ts";

// Pass-through by default; one test runs a step inside the liveness check.
const liveness = vi.hoisted(() => ({ during: undefined as (() => void) | undefined }));
vi.mock("./sessions.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./sessions.ts")>();
  return {
    ...actual,
    lockHolderIsDead: vi.fn((...args: Parameters<typeof actual.lockHolderIsDead>) => {
      const dead = actual.lockHolderIsDead(...args);
      liveness.during?.();
      return dead;
    }),
  };
});

const BOOT_A = "linux:11111111-2222-3333-4444-555555555555";
const BOOT_B = "linux:66666666-7777-8888-9999-aaaaaaaaaaaa";
const PROCESS_A = "linux:12345";
const PROCESS_B = "linux:67890";
const SESSION_ID = "rf-20261025-abc123";
const CONTAINER_NAME = `runfree-0123456789ab-session-${SESSION_ID}`;
const CONTAINER_ID = "a".repeat(64);

let tmp: string;
let stateDir: string;
let inboxDir: string;
let sessionsDir: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-headless-lock-"));
  stateDir = path.join(tmp, "state");
  inboxDir = path.join(stateDir, "inbox");
  sessionsDir = path.join(stateDir, "sessions");
  fs.mkdirSync(inboxDir, { recursive: true, mode: 0o700 });
});

afterEach(() => {
  liveness.during = undefined;
  vi.restoreAllMocks();
  fs.rmSync(tmp, { recursive: true, force: true });
});

function harnessEnv(bootId: string, processStart?: string): NodeJS.ProcessEnv {
  return {
    RUNFREE_TEST_FAKE_DOCKER: "1",
    RUNFREE_TEST_HOST_BOOT_ID: bootId,
    ...(processStart ? { RUNFREE_TEST_HOST_PROCESS_START: processStart } : {}),
  };
}

// A pid that has been allocated and reaped, so it is genuinely not running.
function reapedPid(): number {
  const { pid } = spawnSync("/bin/sh", ["-c", "exit 0"], { stdio: "ignore" });
  if (!pid) throw new Error("could not determine a reaped pid");
  return pid;
}

type Inspect = (ref: string) => CaptureResult;

const present: Inspect = () => ({ status: 0, stdout: `[{"Id":"${CONTAINER_ID}"}]`, stderr: "" });
const absent: Inspect = (ref) => ({ status: 1, stdout: "[]", stderr: `Error response from daemon: No such container: ${ref}\n` });
const unreachable: Inspect = () => ({
  status: 1,
  stdout: "",
  stderr: "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\n",
});

function dockerIo(inspect: Inspect) {
  const capture = vi.fn((command: string, args: string[]): CaptureResult => {
    expect(command).toBe("docker");
    expect(args.slice(0, 2)).toEqual(["container", "inspect"]);
    return inspect(args[args.length - 1] ?? "");
  });
  return { capture };
}

function input(io: { capture: ReturnType<typeof dockerIo>["capture"] }, env: NodeJS.ProcessEnv = harnessEnv(BOOT_B)): AcquireHeadlessRunLockInput {
  return { stateDir, projectId: "0123456789ab", inboxDir, sessionsDir, io, env };
}

// A lock left by another `run`: its stamps, and the session it recorded.
function writeHolder(owner: {
  pid?: number;
  boot?: string;
  processStart?: string;
  session?: Record<string, unknown>;
}): string {
  const lockPath = headlessRunLockPath(stateDir);
  fs.mkdirSync(lockPath, { recursive: true, mode: 0o700 });
  if (owner.boot !== undefined) fs.writeFileSync(path.join(lockPath, "boot"), `${owner.boot}\n`);
  if (owner.processStart !== undefined) fs.writeFileSync(path.join(lockPath, "process-start"), `${owner.processStart}\n`);
  if (owner.pid !== undefined) fs.writeFileSync(path.join(lockPath, "pid"), `${owner.pid}\n`);
  if (owner.session !== undefined) fs.writeFileSync(path.join(lockPath, "session.json"), `${JSON.stringify(owner.session)}\n`);
  return lockPath;
}

function inboxNames(): string[] {
  return fs.readdirSync(inboxDir).sort();
}

const STALE_PROMPT = "run-20261024T101010Z-0badc0de.prompt";
const IMAGE = "clip-2026-10-24-101010-abcd.png";

function seedInbox(): void {
  fs.writeFileSync(path.join(inboxDir, STALE_PROMPT), "old prompt");
  fs.writeFileSync(path.join(inboxDir, IMAGE), "png");
}

function expectHeld(fn: () => unknown): HeadlessRunLockHeldError {
  let caught: unknown;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(HeadlessRunLockHeldError);
  const held = caught as HeadlessRunLockHeldError;
  expect(held.message).toContain("runfree sessions");
  expect(held.message).toContain("runfree stop");
  return held;
}

test("acquisition prunes headless host records past the retention and keeps younger and interactive ones", () => {
  fs.mkdirSync(sessionsDir, { mode: 0o700 });
  const DAY_MS = 24 * 60 * 60 * 1000;
  expect(HEADLESS_SESSION_EVIDENCE_RETENTION_MS).toBe(7 * DAY_MS);
  const ago = (ms: number): string => new Date(Date.now() - ms).toISOString();
  const record = (id: string, fields: Record<string, unknown>): void => {
    fs.writeFileSync(path.join(sessionsDir, `${id}.json`), `${JSON.stringify({
      id,
      startedAt: ago(30 * DAY_MS),
      lastSeenAt: ago(30 * DAY_MS),
      ...fields,
    })}\n`);
  };
  record("rf-20261001-hdlold", { launchMode: "headless", endedAt: ago(8 * DAY_MS), exitStatus: 0, outcome: "interrupted" });
  // A run that crashed before its end was stamped ages by its last heartbeat.
  record("rf-20261001-hdlcrs", { launchMode: "headless", lastSeenAt: ago(8 * DAY_MS) });
  record("rf-20261001-hdlnew", { launchMode: "headless", endedAt: ago(6 * DAY_MS), exitStatus: 0, outcome: "interrupted" });
  record("rf-20261001-intold", { endedAt: ago(30 * DAY_MS), outcome: "interrupted" });
  // Not followed: a link is never read or removed as a record.
  fs.writeFileSync(path.join(tmp, "elsewhere.json"), JSON.stringify({ id: "rf-20261001-hdllnk", launchMode: "headless", endedAt: ago(30 * DAY_MS) }));
  fs.symlinkSync(path.join(tmp, "elsewhere.json"), path.join(sessionsDir, "rf-20261001-hdllnk.json"));

  acquireHeadlessRunLock(input(dockerIo(present))).release();

  expect(fs.readdirSync(sessionsDir).sort()).toEqual([
    "rf-20261001-hdllnk.json",
    "rf-20261001-hdlnew.json",
    "rf-20261001-intold.json",
  ]);
  expect(fs.existsSync(path.join(tmp, "elsewhere.json"))).toBe(true);
});

test("a fresh acquisition stamps the holder and sweeps only stale run prompts from the inbox", () => {
  seedInbox();
  const io = dockerIo(present);

  const lock = acquireHeadlessRunLock(input(io));

  const lockPath = headlessRunLockPath(stateDir);
  expect(lock.path).toBe(lockPath);
  expect(lockPath.startsWith(stateDir)).toBe(true);
  expect(fs.readFileSync(path.join(lockPath, "pid"), "utf8").trim()).toBe(String(process.pid));
  expect(fs.readFileSync(path.join(lockPath, "boot"), "utf8").trim()).toBe(BOOT_B);
  expect(inboxNames()).toEqual([IMAGE]);
  expect(io.capture).not.toHaveBeenCalled();
  lock.release();
  expect(fs.existsSync(lockPath)).toBe(false);
});

test("a live holder refuses before any side effect: no Docker call, no inbox change, lock untouched", () => {
  seedInbox();
  const lockPath = writeHolder({ pid: process.pid, boot: BOOT_B, session: { v: 1, sessionId: SESSION_ID, containerName: CONTAINER_NAME } });
  const before = fs.readdirSync(lockPath).sort();
  const io = dockerIo(absent);

  const held = expectHeld(() => acquireHeadlessRunLock(input(io)));

  expect(held.holder.pid).toBe(process.pid);
  expect(held.holder.containerName).toBe(CONTAINER_NAME);
  expect(io.capture).not.toHaveBeenCalled();
  expect(inboxNames()).toEqual([IMAGE, STALE_PROMPT].sort());
  expect(fs.readdirSync(lockPath).sort()).toEqual(before);
});

test("a second acquisition in the same live process refuses while the first is held", () => {
  const io = dockerIo(absent);
  const lock = acquireHeadlessRunLock(input(io));
  expectHeld(() => acquireHeadlessRunLock(input(io)));
  lock.release();
  acquireHeadlessRunLock(input(io)).release();
});

test("a dead holder that recorded no session is reclaimed without a Docker call", () => {
  seedInbox();
  writeHolder({ pid: reapedPid(), boot: BOOT_B });
  const io = dockerIo(present);

  const lock = acquireHeadlessRunLock(input(io));

  expect(io.capture).not.toHaveBeenCalled();
  expect(fs.readFileSync(path.join(lock.path, "pid"), "utf8").trim()).toBe(String(process.pid));
  expect(fs.existsSync(path.join(lock.path, "session.json"))).toBe(false);
  expect(inboxNames()).toEqual([IMAGE]);
  lock.release();
});

test("a session the holder records while its liveness is judged is honored: reclaim still needs its container gone", () => {
  // The holder records its session, then crashes, between the contender's
  // first look and its liveness verdict. A read taken before the verdict would
  // see no session and reclaim without asking Docker.
  const lockPath = writeHolder({ pid: reapedPid(), boot: BOOT_B });
  liveness.during = () => {
    fs.writeFileSync(path.join(lockPath, "session.json"), `${JSON.stringify({ v: 1, sessionId: SESSION_ID, containerName: CONTAINER_NAME, containerId: CONTAINER_ID })}\n`);
  };
  const io = dockerIo(present);

  const held = expectHeld(() => acquireHeadlessRunLock(input(io)));

  expect(lockHolderIsDead).toHaveBeenCalled();
  expect(held.holder.containerId).toBe(CONTAINER_ID);
  expect(io.capture.mock.calls[0]?.[1]).toEqual(["container", "inspect", CONTAINER_ID]);
});

test("a reclaim whose rename moves a replacement lock refuses instead of taking the lock again", () => {
  // A passes the ownership check on the dead holder's lock; B reclaims it and
  // stamps its own before A's rename, which then quarantines B's lock. A must
  // not mkdir again: nothing proved B dead or its container gone.
  seedInbox();
  const lockPath = writeHolder({ pid: reapedPid(), boot: BOOT_B });
  fs.writeFileSync(path.join(lockPath, "owner-token"), `${"1".repeat(64)}\n`);
  const originalRename = fs.renameSync;
  let replaced = false;
  vi.spyOn(fs, "renameSync").mockImplementation((from, to) => {
    if (!replaced && from === lockPath) {
      replaced = true;
      fs.rmSync(lockPath, { recursive: true, force: true });
      // Same inode is possible after rm + mkdir; the owner token tells them apart.
      writeHolder({ pid: process.pid, boot: BOOT_B, processStart: PROCESS_B });
      fs.writeFileSync(path.join(lockPath, "owner-token"), `${"2".repeat(64)}\n`);
    }
    originalRename(from, to);
  });
  const mkdir = vi.spyOn(fs, "mkdirSync");
  const io = dockerIo(absent);

  expectHeld(() => acquireHeadlessRunLock(input(io)));

  expect(replaced).toBe(true);
  // One acquire mkdir (non-recursive); the replacement's mkdir is recursive.
  const acquireAttempts = mkdir.mock.calls.filter(([target, options]) => target === lockPath && !(typeof options === "object" && options?.recursive));
  expect(acquireAttempts).toHaveLength(1);
  expect(fs.existsSync(lockPath)).toBe(false);
  const quarantined = fs.readdirSync(stateDir).filter((name) => name.startsWith("headless-run.lock.quarantine-"));
  expect(quarantined).toHaveLength(1);
  expect(fs.readFileSync(path.join(stateDir, quarantined[0] ?? "", "pid"), "utf8").trim()).toBe(String(process.pid));
  expect(inboxNames()).toEqual([IMAGE, STALE_PROMPT].sort());
});

// A dead holder whose session record cannot be read: before, a permanent 66
// whose remedy named a container nobody could read. Docker's list of this
// project's session containers decides instead.
function listingIo(answer: CaptureResult) {
  const capture = vi.fn((command: string, args: string[]): CaptureResult => {
    expect(command).toBe("docker");
    expect(args[0]).toBe("ps");
    expect(args).toContain("--all");
    expect(args).toContain("label=io.runfree.project-id=0123456789ab");
    expect(args).toContain("label=io.runfree.container-role=session-agent");
    return answer;
  });
  return { capture };
}

test("a dead holder with an unreadable session record is reclaimed once the project has no session containers", () => {
  seedInbox();
  writeHolder({ pid: reapedPid(), boot: BOOT_B, session: { v: 1, sessionId: "not a session id" } });
  const io = listingIo({ status: 0, stdout: "", stderr: "" });

  const lock = acquireHeadlessRunLock(input(io));

  expect(io.capture).toHaveBeenCalledTimes(1);
  expect(inboxNames()).toEqual([IMAGE]);
  lock.release();
});

test("a dead holder with an unreadable session record keeps the lock while the project has a session container, naming `runfree up`", () => {
  writeHolder({ pid: reapedPid(), boot: BOOT_B, session: { v: 1, sessionId: "not a session id" } });
  const held = expectHeld(() => acquireHeadlessRunLock(input(listingIo({ status: 0, stdout: `${CONTAINER_ID}\n`, stderr: "" }))));
  expect(held.message).toContain("still has 1 session container(s)");
  expect(held.message).toContain("runfree up");
  // A listing Docker cannot make proves nothing either.
  expectHeld(() => acquireHeadlessRunLock(input(listingIo(unreachable("")))));
  expect(fs.existsSync(path.join(headlessRunLockPath(stateDir), "session.json"))).toBe(true);
});

test("a dead holder whose container inspects as present keeps the lock", () => {
  seedInbox();
  writeHolder({ pid: reapedPid(), boot: BOOT_B, session: { v: 1, sessionId: SESSION_ID, containerName: CONTAINER_NAME, containerId: CONTAINER_ID } });
  const io = dockerIo(present);

  const held = expectHeld(() => acquireHeadlessRunLock(input(io)));

  expect(held.holder.containerId).toBe(CONTAINER_ID);
  expect(io.capture).toHaveBeenCalledTimes(1);
  expect(io.capture.mock.calls[0]?.[1]).toEqual(["container", "inspect", CONTAINER_ID]);
  expect(inboxNames()).toEqual([IMAGE, STALE_PROMPT].sort());
});

test("a dead holder whose inspection fails with a Docker connection error keeps the lock", () => {
  writeHolder({ pid: reapedPid(), boot: BOOT_B, session: { v: 1, sessionId: SESSION_ID, containerName: CONTAINER_NAME, containerId: CONTAINER_ID } });
  const io = dockerIo(unreachable);

  expectHeld(() => acquireHeadlessRunLock(input(io)));
  expect(fs.existsSync(path.join(headlessRunLockPath(stateDir), "session.json"))).toBe(true);
});

test("a dead holder whose container is proven absent by id is reclaimed", () => {
  seedInbox();
  writeHolder({ pid: reapedPid(), boot: BOOT_B, session: { v: 1, sessionId: SESSION_ID, containerName: CONTAINER_NAME, containerId: CONTAINER_ID } });
  const io = dockerIo(absent);

  const lock = acquireHeadlessRunLock(input(io));

  expect(io.capture.mock.calls[0]?.[1]).toEqual(["container", "inspect", CONTAINER_ID]);
  expect(fs.existsSync(path.join(lock.path, "session.json"))).toBe(false);
  expect(inboxNames()).toEqual([IMAGE]);
  lock.release();
});

test("an absence answer naming a different container proves nothing", () => {
  writeHolder({ pid: reapedPid(), boot: BOOT_B, session: { v: 1, sessionId: SESSION_ID, containerName: CONTAINER_NAME, containerId: CONTAINER_ID } });
  const io = dockerIo(() => ({ status: 1, stdout: "", stderr: `Error response from daemon: No such container: ${"b".repeat(64)}\n` }));

  expectHeld(() => acquireHeadlessRunLock(input(io)));
});

test("a holder that crashed before create returned is judged by its container name", () => {
  writeHolder({ pid: reapedPid(), boot: BOOT_B, session: { v: 1, sessionId: SESSION_ID, containerName: CONTAINER_NAME } });

  const presentIo = dockerIo(present);
  expectHeld(() => acquireHeadlessRunLock(input(presentIo)));
  expect(presentIo.capture.mock.calls[0]?.[1]).toEqual(["container", "inspect", CONTAINER_NAME]);

  const absentIo = dockerIo(absent);
  const lock = acquireHeadlessRunLock(input(absentIo));
  expect(absentIo.capture.mock.calls[0]?.[1]).toEqual(["container", "inspect", CONTAINER_NAME]);
  lock.release();
});

test("a previous-boot lock whose PID is reused by a live process is dead but still needs container absence", () => {
  writeHolder({ pid: process.pid, boot: BOOT_A, session: { v: 1, sessionId: SESSION_ID, containerName: CONTAINER_NAME, containerId: CONTAINER_ID } });

  expectHeld(() => acquireHeadlessRunLock(input(dockerIo(present), harnessEnv(BOOT_B))));
  const io = dockerIo(absent);
  const lock = acquireHeadlessRunLock(input(io, harnessEnv(BOOT_B)));
  expect(io.capture).toHaveBeenCalledTimes(1);
  lock.release();
});

test("a PID reused within this boot (process-start mismatch) is dead but still needs container absence", () => {
  writeHolder({ pid: process.pid, boot: BOOT_B, processStart: PROCESS_A, session: { v: 1, sessionId: SESSION_ID, containerName: CONTAINER_NAME } });

  expectHeld(() => acquireHeadlessRunLock(input(dockerIo(present), harnessEnv(BOOT_B, PROCESS_B))));
  acquireHeadlessRunLock(input(dockerIo(absent), harnessEnv(BOOT_B, PROCESS_B))).release();
});

test("a pid-less lock inside the acquisition grace is kept; past it, it is reclaimed", () => {
  const lockPath = writeHolder({});
  const io = dockerIo(absent);
  expectHeld(() => acquireHeadlessRunLock(input(io)));

  const old = new Date(Date.now() - 60_000);
  fs.utimesSync(lockPath, old, old);
  acquireHeadlessRunLock(input(io)).release();
  expect(io.capture).not.toHaveBeenCalled();
});

test("a malformed session record in a dead holder's lock keeps the lock and names its path while a container remains", () => {
  const lockPath = writeHolder({ pid: reapedPid(), boot: BOOT_B, session: { v: 1, sessionId: SESSION_ID, containerName: "--format=x" } });
  const io = listingIo({ status: 0, stdout: `${CONTAINER_ID}\n`, stderr: "" });

  const held = expectHeld(() => acquireHeadlessRunLock(input(io)));

  expect(held.message).toContain(lockPath);
  // The unreadable record is never handed to Docker as a reference; only the
  // project's labels are.
  expect(io.capture.mock.calls.every(([, args]) => !args.includes("--format=x"))).toBe(true);
});

test("recordSession and recordContainer name the session; release removes only an owned lock", () => {
  const lock = acquireHeadlessRunLock(input(dockerIo(absent)));
  lock.recordSession({ sessionId: SESSION_ID, containerName: CONTAINER_NAME });
  expect(JSON.parse(fs.readFileSync(path.join(lock.path, "session.json"), "utf8"))).toEqual({
    v: 1,
    sessionId: SESSION_ID,
    containerName: CONTAINER_NAME,
  });
  lock.recordContainer(CONTAINER_ID);
  expect(JSON.parse(fs.readFileSync(path.join(lock.path, "session.json"), "utf8"))).toEqual({
    v: 1,
    sessionId: SESSION_ID,
    containerName: CONTAINER_NAME,
    containerId: CONTAINER_ID,
  });
  expect(() => lock.recordContainer("not-an-id")).toThrow(/container id/);
  expect(() => lock.recordSession({ sessionId: SESSION_ID, containerName: "other" })).toThrow(/container name/);

  // Another process replaced the lock: this process no longer owns it.
  fs.rmSync(lock.path, { recursive: true });
  writeHolder({ pid: process.pid, boot: BOOT_B });
  expect(() => lock.release()).toThrow(/replaced/);
  expect(() => lock.recordContainer(CONTAINER_ID)).toThrow(/ownership/);
  expect(fs.existsSync(headlessRunLockPath(stateDir))).toBe(true);
});

test("recordContainer before recordSession is refused", () => {
  const lock = acquireHeadlessRunLock(input(dockerIo(absent)));
  expect(() => lock.recordContainer(CONTAINER_ID)).toThrow(/session/);
  lock.release();
});

test("a lock kept after an unconfirmed teardown refuses until its container is gone, then is reclaimed", () => {
  // The orchestrator keeps the lock when the stop was not confirmed (spec
  // §3.5 step 4): it never calls release, and its process then exits.
  const first = acquireHeadlessRunLock(input(dockerIo(absent)));
  first.recordSession({ sessionId: SESSION_ID, containerName: CONTAINER_NAME });
  first.recordContainer(CONTAINER_ID);
  // The holder exits without releasing.
  fs.writeFileSync(path.join(first.path, "pid"), `${reapedPid()}\n`);
  seedInbox();

  expectHeld(() => acquireHeadlessRunLock(input(dockerIo(present))));
  expectHeld(() => acquireHeadlessRunLock(input(dockerIo(unreachable))));
  expect(inboxNames()).toEqual([IMAGE, STALE_PROMPT].sort());

  // The operator removes the container (`runfree stop`); the next run reclaims.
  const next = acquireHeadlessRunLock(input(dockerIo(absent)));
  expect(inboxNames()).toEqual([IMAGE]);
  next.release();
});

test("the inbox sweep leaves non-matching names, directories, and a missing inbox alone", () => {
  fs.writeFileSync(path.join(inboxDir, "run-notadate.prompt"), "x");
  fs.writeFileSync(path.join(inboxDir, `${STALE_PROMPT}.bak`), "x");
  fs.mkdirSync(path.join(inboxDir, "run-20261024T101010Z-0badc0d1.prompt"));
  acquireHeadlessRunLock(input(dockerIo(absent))).release();
  expect(inboxNames()).toEqual(["run-20261024T101010Z-0badc0d1.prompt", "run-notadate.prompt", `${STALE_PROMPT}.bak`].sort());

  fs.rmSync(inboxDir, { recursive: true });
  acquireHeadlessRunLock(input(dockerIo(absent))).release();
  expect(fs.existsSync(inboxDir)).toBe(false);
});
