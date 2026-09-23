import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, expect, test, vi } from "vitest";

import type { RuntimeDocker } from "./docker.ts";
import { composeProjectName, projectHash } from "./env.ts";
import {
  CONTROL_PLANE_PROOF_SCHEMA_VERSION,
  createControlPlaneGenerationV2,
  createControlPlaneMaterializationManifestV2,
  publishControlPlaneMaterializationV2,
  selectEffectiveControlPlaneV2,
} from "./component-state-v2.ts";
import { sha256Digest } from "./component-state.ts";
import { sessionContainerRecordFixture } from "./session-container.test-harness.ts";
import { writeSessionContainerRecordV2 } from "./session-containers.ts";
import { writeSessionHostStatus } from "./session-host-status.ts";
import {
  activeOrStartingAgentSessions,
  createSessionLockManager,
  createSessionMetadata,
  normalizeSessionName,
  parseActiveAgentSessionsForTest,
  printSessions,
  projectLifecycleLockPath,
  warnDeferredRuntimeUpgrade,
  readSessionMetadata,
  renameSessionMetadata,
  SessionLockAcquisitionAbortedError,
  SessionLockAcquisitionTimeoutError,
  sessionCommandLabelForTest,
  sessionEnvOptions,
  stampLockOwner,
  synthesizeSessionName,
  tryAcquireProjectLifecycleLock,
  tryAcquireProjectLifecycleLockWithRetry,
  writeSessionMetadata,
} from "./sessions.ts";
import { flushWarnings } from "../warnings.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

const BOOT_A = "linux:11111111-2222-3333-4444-555555555555";
const BOOT_B = "linux:66666666-7777-8888-9999-aaaaaaaaaaaa";
const PROCESS_A = "linux:12345";
const PROCESS_B = "linux:67890";

// Boot identity is a property of the machine, so the override that pins it is
// honored only under the fake-docker harness; production contexts never carry
// it. See `hostBootId`.
function harnessEnv(bootId: string, processStart?: string): NodeJS.ProcessEnv {
  return {
    RUNFREE_TEST_FAKE_DOCKER: "1",
    RUNFREE_TEST_HOST_BOOT_ID: bootId,
    ...(processStart ? { RUNFREE_TEST_HOST_PROCESS_START: processStart } : {}),
  };
}

const context = {
  projectRoot: "/workspace/project",
  project: {
    config: {},
    paths: { sessionsDir: "/state/sessions" },
  },
  runtimeRoot: "/runtime",
} as unknown as RuntimeContext;

test("labels known agent commands", () => {
  expect(sessionCommandLabelForTest("claude")).toContain("Claude");
  expect(sessionCommandLabelForTest("codex")).toContain("Codex");
});

test("parses active session process output", () => {
  const sessions = parseActiveAgentSessionsForTest("123\tpts/0\tclaude --dangerously-skip-permissions\n", context);
  expect(sessions).toHaveLength(1);
  expect(sessions[0]?.command).toContain("Claude");
  expect(sessions[0]?.processCount).toBe(1);
});

test("a deferred runtime upgrade warns with the active session and the rebuild hint", () => {
  const sessions = parseActiveAgentSessionsForTest("123\tpts/0\tclaude --dangerously-skip-permissions\n", context);
  const errors: string[] = [];
  const spy = vi.spyOn(console, "error").mockImplementation((message?: unknown) => { errors.push(String(message)); });
  try {
    warnDeferredRuntimeUpgrade({ reason: "full recreate", services: ["proxy"], sessions });
    flushWarnings();
  } finally {
    spy.mockRestore();
  }
  const output = errors.join("\n");
  expect(output).toContain("the runtime was not upgraded");
  expect(output).toContain("Claude");
  expect(output).toContain("run `runfree rebuild` when those sessions can be stopped");
  expect(output).toContain("the runtime was not upgraded");
});

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-sessions-"));
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  fs.rmSync(tmp, { recursive: true, force: true });
});

function hostContext(env: NodeJS.ProcessEnv = {}): RuntimeContext {
  const projectRoot = path.join(tmp, "project");
  const stateDir = path.join(tmp, "state");
  fs.mkdirSync(projectRoot, { recursive: true });
  return {
    projectRoot,
    project: {
      config: {},
      paths: { inboxDir: path.join(stateDir, "inbox"), stateDir, sessionsDir: path.join(stateDir, "sessions") },
    },
    runtimeRoot: path.join(tmp, "runtime"),
    env,
  } as unknown as RuntimeContext;
}

function writeLifecycleLock(
  runtimeContext: RuntimeContext,
  owner: { pid?: number; boot?: string },
): string {
  const lockPath = projectLifecycleLockPath(runtimeContext);
  fs.mkdirSync(lockPath, { recursive: true });
  if (owner.pid !== undefined) fs.writeFileSync(path.join(lockPath, "pid"), `${owner.pid}\n`);
  if (owner.boot !== undefined) fs.writeFileSync(path.join(lockPath, "boot"), `${owner.boot}\n`);
  return lockPath;
}

// A pid that has been allocated and reaped, so it is genuinely not running.
function reapedPid(): number {
  const { pid } = spawnSync("/bin/sh", ["-c", "exit 0"], { stdio: "ignore" });
  if (!pid) throw new Error("could not determine a reaped pid");
  return pid;
}

test("reclaims a lifecycle lock stamped with a previous boot", () => {
  // The wedge this prevents: power loss during `runfree up` leaves the lock
  // behind, then after the reboot its pid is reissued to an unrelated live
  // process (here, the test runner) and PID liveness alone reports it held.
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const lockPath = writeLifecycleLock(runtimeContext, { pid: process.pid, boot: BOOT_A });

  const lock = tryAcquireProjectLifecycleLock(runtimeContext);

  expect(lock).toBeDefined();
  expect(fs.readFileSync(path.join(lockPath, "boot"), "utf8").trim()).toBe(BOOT_B);
  lock?.release();
});

test("leaves a lifecycle lock held on the current boot alone", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  writeLifecycleLock(runtimeContext, { pid: process.pid, boot: BOOT_B });

  expect(tryAcquireProjectLifecycleLock(runtimeContext)).toBeUndefined();
});

test("reclaims a lifecycle lock whose pid was reused within the current boot", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B, PROCESS_B));
  const lockPath = writeLifecycleLock(runtimeContext, { pid: process.pid, boot: BOOT_B });
  fs.writeFileSync(path.join(lockPath, "process-start"), `${PROCESS_A}\n`);

  const lock = tryAcquireProjectLifecycleLock(runtimeContext);

  expect(lock).toBeDefined();
  expect(fs.readFileSync(path.join(lockPath, "process-start"), "utf8").trim()).toBe(PROCESS_B);
  lock?.release();
});

test("the retrying acquire rides out a short-lived holder and acquires", async () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const holder = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(holder).toBeDefined();
  // Released mid-retry-window: the concrete contender this models is a
  // concurrent resume selector's claim check, which holds for milliseconds.
  setTimeout(() => holder?.release(), 150);

  const lock = await tryAcquireProjectLifecycleLockWithRetry(runtimeContext, { attempts: 10, delayMs: 50 });

  expect(lock).toBeDefined();
  lock?.release();
});

test("the retrying acquire still defers to a holder that outlives the window", async () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const holder = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(holder).toBeDefined();

  const lock = await tryAcquireProjectLifecycleLockWithRetry(runtimeContext, { attempts: 3, delayMs: 20 });

  expect(lock).toBeUndefined();
  holder?.release();
});

test("the default retry window outlasts a multi-second renewal critical section", async () => {
  vi.useFakeTimers();
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const holder = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(holder).toBeDefined();
  const settled = vi.fn();
  const errors: string[] = [];
  const errorSpy = vi.spyOn(console, "error").mockImplementation((message?: unknown) => {
    errors.push(String(message));
  });

  try {
    setTimeout(() => holder?.release(), 5_500);
    const waiting = tryAcquireProjectLifecycleLockWithRetry(runtimeContext);
    void waiting.then(settled);

    await vi.advanceTimersByTimeAsync(2_000);
    expect(settled).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(4_000);
    expect(errors.join("\n")).toContain(projectLifecycleLockPath(runtimeContext));
    const lock = await waiting;
    expect(lock).toBeDefined();
    lock?.release();
  } finally {
    holder?.release();
    errorSpy.mockRestore();
    vi.useRealTimers();
  }
});

test("a session lock manager leaves the project lock free while attached", async () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const initial = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(initial).toBeDefined();
  if (!initial) return;
  const manager = createSessionLockManager(runtimeContext, initial, { retryDelayMs: 5 });

  expect(() => manager.lock.release()).toThrow("session lock manager owns project lifecycle lock release");
  manager.lock.assertHeld();
  manager.releaseForWait();
  const concurrent = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(concurrent).toBeDefined();
  concurrent?.release();

  await manager.reacquire();
  manager.lock.assertHeld();
  expect(tryAcquireProjectLifecycleLock(runtimeContext)).toBeUndefined();
  manager.close();

  const after = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(after).toBeDefined();
  after?.release();
});

test("a session lock manager reacquires only for its renewal critical section", async () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const initial = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(initial).toBeDefined();
  if (!initial) return;
  const manager = createSessionLockManager(runtimeContext, initial, { retryDelayMs: 5 });
  manager.releaseForWait();

  let enterCritical: (() => void) | undefined;
  const entered = new Promise<void>((resolve) => { enterCritical = resolve; });
  let leaveCritical: (() => void) | undefined;
  const leave = new Promise<void>((resolve) => { leaveCritical = resolve; });
  const critical = manager.withLock(async () => {
    manager.lock.assertHeld();
    enterCritical?.();
    await leave;
  }, new AbortController().signal);

  await entered;
  expect(tryAcquireProjectLifecycleLock(runtimeContext)).toBeUndefined();
  leaveCritical?.();
  await critical;

  const betweenRenewals = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(betweenRenewals).toBeDefined();
  betweenRenewals?.release();
  await manager.reacquire();
  manager.close();
});

test("teardown lock waiting periodically names the contended lock", async () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const initial = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(initial).toBeDefined();
  if (!initial) return;
  const manager = createSessionLockManager(runtimeContext, initial, {
    retryDelayMs: 5,
    diagnosticIntervalMs: 10,
  });
  manager.releaseForWait();
  const contender = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(contender).toBeDefined();
  const errors: string[] = [];
  const errorSpy = vi.spyOn(console, "error").mockImplementation((message?: unknown) => {
    errors.push(String(message));
  });

  const teardown = manager.reacquire();
  await new Promise((resolve) => setTimeout(resolve, 30));
  expect(errors.join("\n")).toContain(projectLifecycleLockPath(runtimeContext));

  contender?.release();
  await teardown;
  manager.close();
  errorSpy.mockRestore();
});

test("a session lock manager bounds teardown lock acquisition", async () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const initial = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(initial).toBeDefined();
  if (!initial) return;
  const manager = createSessionLockManager(runtimeContext, initial, {
    retryDelayMs: 5,
    reacquisitionTimeoutMs: 20,
  });
  manager.releaseForWait();
  const contender = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(contender).toBeDefined();

  await expect(manager.reacquire()).rejects.toBeInstanceOf(SessionLockAcquisitionTimeoutError);

  contender?.release();
  await manager.reacquire();
  manager.close();
});

test("foreground completion cancels a queued renewal lock acquisition", async () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const initial = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(initial).toBeDefined();
  if (!initial) return;
  const manager = createSessionLockManager(runtimeContext, initial, { retryDelayMs: 5 });
  manager.releaseForWait();
  const contender = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(contender).toBeDefined();
  const operation = vi.fn(async () => undefined);
  const cancellation = new AbortController();

  const critical = manager.withLock(operation, cancellation.signal);
  cancellation.abort();
  await expect(critical).rejects.toBeInstanceOf(SessionLockAcquisitionAbortedError);
  expect(operation).not.toHaveBeenCalled();

  contender?.release();
  await manager.reacquire();
  manager.close();
});

test("renewal waiting is not cut off by the teardown reacquisition timeout", async () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const initial = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(initial).toBeDefined();
  if (!initial) return;
  const manager = createSessionLockManager(runtimeContext, initial, {
    retryDelayMs: 5,
    reacquisitionTimeoutMs: 20,
  });
  manager.releaseForWait();
  const contender = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(contender).toBeDefined();
  const operation = vi.fn(async () => undefined);
  const errors: string[] = [];
  const errorSpy = vi.spyOn(console, "error").mockImplementation((message?: unknown) => {
    errors.push(String(message));
  });

  const critical = manager.withLock(operation, new AbortController().signal);
  await new Promise((resolve) => setTimeout(resolve, 35));
  expect(operation).not.toHaveBeenCalled();
  expect(errors).toEqual([]);

  contender?.release();
  await critical;
  expect(operation).toHaveBeenCalledOnce();
  await manager.reacquire();
  manager.close();
  errorSpy.mockRestore();
});

test("a failed renewal critical section retains the lock into teardown", async () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const initial = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(initial).toBeDefined();
  if (!initial) return;
  const manager = createSessionLockManager(runtimeContext, initial, { retryDelayMs: 5 });
  const renewalFailure = new Error("renewal failed after compensation");
  manager.releaseForWait();

  await expect(manager.withLock(
    async () => { throw renewalFailure; },
    new AbortController().signal,
  )).rejects.toBe(renewalFailure);
  manager.lock.assertHeld();
  expect(tryAcquireProjectLifecycleLock(runtimeContext)).toBeUndefined();
  await manager.reacquire();
  expect(tryAcquireProjectLifecycleLock(runtimeContext)).toBeUndefined();

  manager.close();
  const afterTeardown = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(afterTeardown).toBeDefined();
  afterTeardown?.release();
});

test("failed post-acquisition validation releases the newly acquired lock", async () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const initial = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(initial).toBeDefined();
  if (!initial) return;
  const manager = createSessionLockManager(runtimeContext, initial, { retryDelayMs: 5 });
  manager.releaseForWait();
  const lockPath = projectLifecycleLockPath(runtimeContext);
  const tokenPath = path.join(lockPath, "owner-token");
  const originalReadFileSync = fs.readFileSync.bind(fs);
  let tokenReads = 0;
  const readSpy = vi.spyOn(fs, "readFileSync").mockImplementation(((...args: unknown[]) => {
    if (String(args[0]) === tokenPath) {
      tokenReads += 1;
      // The first read validates acquisition. Fail only the immediate manager
      // validation, then let its exact release observe the real token.
      if (tokenReads === 2) return `${"0".repeat(64)}\n`;
    }
    return Reflect.apply(originalReadFileSync, fs, args);
  }) as typeof fs.readFileSync);
  const operation = vi.fn(async () => undefined);

  try {
    await expect(manager.withLock(operation, new AbortController().signal)).rejects.toThrow(
      "project lifecycle lock ownership was lost or replaced",
    );
  } finally {
    readSpy.mockRestore();
  }

  expect(operation).not.toHaveBeenCalled();
  expect(fs.existsSync(lockPath)).toBe(false);
  await manager.reacquire();
  manager.close();
});

test("a session lock manager does not stay critical when exact release is refused", async () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const initial = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(initial).toBeDefined();
  if (!initial) return;
  const manager = createSessionLockManager(runtimeContext, initial, { retryDelayMs: 5 });
  manager.releaseForWait();
  const lockPath = projectLifecycleLockPath(runtimeContext);

  await expect(manager.withLock(async () => {
    fs.writeFileSync(path.join(lockPath, "owner-token"), `${"0".repeat(64)}\n`);
  }, new AbortController().signal)).rejects.toThrow("refusing to release a replaced project lifecycle lock");

  expect(() => manager.close()).not.toThrow();
  fs.rmSync(lockPath, { recursive: true, force: true });
});

test("a session lock manager closes its state even when initial release fails", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const releaseFailure = new Error("release failed");
  const manager = createSessionLockManager(runtimeContext, {
    ownerToken: "f".repeat(64),
    assertHeld: vi.fn(),
    release: vi.fn(() => { throw releaseFailure; }),
  });

  expect(() => manager.releaseForWait()).toThrow(releaseFailure);
  expect(() => manager.close()).not.toThrow();
});

test("leaves a legacy pid-only lifecycle lock held by a live process alone", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  writeLifecycleLock(runtimeContext, { pid: process.pid });

  expect(tryAcquireProjectLifecycleLock(runtimeContext)).toBeUndefined();
});

test("leaves a lifecycle lock with a corrupt boot stamp held by a live process alone", () => {
  // The boot check runs before the PID check and short-circuits it, so a
  // truncated stamp that merely compares unequal must not read as a previous
  // boot — that would delete a lock whose owner is still running.
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  writeLifecycleLock(runtimeContext, { pid: process.pid, boot: "linux:11111111" });

  expect(tryAcquireProjectLifecycleLock(runtimeContext)).toBeUndefined();
});

test("does not steal a pid-less lifecycle lock inside the acquisition grace", () => {
  // mkdir is the acquire primitive and the pid file is written a step later;
  // deleting the lock in that window would put two processes in the critical
  // section.
  const runtimeContext = hostContext();
  writeLifecycleLock(runtimeContext, {});

  expect(tryAcquireProjectLifecycleLock(runtimeContext)).toBeUndefined();
});

test("stamps a lock with the boot id it is handed and derives none itself", () => {
  // The ordering property behind the acquisition window: callers resolve boot
  // identity *before* mkdir, so `stampLockOwner` must be two plain writes. If
  // it derived its own id, on macOS that would put a `sysctl` spawn between the
  // atomic acquire and the pid write, leaving the lock pid-less for the length
  // of the probe — exactly when a contender may steal it. Both assertions here
  // fail if the derivation moves back inside.
  const lockPath = path.join(tmp, "handed.lock");
  fs.mkdirSync(lockPath);
  stampLockOwner(lockPath, BOOT_A, PROCESS_A);
  expect(fs.readFileSync(path.join(lockPath, "boot"), "utf8").trim()).toBe(BOOT_A);
  expect(fs.readFileSync(path.join(lockPath, "process-start"), "utf8").trim()).toBe(PROCESS_A);
  expect(fs.readFileSync(path.join(lockPath, "pid"), "utf8").trim()).toBe(String(process.pid));

  // Handed nothing, it records nothing — even on a host where a boot id is
  // derivable. A stamp that appeared here would prove the probe ran inside.
  const unprovable = path.join(tmp, "unprovable.lock");
  fs.mkdirSync(unprovable);
  stampLockOwner(unprovable, undefined);
  expect(fs.existsSync(path.join(unprovable, "boot"))).toBe(false);
  expect(fs.existsSync(path.join(unprovable, "pid"))).toBe(true);
});

test("never leaves an acquired lifecycle lock unstamped", () => {
  // An unstamped lock is worse than no lock: nothing can attribute it, so only
  // the pid-less grace can ever reclaim it. Acquisition must either produce a
  // fully stamped lock or none at all.
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const lock = tryAcquireProjectLifecycleLock(runtimeContext);

  expect(lock).toBeDefined();
  const lockPath = projectLifecycleLockPath(runtimeContext);
  expect(fs.readFileSync(path.join(lockPath, "boot"), "utf8").trim()).toBe(BOOT_B);
  expect(fs.readFileSync(path.join(lockPath, "pid"), "utf8").trim()).toBe(String(process.pid));
  expect(lock?.ownerToken).toMatch(/^[a-f0-9]{64}$/);
  expect(fs.readFileSync(path.join(lockPath, "owner-token"), "utf8").trim()).toBe(lock?.ownerToken);
  expect(() => lock?.assertHeld()).not.toThrow();
  lock?.release();
  expect(fs.existsSync(lockPath)).toBe(false);
  expect(() => lock?.assertHeld()).toThrow("ownership was lost or replaced");
});

test("assertHeld and release reject a replacement lock even when it copies the owner token", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const lock = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(lock).toBeDefined();
  if (!lock) return;

  const lockPath = projectLifecycleLockPath(runtimeContext);
  const displacedPath = `${lockPath}.displaced`;
  fs.renameSync(lockPath, displacedPath);
  fs.mkdirSync(lockPath, { mode: 0o700 });
  fs.writeFileSync(path.join(lockPath, "owner-token"), `${lock.ownerToken}\n`, { mode: 0o600 });
  fs.writeFileSync(path.join(lockPath, "replacement-marker"), "live replacement\n", { mode: 0o600 });

  expect(() => lock.assertHeld()).toThrow("ownership was lost or replaced");
  expect(() => lock.release()).toThrow("refusing to release a replaced");
  expect(fs.readFileSync(path.join(lockPath, "replacement-marker"), "utf8")).toBe("live replacement\n");
});

test("release preserves a replacement that wins after the ownership check", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const lock = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(lock).toBeDefined();
  if (!lock) return;

  const lockPath = projectLifecycleLockPath(runtimeContext);
  const displacedPath = `${lockPath}.displaced-during-release`;
  const renameSync = fs.renameSync.bind(fs);
  let replaced = false;
  vi.spyOn(fs, "renameSync").mockImplementation(((source, destination) => {
    if (!replaced && source === lockPath) {
      replaced = true;
      renameSync(lockPath, displacedPath);
      fs.mkdirSync(lockPath, { mode: 0o700 });
      fs.writeFileSync(path.join(lockPath, "owner-token"), `${"b".repeat(64)}\n`, { mode: 0o600 });
      fs.writeFileSync(path.join(lockPath, "replacement-marker"), "release-race replacement\n", { mode: 0o600 });
    }
    return renameSync(source, destination);
  }) as typeof fs.renameSync);

  expect(() => lock.release()).toThrow("refusing to release a replaced");
  const quarantines = fs.readdirSync(path.dirname(lockPath))
    .filter((entry) => entry.startsWith(`${path.basename(lockPath)}.quarantine-`));
  expect(quarantines).toHaveLength(1);
  expect(fs.readFileSync(path.join(path.dirname(lockPath), quarantines[0] as string, "replacement-marker"), "utf8"))
    .toBe("release-race replacement\n");
});

test("stale reclaim quarantines rather than deleting a replacement won during the reclaim race", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const lockPath = writeLifecycleLock(runtimeContext, { pid: process.pid, boot: BOOT_A });
  const stalePath = `${lockPath}.stale-before-race`;
  const renameSync = fs.renameSync.bind(fs);
  let replaced = false;
  vi.spyOn(fs, "renameSync").mockImplementation(((source, destination) => {
    if (!replaced && source === lockPath) {
      replaced = true;
      renameSync(lockPath, stalePath);
      fs.mkdirSync(lockPath, { mode: 0o700 });
      fs.writeFileSync(path.join(lockPath, "owner-token"), `${"a".repeat(64)}\n`, { mode: 0o600 });
      fs.writeFileSync(path.join(lockPath, "replacement-marker"), "live replacement\n", { mode: 0o600 });
    }
    return renameSync(source, destination);
  }) as typeof fs.renameSync);

  expect(tryAcquireProjectLifecycleLock(runtimeContext)).toBeUndefined();
  expect(replaced).toBe(true);
  const quarantines = fs.readdirSync(path.dirname(lockPath))
    .filter((entry) => entry.startsWith(`${path.basename(lockPath)}.quarantine-`));
  expect(quarantines).toHaveLength(1);
  expect(fs.readFileSync(path.join(path.dirname(lockPath), quarantines[0] as string, "replacement-marker"), "utf8"))
    .toBe("live replacement\n");
});

test("reclaims a pid-less lifecycle lock older than the acquisition grace", () => {
  const runtimeContext = hostContext();
  const lockPath = writeLifecycleLock(runtimeContext, {});
  const past = new Date(Date.now() - 60_000);
  fs.utimesSync(lockPath, past, past);

  const lock = tryAcquireProjectLifecycleLock(runtimeContext);

  expect(lock).toBeDefined();
  lock?.release();
});

const noActiveSessionsDocker = { activeAgentSessions: () => [] } as unknown as RuntimeDocker;

function writeSessionMetadataFixture(
  runtimeContext: RuntimeContext,
  id: string,
  overrides: Record<string, unknown> = {},
): void {
  fs.mkdirSync(runtimeContext.project.paths.sessionsDir, { recursive: true });
  const now = new Date().toISOString();
  fs.writeFileSync(
    path.join(runtimeContext.project.paths.sessionsDir, `${id}.json`),
    `${JSON.stringify({
      id,
      projectRoot: runtimeContext.projectRoot,
      composeProject: composeProjectName(runtimeContext.projectRoot),
      command: "claude",
      hostPid: process.pid,
      hostInbox: runtimeContext.project.paths.inboxDir,
      containerInbox: "/runfree/inbox",
      startedAt: now,
      lastSeenAt: now,
      ...overrides,
    })}\n`,
  );
}

test("reports a recent session whose host process is still running as starting", () => {
  const runtimeContext = hostContext();
  writeSessionMetadataFixture(runtimeContext, "rf-20260726-live");

  const sessions = activeOrStartingAgentSessions(runtimeContext, noActiveSessionsDocker);

  expect(sessions).toHaveLength(1);
  expect(sessions[0]?.sessionId).toBe("rf-20260726-live");
  expect(sessions[0]?.containerTty).toBe("<starting>");
  expect(sessions[0]?.name).toMatch(/^claude /);
});

test("reports an attached lifecycle session after its host metadata ages out", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B, PROCESS_B));
  const sessionId = "rf-20260824-longrun";
  const projectId = projectHash(runtimeContext.projectRoot);
  const base = sessionContainerRecordFixture({
    containerId: "7".repeat(64),
    overrides: {
      projectId,
      composeProject: composeProjectName(runtimeContext.projectRoot),
      sessionId,
      containerName: `runfree-${projectId}-session-${sessionId}`,
      displayName: "long-running codex",
      command: "codex",
      hostPid: process.pid,
      hostBootId: BOOT_B,
      hostProcessStart: PROCESS_B,
      createdAt: "2026-08-24T00:00:00.000Z",
    },
  });
  writeSessionContainerRecordV2(runtimeContext.project.paths.stateDir, {
    projectId,
    composeProject: composeProjectName(runtimeContext.projectRoot),
  }, {
    ...base,
    state: "attached",
    admittedAt: "2026-08-24T00:00:00.000Z",
    leaseGeneration: "8".repeat(32),
    leaseExpiresAt: "2026-08-24T00:05:00.000Z",
  });
  writeSessionMetadataFixture(runtimeContext, sessionId, {
    name: "my long session",
    hostPid: process.pid,
    hostBootId: BOOT_B,
    hostProcessStart: PROCESS_B,
    startedAt: "2026-08-24T00:00:00.000Z",
    lastSeenAt: "2026-08-24T00:00:00.000Z",
  });

  const sessions = activeOrStartingAgentSessions(runtimeContext, noActiveSessionsDocker);

  expect(sessions).toHaveLength(1);
  expect(sessions[0]).toEqual(expect.objectContaining({
    sessionId,
    name: "my long session",
    containerTty: "<session-container>",
  }));
});

/** An attached lifecycle record whose owning host process is this test itself. */
function writeAttachedOwnedRecord(runtimeContext: RuntimeContext, sessionId: string): void {
  const projectId = projectHash(runtimeContext.projectRoot);
  const base = sessionContainerRecordFixture({
    containerId: "7".repeat(64),
    overrides: {
      projectId,
      composeProject: composeProjectName(runtimeContext.projectRoot),
      sessionId,
      containerName: `runfree-${projectId}-session-${sessionId}`,
      displayName: "heartbeat session",
      command: "claude",
      hostPid: process.pid,
      hostBootId: BOOT_B,
      hostProcessStart: PROCESS_B,
      createdAt: "2026-09-07T00:00:00.000Z",
    },
  });
  writeSessionContainerRecordV2(runtimeContext.project.paths.stateDir, {
    projectId,
    composeProject: composeProjectName(runtimeContext.projectRoot),
  }, {
    ...base,
    state: "attached",
    admittedAt: "2026-09-07T00:00:00.000Z",
    leaseGeneration: "8".repeat(32),
    leaseExpiresAt: "2026-09-07T00:05:00.000Z",
  });
  writeSessionMetadataFixture(runtimeContext, sessionId, {
    name: "heartbeat session",
    hostPid: process.pid,
    hostBootId: BOOT_B,
    hostProcessStart: PROCESS_B,
    startedAt: "2026-09-07T00:00:00.000Z",
    lastSeenAt: "2026-09-07T00:00:00.000Z",
  });
}

test("shows served-until state from a served heartbeat stamp", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B, PROCESS_B));
  const sessionId = "rf-20260907-served";
  writeAttachedOwnedRecord(runtimeContext, sessionId);
  writeSessionHostStatus(runtimeContext.project.paths.stateDir, {
    v: 1,
    sessionId,
    lastHeartbeatAt: "2026-09-07T00:04:00.000Z",
    aliveUntil: "2026-09-07T00:09:00.000Z",
    served: "served",
  });

  const sessions = activeOrStartingAgentSessions(runtimeContext, noActiveSessionsDocker);

  expect(sessions).toHaveLength(1);
  expect(sessions[0]).toEqual(expect.objectContaining({
    sessionId,
    servedUntil: "2026-09-07T00:09:00.000Z",
    containerTty: "attached, served until 2026-09-07T00:09:00.000Z",
  }));
  expect(sessions[0]?.notServedSince).toBeUndefined();
});

test("shows NOT served / retrying state from a retrying heartbeat stamp", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B, PROCESS_B));
  const sessionId = "rf-20260907-retrying";
  writeAttachedOwnedRecord(runtimeContext, sessionId);
  writeSessionHostStatus(runtimeContext.project.paths.stateDir, {
    v: 1,
    sessionId,
    lastHeartbeatAt: "2026-09-07T00:03:00.000Z",
    aliveUntil: "2026-09-07T00:08:00.000Z",
    served: "retrying",
  });

  const sessions = activeOrStartingAgentSessions(runtimeContext, noActiveSessionsDocker);

  expect(sessions).toHaveLength(1);
  expect(sessions[0]).toEqual(expect.objectContaining({
    sessionId,
    notServedSince: "2026-09-07T00:03:00.000Z",
    containerTty: "attached, NOT served since 2026-09-07T00:03:00.000Z (heartbeat retrying)",
  }));
  expect(sessions[0]?.servedUntil).toBeUndefined();
});

test("keeps an unreadable lifecycle-registry warning row beside an id-less legacy session", () => {
  const runtimeContext = hostContext();
  const recordsRoot = path.join(runtimeContext.project.paths.stateDir, "runtime", "v2", "session-containers");
  fs.mkdirSync(recordsRoot, { recursive: true });
  fs.writeFileSync(path.join(recordsRoot, "rf-20260824-broken1.json"), "{not-json\n");
  const docker = {
    activeAgentSessions: () => [{
      command: "Claude Code",
      containerTty: "/dev/pts/0",
      name: "legacy claude",
      processCount: 1,
    }],
  } as unknown as RuntimeDocker;
  vi.spyOn(console, "error").mockImplementation(() => undefined);

  const sessions = activeOrStartingAgentSessions(runtimeContext, docker);

  expect(sessions).toHaveLength(2);
  expect(sessions.map((session) => session.name)).toEqual([
    "legacy claude",
    "1 unreadable session record(s)",
  ]);
});

test("keeps a container-observed session whose metadata is recent", () => {
  // Baseline for the test below: the recency window still rescues a record
  // whose host PID is dead but whose boot is the current one — an unknown, not
  // a proof, so the heuristic is allowed to keep it.
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  writeSessionMetadataFixture(runtimeContext, "rf-20260726-window", {
    hostPid: reapedPid(),
    hostBootId: BOOT_B,
  });

  const sessions = parseActiveAgentSessionsForTest(
    "123\tpts/0\trf-20260726-window\tclaude --dangerously-skip-permissions\n",
    runtimeContext,
  );

  expect(sessions).toHaveLength(1);
});

test("carries host-owned display names into active session listing data", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  writeSessionMetadataFixture(runtimeContext, "rf-20260726-named", {
    name: "payments refactor",
    hostPid: process.pid,
    hostBootId: BOOT_B,
  });

  const sessions = parseActiveAgentSessionsForTest(
    "123\tpts/0\trf-20260726-named\tclaude --dangerously-skip-permissions\n",
    runtimeContext,
  );

  expect(sessions).toHaveLength(1);
  expect(sessions[0]?.name).toBe("payments refactor");
});

test("the recency window does not resurrect a session proved to be from a previous boot", () => {
  // Same record, same window, one field different: the boot is now provably a
  // previous one. A proof outranks the heuristic — the window exists to cover a
  // host process that has not been observed yet, not to override identity. It
  // hides nothing live, because a `docker exec` session cannot outlive the
  // reboot the stamp proves happened.
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  writeSessionMetadataFixture(runtimeContext, "rf-20260726-rebooted", {
    hostPid: reapedPid(),
    hostBootId: BOOT_A,
  });

  const sessions = parseActiveAgentSessionsForTest(
    "123\tpts/0\trf-20260726-rebooted\tclaude --dangerously-skip-permissions\n",
    runtimeContext,
  );

  expect(sessions).toEqual([]);
});

test("drops a recent crash leftover whose host process is gone", () => {
  // Without this the leftover counts as a pending session start for the whole
  // recency window: `runfree rebuild` warns about a session that does not
  // exist, and an automatic runtime upgrade defers instead of running.
  const runtimeContext = hostContext();
  writeSessionMetadataFixture(runtimeContext, "rf-20260726-dead", { hostPid: reapedPid() });

  expect(activeOrStartingAgentSessions(runtimeContext, noActiveSessionsDocker)).toEqual([]);
});

test("drops a crash leftover whose pid was reissued after a reboot", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  writeSessionMetadataFixture(runtimeContext, "rf-20260726-reused", {
    hostPid: process.pid,
    hostBootId: BOOT_A,
  });

  expect(activeOrStartingAgentSessions(runtimeContext, noActiveSessionsDocker)).toEqual([]);
});

test("drops a crash leftover whose pid was reused within one boot", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B, PROCESS_B));
  writeSessionMetadataFixture(runtimeContext, "rf-20260726-within-boot-reused", {
    hostPid: process.pid,
    hostBootId: BOOT_B,
    hostProcessStart: PROCESS_A,
  });

  expect(activeOrStartingAgentSessions(runtimeContext, noActiveSessionsDocker)).toEqual([]);
});

test("drops a previous-boot crash leftover even when its recorded pid is unusable", () => {
  // Boot proof outranks the PID: a record from a previous boot cannot have a
  // live owner whatever it says its PID was, so the unusable-PID "assume alive"
  // fallback must not run first and resurrect it.
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  writeSessionMetadataFixture(runtimeContext, "rf-20260726-nopid", { hostPid: 0, hostBootId: BOOT_A });

  expect(activeOrStartingAgentSessions(runtimeContext, noActiveSessionsDocker)).toEqual([]);
});

test("survives a session record whose boot stamp is not a string", () => {
  // `readSessionMetadata` casts a JSON.parse result without validating this
  // field. A corrupt record must degrade to the PID-only check rather than
  // throw out of `runfree up`/`rebuild`/`sessions`.
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  writeSessionMetadataFixture(runtimeContext, "rf-20260726-corrupt", {
    hostPid: process.pid,
    hostBootId: 123 as unknown as string,
  });

  expect(activeOrStartingAgentSessions(runtimeContext, noActiveSessionsDocker)).toHaveLength(1);
});

/**
 * Selects a file-backed control plane for the temporary project, so the
 * listing consults the proxy's session files the way a real project does.
 */
function selectFileBackedControlPlane(runtimeContext: RuntimeContext): string {
  const stateDir = runtimeContext.project.paths.stateDir;
  const projectId = projectHash(runtimeContext.projectRoot);
  const composeProject = composeProjectName(runtimeContext.projectRoot);
  const proxyContainerId = "7".repeat(64);
  const generation = createControlPlaneGenerationV2({
    projectId,
    composeProject,
    proxyImageInputDigest: sha256Digest("proxy-image-input"),
    controlPlaneTopologyDigest: sha256Digest("control-plane-topology"),
    admissionContractEpoch: 1,
  });
  const manifest = createControlPlaneMaterializationManifestV2({
    projectId,
    composeProject,
    generation,
    proxyImageRef: "runfree/proxy:test",
    proxyImageId: sha256Digest("proxy-image-id"),
    renderedControlPlaneSha256: generation.controlPlaneTopologyDigest,
    sessionAdmissionSource: "files",
  });
  publishControlPlaneMaterializationV2(stateDir, manifest);
  selectEffectiveControlPlaneV2(stateDir, {
    schemaVersion: 2,
    projectId,
    composeProject,
    controlPlaneGenerationDigest: generation.controlPlaneGenerationDigest,
    controlPlaneMaterializationDigest: manifest.controlPlaneMaterializationDigest,
    proxyContainerId,
    proxyImageId: manifest.proxyImageId,
    sidecarContainerIds: [],
    networkIds: { agentInternal: "8".repeat(64), proxyEgress: "9".repeat(64) },
    securityContractHash: sha256Digest("security-contract"),
    proofSchemaVersion: CONTROL_PLANE_PROOF_SCHEMA_VERSION,
    admissionContractEpoch: 1,
    denyByDefaultBaseProofHash: sha256Digest("deny-by-default-base-proof"),
    selectedAt: "2026-09-07T11:59:00.000Z",
    runfreeVersion: "0.3.0",
  });
  return proxyContainerId;
}

/** A lifecycle record whose owning host process can be proved neither way. */
function writeUnprovableOwnerRecord(runtimeContext: RuntimeContext): { sessionId: string; sessionPrincipal: string } {
  const projectId = projectHash(runtimeContext.projectRoot);
  const composeProject = composeProjectName(runtimeContext.projectRoot);
  const sessionId = "rf-20260907-unknown";
  const base = sessionContainerRecordFixture({
    containerId: "a".repeat(64),
    overrides: {
      projectId,
      composeProject,
      sessionId,
      containerName: `runfree-${projectId}-session-${sessionId}`,
      // A live PID on this boot with no process-start stamp: ownership cannot
      // settle it, so nothing may reclaim the session.
      hostPid: process.pid,
      hostBootId: BOOT_B,
      createdAt: "2026-09-07T12:00:00.000Z",
    },
  });
  const record = {
    ...base,
    state: "attached" as const,
    admittedAt: "2026-09-07T12:00:00.000Z",
    leaseGeneration: "8".repeat(32),
    leaseExpiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
  };
  writeSessionContainerRecordV2(runtimeContext.project.paths.stateDir, { projectId, composeProject }, record);
  return { sessionId, sessionPrincipal: record.sessionPrincipal };
}

test("reports the proxy's session-file residue without changing anything", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  selectFileBackedControlPlane(runtimeContext);
  const unknown = writeUnprovableOwnerRecord(runtimeContext);
  const captured: Array<{ args: string[] }> = [];
  const io = {
    capture: vi.fn((_command: string, args: string[]) => {
      captured.push({ args: [...args] });
      // The cheap running-proxy check `serviceContainerId` makes before the
      // exec: a `docker ps` naming this project's running proxy container.
      if (args[0] === "ps") return { status: 0, stdout: `${"7".repeat(64)}\n`, stderr: "" };
      return {
        status: 0,
        stdout: `${JSON.stringify([
          { sessionKey: unknown.sessionPrincipal, sourceIp: "172.31.90.20", aliveUntil: "2026-09-07T12:05:00.000Z", nonce: "a".repeat(32), eligible: true, wallActive: true },
          { sessionKey: "c".repeat(64), sourceIp: "172.31.90.21", aliveUntil: "2026-09-07T12:05:00.000Z", nonce: "b".repeat(32), eligible: false, wallActive: true },
        ])}\n`,
        stderr: "",
      };
    }),
  } as unknown as RuntimeIO;
  const errors: string[] = [];
  const spy = vi.spyOn(console, "error").mockImplementation((message?: unknown) => { errors.push(String(message)); });
  try {
    const sessions = activeOrStartingAgentSessions(runtimeContext, noActiveSessionsDocker, io);
    flushWarnings();
    expect(sessions.map((session) => session.sessionId)).toEqual([unknown.sessionId]);
  } finally {
    spy.mockRestore();
  }

  // Two observations, and nothing else: the cheap running-proxy check, then
  // the served-set read; no delete, no write, no container stop.
  expect(captured).toHaveLength(2);
  expect(captured[0]?.args[0]).toBe("ps");
  expect(captured[1]?.args.slice(0, 7)).toEqual(["exec", "--user", "0:0", "-i", "7".repeat(64), "node", "-e"]);
  expect(captured[1]?.args).toHaveLength(8);
  const output = errors.join("\n");
  expect(output).toContain(unknown.sessionId);
  expect(output).toContain("cannot be proved alive or dead from this host");
  expect(output).toContain("runfree destroy --force");
  // The reworded line no longer asserts the unprovable owner is running,
  // which contradicted `runfree sessions` listing it as an active session.
  expect(output).not.toContain("left running until their lease lapses");
  expect(output).toContain("1 session file(s) this project has no record for");
});

test("skips comparing session files silently when the project holds no lifecycle record", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  selectFileBackedControlPlane(runtimeContext);
  const io = {
    capture: vi.fn(() => {
      throw new Error("reportSessionFileResidue must not observe the proxy with no lifecycle records");
    }),
  } as unknown as RuntimeIO;
  const errors: string[] = [];
  const spy = vi.spyOn(console, "error").mockImplementation((message?: unknown) => { errors.push(String(message)); });
  try {
    const sessions = activeOrStartingAgentSessions(runtimeContext, noActiveSessionsDocker, io);
    flushWarnings();
    expect(sessions).toEqual([]);
  } finally {
    spy.mockRestore();
  }

  expect(io.capture).not.toHaveBeenCalled();
  expect(errors.join("\n")).toBe("");
});

test("skips comparing session files silently when the proxy is not running", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  selectFileBackedControlPlane(runtimeContext);
  const unknown = writeUnprovableOwnerRecord(runtimeContext);
  const captured: Array<{ args: string[] }> = [];
  const io = {
    capture: vi.fn((_command: string, args: string[]) => {
      captured.push({ args: [...args] });
      // No running proxy container for this project's compose service.
      return { status: 0, stdout: "", stderr: "" };
    }),
  } as unknown as RuntimeIO;
  const errors: string[] = [];
  const spy = vi.spyOn(console, "error").mockImplementation((message?: unknown) => { errors.push(String(message)); });
  try {
    const sessions = activeOrStartingAgentSessions(runtimeContext, noActiveSessionsDocker, io);
    flushWarnings();
    // The record's own liveness classification is untouched: an unproven
    // owner with an unexpired lease still lists as live, independent of
    // whether the file-residue comparison could run at all.
    expect(sessions.map((session) => session.sessionId)).toEqual([unknown.sessionId]);
  } finally {
    spy.mockRestore();
  }

  // Only the running-proxy check ran; it answered "not running" and the
  // exec that would have compared session files never happened.
  expect(captured).toHaveLength(1);
  expect(captured[0]?.args[0]).toBe("ps");
  expect(errors.join("\n")).toBe("");
});

test("consults nothing when the listing has no way to observe the proxy", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  selectFileBackedControlPlane(runtimeContext);
  writeUnprovableOwnerRecord(runtimeContext);

  // Every caller but `runfree sessions` reads exactly the host state it reads
  // today; the report is additive and never becomes a dependency of the list.
  expect(activeOrStartingAgentSessions(runtimeContext, noActiveSessionsDocker)).toHaveLength(1);
});

test("keeps legacy metadata without a boot stamp on a live pid", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  writeSessionMetadataFixture(runtimeContext, "rf-20260726-legacy", { hostPid: process.pid });

  expect(activeOrStartingAgentSessions(runtimeContext, noActiveSessionsDocker)).toHaveLength(1);
});

test("reads legacy inbox field names without rewriting the session record", () => {
  const runtimeContext = hostContext();
  const id = "rf-20260726-legacy-inbox";
  writeSessionMetadataFixture(runtimeContext, id, {
    hostInbox: undefined,
    containerInbox: undefined,
    hostImageInbox: path.join(tmp, "state", "images"),
    containerImageInbox: "/workspace/.runfree-images",
  });
  const sessionPath = path.join(runtimeContext.project.paths.sessionsDir, `${id}.json`);
  const before = fs.readFileSync(sessionPath, "utf8");

  expect(readSessionMetadata(runtimeContext, id)).toMatchObject({
    hostInbox: path.join(tmp, "state", "images"),
    containerInbox: "/workspace/.runfree-images",
  });
  expect(fs.readFileSync(sessionPath, "utf8")).toBe(before);
});

test("stamps new session metadata with the current boot", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B, PROCESS_B));
  const io = { capture: () => ({ status: 1, stdout: "", stderr: "" }) } as unknown as RuntimeIO;

  const metadata = createSessionMetadata(runtimeContext, io, "claude");

  expect(metadata.hostBootId).toBe(BOOT_B);
  expect(metadata.hostProcessStart).toBe(PROCESS_B);
  expect(metadata.hostPid).toBe(process.pid);
  expect(metadata.hostInbox).toBe(path.join(tmp, "state", "inbox"));
  expect(metadata.containerInbox).toBe("/runfree/inbox");
  expect(metadata.name).toMatch(/^claude /);
});

test("normalizes bounded session names by Unicode characters", () => {
  expect(normalizeSessionName("  payments refactor  ")).toBe("payments refactor");
  expect(normalizeSessionName("😀".repeat(80))).toBe("😀".repeat(80));
  expect(() => normalizeSessionName("😀".repeat(81))).toThrow("at most 80 characters");
  expect(() => normalizeSessionName("release\nnotes")).toThrow("control characters");
  expect(() => normalizeSessionName("   ")).toThrow("must not be empty");
});

test("synthesizes deterministic terminal-locatable fallback names", () => {
  expect(synthesizeSessionName({
    command: "codex",
    hostTty: "/dev/ttys004",
    termProgram: "ignored",
    startedAt: "2026-08-05T14:32:00.000Z",
  })).toBe("codex ttys004 14:32");
  expect(synthesizeSessionName({
    command: "shell",
    termProgram: "Apple_Terminal",
    startedAt: "2026-08-05T14:50:00.000Z",
  })).toBe("shell Terminal 14:50");
});

test("uses an explicit name before RUNFREE_SESSION_NAME and otherwise synthesizes", () => {
  const runtimeContext = hostContext({
    ...harnessEnv(BOOT_B, PROCESS_B),
    RUNFREE_SESSION_NAME: "  environment name  ",
    TERM_PROGRAM: "Apple_Terminal",
  });
  const io = { capture: () => ({ status: 1, stdout: "", stderr: "" }) } as unknown as RuntimeIO;
  const now = new Date("2026-08-05T14:32:00.000Z");

  expect(createSessionMetadata(runtimeContext, io, "claude", undefined, { now }).name).toBe("environment name");
  expect(createSessionMetadata(runtimeContext, io, "claude", undefined, { name: " CLI name ", now }).name)
    .toBe("CLI name");
  delete runtimeContext.env?.RUNFREE_SESSION_NAME;
  expect(createSessionMetadata(runtimeContext, io, "claude", undefined, { now }).name)
    .toBe("claude Terminal 14:32");
});

test("normalizes legacy metadata without a name without rewriting its record", () => {
  const runtimeContext = hostContext();
  const id = "rf-20260726-legacy-name";
  writeSessionMetadataFixture(runtimeContext, id, {
    name: undefined,
    termProgram: "Apple_Terminal",
    startedAt: "2026-08-05T14:32:00.000Z",
    lastSeenAt: "2026-08-05T14:32:00.000Z",
  });
  const sessionPath = path.join(runtimeContext.project.paths.sessionsDir, `${id}.json`);
  const before = fs.readFileSync(sessionPath, "utf8");

  expect(readSessionMetadata(runtimeContext, id)?.name).toBe("claude Terminal 14:32");
  expect(fs.readFileSync(sessionPath, "utf8")).toBe(before);
});

test("replaces malformed legacy display names with a safe synthesized label", () => {
  const runtimeContext = hostContext();
  const id = "rf-20260726-malformed-name";
  writeSessionMetadataFixture(runtimeContext, id, {
    name: "forged\u0080\u0081name",
    hostTty: "/dev/ttys007",
    startedAt: "2026-08-05T14:32:00.000Z",
  });

  expect(readSessionMetadata(runtimeContext, id)?.name).toBe("claude ttys007 14:32");
});

test("renames exactly one current session metadata record as display-only state", () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B, PROCESS_B));
  const io = { capture: () => ({ status: 1, stdout: "", stderr: "" }) } as unknown as RuntimeIO;
  const metadata = createSessionMetadata(runtimeContext, io, "claude", "claude --resume abc", {
    name: "before",
    now: new Date("2026-08-05T14:32:00.000Z"),
  });
  writeSessionMetadata(runtimeContext, metadata);

  const renamed = renameSessionMetadata(runtimeContext, metadata.id, "  payments refactor  ");

  expect(renamed).toEqual({ ...metadata, name: "payments refactor" });
  expect(readSessionMetadata(runtimeContext, metadata.id)).toEqual(renamed);
  expect(fs.statSync(path.join(runtimeContext.project.paths.sessionsDir, `${metadata.id}.json`)).mode & 0o777)
    .toBe(0o600);
  expect(sessionEnvOptions(renamed).join("\n")).not.toContain("RUNFREE_SESSION_NAME");
});

test("rename rejects invalid input and linked records before any outside mutation", () => {
  const runtimeContext = hostContext();
  const id = "rf-20260726-abcdef";
  const sessionPath = path.join(runtimeContext.project.paths.sessionsDir, `${id}.json`);
  fs.mkdirSync(runtimeContext.project.paths.sessionsDir, { recursive: true });
  const outside = path.join(tmp, "outside.json");
  fs.writeFileSync(outside, "outside\n");
  fs.symlinkSync(outside, sessionPath);

  expect(() => renameSessionMetadata(runtimeContext, id, "bad\nname")).toThrow("control characters");
  expect(() => renameSessionMetadata(runtimeContext, id, "safe name")).toThrow("bounded normal file");
  expect(fs.readFileSync(outside, "utf8")).toBe("outside\n");

  fs.unlinkSync(sessionPath);
  fs.linkSync(outside, sessionPath);
  expect(() => renameSessionMetadata(runtimeContext, id, "safe name")).toThrow("bounded normal file");
  expect(fs.readFileSync(outside, "utf8")).toBe("outside\n");
  expect(() => renameSessionMetadata(runtimeContext, "../../outside", "safe name")).toThrow("invalid Runfree session id");
});

test("rename rejects a symlinked session-state directory", () => {
  const runtimeContext = hostContext();
  const id = "rf-20260726-abcdef";
  const outsideDir = path.join(tmp, "outside-sessions");
  fs.mkdirSync(outsideDir);
  const outsideRecord = path.join(outsideDir, `${id}.json`);
  fs.writeFileSync(outsideRecord, "outside\n");
  fs.mkdirSync(path.dirname(runtimeContext.project.paths.sessionsDir), { recursive: true });
  fs.symlinkSync(outsideDir, runtimeContext.project.paths.sessionsDir, "dir");

  expect(() => renameSessionMetadata(runtimeContext, id, "safe name")).toThrow("safe directory");
  expect(fs.readFileSync(outsideRecord, "utf8")).toBe("outside\n");
});

test("session listing exposes display names independently from command identity", () => {
  const log = vi.spyOn(console, "log").mockImplementation(() => {});

  printSessions([{
    sessionId: "rf-20260805-abcdef",
    name: "payments refactor",
    command: "Codex CLI",
    containerTty: "pts/0",
    hostTty: "/dev/ttys004",
    hostTermProgram: "Apple_Terminal",
    startedAt: "2026-08-05T14:32:00.000Z",
    processCount: 1,
  }]);

  const output = String(log.mock.calls[0]?.[0]);
  expect(output).toContain("NAME");
  expect(output).toContain("payments refactor");
  expect(output).toContain("codex");
});

test.each([32, 64])("queued renewals finish before a new launch at %i owners", async (count) => {
  // Scheduling is measured on a controlled clock; filesystem work still uses
  // real locks and tickets. Pin process identity to avoid macOS ps spawns.
  vi.useFakeTimers({ toFake: ["Date", "performance", "setTimeout", "clearTimeout"] });
  const runtimeContext = hostContext(harnessEnv(BOOT_B, PROCESS_B));
  const managers = Array.from({ length: count }, () => {
    const lock = tryAcquireProjectLifecycleLock(runtimeContext);
    if (!lock) throw new Error("fixture could not acquire lifecycle lock");
    const manager = createSessionLockManager(runtimeContext, lock, { retryDelayMs: 1 });
    manager.releaseForWait();
    return manager;
  });
  const holder = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(holder).toBeDefined();
  const completed = new Set<number>();
  const renewals = managers.map((manager, index) => manager.withLock(async () => {
    expect(tryAcquireProjectLifecycleLock(runtimeContext)).toBeUndefined();
    completed.add(index);
  }, new AbortController().signal));
  expect(tryAcquireProjectLifecycleLock(runtimeContext)).toBeUndefined();
  holder?.release();
  // This attempt occurs with a free lifecycle lock and every renewal queued:
  // only queue priority can keep the launch out here.
  expect(tryAcquireProjectLifecycleLock(runtimeContext)).toBeUndefined();
  await vi.advanceTimersByTimeAsync(9_999);
  expect(completed.size).toBe(count);
  await Promise.all(renewals);
  const launch = tryAcquireProjectLifecycleLock(runtimeContext);
  expect(launch).toBeDefined();
  launch?.release();
  managers.forEach((manager) => { manager.close(); });
});

test("a corrupt renewal queue refuses acquisition without wedging the manager, then permits repair", async () => {
  const runtimeContext = hostContext(harnessEnv(BOOT_B));
  const lock = tryAcquireProjectLifecycleLock(runtimeContext);
  if (!lock) throw new Error("fixture could not acquire lifecycle lock");
  const manager = createSessionLockManager(runtimeContext, lock, { retryDelayMs: 1 });
  manager.releaseForWait();
  const queue = path.join(runtimeContext.project.paths.stateDir, "session-renewal-queue");
  fs.writeFileSync(queue, "corrupt");
  const work = vi.fn(async () => undefined);
  await expect(manager.withLock(work, new AbortController().signal)).rejects.toThrow();
  expect(work).not.toHaveBeenCalled();
  fs.unlinkSync(queue);
  await manager.withLock(work, new AbortController().signal);
  expect(work).toHaveBeenCalledOnce();
  manager.close();
});
