import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  createDriver: vi.fn(),
  launchBuiltin: vi.fn(),
  launchShell: vi.fn(),
  // The held-lock handoffs startup attached, keyed by prepared runtime.
  handoffs: new Map<object, { lifecycleLock: { release(): void }; lockOwnerToken: string; lockAcquiredAtMonotonicMs: number }>(),
  // Prepared runtimes whose startup declined the handoff for its hold span.
  declined: new Set<object>(),
}));

vi.mock("./session-admission-driver.ts", () => ({
  createInternalSessionAdmissionDriver: mocks.createDriver,
}));
vi.mock("./prepared-runtime.ts", () => ({
  preparedRuntimeContext: (prepared: { context: unknown }) => prepared.context,
  StalePreparedRuntimeError: class StalePreparedRuntimeError extends Error {},
  takeLaunchHandoff: (prepared: object) => {
    const handoff = mocks.handoffs.get(prepared);
    mocks.handoffs.delete(prepared);
    return handoff;
  },
  disposeLaunchHandoff: (prepared: object) => {
    const handoff = mocks.handoffs.get(prepared);
    mocks.handoffs.delete(prepared);
    handoff?.lifecycleLock.release();
  },
  takeLaunchHandoffDeclined: (prepared: object) => mocks.declined.delete(prepared),
}));

import { defaultConfig } from "../config.ts";
import { projectHash } from "../project-identity.ts";
import {
  launchConfiguredAgentThroughAdmission,
  launchShellThroughAdmission,
} from "./session-public-launch.ts";
import { StalePreparedRuntimeError } from "./prepared-runtime.ts";
import { tryAcquireProjectLifecycleLock, tryAcquireProjectLifecycleLockWithRetry } from "./sessions.ts";
import { LAUNCH_HANDOFF_STARTUP_SPAN_MAX_MS } from "./launch-lock-hold.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

// Host-chosen ids are minted by `crypto.randomUUID()`, always lowercase.
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

let tmp: string;
let projectRoot: string;
let stateDir: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  vi.clearAllMocks();
  mocks.handoffs.clear();
  mocks.declined.clear();
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-public-launch-"));
  projectRoot = path.join(tmp, "project");
  fs.mkdirSync(projectRoot, { recursive: true });
  env = {
    XDG_STATE_HOME: path.join(tmp, "xdg-state"),
    RUNFREE_TEST_FAKE_DOCKER: "1",
  };
  stateDir = path.join(env.XDG_STATE_HOME as string, "runfree", "projects", projectHash(projectRoot));
  fs.mkdirSync(path.join(stateDir, "sessions"), { recursive: true });
  mocks.launchBuiltin.mockResolvedValue({ status: 0, signal: null });
  mocks.launchShell.mockResolvedValue({ status: 0, signal: null });
  mocks.createDriver.mockImplementation((input: { sessionLockManager: { lock: { assertHeld(): void } } }) => {
    // The driver constructor asserts the lock in production; doing the same
    // here pins that the composition acquires it before building the driver.
    input.sessionLockManager.lock.assertHeld();
    return { launchBuiltin: mocks.launchBuiltin, launchShell: mocks.launchShell };
  });
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function runtimeContext(): RuntimeContext {
  return {
    projectRoot,
    project: {
      config: { ...defaultConfig(), version: 3 },
      paths: { stateDir, sessionsDir: path.join(stateDir, "sessions") },
    },
    runtimeRoot: path.join(tmp, "runtime"),
    env,
  } as unknown as RuntimeContext;
}

const io = { capture: () => ({ status: 1, stdout: "", stderr: "" }) } as unknown as RuntimeIO;

function preparedRuntime(context = runtimeContext()) {
  return Object.freeze({ version: 1, context }) as never;
}

describe("public launch through session admission", () => {
  test("launches a built-in agent through the driver and returns its exit status", async () => {
    const status = await launchConfiguredAgentThroughAdmission({
      preparedRuntime: preparedRuntime(),
      io,
      agentName: "claude",
    });

    expect(status).toBe(0);
    // Claude declares the host-chosen conversation id flag, so a fresh public
    // launch mints one (spec §2).
    expect(mocks.launchBuiltin).toHaveBeenCalledWith(
      "claude",
      { launchConversationId: expect.stringMatching(UUID_PATTERN) },
    );
    const driverInput = mocks.createDriver.mock.calls[0]?.[0] as {
      sessionLockManager?: { lock: unknown };
      lifecycleLock?: unknown;
      lifecycleLockLease?: unknown;
    };
    expect(driverInput.sessionLockManager).toBeDefined();
    expect(driverInput).not.toHaveProperty("lifecycleLock");
    expect(driverInput).not.toHaveProperty("lifecycleLockLease");
    // The lock must be free again: a launch that kept it would defer every
    // later lifecycle operation in the project.
    const reacquired = tryAcquireProjectLifecycleLock(runtimeContext());
    expect(reacquired).toBeDefined();
    reacquired?.release();
  });

  test("maps a signal death to exit status 1", async () => {
    mocks.launchBuiltin.mockResolvedValueOnce({ status: null, signal: "SIGKILL" });

    const status = await launchConfiguredAgentThroughAdmission({
      preparedRuntime: preparedRuntime(),
      io,
      agentName: "codex",
    });

    expect(status).toBe(1);
  });

  test("refuses a non-builtin agent before touching the lock or the driver", async () => {
    await expect(launchConfiguredAgentThroughAdmission({
      preparedRuntime: preparedRuntime(),
      io,
      agentName: "aider",
    })).rejects.toThrow(/built-in agents \(claude, codex, pi\), not aider.*runfree shell/su);

    expect(mocks.createDriver).not.toHaveBeenCalled();
    // The refusal happened before lock acquisition, so the lock is untouched.
    const lock = tryAcquireProjectLifecycleLock(runtimeContext());
    expect(lock).toBeDefined();
    lock?.release();
  });

  test("defers when the project lifecycle lock is held, naming the lock path", async () => {
    const held = tryAcquireProjectLifecycleLock(runtimeContext());
    expect(held).toBeDefined();
    vi.useFakeTimers();
    try {
      const refusal = expect(launchConfiguredAgentThroughAdmission({
        preparedRuntime: preparedRuntime(),
        io,
        agentName: "claude",
      })).rejects.toThrow(/lifecycle change is in progress \(lock: .*lifecycle\.lock/u);
      await vi.advanceTimersByTimeAsync(60_000);
      await refusal;
      expect(mocks.createDriver).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
      held?.release();
    }
  }, 15_000);

  test("releases the lock when the driver launch fails", async () => {
    mocks.launchBuiltin.mockRejectedValueOnce(new Error("admission failed closed"));

    await expect(launchConfiguredAgentThroughAdmission({
      preparedRuntime: preparedRuntime(),
      io,
      agentName: "pi",
    })).rejects.toThrow("admission failed closed");

    const reacquired = tryAcquireProjectLifecycleLock(runtimeContext());
    expect(reacquired).toBeDefined();
    reacquired?.release();
  });

  test("launches the shell session through the driver's shell kind with no agent involved", async () => {
    const status = await launchShellThroughAdmission({ preparedRuntime: preparedRuntime(), io });

    expect(status).toBe(0);
    expect(mocks.launchShell).toHaveBeenCalledTimes(1);
    expect(mocks.launchBuiltin).not.toHaveBeenCalled();
    // Lock hygiene holds for the shell frame too.
    const reacquired = tryAcquireProjectLifecycleLock(runtimeContext());
    expect(reacquired).toBeDefined();
    reacquired?.release();
  });

  test("threads a provided foreground spawner into the driver", async () => {
    const foregroundSpawner = vi.fn();

    await launchConfiguredAgentThroughAdmission({
      preparedRuntime: preparedRuntime(),
      io,
      agentName: "claude",
      foregroundSpawner: foregroundSpawner as never,
    });

    expect(mocks.createDriver).toHaveBeenCalledWith(expect.objectContaining({ foregroundSpawner }));
  });

  test("admits under the lock startup handed off: no second acquisition, and the lock is free afterwards", async () => {
    const prepared = preparedRuntime();
    const held = tryAcquireProjectLifecycleLock(runtimeContext());
    if (!held) throw new Error("fixture lock");
    const handoff = { lifecycleLock: held, lockOwnerToken: held.ownerToken, lockAcquiredAtMonotonicMs: performance.now() };
    mocks.handoffs.set(prepared, handoff);

    const status = await launchConfiguredAgentThroughAdmission({ preparedRuntime: prepared, io, agentName: "claude" });

    expect(status).toBe(0);
    const driverInput = mocks.createDriver.mock.calls[0]?.[0] as { handoff?: unknown; sessionLockManager: { lock: { ownerToken: string } } };
    // The driver runs under the exact handed-off lock and receives the handoff.
    expect(driverInput.handoff).toBe(handoff);
    expect(driverInput.sessionLockManager.lock.ownerToken).toBe(held.ownerToken);
    // Taken once: nothing is left for a second consumer.
    expect(mocks.handoffs.has(prepared)).toBe(false);
    const reacquired = tryAcquireProjectLifecycleLock(runtimeContext());
    expect(reacquired).toBeDefined();
    reacquired?.release();
  });

  test("a handoff whose startup span outgrew the budget is released, and admission takes its own lock", async () => {
    const prepared = preparedRuntime();
    const held = tryAcquireProjectLifecycleLock(runtimeContext());
    if (!held) throw new Error("fixture lock");
    const release = vi.spyOn(held, "release");
    mocks.handoffs.set(prepared, {
      lifecycleLock: held,
      lockOwnerToken: held.ownerToken,
      lockAcquiredAtMonotonicMs: performance.now() - LAUNCH_HANDOFF_STARTUP_SPAN_MAX_MS - 1,
    });
    const before = performance.now();

    const status = await launchConfiguredAgentThroughAdmission({ preparedRuntime: prepared, io, agentName: "claude" });

    expect(status).toBe(0);
    expect(release).toHaveBeenCalledTimes(1);
    const driverInput = mocks.createDriver.mock.calls[0]?.[0] as {
      handoff?: unknown;
      lockHeldSinceMonotonicMs: number;
      sessionLockManager: { lock: { ownerToken: string } };
    };
    // The non-handoff path: no handoff reaches the driver, it runs under a
    // freshly taken lock, and its hold is planned from that acquisition.
    expect(driverInput.handoff).toBeUndefined();
    expect(driverInput.sessionLockManager.lock.ownerToken).not.toBe(held.ownerToken);
    expect(driverInput.lockHeldSinceMonotonicMs).toBeGreaterThanOrEqual(before);
    const reacquired = tryAcquireProjectLifecycleLock(runtimeContext());
    expect(reacquired).toBeDefined();
    reacquired?.release();
  });

  test.each([
    ["a handoff that outgrew the budget at take", "expired"],
    ["a handoff startup declined for its hold span", "declined"],
  ] as const)("after %s, a command already waiting gets the lock before admission retakes it", async (_label, cause) => {
    const prepared = preparedRuntime();
    const held = tryAcquireProjectLifecycleLock(runtimeContext());
    if (!held) throw new Error("fixture lock");
    const order: string[] = [];
    // A concurrent command waiting the ordinary way: a try every 200 ms.
    const waiter = tryAcquireProjectLifecycleLockWithRetry(runtimeContext()).then(async (lock) => {
      order.push("waiter-acquired");
      await new Promise((resolve) => setTimeout(resolve, 50));
      lock?.release();
    });
    // Let the waiter make its first, failed, try.
    await new Promise((resolve) => setTimeout(resolve, 20));
    if (cause === "expired") {
      mocks.handoffs.set(prepared, {
        lifecycleLock: held,
        lockOwnerToken: held.ownerToken,
        lockAcquiredAtMonotonicMs: performance.now() - LAUNCH_HANDOFF_STARTUP_SPAN_MAX_MS - 1,
      });
    } else {
      // Startup's own `finally` released the lock it declined to hand off.
      held.release();
      mocks.declined.add(prepared);
    }
    mocks.createDriver.mockImplementationOnce((input: { sessionLockManager: { lock: { assertHeld(): void } } }) => {
      input.sessionLockManager.lock.assertHeld();
      order.push("admission-acquired");
      return { launchBuiltin: mocks.launchBuiltin, launchShell: mocks.launchShell };
    });

    await expect(launchConfiguredAgentThroughAdmission({ preparedRuntime: prepared, io, agentName: "claude" })).resolves.toBe(0);
    await waiter;

    expect(order).toEqual(["waiter-acquired", "admission-acquired"]);
  });

  test("a handoff inside the budget plans the hold from startup's acquisition", async () => {
    const prepared = preparedRuntime();
    const held = tryAcquireProjectLifecycleLock(runtimeContext());
    if (!held) throw new Error("fixture lock");
    const acquiredAt = performance.now() - 1_000;
    mocks.handoffs.set(prepared, { lifecycleLock: held, lockOwnerToken: held.ownerToken, lockAcquiredAtMonotonicMs: acquiredAt });

    await launchConfiguredAgentThroughAdmission({ preparedRuntime: prepared, io, agentName: "claude" });

    const driverInput = mocks.createDriver.mock.calls[0]?.[0] as { lockHeldSinceMonotonicMs: number };
    expect(driverInput.lockHeldSinceMonotonicMs).toBe(acquiredAt);
  });

  describe("a cold launch's handoff with its startup allowance almost spent", () => {
    // What a cold startup hands over: its reconcile's settled state, under the
    // lock it took before the compose start, full validation and publication.
    function coldHandoff(held: NonNullable<ReturnType<typeof tryAcquireProjectLifecycleLock>>) {
      return {
        lifecycleLock: held,
        lockOwnerToken: held.ownerToken,
        lockAcquiredAtMonotonicMs: performance.now() - (LAUNCH_HANDOFF_STARTUP_SPAN_MAX_MS - 250),
        sessionState: { kind: "reconciled", inventoryClean: true, reservedSourceIps: [] },
      };
    }
    const lockIsFree = (): boolean => {
      const lock = tryAcquireProjectLifecycleLock(runtimeContext());
      lock?.release();
      return lock !== undefined;
    };

    test("admission runs under it with no yield, its hold planned from the original acquisition, and a waiting command gets the lock next", async () => {
      const prepared = preparedRuntime();
      const held = tryAcquireProjectLifecycleLock(runtimeContext());
      if (!held) throw new Error("fixture lock");
      const handoff = coldHandoff(held);
      mocks.handoffs.set(prepared, handoff);
      const order: string[] = [];
      const waiter = tryAcquireProjectLifecycleLockWithRetry(runtimeContext()).then((lock) => {
        order.push("waiter-acquired");
        lock?.release();
      });
      await new Promise((resolve) => setTimeout(resolve, 20));
      mocks.createDriver.mockImplementationOnce((input: { sessionLockManager: { lock: { assertHeld(): void; ownerToken: string } } }) => {
        input.sessionLockManager.lock.assertHeld();
        expect(input.sessionLockManager.lock.ownerToken).toBe(held.ownerToken);
        order.push("admission-under-handoff");
        return { launchBuiltin: mocks.launchBuiltin, launchShell: mocks.launchShell };
      });

      await expect(launchConfiguredAgentThroughAdmission({ preparedRuntime: prepared, io, agentName: "claude" })).resolves.toBe(0);
      await waiter;

      const driverInput = mocks.createDriver.mock.calls[0]?.[0] as { handoff?: unknown; lockHeldSinceMonotonicMs: number };
      expect(driverInput.handoff).toBe(handoff);
      expect(driverInput.lockHeldSinceMonotonicMs).toBe(handoff.lockAcquiredAtMonotonicMs);
      expect(order).toEqual(["admission-under-handoff", "waiter-acquired"]);
    });

    test.each([
      ["the MCP callback setup fails", () => mocks.launchBuiltin.mockRejectedValueOnce(new Error("MCP OAuth callback setup used its budget")), undefined],
      ["the foreground agent exits non-zero", () => mocks.launchBuiltin.mockResolvedValueOnce({ status: 3, signal: null }), 3],
      ["the foreground agent dies by a signal", () => mocks.launchBuiltin.mockResolvedValueOnce({ status: null, signal: "SIGKILL" }), 1],
    ] as const)("when %s, the handed-off lock is released and the next command takes it", async (_label, arrange, status) => {
      const prepared = preparedRuntime();
      const held = tryAcquireProjectLifecycleLock(runtimeContext());
      if (!held) throw new Error("fixture lock");
      mocks.handoffs.set(prepared, coldHandoff(held));
      arrange();

      const launched = launchConfiguredAgentThroughAdmission({ preparedRuntime: prepared, io, agentName: "claude" });
      if (status === undefined) await expect(launched).rejects.toThrow("callback setup");
      else await expect(launched).resolves.toBe(status);

      expect(mocks.handoffs.has(prepared)).toBe(false);
      expect(lockIsFree()).toBe(true);
    });
  });

  test("releases a handed-off lock when the launch fails", async () => {
    const prepared = preparedRuntime();
    const held = tryAcquireProjectLifecycleLock(runtimeContext());
    if (!held) throw new Error("fixture lock");
    mocks.handoffs.set(prepared, { lifecycleLock: held, lockOwnerToken: held.ownerToken, lockAcquiredAtMonotonicMs: performance.now() });
    mocks.launchBuiltin.mockRejectedValueOnce(new Error("admission failed closed"));

    await expect(launchConfiguredAgentThroughAdmission({ preparedRuntime: prepared, io, agentName: "codex" }))
      .rejects.toThrow("admission failed closed");

    const reacquired = tryAcquireProjectLifecycleLock(runtimeContext());
    expect(reacquired).toBeDefined();
    reacquired?.release();
  });

  test("a stale handed-off launch re-prepares once under a fresh lock and leaves no lock behind", async () => {
    const first = preparedRuntime();
    const second = preparedRuntime();
    const held = tryAcquireProjectLifecycleLock(runtimeContext());
    if (!held) throw new Error("fixture lock");
    mocks.handoffs.set(first, { lifecycleLock: held, lockOwnerToken: held.ownerToken, lockAcquiredAtMonotonicMs: performance.now() });
    mocks.createDriver.mockImplementationOnce(() => {
      throw new StalePreparedRuntimeError("the proxy restarted after startup prepared this launch");
    });

    const status = await launchConfiguredAgentThroughAdmission({
      preparedRuntime: first,
      io,
      agentName: "pi",
      reprepare: async () => second,
    });

    expect(status).toBe(0);
    expect(mocks.createDriver).toHaveBeenCalledTimes(2);
    expect((mocks.createDriver.mock.calls[1]?.[0] as { handoff?: unknown }).handoff).toBeUndefined();
    const reacquired = tryAcquireProjectLifecycleLock(runtimeContext());
    expect(reacquired).toBeDefined();
    reacquired?.release();
  });

  test("re-prepares once when durable lifecycle state changes before container creation", async () => {
    const first = preparedRuntime();
    const second = preparedRuntime();
    const reprepare = vi.fn(async () => second);
    mocks.createDriver.mockImplementationOnce(() => {
      throw new StalePreparedRuntimeError("selection changed");
    });

    const status = await launchConfiguredAgentThroughAdmission({
      preparedRuntime: first,
      io,
      agentName: "codex",
      reprepare,
    });

    expect(status).toBe(0);
    expect(reprepare).toHaveBeenCalledTimes(1);
    expect(mocks.createDriver).toHaveBeenCalledTimes(2);
    expect(mocks.createDriver.mock.calls[1]?.[0]).toEqual(expect.objectContaining({ preparedRuntime: second }));
  });

  test("mints one host-chosen conversation id per public launch and reuses it across an admission retry", async () => {
    // Spec §2 / plan decision P1: the id is minted once, outside the frame's
    // retry loop, so a re-prepared runtime admission retry still resumes the
    // same conversation rather than two different ones.
    const first = preparedRuntime();
    const second = preparedRuntime();
    mocks.launchBuiltin.mockImplementationOnce(() => {
      throw new StalePreparedRuntimeError("the proxy restarted after startup prepared this launch");
    });

    const status = await launchConfiguredAgentThroughAdmission({
      preparedRuntime: first,
      io,
      agentName: "claude",
      reprepare: async () => second,
    });

    expect(status).toBe(0);
    expect(mocks.launchBuiltin).toHaveBeenCalledTimes(2);
    const firstOptions = mocks.launchBuiltin.mock.calls[0]?.[1] as { launchConversationId?: string };
    const secondOptions = mocks.launchBuiltin.mock.calls[1]?.[1] as { launchConversationId?: string };
    expect(firstOptions.launchConversationId).toMatch(UUID_PATTERN);
    expect(secondOptions.launchConversationId).toBe(firstOptions.launchConversationId);
  });

  test("codex has no host-chosen conversation id flag, so the public launch mints none", async () => {
    await launchConfiguredAgentThroughAdmission({
      preparedRuntime: preparedRuntime(),
      io,
      agentName: "codex",
    });

    expect(mocks.launchBuiltin).toHaveBeenCalledWith("codex", {});
  });

  test("refuses repeated preparation drift at the retry bound", async () => {
    mocks.createDriver.mockImplementation(() => {
      throw new StalePreparedRuntimeError("selection changed again");
    });
    const reprepare = vi.fn(async () => preparedRuntime());

    await expect(launchConfiguredAgentThroughAdmission({
      preparedRuntime: preparedRuntime(),
      io,
      agentName: "pi",
      reprepare,
    })).rejects.toThrow("runtime lifecycle state changed repeatedly");

    expect(reprepare).toHaveBeenCalledTimes(1);
    expect(mocks.createDriver).toHaveBeenCalledTimes(2);
    expect(mocks.launchBuiltin).not.toHaveBeenCalled();
  });
});
