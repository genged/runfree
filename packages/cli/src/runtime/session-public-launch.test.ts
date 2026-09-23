import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  createDriver: vi.fn(),
  launchBuiltin: vi.fn(),
  launchShell: vi.fn(),
}));

vi.mock("./session-admission-driver.ts", () => ({
  createInternalSessionAdmissionDriver: mocks.createDriver,
}));
vi.mock("./prepared-runtime.ts", () => ({
  preparedRuntimeContext: (prepared: { context: unknown }) => prepared.context,
  StalePreparedRuntimeError: class StalePreparedRuntimeError extends Error {},
}));

import { defaultConfig } from "../config.ts";
import { projectHash } from "../project-identity.ts";
import {
  launchConfiguredAgentThroughAdmission,
  launchShellThroughAdmission,
} from "./session-public-launch.ts";
import { StalePreparedRuntimeError } from "./prepared-runtime.ts";
import { tryAcquireProjectLifecycleLock } from "./sessions.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

let tmp: string;
let projectRoot: string;
let stateDir: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  vi.clearAllMocks();
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
    expect(mocks.launchBuiltin).toHaveBeenCalledWith("claude");
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
