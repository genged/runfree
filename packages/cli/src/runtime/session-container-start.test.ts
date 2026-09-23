import { EventEmitter } from "node:events";
import type { ChildProcess, SpawnOptions } from "node:child_process";

import { afterEach, beforeAll, describe, expect, test, vi } from "vitest";

import {
  sessionContainerAttachCommand,
  sessionContainerStartAttachCommand,
  sessionNetworkInspectCommand,
  type SessionDockerCommand,
} from "./session-container-docker.ts";
import { SESSION_CONTAINER_INSPECT_MAX_BYTES } from "./session-container-proof.ts";
import {
  sessionContainerCreatePlanFixture,
  sessionContainerInspectJsonFixture,
  sessionContainerRecordFixture,
  SESSION_TEST_PROJECT,
} from "./session-container.test-harness.ts";
import {
  assertSessionContainerForegroundAttachReceipt,
  assertSessionContainerForegroundHandleIdentity,
  cancelSessionContainerForegroundAttach,
  currentSessionContainerForegroundCompletion,
  reattachSessionContainerForeground,
  startSessionContainerForeground,
  type SessionContainerForegroundHandle,
  type SessionContainerForegroundSpawner,
} from "./session-container-start.ts";
import { waitForRunningSessionContainerProof } from "./session-container-running-proof.ts";
import {
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2,
  transitionProvisioningRunningSessionContainerToAttachedV2,
  type SessionContainerRecordV2,
} from "./session-containers.ts";

const CONTAINER_ID = "3".repeat(64);
const OTHER_CONTAINER_ID = "4".repeat(64);
const NETWORK_ID = "8".repeat(64);
const DOCKER_CLIENT_ENV = Object.freeze({
  DOCKER_HOST: "unix:///var/run/docker.sock",
  PATH: "/usr/local/bin:/usr/bin:/bin",
});

type FakeChild = ChildProcess & {
  kill: ReturnType<typeof vi.fn>;
};

function provisioningRunningRecord(containerId: string, marker: string): SessionContainerRecordV2 {
  const bound = sessionContainerRecordFixture({
    containerId,
    overrides: {
      sessionIncarnation: marker.repeat(64),
      sessionPrincipal: (marker === "a" ? "c" : "d").repeat(64),
    },
  });
  return transitionBoundAllocatedSessionContainerToProvisioningRunningV2(bound, {
    admittedAt: "2026-08-08T12:00:01.000Z",
    leaseGeneration: marker.repeat(32),
    leaseExpiresAt: "2026-08-08T12:02:01.000Z",
  });
}

function provisioningRunningPlan(record: SessionContainerRecordV2) {
  return sessionContainerCreatePlanFixture({ record });
}

function fakeChild(pid = 4242): FakeChild {
  const child = new EventEmitter() as FakeChild;
  Object.assign(child, {
    pid,
    exitCode: null,
    signalCode: null,
    kill: vi.fn(() => true),
  });
  return child;
}

function spawnAcknowledged(child: FakeChild) {
  return vi.fn((_executable: string, _args: readonly string[], _options: SpawnOptions) => {
    queueMicrotask(() => child.emit("spawn"));
    return child;
  });
}

function startOptions(
  spawn: SessionContainerForegroundSpawner,
  overrides: { spawnTimeoutMs?: number } = {},
) {
  return {
    dockerClientEnv: { ...DOCKER_CLIENT_ENV },
    spawn,
    ...overrides,
  };
}


describe("foreground session-container start", () => {
  let record: SessionContainerRecordV2;
  let otherRecord: SessionContainerRecordV2;
  let command: SessionDockerCommand;
  let otherCommand: SessionDockerCommand;

  beforeAll(() => {
    record = provisioningRunningRecord(CONTAINER_ID, "a");
    otherRecord = provisioningRunningRecord(OTHER_CONTAINER_ID, "b");
    command = sessionContainerStartAttachCommand(record, SESSION_TEST_PROJECT);
    otherCommand = sessionContainerStartAttachCommand(otherRecord, SESSION_TEST_PROJECT);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test("spawns the sealed foreground start with exact argv and no shell", async () => {
    const child = fakeChild();
    const spawn = spawnAcknowledged(child);
    const dockerClientEnv = { ...DOCKER_CLIENT_ENV };

    const handle = await startSessionContainerForeground(
      command,
      record,
      SESSION_TEST_PROJECT,
      { dockerClientEnv, spawn },
    );

    expect(spawn).toHaveBeenCalledOnce();
    expect(spawn).toHaveBeenCalledWith("docker", [
      "container",
      "start",
      "--attach",
      "--interactive",
      CONTAINER_ID,
    ], {
      env: DOCKER_CLIENT_ENV,
      shell: false,
      stdio: "inherit",
    });
    const spawnOptions = spawn.mock.calls[0]?.[2];
    expect(spawnOptions?.env).not.toBe(dockerClientEnv);
    expect(spawnOptions?.env).toEqual(DOCKER_CLIENT_ENV);
    expect(handle).toMatchObject({ pid: 4242, containerId: CONTAINER_ID });
    expect(Object.isFrozen(handle)).toBe(true);
    expect(() => assertSessionContainerForegroundAttachReceipt(
      handle.receipt,
      record,
      SESSION_TEST_PROJECT,
    )).not.toThrow();
    expect(() => assertSessionContainerForegroundHandleIdentity(
      handle,
      transitionProvisioningRunningSessionContainerToAttachedV2(record),
      SESSION_TEST_PROJECT,
    )).not.toThrow();
    expect(() => assertSessionContainerForegroundHandleIdentity(
      { ...handle } as SessionContainerForegroundHandle,
      record,
      SESSION_TEST_PROJECT,
    )).toThrow("unsealed");
    expect(() => assertSessionContainerForegroundHandleIdentity(
      handle,
      otherRecord,
      SESSION_TEST_PROJECT,
    )).toThrow("different lifecycle identity");

    child.emit("exit", 17, null);
    await expect(handle.completion).resolves.toEqual({ kind: "exit", code: 17, signal: null });
  });

  test("rejects forged, non-start, and cross-session commands before spawning", async () => {
    const child = fakeChild();
    const spawn = spawnAcknowledged(child);
    const forged = {
      executable: "docker",
      args: ["container", "start", "--attach", CONTAINER_ID],
      effect: "start-attach-session-container",
      exactTarget: CONTAINER_ID,
    } as unknown as SessionDockerCommand;

    await expect(startSessionContainerForeground(forged, record, SESSION_TEST_PROJECT, startOptions(spawn)))
      .rejects.toThrow(/unvalidated|sealed/);
    await expect(startSessionContainerForeground(
      sessionNetworkInspectCommand(NETWORK_ID),
      record,
      SESSION_TEST_PROJECT,
      startOptions(spawn),
    )).rejects.toThrow(/foreground|start/);
    await expect(startSessionContainerForeground(command, otherRecord, SESSION_TEST_PROJECT, startOptions(spawn)))
      .rejects.toThrow(/different|exact|lifecycle/);
    expect(spawn).not.toHaveBeenCalled();
  });

  test("rejects a spawn error or exit before spawn acknowledgement", async () => {
    const erroredChild = fakeChild();
    const spawnError = vi.fn(() => {
      queueMicrotask(() => erroredChild.emit("error", new Error("spawn denied")));
      return erroredChild;
    });
    await expect(startSessionContainerForeground(
      command,
      record,
      SESSION_TEST_PROJECT,
      { dockerClientEnv: { ...DOCKER_CLIENT_ENV }, spawn: spawnError },
    )).rejects.toThrow("spawn denied");

    const exitedChild = fakeChild();
    const exitBeforeSpawn = vi.fn(() => {
      queueMicrotask(() => exitedChild.emit("exit", 125, null));
      return exitedChild;
    });
    await expect(startSessionContainerForeground(
      command,
      record,
      SESSION_TEST_PROJECT,
      { dockerClientEnv: { ...DOCKER_CLIENT_ENV }, spawn: exitBeforeSpawn },
    )).rejects.toThrow(/exited before.*acknowledged/i);
  });

  test("terminates and rejects when Docker does not acknowledge spawn in time", async () => {
    vi.useFakeTimers();
    const child = fakeChild();
    const spawn = vi.fn(() => child);

    const pending = startSessionContainerForeground(
      command,
      record,
      SESSION_TEST_PROJECT,
      {
        dockerClientEnv: { ...DOCKER_CLIENT_ENV },
        spawn,
        spawnTimeoutMs: 25,
      },
    );
    const rejected = expect(pending).rejects.toThrow(/timed out|timeout/i);
    await vi.advanceTimersByTimeAsync(25);

    await rejected;
    expect(spawn).toHaveBeenCalledOnce();
    expect(child.kill).toHaveBeenCalledOnce();
    expect(child.kill).toHaveBeenCalledWith("SIGTERM");
  });

  test("rejects malformed Docker-client environment and timeout before spawning", async () => {
    const spawn = spawnAcknowledged(fakeChild());

    await expect(startSessionContainerForeground(
      command,
      record,
      SESSION_TEST_PROJECT,
      {
        dockerClientEnv: { PATH: "/usr/bin\u0000/attacker" },
        spawn,
      },
    )).rejects.toThrow(/environment|NUL|control/i);
    await expect(startSessionContainerForeground(
      command,
      record,
      SESSION_TEST_PROJECT,
      {
        dockerClientEnv: { ...DOCKER_CLIENT_ENV },
        spawn,
        spawnTimeoutMs: 0,
      },
    )).rejects.toThrow(/timeout|positive/i);

    expect(spawn).not.toHaveBeenCalled();
  });

  test("reports asynchronous child errors through completion", async () => {
    const child = fakeChild();
    const handle = await startSessionContainerForeground(
      command,
      record,
      SESSION_TEST_PROJECT,
      startOptions(spawnAcknowledged(child)),
    );
    const error = new Error("docker attach failed");

    child.emit("error", error);

    await expect(handle.completion).resolves.toEqual({ kind: "error", error });
  });

  test("reports only the current completion of an exact sealed foreground handle", async () => {
    const child = fakeChild();
    const handle = await startSessionContainerForeground(
      command,
      record,
      SESSION_TEST_PROJECT,
      startOptions(spawnAcknowledged(child)),
    );

    expect(currentSessionContainerForegroundCompletion(handle)).toBeUndefined();
    child.emit("exit", 23, null);
    child.emit("error", new Error("late duplicate terminal event"));
    const completion = currentSessionContainerForegroundCompletion(handle);
    expect(completion).toEqual({ kind: "exit", code: 23, signal: null });
    await expect(handle.completion).resolves.toEqual({ kind: "exit", code: 23, signal: null });
    expect(Object.isFrozen(completion)).toBe(true);
    expect(() => currentSessionContainerForegroundCompletion(
      { ...handle } as SessionContainerForegroundHandle,
    )).toThrow(/sealed|handle/);
  });

  test("retries an exact created inspect and returns the exact running proof", async () => {
    const child = fakeChild();
    const handle = await startSessionContainerForeground(
      command,
      record,
      SESSION_TEST_PROJECT,
      startOptions(spawnAcknowledged(child)),
    );
    const plan = provisioningRunningPlan(record);
    const results = [
      sessionContainerInspectJsonFixture(plan),
      sessionContainerInspectJsonFixture(plan, { running: true }),
    ];
    const capture = vi.fn(() => ({
      status: 0,
      stdout: results.shift() ?? "",
      stderr: "",
    }));
    const delay = vi.fn(async () => {});

    await expect(waitForRunningSessionContainerProof(capture, plan, handle, {
      nowMs: () => 0,
      delay,
      dockerOptions: {
        maxBuffer: SESSION_CONTAINER_INSPECT_MAX_BYTES * 2,
        timeout: 30_000,
      },
    })).resolves.toMatchObject({
      phase: "provisioning-running",
      containerId: CONTAINER_ID,
      sourceIp: record.sourceIp,
      running: true,
    });
    expect(capture).toHaveBeenCalledTimes(2);
    expect(capture).toHaveBeenNthCalledWith(1, "docker", [
      "container",
      "inspect",
      CONTAINER_ID,
    ], {
      maxBuffer: SESSION_CONTAINER_INSPECT_MAX_BYTES,
      timeout: 5_000,
    });
    expect(delay).toHaveBeenCalledOnce();
  });

  test("aborts on foreground exit or error before the first inspect", async () => {
    for (const scenario of ["exit", "error"] as const) {
      const child = fakeChild();
      const handle = await startSessionContainerForeground(
        command,
        record,
        SESSION_TEST_PROJECT,
        startOptions(spawnAcknowledged(child)),
      );
      const plan = provisioningRunningPlan(record);
      const capture = vi.fn(() => ({ status: 0, stdout: "", stderr: "" }));
      if (scenario === "exit") child.emit("exit", 125, null);
      else child.emit("error", new Error("attach transport failed"));

      await expect(waitForRunningSessionContainerProof(capture, plan, handle))
        .rejects.toThrow(scenario === "exit" ? /exited.*code=125/i : /attach transport failed/i);
      expect(capture).not.toHaveBeenCalled();
    }
  });

  test("aborts on foreground exit or error while waiting to retry", async () => {
    for (const scenario of ["exit", "error"] as const) {
      const child = fakeChild();
      const handle = await startSessionContainerForeground(
        command,
        record,
        SESSION_TEST_PROJECT,
        startOptions(spawnAcknowledged(child)),
      );
      const plan = provisioningRunningPlan(record);
      const capture = vi.fn(() => {
        queueMicrotask(() => {
          if (scenario === "exit") child.emit("exit", 137, null);
          else child.emit("error", new Error("attach failed during poll"));
        });
        return {
          status: 0,
          stdout: sessionContainerInspectJsonFixture(plan),
          stderr: "",
        };
      });
      const delay = vi.fn(() => new Promise<void>(() => {}));

      await expect(waitForRunningSessionContainerProof(capture, plan, handle, { delay }))
        .rejects.toThrow(scenario === "exit" ? /exited.*code=137/i : /attach failed during poll/i);
      expect(capture).toHaveBeenCalledOnce();
      expect(delay).toHaveBeenCalledOnce();
    }
  });

  test("does not retry a hard inspect drift or Docker daemon failure", async () => {
    const plan = provisioningRunningPlan(record);
    const drifted = JSON.parse(sessionContainerInspectJsonFixture(plan));
    drifted[0].Image = `sha256:${"f".repeat(64)}`;
    const scenarios = [
      { result: { status: 0, stdout: JSON.stringify(drifted), stderr: "" }, error: /image id differs/i },
      { result: { status: 1, stdout: "", stderr: "daemon unavailable" }, error: /failed to inspect/i },
    ];

    for (const scenario of scenarios) {
      const child = fakeChild();
      const handle = await startSessionContainerForeground(
        command,
        record,
        SESSION_TEST_PROJECT,
        startOptions(spawnAcknowledged(child)),
      );
      const capture = vi.fn(() => scenario.result);
      const delay = vi.fn(async () => {});

      await expect(waitForRunningSessionContainerProof(capture, plan, handle, { delay }))
        .rejects.toThrow(scenario.error);
      expect(capture).toHaveBeenCalledOnce();
      expect(delay).not.toHaveBeenCalled();
    }
  });

  test("bounds created-state polling by the configured timeout", async () => {
    const child = fakeChild();
    const handle = await startSessionContainerForeground(
      command,
      record,
      SESSION_TEST_PROJECT,
      startOptions(spawnAcknowledged(child)),
    );
    const plan = provisioningRunningPlan(record);
    const capture = vi.fn(() => ({
      status: 0,
      stdout: sessionContainerInspectJsonFixture(plan),
      stderr: "",
    }));
    let now = 0;
    const delay = vi.fn(async (milliseconds: number) => {
      now += milliseconds;
    });

    await expect(waitForRunningSessionContainerProof(capture, plan, handle, {
      timeoutMs: 3,
      pollMs: 1_000,
      nowMs: () => now,
      delay,
    })).rejects.toThrow(/running state.*timeout/i);
    expect(capture).toHaveBeenCalledOnce();
    expect(capture).toHaveBeenCalledWith("docker", [
      "container",
      "inspect",
      CONTAINER_ID,
    ], {
      maxBuffer: SESSION_CONTAINER_INSPECT_MAX_BYTES,
      timeout: 3,
    });
    expect(delay).toHaveBeenCalledOnce();
    expect(delay).toHaveBeenCalledWith(3);
  });

  test("rejects forged and cross-session foreground handles before inspect", async () => {
    const child = fakeChild();
    const otherChild = fakeChild();
    const handle = await startSessionContainerForeground(
      command,
      record,
      SESSION_TEST_PROJECT,
      startOptions(spawnAcknowledged(child)),
    );
    const otherHandle = await startSessionContainerForeground(
      otherCommand,
      otherRecord,
      SESSION_TEST_PROJECT,
      startOptions(spawnAcknowledged(otherChild)),
    );
    const plan = provisioningRunningPlan(record);
    const capture = vi.fn(() => ({ status: 0, stdout: "", stderr: "" }));

    await expect(waitForRunningSessionContainerProof(
      capture,
      plan,
      { ...handle } as SessionContainerForegroundHandle,
    )).rejects.toThrow(/sealed|handle/);
    await expect(waitForRunningSessionContainerProof(capture, plan, otherHandle))
      .rejects.toThrow(/different|lifecycle|authority/);
    expect(capture).not.toHaveBeenCalled();
  });

  test("rejects a plan that has not reached provisioning-running before inspect", async () => {
    const child = fakeChild();
    const handle = await startSessionContainerForeground(
      command,
      record,
      SESSION_TEST_PROJECT,
      startOptions(spawnAcknowledged(child)),
    );
    const allocatedPlan = sessionContainerCreatePlanFixture({
      record: sessionContainerRecordFixture({
        containerId: CONTAINER_ID,
        overrides: {
          sessionIncarnation: "a".repeat(64),
          sessionPrincipal: "c".repeat(64),
        },
      }),
    });
    const capture = vi.fn(() => ({ status: 0, stdout: "", stderr: "" }));

    await expect(waitForRunningSessionContainerProof(capture, allocatedPlan, handle))
      .rejects.toThrow("requires a provisioning-running session-container plan");
    expect(capture).not.toHaveBeenCalled();
  });

  test("cancels only the child bound to an exact sealed handle and only once", async () => {
    const child = fakeChild(4242);
    const otherChild = fakeChild(5252);
    const handle = await startSessionContainerForeground(
      command,
      record,
      SESSION_TEST_PROJECT,
      startOptions(spawnAcknowledged(child)),
    );
    const otherHandle = await startSessionContainerForeground(
      otherCommand,
      otherRecord,
      SESSION_TEST_PROJECT,
      startOptions(spawnAcknowledged(otherChild)),
    );

    expect(cancelSessionContainerForegroundAttach(handle)).toBe(true);
    expect(child.kill).toHaveBeenCalledOnce();
    expect(child.kill).toHaveBeenCalledWith("SIGTERM");
    expect(otherChild.kill).not.toHaveBeenCalled();
    expect(cancelSessionContainerForegroundAttach(handle)).toBe(false);
    expect(child.kill).toHaveBeenCalledOnce();

    const forged = { ...otherHandle } as SessionContainerForegroundHandle;
    expect(() => cancelSessionContainerForegroundAttach(forged)).toThrow(/sealed|handle/);
    expect(otherChild.kill).not.toHaveBeenCalled();
  });

  test("re-attaches an ended stream to the same sealed lifecycle authority", async () => {
    const child = fakeChild(4242);
    const handle = await startSessionContainerForeground(
      command,
      record,
      SESSION_TEST_PROJECT,
      startOptions(spawnAcknowledged(child)),
    );
    const attached = transitionProvisioningRunningSessionContainerToAttachedV2(record);
    const attachCommand = sessionContainerAttachCommand(attached, SESSION_TEST_PROJECT);
    const next = fakeChild(4343);
    const respawn = spawnAcknowledged(next);

    // A live stream is not a lost one: re-attaching beside a running child
    // would put two attaches on one container.
    await expect(reattachSessionContainerForeground(
      handle,
      attachCommand,
      startOptions(respawn),
    )).rejects.toThrow(/has not ended/);
    expect(respawn).not.toHaveBeenCalled();

    child.emit("error", new Error("attach stream closed"));
    await expect(handle.completion).resolves.toMatchObject({ kind: "error" });

    const reattached = await reattachSessionContainerForeground(
      handle,
      attachCommand,
      startOptions(respawn),
    );

    expect(respawn).toHaveBeenCalledOnce();
    expect(respawn).toHaveBeenCalledWith("docker", [
      "container",
      "attach",
      CONTAINER_ID,
    ], {
      env: DOCKER_CLIENT_ENV,
      shell: false,
      stdio: "inherit",
    });
    // The OS child is new; the sealed admission authority it attaches is not.
    expect(reattached.receipt).toBe(handle.receipt);
    expect(reattached.pid).toBe(4343);
    expect(reattached.containerId).toBe(CONTAINER_ID);
    expect(Object.isFrozen(reattached)).toBe(true);
    expect(() => assertSessionContainerForegroundHandleIdentity(
      reattached,
      attached,
      SESSION_TEST_PROJECT,
    )).not.toThrow();
    expect(currentSessionContainerForegroundCompletion(reattached)).toBeUndefined();
    // The new handle owns the new child, and only it.
    expect(cancelSessionContainerForegroundAttach(reattached)).toBe(true);
    expect(next.kill).toHaveBeenCalledWith("SIGTERM");
    expect(child.kill).not.toHaveBeenCalled();

    next.emit("exit", 9, null);
    await expect(reattached.completion).resolves.toEqual({ kind: "exit", code: 9, signal: null });
    expect(currentSessionContainerForegroundCompletion(reattached)).toEqual({ kind: "exit", code: 9, signal: null });
    // The ended stream keeps its own answer; it never learns the new one.
    await expect(handle.completion).resolves.toMatchObject({ kind: "error" });
  });

  test("refuses to re-attach a forged handle, a cancelled attach, or another container", async () => {
    const child = fakeChild(4242);
    const handle = await startSessionContainerForeground(
      command,
      record,
      SESSION_TEST_PROJECT,
      startOptions(spawnAcknowledged(child)),
    );
    const attached = transitionProvisioningRunningSessionContainerToAttachedV2(record);
    const otherAttached = transitionProvisioningRunningSessionContainerToAttachedV2(otherRecord);
    const attachCommand = sessionContainerAttachCommand(attached, SESSION_TEST_PROJECT);
    const respawn = spawnAcknowledged(fakeChild(4343));

    child.emit("error", new Error("attach stream closed"));
    await handle.completion;

    await expect(reattachSessionContainerForeground(
      { ...handle } as SessionContainerForegroundHandle,
      attachCommand,
      startOptions(respawn),
    )).rejects.toThrow(/unsealed/);
    await expect(reattachSessionContainerForeground(
      handle,
      sessionContainerAttachCommand(otherAttached, SESSION_TEST_PROJECT),
      startOptions(respawn),
    )).rejects.toThrow(/different lifecycle identity/);
    await expect(reattachSessionContainerForeground(
      handle,
      command,
      startOptions(respawn),
    )).rejects.toThrow(/unsealed/);
    await expect(reattachSessionContainerForeground(
      handle,
      attachCommand,
      { dockerClientEnv: { PATH: "/usr/bin\u0000/attacker" }, spawn: respawn },
    )).rejects.toThrow(/environment|NUL|control/i);

    // A foreground this host already asked to end is never re-attached: the
    // cancellation is the teardown's decision, not a lost stream.
    const cancelledChild = fakeChild(5252);
    const cancelled = await startSessionContainerForeground(
      otherCommand,
      otherRecord,
      SESSION_TEST_PROJECT,
      startOptions(spawnAcknowledged(cancelledChild)),
    );
    expect(cancelSessionContainerForegroundAttach(cancelled)).toBe(true);
    cancelledChild.emit("exit", null, "SIGTERM");
    await cancelled.completion;
    await expect(reattachSessionContainerForeground(
      cancelled,
      sessionContainerAttachCommand(otherAttached, SESSION_TEST_PROJECT),
      startOptions(respawn),
    )).rejects.toThrow(/cancelled/);

    expect(respawn).not.toHaveBeenCalled();
  });

  test("binds the start receipt to the exact lifecycle authority", async () => {
    const child = fakeChild();
    const handle = await startSessionContainerForeground(
      command,
      record,
      SESSION_TEST_PROJECT,
      startOptions(spawnAcknowledged(child)),
    );

    expect(() => assertSessionContainerForegroundAttachReceipt(
      handle.receipt,
      otherRecord,
      SESSION_TEST_PROJECT,
    )).toThrow(/different|exact|lifecycle/);
    expect(() => assertSessionContainerForegroundAttachReceipt(
      { ...handle.receipt },
      record,
      SESSION_TEST_PROJECT,
    )).toThrow(/sealed|receipt/);
  });
});
