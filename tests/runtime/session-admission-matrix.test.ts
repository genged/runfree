import childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test, vi, type Mock } from "vitest";

import {
  aggregateSessionAdmissionMatrix,
  executeSessionAdmissionMatrix,
  inspectSessionAdmissionMatrixBackend,
  parseSessionAdmissionMatrixArgs,
  sessionAdmissionMatrixWorkerNonce,
  signalSessionAdmissionWorkerProcessGroup,
  superviseSessionAdmissionMatrixWorker,
  validSessionAdmissionWorkerBootstrap,
  waitForSessionAdmissionWorkerBootstrap,
  type SessionAdmissionMatrixSample,
} from "./session-admission-matrix.ts";
import type {
  SessionAdmissionProbeAgent,
  SessionAdmissionProbeMetrics,
} from "../../packages/cli/src/runtime/session-admission-probe.ts";
import {
  tryAcquireProjectLifecycleLock,
  type ProjectLifecycleLock,
} from "../../packages/cli/src/runtime/sessions.ts";
import type { RuntimeContext, RuntimeIO } from "../../packages/cli/src/runtime/types.ts";

function metrics(
  agent: SessionAdmissionProbeAgent,
  provisioningToSequenceMs: number,
  dockerOperations: number,
): SessionAdmissionProbeMetrics {
  return Object.freeze({
    agent,
    dockerOperations,
    provisioningToSequenceMs,
  });
}

function lock(): ProjectLifecycleLock & { assertHeld: Mock<() => void>; release: Mock<() => void> } {
  return {
    ownerToken: "matrix-owner",
    assertHeld: vi.fn<() => void>(),
    release: vi.fn<() => void>(),
  };
}

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ESRCH") return false;
    throw error;
  }
  if (process.platform === "linux") {
    try {
      // A zombie cannot execute or retain inherited descriptors. Some
      // container PID 1 implementations do not reap adopted children, so
      // kill(pid, 0) alone would report a terminated descendant forever.
      const status = fs.readFileSync(`/proc/${pid}/status`, "utf8");
      if (/^State:\s+Z\b/mu.test(status)) return false;
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") return false;
      throw error;
    }
  }
  return true;
}

async function waitUntil(check: () => boolean, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!check()) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for process-group state");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

function backendIO(values: Record<string, string>): RuntimeIO {
  return {
    run: () => 0,
    capture(_command, args) {
      const key = args.join("\0");
      const value = values[key];
      return value === undefined
        ? { status: 1, stdout: "", stderr: `unexpected Docker query: ${key}` }
        : { status: 0, stdout: `${value}\n`, stderr: "" };
    },
    commandExists: () => true,
    confirm: () => false,
    async admin() {
      throw new Error("unexpected admin call");
    },
  };
}

describe("internal session admission live matrix", () => {
  const workerNonce = "a".repeat(43);

  test("requires attributable bounded arguments for an already-started runtime", () => {
    expect(parseSessionAdmissionMatrixArgs([
      "--workspace",
      "sandbox",
      "--backend",
      "docker-desktop",
      "--repeat",
      "3",
      "--cleanup-request-after-seconds",
      "90",
    ], "/tmp/matrix-root")).toEqual({
      agents: ["claude", "codex", "pi"],
      backend: "docker-desktop",
      repetitions: 3,
      cleanupRequestAfterSeconds: 90,
      workspace: "/tmp/matrix-root/sandbox",
    });

    expect(() => parseSessionAdmissionMatrixArgs(["--workspace", "/tmp/sandbox"]))
      .toThrow("--backend is required");
    expect(() => parseSessionAdmissionMatrixArgs(["--workspace", "/tmp/sandbox", "--backend", "linux"]))
      .toThrow("--backend must be docker-desktop or orbstack");
    expect(() => parseSessionAdmissionMatrixArgs([
      "--workspace",
      "/tmp/sandbox",
      "--backend",
      "orbstack",
      "--repeat",
      "21",
    ])).toThrow("--repeat must be an integer from 1 through 20");
    expect(() => parseSessionAdmissionMatrixArgs([
      "--workspace",
      "/tmp/sandbox",
      "--backend",
      "orbstack",
      "--cleanup-request-after-seconds",
      "29",
    ])).toThrow("--cleanup-request-after-seconds must be an integer from 30 through 3600");
    expect(() => parseSessionAdmissionMatrixArgs([
      "--workspace",
      "/tmp/sandbox",
      "--backend",
      "orbstack",
      "--workspace",
      "/tmp/other",
    ])).toThrow("duplicate session admission matrix option: --workspace");
    expect(() => parseSessionAdmissionMatrixArgs([
      "--workspace",
      "/tmp/sandbox",
      "--backend",
      "orbstack",
      "--agents",
      "claude",
    ])).toThrow("unknown session admission matrix option: --agents");
  });

  test("narrows the tranche to an exact reproducible agent slice", () => {
    // Canonical order, not caller order: a sliced rerun must produce the same
    // sample sequence and aggregate shape as the corresponding full run.
    expect(parseSessionAdmissionMatrixArgs([
      "--workspace",
      "/tmp/sandbox",
      "--backend",
      "orbstack",
      "--agent",
      "pi",
      "--agent",
      "claude",
    ]).agents).toEqual(["claude", "pi"]);

    expect(parseSessionAdmissionMatrixArgs([
      "--workspace",
      "/tmp/sandbox",
      "--backend",
      "orbstack",
      "--agent",
      "codex",
    ]).agents).toEqual(["codex"]);

    expect(() => parseSessionAdmissionMatrixArgs([
      "--workspace",
      "/tmp/sandbox",
      "--backend",
      "orbstack",
      "--agent",
      "gemini",
    ])).toThrow("--agent must be one of claude, codex, pi");

    expect(() => parseSessionAdmissionMatrixArgs([
      "--workspace",
      "/tmp/sandbox",
      "--backend",
      "orbstack",
      "--agent",
      "claude",
      "--agent",
      "claude",
    ])).toThrow("duplicate session admission agent: claude");
  });

  test("requires the claimed backend label to match live daemon identity", () => {
    const io = backendIO({
      [["version", "--format", "{{.Server.Platform.Name}}"].join("\0")]: "Docker Engine - Community",
      [["info", "--format", "{{.OperatingSystem}}"].join("\0")]: "Docker Desktop",
      [["version", "--format", "{{.Server.Arch}}"].join("\0")]: "arm64",
      [["context", "show"].join("\0")]: "desktop-linux",
      [["version", "--format", "{{.Server.Version}}"].join("\0")]: "29.0.0",
    });
    expect(inspectSessionAdmissionMatrixBackend("docker-desktop", io)).toEqual({
      architecture: "arm64",
      context: "desktop-linux",
      detected: "docker-desktop",
      operatingSystem: "Docker Desktop",
      platformName: "Docker Engine - Community",
      version: "29.0.0",
    });
    expect(() => inspectSessionAdmissionMatrixBackend("orbstack", io))
      .toThrow("expected orbstack, detected docker-desktop");
  });

  test("accepts only the exact non-degenerate worker bootstrap nonce", () => {
    expect(validSessionAdmissionWorkerBootstrap({
      kind: "runfree-session-admission-matrix-worker",
      nonce: workerNonce,
    }, workerNonce)).toBe(true);
    for (const candidate of [
      undefined,
      null,
      {},
      { kind: "wrong", nonce: workerNonce },
      { kind: "runfree-session-admission-matrix-worker" },
      { kind: "runfree-session-admission-matrix-worker", nonce: 42 },
      { kind: "runfree-session-admission-matrix-worker", nonce: "" },
      { kind: "runfree-session-admission-matrix-worker", nonce: "a".repeat(42) },
      { kind: "runfree-session-admission-matrix-worker", nonce: "b".repeat(43) },
    ]) {
      expect(validSessionAdmissionWorkerBootstrap(candidate, workerNonce)).toBe(false);
    }
    expect(validSessionAdmissionWorkerBootstrap({
      kind: "runfree-session-admission-matrix-worker",
      nonce: "",
    }, "")).toBe(false);
  });

  test("refuses ambient or malformed worker mode without the private IPC channel", () => {
    expect(sessionAdmissionMatrixWorkerNonce(undefined, false)).toBeUndefined();
    expect(sessionAdmissionMatrixWorkerNonce(workerNonce, true)).toBe(workerNonce);
    expect(() => sessionAdmissionMatrixWorkerNonce(workerNonce, false))
      .toThrow("refuses an ambient worker bootstrap nonce");
    expect(() => sessionAdmissionMatrixWorkerNonce("", true))
      .toThrow("worker bootstrap nonce is invalid");
  });

  test("requires a matching bootstrap message before timeout or channel disconnect", async () => {
    const acceptedChannel = new EventEmitter();
    const disconnect = vi.fn();
    const accepted = waitForSessionAdmissionWorkerBootstrap(workerNonce, {
      channel: acceptedChannel,
      disconnect,
      timeoutMs: 500,
    });
    acceptedChannel.emit("message", {
      kind: "runfree-session-admission-matrix-worker",
      nonce: workerNonce,
    });
    // Load-bearing: the channel must NOT be released inside the emit. The
    // bootstrap nonce is normally buffered before the listener exists, so Node
    // delivers it from the pending-message flush in its `newListener` hook and
    // writes `target.channel[kPendingMessages] = []` immediately afterwards.
    // Disconnecting synchronously nulls that channel underneath the flush and
    // kills the worker inside Node with no user frame. Confirmed against real
    // child-process IPC, where the synchronous form reproduces the crash and
    // this deferred form exits cleanly.
    expect(disconnect).not.toHaveBeenCalled();
    await expect(accepted).resolves.toBeUndefined();
    await new Promise((resolve) => { setImmediate(resolve); });
    expect(disconnect).toHaveBeenCalledOnce();
    expect(acceptedChannel.listenerCount("message")).toBe(0);
    expect(acceptedChannel.listenerCount("disconnect")).toBe(0);

    const rejectedChannel = new EventEmitter();
    const rejected = waitForSessionAdmissionWorkerBootstrap(workerNonce, {
      channel: rejectedChannel,
      timeoutMs: 500,
    });
    rejectedChannel.emit("message", {
      kind: "runfree-session-admission-matrix-worker",
      nonce: "b".repeat(43),
    });
    await expect(rejected).rejects.toThrow("bootstrap was rejected");

    const disconnectedChannel = new EventEmitter();
    const disconnected = waitForSessionAdmissionWorkerBootstrap(workerNonce, {
      channel: disconnectedChannel,
      timeoutMs: 500,
    });
    disconnectedChannel.emit("disconnect");
    await expect(disconnected).rejects.toThrow("bootstrap channel closed");

    await expect(waitForSessionAdmissionWorkerBootstrap(workerNonce, {
      channel: new EventEmitter(),
      timeoutMs: 20,
    })).rejects.toThrow("bootstrap timed out");
  });

  test("runs every built-in in deterministic repeated order and releases the lock", async () => {
    const lifecycleLock = lock();
    const observed: SessionAdmissionProbeAgent[] = [];
    const assertCleanOutcome = vi.fn(() => {
      expect(lifecycleLock.release).not.toHaveBeenCalled();
    });
    const samples = await executeSessionAdmissionMatrix({
      repetitions: 2,
      acquireLock: () => lifecycleLock,
      assertCleanOutcome,
      createDriver: (received) => {
        expect(received).toBe(lifecycleLock);
        return {
          async recoverPending() {},
          async probeBuiltin(agent) {
            observed.push(agent);
            return metrics(agent, observed.length * 10, observed.length + 3);
          },
        };
      },
    });

    expect(observed).toEqual(["claude", "codex", "pi", "claude", "codex", "pi"]);
    expect(samples.map((sample) => [sample.iteration, sample.metrics.agent])).toEqual([
      [1, "claude"],
      [1, "codex"],
      [1, "pi"],
      [2, "claude"],
      [2, "codex"],
      [2, "pi"],
    ]);
    expect(assertCleanOutcome).toHaveBeenCalledOnce();
    expect(lifecycleLock.release).toHaveBeenCalledTimes(1);
  });

  test("recovers pending state under the held lock before releasing after a probe failure", async () => {
    const lifecycleLock = lock();
    const probes: string[] = [];
    const recoverPending = vi.fn(async () => {
      expect(lifecycleLock.release).not.toHaveBeenCalled();
    });
    await expect(executeSessionAdmissionMatrix({
      repetitions: 3,
      acquireLock: () => lifecycleLock,
      createDriver: () => ({
        recoverPending,
        async probeBuiltin(agent) {
          probes.push(agent);
          if (agent === "codex") throw new Error("codex provisioning failed");
          return metrics(agent, 10, 4);
        },
      }),
    })).rejects.toThrow("codex provisioning failed");

    expect(probes).toEqual(["claude", "codex"]);
    expect(recoverPending).toHaveBeenCalledExactlyOnceWith("codex");
    expect(lifecycleLock.release).toHaveBeenCalledTimes(1);
  });

  test("retains the lifecycle fence and retries until exact pending-state recovery succeeds", async () => {
    const lifecycleLock = lock();
    let recoveryAttempts = 0;
    const onRecoveryRetry = vi.fn();
    await expect(executeSessionAdmissionMatrix({
      repetitions: 1,
      acquireLock: () => lifecycleLock,
      onRecoveryRetry,
      waitForRecoveryRetry: async () => {
        expect(lifecycleLock.release).not.toHaveBeenCalled();
      },
      createDriver: () => ({
        async probeBuiltin() {
          throw new Error("provisioning failed");
        },
        async recoverPending() {
          recoveryAttempts += 1;
          if (recoveryAttempts === 1) throw new Error("exact recovery failed");
        },
      }),
    })).rejects.toThrow("exact pending-state recovery succeeded after retry");

    expect(recoveryAttempts).toBe(2);
    expect(onRecoveryRetry).toHaveBeenCalledTimes(1);
    expect(lifecycleLock.release).toHaveBeenCalledTimes(1);
  });

  test("bounds exact pending-state recovery attempts and releases the durable fence", async () => {
    const lifecycleLock = lock();
    const recoverPending = vi.fn(async () => {
      throw new Error("exact recovery remains unavailable");
    });
    const waitForRecoveryRetry = vi.fn(async () => {
      expect(lifecycleLock.release).not.toHaveBeenCalled();
    });
    await expect(executeSessionAdmissionMatrix({
      repetitions: 1,
      acquireLock: () => lifecycleLock,
      waitForRecoveryRetry,
      createDriver: () => ({
        async probeBuiltin() {
          throw new Error("provisioning failed");
        },
        recoverPending,
      }),
    })).rejects.toThrow("recovery failed after 3 attempts; durable pending state remains");

    expect(recoverPending).toHaveBeenCalledTimes(3);
    expect(waitForRecoveryRetry).toHaveBeenCalledTimes(2);
    expect(lifecycleLock.release).toHaveBeenCalledOnce();
  });

  test("stops recovery retry cooperatively when the watchdog requests interruption", async () => {
    const lifecycleLock = lock();
    let reason: string | undefined;
    const recoverPending = vi.fn(async () => {
      reason = "SIGTERM";
      throw new Error("exact recovery failed during shutdown");
    });
    const waitForRecoveryRetry = vi.fn(async () => {});
    await expect(executeSessionAdmissionMatrix({
      repetitions: 1,
      acquireLock: () => lifecycleLock,
      interruptionReason: () => reason,
      waitForRecoveryRetry,
      createDriver: () => ({
        async probeBuiltin() {
          throw new Error("provisioning failed");
        },
        recoverPending,
      }),
    })).rejects.toThrow("recovery interrupted by SIGTERM; durable pending state remains");

    expect(recoverPending).toHaveBeenCalledOnce();
    expect(waitForRecoveryRetry).not.toHaveBeenCalled();
    expect(lifecycleLock.release).toHaveBeenCalledOnce();
  });

  test("fails the matrix when its final clean outcome is not observed under the lock", async () => {
    const lifecycleLock = lock();
    await expect(executeSessionAdmissionMatrix({
      repetitions: 1,
      agents: ["claude"],
      acquireLock: () => lifecycleLock,
      assertCleanOutcome() {
        expect(lifecycleLock.release).not.toHaveBeenCalled();
        throw new Error("residual session container");
      },
      createDriver: () => ({
        async recoverPending() {},
        async probeBuiltin(agent) {
          return metrics(agent, 10, 4);
        },
      }),
    })).rejects.toThrow("residual session container");

    expect(lifecycleLock.release).toHaveBeenCalledOnce();
  });

  test("keeps canonical lifecycle acquisition fenced throughout a recovery retry", async () => {
    const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-matrix-lock-"));
    const stateDirectory = path.join(temporaryDirectory, "state");
    const context = {
      projectRoot: path.join(temporaryDirectory, "project"),
      project: { config: {}, paths: { stateDir: stateDirectory } },
      runtimeRoot: path.join(temporaryDirectory, "runtime"),
      env: {},
    } as unknown as RuntimeContext;
    const held = tryAcquireProjectLifecycleLock(context);
    expect(held).toBeDefined();
    let recoveryAttempts = 0;
    try {
      await expect(executeSessionAdmissionMatrix({
        repetitions: 1,
        acquireLock: () => held,
        waitForRecoveryRetry: async () => {
          expect(tryAcquireProjectLifecycleLock(context)).toBeUndefined();
        },
        createDriver: () => ({
          async probeBuiltin() {
            throw new Error("provisioning failed");
          },
          async recoverPending() {
            recoveryAttempts += 1;
            if (recoveryAttempts === 1) throw new Error("retry recovery");
          },
        }),
      })).rejects.toThrow("exact pending-state recovery succeeded after retry");

      const acquiredAfterRecovery = tryAcquireProjectLifecycleLock(context);
      expect(acquiredAfterRecovery).toBeDefined();
      acquiredAfterRecovery?.release();
    } finally {
      try {
        held?.release();
      } catch {
        // The successful matrix recovery already released it.
      }
      fs.rmSync(temporaryDirectory, { recursive: true, force: true });
    }
  });

  test("honors an interruption between probes and releases the lock", async () => {
    const lifecycleLock = lock();
    let reason: string | undefined;
    const probes: string[] = [];
    await expect(executeSessionAdmissionMatrix({
      repetitions: 2,
      acquireLock: () => lifecycleLock,
      interruptionReason: () => reason,
      createDriver: () => ({
        async recoverPending() {},
        async probeBuiltin(agent) {
          probes.push(agent);
          reason = "SIGTERM";
          return metrics(agent, 10, 4);
        },
      }),
    })).rejects.toThrow("session admission matrix interrupted by SIGTERM");

    expect(probes).toEqual(["claude"]);
    expect(lifecycleLock.release).toHaveBeenCalledTimes(1);
  });

  test("signals the detached worker process group so a long-lived descendant cannot survive", async () => {
    const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-matrix-watchdog-"));
    const statePath = path.join(temporaryDirectory, "processes.json");
    const fixturePath = path.join(
      path.dirname(fileURLToPath(import.meta.url)),
      "fixtures/session-admission-watchdog.cjs",
    );
    const child = childProcess.spawn(process.execPath, [fixturePath, "worker", statePath], {
      detached: true,
      stdio: "ignore",
    });
    let descendantPid: number | undefined;
    try {
      await waitUntil(() => {
        try {
          const parsed = JSON.parse(fs.readFileSync(statePath, "utf8")) as { descendantPid?: unknown };
          if (typeof parsed.descendantPid === "number") descendantPid = parsed.descendantPid;
          return descendantPid !== undefined;
        } catch {
          return false;
        }
      });
      expect(processExists(child.pid as number)).toBe(true);
      expect(processExists(descendantPid as number)).toBe(true);

      signalSessionAdmissionWorkerProcessGroup(child, "SIGTERM");
      await waitUntil(() => !processExists(child.pid as number) && !processExists(descendantPid as number));
    } finally {
      if (child.pid && (processExists(child.pid) || (descendantPid && processExists(descendantPid)))) {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {
          // Already drained.
        }
      }
      fs.rmSync(temporaryDirectory, { recursive: true, force: true });
    }
  });

  test("refuses invalid live targets and never signals a reaped worker process group", () => {
    const kill = vi.spyOn(process, "kill").mockReturnValue(true);
    try {
      signalSessionAdmissionWorkerProcessGroup({
        exitCode: 0,
        signalCode: null,
        pid: 123,
      }, "SIGKILL");
      signalSessionAdmissionWorkerProcessGroup({
        exitCode: null,
        signalCode: "SIGTERM",
        pid: 123,
      }, "SIGKILL");
      expect(kill).not.toHaveBeenCalled();

      expect(() => signalSessionAdmissionWorkerProcessGroup({
        exitCode: null,
        signalCode: null,
      }, "SIGTERM")).toThrow("no exact process-group id");
      expect(() => signalSessionAdmissionWorkerProcessGroup({
        exitCode: null,
        signalCode: null,
        pid: 0,
      }, "SIGTERM")).toThrow("no exact process-group id");
      expect(kill).not.toHaveBeenCalled();
    } finally {
      kill.mockRestore();
    }
  });

  test("bounds cleanup and force-stops a worker process group that ignores TERM", async () => {
    const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-matrix-hard-stop-"));
    const statePath = path.join(temporaryDirectory, "processes.json");
    const fixturePath = path.join(
      path.dirname(fileURLToPath(import.meta.url)),
      "fixtures/session-admission-watchdog.cjs",
    );
    const diagnostics: string[] = [];
    let child: childProcess.ChildProcess | undefined;
    let descendantPid: number | undefined;
    try {
      const completion = superviseSessionAdmissionMatrixWorker({
        cleanupRequestAfterMs: 500,
        cleanupGraceMs: 100,
        forceReapMs: 1_000,
        spawnWorker() {
          child = childProcess.spawn(
            process.execPath,
            [fixturePath, "ignore-term-worker", statePath],
            { detached: true, stdio: "ignore" },
          );
          return child;
        },
        writeDiagnostic: (message) => diagnostics.push(message),
      });
      await waitUntil(() => {
        try {
          const parsed = JSON.parse(fs.readFileSync(statePath, "utf8")) as { descendantPid?: unknown };
          if (typeof parsed.descendantPid === "number") descendantPid = parsed.descendantPid;
          return descendantPid !== undefined;
        } catch {
          return false;
        }
      });
      const leaderPid = child?.pid;
      if (!leaderPid) throw new Error("watchdog hard-stop fixture has no leader pid");
      expect(processExists(leaderPid)).toBe(true);
      expect(processExists(descendantPid as number)).toBe(true);

      await expect(completion).resolves.toBe(124);
      await waitUntil(() => !processExists(leaderPid) && !processExists(descendantPid as number));
      expect(diagnostics.join("\n")).toContain("cleanup grace elapsed");
    } finally {
      if (child?.pid && (processExists(child.pid) || (descendantPid && processExists(descendantPid)))) {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {
          // Already drained.
        }
      }
      fs.rmSync(temporaryDirectory, { recursive: true, force: true });
    }
  });

  test("unrefs the worker and IPC handles when forced reap cannot observe exit", async () => {
    const kill = vi.spyOn(process, "kill").mockReturnValue(true);
    const channelUnref = vi.fn();
    const fakeChild = Object.assign(new EventEmitter(), {
      channel: { ref: vi.fn(), unref: channelUnref },
      connected: true,
      exitCode: null,
      pid: 123,
      signalCode: null,
    }) as unknown as childProcess.ChildProcess;
    const disconnect = vi.fn(() => Object.assign(fakeChild, {
      channel: null,
      connected: false,
    }));
    const unref = vi.fn(() => fakeChild);
    Object.assign(fakeChild, { disconnect, unref });
    const diagnostics: string[] = [];
    try {
      await expect(superviseSessionAdmissionMatrixWorker({
        cleanupRequestAfterMs: 10,
        cleanupGraceMs: 10,
        forceReapMs: 10,
        spawnWorker: () => fakeChild,
        writeDiagnostic: (message) => diagnostics.push(message),
      })).resolves.toBe(124);

      expect(disconnect).toHaveBeenCalledOnce();
      expect(channelUnref).toHaveBeenCalledOnce();
      expect(unref).toHaveBeenCalledOnce();
      expect(diagnostics.join("\n")).toContain("did not report exit after forced stop");

      const disconnectedChild = Object.assign(new EventEmitter(), {
        channel: null,
        connected: false,
        exitCode: null,
        pid: 456,
        signalCode: null,
      }) as unknown as childProcess.ChildProcess;
      const disconnectedDisconnect = vi.fn();
      const disconnectedUnref = vi.fn(() => disconnectedChild);
      Object.assign(disconnectedChild, {
        disconnect: disconnectedDisconnect,
        unref: disconnectedUnref,
      });
      await expect(superviseSessionAdmissionMatrixWorker({
        cleanupRequestAfterMs: 10,
        cleanupGraceMs: 10,
        forceReapMs: 10,
        spawnWorker: () => disconnectedChild,
        writeDiagnostic: (message) => diagnostics.push(message),
      })).resolves.toBe(124);
      expect(disconnectedDisconnect).not.toHaveBeenCalled();
      expect(disconnectedUnref).toHaveBeenCalledOnce();
    } finally {
      kill.mockRestore();
    }
  });

  test("reports exact per-run metrics and nearest-rank p50/p95 by agent", () => {
    const samples: SessionAdmissionMatrixSample[] = [];
    const latencies = {
      claude: [10, 20, 100],
      codex: [11, 21, 101],
      pi: [12, 22, 102],
    } as const;
    for (let iteration = 1; iteration <= 3; iteration += 1) {
      for (const agent of ["claude", "codex", "pi"] as const) {
        samples.push({
          iteration,
          metrics: metrics(agent, latencies[agent][iteration - 1] as number, iteration + 3),
        });
      }
    }

    const aggregates = aggregateSessionAdmissionMatrix(samples, 3);
    expect(aggregates).toEqual([
      {
        agent: "claude",
        dockerOperations: { min: 4, max: 6, p50: 5, p95: 6, values: [4, 5, 6] },
        provisioningToSequenceMs: { min: 10, max: 100, p50: 20, p95: 100, values: [10, 20, 100] },
        samples: 3,
      },
      {
        agent: "codex",
        dockerOperations: { min: 4, max: 6, p50: 5, p95: 6, values: [4, 5, 6] },
        provisioningToSequenceMs: { min: 11, max: 101, p50: 21, p95: 101, values: [11, 21, 101] },
        samples: 3,
      },
      {
        agent: "pi",
        dockerOperations: { min: 4, max: 6, p50: 5, p95: 6, values: [4, 5, 6] },
        provisioningToSequenceMs: { min: 12, max: 102, p50: 22, p95: 102, values: [12, 22, 102] },
        samples: 3,
      },
    ]);
  });

  test("rejects incomplete or reordered results instead of publishing partial metrics", () => {
    expect(() => aggregateSessionAdmissionMatrix([
      { iteration: 1, metrics: metrics("codex", 10, 4) },
      { iteration: 1, metrics: metrics("claude", 10, 4) },
      { iteration: 1, metrics: metrics("pi", 10, 4) },
    ], 1)).toThrow("sample order or identity is invalid");
    expect(() => aggregateSessionAdmissionMatrix([
      { iteration: 1, metrics: metrics("claude", 10, 4) },
    ], 1)).toThrow("expected 3 session admission samples, got 1");
  });
});
