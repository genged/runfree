import type * as childProcess from "node:child_process";
import { performance } from "node:perf_hooks";

import {
  executeSessionDockerCommand,
  sessionContainerInspectCommand,
} from "./session-container-docker.ts";
import {
  SessionContainerNotRunningYetError,
  SESSION_CONTAINER_INSPECT_MAX_BYTES,
  validateSessionContainerInspect,
  type SessionContainerProof,
} from "./session-container-proof.ts";
import {
  assertSessionContainerForegroundHandleIdentity,
  currentSessionContainerForegroundCompletion,
  type SessionContainerForegroundCompletion,
  type SessionContainerForegroundHandle,
} from "./session-container-start.ts";
import {
  assertSessionContainerCreatePlan,
  type SessionContainerCreatePlan,
} from "./session-container-template.ts";
import type { CaptureResult } from "./types.ts";

export type SessionContainerRunningProofExecutor = (
  executable: "docker",
  args: readonly string[],
  options?: childProcess.SpawnSyncOptions,
) => CaptureResult;

export type SessionContainerRunningProofOptions = Readonly<{
  timeoutMs?: number;
  pollMs?: number;
  nowMs?: () => number;
  delay?: (milliseconds: number) => Promise<void>;
  dockerOptions?: childProcess.SpawnSyncOptions;
}>;

function positiveBoundedInteger(value: number | undefined, fallback: number, maximum: number, label: string): number {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > maximum) {
    throw new Error(`${label} must be between 1 and ${maximum} milliseconds`);
  }
  return selected;
}

function foregroundEnded(outcome: SessionContainerForegroundCompletion): Error {
  if (outcome.kind === "error") {
    return new Error(`foreground Docker attach failed before running proof: ${outcome.error.message}`, {
      cause: outcome.error,
    });
  }
  return new Error(
    `foreground Docker attach exited before running proof: code=${outcome.code ?? "<none>"} signal=${outcome.signal ?? "<none>"}`,
  );
}

export async function waitForRunningSessionContainerProof(
  executor: SessionContainerRunningProofExecutor,
  plan: SessionContainerCreatePlan,
  handle: SessionContainerForegroundHandle,
  options: SessionContainerRunningProofOptions = {},
): Promise<SessionContainerProof> {
  assertSessionContainerCreatePlan(plan);
  if (plan.record.state !== "provisioning-running") {
    throw new Error("running proof requires a provisioning-running session-container plan");
  }
  assertSessionContainerForegroundHandleIdentity(handle, plan.record, plan.expectedProject);
  const timeoutMs = positiveBoundedInteger(options.timeoutMs, 5_000, 30_000, "running proof timeout");
  const pollMs = positiveBoundedInteger(options.pollMs, 25, 1_000, "running proof poll interval");
  const nowMs = options.nowMs ?? (() => performance.now());
  const delay = options.delay ?? ((milliseconds: number) => new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, milliseconds);
    timer.unref();
  }));
  const startedAt = nowMs();

  while (true) {
    const remainingMs = timeoutMs - (nowMs() - startedAt);
    if (remainingMs <= 0) break;
    const beforeInspect = currentSessionContainerForegroundCompletion(handle);
    if (beforeInspect) throw foregroundEnded(beforeInspect);
    const command = sessionContainerInspectCommand(plan.record, plan.expectedProject);
    const result = executeSessionDockerCommand(command, (executable, args) => (
      executor(executable, args, {
        ...options.dockerOptions,
        maxBuffer: SESSION_CONTAINER_INSPECT_MAX_BYTES,
        timeout: Math.max(1, Math.ceil(remainingMs)),
      })
    ));
    if (result.status !== 0) throw new Error("Docker failed to inspect the foreground session container");
    try {
      const proof = validateSessionContainerInspect(result.stdout, plan, { kind: "provisioning-running" });
      const afterInspect = currentSessionContainerForegroundCompletion(handle);
      if (afterInspect) throw foregroundEnded(afterInspect);
      if (nowMs() - startedAt >= timeoutMs) break;
      return proof;
    } catch (error) {
      if (!(error instanceof SessionContainerNotRunningYetError)) throw error;
    }
    const delayRemainingMs = timeoutMs - (nowMs() - startedAt);
    if (delayRemainingMs <= 0) break;
    const outcome = await Promise.race([
      handle.completion.then((completion) => ({ kind: "completion" as const, completion })),
      delay(Math.min(pollMs, delayRemainingMs)).then(() => ({ kind: "delay" as const })),
    ]);
    if (outcome.kind === "completion") throw foregroundEnded(outcome.completion);
  }
  throw new Error("foreground session container did not reach Docker running state before timeout");
}
