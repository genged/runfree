import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import type { SessionFileV1 } from "@runfree/runtime-contracts/session-file";

import { setOutputWriterForTest } from "../warnings.ts";
import {
  lostForegroundStream,
  waitForAttachedSessionCompletion,
  type AttachedSessionWaitPorts,
  type LostForegroundStreamDecision,
} from "./session-attached-wait.ts";
import type {
  SessionContainerForegroundCompletion,
  SessionContainerForegroundHandle,
} from "./session-container-start.ts";
import type { HeartbeatOutcome } from "./session-file-heartbeat.ts";

type Settle = (completion: SessionContainerForegroundCompletion) => void;

function foregroundHandle(): { handle: SessionContainerForegroundHandle; settle: Settle } {
  let settle!: Settle;
  const completion = new Promise<SessionContainerForegroundCompletion>((resolve) => { settle = resolve; });
  return { handle: { completion } as unknown as SessionContainerForegroundHandle, settle };
}

const writtenFile = { aliveUntil: "2026-09-30T00:05:00.000Z" } as unknown as SessionFileV1;

function ports(overrides: Partial<AttachedSessionWaitPorts> & { foreground: SessionContainerForegroundHandle }): AttachedSessionWaitPorts {
  return {
    cadenceMs: 1_000,
    beat: vi.fn(async (): Promise<HeartbeatOutcome> => ({ kind: "written", file: writtenFile })),
    adoptDurableSelectionIfChanged: vi.fn(async () => {}),
    classifyAdoptionFailure: vi.fn(() => "fatal" as const),
    releaseLockForWait: vi.fn(),
    onBeatWritten: vi.fn(),
    onBeatRetrying: vi.fn(),
    leaseExpiry: vi.fn(() => undefined),
    classifyLostStream: vi.fn((): LostForegroundStreamDecision => ({ kind: "wait", observation: "unreachable" })),
    reattach: vi.fn(async () => { throw new Error("no re-attach in this test"); }),
    reportCompletion: vi.fn((completion: SessionContainerForegroundCompletion) => {
      if (completion.kind === "error") throw completion.error;
      return { status: completion.code, signal: completion.signal };
    }),
    reportInspectedExit: vi.fn((status: number) => ({ status, signal: null })),
    ...overrides,
  };
}

describe("attached session wait", () => {
  const lines: string[] = [];
  beforeEach(() => {
    vi.useFakeTimers();
    lines.length = 0;
    setOutputWriterForTest((line) => lines.push(line));
  });
  afterEach(() => {
    setOutputWriterForTest(undefined);
    vi.useRealTimers();
  });

  test("a lost stream is an error or a signal-only exit, never a numeric exit", () => {
    expect(lostForegroundStream({ kind: "error", error: new Error("x") })).toBe(true);
    expect(lostForegroundStream({ kind: "exit", code: null, signal: "SIGKILL" })).toBe(true);
    expect(lostForegroundStream({ kind: "exit", code: 0, signal: null })).toBe(false);
    expect(lostForegroundStream({ kind: "exit", code: 137, signal: null })).toBe(false);
  });

  test("an ordinary exit returns its status and stops the heartbeat", async () => {
    const { handle, settle } = foregroundHandle();
    const wait = ports({ foreground: handle });
    const outcome = waitForAttachedSessionCompletion(wait);
    await vi.advanceTimersByTimeAsync(2_500);
    expect(wait.beat).toHaveBeenCalledTimes(2);
    settle({ kind: "exit", code: 3, signal: null });
    await expect(outcome).resolves.toEqual({ status: 3, signal: null });
    await vi.advanceTimersByTimeAsync(10_000);
    expect(wait.beat).toHaveBeenCalledTimes(2);
    expect(wait.onBeatWritten).toHaveBeenCalledWith(writtenFile);
  });

  test("a lost stream whose container is proved exited reports the inspected status", async () => {
    const { handle, settle } = foregroundHandle();
    const wait = ports({
      foreground: handle,
      classifyLostStream: vi.fn((): LostForegroundStreamDecision => ({ kind: "exited", status: 42 })),
    });
    const outcome = waitForAttachedSessionCompletion(wait);
    settle({ kind: "exit", code: null, signal: "SIGKILL" });
    await expect(outcome).resolves.toEqual({ status: 42, signal: null });
    expect(wait.reportInspectedExit).toHaveBeenCalledWith(42);
    expect(wait.reportCompletion).not.toHaveBeenCalled();
  });

  test("an unconfirmed lost stream waits for the beat, and a mismatch beat answers it with teardown", async () => {
    const { handle, settle } = foregroundHandle();
    const beat = vi.fn(async (): Promise<HeartbeatOutcome> => ({ kind: "mismatch", observation: "container is gone", deleted: true }));
    const wait = ports({ foreground: handle, beat });
    const outcome = waitForAttachedSessionCompletion(wait);
    const lost = { kind: "exit" as const, code: null, signal: "SIGTERM" as const };
    settle(lost);
    await vi.advanceTimersByTimeAsync(0);
    expect(lines.some((line) => line.includes("session output stream lost: unreachable"))).toBe(true);
    await vi.advanceTimersByTimeAsync(1_000);
    await expect(outcome).resolves.toEqual({ status: null, signal: "SIGTERM" });
    expect(wait.reportCompletion).toHaveBeenCalledWith(lost);
    expect(lines.some((line) => line.includes("cannot be recovered: container is gone"))).toBe(true);
  });

  test("a running container is re-attached and the race continues on the new stream", async () => {
    const first = foregroundHandle();
    const second = foregroundHandle();
    const wait = ports({
      foreground: first.handle,
      classifyLostStream: vi.fn((): LostForegroundStreamDecision => ({ kind: "reattach" })),
      reattach: vi.fn(async () => second.handle),
    });
    const outcome = waitForAttachedSessionCompletion(wait);
    first.settle({ kind: "error", error: new Error("stream closed") });
    await vi.advanceTimersByTimeAsync(0);
    expect(wait.reattach).toHaveBeenCalledWith(first.handle);
    second.settle({ kind: "exit", code: 0, signal: null });
    await expect(outcome).resolves.toEqual({ status: 0, signal: null });
  });

  test("failing beats never end the session; a written beat after a gap is announced", async () => {
    const { handle, settle } = foregroundHandle();
    const outcomes: HeartbeatOutcome[] = [
      { kind: "unavailable", error: Object.assign(new Error("daemon busy")) } as HeartbeatOutcome,
      { kind: "unavailable", error: Object.assign(new Error("daemon busy")) } as HeartbeatOutcome,
      { kind: "written", file: writtenFile },
    ];
    const wait = ports({ foreground: handle, beat: vi.fn(async (): Promise<HeartbeatOutcome> => outcomes.shift() ?? { kind: "written", file: writtenFile }) });
    const outcome = waitForAttachedSessionCompletion(wait);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(wait.onBeatRetrying).toHaveBeenCalledTimes(2);
    expect(lines.some((line) => line.includes("session network restored"))).toBe(true);
    settle({ kind: "exit", code: 0, signal: null });
    await expect(outcome).resolves.toEqual({ status: 0, signal: null });
  });

  test("a fatal adoption failure stops renewal and fails the wait; a preserved one keeps beating", async () => {
    const fatal = foregroundHandle();
    const failing = ports({
      foreground: fatal.handle,
      adoptDurableSelectionIfChanged: vi.fn(async () => { throw new Error("incompatible replacement"); }),
    });
    const failed = waitForAttachedSessionCompletion(failing);
    // The renewal loop's own rejection wins the race: the refusal is the news.
    const failure = expect(failed).rejects.toThrow("incompatible replacement");
    await vi.advanceTimersByTimeAsync(1_000);
    await failure;
    expect(failing.beat).not.toHaveBeenCalled();

    const preserved = foregroundHandle();
    const tolerant = ports({
      foreground: preserved.handle,
      adoptDurableSelectionIfChanged: vi.fn(async () => { throw new Error("rebind in flight"); }),
      classifyAdoptionFailure: vi.fn(() => "preserve" as const),
    });
    const kept = waitForAttachedSessionCompletion(tolerant);
    await vi.advanceTimersByTimeAsync(3_000);
    expect(tolerant.beat).toHaveBeenCalledTimes(3);
    expect(tolerant.releaseLockForWait).toHaveBeenCalledTimes(3);
    expect(lines.filter((line) => line.includes("rebind in flight"))).toHaveLength(1);
    preserved.settle({ kind: "exit", code: 0, signal: null });
    await expect(kept).resolves.toEqual({ status: 0, signal: null });
  });

  test("a re-attach that cannot spawn waits on the beat, which answers with the container's proved exit", async () => {
    const { handle, settle } = foregroundHandle();
    const decisions: LostForegroundStreamDecision[] = [{ kind: "reattach" }, { kind: "exited", status: 7 }];
    const wait = ports({
      foreground: handle,
      classifyLostStream: vi.fn((): LostForegroundStreamDecision => decisions.shift() ?? { kind: "wait", observation: "unreachable" }),
      reattach: vi.fn(async () => { throw new Error("docker start --attach could not spawn"); }),
    });
    const outcome = waitForAttachedSessionCompletion(wait);
    settle({ kind: "error", error: new Error("stream closed") });
    await vi.advanceTimersByTimeAsync(0);
    expect(lines.some((line) => line.includes("session output stream lost: docker start --attach could not spawn"))).toBe(true);
    await vi.advanceTimersByTimeAsync(1_000);
    await expect(outcome).resolves.toEqual({ status: 7, signal: null });
    expect(wait.reportInspectedExit).toHaveBeenCalledWith(7);
    expect(wait.reportCompletion).not.toHaveBeenCalled();
    expect(lines.some((line) => line.includes("session container exited with code 7"))).toBe(true);
  });
});
