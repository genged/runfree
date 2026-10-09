import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { projectInfo, type ProjectInfo } from "../config.ts";
import {
  ControlLockBusyError,
  controlLockPath,
  tryAcquireControlLock,
  waitWhileControlLockBusy,
  withControlLock,
} from "./lock.ts";

describe("shared control lock", () => {
  let root: string;
  let stateHome: string;
  let project: ProjectInfo;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-control-lock-"));
    stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-control-lock-state-"));
    fs.mkdirSync(path.join(root, ".runfree"));
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), '{"version":2,"hosts":[]}\n');
    project = projectInfo(root, { XDG_STATE_HOME: stateHome });
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true });
    fs.rmSync(stateHome, { recursive: true });
  });

  test("admits only one control operation and releases for the next operation", () => {
    const first = tryAcquireControlLock(project);
    expect(first).toBeDefined();
    expect(tryAcquireControlLock(project)).toBeUndefined();

    first?.release();
    const next = tryAcquireControlLock(project);
    expect(next).toBeDefined();
    next?.release();
  });

  test("reclaims a lock proven to belong to an earlier host boot", () => {
    const lockPath = controlLockPath(project);
    fs.mkdirSync(lockPath, { recursive: true });
    fs.writeFileSync(path.join(lockPath, "owner.json"), `${JSON.stringify({
      schemaVersion: 1,
      pid: process.pid,
      nonce: "old-owner",
      createdAt: "2026-01-01T00:00:00.000Z",
      hostBootId: "linux:11111111-1111-1111-1111-111111111111",
    })}\n`);

    const lock = tryAcquireControlLock(project, {
      RUNFREE_TEST_FAKE_DOCKER: "1",
      RUNFREE_TEST_HOST_BOOT_ID: "linux:22222222-2222-2222-2222-222222222222",
    });

    expect(lock).toBeDefined();
    expect(fs.readFileSync(path.join(lockPath, "owner.json"), "utf8")).not.toContain("old-owner");
    lock?.release();
  });

  test("an old holder cannot release a replacement lock", () => {
    const first = tryAcquireControlLock(project);
    expect(first).toBeDefined();
    const lockPath = controlLockPath(project);
    fs.rmSync(lockPath, { recursive: true });
    const replacement = tryAcquireControlLock(project);
    expect(replacement).toBeDefined();

    first?.release();
    expect(fs.existsSync(lockPath)).toBe(true);
    replacement?.release();
  });

  test("a busy lock fails withControlLock at once with a typed error and the original message", () => {
    const held = tryAcquireControlLock(project);
    expect(held).toBeDefined();
    const action = vi.fn(() => "ran");
    let thrown: unknown;
    try {
      withControlLock(project, action);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(ControlLockBusyError);
    expect((thrown as Error).message).toBe(`another control operation is in progress (${controlLockPath(project)})`);
    expect(action).not.toHaveBeenCalled();
    held?.release();
  });

  test("a lock left by a dead owner is reclaimed on the first try of a wait", async () => {
    const exited = spawnSync(process.execPath, ["-e", ""]);
    const deadPid = exited.pid;
    expect(deadPid).toBeGreaterThan(0);
    const lockPath = controlLockPath(project);
    fs.mkdirSync(lockPath, { recursive: true });
    fs.writeFileSync(path.join(lockPath, "owner.json"), `${JSON.stringify({
      schemaVersion: 1,
      pid: deadPid,
      nonce: "dead-owner",
      createdAt: "2026-01-01T00:00:00.000Z",
    })}\n`);
    const attempt = vi.fn(() => withControlLock(project, () => fs.readFileSync(path.join(lockPath, "owner.json"), "utf8")));

    const owner = await waitWhileControlLockBusy(project, attempt, { attempts: 3, delayMs: 1 });

    expect(attempt).toHaveBeenCalledTimes(1);
    expect(owner).not.toContain("dead-owner");
    expect(fs.existsSync(lockPath)).toBe(false);
  });

  describe("waiting while the lock is busy", () => {
    test("succeeds once the holder releases the lock mid-wait, with a periodic diagnostic", async () => {
      const held = tryAcquireControlLock(project);
      expect(held).toBeDefined();
      const logs: string[] = [];
      let tries = 0;
      const result = await waitWhileControlLockBusy(project, () => {
        tries += 1;
        if (tries === 3) held?.release();
        return withControlLock(project, () => "done");
      }, { attempts: 10, delayMs: 5, diagnosticIntervalMs: 1, log: (line) => logs.push(line) });

      expect(result).toBe("done");
      expect(tries).toBe(3);
      expect(logs.length).toBeGreaterThan(0);
      expect(logs[0]).toMatch(/^waiting for the project control lock \(\d+s; lock: /);
      expect(logs[0]).toContain(controlLockPath(project));
    });

    test("fails with the original busy error once the bounded wait is spent", async () => {
      const held = tryAcquireControlLock(project);
      expect(held).toBeDefined();
      const attempt = vi.fn(() => withControlLock(project, () => "never"));

      await expect(waitWhileControlLockBusy(project, attempt, { attempts: 4, delayMs: 1, log: () => {} }))
        .rejects.toThrow(new ControlLockBusyError(controlLockPath(project)));
      expect(attempt).toHaveBeenCalledTimes(4);
      held?.release();
    });

    test("does not retry an error that is not lock contention", async () => {
      const failure = new Error("control publication failed");
      const attempt = vi.fn(() => {
        throw failure;
      });

      await expect(waitWhileControlLockBusy(project, attempt, { attempts: 5, delayMs: 1 })).rejects.toBe(failure);
      expect(attempt).toHaveBeenCalledTimes(1);
    });
  });
});
