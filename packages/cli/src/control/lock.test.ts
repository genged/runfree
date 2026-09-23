import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { projectInfo, type ProjectInfo } from "../config.ts";
import { controlLockPath, tryAcquireControlLock } from "./lock.ts";

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
});
