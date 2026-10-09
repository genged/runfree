// Unit coverage for the resume stub's shell syntax and ready/release
// handshake (`agent-stub.ts`).
//
// The live crash tranche runs this script inside a session container, where
// a syntax error or a stuck handshake costs a full Docker cycle to discover.
// Both are provable without Docker: `sh -n` proves the generated script
// parses, and running it directly against a host temp directory (in place of
// the container's bind-mounted `/workspace`) proves the bare and
// per-conversation ready/release names it writes and waits on, including
// that two concurrently resumed conversations do not share one release.

import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, test } from "vitest";

import { resumeStub, startObservationStub } from "./agent-stub.ts";

// A sentinel tail distinct from the real `exec sleep 3600` the long-lived
// agent image appends: an unexercised stub falls through to this exit code,
// which proves the fallthrough rather than merely proving the process ended.
const FALLTHROUGH_EXIT = 7;

function stageStub(directory: string): string {
  return `${resumeStub(directory)}\nexit ${FALLTHROUGH_EXIT}\n`;
}

async function waitFor(predicate: () => boolean, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("condition was never met");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

function childExit(child: childProcess.ChildProcess): Promise<number | null> {
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (status) => resolve(status));
  });
}

describe("resume stub", () => {
  test("is syntactically valid sh, exactly as staged for the long-lived agent binary", () => {
    const script = `#!/bin/sh\n${stageStub("/workspace/.runfree-resume-stub")}`;
    const syntax = childProcess.spawnSync("sh", ["-n"], { encoding: "utf8", input: script });
    expect(syntax.status, syntax.stderr).toBe(0);
  });

  test("falls through untouched when --resume never appears in argv", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "resume-stub-"));
    try {
      const result = childProcess.spawnSync(
        "sh",
        ["-c", stageStub(dir), "stub", "--dangerously-skip-permissions", "--add-dir", "/runfree/inbox"],
        { encoding: "utf8" },
      );
      expect(result.status, result.stderr).toBe(FALLTHROUGH_EXIT);
      expect(fs.existsSync(path.join(dir, "ready"))).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("falls through untouched when --resume is the last argument with no id after it", () => {
    // Never happens in production (the driver always appends the exact
    // conversation id after --resume), but the stub must not hang or crash
    // on it: `$prev` is only checked against the *next* `$a`, so a trailing
    // --resume with nothing after it is never matched.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "resume-stub-"));
    try {
      const result = childProcess.spawnSync(
        "sh",
        ["-c", stageStub(dir), "stub", "--resume"],
        { encoding: "utf8" },
      );
      expect(result.status, result.stderr).toBe(FALLTHROUGH_EXIT);
      expect(fs.existsSync(path.join(dir, "ready"))).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("writes the bare and id-qualified ready files, and the bare release still ends it (single-conversation case)", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "resume-stub-"));
    const conversationId = "11111111-1111-4111-8111-111111111111";
    try {
      const child = childProcess.spawn("sh", ["-c", stageStub(dir), "stub", "--resume", conversationId]);
      const exit = childExit(child);
      await waitFor(() => fs.existsSync(path.join(dir, "ready")) && fs.existsSync(path.join(dir, `ready-${conversationId}`)));
      fs.writeFileSync(path.join(dir, "release"), "");
      expect(await exit).toBe(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("two concurrently resumed conversations each wait on their own ready/release pair", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "resume-stub-"));
    const idA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const idB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    try {
      const childA = childProcess.spawn("sh", ["-c", stageStub(dir), "stub", "--resume", idA]);
      const childB = childProcess.spawn("sh", ["-c", stageStub(dir), "stub", "--resume", idB]);
      const exitA = childExit(childA);
      const exitB = childExit(childB);
      await waitFor(() => fs.existsSync(path.join(dir, `ready-${idA}`)) && fs.existsSync(path.join(dir, `ready-${idB}`)));

      fs.writeFileSync(path.join(dir, `release-${idA}`), "");
      expect(await exitA).toBe(0);
      // Releasing A alone must never also release B: a shared bare release
      // would make two concurrent resumes look like one process answering
      // for both.
      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(childB.exitCode).toBeNull();

      fs.writeFileSync(path.join(dir, `release-${idB}`), "");
      expect(await exitB).toBe(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("start observation stub", () => {
  function observe(dir: string, portFile: string, env: NodeJS.ProcessEnv): childProcess.SpawnSyncReturns<string> {
    return childProcess.spawnSync("sh", ["-c", startObservationStub(dir, portFile)], { encoding: "utf8", env, timeout: 10_000 });
  }

  test("is syntactically valid sh", () => {
    const syntax = childProcess.spawnSync("sh", ["-n"], { encoding: "utf8", input: startObservationStub("/workspace/x", "/tmp/p") });
    expect(syntax.status, syntax.stderr).toBe(0);
  });

  test("records the port file's contents under the hostname when no session id is set", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "start-observation-"));
    try {
      const portFile = path.join(dir, "port");
      fs.writeFileSync(portFile, "41234");
      const result = observe(path.join(dir, "records"), portFile, { PATH: process.env.PATH, HOSTNAME: "abc123" });
      expect(result.status, result.stderr).toBe(0);
      expect(fs.readFileSync(path.join(dir, "records", "abc123"), "utf8")).toBe("41234\n");
      expect(fs.existsSync(path.join(dir, "records", "abc123.tmp"))).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("records absent under the session id when the port file does not exist", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "start-observation-"));
    try {
      const result = observe(path.join(dir, "records"), path.join(dir, "missing"), {
        PATH: process.env.PATH,
        HOSTNAME: "abc123",
        RUNFREE_SESSION_ID: "session-1",
      });
      expect(result.status, result.stderr).toBe(0);
      expect(fs.readFileSync(path.join(dir, "records", "session-1"), "utf8")).toBe("absent\n");
      expect(fs.existsSync(path.join(dir, "records", "abc123"))).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
