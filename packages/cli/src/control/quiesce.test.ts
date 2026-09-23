import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { projectInfo } from "../config.ts";
import { writeLiveAttachedSessionContainerRecordFixture } from "../runtime/session-container.test-harness.ts";
import { sessionContainerRecordsRoot } from "../runtime/session-containers.ts";
import { writeSessionHostStatus } from "../runtime/session-host-status.ts";
import { projectLifecycleLockPath } from "../runtime/sessions.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { ProjectQuiesceError, withQuiescedProject } from "./quiesce.ts";

describe("quiesced project transaction", () => {
  let root: string;
  let context: RuntimeContext;
  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-quiesce-"));
    const projectRoot = path.join(root, "project");
    fs.mkdirSync(projectRoot);
    fs.mkdirSync(path.join(projectRoot, ".runfree"));
    // A real ProjectInfo, not a stateDir stub: the locked prelude now reads the
    // approvals record, so a project that cannot name its own control paths
    // would be a fixture that silently skips the funnel.
    const env = {
      XDG_STATE_HOME: path.join(root, "state"),
      XDG_CONFIG_HOME: path.join(root, "config"),
      RUNFREE_TEST_FAKE_DOCKER: "1",
      RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
      RUNFREE_TEST_HOST_PROCESS_START: "linux:12345",
    };
    context = {
      projectRoot,
      project: projectInfo(projectRoot, env),
      runtimeRoot: path.join(root, "runtime"),
      env,
    } as unknown as RuntimeContext;
  });
  afterEach(() => fs.rmSync(root, { recursive: true }));

  // Sessions are never paused, inspected, or resumed by a control transaction
  // (A2 decision): any Docker call from this path is a regression.
  function fakeIo() {
    const calls: string[][] = [];
    const io = {
      capture: (_command: string, args: string[]) => {
        calls.push(args);
        throw new Error(`unexpected docker call: ${args.join(" ")}`);
      },
      run: () => 0,
      commandExists: () => true,
      confirm: () => false,
      admin: async () => 0,
    } as unknown as RuntimeIO;
    return { calls, io };
  }

  function writeLiveSessionRecord(sessionId: string): { command: string; displayName: string } {
    return writeLiveAttachedSessionContainerRecordFixture({
      stateDir: context.project.paths.stateDir,
      projectRoot: context.projectRoot,
      env: context.env,
      sessionId,
    });
  }

  test("holds the lifecycle lock for the action and touches no container", async () => {
    const fake = fakeIo();
    await expect(withQuiescedProject(context, fake.io, () => {
      expect(fs.existsSync(projectLifecycleLockPath(context))).toBe(true);
      return "captured";
    })).resolves.toBe("captured");
    expect(fs.existsSync(projectLifecycleLockPath(context))).toBe(false);
    expect(fake.calls).toEqual([]);
  });

  test("releases the lock and propagates an action failure", async () => {
    const fake = fakeIo();
    await expect(withQuiescedProject(context, fake.io, () => {
      throw new Error("action failed");
    })).rejects.toThrow("action failed");
    expect(fs.existsSync(projectLifecycleLockPath(context))).toBe(false);
  });

  test("refuses a concurrent lifecycle holder before any trusted work", async () => {
    fs.mkdirSync(projectLifecycleLockPath(context), { recursive: true });
    fs.writeFileSync(path.join(projectLifecycleLockPath(context), "pid"), `${process.pid}\n`);
    const fake = fakeIo();
    let acted = false;
    await expect(withQuiescedProject(context, fake.io, () => {
      acted = true;
    }, {
      lifecycleLockRetry: { attempts: 3, delayMs: 5 },
    })).rejects.toBeInstanceOf(ProjectQuiesceError);
    expect(acted).toBe(false);
    expect(fake.calls).toEqual([]);
  });

  // A host that cannot report process starts is the documented "owner
  // unprovable" case: the record is ordinary, the current host simply cannot
  // corroborate its PID, so the classifier falls back to an expiry — which is
  // exactly where the host status stamp replaces the record's frozen lease.
  function contextThatCannotProveOwnership(): RuntimeContext {
    return {
      ...context,
      env: { ...context.env, RUNFREE_TEST_HOST_PROCESS_START: "unreportable" },
    } as RuntimeContext;
  }

  function stampSession(sessionId: string, aliveUntilMs: number): void {
    writeSessionHostStatus(context.project.paths.stateDir, {
      v: 1,
      sessionId,
      lastHeartbeatAt: new Date(aliveUntilMs - 60_000).toISOString(),
      aliveUntil: new Date(aliveUntilMs).toISOString(),
      served: "served",
    });
  }

  test("refuses a control change when advisory stamp writes stopped and ownership is unknown", async () => {
    // A failed host stamp write does not stop the proxy heartbeat. Its old
    // readable stamp must not authorize a destructive control change.
    const sessionId = "rf-20260907-stamped";
    writeLiveSessionRecord(sessionId);
    stampSession(sessionId, Date.now() - 1_000);
    const fake = fakeIo();

    await expect(withQuiescedProject(contextThatCannotProveOwnership(), fake.io, () => "proceeded"))
      .rejects.toThrow(ProjectQuiesceError);
    expect(fake.calls).toEqual([]);
  });

  test("refuses a control change for a beating session whose admission lease froze in the past", async () => {
    // The inverse, and the reason the stamp exists: under the session-file
    // design `leaseExpiresAt` freezes at admission, so a still-beating session
    // carries a lease that lapsed an hour ago.
    const sessionId = "rf-20260907-beating";
    writeLiveAttachedSessionContainerRecordFixture({
      stateDir: context.project.paths.stateDir,
      projectRoot: context.projectRoot,
      env: context.env,
      sessionId,
      leaseExpiresAt: new Date(Date.now() - 60 * 60_000).toISOString(),
    });
    stampSession(sessionId, Date.now() + 60_000);
    const fake = fakeIo();
    let acted = false;

    await expect(withQuiescedProject(contextThatCannotProveOwnership(), fake.io, () => {
      acted = true;
    })).rejects.toThrow("control change deferred because 1 active per-session agent is running");
    expect(acted).toBe(false);
    expect(fake.calls).toEqual([]);
  });

  test("refuses a control change while a per-session agent is active", async () => {
    const sessionId = "rf-20260824-quiesce1";
    const written = writeLiveSessionRecord(sessionId);
    const fake = fakeIo();
    let acted = false;

    const failure = withQuiescedProject(context, fake.io, () => {
      acted = true;
    });
    await expect(failure).rejects.toThrow("control change deferred because 1 active per-session agent is running");
    await expect(failure).rejects.toThrow(sessionId);
    await expect(failure).rejects.toThrow(written.displayName);
    await expect(failure).rejects.toThrow(written.command);
    await expect(failure).rejects.toThrow(`host pid ${process.pid}`);

    expect(acted).toBe(false);
    expect(fake.calls).toEqual([]);
    expect(fs.existsSync(projectLifecycleLockPath(context))).toBe(false);
  });

  test("allowLiveSessions runs the action beside a live per-session agent without touching it", async () => {
    writeLiveSessionRecord("rf-20260901-livemut1");
    const fake = fakeIo();
    await expect(withQuiescedProject(context, fake.io, () => {
      expect(fs.existsSync(projectLifecycleLockPath(context))).toBe(true);
      return "mutated";
    }, { allowLiveSessions: true })).resolves.toBe("mutated");
    expect(fake.calls).toEqual([]);
    expect(fs.existsSync(projectLifecycleLockPath(context))).toBe(false);
  });

  test("the live-session opt-in set is exactly the typed desired-policy mutations", () => {
    // A scope gate, not a spelling check: enumerate every module that imports
    // the quiesce transaction and every module that mentions the opt-in, then
    // require both sets to match an explicit allowlist. A file-name substring
    // assertion would stay green when a NEW module opts in, or when a call site
    // passes options built in a helper.
    const sourceRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
    const sources: string[] = [];
    const walk = (directory: string): void => {
      for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        const full = path.join(directory, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) sources.push(full);
      }
    };
    walk(sourceRoot);

    const relative = (file: string): string => path.relative(sourceRoot, file);
    const importers = sources
      .filter((file) => /from "\.{1,2}(?:\/[\w.-]+)*\/quiesce\.ts"/u.test(fs.readFileSync(file, "utf8")))
      .map(relative)
      .sort();
    const optIns = sources
      .filter((file) => relative(file) !== "control/quiesce.ts" && fs.readFileSync(file, "utf8").includes("allowLiveSessions"))
      .map(relative)
      .sort();

    // Opting in means: this path carries the full capture -> approved-base ->
    // atomic-write -> re-read exact-match -> content-addressed-approve chain,
    // which is what replaces the deleted pause (A2). Adding a module here needs
    // that chain and a security review, not just a passing test.
    //
    // Two entries, not three families: `desired-policy-transaction.ts` owns
    // that chain once for the host, service, and credential mutations, and
    // `local-host-mutation.ts` opts in a second time for the read-only rules
    // query, which holds the same approved base but writes nothing.
    expect(optIns).toEqual([
      "control/desired-policy-transaction.ts",
      "control/local-host-mutation.ts",
    ]);
    // Every other importer takes the default refusal. A new importer trips this
    // and forces an explicit decision about which side it belongs on.
    expect(importers).toEqual([
      "commands/image.ts",
      "commands/init.ts",
      "control/desired-policy-transaction.ts",
      "control/local-host-mutation.ts",
      "control/workflow.ts",
    ]);
  });

  test("refuses unreadable lifecycle state even under allowLiveSessions", async () => {
    writeLiveSessionRecord("rf-20260901-livemut2");
    fs.writeFileSync(
      path.join(sessionContainerRecordsRoot(context.project.paths.stateDir), "corrupt.json"),
      "{not json",
    );
    const fake = fakeIo();
    let acted = false;
    await expect(withQuiescedProject(context, fake.io, () => {
      acted = true;
    }, { allowLiveSessions: true })).rejects.toThrow("session-container lifecycle state is unreadable");
    expect(acted).toBe(false);
    expect(fake.calls).toEqual([]);
  });
});
