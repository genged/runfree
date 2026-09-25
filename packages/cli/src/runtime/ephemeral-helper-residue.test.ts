import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import {
  EphemeralHelperUnconfirmedError,
  helperMarkerPath,
  legacyHelperRunsRoot,
  markHelperRunPending,
  PENDING_CREATE_GRACE_MS,
  readHelperMarker,
  reclaimHelperResidue,
  removeHelperState,
  settleHelperRun,
  sweepProjectHelpers,
  type EphemeralHelperFence,
} from "./ephemeral-helper-residue.ts";
import type { CaptureResult, RuntimeIO } from "./types.ts";

const PROJECT_ID = "0123456789ab";
const OTHER_PROJECT_ID = "ba9876543210";
const HELPER_ID = "a".repeat(64);
const SECOND_HELPER_ID = "b".repeat(64);
const SESSION_ID = "c".repeat(64);
const FOREIGN_HELPER_ID = "d".repeat(64);
const NOW_MS = Date.parse("2026-09-24T12:00:00.000Z");

let stateDir: string;

beforeEach(() => {
  stateDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-helper-residue-")));
});

afterEach(() => {
  fs.rmSync(stateDir, { recursive: true, force: true });
});

type Container = { id: string; labels: Record<string, string> };

function helper(id: string, projectId = PROJECT_ID): Container {
  return {
    id,
    labels: {
      "io.runfree.container-role": "ephemeral-helper",
      "io.runfree.project-id": projectId,
      "io.runfree.helper-purpose": "deny-probe",
    },
  };
}

function session(id: string): Container {
  return { id, labels: { "io.runfree.container-role": "session-agent", "io.runfree.project-id": PROJECT_ID } };
}

type Call = { kind: "docker"; args: string[] } | { kind: "assertHeld" };

/** A Docker double over a container table; every call is logged beside every lock assertion. */
function fakeDocker(initial: Container[] = []) {
  const containers = new Map(initial.map((entry) => [entry.id, entry]));
  const calls: Call[] = [];
  const hooks: { ps?: (args: string[]) => CaptureResult | undefined; rm?: (ids: string[]) => boolean } = {};
  let lockThrowsAt: number | undefined;
  let assertions = 0;
  const capture = (command: string, args: string[]): CaptureResult => {
    expect(command).toBe("docker");
    calls.push({ kind: "docker", args });
    if (args[0] === "ps") {
      const hooked = hooks.ps?.(args);
      if (hooked) return hooked;
      const filters = args.filter((arg) => arg.startsWith("label=")).map((arg) => arg.slice(6).split("="));
      const matching = [...containers.values()].filter((entry) => filters.every(([key, value]) => entry.labels[key] === value));
      return { status: 0, stdout: matching.map((entry) => `${entry.id}\n`).join(""), stderr: "" };
    }
    if (args[0] === "rm" && args[1] === "--force") {
      const ids = args.slice(2);
      if (hooks.rm?.(ids) !== false) for (const id of ids) containers.delete(id);
      return { status: 0, stdout: "", stderr: "" };
    }
    throw new Error(`unexpected docker call: ${args.join(" ")}`);
  };
  const fence = (): EphemeralHelperFence => ({
    lifecycleLock: {
      assertHeld: () => {
        assertions += 1;
        calls.push({ kind: "assertHeld" });
        if (lockThrowsAt !== undefined && assertions >= lockThrowsAt) throw new Error("project lifecycle lock was lost");
      },
    },
    containmentIO: { capture } as unknown as RuntimeIO,
    stateDir,
  });
  return {
    containers,
    calls,
    hooks,
    fence,
    dockerCalls: () => calls.filter((call): call is Extract<Call, { kind: "docker" }> => call.kind === "docker"),
    rmCalls: () => calls.filter((call) => call.kind === "docker" && call.args[0] === "rm"),
    loseLockAt: (nth: number) => { lockThrowsAt = nth; },
  };
}

const NO_WAIT = { sleep: () => {}, pollDeadlineMs: 0, wallClockMs: () => NOW_MS } as const;
// Past the late-create window of a marker written at NOW_MS.
const AFTER_WINDOW = { ...NO_WAIT, wallClockMs: () => NOW_MS + PENDING_CREATE_GRACE_MS + 1 } as const;

describe("sweepProjectHelpers", () => {
  test("removes exactly this project's helpers, never a session or another project's helper", () => {
    const docker = fakeDocker([helper(HELPER_ID), helper(SECOND_HELPER_ID), session(SESSION_ID), helper(FOREIGN_HELPER_ID, OTHER_PROJECT_ID)]);
    expect(sweepProjectHelpers(docker.fence(), PROJECT_ID, NO_WAIT)).toBe(2);
    expect([...docker.containers.keys()].sort()).toEqual([SESSION_ID, FOREIGN_HELPER_ID].sort());
    const listing = docker.dockerCalls()[0].args;
    expect(listing).toEqual(expect.arrayContaining([
      `label=io.runfree.project-id=${PROJECT_ID}`,
      "label=io.runfree.container-role=ephemeral-helper",
    ]));
  });

  test("no helper costs one listing and no removal", () => {
    const docker = fakeDocker([session(SESSION_ID)]);
    expect(sweepProjectHelpers(docker.fence(), PROJECT_ID, NO_WAIT)).toBe(0);
    expect(docker.dockerCalls()).toHaveLength(1);
    expect(docker.rmCalls()).toEqual([]);
  });

  test("every Docker call is fenced by a lock assertion before and after", () => {
    const docker = fakeDocker([helper(HELPER_ID)]);
    sweepProjectHelpers(docker.fence(), PROJECT_ID, NO_WAIT);
    const kinds = docker.calls.map((call) => call.kind);
    kinds.forEach((kind, index) => {
      if (kind === "docker") {
        expect(kinds[index - 1]).toBe("assertHeld");
        expect(kinds[index + 1]).toBe("assertHeld");
      }
    });
  });

  test.each([
    ["a failed listing", { status: 1, stdout: "", stderr: "Cannot connect to the Docker daemon" }],
    ["a timed-out listing with empty output", { status: 124, stdout: "", stderr: "" }],
    ["a non-id line", { status: 0, stdout: "not-an-id\n", stderr: "" }],
  ])("%s is unconfirmed and removes nothing", (_name, answer) => {
    const docker = fakeDocker([helper(HELPER_ID)]);
    docker.hooks.ps = () => answer;
    expect(() => sweepProjectHelpers(docker.fence(), PROJECT_ID, NO_WAIT)).toThrow(EphemeralHelperUnconfirmedError);
    expect(docker.rmCalls()).toEqual([]);
  });

  test("a successful listing with a stderr warning is still an answer", () => {
    const docker = fakeDocker([helper(HELPER_ID)]);
    const listed = { status: 0, stdout: `${HELPER_ID}\n`, stderr: "WARNING: config deprecated" };
    docker.hooks.ps = (args) => (docker.containers.size > 0 ? listed : { status: 0, stdout: "", stderr: "WARNING: config deprecated" });
    expect(sweepProjectHelpers(docker.fence(), PROJECT_ID, NO_WAIT)).toBe(1);
  });

  test("a helper still listed after rm is unconfirmed and names both remedies", () => {
    const docker = fakeDocker([helper(HELPER_ID)]);
    docker.hooks.rm = () => false;
    expect(() => sweepProjectHelpers(docker.fence(), PROJECT_ID, NO_WAIT)).toThrow(/runfree up.*runfree destroy --force/u);
  });

  test("absence is polled until Docker's own --rm catches up", () => {
    const docker = fakeDocker([helper(HELPER_ID)]);
    let lists = 0;
    docker.hooks.rm = () => false;
    docker.hooks.ps = () => {
      lists += 1;
      return lists >= 3 ? { status: 0, stdout: "", stderr: "" } : undefined;
    };
    let clock = 0;
    expect(sweepProjectHelpers(docker.fence(), PROJECT_ID, { sleep: (ms) => { clock += ms; }, now: () => clock, pollDeadlineMs: 5_000 }))
      .toBe(1);
  });

  test("a lost lock before the listing removes nothing", () => {
    const docker = fakeDocker([helper(HELPER_ID)]);
    docker.loseLockAt(1);
    expect(() => sweepProjectHelpers(docker.fence(), PROJECT_ID, NO_WAIT)).toThrow(EphemeralHelperUnconfirmedError);
    expect(docker.dockerCalls()).toEqual([]);
  });

  test("a lost lock after the listing never reaches rm", () => {
    const docker = fakeDocker([helper(HELPER_ID)]);
    docker.loseLockAt(2);
    expect(() => sweepProjectHelpers(docker.fence(), PROJECT_ID, NO_WAIT)).toThrow(EphemeralHelperUnconfirmedError);
    expect(docker.rmCalls()).toEqual([]);
  });
});

describe("reclaimHelperResidue", () => {
  test("no marker and no legacy directory costs no Docker call and no lock assertion", () => {
    const docker = fakeDocker([helper(HELPER_ID)]);
    expect(reclaimHelperResidue(docker.fence(), PROJECT_ID, NO_WAIT)).toEqual({ swept: 0 });
    expect(docker.calls).toEqual([]);
  });

  test("a marker left by a dead run sweeps and is cleared once its late-create window has passed", () => {
    markHelperRunPending(stateDir, NO_WAIT);
    const docker = fakeDocker([helper(HELPER_ID)]);
    expect(reclaimHelperResidue(docker.fence(), PROJECT_ID, AFTER_WINDOW)).toEqual({ swept: 1 });
    expect(docker.containers.size).toBe(0);
    expect(readHelperMarker(stateDir)).toBeUndefined();
  });

  test("a marker left by a dead run is kept for the window after its spawn: the dead client may have been mid-create", () => {
    markHelperRunPending(stateDir, NO_WAIT);
    const early = fakeDocker();
    expect(reclaimHelperResidue(early.fence(), PROJECT_ID, { ...NO_WAIT, wallClockMs: () => NOW_MS + 60_000 })).toEqual({ swept: 0 });
    expect(readHelperMarker(stateDir)).toBeDefined();
    // The late container lands; the next lock holder's sweep removes it.
    const late = fakeDocker([helper(HELPER_ID)]);
    expect(reclaimHelperResidue(late.fence(), PROJECT_ID, AFTER_WINDOW)).toEqual({ swept: 1 });
    expect(readHelperMarker(stateDir)).toBeUndefined();
  });

  test("a new run carries a left-behind window forward instead of resetting it", () => {
    markHelperRunPending(stateDir, NO_WAIT);
    markHelperRunPending(stateDir, { ...NO_WAIT, wallClockMs: () => NOW_MS + 60_000 });
    settleHelperRun(fakeDocker().fence(), PROJECT_ID, { clean: true, clientKilled: false }, { ...NO_WAIT, wallClockMs: () => NOW_MS + 61_000 });
    expect(readHelperMarker(stateDir)?.lateCreateUntil).toBe(new Date(NOW_MS + PENDING_CREATE_GRACE_MS).toISOString());
  });

  test("an unconfirmed sweep keeps the marker for the next lock holder", () => {
    markHelperRunPending(stateDir, NO_WAIT);
    const docker = fakeDocker([helper(HELPER_ID)]);
    docker.hooks.ps = () => ({ status: 1, stdout: "", stderr: "daemon down" });
    expect(() => reclaimHelperResidue(docker.fence(), PROJECT_ID, AFTER_WINDOW)).toThrow(EphemeralHelperUnconfirmedError);
    expect(readHelperMarker(stateDir)).toBeDefined();
  });

  test.each([
    ["malformed JSON", "{not json"],
    ["an unknown version", "{\"v\":2}\n"],
  ])("a marker with %s still sweeps, then is cleared", (_name, content) => {
    fs.writeFileSync(helperMarkerPath(stateDir), content);
    const docker = fakeDocker([helper(HELPER_ID)]);
    expect(reclaimHelperResidue(docker.fence(), PROJECT_ID, NO_WAIT)).toEqual({ swept: 1 });
    expect(fs.existsSync(helperMarkerPath(stateDir))).toBe(false);
  });

  test("a legacy helper-runs directory sweeps and is removed", () => {
    fs.mkdirSync(path.join(legacyHelperRunsRoot(stateDir), "run-AbC123"), { recursive: true });
    const docker = fakeDocker([helper(HELPER_ID)]);
    expect(reclaimHelperResidue(docker.fence(), PROJECT_ID, NO_WAIT)).toEqual({ swept: 1 });
    expect(fs.existsSync(legacyHelperRunsRoot(stateDir))).toBe(false);
  });

  test("a symlinked legacy root is unlinked, never followed", () => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-helper-outside-"));
    try {
      fs.writeFileSync(path.join(outside, "keep"), "x");
      fs.symlinkSync(outside, legacyHelperRunsRoot(stateDir));
      reclaimHelperResidue(fakeDocker().fence(), PROJECT_ID, NO_WAIT);
      expect(fs.existsSync(path.join(outside, "keep"))).toBe(true);
      expect(() => fs.lstatSync(legacyHelperRunsRoot(stateDir))).toThrow();
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });
});

describe("late create window", () => {
  test("a killed client opens the window: the marker survives an empty sweep", () => {
    markHelperRunPending(stateDir, NO_WAIT);
    const docker = fakeDocker();
    settleHelperRun(docker.fence(), PROJECT_ID, { clean: false, clientKilled: true }, NO_WAIT);
    expect(readHelperMarker(stateDir)?.lateCreateUntil).toBe(new Date(NOW_MS + PENDING_CREATE_GRACE_MS).toISOString());
  });

  test("inside the window a later lock holder sweeps again and keeps the marker", () => {
    markHelperRunPending(stateDir, NO_WAIT);
    settleHelperRun(fakeDocker().fence(), PROJECT_ID, { clean: false, clientKilled: true }, NO_WAIT);
    const late = fakeDocker([helper(HELPER_ID)]);
    expect(reclaimHelperResidue(late.fence(), PROJECT_ID, { ...NO_WAIT, wallClockMs: () => NOW_MS + 60_000 })).toEqual({ swept: 1 });
    expect(late.containers.size).toBe(0);
    expect(readHelperMarker(stateDir)?.lateCreateUntil).toBeDefined();
  });

  test("after the window an empty sweep clears the marker", () => {
    markHelperRunPending(stateDir, NO_WAIT);
    settleHelperRun(fakeDocker().fence(), PROJECT_ID, { clean: false, clientKilled: true }, NO_WAIT);
    reclaimHelperResidue(fakeDocker().fence(), PROJECT_ID, AFTER_WINDOW);
    expect(readHelperMarker(stateDir)).toBeUndefined();
  });

  test("a clean run inside an open window keeps the window", () => {
    markHelperRunPending(stateDir, NO_WAIT);
    settleHelperRun(fakeDocker().fence(), PROJECT_ID, { clean: false, clientKilled: true }, NO_WAIT);
    markHelperRunPending(stateDir, NO_WAIT);
    const docker = fakeDocker();
    settleHelperRun(docker.fence(), PROJECT_ID, { clean: true, clientKilled: false }, NO_WAIT);
    expect(docker.dockerCalls()).toEqual([]);
    expect(readHelperMarker(stateDir)?.lateCreateUntil).toBeDefined();
  });
});

describe("settleHelperRun", () => {
  test("a clean exit makes no Docker call and clears the marker", () => {
    markHelperRunPending(stateDir, NO_WAIT);
    const docker = fakeDocker([helper(HELPER_ID)]);
    settleHelperRun(docker.fence(), PROJECT_ID, { clean: true, clientKilled: false }, NO_WAIT);
    expect(docker.dockerCalls()).toEqual([]);
    expect(readHelperMarker(stateDir)).toBeUndefined();
  });

  test("an unclean exit whose client exited on its own sweeps and clears", () => {
    markHelperRunPending(stateDir, NO_WAIT);
    const docker = fakeDocker([helper(HELPER_ID)]);
    settleHelperRun(docker.fence(), PROJECT_ID, { clean: false, clientKilled: false }, NO_WAIT);
    expect(docker.containers.size).toBe(0);
    expect(readHelperMarker(stateDir)).toBeUndefined();
  });
});

test("removeHelperState clears the marker and the legacy directory", () => {
  markHelperRunPending(stateDir, NO_WAIT);
  fs.mkdirSync(legacyHelperRunsRoot(stateDir));
  removeHelperState(stateDir);
  expect(fs.existsSync(helperMarkerPath(stateDir))).toBe(false);
  expect(fs.existsSync(legacyHelperRunsRoot(stateDir))).toBe(false);
});
