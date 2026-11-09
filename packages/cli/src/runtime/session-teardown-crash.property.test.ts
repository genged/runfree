// Model-based crash test for the session-record teardown lifecycle (SM1).
//
// Two writers mark a record's teardown — `destroy`/`rebuild` transition the
// record to `revoking`; the per-session teardown stamps the host status
// `terminal` — and a host crash can land after any write of either. Whatever
// state that leaves, three readers must agree on it:
//
//   - the pending-admission classifier (`runfree up` defers these records to
//     its reclaim instead of refusing the upgrade over them);
//   - the reclaim itself, which must finish a dead owner's teardown and refuse
//     a live owner's with a remedy that names the session;
//   - `runfree sessions`, which must either list the record or warn about it
//     with the command that finishes it.
//
// The model keeps, per session, whether its record is still on disk and
// whether its teardown has begun. Every command re-checks the three readers
// against that model, so the property is the AGENTS.md reclaim rule itself:
// no crash point leaves a record the upgrade refuses over that the listing
// hides, and none leaves a dead owner's teardown that `runfree up` cannot
// finish. The counterexample that motivated this file (a `revoking` record
// with no stamp after a failed `destroy`) is pinned as a plain example below.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import fc from "fast-check";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { SESSION_FILES_DIR } from "@runfree/runtime-contracts/session-file";

import { runWithCrashAfter } from "../../../../tests/support/crash-steps.ts";
import { propertyParameters } from "../../../../tests/support/property.ts";
import { flushWarnings, pendingWarningsForTest, setOutputWriterForTest } from "../warnings.ts";
import { composeProjectName, projectHash } from "./env.ts";
import { publishControlPlaneMaterializationV2, selectEffectiveControlPlaneV2 } from "./component-state-v2.ts";
import {
  pendingSessionFileAdmissionRecords,
  reclaimPendingSessionAdmissions,
  type PendingSessionAdmissionReclaimInput,
} from "./session-admission-pending-reclaim.ts";
import {
  controlPlaneMaterializationFixture,
  effectiveControlPlaneFixture,
  sessionContainerRecordFixture,
  sessionGenerationFixture,
} from "./session-container.test-harness.ts";
import {
  listSessionContainerRecordsV2,
  readSessionContainerRecordV2,
  removeExactSessionContainerRecordV2,
  replaceExactSessionContainerRecordV2,
  sessionContainerName,
  transitionSessionContainerToRevokingV2,
  writeSessionContainerRecordV2,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import { teardownSessionRecord, UNCERTAIN_SESSION_COMPLETION } from "./session-file-teardown.ts";
import { readSessionHostStatus, removeSessionHostStatus, writeSessionHostStatus } from "./session-host-status.ts";
import { sessionTeardownInFlight } from "./session-teardown-in-flight.ts";
import { activeLifecycleSessions, type ProjectLifecycleLock } from "./sessions.ts";
import type { CaptureResult, RuntimeContext } from "./types.ts";

const RECORDED_BOOT = "linux:11111111-1111-4111-8111-111111111111";
const CURRENT_BOOT = "linux:22222222-2222-4222-8222-222222222222";
const OWN_START = "linux:424242";
// Boot and process-start overrides are honored only under the fake-docker
// harness flag; nothing here reaches Docker, every call goes to `io` below.
const HOST_ENV: NodeJS.ProcessEnv = {
  RUNFREE_TEST_FAKE_DOCKER: "1",
  RUNFREE_TEST_HOST_BOOT_ID: CURRENT_BOOT,
  RUNFREE_TEST_HOST_PROCESS_START: OWN_START,
};

// Session 0's owner died with a previous boot; session 1's owner is this very
// process. The reclaim may finish the first and must refuse the second.
const SESSIONS = [
  { sessionId: "rf-20260808-aaaaaa", containerId: "a".repeat(64), owner: "dead" as const },
  { sessionId: "rf-20260808-bbbbbb", containerId: "b".repeat(64), owner: "alive" as const },
] as const;

const SELECTION = effectiveControlPlaneFixture({ target: sessionGenerationFixture().target });
const PROXY_ID = SELECTION.proxyContainerId;
const OK: CaptureResult = { status: 0, stdout: "", stderr: "" };

function noSuch(reference: string): CaptureResult {
  return { status: 1, stdout: "", stderr: `Error response from daemon: No such container: ${reference}` };
}

type Real = Readonly<{
  stateDir: string;
  expectedProject: SessionContainerProjectIdentity;
  context: RuntimeContext;
  reclaimInput: PendingSessionAdmissionReclaimInput;
}>;

type ModelSession = { present: boolean; inFlight: boolean };
type Model = { sessions: ModelSession[] };

function sessionAt(index: number): (typeof SESSIONS)[number] {
  const session = SESSIONS[index];
  if (!session) throw new Error(`no session ${index}`);
  return session;
}

function modelSession(model: Readonly<Model>, index: number): ModelSession {
  const state = model.sessions[index];
  if (!state) throw new Error(`no model session ${index}`);
  return state;
}

let controlPlaneTemplate: string;
let tmp: string;

beforeAll(() => {
  controlPlaneTemplate = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-teardown-crash-template-"));
  publishControlPlaneMaterializationV2(
    controlPlaneTemplate,
    controlPlaneMaterializationFixture({ target: sessionGenerationFixture().target }),
  );
  selectEffectiveControlPlaneV2(controlPlaneTemplate, SELECTION);
  setOutputWriterForTest(() => undefined);
});

afterAll(() => {
  fs.rmSync(controlPlaneTemplate, { recursive: true, force: true });
  setOutputWriterForTest(undefined);
});

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-teardown-crash-"));
});

afterEach(() => {
  flushWarnings();
  fs.rmSync(tmp, { recursive: true, force: true });
});

/** The Docker a crashed host comes back to: every session container gone, the proxy stopped on tmpfs. */
function dockerAfterCrash(): PendingSessionAdmissionReclaimInput["io"] {
  const projectId = projectHash(path.join(tmp, "project"));
  return {
    capture(command: string, args: string[]): CaptureResult {
      if (command !== "docker") throw new Error(`unexpected command ${command}`);
      if (args[0] === "ps" && args.includes("label=io.runfree.ingress-purpose=mcp-callback")) return OK;
      if (args[0] === "ps" && args.includes(`id=${PROXY_ID}`)) return { ...OK, stdout: `${PROXY_ID}\n` };
      if (args[0] === "ps" && args.includes("label=com.docker.compose.service=proxy")) return OK;
      if (args[0] === "container" && args[1] === "inspect" && args[2] === PROXY_ID) {
        return {
          ...OK,
          stdout: JSON.stringify([{
            Id: PROXY_ID,
            Config: {
              Labels: {
                "io.runfree.project-id": projectId,
                "io.runfree.container-role": "proxy",
                "com.docker.compose.project": `runfree-${projectId}`,
                "com.docker.compose.service": "proxy",
              },
            },
            State: { Running: false, Status: "exited" },
            HostConfig: { Tmpfs: { "/run/runfree-sessions": "mode=0755" } },
          }]),
        };
      }
      if (args[0] === "container" && args[1] === "inspect") return noSuch(args[2] ?? "");
      if (args[0] === "exec" && args.some((arg) => arg.startsWith(`${SESSION_FILES_DIR}/`))) return OK;
      if (args[0] === "network" && args[1] === "disconnect") return OK;
      if (args[0] === "container" && args[1] === "stop") return OK;
      if (args[0] === "container" && args[1] === "rm") return noSuch(args.at(-1) ?? "");
      throw new Error(`unexpected docker ${args.join(" ")}`);
    },
  } as unknown as PendingSessionAdmissionReclaimInput["io"];
}

function setup(): { model: Model; real: Real } {
  const projectRoot = path.join(tmp, "project");
  const stateDir = path.join(tmp, "state");
  fs.mkdirSync(projectRoot, { recursive: true });
  fs.rmSync(stateDir, { recursive: true, force: true });
  fs.cpSync(controlPlaneTemplate, stateDir, { recursive: true });
  const projectId = projectHash(projectRoot);
  const expectedProject = { projectId, composeProject: composeProjectName(projectRoot) };
  for (const session of SESSIONS) {
    const base = sessionContainerRecordFixture({
      containerId: session.containerId,
      overrides: {
        projectId,
        composeProject: expectedProject.composeProject,
        sessionId: session.sessionId,
        containerName: sessionContainerName(projectId, session.sessionId),
        ...(session.owner === "dead"
          ? { hostPid: 123, hostBootId: RECORDED_BOOT }
          : { hostPid: process.pid, hostBootId: CURRENT_BOOT, hostProcessStart: OWN_START }),
      },
    });
    writeSessionContainerRecordV2(stateDir, expectedProject, {
      ...base,
      state: "attached",
      admittedAt: "2026-08-08T12:00:01.000Z",
      leaseGeneration: "8".repeat(32),
      leaseExpiresAt: "2026-08-08T12:05:00.000Z",
    });
  }
  const lock: ProjectLifecycleLock = { ownerToken: "test-owner", assertHeld: () => undefined, release: () => undefined };
  const context = {
    projectRoot,
    project: {
      config: {},
      paths: { stateDir, sessionsDir: path.join(stateDir, "sessions"), inboxDir: path.join(stateDir, "inbox") },
    },
    runtimeRoot: path.join(tmp, "runtime"),
    env: HOST_ENV,
  } as unknown as RuntimeContext;
  const reclaimInput: PendingSessionAdmissionReclaimInput = {
    stateDir,
    expectedProject,
    io: dockerAfterCrash(),
    lifecycleLock: lock,
    env: HOST_ENV,
    nowEpochMs: Date.parse("2026-08-08T13:00:00.000Z"),
  };
  return {
    model: { sessions: SESSIONS.map(() => ({ present: true, inFlight: false })) },
    real: { stateDir, expectedProject, context, reclaimInput },
  };
}

function readRecord(real: Real, index: number): SessionContainerRecordV2 | undefined {
  return readSessionContainerRecordV2(real.stateDir, real.expectedProject, sessionAt(index).sessionId);
}

function requireRecord(real: Real, index: number): SessionContainerRecordV2 {
  const record = readRecord(real, index);
  if (!record) throw new Error(`session ${sessionAt(index).sessionId} has no record on disk`);
  return record;
}

function stampTerminal(real: Real, record: SessionContainerRecordV2): void {
  const now = "2026-08-08T12:30:00.000Z";
  writeSessionHostStatus(real.stateDir, {
    v: 1,
    sessionId: record.sessionId,
    lastHeartbeatAt: now,
    aliveUntil: now,
    served: "unknown",
    terminal: "revoking",
  });
}

/** The three readers against the model. Every command ends here. */
function assertReadersAgree(model: Model, real: Real): void {
  const onDisk = listSessionContainerRecordsV2(real.stateDir, real.expectedProject);
  const presentIds: string[] = SESSIONS.filter((_, i) => modelSession(model, i).present).map((s) => s.sessionId).sort();
  expect(onDisk.map((record) => record.sessionId).sort()).toEqual(presentIds);

  // Reader 1: a record is pending exactly when its teardown is in flight, and
  // that fact is read from both marks, never from one.
  const pending = pendingSessionFileAdmissionRecords({ stateDir: real.stateDir, records: onDisk, nowEpochMs: real.reclaimInput.nowEpochMs });
  const inFlightIds: string[] = SESSIONS.filter((_, i) => modelSession(model, i).present && modelSession(model, i).inFlight).map((s) => s.sessionId).sort();
  expect(pending.map((record) => record.sessionId).sort()).toEqual(inFlightIds);
  for (const record of onDisk) {
    expect(sessionTeardownInFlight(record, readSessionHostStatus(real.stateDir, record.sessionId)))
      .toBe(inFlightIds.includes(record.sessionId));
  }

  // Reader 3: `runfree sessions` lists a session or warns about its teardown.
  flushWarnings();
  const listed = activeLifecycleSessions(real.context, real.reclaimInput.nowEpochMs);
  const warnings = pendingWarningsForTest().map((event) => event.message);
  flushWarnings();
  for (const [index, session] of SESSIONS.entries()) {
    const state = modelSession(model, index);
    const isListed = listed.some((entry) => entry.sessionId === session.sessionId);
    if (!state.present) {
      expect(isListed).toBe(false);
      continue;
    }
    if (!state.inFlight) {
      // An ordinary record is listed exactly when its owner is alive.
      expect(isListed).toBe(session.owner === "alive");
      continue;
    }
    const warned = warnings.some((message) => message.includes(session.sessionId) && message.includes("runfree up"));
    expect(isListed || warned, `session ${session.sessionId} is tearing down but neither listed nor warned about`).toBe(true);
  }
}

class BeginDestroy implements fc.Command<Model, Real> {
  constructor(readonly index: number) {}
  check(model: Readonly<Model>): boolean {
    return modelSession(model, this.index).present;
  }
  run(model: Model, real: Real): void {
    const record = requireRecord(real, this.index);
    if (record.state !== "revoking") {
      // Exactly destroy's first durable step, after which it may die.
      replaceExactSessionContainerRecordV2(real.stateDir, real.expectedProject, record, transitionSessionContainerToRevokingV2(record));
    }
    modelSession(model, this.index).inFlight = true;
    assertReadersAgree(model, real);
  }
  toString(): string {
    return `beginDestroy(${this.index})`;
  }
}

class StampTerminal implements fc.Command<Model, Real> {
  constructor(readonly index: number) {}
  check(model: Readonly<Model>): boolean {
    return modelSession(model, this.index).present;
  }
  run(model: Model, real: Real): void {
    const record = requireRecord(real, this.index);
    // Exactly the reconcile's and the teardown's first durable step.
    stampTerminal(real, record);
    modelSession(model, this.index).inFlight = true;
    assertReadersAgree(model, real);
  }
  toString(): string {
    return `stampTerminal(${this.index})`;
  }
}

/**
 * The per-session teardown, crashed after its k-th publishing write.
 *
 * The teardown publishes exactly three times under the state directory, in
 * the order its contract fixes: the terminal stamp, the record removal (which
 * releases the address), the stamp removal. So k=1 leaves a stamped record,
 * and k>=2 leaves no record.
 */
class TeardownCrash implements fc.Command<Model, Real> {
  constructor(readonly index: number, readonly afterWrites: 1 | 2 | 3) {}
  check(model: Readonly<Model>): boolean {
    return modelSession(model, this.index).present;
  }
  run(model: Model, real: Real): void {
    const record = requireRecord(real, this.index);
    const outcome = runWithCrashAfter(real.stateDir, this.afterWrites, () => teardownSessionRecord({
      io: real.reclaimInput.io,
      proxyId: PROXY_ID,
      record: record,
      expectedProject: real.expectedProject,
      networkId: SELECTION.networkIds.agentInternal,
      lock: () => undefined,
      markTerminal: () => stampTerminal(real, record),
      clearStamp: () => removeSessionHostStatus(real.stateDir, record.sessionId),
      removeRecord: () => removeExactSessionContainerRecordV2(real.stateDir, real.expectedProject, record),
      // The proxy is stopped: nothing to delete, as the reclaim path proves.
      removeSessionFile: () => undefined,
      completion: () => UNCERTAIN_SESSION_COMPLETION,
    }));
    expect(outcome.kind, `teardown crash point ${this.afterWrites}: ${JSON.stringify(outcome)}`).toBe("crashed");
    expect(outcome.writes).toBe(this.afterWrites);
    const state = modelSession(model, this.index);
    if (this.afterWrites === 1) {
      state.inFlight = true;
    } else {
      state.present = false;
      state.inFlight = false;
    }
    assertReadersAgree(model, real);
  }
  toString(): string {
    return `teardownCrash(${this.index}, after ${this.afterWrites})`;
  }
}

/** Reader 2: what `runfree up` runs under the lifecycle lock before planning. */
class Reclaim implements fc.Command<Model, Real> {
  check(): boolean {
    return true;
  }
  run(model: Model, real: Real): void {
    const result = reclaimPendingSessionAdmissions(real.reclaimInput);
    const inFlight = SESSIONS.map((session, i) => ({ session, state: modelSession(model, i) }))
      .filter(({ state }) => state.present && state.inFlight);
    const liveOwners = inFlight.filter(({ session }) => session.owner === "alive");
    if (inFlight.length === 0) {
      expect(result.kind).toBe("none");
    } else if (liveOwners.length === 0) {
      expect(result, "a dead owner's interrupted teardown must be finished, not refused").toEqual({
        kind: "reclaimed",
        sessionIds: inFlight.map(({ session }) => session.sessionId),
      });
    } else {
      expect(result.kind).toBe("refused");
      if (result.kind === "refused") {
        expect([...result.sessionIds].sort()).toEqual(liveOwners.map(({ session }) => session.sessionId).sort());
        for (const { session } of liveOwners) {
          expect(result.reasons.some((reason) => reason.includes(session.sessionId) && reason.includes("retry the command once it exits"))).toBe(true);
        }
      }
    }
    for (const { session, state } of inFlight) {
      if (session.owner === "dead") {
        state.present = false;
        state.inFlight = false;
      }
    }
    assertReadersAgree(model, real);
  }
  toString(): string {
    return "reclaim";
  }
}

const index = fc.integer({ min: 0, max: SESSIONS.length - 1 });
const commands = fc.commands(
  [
    index.map((i) => new BeginDestroy(i)),
    index.map((i) => new StampTerminal(i)),
    fc.tuple(index, fc.constantFrom(1 as const, 2 as const, 3 as const)).map(([i, k]) => new TeardownCrash(i, k)),
    fc.constant(new Reclaim()),
    fc.constant(new Reclaim()),
  ],
  { maxCommands: 12, size: "+1" },
);

describe("session teardown crash points", () => {
  it("SM1: every interrupted teardown is pending to `up`, finished or named by its reclaim, and visible to `sessions`", () => {
    fc.assert(
      fc.property(commands, (sequence) => {
        fc.modelRun(setup, sequence);
      }),
      // Each run copies a control plane and touches real files, so fewer runs
      // than a pure classifier property; the command space is small.
      propertyParameters({ numRuns: 60 }),
    );
  });

  it("a `destroy` that died after marking one record revoking leaves a teardown `up` finishes", () => {
    // The counterexample this file was written for: no stamp, only the
    // record's own state, after which `runfree up` used to refuse the
    // upgrade over a session `runfree sessions` did not list.
    const { model, real } = setup();
    new BeginDestroy(0).run(model, real);
    expect(readRecord(real, 0)?.state).toBe("revoking");
    expect(readSessionHostStatus(real.stateDir, SESSIONS[0].sessionId)).toBeUndefined();
    new Reclaim().run(model, real);
    expect(readRecord(real, 0)).toBeUndefined();
    expect(readRecord(real, 1)?.state).toBe("attached");
  });
});
