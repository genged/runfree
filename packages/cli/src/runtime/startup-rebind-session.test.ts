// The per-session proof a compatible proxy replacement runs before it rebinds a
// live session's record to the candidate proxy.
//
// A rebind happens across CLI upgrades, so the live session may predate this
// CLI. The retained proof plan is replaced with the harness plan (it needs a
// complete retained image/template fixture and proves nothing about labels);
// the Docker inspection and the container proof are real.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, expect, test, vi } from "vitest";

vi.mock("./session-admission-driver-preflight.ts", async (importOriginal) => {
  const harness = await import("./session-container.test-harness.ts");
  return {
    ...await importOriginal<typeof import("./session-admission-driver-preflight.ts")>(),
    createRetainedSessionRebindProofPlan: (input: Readonly<{ replacementRecord: SessionContainerRecordV2; runfreeVersion: string }>) => (
      harness.sessionContainerCreatePlanFixture({ record: input.replacementRecord, runfreeVersion: input.runfreeVersion })
    ),
  };
});

import { RUNFREE_VERSION_LABEL } from "./constants.ts";
import {
  controlPlaneMaterializationFixture,
  effectiveControlPlaneFixture,
  sessionContainerCreatePlanFixture,
  sessionContainerInspectJsonFixture,
  sessionContainerRecordFixture,
  SESSION_TEST_PROJECT,
} from "./session-container.test-harness.ts";
import { SESSION_CONTAINER_LABELS, type SessionContainerRecordV2 } from "./session-containers.ts";
import { proveRebindSession } from "./startup.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { CaptureResult, RuntimeIO } from "./types.ts";

const CONTAINER_ID = "a".repeat(64);
const CURRENT_VERSION = "0.4.0";

let stateDir: string;

beforeEach(() => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-startup-rebind-session-"));
});

afterEach(() => {
  fs.rmSync(stateDir, { recursive: true, force: true });
});

function lifecycleLock(): ProjectLifecycleLock {
  return { ownerToken: "test-owner", assertHeld: vi.fn(), release: vi.fn() };
}

/** The live container exactly as Docker reports it, created by `createdBy`. */
function liveContainer(record: SessionContainerRecordV2, createdBy: string): Record<string, any> {
  const [inspect] = JSON.parse(sessionContainerInspectJsonFixture(
    sessionContainerCreatePlanFixture({ record, runfreeVersion: createdBy }),
    { running: true },
  )) as Array<Record<string, any>>;
  return inspect as Record<string, any>;
}

function proveAgainst(container: Record<string, any>, record: SessionContainerRecordV2) {
  const capture = vi.fn((_command: string, args: string[]): CaptureResult => {
    if (args[0] === "container" && args[1] === "inspect" && args.includes(CONTAINER_ID)) {
      return { status: 0, stdout: JSON.stringify([container]), stderr: "" };
    }
    throw new Error(`unexpected Docker command: ${args.join(" ")}`);
  });
  return proveRebindSession({
    plan: {
      projectId: SESSION_TEST_PROJECT.projectId,
      composeProjectName: SESSION_TEST_PROJECT.composeProject,
      paths: { stateDir },
      runfreeVersion: CURRENT_VERSION,
    } as unknown as ActiveRuntimePlan,
    replacementRecord: record,
    candidateSelection: effectiveControlPlaneFixture(),
    candidateMaterialization: controlPlaneMaterializationFixture(),
    docker: { inspectImage: vi.fn(() => undefined) },
    io: { capture } as unknown as RuntimeIO,
    dockerOptions: {},
    lifecycleLock: lifecycleLock(),
  });
}

test.each(["0.3.0", "0.5.0"])("a live session created by runfree %s is proved for rebind", (createdBy) => {
  const record = sessionContainerRecordFixture({ containerId: CONTAINER_ID });
  const container = liveContainer(record, createdBy);
  expect(container.Config.Labels[RUNFREE_VERSION_LABEL]).toBe(createdBy);

  expect(proveAgainst(container, record).containerId).toBe(CONTAINER_ID);
});

test("a live session from another release with a changed admission epoch is refused", () => {
  const record = sessionContainerRecordFixture({ containerId: CONTAINER_ID });
  const container = liveContainer(record, "0.3.0");
  container.Config.Labels[SESSION_CONTAINER_LABELS.admissionContractEpoch] = "99";

  expect(() => proveAgainst(container, record))
    .toThrow(`session container label differs: ${SESSION_CONTAINER_LABELS.admissionContractEpoch}`);
});

test("a rebind with no proved or journalled candidate refuses before inspecting the session", () => {
  const record = sessionContainerRecordFixture({ containerId: CONTAINER_ID });
  const capture = vi.fn();
  expect(() => proveRebindSession({
    plan: {
      projectId: SESSION_TEST_PROJECT.projectId,
      composeProjectName: SESSION_TEST_PROJECT.composeProject,
      paths: { stateDir },
      runfreeVersion: CURRENT_VERSION,
    } as unknown as ActiveRuntimePlan,
    replacementRecord: record,
    candidateSelection: undefined,
    candidateMaterialization: controlPlaneMaterializationFixture(),
    docker: { inspectImage: vi.fn(() => undefined) },
    io: { capture } as unknown as RuntimeIO,
    dockerOptions: {},
    lifecycleLock: lifecycleLock(),
  })).toThrow("control-plane rebind candidate proof is missing before session proof");
  expect(capture).not.toHaveBeenCalled();
});
