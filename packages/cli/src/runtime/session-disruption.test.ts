import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, test, vi } from "vitest";
import { publishControlPlaneMaterializationV2, selectEffectiveControlPlaneV2 } from "./component-state-v2.ts";
import { assertSessionDisruptionAuthorized } from "./session-disruption.ts";
import {
  controlPlaneMaterializationFixture,
  effectiveControlPlaneFixture,
  sessionContainerRecordFixture,
  SESSION_TEST_PROJECT,
} from "./session-container.test-harness.ts";
import { transitionSessionContainerToRevokingV2, writeSessionContainerRecordV2 } from "./session-containers.ts";
import { writeSessionHostStatus } from "./session-host-status.ts";

const liveness = vi.hoisted(() => ({ value: "alive" as "alive" | "dead" | "unknown" }));
vi.mock("./session-record-liveness.ts", () => ({ sessionRecordOwnerLiveness: () => liveness.value }));
const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });

test.each([
  ["alive", false], ["unknown", false], ["alive", true], ["unknown", true],
] as const)("explicit stop and reload preserve %s owners (revoking: %s) until forced", (owner, revoking) => {
  liveness.value = owner;
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-disruption-")); roots.push(stateDir);
  const record = sessionContainerRecordFixture();
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, revoking ? transitionSessionContainerToRevokingV2(record) : record);
  const input = { stateDir, expectedProject: SESSION_TEST_PROJECT,
    lifecycleLock: { ownerToken: "a".repeat(64), assertHeld() {}, release() {} } };
  for (const operation of ["stop", "runtime reload-policy"] as const) {
    expect(() => assertSessionDisruptionAuthorized({ ...input, operation })).toThrow(`runfree ${operation} --force`);
    expect(() => assertSessionDisruptionAuthorized({ ...input, operation, force: true })).not.toThrow();
  }
  liveness.value = "dead";
  expect(() => assertSessionDisruptionAuthorized({ ...input, operation: "stop" })).not.toThrow();
});

// There is no admission journal to read, so what says "a lifecycle transaction
// is in flight" is a record whose host status stamp is terminal: its owner has
// begun revoking it, and stopping the runtime underneath that teardown is
// exactly the disruption this gate exists to refuse.
test("a terminal-stamped record refuses disruption even with a dead owner", () => {
    liveness.value = "dead";
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-disruption-files-")); roots.push(stateDir);
    publishControlPlaneMaterializationV2(stateDir, controlPlaneMaterializationFixture());
    selectEffectiveControlPlaneV2(stateDir, effectiveControlPlaneFixture());
    const record = sessionContainerRecordFixture();
    writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, record);
    writeSessionHostStatus(stateDir, {
      v: 1,
      sessionId: record.sessionId,
      lastHeartbeatAt: "2026-09-07T12:00:00.000Z",
      aliveUntil: "2026-09-07T12:00:30.000Z",
      served: "served",
      terminal: "revoking",
    });
    const input = { stateDir, expectedProject: SESSION_TEST_PROJECT,
      lifecycleLock: { ownerToken: "a".repeat(64), assertHeld() {}, release() {} } };
    for (const operation of ["stop", "runtime reload-policy"] as const) {
      expect(() => assertSessionDisruptionAuthorized({ ...input, operation })).toThrow(record.sessionId);
      expect(() => assertSessionDisruptionAuthorized({ ...input, operation })).toThrow(`runfree ${operation} --force`);
      expect(() => assertSessionDisruptionAuthorized({ ...input, operation, force: true })).not.toThrow();
    }
});

test("force cannot bypass the exact lifecycle fence", () => {
  expect(() => assertSessionDisruptionAuthorized({ stateDir: "/unused", expectedProject: SESSION_TEST_PROJECT,
    lifecycleLock: { ownerToken: "a".repeat(64), assertHeld() { throw new Error("fence lost"); }, release() {} },
    operation: "stop", force: true })).toThrow("fence lost");
});
