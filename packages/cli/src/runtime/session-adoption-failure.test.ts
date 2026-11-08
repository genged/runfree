// How the attached wait classifies an adoption failure (SM14 F1).
//
// The wait preserves a live agent over anything that is not a decision about
// its authority. A host read fault on the durable selection — the file
// mid-rename during a concurrent rebind, a selection whose materialization is
// momentarily gone — used to surface as a plain Error, which classified as
// fatal and tore the session down. It is observation evidence now.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import {
  controlPlaneMaterializationsRootV2,
  publishControlPlaneMaterializationV2,
  selectEffectiveControlPlaneV2,
} from "./component-state-v2.ts";
import { RuntimeObservationError } from "./observation-failure.ts";
import {
  classifyAttachedAdoptionFailure,
  readDurableControlPlaneForAdoption,
} from "./session-admission-driver.ts";
import {
  controlPlaneMaterializationFixture,
  effectiveControlPlaneFixture,
  sessionGenerationFixture,
} from "./session-container.test-harness.ts";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe("attached-wait adoption failures", () => {
  test("a host read fault on the durable selection preserves the session instead of ending it", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-adoption-"));
    roots.push(stateDir);
    const target = sessionGenerationFixture().target;
    const selection = effectiveControlPlaneFixture({ target });
    publishControlPlaneMaterializationV2(stateDir, controlPlaneMaterializationFixture({ target }));
    selectEffectiveControlPlaneV2(stateDir, selection);
    expect(readDurableControlPlaneForAdoption(stateDir, selection.proxyContainerId)?.selection).toEqual(selection);

    // The selection now points at a materialization that is not there: what
    // a reader sees between a rebind's two publications.
    fs.rmSync(controlPlaneMaterializationsRootV2(stateDir), { recursive: true, force: true });
    let caught: unknown;
    try {
      readDurableControlPlaneForAdoption(stateDir, selection.proxyContainerId);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(RuntimeObservationError);
    expect((caught as RuntimeObservationError).evidence).toMatchObject({
      kind: "observation-unavailable",
      subject: "registry",
      expectedIdentity: selection.proxyContainerId,
    });
    expect(classifyAttachedAdoptionFailure(caught)).toBe("preserve");
  });

  test("only a decision about the session's authority is fatal", () => {
    expect(classifyAttachedAdoptionFailure(new Error("incompatible control-plane replacement"))).toBe("fatal");
    expect(classifyAttachedAdoptionFailure(new RuntimeObservationError({
      kind: "identity-contradiction",
      subject: "proxy",
      expectedIdentity: "a".repeat(64),
      phase: "adoption",
      observation: "another proxy answered",
    }))).toBe("fatal");
    expect(classifyAttachedAdoptionFailure(new RuntimeObservationError({
      kind: "observation-unavailable",
      subject: "proxy",
      expectedIdentity: "a".repeat(64),
      phase: "adoption",
      observation: "docker did not answer",
    }))).toBe("preserve");
  });
});
