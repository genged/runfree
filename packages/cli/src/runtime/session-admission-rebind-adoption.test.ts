import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { beforeEach, describe, expect, test, vi, type Mock } from "vitest";

import {
  createControlPlaneGenerationV2,
  createControlPlaneMaterializationManifestV2,
  publishControlPlaneMaterializationV2,
  selectEffectiveControlPlaneV2,
  type ControlPlaneEffectiveSelectionV2,
  type ControlPlaneMaterializationManifestV2,
} from "./component-state-v2.ts";
import { sha256Digest } from "./component-state.ts";
import {
  createControlPlaneRebindTransaction,
  createReboundSessionContainerRecordV2,
  prepareControlPlaneRebindTransaction,
} from "./control-plane-rebind.ts";
import {
  adoptCompatibleSessionControlPlaneRebind,
} from "./session-admission-rebind-adoption.ts";
import {
  controlPlaneMaterializationFixture,
  effectiveControlPlaneFixture,
  SESSION_TEST_PROJECT,
  sessionContainerRecordFixture,
  sessionGenerationFixture,
} from "./session-container.test-harness.ts";
import {
  parseSessionContainerRecordV2,
  replaceExactSessionContainerRecordForControlPlaneRebindV2,
  serializeSessionContainerRecordV2,
  sessionContainerRecordPath,
  replaceExactSessionContainerRecordV2,
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2,
  transitionProvisioningRunningSessionContainerToAttachedV2,
  transitionSessionContainerToRevokingV2,
  writeSessionContainerRecordV2,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";

const LEASE = Object.freeze({
  admittedAt: "2026-08-08T12:00:01.000Z",
  leaseGeneration: "e".repeat(32),
  leaseExpiresAt: "2026-08-08T12:05:00.000Z",
});
const REBIND_NOW = new Date("2026-08-08T12:04:00.000Z");

let stateDir: string;

beforeEach(() => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-rebind-adoption-"));
});

function lifecycleLock(): ProjectLifecycleLock & { assertHeld: Mock<() => void> } {
  return { ownerToken: "test-owner", assertHeld: vi.fn<() => void>(), release: vi.fn<() => void>() };
}

function candidateSelection(
  base: ControlPlaneEffectiveSelectionV2,
  manifest: ControlPlaneMaterializationManifestV2,
  overrides: Partial<ControlPlaneEffectiveSelectionV2> = {},
): ControlPlaneEffectiveSelectionV2 {
  return {
    ...base,
    controlPlaneGenerationDigest: manifest.generation.controlPlaneGenerationDigest,
    controlPlaneMaterializationDigest: manifest.controlPlaneMaterializationDigest,
    proxyContainerId: "6".repeat(64),
    proxyImageId: manifest.proxyImageId,
    admissionContractEpoch: manifest.generation.admissionContractEpoch,
    selectedAt: "2026-08-08T12:03:00.000Z",
    ...overrides,
  };
}

function fixture() {
  const { target } = sessionGenerationFixture();
  const oldSelection = effectiveControlPlaneFixture({ target });
  const oldManifest = controlPlaneMaterializationFixture({ target });
  publishControlPlaneMaterializationV2(stateDir, oldManifest);
  selectEffectiveControlPlaneV2(stateDir, oldSelection);
  const attached = transitionProvisioningRunningSessionContainerToAttachedV2(
    transitionBoundAllocatedSessionContainerToProvisioningRunningV2(
      sessionContainerRecordFixture({ target, containerId: "3".repeat(64) }),
      LEASE,
    ),
  );
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached);
  const candidateGeneration = createControlPlaneGenerationV2({
    ...SESSION_TEST_PROJECT,
    proxyImageInputDigest: sha256Digest("candidate-proxy-image-input"),
    controlPlaneTopologyDigest: target.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: target.controlPlane.admissionContractEpoch,
  });
  const candidateManifest = createControlPlaneMaterializationManifestV2({
    ...SESSION_TEST_PROJECT,
    generation: candidateGeneration,
    proxyImageRef: "runfree/proxy:candidate",
    proxyImageId: sha256Digest("candidate-proxy-image-id"),
    renderedControlPlaneSha256: candidateGeneration.controlPlaneTopologyDigest,
  
    sessionAdmissionSource: "files",
  });
  publishControlPlaneMaterializationV2(stateDir, candidateManifest);
  const candidate = candidateSelection(oldSelection, candidateManifest);
  return { target, oldSelection, oldManifest, candidateManifest, candidate, attached };
}

function performCompatibleRebind(value: ReturnType<typeof fixture>): SessionContainerRecordV2 {
  selectEffectiveControlPlaneV2(stateDir, value.candidate);
  const rebound = createReboundSessionContainerRecordV2({
    current: value.attached,
    candidateControlPlane: value.candidate,
  });
  replaceExactSessionContainerRecordForControlPlaneRebindV2(
    stateDir,
    SESSION_TEST_PROJECT,
    value.attached,
    rebound,
  );
  return rebound;
}

function adoptionInput(value: ReturnType<typeof fixture>) {
  return {
    stateDir,
    lifecycleLock: lifecycleLock(),
    expectedProject: SESSION_TEST_PROJECT,
    boundControlPlane: value.oldSelection,
    launchControlPlaneGeneration: value.target.controlPlane,
    attachedRecord: value.attached,
  };
}

describe("adoptCompatibleSessionControlPlaneRebind", () => {
  test("returns undefined while the durable selection is the held one", () => {
    const value = fixture();
    expect(adoptCompatibleSessionControlPlaneRebind(adoptionInput(value))).toBeUndefined();
  });

  test("adopts one exact completed compatible rebind of this session", () => {
    const value = fixture();
    const rebound = performCompatibleRebind(value);
    const adoption = adoptCompatibleSessionControlPlaneRebind(adoptionInput(value));
    expect(adoption).toBeDefined();
    expect(adoption?.effectiveControlPlane).toEqual(value.candidate);
    expect(adoption?.candidateMaterialization.controlPlaneMaterializationDigest)
      .toBe(value.candidateManifest.controlPlaneMaterializationDigest);
    expect(adoption?.record).toEqual(rebound);
  });

  test("adopts a proxy replacement under an unchanged control generation", () => {
    const value = fixture();
    // Same generation and materialization; only the proxy container moved, so
    // the record has nothing to advance at all.
    const candidate = candidateSelection(value.oldSelection, value.oldManifest);
    selectEffectiveControlPlaneV2(stateDir, candidate);

    const adoption = adoptCompatibleSessionControlPlaneRebind({
      ...adoptionInput(value),
      boundControlPlane: value.oldSelection,
    });

    expect(adoption?.effectiveControlPlane).toEqual(candidate);
    expect(adoption?.record).toEqual(value.attached);
  });

  test("refuses a rebind that also minted a fresh lease", () => {
    const value = fixture();
    selectEffectiveControlPlaneV2(stateDir, value.candidate);
    // The retired transaction protocol's batch shape: digest plus an advanced
    // lease. Nothing renews that lease now, so a rebind that mints one is
    // granting liveness no heartbeat will ever prove.
    const advanced = parseSessionContainerRecordV2({
      ...value.attached,
      controlPlaneGenerationDigest: value.candidate.controlPlaneGenerationDigest,
      leaseGeneration: "f".repeat(32),
      leaseExpiresAt: "2026-08-27T00:30:00.000Z",
    });
    if (!advanced) throw new Error("fixture requires a valid advanced record");
    // The rebind writer refuses it outright...
    expect(() => replaceExactSessionContainerRecordForControlPlaneRebindV2(
      stateDir,
      SESSION_TEST_PROJECT,
      value.attached,
      advanced,
    )).toThrow("did not advance exact compatible authority");
    // ...and a surviving client refuses to adopt one that reached the registry
    // some other way.
    fs.writeFileSync(
      sessionContainerRecordPath(stateDir, value.attached.sessionId),
      serializeSessionContainerRecordV2(advanced),
    );
    expect(() => adoptCompatibleSessionControlPlaneRebind(adoptionInput(value)))
      .toThrow("not an exact rebind of the held lifecycle authority");
  });

  test("refuses while a rebind transaction is pending", () => {
    const value = fixture();
    performCompatibleRebind(value);
    prepareControlPlaneRebindTransaction(stateDir, createControlPlaneRebindTransaction({
      expectedProject: SESSION_TEST_PROJECT,
      lockOwnerToken: "a".repeat(64),
      oldControlPlane: value.oldSelection,
      oldMaterialization: value.oldManifest,
      candidateMaterialization: value.candidateManifest,
      oldRecords: [value.attached],
      now: () => REBIND_NOW,
    }));
    expect(() => adoptCompatibleSessionControlPlaneRebind(adoptionInput(value)))
      .toThrow("a control-plane rebind is pending at prepared");
    // Both reclamations are named, from the remedy registry (output contract D4).
    expect(() => adoptCompatibleSessionControlPlaneRebind(adoptionInput(value)))
      .toThrow("run `runfree up` to resume it, or `runfree destroy --force` to clear a stuck one");
  });

  test("refuses a changed admission contract epoch before reading the record", () => {
    const value = fixture();
    const epochGeneration = createControlPlaneGenerationV2({
      ...SESSION_TEST_PROJECT,
      proxyImageInputDigest: sha256Digest("candidate-proxy-image-input"),
      controlPlaneTopologyDigest: value.target.controlPlane.controlPlaneTopologyDigest,
      admissionContractEpoch: value.target.controlPlane.admissionContractEpoch + 1,
    });
    const epochManifest = createControlPlaneMaterializationManifestV2({
      ...SESSION_TEST_PROJECT,
      generation: epochGeneration,
      proxyImageRef: "runfree/proxy:epoch",
      proxyImageId: sha256Digest("epoch-proxy-image-id"),
      renderedControlPlaneSha256: epochGeneration.controlPlaneTopologyDigest,
    
      sessionAdmissionSource: "files",
    });
    publishControlPlaneMaterializationV2(stateDir, epochManifest);
    selectEffectiveControlPlaneV2(stateDir, candidateSelection(value.oldSelection, epochManifest));
    expect(() => adoptCompatibleSessionControlPlaneRebind(adoptionInput(value)))
      .toThrow("not a compatible rebind");
  });

  test("refuses a changed control-plane topology", () => {
    const value = fixture();
    const topologyGeneration = createControlPlaneGenerationV2({
      ...SESSION_TEST_PROJECT,
      proxyImageInputDigest: sha256Digest("candidate-proxy-image-input"),
      controlPlaneTopologyDigest: sha256Digest("different-control-topology"),
      admissionContractEpoch: value.target.controlPlane.admissionContractEpoch,
    });
    const topologyManifest = createControlPlaneMaterializationManifestV2({
      ...SESSION_TEST_PROJECT,
      generation: topologyGeneration,
      proxyImageRef: "runfree/proxy:topology",
      proxyImageId: sha256Digest("topology-proxy-image-id"),
      renderedControlPlaneSha256: topologyGeneration.controlPlaneTopologyDigest,
    
      sessionAdmissionSource: "files",
    });
    publishControlPlaneMaterializationV2(stateDir, topologyManifest);
    selectEffectiveControlPlaneV2(stateDir, candidateSelection(value.oldSelection, topologyManifest));
    expect(() => adoptCompatibleSessionControlPlaneRebind(adoptionInput(value)))
      .toThrow("not a compatible rebind");
  });

  test("refuses a moved agent-internal network", () => {
    const value = fixture();
    selectEffectiveControlPlaneV2(stateDir, candidateSelection(value.oldSelection, value.candidateManifest, {
      networkIds: { agentInternal: "5".repeat(64), proxyEgress: value.oldSelection.networkIds.proxyEgress },
    }));
    expect(() => adoptCompatibleSessionControlPlaneRebind(adoptionInput(value)))
      .toThrow("not a compatible rebind");
  });

  test("refuses when the rebind did not retain an attached record for this session", () => {
    const value = fixture();
    const rebound = performCompatibleRebind(value);
    replaceExactSessionContainerRecordV2(
      stateDir,
      SESSION_TEST_PROJECT,
      rebound,
      transitionSessionContainerToRevokingV2(rebound),
    );
    expect(() => adoptCompatibleSessionControlPlaneRebind(adoptionInput(value)))
      .toThrow("retained no attached record");
  });

  test("refuses a registry record that is not an exact rebind of the held one", () => {
    const value = fixture();
    // The durable selection moved, but this session's record was never rebound
    // to the candidate control plane: the registry still holds the old record.
    selectEffectiveControlPlaneV2(stateDir, value.candidate);
    expect(() => adoptCompatibleSessionControlPlaneRebind(adoptionInput(value)))
      .toThrow("not an exact rebind of the held lifecycle authority");
  });

  test("refuses a held record outside the bound control plane", () => {
    const value = fixture();
    const rebound = performCompatibleRebind(value);
    expect(() => adoptCompatibleSessionControlPlaneRebind({
      ...adoptionInput(value),
      // The held record already names the candidate digest while the bound
      // selection is still the old one: incoherent driver state, not a rebind.
      attachedRecord: rebound,
    })).toThrow("outside its bound control plane");
  });
});
