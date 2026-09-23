import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, expect, test, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  events: [] as string[],
  desired: undefined as unknown,
  effective: undefined as unknown,
  invalidMaterializationSessionIds: new Set<string>(),
}));

vi.mock("./component-state-v2.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./component-state-v2.ts")>();
  return {
    ...actual,
    readDesiredSessionAgentV2: () => mocks.desired,
    readRetainedDesiredSessionAgentV2: () => mocks.desired,
    readEffectiveControlPlaneV2: () => mocks.effective,
    selectEffectiveControlPlaneV2: (_stateDir: string, selection: unknown) => {
      mocks.effective = { ...(mocks.effective as object), selection };
      mocks.events.push("control-selected");
    },
  };
});
// The eligibility publication itself is proved in
// `session-eligibility-publication`'s own tests. What this file must show is
// that the rebind reaches it, for the candidate proxy, before the effective
// selection flips to that candidate.
vi.mock("./session-eligibility-publication.ts", async (importOriginal) => ({
  ...await importOriginal<typeof import("./session-eligibility-publication.ts")>(),
  observeProxyStartedAt: (_io: unknown, proxyId: string) => {
    mocks.events.push(`proxy-start-observed:${proxyId}`);
    return "2026-08-27T00:00:00.000000000Z";
  },
  ensureSessionEligibilityPublished: (input: { proxyId: string; proxyStartedAt: string; records: readonly { sessionId: string }[] }) => {
    mocks.events.push(`eligibility-published:${input.proxyId}:${input.proxyStartedAt}:${input.records.length}`);
    return { published: true };
  },
}));
vi.mock("./session-materialization-eligibility.ts", () => ({
  compileAllowedSessionAgentMaterializationsV2: (input: { candidate: unknown }) => [input.candidate],
  classifySessionAgentMaterializationEligibilityV2: (input: {
    candidate: unknown;
    records: Array<{ sessionId: string }>;
  }) => ({
    allowed: [input.candidate],
    invalidRecords: input.records.filter((record) => mocks.invalidMaterializationSessionIds.has(record.sessionId)),
  }),
}));

import { sha256Digest } from "./component-state.ts";
import { createControlPlaneGenerationV2 } from "./component-state-v2.ts";
import {
  assertControlPlaneRebindReceiptForTokenSync,
  ControlPlaneRebindCandidateMismatchError,
  runCompatibleControlPlaneRebind,
} from "./control-plane-rebind-coordinator.ts";
import {
  CONTROL_PLANE_REBIND_PHASES,
  controlPlaneRebindTransactionPath,
  readControlPlaneRebindTransaction,
} from "./control-plane-rebind.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import {
  controlPlaneMaterializationFixture,
  effectiveControlPlaneFixture,
  sessionAgentMaterializationFixture,
  sessionContainerCreatePlanFixture,
  sessionContainerInspectJsonFixture,
  sessionContainerRecordFixture,
  sessionGenerationFixture,
  SESSION_TEST_PROJECT,
} from "./session-container.test-harness.ts";
import { validateSessionContainerInspect } from "./session-container-proof.ts";
import {
  readSessionContainerRecordV2,
  removeExactSessionContainerRecordV2,
  sessionContainerName,
  sessionContainerRecordPath,
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2,
  transitionProvisioningRunningSessionContainerToAttachedV2,
  writeSessionContainerRecordV2,
} from "./session-containers.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import { RuntimeObservationError } from "./observation-failure.ts";

let stateDir: string;

beforeEach(() => {
  mocks.events.length = 0;
  mocks.invalidMaterializationSessionIds.clear();
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-rebind-coordinator-"));
  const desiredManifest = sessionAgentMaterializationFixture();
  mocks.desired = {
    selection: {
      schemaVersion: 2,
      ...SESSION_TEST_PROJECT,
      sessionAgentGenerationDigest: desiredManifest.generation.sessionAgentGenerationDigest,
      sessionAgentMaterializationDigest: desiredManifest.sessionAgentMaterializationDigest,
      selectedAgentImageId: desiredManifest.selectedAgentImageId,
    },
    manifest: desiredManifest,
    selectable: true,
  };
});

afterEach(() => fs.rmSync(stateDir, { recursive: true, force: true }));

test("zero-session rebind publishes eligibility to the candidate and admits nothing", async () => {
  const oldTarget = sessionGenerationFixture().target;
  const candidateControl = createControlPlaneGenerationV2({
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProject: SESSION_TEST_PROJECT.composeProject,
    proxyImageInputDigest: sha256Digest("candidate-proxy"),
    controlPlaneTopologyDigest: oldTarget.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: oldTarget.controlPlane.admissionContractEpoch,
  });
  const candidateTarget = { ...oldTarget, controlPlane: candidateControl };
  const candidateSelection = effectiveControlPlaneFixture({ target: candidateTarget });
  const oldSelection = effectiveControlPlaneFixture({ target: oldTarget });
  mocks.effective = {
    selection: oldSelection,
    manifest: controlPlaneMaterializationFixture({ target: oldTarget }),
  };
  const lock: ProjectLifecycleLock = {
    ownerToken: "a".repeat(64),
    assertHeld: () => undefined,
    release: () => undefined,
  };
  const plan = {
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProjectName: SESSION_TEST_PROJECT.composeProject,
    paths: { stateDir },
    execution: { dockerClientEnv: {} },
  } as ActiveRuntimePlan;

  const result = await runCompatibleControlPlaneRebind({
    plan,
    lifecycleLock: lock,
    io: {} as never,
    oldControlPlane: {
      selection: oldSelection,
      manifest: controlPlaneMaterializationFixture({ target: oldTarget }),
    },
    candidateMaterialization: controlPlaneMaterializationFixture({ target: candidateTarget }),
    now: (() => {
      let milliseconds = Date.parse("2026-08-27T00:00:00.000Z");
      return () => {
        milliseconds += 1_000;
        return new Date(milliseconds);
      };
    })(),
    randomBytes: () => new Uint8Array(32).fill(0xab),
    services: {
      startAndProveCandidate: async () => {
        mocks.events.push("candidate-proved-deny-all");
        return candidateSelection;
      },
      proveCandidate: async () => candidateSelection,
      reproveCandidate: async (recorded) => {
        expect(recorded).toEqual(candidateSelection);
        mocks.events.push("candidate-reproved-identity");
      },
      proveSession: () => {
        throw new Error("no retained session exists in this fixture");
      },
      finalize: async () => {
        mocks.events.push("tokens-finalized");
        return { preparedRuntime: Object.freeze({ version: 1 }) as never, tokenResolutionReceipts: [] };
      },
    },
  });

  expect(result.selection).toEqual(candidateSelection);
  expect(mocks.events).toEqual([
    "candidate-proved-deny-all",
    "candidate-reproved-identity",
    "candidate-reproved-identity",
    "proxy-start-observed:7777777777777777777777777777777777777777777777777777777777777777",
    "eligibility-published:7777777777777777777777777777777777777777777777777777777777777777:2026-08-27T00:00:00.000000000Z:0",
    "control-selected",
    "candidate-reproved-identity",
    "tokens-finalized",
    "candidate-reproved-identity",
  ]);
  expect(fs.existsSync(controlPlaneRebindTransactionPath(stateDir))).toBe(false);
});

test("replaces a missing proxy with a new container identity in the same control generation", async () => {
  const target = sessionGenerationFixture().target;
  const manifest = controlPlaneMaterializationFixture({ target });
  const oldSelection = {
    ...effectiveControlPlaneFixture({ target }),
    proxyContainerId: "6".repeat(64),
  };
  const candidateSelection = effectiveControlPlaneFixture({ target });
  mocks.effective = { selection: oldSelection, manifest };
  const plan = {
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProjectName: SESSION_TEST_PROJECT.composeProject,
    paths: { stateDir },
    execution: { dockerClientEnv: {} },
  } as ActiveRuntimePlan;

  const result = await runCompatibleControlPlaneRebind({
    plan,
    lifecycleLock: {
      ownerToken: "a".repeat(64),
      assertHeld: () => undefined,
      release: () => undefined,
    },
    io: {} as never,
    oldControlPlane: { selection: oldSelection, manifest },
    candidateMaterialization: manifest,
    services: {
      startAndProveCandidate: async () => candidateSelection,
      proveCandidate: async () => candidateSelection,
      reproveCandidate: async () => undefined,
      proveSession: () => { throw new Error("zero-session replacement must not prove a session"); },
      finalize: async () => ({
        preparedRuntime: Object.freeze({ version: 1 }) as never,
        tokenResolutionReceipts: [],
      }),
    },
  });

  expect(result.selection).toEqual(candidateSelection);
  expect(mocks.effective).toMatchObject({ selection: candidateSelection });
  expect(fs.existsSync(controlPlaneRebindTransactionPath(stateDir))).toBe(false);
});

test("recovery refuses a recreated proxy that differs from the journaled candidate authority", async () => {
  const oldTarget = sessionGenerationFixture().target;
  const candidateControl = createControlPlaneGenerationV2({
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProject: SESSION_TEST_PROJECT.composeProject,
    proxyImageInputDigest: sha256Digest("candidate-proxy-journal-binding"),
    controlPlaneTopologyDigest: oldTarget.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: oldTarget.controlPlane.admissionContractEpoch,
  });
  const candidateTarget = { ...oldTarget, controlPlane: candidateControl };
  const oldSelection = effectiveControlPlaneFixture({ target: oldTarget });
  const candidateSelection = effectiveControlPlaneFixture({ target: candidateTarget });
  const oldManifest = controlPlaneMaterializationFixture({ target: oldTarget });
  const candidateManifest = controlPlaneMaterializationFixture({ target: candidateTarget });
  mocks.effective = { selection: oldSelection, manifest: oldManifest };
  const plan = {
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProjectName: SESSION_TEST_PROJECT.composeProject,
    paths: { stateDir },
    execution: { dockerClientEnv: {} },
  } as ActiveRuntimePlan;
  let crashed = false;
  const finalize = vi.fn(async () => ({
    preparedRuntime: Object.freeze({ version: 1 }) as never,
    tokenResolutionReceipts: [],
  }));
  const services = {
    startAndProveCandidate: async () => candidateSelection,
    proveCandidate: async () => {
      if (!crashed) {
        crashed = true;
        throw new Error("simulated crash after candidate journal");
      }
      return candidateSelection;
    },
    reproveCandidate: async () => undefined,
    proveSession: () => { throw new Error("zero-session recovery must not prove a session"); },
    finalize,
  };
  await expect(runCompatibleControlPlaneRebind({
    plan,
    lifecycleLock: {
      ownerToken: "a".repeat(64),
      assertHeld: () => undefined,
      release: () => undefined,
    },
    io: {} as never,
    oldControlPlane: { selection: oldSelection, manifest: oldManifest },
    candidateMaterialization: candidateManifest,
    services,
  })).rejects.toThrow("simulated crash after candidate journal");
  expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase).toBe("proxy-started-deny-all");

  const journalPath = controlPlaneRebindTransactionPath(stateDir);
  const journalBeforeRefusal = fs.readFileSync(journalPath, "utf8");
  const refusal = await runCompatibleControlPlaneRebind({
    plan,
    lifecycleLock: {
      ownerToken: "b".repeat(64),
      assertHeld: () => undefined,
      release: () => undefined,
    },
    io: {} as never,
    oldControlPlane: { selection: oldSelection, manifest: oldManifest },
    candidateMaterialization: candidateManifest,
    services: {
      ...services,
      proveCandidate: async () => ({ ...candidateSelection, proxyContainerId: "5".repeat(64) }),
    },
  }).then(
    () => undefined,
    (error: unknown) => error,
  );

  expect(refusal).toBeInstanceOf(ControlPlaneRebindCandidateMismatchError);
  expect(refusal).toMatchObject({
    message: "proved candidate control-plane authority contradicts the rebind journal: proxyContainerId",
  });
  expect(fs.readFileSync(journalPath, "utf8")).toBe(journalBeforeRefusal);
  expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)).toMatchObject({
    lockOwnerToken: "a".repeat(64),
    phase: "proxy-started-deny-all",
  });
  expect(finalize).not.toHaveBeenCalled();
  expect(mocks.events).not.toContain("control-selected");
  expect((mocks.effective as { selection: unknown }).selection).toEqual(oldSelection);

  const proofCheckpoints: Array<{ phase: string; lockOwnerToken: string }> = [];
  await expect(runCompatibleControlPlaneRebind({
    plan,
    lifecycleLock: {
      ownerToken: "b".repeat(64),
      assertHeld: () => undefined,
      release: () => undefined,
    },
    io: {} as never,
    oldControlPlane: { selection: oldSelection, manifest: oldManifest },
    candidateMaterialization: candidateManifest,
    services: {
      ...services,
      proveCandidate: async () => {
        const journal = readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT);
        if (!journal) throw new Error("expected recovery journal");
        proofCheckpoints.push({ phase: journal.phase, lockOwnerToken: journal.lockOwnerToken });
        if (proofCheckpoints.length === 1) return candidateSelection;
        throw new Error("stop after the recovery phase boundary");
      },
    },
  })).rejects.toThrow("stop after the recovery phase boundary");
  expect(proofCheckpoints).toEqual([
    { phase: "proxy-started-deny-all", lockOwnerToken: "a".repeat(64) },
    { phase: "sessions-revalidated", lockOwnerToken: "b".repeat(64) },
  ]);

  // The journal is still parked, so the drifts below buy their refusals without
  // paying for another crash. The refusal above already proved once that a
  // mismatch leaves the journal bytes, the durable selection, and finalization
  // untouched; what is left to prove is which fields bind the identity.
  const refuseDrift = async (proved: typeof candidateSelection): Promise<unknown> =>
    runCompatibleControlPlaneRebind({
      plan,
      lifecycleLock: {
        ownerToken: "c".repeat(64),
        assertHeld: () => undefined,
        release: () => undefined,
      },
      io: {} as never,
      oldControlPlane: { selection: oldSelection, manifest: oldManifest },
      candidateMaterialization: candidateManifest,
      services: { ...services, proveCandidate: async () => proved },
    }).then(
      () => undefined,
      (error: unknown) => error,
    );

  const networkDrift = await refuseDrift({
    ...candidateSelection,
    networkIds: { ...candidateSelection.networkIds, agentInternal: "e".repeat(64) },
  });
  expect(networkDrift).toBeInstanceOf(ControlPlaneRebindCandidateMismatchError);
  expect((networkDrift as Error).message).toContain("networkIds");

  const contractDrift = await refuseDrift({
    ...candidateSelection,
    securityContractHash: sha256Digest("drifted-contract"),
  });
  expect(contractDrift).toBeInstanceOf(ControlPlaneRebindCandidateMismatchError);
  expect((contractDrift as Error).message).toContain("securityContractHash");

  // A field this CLI has no name for binds identity too: the comparison is
  // total, so an authority field a future writer adds cannot drift past it
  // merely by being unknown here. The field list is diagnostic, not contract,
  // so only its mention of the drifted field is asserted.
  const futureDrift = await refuseDrift(
    Object.assign({ ...candidateSelection }, { futureAuthorityField: "x" }),
  );
  expect(futureDrift).toBeInstanceOf(ControlPlaneRebindCandidateMismatchError);
  expect((futureDrift as Error).message).toContain("futureAuthorityField");
});

test("compatible rebind preserves exact live session identity and re-proves it before the selection flips", async () => {
  const oldTarget = sessionGenerationFixture().target;
  const candidateControl = createControlPlaneGenerationV2({
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProject: SESSION_TEST_PROJECT.composeProject,
    proxyImageInputDigest: sha256Digest("candidate-proxy-with-session"),
    controlPlaneTopologyDigest: oldTarget.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: oldTarget.controlPlane.admissionContractEpoch,
  });
  const candidateTarget = { ...oldTarget, controlPlane: candidateControl };
  const candidateSelection = effectiveControlPlaneFixture({ target: candidateTarget });
  const oldSelection = effectiveControlPlaneFixture({ target: oldTarget });
  mocks.effective = {
    selection: oldSelection,
    manifest: controlPlaneMaterializationFixture({ target: oldTarget }),
  };
  const allocated = sessionContainerRecordFixture({
    target: oldTarget,
    containerId: "c".repeat(64),
  });
  const attached = transitionProvisioningRunningSessionContainerToAttachedV2(
    transitionBoundAllocatedSessionContainerToProvisioningRunningV2(allocated, {
      admittedAt: "2026-08-27T00:00:00.000Z",
      leaseGeneration: "d".repeat(64),
      leaseExpiresAt: "2026-08-27T00:05:00.000Z",
    }),
  );
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached);
  const lock: ProjectLifecycleLock = {
    ownerToken: "a".repeat(64),
    assertHeld: () => undefined,
    release: () => undefined,
  };
  const plan = {
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProjectName: SESSION_TEST_PROJECT.composeProject,
    paths: { stateDir },
    execution: { dockerClientEnv: {} },
  } as ActiveRuntimePlan;
  let proofCount = 0;

  await runCompatibleControlPlaneRebind({
    plan,
    lifecycleLock: lock,
    io: {} as never,
    oldControlPlane: {
      selection: oldSelection,
      manifest: controlPlaneMaterializationFixture({ target: oldTarget }),
    },
    candidateMaterialization: controlPlaneMaterializationFixture({ target: candidateTarget }),
    now: (() => {
      let milliseconds = Date.parse("2026-08-27T00:00:00.000Z");
      return () => {
        milliseconds += 1_000;
        return new Date(milliseconds);
      };
    })(),
    randomBytes: () => new Uint8Array(32).fill(0xab),
    services: {
      startAndProveCandidate: async () => candidateSelection,
      proveCandidate: async () => candidateSelection,
      reproveCandidate: async (recorded) => {
        expect(recorded).toEqual(candidateSelection);
      },
      proveSession: (replacement) => {
        proofCount += 1;
        const createPlan = sessionContainerCreatePlanFixture({
          target: candidateTarget,
          generation: sessionGenerationFixture().generation,
          record: replacement,
        });
        return validateSessionContainerInspect(
          sessionContainerInspectJsonFixture(createPlan, { running: true }),
          createPlan,
          { kind: "active-running" },
        );
      },
      finalize: async () => ({
        preparedRuntime: Object.freeze({ version: 1 }) as never,
        tokenResolutionReceipts: [],
      }),
    },
  });

  expect(mocks.events).toEqual([
    "proxy-start-observed:7777777777777777777777777777777777777777777777777777777777777777",
    "eligibility-published:7777777777777777777777777777777777777777777777777777777777777777:2026-08-27T00:00:00.000000000Z:1",
    "control-selected",
  ]);
  const rebound = readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached.sessionId);
  expect(rebound).toMatchObject({
    sessionId: attached.sessionId,
    sessionIncarnation: attached.sessionIncarnation,
    sessionPrincipal: attached.sessionPrincipal,
    containerId: attached.containerId,
    selectedAgentImageId: attached.selectedAgentImageId,
    sessionAgentMaterializationDigest: attached.sessionAgentMaterializationDigest,
    controlPlaneGenerationDigest: candidateControl.controlPlaneGenerationDigest,
  });
  // The digest moves and nothing else: the record's lease is not this
  // session's authority and no heartbeat renews it.
  expect(rebound?.leaseGeneration).toBe(attached.leaseGeneration);
  expect(rebound?.leaseExpiresAt).toBe(attached.leaseExpiresAt);
  expect(proofCount).toBe(2);
});

test("isolates a missing materialization when concurrent teardown already removed its record", async () => {
  const oldTarget = sessionGenerationFixture().target;
  const candidateControl = createControlPlaneGenerationV2({
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProject: SESSION_TEST_PROJECT.composeProject,
    proxyImageInputDigest: sha256Digest("candidate-proxy-missing-materialization"),
    controlPlaneTopologyDigest: oldTarget.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: oldTarget.controlPlane.admissionContractEpoch,
  });
  const candidateTarget = { ...oldTarget, controlPlane: candidateControl };
  const oldSelection = effectiveControlPlaneFixture({ target: oldTarget });
  const candidateSelection = effectiveControlPlaneFixture({ target: candidateTarget });
  mocks.effective = {
    selection: oldSelection,
    manifest: controlPlaneMaterializationFixture({ target: oldTarget }),
  };
  const allocated = sessionContainerRecordFixture({ target: oldTarget, containerId: "c".repeat(64) });
  const attached = transitionProvisioningRunningSessionContainerToAttachedV2(
    transitionBoundAllocatedSessionContainerToProvisioningRunningV2(allocated, {
      admittedAt: "2026-08-27T00:00:00.000Z",
      leaseGeneration: "d".repeat(64),
      leaseExpiresAt: "2026-08-27T00:05:00.000Z",
    }),
  );
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached);
  mocks.invalidMaterializationSessionIds.add(attached.sessionId);
  const plan = {
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProjectName: SESSION_TEST_PROJECT.composeProject,
    paths: { stateDir },
    execution: { dockerClientEnv: {} },
  } as ActiveRuntimePlan;
  let proofCount = 0;
  let recordRemoved = false;

  await runCompatibleControlPlaneRebind({
    plan,
    lifecycleLock: {
      ownerToken: "a".repeat(64),
      assertHeld: () => undefined,
      release: () => undefined,
    },
    io: {} as never,
    oldControlPlane: {
      selection: oldSelection,
      manifest: controlPlaneMaterializationFixture({ target: oldTarget }),
    },
    candidateMaterialization: controlPlaneMaterializationFixture({ target: candidateTarget }),
    services: {
      startAndProveCandidate: async () => candidateSelection,
      proveCandidate: async () => {
        if (!recordRemoved
          && readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase === "sessions-revalidated") {
          recordRemoved = true;
          removeExactSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached);
        }
        return candidateSelection;
      },
      reproveCandidate: async () => undefined,
      proveSession: (replacement) => {
        proofCount += 1;
        const createPlan = sessionContainerCreatePlanFixture({
          target: candidateTarget,
          generation: sessionGenerationFixture().generation,
          record: replacement,
        });
        return validateSessionContainerInspect(
          sessionContainerInspectJsonFixture(createPlan, { running: true }),
          createPlan,
          { kind: "active-running" },
        );
      },
      finalize: async () => ({
        preparedRuntime: Object.freeze({ version: 1 }) as never,
        tokenResolutionReceipts: [],
      }),
    },
  });

  expect(readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached.sessionId)).toBeUndefined();
  expect(recordRemoved).toBe(true);
  expect(proofCount).toBe(1);
});

test("recovery re-proves sessions and durably re-runs the record batch before publication", async () => {
  const oldTarget = sessionGenerationFixture().target;
  const candidateControl = createControlPlaneGenerationV2({
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProject: SESSION_TEST_PROJECT.composeProject,
    proxyImageInputDigest: sha256Digest("candidate-proxy-expired-recovery"),
    controlPlaneTopologyDigest: oldTarget.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: oldTarget.controlPlane.admissionContractEpoch,
  });
  const candidateTarget = { ...oldTarget, controlPlane: candidateControl };
  const oldSelection = effectiveControlPlaneFixture({ target: oldTarget });
  const candidateSelection = effectiveControlPlaneFixture({ target: candidateTarget });
  const oldManifest = controlPlaneMaterializationFixture({ target: oldTarget });
  const candidateManifest = controlPlaneMaterializationFixture({ target: candidateTarget });
  mocks.effective = { selection: oldSelection, manifest: oldManifest };
  const allocated = sessionContainerRecordFixture({ target: oldTarget, containerId: "c".repeat(64) });
  const attached = transitionProvisioningRunningSessionContainerToAttachedV2(
    transitionBoundAllocatedSessionContainerToProvisioningRunningV2(allocated, {
      admittedAt: "2026-08-27T00:00:00.000Z",
      leaseGeneration: "d".repeat(64),
      leaseExpiresAt: "2026-08-27T00:05:00.000Z",
    }),
  );
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached);
  const plan = {
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProjectName: SESSION_TEST_PROJECT.composeProject,
    paths: { stateDir },
    execution: { dockerClientEnv: {} },
  } as ActiveRuntimePlan;
  const proof = (replacement: typeof attached) => {
    const createPlan = sessionContainerCreatePlanFixture({
      target: candidateTarget,
      generation: sessionGenerationFixture().generation,
      record: replacement,
    });
    return validateSessionContainerInspect(
      sessionContainerInspectJsonFixture(createPlan, { running: true }),
      createPlan,
      { kind: "active-running" },
    );
  };
  let crashed = false;
  let firstNow = Date.parse("2026-08-27T00:00:00.000Z");
  const firstServices = {
    startAndProveCandidate: async () => candidateSelection,
    proveCandidate: async () => candidateSelection,
    reproveCandidate: async () => {
      if (!crashed && readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase === "records-rebound") {
        crashed = true;
        throw new Error("simulated long rebind outage");
      }
    },
    proveSession: proof,
    finalize: async () => ({
      preparedRuntime: Object.freeze({ version: 1 }) as never,
      tokenResolutionReceipts: [],
    }),
  };
  await expect(runCompatibleControlPlaneRebind({
    plan,
    lifecycleLock: {
      ownerToken: "a".repeat(64),
      assertHeld: () => undefined,
      release: () => undefined,
    },
    io: {} as never,
    oldControlPlane: { selection: oldSelection, manifest: oldManifest },
    candidateMaterialization: candidateManifest,
    now: () => {
      firstNow += 1_000;
      return new Date(firstNow);
    },
    randomBytes: () => new Uint8Array(32).fill(0xab),
    services: firstServices,
  })).rejects.toThrow("simulated long rebind outage");
  const staleRebound = readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached.sessionId);
  // The rebind moves the control digest and nothing else: the record's lease
  // is not this session's authority and no heartbeat renews it.
  expect(staleRebound?.leaseGeneration).toBe(attached.leaseGeneration);
  expect(staleRebound?.leaseExpiresAt).toBe(attached.leaseExpiresAt);

  let recoveryNow = Date.parse("2026-08-27T02:00:00.000Z");
  await runCompatibleControlPlaneRebind({
    explicitRetry: true,
    plan,
    lifecycleLock: {
      ownerToken: "b".repeat(64),
      assertHeld: () => undefined,
      release: () => undefined,
    },
    io: {} as never,
    oldControlPlane: { selection: oldSelection, manifest: oldManifest },
    candidateMaterialization: candidateManifest,
    now: () => {
      recoveryNow += 1_000;
      return new Date(recoveryNow);
    },
    randomBytes: () => new Uint8Array(32).fill(0xcd),
    services: { ...firstServices, proveCandidate: async () => candidateSelection },
  });

  const refreshed = readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached.sessionId);
  expect(refreshed?.leaseGeneration).toBe(attached.leaseGeneration);
  expect(refreshed?.controlPlaneGenerationDigest).toBe(candidateSelection.controlPlaneGenerationDigest);
  // The recovered run republishes eligibility into the candidate before it
  // re-selects: a proxy holding none serves nothing.
  expect(mocks.events.filter((event) => event.startsWith("eligibility-published:")).length)
    .toBeGreaterThanOrEqual(1);
});

test("recovers each durable pre-completion phase under a new lifecycle lock fence", async () => {
  const oldTarget = sessionGenerationFixture().target;
  const candidateControl = createControlPlaneGenerationV2({
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProject: SESSION_TEST_PROJECT.composeProject,
    proxyImageInputDigest: sha256Digest("candidate-proxy-crash-recovery"),
    controlPlaneTopologyDigest: oldTarget.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: oldTarget.controlPlane.admissionContractEpoch,
  });
  const candidateTarget = { ...oldTarget, controlPlane: candidateControl };
  const oldSelection = effectiveControlPlaneFixture({ target: oldTarget });
  const candidateSelection = effectiveControlPlaneFixture({ target: candidateTarget });
  const oldManifest = controlPlaneMaterializationFixture({ target: oldTarget });
  const candidateManifest = controlPlaneMaterializationFixture({ target: candidateTarget });

  for (const crashPhase of CONTROL_PLANE_REBIND_PHASES.filter((phase) => phase !== "complete")) {
    fs.rmSync(stateDir, { recursive: true, force: true });
    stateDir = fs.mkdtempSync(path.join(os.tmpdir(), `runfree-rebind-${crashPhase}-`));
    mocks.effective = { selection: oldSelection, manifest: oldManifest };
    mocks.events.length = 0;
    const plan = {
      projectId: SESSION_TEST_PROJECT.projectId,
      composeProjectName: SESSION_TEST_PROJECT.composeProject,
      paths: { stateDir },
      execution: { dockerClientEnv: {} },
    } as ActiveRuntimePlan;
    const firstLock: ProjectLifecycleLock = {
      ownerToken: "a".repeat(64),
      assertHeld: () => undefined,
      release: () => undefined,
    };
    let crashed = false;
    const crashAtPhase = () => {
      const phase = readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase;
      if (!crashed && phase === crashPhase) {
        crashed = true;
        throw new Error(`simulated crash at ${crashPhase}`);
      }
    };
    const services = {
      startAndProveCandidate: async () => {
        if (!crashed && crashPhase === "prepared") {
          crashed = true;
          throw new Error(`simulated crash at ${crashPhase}`);
        }
        return candidateSelection;
      },
      proveCandidate: async () => {
        crashAtPhase();
        return candidateSelection;
      },
      reproveCandidate: async () => crashAtPhase(),
      proveSession: () => { throw new Error("zero-session recovery fixture must not prove a session"); },
      finalize: async () => ({
        preparedRuntime: Object.freeze({ version: 1 }) as never,
        tokenResolutionReceipts: [],
      }),
    };
    await expect(runCompatibleControlPlaneRebind({
      plan,
      lifecycleLock: firstLock,
      io: {} as never,
      oldControlPlane: { selection: oldSelection, manifest: oldManifest },
      candidateMaterialization: candidateManifest,
      services,
    })).rejects.toThrow(`simulated crash at ${crashPhase}`);
    expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase).toBe(crashPhase);

    const recoveryLock: ProjectLifecycleLock = {
      ownerToken: "b".repeat(64),
      assertHeld: () => undefined,
      release: () => undefined,
    };
    const recovered = await runCompatibleControlPlaneRebind({
      plan,
      lifecycleLock: recoveryLock,
      io: {} as never,
      oldControlPlane: { selection: oldSelection, manifest: oldManifest },
      candidateMaterialization: candidateManifest,
      services,
    });
    expect(recovered.selection).toEqual(candidateSelection);
    expect(fs.existsSync(controlPlaneRebindTransactionPath(stateDir))).toBe(false);
  }
});

test("recovers a complete journal when cleanup crashes", async () => {
  const oldTarget = sessionGenerationFixture().target;
  const candidateControl = createControlPlaneGenerationV2({
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProject: SESSION_TEST_PROJECT.composeProject,
    proxyImageInputDigest: sha256Digest("candidate-proxy-complete-crash"),
    controlPlaneTopologyDigest: oldTarget.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: oldTarget.controlPlane.admissionContractEpoch,
  });
  const candidateTarget = { ...oldTarget, controlPlane: candidateControl };
  const oldSelection = effectiveControlPlaneFixture({ target: oldTarget });
  const candidateSelection = effectiveControlPlaneFixture({ target: candidateTarget });
  const oldManifest = controlPlaneMaterializationFixture({ target: oldTarget });
  const candidateManifest = controlPlaneMaterializationFixture({ target: candidateTarget });
  mocks.effective = { selection: oldSelection, manifest: oldManifest };
  const lock = (ownerToken: string): ProjectLifecycleLock => ({
    ownerToken,
    assertHeld: () => undefined,
    release: () => undefined,
  });
  const plan = {
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProjectName: SESSION_TEST_PROJECT.composeProject,
    paths: { stateDir },
    execution: { dockerClientEnv: {} },
  } as ActiveRuntimePlan;
  const services = {
    startAndProveCandidate: async () => candidateSelection,
    proveCandidate: async () => candidateSelection,
    reproveCandidate: async () => undefined,
    proveSession: () => { throw new Error("zero-session recovery fixture must not prove a session"); },
    finalize: async () => ({
      preparedRuntime: Object.freeze({ version: 1 }) as never,
      tokenResolutionReceipts: [],
    }),
  };
  const journalPath = controlPlaneRebindTransactionPath(stateDir);
  const unlink = fs.unlinkSync.bind(fs);
  let interrupted = false;
  const unlinkSpy = vi.spyOn(fs, "unlinkSync").mockImplementation((filePath) => {
    if (!interrupted && filePath === journalPath) {
      interrupted = true;
      throw new Error("simulated complete cleanup crash");
    }
    return unlink(filePath);
  });
  await expect(runCompatibleControlPlaneRebind({
    plan,
    lifecycleLock: lock("a".repeat(64)),
    io: {} as never,
    oldControlPlane: { selection: oldSelection, manifest: oldManifest },
    candidateMaterialization: candidateManifest,
    services,
  })).rejects.toThrow("simulated complete cleanup crash");
  unlinkSpy.mockRestore();
  expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase).toBe("complete");

  await runCompatibleControlPlaneRebind({
    plan,
    lifecycleLock: lock("b".repeat(64)),
    io: {} as never,
    oldControlPlane: { selection: oldSelection, manifest: oldManifest },
    candidateMaterialization: candidateManifest,
    services,
  });
  expect(fs.existsSync(journalPath)).toBe(false);
});

test("recovery of a published transaction never re-runs the deny-all base-state proof", async () => {
  const oldTarget = sessionGenerationFixture().target;
  const candidateControl = createControlPlaneGenerationV2({
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProject: SESSION_TEST_PROJECT.composeProject,
    proxyImageInputDigest: sha256Digest("candidate-proxy-published-recovery"),
    controlPlaneTopologyDigest: oldTarget.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: oldTarget.controlPlane.admissionContractEpoch,
  });
  const candidateTarget = { ...oldTarget, controlPlane: candidateControl };
  const oldSelection = effectiveControlPlaneFixture({ target: oldTarget });
  const candidateSelection = effectiveControlPlaneFixture({ target: candidateTarget });
  const oldManifest = controlPlaneMaterializationFixture({ target: oldTarget });
  const candidateManifest = controlPlaneMaterializationFixture({ target: candidateTarget });
  mocks.effective = { selection: oldSelection, manifest: oldManifest };
  const plan = {
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProjectName: SESSION_TEST_PROJECT.composeProject,
    paths: { stateDir },
    execution: { dockerClientEnv: {} },
  } as ActiveRuntimePlan;
  let crashed = false;
  await expect(runCompatibleControlPlaneRebind({
    plan,
    lifecycleLock: { ownerToken: "a".repeat(64), assertHeld: () => undefined, release: () => undefined },
    io: {} as never,
    oldControlPlane: { selection: oldSelection, manifest: oldManifest },
    candidateMaterialization: candidateManifest,
    services: {
      startAndProveCandidate: async () => candidateSelection,
      proveCandidate: async () => candidateSelection,
      reproveCandidate: async () => {
        if (!crashed
          && readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase === "eligibility-published") {
          crashed = true;
          throw new Error("simulated crash after request-proxy acknowledgement");
        }
      },
      proveSession: () => { throw new Error("zero-session fixture must not prove a session"); },
      finalize: async () => ({
        preparedRuntime: Object.freeze({ version: 1 }) as never,
        tokenResolutionReceipts: [],
      }),
    },
  })).rejects.toThrow("simulated crash after request-proxy acknowledgement");
  expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase).toBe("eligibility-published");

  // The published overlay legitimately exists now, so the deny-all base-state
  // proof would refuse; recovery must not consult it at any published phase.
  mocks.events.length = 0;
  const recovered = await runCompatibleControlPlaneRebind({
    plan,
    lifecycleLock: { ownerToken: "b".repeat(64), assertHeld: () => undefined, release: () => undefined },
    io: {} as never,
    oldControlPlane: { selection: oldSelection, manifest: oldManifest },
    candidateMaterialization: candidateManifest,
    services: {
      startAndProveCandidate: async () => {
        throw new Error("recovery must not restart the candidate proxy");
      },
      proveCandidate: async () => {
        throw new Error("session-admission base state is not deny-by-default");
      },
      reproveCandidate: async (recorded) => {
        expect(recorded).toEqual(candidateSelection);
      },
      proveSession: () => { throw new Error("zero-session fixture must not prove a session"); },
      finalize: async () => ({
        preparedRuntime: Object.freeze({ version: 1 }) as never,
        tokenResolutionReceipts: [],
      }),
    },
  });
  expect(recovered.selection).toEqual(candidateSelection);
  expect(mocks.events).toContain("control-selected");
  expect(mocks.events).not.toContain("candidate-proved-deny-all");
  expect(fs.existsSync(controlPlaneRebindTransactionPath(stateDir))).toBe(false);
});

test("recovery refuses a published candidate whose live identity no longer matches, before any consumer mutation", async () => {
  const oldTarget = sessionGenerationFixture().target;
  const candidateControl = createControlPlaneGenerationV2({
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProject: SESSION_TEST_PROJECT.composeProject,
    proxyImageInputDigest: sha256Digest("candidate-proxy-published-identity-drift"),
    controlPlaneTopologyDigest: oldTarget.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: oldTarget.controlPlane.admissionContractEpoch,
  });
  const candidateTarget = { ...oldTarget, controlPlane: candidateControl };
  const oldSelection = effectiveControlPlaneFixture({ target: oldTarget });
  const candidateSelection = effectiveControlPlaneFixture({ target: candidateTarget });
  const oldManifest = controlPlaneMaterializationFixture({ target: oldTarget });
  const candidateManifest = controlPlaneMaterializationFixture({ target: candidateTarget });
  mocks.effective = { selection: oldSelection, manifest: oldManifest };
  const plan = {
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProjectName: SESSION_TEST_PROJECT.composeProject,
    paths: { stateDir },
    execution: { dockerClientEnv: {} },
  } as ActiveRuntimePlan;
  let crashed = false;
  await expect(runCompatibleControlPlaneRebind({
    plan,
    lifecycleLock: { ownerToken: "a".repeat(64), assertHeld: () => undefined, release: () => undefined },
    io: {} as never,
    oldControlPlane: { selection: oldSelection, manifest: oldManifest },
    candidateMaterialization: candidateManifest,
    services: {
      startAndProveCandidate: async () => candidateSelection,
      proveCandidate: async () => candidateSelection,
      reproveCandidate: async () => {
        if (!crashed
          && readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase === "eligibility-published") {
          crashed = true;
          throw new Error("simulated crash after request-proxy acknowledgement");
        }
      },
      proveSession: () => { throw new Error("zero-session fixture must not prove a session"); },
      finalize: async () => ({
        preparedRuntime: Object.freeze({ version: 1 }) as never,
        tokenResolutionReceipts: [],
      }),
    },
  })).rejects.toThrow("simulated crash after request-proxy acknowledgement");

  mocks.events.length = 0;
  await expect(runCompatibleControlPlaneRebind({
    plan,
    lifecycleLock: { ownerToken: "b".repeat(64), assertHeld: () => undefined, release: () => undefined },
    io: {} as never,
    oldControlPlane: { selection: oldSelection, manifest: oldManifest },
    candidateMaterialization: candidateManifest,
    services: {
      startAndProveCandidate: async () => candidateSelection,
      proveCandidate: async () => candidateSelection,
      reproveCandidate: async () => {
        throw new Error("recorded rebind candidate contradicts live Docker identity");
      },
      proveSession: () => { throw new Error("zero-session fixture must not prove a session"); },
      finalize: async () => {
        throw new Error("refused recovery must not finalize tokens");
      },
    },
  })).rejects.toThrow("recorded rebind candidate contradicts live Docker identity");
  expect(mocks.events).toEqual([]);
  expect((mocks.effective as { selection: unknown }).selection).toEqual(oldSelection);
  expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase).toBe("eligibility-published");
});

test("token sync is impossible before the rebind receipt records candidate selection", async () => {
  const oldTarget = sessionGenerationFixture().target;
  const candidateControl = createControlPlaneGenerationV2({
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProject: SESSION_TEST_PROJECT.composeProject,
    proxyImageInputDigest: sha256Digest("candidate-proxy-receipt-gate"),
    controlPlaneTopologyDigest: oldTarget.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: oldTarget.controlPlane.admissionContractEpoch,
  });
  const candidateTarget = { ...oldTarget, controlPlane: candidateControl };
  const oldSelection = effectiveControlPlaneFixture({ target: oldTarget });
  const candidateSelection = effectiveControlPlaneFixture({ target: candidateTarget });
  const oldManifest = controlPlaneMaterializationFixture({ target: oldTarget });
  const candidateManifest = controlPlaneMaterializationFixture({ target: candidateTarget });
  mocks.effective = { selection: oldSelection, manifest: oldManifest };
  const plan = {
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProjectName: SESSION_TEST_PROJECT.composeProject,
    paths: { stateDir },
    execution: { dockerClientEnv: {} },
  } as ActiveRuntimePlan;

  // No journal at all: nothing may authorize credential resolution.
  expect(() => assertControlPlaneRebindReceiptForTokenSync(stateDir, SESSION_TEST_PROJECT))
    .toThrow("token sync is impossible before the rebind receipt records candidate selection");

  const crashAt = async (phase: string): Promise<void> => {
    let crashed = false;
    await expect(runCompatibleControlPlaneRebind({
      plan,
      lifecycleLock: { ownerToken: "a".repeat(64), assertHeld: () => undefined, release: () => undefined },
      io: {} as never,
      oldControlPlane: { selection: oldSelection, manifest: oldManifest },
      candidateMaterialization: candidateManifest,
      services: {
        startAndProveCandidate: async () => candidateSelection,
        proveCandidate: async () => candidateSelection,
        reproveCandidate: async () => {
          if (!crashed
            && readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase === phase) {
            crashed = true;
            throw new Error(`simulated crash at ${phase}`);
          }
        },
        proveSession: () => { throw new Error("zero-session fixture must not prove a session"); },
        finalize: async () => ({
          preparedRuntime: Object.freeze({ version: 1 }) as never,
          tokenResolutionReceipts: [],
        }),
      },
    })).rejects.toThrow(`simulated crash at ${phase}`);
  };

  // Journal exists but selection has not happened: still refused, before any
  // credential side effect.
  await crashAt("records-rebound");
  expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase).toBe("records-rebound");
  expect(() => assertControlPlaneRebindReceiptForTokenSync(stateDir, SESSION_TEST_PROJECT))
    .toThrow("token sync is impossible before the rebind receipt records candidate selection");

  // Selection recorded, durable selection is the candidate: the gate opens.
  await crashAt("tokens-synced");
  expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase).toBe("tokens-synced");
  expect((mocks.effective as { selection: unknown }).selection).toEqual(candidateSelection);
  expect(() => assertControlPlaneRebindReceiptForTokenSync(stateDir, SESSION_TEST_PROJECT)).not.toThrow();

  // Same journal but a contradictory durable selection: refused again.
  mocks.effective = { selection: oldSelection, manifest: oldManifest };
  expect(() => assertControlPlaneRebindReceiptForTokenSync(stateDir, SESSION_TEST_PROJECT))
    .toThrow("token sync is impossible while the effective selection is not the rebind candidate");
});

function recoveryFixture() {
  const oldTarget = sessionGenerationFixture().target;
  const candidateTarget = { ...oldTarget, controlPlane: createControlPlaneGenerationV2({
    ...SESSION_TEST_PROJECT, proxyImageInputDigest: sha256Digest("recovery-budget-candidate"),
    controlPlaneTopologyDigest: oldTarget.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: oldTarget.controlPlane.admissionContractEpoch,
  }) };
  const oldControlPlane = { selection: effectiveControlPlaneFixture({ target: oldTarget }),
    manifest: controlPlaneMaterializationFixture({ target: oldTarget }) };
  const candidate = { ...effectiveControlPlaneFixture({ target: candidateTarget }), proxyContainerId: "e".repeat(64) };
  const candidateMaterialization = controlPlaneMaterializationFixture({ target: candidateTarget });
  mocks.effective = oldControlPlane;
  let nowMs = Date.parse("2026-08-27T00:00:00.000Z");
  const args: Parameters<typeof runCompatibleControlPlaneRebind>[0] = {
    plan: { ...SESSION_TEST_PROJECT, composeProjectName: SESSION_TEST_PROJECT.composeProject,
      paths: { stateDir }, execution: { dockerClientEnv: {} } } as unknown as ActiveRuntimePlan,
    lifecycleLock: { ownerToken: "a".repeat(64), assertHeld() {}, release() {} },
    io: {} as never, oldControlPlane, candidateMaterialization,
    now: () => new Date(nowMs), randomBytes: () => new Uint8Array(32).fill(0xab),
    services: {
      startAndProveCandidate: vi.fn(async () => candidate), proveCandidate: async () => candidate,
      reproveCandidate: async () => {}, proveSession: (record) => {
        const plan = sessionContainerCreatePlanFixture({ target: candidateTarget,
          generation: sessionGenerationFixture().generation, record });
        return validateSessionContainerInspect(sessionContainerInspectJsonFixture(plan, { running: true }), plan, { kind: "active-running" });
      },
      finalize: vi.fn(async () => ({ preparedRuntime: {} as never, tokenResolutionReceipts: [] })),
    },
  };
  return { args, candidate, advance: (ms: number) => { nowMs += ms; } };
}

test("creation allowance is shared across callers and only explicit retry grants another allowance", async () => {
  const fixture = recoveryFixture();
  const create = vi.fn(async () => { throw new Error("Docker creation crashed"); });
  const failed = { ...fixture.args, services: { ...fixture.args.services, startAndProveCandidate: create } };
  await expect(runCompatibleControlPlaneRebind(failed)).rejects.toThrow("Docker creation crashed");
  await expect(runCompatibleControlPlaneRebind(failed)).rejects.toThrow("Docker creation crashed");
  expect(create).toHaveBeenCalledTimes(2);
  await expect(runCompatibleControlPlaneRebind(failed)).rejects.toThrow("runtime recover --retry");
  await expect(runCompatibleControlPlaneRebind({ ...failed, lifecycleLock: { ...failed.lifecycleLock, ownerToken: "b".repeat(64) } })).rejects.toThrow("runtime recover --retry");
  expect(create).toHaveBeenCalledTimes(2);
  const exhausted = readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT);
  expect(exhausted?.recovery?.allowance).toMatchObject({ creations: 2, exhausted: true, number: 0 });
  await runCompatibleControlPlaneRebind({ ...fixture.args, explicitRetry: true });
  expect(fixture.args.services.startAndProveCandidate).toHaveBeenCalledOnce();
  expect(fs.existsSync(controlPlaneRebindTransactionPath(stateDir))).toBe(false);
});

test.each([120_000, -1])("recovery time change %i ends the allowance without creating or erasing evidence", async (delta) => {
  const fixture = recoveryFixture();
  await expect(runCompatibleControlPlaneRebind({ ...fixture.args, services: { ...fixture.args.services,
    startAndProveCandidate: async () => { throw new Error("crash"); } } })).rejects.toThrow("crash");
  fixture.advance(delta);
  await expect(runCompatibleControlPlaneRebind(fixture.args)).rejects.toThrow("runtime recover --retry");
  expect(fixture.args.services.startAndProveCandidate).not.toHaveBeenCalled();
  expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.recovery?.allowance.exhausted).toBe(true);
});

test("a stopped unrecorded creation is retired exactly, then a new marked attempt restores service", async () => {
  const fixture = recoveryFixture();
  await expect(runCompatibleControlPlaneRebind({ ...fixture.args, services: { ...fixture.args.services,
    startAndProveCandidate: async () => { throw new Error("crash before identity write"); } } })).rejects.toThrow("crash before identity write");
  let stopped = true;
  const retire = vi.fn(async (id: string) => { expect(id).toBe("e".repeat(64)); stopped = false; });
  const create = vi.fn(async (transaction) => {
    expect(transaction.recovery.candidateAttempt).toBe(1);
    expect(fs.readFileSync(path.join(stateDir, "runtime/v2", `rebind-retired.${transaction.recovery.retired[0].slice(7)}.json`), "utf8")).toContain("e".repeat(64));
    return fixture.candidate;
  });
  await runCompatibleControlPlaneRebind({ ...fixture.args, services: { ...fixture.args.services,
    recoverUnrecordedCandidate: async () => stopped ? { stoppedProxyId: "e".repeat(64) } : undefined,
    retireUnrecordedCandidate: retire, startAndProveCandidate: create } });
  expect(retire).toHaveBeenCalledOnce();
  expect(create).toHaveBeenCalledOnce();
});

test.each(CONTROL_PLANE_REBIND_PHASES.filter((phase) => phase !== "prepared" && phase !== "eligibility-published"))(
  "a candidate lost at %s recovers on a new identity while retaining the shared allowance", async (phase) => {
    const fixture = recoveryFixture();
    let crashed = false;
    const firstLock = { ...fixture.args.lifecycleLock, assertHeld: () => {
      if (!crashed && readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase === phase) {
        crashed = true; throw new Error(`crash at ${phase}`);
      }
    } };
    await expect(runCompatibleControlPlaneRebind({ ...fixture.args, lifecycleLock: firstLock })).rejects.toThrow(`crash at ${phase}`);
    const prior = readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT);
    if ((mocks.effective as { selection: { proxyContainerId: string } }).selection.proxyContainerId === fixture.candidate.proxyContainerId) {
      mocks.effective = { selection: fixture.candidate, manifest: fixture.args.candidateMaterialization };
    }
    const next = { ...fixture.candidate, proxyContainerId: "f".repeat(64) };
    const create = vi.fn(async (transaction) => {
      expect(transaction.recovery.allowance.creations).toBe(2);
      expect(fs.readFileSync(path.join(stateDir, "runtime/v2", `rebind-retired.${transaction.recovery.retired[0].slice(7)}.json`), "utf8")).toContain(prior?.candidateControlPlane?.proxyContainerId);
      return next;
    });
    await runCompatibleControlPlaneRebind({ ...fixture.args, lifecycleLock: { ...fixture.args.lifecycleLock, ownerToken: "b".repeat(64) },
      services: { ...fixture.args.services, observeRecordedCandidate: async () => "absent",
        startAndProveCandidate: create, proveCandidate: async () => next } });
    expect(create).toHaveBeenCalledOnce();
    expect(fs.existsSync(controlPlaneRebindTransactionPath(stateDir))).toBe(false);
  },
);

test("a departed participant revises a nonempty batch before replay", async () => {
  const fixture = recoveryFixture();
  const allocated = sessionContainerRecordFixture({ containerId: "c".repeat(64) });
  const attached = transitionProvisioningRunningSessionContainerToAttachedV2(
    transitionBoundAllocatedSessionContainerToProvisioningRunningV2(allocated, {
      admittedAt: "2026-08-27T00:00:00.000Z", leaseGeneration: "d".repeat(64), leaseExpiresAt: "2026-08-27T00:05:00.000Z",
    }),
  );
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached);
  fixture.advance(1000);
  let crashed = false;
  await expect(runCompatibleControlPlaneRebind({ ...fixture.args, services: { ...fixture.args.services,
    reproveCandidate: async () => {
      if (!crashed && readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase === "records-rebound") {
        crashed = true; throw new Error("crash after record writes");
      }
    } } })).rejects.toThrow("crash after record writes");
  const rebound = readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached.sessionId);
  if (!rebound) throw new Error("fixture did not persist its rebound participant");
  removeExactSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, rebound);
  fixture.advance(60_000);
  let observedRevision = -1;
  await runCompatibleControlPlaneRebind({ ...fixture.args, randomBytes: () => new Uint8Array(32).fill(0xef),
    lifecycleLock: { ...fixture.args.lifecycleLock, ownerToken: "b".repeat(64) },
    services: { ...fixture.args.services, participantIsAbsent: () => true, finalize: async () => {
      const journal = readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT);
      observedRevision = journal?.recovery?.batchRevision ?? -1;
      expect(journal?.invalidSessionIds).toContain(attached.sessionId);
      return { preparedRuntime: {} as never, tokenResolutionReceipts: [] };
    } } });
  expect(observedRevision).toBe(1);
  expect(readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached.sessionId)).toBeUndefined();
});

test("a v1 prepared journal migrates atomically while retaining its original bytes", async () => {
  const fixture = recoveryFixture();
  await expect(runCompatibleControlPlaneRebind({ ...fixture.args, services: { ...fixture.args.services,
    startAndProveCandidate: async () => { throw new Error("crash"); } } })).rejects.toThrow("crash");
  const file = controlPlaneRebindTransactionPath(stateDir);
  const v2 = JSON.parse(fs.readFileSync(file, "utf8"));
  delete v2.recovery;
  v2.schemaVersion = 1;
  // Legacy writers also use canonical serialization.
  const { serializeControlPlaneRebindTransaction } = await import("./control-plane-rebind.ts");
  const original = serializeControlPlaneRebindTransaction(v2);
  fs.writeFileSync(file, original);
  let originalReceipt: string | undefined;
  await runCompatibleControlPlaneRebind({ ...fixture.args, lifecycleLock: { ...fixture.args.lifecycleLock, ownerToken: "b".repeat(64) },
    services: { ...fixture.args.services, finalize: async () => {
      originalReceipt = readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.recovery?.originalV1;
      return { preparedRuntime: {} as never, tokenResolutionReceipts: [] };
    } } });
  expect(originalReceipt).toBe(original);
});

test("complete-journal recovery reconverges an owner departure during final credential handoff", async () => {
  const fixture = recoveryFixture();
  const allocated = sessionContainerRecordFixture({ containerId: "c".repeat(64) });
  const attached = transitionProvisioningRunningSessionContainerToAttachedV2(
    transitionBoundAllocatedSessionContainerToProvisioningRunningV2(allocated, {
      admittedAt: "2026-08-27T00:00:00.000Z", leaseGeneration: "d".repeat(64), leaseExpiresAt: "2026-08-27T00:05:00.000Z",
    }),
  );
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached);
  fixture.advance(1000);
  let crashed = false;
  await expect(runCompatibleControlPlaneRebind({ ...fixture.args, lifecycleLock: { ...fixture.args.lifecycleLock, assertHeld() {
    if (!crashed && readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase === "complete") {
      crashed = true; throw new Error("crash before journal removal");
    }
  } } })).rejects.toThrow("crash before journal removal");
  let departed = false;
  const finalize = vi.fn(async () => {
    const current = readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached.sessionId);
    if (current) {
      removeExactSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, current);
      departed = true;
    } else {
      const journal = readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT);
      expect(journal?.replacementRecords).toEqual([]);
      expect(journal?.invalidSessionIds).toContain(attached.sessionId);
      expect(journal?.recovery?.batchRevision).toBe(1);
    }
    return { preparedRuntime: {} as never, tokenResolutionReceipts: [] };
  });
  await runCompatibleControlPlaneRebind({ ...fixture.args,
    lifecycleLock: { ...fixture.args.lifecycleLock, ownerToken: "b".repeat(64) },
    services: { ...fixture.args.services, participantIsAbsent: () => departed, finalize } });
  expect(finalize).toHaveBeenCalledTimes(2);
  expect(readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached.sessionId)).toBeUndefined();
  expect(fs.existsSync(controlPlaneRebindTransactionPath(stateDir))).toBe(false);
});

/**
 * One live session under a project whose proxy was materialized with the
 * per-session file source, plus everything a rebind of it needs.
 */
function fileSourceFixture(seed: string) {
  const oldTarget = sessionGenerationFixture().target;
  const candidateControl = createControlPlaneGenerationV2({
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProject: SESSION_TEST_PROJECT.composeProject,
    proxyImageInputDigest: sha256Digest(seed),
    controlPlaneTopologyDigest: oldTarget.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: oldTarget.controlPlane.admissionContractEpoch,
  });
  const candidateTarget = { ...oldTarget, controlPlane: candidateControl };
  const oldSelection = effectiveControlPlaneFixture({ target: oldTarget });
  const candidateSelection = {
    ...effectiveControlPlaneFixture({ target: candidateTarget }),
    proxyContainerId: "4".repeat(64),
  };
  const oldManifest = controlPlaneMaterializationFixture({ target: oldTarget });
  const candidateManifest = controlPlaneMaterializationFixture({ target: candidateTarget });
  mocks.effective = { selection: oldSelection, manifest: oldManifest };
  const attached = transitionProvisioningRunningSessionContainerToAttachedV2(
    transitionBoundAllocatedSessionContainerToProvisioningRunningV2(
      sessionContainerRecordFixture({ target: oldTarget, containerId: "c".repeat(64) }),
      {
        admittedAt: "2026-08-27T00:00:00.000Z",
        leaseGeneration: "d".repeat(64),
        leaseExpiresAt: "2026-08-27T00:05:00.000Z",
      },
    ),
  );
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached);
  const plan = {
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProjectName: SESSION_TEST_PROJECT.composeProject,
    paths: { stateDir },
    execution: { dockerClientEnv: {} },
  } as ActiveRuntimePlan;
  const proveSession = (replacement: typeof attached) => {
    mocks.events.push(`session-proved:${readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase ?? "prepared"}`);
    const createPlan = sessionContainerCreatePlanFixture({
      target: candidateTarget,
      generation: sessionGenerationFixture().generation,
      record: replacement,
    });
    return validateSessionContainerInspect(
      sessionContainerInspectJsonFixture(createPlan, { running: true }),
      createPlan,
      { kind: "active-running" },
    );
  };
  const recordPhase = () => {
    mocks.events.push(`phase:${readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase ?? "gone"}`);
  };
  const args = {
    plan,
    lifecycleLock: {
      ownerToken: "a".repeat(64),
      assertHeld: () => undefined,
      release: () => undefined,
    } as ProjectLifecycleLock,
    io: {} as never,
    oldControlPlane: { selection: oldSelection, manifest: oldManifest },
    candidateMaterialization: candidateManifest,
    now: (() => {
      let milliseconds = Date.parse("2026-08-27T00:00:00.000Z");
      return () => {
        milliseconds += 1_000;
        return new Date(milliseconds);
      };
    })(),
    randomBytes: () => new Uint8Array(32).fill(0xab),
    services: {
      startAndProveCandidate: async () => candidateSelection,
      proveCandidate: async () => { recordPhase(); return candidateSelection; },
      reproveCandidate: async () => recordPhase(),
      proveSession,
      finalize: async () => ({
        preparedRuntime: Object.freeze({ version: 1 }) as never,
        tokenResolutionReceipts: [],
      }),
    },
  };
  return { args, attached, candidateSelection, candidateControl, candidateManifest, oldSelection, oldManifest };
}

test("a file-source rebind publishes eligibility to the candidate before selecting it and acknowledges no consumer", async () => {
  const fixture = fileSourceFixture("candidate-proxy-files-rebind");

  await runCompatibleControlPlaneRebind(fixture.args);

  // The phase order this source runs: the two consumer acknowledgements are
  // gone, and the new phase carries the last identity re-proof, the
  // eligibility publication, and the selection.
  expect(mocks.events.filter((event) => event.startsWith("phase:"))).toEqual([
    "phase:proxy-started-deny-all",
    "phase:sessions-revalidated",
    "phase:records-rebound",
    "phase:eligibility-published",
    "phase:control-selected",
    "phase:tokens-synced",
  ]);
  // Invariant 9: the candidate proxy holds the project's eligibility before the
  // durable selection names it, and it is told about the rebound session.
  const published = mocks.events.indexOf(
    `eligibility-published:${fixture.candidateSelection.proxyContainerId}:2026-08-27T00:00:00.000000000Z:1`,
  );
  expect(published).toBeGreaterThan(-1);
  expect(mocks.events.indexOf(`proxy-start-observed:${fixture.candidateSelection.proxyContainerId}`))
    .toBeLessThan(published);
  expect(published).toBeLessThan(mocks.events.indexOf("control-selected"));
  // F6: the last per-session identity re-proof still runs immediately before
  // the selection, in the phase that replaced the acknowledgements.
  const reproved = mocks.events.lastIndexOf("session-proved:eligibility-published");
  expect(reproved).toBeGreaterThan(-1);
  expect(reproved).toBeLessThan(published);
  // Nothing from the retired transaction protocol is touched.
  for (const event of ["snapshot-published", "request-proxy-selected", "request-proxy-acknowledged",
    "firewall-selected", "firewall-acknowledged", "base-state-cleared", "firewall-set-verified-empty"]) {
    expect(mocks.events).not.toContain(event);
  }
  // Invariant 11: the host record carries the candidate digest — what the
  // launch baseline compares against — and nothing else moved. The lease is
  // not this source's authority and no heartbeat renews it, so the rebind
  // does not mint a fresh one.
  expect(readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, fixture.attached.sessionId)).toEqual({
    ...fixture.attached,
    controlPlaneGenerationDigest: fixture.candidateControl.controlPlaneGenerationDigest,
  });
  expect((mocks.effective as { selection: { controlPlaneGenerationDigest: string } }).selection.controlPlaneGenerationDigest)
    .toBe(fixture.candidateControl.controlPlaneGenerationDigest);
  expect(fs.existsSync(controlPlaneRebindTransactionPath(stateDir))).toBe(false);
});

test("a file-source journal held at eligibility-published resumes through recovery", async () => {
  const fixture = fileSourceFixture("candidate-proxy-files-recovery");
  let crashed = false;
  await expect(runCompatibleControlPlaneRebind({
    ...fixture.args,
    services: {
      ...fixture.args.services,
      reproveCandidate: async () => {
        const phase = readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase;
        mocks.events.push(`phase:${phase ?? "gone"}`);
        if (!crashed && phase === "eligibility-published") {
          crashed = true;
          throw new Error("simulated crash at eligibility-published");
        }
      },
    },
  })).rejects.toThrow("simulated crash at eligibility-published");
  expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase).toBe("eligibility-published");
  expect(mocks.events).not.toContain("control-selected");

  mocks.events.length = 0;
  const recovered = await runCompatibleControlPlaneRebind({
    ...fixture.args,
    lifecycleLock: { ...fixture.args.lifecycleLock, ownerToken: "b".repeat(64) },
  });

  expect(recovered.selection).toEqual(fixture.candidateSelection);
  expect(mocks.events).toContain("control-selected");
  expect(mocks.events.some((event) => event.startsWith("eligibility-published:"))).toBe(true);
  expect(fs.existsSync(controlPlaneRebindTransactionPath(stateDir))).toBe(false);
});

test("a file-source batch refresh republishes nothing when a participant departs mid-rebind", async () => {
  const fixture = fileSourceFixture("candidate-proxy-files-departure");
  let crashed = false;
  await expect(runCompatibleControlPlaneRebind({
    ...fixture.args,
    services: {
      ...fixture.args.services,
      reproveCandidate: async () => {
        if (!crashed && readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase === "records-rebound") {
          crashed = true;
          throw new Error("crash after record writes");
        }
      },
    },
  })).rejects.toThrow("crash after record writes");
  // The owner departs while the journal is parked: its record is gone, so the
  // batch no longer matches and recovery must revise it before replaying.
  const rebound = readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, fixture.attached.sessionId);
  if (!rebound) throw new Error("fixture did not persist its rebound participant");
  removeExactSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, rebound);
  mocks.events.length = 0;

  const recovered = await runCompatibleControlPlaneRebind({
    ...fixture.args,
    lifecycleLock: { ...fixture.args.lifecycleLock, ownerToken: "b".repeat(64) },
    services: { ...fixture.args.services, participantIsAbsent: () => true },
  });

  expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)).toBeUndefined();
  expect(recovered.selection).toEqual(fixture.candidateSelection);
  // The revised batch is journaled and the record is gone, and nothing from the
  // retired transaction protocol is touched on the way: the proxy acknowledges
  // no snapshot, so a republication here would wait forever and leave selection
  // residue behind.
  for (const event of ["snapshot-published", "request-proxy-selected", "request-proxy-acknowledged",
    "firewall-selected", "firewall-acknowledged", "base-state-cleared", "firewall-set-verified-empty"]) {
    expect(mocks.events).not.toContain(event);
  }
  expect(mocks.events.some((event) => event.startsWith("eligibility-published:"))).toBe(true);
});

test("a candidate that fails its proof beside live peers preserves every peer, then recovery rebinds them", async () => {
  // L7's live-peers half. The recovery design's claim ledger records that the
  // phase-loop fixture has zero sessions, so "recovery works with sessions
  // running" was a rejected inference rather than a proved property. This
  // proves it directly.
  //
  // A candidate DNS failure reaches this coordinator as a rejecting
  // `startAndProveCandidate`: the probes and the readiness wait run in
  // `startup.ts`, and the candidate never becomes proved authority here. What
  // must hold is that a candidate which never proved cannot cost a healthy
  // peer anything — the exact claim the refused blanket version of L3 was too
  // weak to make.
  const fixture = recoveryFixture();
  const oldTarget = sessionGenerationFixture().target;
  const allocated = sessionContainerRecordFixture({ target: oldTarget, containerId: "c".repeat(64) });
  const attached = transitionProvisioningRunningSessionContainerToAttachedV2(
    transitionBoundAllocatedSessionContainerToProvisioningRunningV2(allocated, {
      admittedAt: "2026-08-27T00:00:00.000Z",
      leaseGeneration: "d".repeat(64),
      leaseExpiresAt: "2026-08-27T00:05:00.000Z",
    }),
  );
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached);

  const proofFailure = vi.fn(async () => { throw new Error("candidate proof failed: root Docker DNS failed"); });
  await expect(runCompatibleControlPlaneRebind({
    ...fixture.args,
    services: { ...fixture.args.services, startAndProveCandidate: proofFailure },
  })).rejects.toThrow("root Docker DNS failed");
  expect(proofFailure).toHaveBeenCalledOnce();

  // 1. The peer is untouched. Not "still present": the same incarnation, the
  //    same container, and the same lease, still bound to the OLD generation.
  const preserved = readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached.sessionId);
  expect(preserved).toMatchObject({
    sessionId: attached.sessionId,
    sessionIncarnation: attached.sessionIncarnation,
    containerId: attached.containerId,
    controlPlaneGenerationDigest: attached.controlPlaneGenerationDigest,
  });
  expect(preserved?.leaseGeneration).toBe(attached.leaseGeneration);
  expect(preserved?.leaseExpiresAt).toBe(attached.leaseExpiresAt);

  // 2. Nothing was published to, or selected for, a candidate that never proved.
  expect(mocks.events).not.toContain("control-selected");
  expect(mocks.events.some((event) => event.startsWith("eligibility-published"))).toBe(false);

  // 3. Recovery restores service and rebinds the surviving peer rather than
  //    requiring it to be relaunched.
  mocks.events.length = 0;
  await runCompatibleControlPlaneRebind(fixture.args);
  const rebound = readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached.sessionId);
  expect(rebound?.containerId).toBe(attached.containerId);
  expect(rebound?.sessionIncarnation).toBe(attached.sessionIncarnation);
  expect(rebound?.controlPlaneGenerationDigest).not.toBe(attached.controlPlaneGenerationDigest);
  expect(mocks.events).toContain("control-selected");
  expect(mocks.events.some((event) => event.startsWith("eligibility-published"))).toBe(true);
  expect(fs.existsSync(controlPlaneRebindTransactionPath(stateDir))).toBe(false);
});

/**
 * Two live participants of one project, distinct in every identity a record
 * carries, so a batch over them can be interrupted between their writes.
 */
function twoParticipantFixture(seed: string) {
  const oldTarget = sessionGenerationFixture().target;
  const candidateControl = createControlPlaneGenerationV2({
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProject: SESSION_TEST_PROJECT.composeProject,
    proxyImageInputDigest: sha256Digest(seed),
    controlPlaneTopologyDigest: oldTarget.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: oldTarget.controlPlane.admissionContractEpoch,
  });
  const candidateTarget = { ...oldTarget, controlPlane: candidateControl };
  const oldSelection = effectiveControlPlaneFixture({ target: oldTarget });
  const candidateSelection = effectiveControlPlaneFixture({ target: candidateTarget });
  const oldManifest = controlPlaneMaterializationFixture({ target: oldTarget });
  const candidateManifest = controlPlaneMaterializationFixture({ target: candidateTarget });
  mocks.effective = { selection: oldSelection, manifest: oldManifest };
  const attach = (sessionId: string, containerId: string) => {
    const record = transitionProvisioningRunningSessionContainerToAttachedV2(
      transitionBoundAllocatedSessionContainerToProvisioningRunningV2(
        sessionContainerRecordFixture({
          target: oldTarget,
          containerId,
          overrides: {
            sessionId,
            containerName: sessionContainerName(SESSION_TEST_PROJECT.projectId, sessionId),
          },
        }),
        {
          admittedAt: "2026-08-27T00:00:00.000Z",
          leaseGeneration: "d".repeat(64),
          leaseExpiresAt: "2026-08-27T00:05:00.000Z",
        },
      ),
    );
    writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, record);
    return record;
  };
  // Records are batched in filename order, so these names fix which participant
  // the interrupted batch reaches first.
  const first = attach("rf-20260808-aaaaaa", "a".repeat(64));
  const second = attach("rf-20260808-bbbbbb", "b".repeat(64));
  const plan = {
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProjectName: SESSION_TEST_PROJECT.composeProject,
    paths: { stateDir },
    execution: { dockerClientEnv: {} },
  } as ActiveRuntimePlan;
  const services = {
    startAndProveCandidate: async () => candidateSelection,
    proveCandidate: async () => candidateSelection,
    reproveCandidate: async () => undefined,
    proveSession: (replacement: typeof first) => {
      const createPlan = sessionContainerCreatePlanFixture({
        target: candidateTarget,
        generation: sessionGenerationFixture().generation,
        record: replacement,
      });
      return validateSessionContainerInspect(
        sessionContainerInspectJsonFixture(createPlan, { running: true }),
        createPlan,
        { kind: "active-running" },
      );
    },
    finalize: async () => ({
      preparedRuntime: Object.freeze({ version: 1 }) as never,
      tokenResolutionReceipts: [],
    }),
  };
  const args = {
    plan,
    lifecycleLock: {
      ownerToken: "1".repeat(64),
      assertHeld: () => undefined,
      release: () => undefined,
    } as ProjectLifecycleLock,
    io: {} as never,
    oldControlPlane: { selection: oldSelection, manifest: oldManifest },
    candidateMaterialization: candidateManifest,
    services,
  };
  return { args, first, second, candidateControl, candidateSelection, oldSelection };
}

test("a record batch interrupted between two participants recovers per participant", async () => {
  const fixture = twoParticipantFixture("candidate-proxy-partial-batch");
  const reboundFirst = {
    ...fixture.first,
    controlPlaneGenerationDigest: fixture.candidateControl.controlPlaneGenerationDigest,
  };
  let crashed = false;

  await expect(runCompatibleControlPlaneRebind({
    ...fixture.args,
    lifecycleLock: {
      ...fixture.args.lifecycleLock,
      // The batch takes the fence before each participant, so the write of the
      // first record is exactly the state this stops on.
      assertHeld: () => {
        if (crashed
          || readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase !== "sessions-revalidated") return;
        const written = readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, fixture.first.sessionId);
        if (written?.controlPlaneGenerationDigest !== fixture.candidateControl.controlPlaneGenerationDigest) return;
        crashed = true;
        throw new Error("crash between the two record writes");
      },
    },
  })).rejects.toThrow("crash between the two record writes");

  expect(readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, fixture.first.sessionId)).toEqual(reboundFirst);
  expect(readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, fixture.second.sessionId)).toEqual(fixture.second);
  const writtenInode = fs.statSync(sessionContainerRecordPath(stateDir, fixture.first.sessionId)).ino;

  await runCompatibleControlPlaneRebind({
    ...fixture.args,
    lifecycleLock: { ...fixture.args.lifecycleLock, ownerToken: "2".repeat(64) },
  });

  // The participant the interrupted batch already wrote is skipped, not
  // rewritten: replacement is atomic-rename, so its record is the same inode.
  expect(fs.statSync(sessionContainerRecordPath(stateDir, fixture.first.sessionId)).ino).toBe(writtenInode);
  expect(readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, fixture.first.sessionId)).toEqual(reboundFirst);
  // The participant it never reached is written from its own exact journaled
  // input: the digest moves and nothing else.
  expect(readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, fixture.second.sessionId)).toEqual({
    ...fixture.second,
    controlPlaneGenerationDigest: fixture.candidateControl.controlPlaneGenerationDigest,
  });
  expect(fs.existsSync(controlPlaneRebindTransactionPath(stateDir))).toBe(false);
});

const HOST_BOOT_ID = "linux:11111111-1111-1111-1111-111111111111";
const REBOOTED_HOST_BOOT_ID = "linux:22222222-2222-2222-2222-222222222222";
const HOST_PROCESS_START = "linux:4242";
/** The Docker client env under which this process's own pid reads as a live owner. */
const LIVE_OWNER_ENV: NodeJS.ProcessEnv = {
  RUNFREE_TEST_FAKE_DOCKER: "1",
  RUNFREE_TEST_HOST_BOOT_ID: HOST_BOOT_ID,
  RUNFREE_TEST_HOST_PROCESS_START: HOST_PROCESS_START,
};
/** The same record read on a later boot: its owner is proved gone. */
const DEAD_OWNER_ENV: NodeJS.ProcessEnv = {
  RUNFREE_TEST_FAKE_DOCKER: "1",
  RUNFREE_TEST_HOST_BOOT_ID: REBOOTED_HOST_BOOT_ID,
};

/**
 * One attached participant whose host owner is this very process, so owner
 * liveness is decided by the Docker client env the plan carries rather than by
 * whatever pid the default fixture happens to name.
 */
function liveParticipantFixture(seed: string, dockerClientEnv: NodeJS.ProcessEnv = LIVE_OWNER_ENV) {
  const oldTarget = sessionGenerationFixture().target;
  const candidateControl = createControlPlaneGenerationV2({
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProject: SESSION_TEST_PROJECT.composeProject,
    proxyImageInputDigest: sha256Digest(seed),
    controlPlaneTopologyDigest: oldTarget.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: oldTarget.controlPlane.admissionContractEpoch,
  });
  const candidateTarget = { ...oldTarget, controlPlane: candidateControl };
  const oldSelection = effectiveControlPlaneFixture({ target: oldTarget });
  const candidateSelection = effectiveControlPlaneFixture({ target: candidateTarget });
  const oldManifest = controlPlaneMaterializationFixture({ target: oldTarget });
  const candidateManifest = controlPlaneMaterializationFixture({ target: candidateTarget });
  mocks.effective = { selection: oldSelection, manifest: oldManifest };
  const attached = transitionProvisioningRunningSessionContainerToAttachedV2(
    transitionBoundAllocatedSessionContainerToProvisioningRunningV2(
      sessionContainerRecordFixture({
        target: oldTarget,
        containerId: "c".repeat(64),
        overrides: {
          hostPid: process.pid,
          hostBootId: HOST_BOOT_ID,
          hostProcessStart: HOST_PROCESS_START,
        },
      }),
      {
        admittedAt: "2026-08-27T00:00:00.000Z",
        leaseGeneration: "d".repeat(64),
        leaseExpiresAt: "2026-08-27T00:05:00.000Z",
      },
    ),
  );
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached);
  const proveSession = (replacement: typeof attached, dockerPid?: number) => {
    const createPlan = sessionContainerCreatePlanFixture({
      target: candidateTarget,
      generation: sessionGenerationFixture().generation,
      record: replacement,
    });
    const inspect = JSON.parse(sessionContainerInspectJsonFixture(createPlan, { running: true }));
    if (dockerPid !== undefined) inspect[0].State.Pid = dockerPid;
    return validateSessionContainerInspect(JSON.stringify(inspect), createPlan, { kind: "active-running" });
  };
  const args = {
    plan: {
      projectId: SESSION_TEST_PROJECT.projectId,
      composeProjectName: SESSION_TEST_PROJECT.composeProject,
      paths: { stateDir },
      execution: { dockerClientEnv },
    } as ActiveRuntimePlan,
    lifecycleLock: {
      ownerToken: "a".repeat(64),
      assertHeld: () => undefined,
      release: () => undefined,
    } as ProjectLifecycleLock,
    io: {} as never,
    oldControlPlane: { selection: oldSelection, manifest: oldManifest },
    candidateMaterialization: candidateManifest,
    services: {
      startAndProveCandidate: async () => candidateSelection,
      proveCandidate: async () => candidateSelection,
      reproveCandidate: async () => undefined,
      proveSession: (replacement: typeof attached) => proveSession(replacement),
      finalize: vi.fn(async () => ({
        preparedRuntime: Object.freeze({ version: 1 }) as never,
        tokenResolutionReceipts: [],
      })),
    },
  };
  return { args, attached, proveSession, candidateControl, candidateSelection, oldSelection };
}

test("a session proof that cannot be taken beside a live owner is classified evidence, not a revocation", async () => {
  const fixture = liveParticipantFixture("candidate-proxy-live-proof-failure");

  const failure = await runCompatibleControlPlaneRebind({
    ...fixture.args,
    services: {
      ...fixture.args.services,
      proveSession: () => { throw new Error("docker inspect answered nothing for the session container"); },
    },
  }).then(
    () => undefined,
    (error: unknown) => error,
  );

  // The failure is an observation this coordinator could not take, carried as
  // classified evidence with the subject it was taken for.
  expect(failure).toBeInstanceOf(RuntimeObservationError);
  expect((failure as RuntimeObservationError).evidence).toMatchObject({
    kind: "unclassified",
    subject: "session",
    expectedIdentity: fixture.attached.sessionId,
    phase: "proxy-started-deny-all",
  });
  // A proof that could not be taken is not evidence that the session is gone:
  // the live participant keeps its record, its state, and its old binding, and
  // the journal never names it invalid.
  expect(readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, fixture.attached.sessionId))
    .toEqual(fixture.attached);
  expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)).toMatchObject({
    phase: "proxy-started-deny-all",
    invalidSessionIds: [],
  });
  expect(fixture.args.services.finalize).not.toHaveBeenCalled();
  expect(mocks.events).not.toContain("control-selected");
});

test("a session that changes before the selection flips refuses at the last re-proof", async () => {
  const fixture = liveParticipantFixture("candidate-proxy-late-session-drift");

  await expect(runCompatibleControlPlaneRebind({
    ...fixture.args,
    services: {
      ...fixture.args.services,
      // The container is restarted after the batch is journaled: the same
      // record, a different live process.
      proveSession: (replacement) => fixture.proveSession(
        replacement,
        readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase === "eligibility-published"
          ? 5150
          : undefined,
      ),
    },
  })).rejects.toThrow(`session ${fixture.attached.sessionId} changed after control-plane rebind acknowledgement`);

  // The re-proof is spent before the eligibility publication and before the
  // selection, so a changed session costs the candidate both.
  expect(mocks.events).toEqual([]);
  expect((mocks.effective as { selection: unknown }).selection).toEqual(fixture.oldSelection);
  expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase).toBe("eligibility-published");
  expect(fixture.args.services.finalize).not.toHaveBeenCalled();
});

test("a participant whose owner is alive again refuses the batch's revocation", async () => {
  const fixture = liveParticipantFixture("candidate-proxy-owner-alive-again", DEAD_OWNER_ENV);
  let crashed = false;

  // The owner reads as gone, so the unprovable session is journaled invalid;
  // the crash parks the journal before the batch acts on that.
  await expect(runCompatibleControlPlaneRebind({
    ...fixture.args,
    lifecycleLock: {
      ...fixture.args.lifecycleLock,
      assertHeld: () => {
        if (crashed
          || readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase !== "sessions-revalidated") return;
        crashed = true;
        throw new Error("crash before the invalid participant is revoked");
      },
    },
    services: {
      ...fixture.args.services,
      proveSession: () => { throw new Error("docker inspect answered nothing for the session container"); },
    },
  })).rejects.toThrow("crash before the invalid participant is revoked");
  expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)).toMatchObject({
    phase: "sessions-revalidated",
    invalidSessionIds: [fixture.attached.sessionId],
    replacementRecords: [],
  });

  // Recovery observes the same record under an owner that is now proved alive.
  // A journaled verdict is not a licence: the write refuses.
  await expect(runCompatibleControlPlaneRebind({
    ...fixture.args,
    plan: { ...fixture.args.plan, execution: { dockerClientEnv: LIVE_OWNER_ENV } } as ActiveRuntimePlan,
    lifecycleLock: { ...fixture.args.lifecycleLock, ownerToken: "b".repeat(64) },
  })).rejects.toThrow(`session ${fixture.attached.sessionId} has no proved dead owner`);

  expect(readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, fixture.attached.sessionId))
    .toEqual(fixture.attached);
  expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase).toBe("sessions-revalidated");
  expect(mocks.events).toEqual([]);
  expect(fixture.args.services.finalize).not.toHaveBeenCalled();
});

test("a transient failure after an explicit renewal spends that allowance instead of replenishing it", async () => {
  const fixture = recoveryFixture();
  let crashed = false;
  await expect(runCompatibleControlPlaneRebind({
    ...fixture.args,
    lifecycleLock: {
      ...fixture.args.lifecycleLock,
      assertHeld: () => {
        if (crashed
          || readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase !== "sessions-revalidated") return;
        crashed = true;
        throw new Error("crash after the candidate was proved");
      },
    },
  })).rejects.toThrow("crash after the candidate was proved");

  // Classification, not position, decides whether a failure is retried: a
  // contradiction is final, so it is rethrown on its first observation.
  const contradiction = vi.fn(async () => {
    throw new RuntimeObservationError({
      kind: "identity-contradiction",
      subject: "proxy",
      expectedIdentity: fixture.candidate.proxyContainerId,
      phase: "sessions-revalidated",
      observation: "the recreated proxy carries a different network identity",
    });
  });
  await expect(runCompatibleControlPlaneRebind({
    ...fixture.args,
    services: { ...fixture.args.services, proveCandidate: contradiction },
  })).rejects.toThrow("identity-contradiction");
  expect(contradiction).toHaveBeenCalledOnce();

  const allowances: Array<{ number: number; creations: number; retired: number }> = [];
  let transient = 1;
  const unavailable = vi.fn(async () => {
    const recovery = readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.recovery;
    if (!recovery) throw new Error("explicit retry requires a v2 recovery journal");
    allowances.push({
      number: recovery.allowance.number,
      creations: recovery.allowance.creations,
      retired: recovery.retired.length,
    });
    if (transient-- > 0) {
      throw new RuntimeObservationError({
        kind: "observation-unavailable",
        subject: "proxy",
        expectedIdentity: fixture.candidate.proxyContainerId,
        phase: "sessions-revalidated",
        observation: "docker inspect did not answer",
      });
    }
    return fixture.candidate;
  });
  await runCompatibleControlPlaneRebind({
    ...fixture.args,
    explicitRetry: true,
    services: { ...fixture.args.services, proveCandidate: unavailable },
  });

  // An unavailable observation earns a retry, and that retry runs inside the
  // allowance the operator already spent: it mints no second allowance and
  // retires nothing, so the budget an explicit retry grants stays finite.
  expect(unavailable).toHaveBeenCalledTimes(2);
  expect(allowances).toEqual([
    { number: 1, creations: 0, retired: 1 },
    { number: 1, creations: 0, retired: 1 },
  ]);
  expect(fs.existsSync(controlPlaneRebindTransactionPath(stateDir))).toBe(false);
});

/** The exact shape the recovery journal accepts for retained trust inputs. */
function trustReceiptFixture(seed: string): string {
  return JSON.stringify({
    certificateDigest: sha256Digest(`${seed}-certificate`),
    publicKeyDigest: sha256Digest(`${seed}-public-key`),
    directories: [
      { path: "/state/proxy-ca/public", device: 2049, inode: 101 },
      { path: "/state/proxy-ca/private", device: 2049, inode: 102 },
    ],
    volume: {
      name: "runfree-0123456789ab-oauth",
      createdAt: "2026-08-27T00:00:00.000Z",
      mountpoint: "/var/lib/docker/volumes/runfree-0123456789ab-oauth/_data",
      driver: "local",
      scope: "local",
    },
  });
}

test("recovery refuses a changed trust receipt at entry and again before each further effect", async () => {
  const fixture = recoveryFixture();
  const recorded = trustReceiptFixture("recorded");
  const rotated = trustReceiptFixture("rotated");
  let crashed = false;
  await expect(runCompatibleControlPlaneRebind({
    ...fixture.args,
    lifecycleLock: {
      ...fixture.args.lifecycleLock,
      assertHeld: () => {
        if (crashed
          || readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase !== "sessions-revalidated") return;
        crashed = true;
        throw new Error("crash while the recorded trust inputs were still current");
      },
    },
    services: { ...fixture.args.services, captureTrustReceipt: () => recorded },
  })).rejects.toThrow("crash while the recorded trust inputs were still current");
  expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.recovery?.trustReceipt).toBe(recorded);

  // The CA material or the OAuth volume was replaced while the journal was
  // parked. Recovery refuses at entry, before it proves anything.
  await expect(runCompatibleControlPlaneRebind({
    ...fixture.args,
    lifecycleLock: { ...fixture.args.lifecycleLock, ownerToken: "b".repeat(64) },
    services: { ...fixture.args.services, captureTrustReceipt: () => rotated },
  })).rejects.toThrow("retained CA or OAuth volume changed");

  // Entry is not the only observation: the receipt is re-taken before each
  // phase's effect, so material replaced after a passing entry check refuses
  // too.
  let captures = 0;
  await expect(runCompatibleControlPlaneRebind({
    ...fixture.args,
    lifecycleLock: { ...fixture.args.lifecycleLock, ownerToken: "b".repeat(64) },
    services: {
      ...fixture.args.services,
      captureTrustReceipt: () => (captures++ === 0 ? recorded : rotated),
    },
  })).rejects.toThrow("retained trust inputs changed during recovery");

  // Neither refusal published eligibility, flipped the selection, or resolved a
  // credential against a proxy whose trust inputs are no longer the recorded
  // ones.
  expect(mocks.events).toEqual([]);
  expect((mocks.effective as { selection: unknown }).selection)
    .toEqual(fixture.args.oldControlPlane.selection);
  expect(fixture.args.services.finalize).not.toHaveBeenCalled();
  expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase).toBe("sessions-revalidated");
});

test("a retried rebind keeps the first observation as the cause of the failure it reports", async () => {
  const fixture = recoveryFixture();
  const observations = ["docker inspect did not answer", "the recreated proxy carries a different network identity"];
  const proveCandidate = vi.fn(async () => {
    // A transient observation earns a retry; the contradiction that follows is
    // final. The operator must still see what started the failure.
    throw observations.length > 1
      ? new RuntimeObservationError({ kind: "observation-unavailable", subject: "proxy",
        expectedIdentity: fixture.candidate.proxyContainerId, phase: "sessions-revalidated",
        observation: observations.shift() as string })
      : new RuntimeObservationError({ kind: "identity-contradiction", subject: "proxy",
        expectedIdentity: fixture.candidate.proxyContainerId, phase: "sessions-revalidated",
        observation: observations[0] as string });
  });

  const failure = await runCompatibleControlPlaneRebind({
    ...fixture.args,
    services: { ...fixture.args.services, proveCandidate },
  }).then(() => undefined, (error: unknown) => error);

  // The reported classification stays the last one, because callers select a
  // remedy from `evidence.kind` and an AggregateError would erase it.
  expect(failure).toBeInstanceOf(RuntimeObservationError);
  expect((failure as RuntimeObservationError).evidence.kind).toBe("identity-contradiction");
  // The first failure is retained, not discarded with its catch block.
  expect((failure as Error).cause).toBeInstanceOf(RuntimeObservationError);
  expect(((failure as Error).cause as RuntimeObservationError).evidence.observation)
    .toBe("docker inspect did not answer");
  expect(proveCandidate).toHaveBeenCalledTimes(2);
});
