import { REBIND_PHASE_EFFECTS } from "./control-plane-rebind-recovery.ts";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { sha256Digest } from "./component-state.ts";
import { createControlPlaneGenerationV2 } from "./component-state-v2.ts";
import {
  CONTROL_PLANE_REBIND_PHASES,
  advanceControlPlaneRebindTransaction,
  completeControlPlaneRebindTransaction,
  controlPlaneRebindTransactionPath,
  createControlPlaneRebindTransaction,
  createReboundSessionContainerRecordV2,
  discardControlPlaneRebindTransaction,
  prepareControlPlaneRebindTransaction,
  readControlPlaneRebindTransaction,
  type ControlPlaneRebindTransaction,
} from "./control-plane-rebind.ts";
import {
  controlPlaneMaterializationFixture,
  effectiveControlPlaneFixture,
  sessionContainerRecordFixture,
  sessionGenerationFixture,
  SESSION_TEST_PROJECT,
} from "./session-container.test-harness.ts";

let stateDir: string;

beforeEach(() => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-rebind-"));
});

afterEach(() => {
  fs.rmSync(stateDir, { recursive: true, force: true });
});

function fixture() {
  const oldTarget = sessionGenerationFixture().target;
  const candidateControl = createControlPlaneGenerationV2({
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProject: SESSION_TEST_PROJECT.composeProject,
    proxyImageInputDigest: sha256Digest("candidate-proxy-input"),
    controlPlaneTopologyDigest: oldTarget.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: oldTarget.controlPlane.admissionContractEpoch,
  });
  const candidateTarget = {
    ...oldTarget,
    controlPlane: candidateControl,
  };
  const allocated = sessionContainerRecordFixture({
    target: oldTarget,
    containerId: "c".repeat(64),
  });
  const oldRecord = {
    ...allocated,
    state: "attached" as const,
    admittedAt: "2026-08-27T00:00:00.000Z",
    leaseGeneration: "d".repeat(64),
    leaseExpiresAt: "2026-08-27T00:05:00.000Z",
  };
  return createControlPlaneRebindTransaction({
    expectedProject: SESSION_TEST_PROJECT,
    lockOwnerToken: "e".repeat(64),
    oldControlPlane: effectiveControlPlaneFixture({ target: oldTarget }),
    oldMaterialization: controlPlaneMaterializationFixture({ target: oldTarget }),
    candidateMaterialization: controlPlaneMaterializationFixture({ target: candidateTarget }),
    oldRecords: [oldRecord],
    now: () => new Date("2026-08-27T00:00:00.000Z"),
    randomBytes: () => new Uint8Array(32).fill(0xab),
  });
}

describe("durable compatible control-plane rebind", () => {
  test("discards one exact validated transaction at an interrupted phase", () => {
    const prepared = fixture();
    prepareControlPlaneRebindTransaction(stateDir, prepared);

    discardControlPlaneRebindTransaction(stateDir, prepared);

    expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)).toBeUndefined();
  });

  test("re-fsyncs the journal parent when retry follows a completed unlink", () => {
    const prepared = fixture();
    prepareControlPlaneRebindTransaction(stateDir, prepared);
    const transactionPath = controlPlaneRebindTransactionPath(stateDir);

    const originalFsync = fs.fsyncSync.bind(fs);
    const firstFsync = vi.spyOn(fs, "fsyncSync").mockImplementationOnce(() => {
      throw new Error("simulated rebind directory fsync failure");
    });
    try {
      expect(() => discardControlPlaneRebindTransaction(stateDir, prepared))
        .toThrow("simulated rebind directory fsync failure");
    } finally {
      firstFsync.mockRestore();
    }
    expect(fs.existsSync(transactionPath)).toBe(false);

    const retryFsync = vi.spyOn(fs, "fsyncSync").mockImplementation(originalFsync);
    try {
      discardControlPlaneRebindTransaction(stateDir, prepared);
      expect(retryFsync).toHaveBeenCalled();
    } finally {
      retryFsync.mockRestore();
    }
  });

  test("refuses a symlinked state parent before reading or discarding a transaction", () => {
    const sourceState = stateDir;
    const prepared = fixture();
    prepareControlPlaneRebindTransaction(sourceState, prepared);
    const externalPath = controlPlaneRebindTransactionPath(sourceState);

    const redirectedState = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-rebind-redirected-"));
    fs.mkdirSync(path.join(redirectedState, "runtime"));
    fs.symlinkSync(path.join(sourceState, "runtime", "v2"), path.join(redirectedState, "runtime", "v2"), "dir");
    try {
      expect(() => readControlPlaneRebindTransaction(redirectedState, SESSION_TEST_PROJECT)).toThrow("unsafe");
      expect(() => discardControlPlaneRebindTransaction(redirectedState, prepared)).toThrow("unsafe");
      expect(fs.existsSync(externalPath)).toBe(true);
    } finally {
      fs.rmSync(redirectedState, { recursive: true, force: true });
    }
  });

  test("publishes, advances one exact phase, and removes only a complete transaction", () => {
    const prepared = fixture();
    prepareControlPlaneRebindTransaction(stateDir, prepared);
    expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)).toEqual(prepared);

    const next = Object.freeze({
      ...prepared,
      phase: "proxy-started-deny-all" as const,
      recovery: { ...prepared.recovery, outstandingEffect: "none" },
      candidateControlPlane: effectiveControlPlaneFixture({
        target: {
          ...sessionGenerationFixture().target,
          controlPlane: prepared.candidateMaterialization.generation,
        },
      }),
      updatedAt: "2026-08-27T00:00:01.000Z",
    }) as ControlPlaneRebindTransaction;
    advanceControlPlaneRebindTransaction(stateDir, prepared, next);
    expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase)
      .toBe("proxy-started-deny-all");

    expect(() => completeControlPlaneRebindTransaction(stateDir, next)).toThrow("not complete");
    let current = next;
    for (const phase of [
      "sessions-revalidated",
      "records-rebound",
      "eligibility-published",
      "control-selected",
      "tokens-synced",
      "complete",
    ] as const) {
      const advanced = Object.freeze({
        ...current,
        phase,
        recovery: { ...current.recovery, outstandingEffect: REBIND_PHASE_EFFECTS[phase] },
        ...(phase === "sessions-revalidated"
          ? { invalidSessionIds: [prepared.oldRecords[0]?.sessionId] }
          : {}),
        updatedAt: new Date(Date.parse(current.updatedAt) + 1_000).toISOString(),
      }) as ControlPlaneRebindTransaction;
      advanceControlPlaneRebindTransaction(stateDir, current, advanced);
      current = advanced;
    }
    completeControlPlaneRebindTransaction(stateDir, current);
    expect(fs.existsSync(controlPlaneRebindTransactionPath(stateDir))).toBe(false);
  });

  test("rejects unknown fields, another project, and linked transaction authority", () => {
    const transaction = fixture();
    prepareControlPlaneRebindTransaction(stateDir, transaction);
    const transactionPath = controlPlaneRebindTransactionPath(stateDir);
    const source = JSON.parse(fs.readFileSync(transactionPath, "utf8"));
    fs.writeFileSync(transactionPath, `${JSON.stringify({ ...source, unknown: true })}\n`);
    expect(() => readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)).toThrow("invalid");

    fs.unlinkSync(transactionPath);
    prepareControlPlaneRebindTransaction(stateDir, transaction);
    expect(() => readControlPlaneRebindTransaction(stateDir, {
      projectId: "ffffffffffff",
      composeProject: "runfree-ffffffffffff",
    })).toThrow("another project");

    const extraLink = path.join(path.dirname(transactionPath), "extra-link.json");
    fs.linkSync(transactionPath, extraLink);
    expect(() => readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)).toThrow("single-link");
  });
});

test("retired recovery evidence is archived before bounded history compaction", async () => {
  const { appendRetiredRebindReceipt } = await import("./control-plane-rebind.ts");
  const state = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-rebind-archive-"));
  try {
    let receipts: readonly string[] = [];
    const all: string[] = [];
    for (let index = 0; index < 40; index += 1) {
      const source = JSON.stringify({ candidateAttempt: index, phase: "prepared" });
      receipts = appendRetiredRebindReceipt(state, receipts, source);
      all.push(receipts.at(-1) as string);
    }
    expect(receipts.length).toBeLessThan(32);
    all.forEach((digest, index) => {
      const file = path.join(state, "runtime/v2", `rebind-retired.${digest.slice(7)}.json`);
      expect(JSON.parse(fs.readFileSync(file, "utf8"))).toEqual({ candidateAttempt: index, phase: "prepared" });
    });
    const chain = JSON.parse(fs.readFileSync(path.join(state, "runtime/v2", `rebind-retired.${receipts[0].slice(7)}.json`), "utf8"));
    expect(chain.retired).toEqual(all.slice(0, 31));
  } finally { fs.rmSync(state, { recursive: true, force: true }); }
});

describe("the rebind journal's session batch", () => {
  /** The same transaction as `fixture()`, with one attached record to rebind. */
  function filesFixture() {
    const oldTarget = sessionGenerationFixture().target;
    const candidateControl = createControlPlaneGenerationV2({
      projectId: SESSION_TEST_PROJECT.projectId,
      composeProject: SESSION_TEST_PROJECT.composeProject,
      proxyImageInputDigest: sha256Digest("candidate-proxy-input-files"),
      controlPlaneTopologyDigest: oldTarget.controlPlane.controlPlaneTopologyDigest,
      admissionContractEpoch: oldTarget.controlPlane.admissionContractEpoch,
    });
    const candidateTarget = { ...oldTarget, controlPlane: candidateControl };
    const allocated = sessionContainerRecordFixture({ target: oldTarget, containerId: "c".repeat(64) });
    const oldRecord = {
      ...allocated,
      state: "attached" as const,
      admittedAt: "2026-08-27T00:00:00.000Z",
      leaseGeneration: "d".repeat(64),
      leaseExpiresAt: "2026-08-27T00:05:00.000Z",
    };
    const transaction = createControlPlaneRebindTransaction({
      expectedProject: SESSION_TEST_PROJECT,
      lockOwnerToken: "e".repeat(64),
      oldControlPlane: effectiveControlPlaneFixture({ target: oldTarget }),
      oldMaterialization: controlPlaneMaterializationFixture({ target: oldTarget }),
      candidateMaterialization: controlPlaneMaterializationFixture({ target: candidateTarget }),
      oldRecords: [oldRecord],
      now: () => new Date("2026-08-27T00:00:00.000Z"),
      randomBytes: () => new Uint8Array(32).fill(0xab),
    });
    const candidateControlPlane = effectiveControlPlaneFixture({ target: candidateTarget });
    return { transaction, oldRecord, candidateControlPlane, candidateControl };
  }

  test("the phase tuple carries eligibility-published with its own outstanding effect", () => {
    expect([...CONTROL_PLANE_REBIND_PHASES]).toEqual([
      "prepared",
      "proxy-started-deny-all",
      "sessions-revalidated",
      "records-rebound",
      "eligibility-published",
      "control-selected",
      "tokens-synced",
      "complete",
    ]);
    // The label recovery carries for the effect the next case body performs.
    expect(REBIND_PHASE_EFFECTS["eligibility-published"]).toBe("select");
    // Every phase keeps an effect, so the parser's cross-check can never read
    // `undefined` for a phase a journal is allowed to hold.
    for (const phase of CONTROL_PLANE_REBIND_PHASES) {
      expect(typeof REBIND_PHASE_EFFECTS[phase]).toBe("string");
    }
  });

  test("advances through the one phase order and refuses a retired acknowledgement phase", () => {
    const { transaction } = filesFixture();
    const candidateControlPlane = effectiveControlPlaneFixture({
      target: {
        ...sessionGenerationFixture().target,
        controlPlane: transaction.candidateMaterialization.generation,
      },
    });
    prepareControlPlaneRebindTransaction(stateDir, transaction);
    let current = transaction;
    const advance = (phase: string, changes: Record<string, unknown> = {}): ControlPlaneRebindTransaction => {
      const next = Object.freeze({
        ...current,
        ...changes,
        phase,
        recovery: { ...current.recovery, outstandingEffect: REBIND_PHASE_EFFECTS[phase as keyof typeof REBIND_PHASE_EFFECTS] },
        updatedAt: new Date(Date.parse(current.updatedAt) + 1_000).toISOString(),
      }) as ControlPlaneRebindTransaction;
      advanceControlPlaneRebindTransaction(stateDir, current, next);
      current = next;
      return next;
    };
    advance("proxy-started-deny-all", { candidateControlPlane });
    advance("sessions-revalidated", { invalidSessionIds: [transaction.oldRecords[0]?.sessionId] });
    advance("records-rebound");
    // The retired consumer acknowledgement phases do not exist any more.
    expect(() => advance("request-acknowledged")).toThrow("phase transition is invalid");
    advance("eligibility-published");
    advance("control-selected");
    advance("tokens-synced");
    advance("complete");
    expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase).toBe("complete");
  });

  test("a journal parked at a retired phase is refused, not resumed", () => {
    // An edited or foreign journal cannot re-enter a sequence this transaction
    // never runs — recovery would otherwise replay the wrong effect.
    const { transaction } = filesFixture();
    prepareControlPlaneRebindTransaction(stateDir, transaction);
    const files = JSON.parse(fs.readFileSync(controlPlaneRebindTransactionPath(stateDir), "utf8"));
    fs.writeFileSync(controlPlaneRebindTransactionPath(stateDir), `${JSON.stringify({
      ...files,
      phase: "firewall-acknowledged",
      recovery: { ...files.recovery, outstandingEffect: "select" },
      candidateControlPlane: effectiveControlPlaneFixture({
        target: { ...sessionGenerationFixture().target, controlPlane: transaction.candidateMaterialization.generation },
      }),
      invalidSessionIds: [transaction.oldRecords[0]?.sessionId],
    })}\n`);
    expect(() => readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)).toThrow("invalid");
  });

  test("a rebind rebinds the digest alone and the journal refuses a lease it also advanced", () => {
    const { transaction, oldRecord, candidateControlPlane } = filesFixture();
    const rebound = createReboundSessionContainerRecordV2({
      current: oldRecord,
      candidateControlPlane,
    });
    // Only the digest moves: the record's lease is not this source's authority,
    // and nothing renews it, so a rebind must not mint fresh liveness for it.
    expect(rebound).toEqual({
      ...oldRecord,
      controlPlaneGenerationDigest: candidateControlPlane.controlPlaneGenerationDigest,
    });

    prepareControlPlaneRebindTransaction(stateDir, transaction);
    const source = JSON.parse(fs.readFileSync(controlPlaneRebindTransactionPath(stateDir), "utf8"));
    const proof = {
      sessionId: oldRecord.sessionId,
      projectId: oldRecord.projectId,
      sessionIncarnation: oldRecord.sessionIncarnation,
      sessionPrincipal: oldRecord.sessionPrincipal,
      containerId: oldRecord.containerId,
      imageId: oldRecord.selectedAgentImageId,
      sessionAgentGenerationDigest: oldRecord.sessionAgentGenerationDigest,
      controlPlaneGenerationDigest: candidateControlPlane.controlPlaneGenerationDigest,
      admissionContractEpoch: oldRecord.admissionContractEpoch,
      networkId: candidateControlPlane.networkIds.agentInternal,
      sourceIp: oldRecord.sourceIp,
      dockerPid: 4321,
      dockerStartedAt: "2026-08-27T00:00:00.000000000Z",
      networkEndpointId: "b".repeat(64),
    };
    const revalidated = {
      ...source,
      phase: "records-rebound",
      recovery: { ...source.recovery, outstandingEffect: REBIND_PHASE_EFFECTS["records-rebound"] },
      candidateControlPlane,
      replacementRecords: [rebound],
      sessionProofs: [proof],
      updatedAt: "2026-08-27T00:01:00.000Z",
    };
    fs.writeFileSync(controlPlaneRebindTransactionPath(stateDir), `${JSON.stringify(revalidated)}\n`);
    expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.replacementRecords)
      .toEqual([rebound]);

    // The same batch with an advanced lease is refused: the rebind may move the
    // digest and nothing else.
    fs.writeFileSync(controlPlaneRebindTransactionPath(stateDir), `${JSON.stringify({
      ...revalidated,
      replacementRecords: [{ ...rebound, leaseGeneration: "f".repeat(64), leaseExpiresAt: "2026-08-27T00:30:00.000Z" }],
    })}\n`);
    expect(() => readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)).toThrow("invalid");
  });
});
