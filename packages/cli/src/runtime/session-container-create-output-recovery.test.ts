import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, test } from "vitest";

import {
  AGENT_PROJECT_IMAGE_ROLE,
  RUNFREE_DIGEST_SCHEMA_LABEL,
  RUNFREE_DIGEST_SCHEMA_VERSION,
  RUNFREE_IMAGE_INPUT_DIGEST_LABEL,
  RUNFREE_IMAGE_ROLE_LABEL,
} from "./constants.ts";
import {
  authorizeSessionContainerOrphanCleanup,
  authorizeUnboundCreatedSessionRecordRecovery,
  recoverUnboundCreatedSessionRecordV2,
  type SessionContainerCreateOutputRecoveryAuthority,
  type SessionContainerNetworkIdentity,
} from "./session-container-cleanup.ts";
import {
  SESSION_TEST_PROJECT,
  sessionContainerRecordFixture,
} from "./session-container.test-harness.ts";
import {
  bindAllocatedSessionContainerIdV2,
  readSessionContainerRecordV2,
  removeExactSessionContainerRecordV2,
  sessionContainerLabels,
  sessionContainerRecordPath,
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2,
  writeSessionContainerRecordV2,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import {
  classifySessionContainerReconciliation,
  inspectSessionContainerInventory,
  type SessionContainerSnapshot,
  type SessionReconciliationClassification,
} from "./session-container-reconciliation.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { CaptureResult } from "./types.ts";

const CONTAINER_ID = "3".repeat(64);
const OTHER_CONTAINER_ID = "4".repeat(64);
const NETWORK: SessionContainerNetworkIdentity = Object.freeze({
  networkId: "8".repeat(64),
  networkName: `${SESSION_TEST_PROJECT.composeProject}_agent_internal`,
  subnet: "172.31.90.0/24",
});
const LIFECYCLE_LOCK: ProjectLifecycleLock = Object.freeze({
  ownerToken: "a".repeat(64),
  assertHeld: () => undefined,
  release: () => undefined,
});

function success(stdout = ""): CaptureResult {
  return { status: 0, stdout, stderr: "" };
}

function allocatedRecord(overrides: Partial<SessionContainerRecordV2> = {}): SessionContainerRecordV2 {
  return sessionContainerRecordFixture({
    overrides: {
      sessionIncarnation: "a".repeat(64),
      sessionPrincipal: "b".repeat(64),
      ...overrides,
    },
  });
}

function createdSnapshot(
  record: SessionContainerRecordV2,
  overrides: Partial<SessionContainerSnapshot> = {},
): SessionContainerSnapshot {
  return {
    containerId: CONTAINER_ID,
    containerName: record.containerName,
    imageId: record.selectedAgentImageId,
    labels: {
      ...sessionContainerLabels(record, "0.3.0"),
      [RUNFREE_IMAGE_ROLE_LABEL]: AGENT_PROJECT_IMAGE_ROLE,
      [RUNFREE_DIGEST_SCHEMA_LABEL]: RUNFREE_DIGEST_SCHEMA_VERSION,
      [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: record.selectedAgentImageInputDigest,
    },
    sourceIp: record.sourceIp,
    internalNetworkId: NETWORK.networkId,
    running: false,
    ...overrides,
  };
}

function inventoryInspection(snapshots: readonly SessionContainerSnapshot[]): string {
  return JSON.stringify(snapshots.map((snapshot) => ({
    Id: snapshot.containerId,
    Name: `/${snapshot.containerName}`,
    Image: snapshot.imageId,
    Config: { Labels: snapshot.labels },
    State: { Running: snapshot.running },
    NetworkSettings: {
      Networks: snapshot.sourceIp === undefined ? {} : {
        [NETWORK.networkName]: {
          NetworkID: snapshot.internalNetworkId ?? NETWORK.networkId,
          IPAddress: snapshot.sourceIp,
        },
      },
    },
  })));
}

function exactInventory(snapshots: readonly SessionContainerSnapshot[]): readonly SessionContainerSnapshot[] {
  return inspectSessionContainerInventory((_executable, args) => (
    args[1] === "ls"
      ? success(`${snapshots.map((snapshot) => snapshot.containerId).join("\n")}\n`)
      : success(inventoryInspection(snapshots))
  ), SESSION_TEST_PROJECT);
}

function classify(
  records: readonly SessionContainerRecordV2[],
  snapshots: readonly SessionContainerSnapshot[],
): SessionReconciliationClassification[] {
  return classifySessionContainerReconciliation({
    expectedProject: SESSION_TEST_PROJECT,
    records,
    containers: exactInventory(snapshots),
  });
}

function temporaryState(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "runfree-create-output-recovery-"));
}

describe("session create-success/output-lost recovery", () => {
  test("removes only the exact allocation record before fresh orphan cleanup", () => {
    const stateDir = temporaryState();
    const record = allocatedRecord();
    const snapshot = createdSnapshot(record);
    writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, record);

    const [classification] = classify([record], [snapshot]);
    expect(classification).toMatchObject({
      kind: "unbound-created",
      record: { sessionId: record.sessionId },
      container: { containerId: CONTAINER_ID, running: false },
    });
    if (classification?.kind !== "unbound-created") throw new Error("expected create-output recovery");
    expect(classification.record.containerId).toBeUndefined();
    const authority = authorizeUnboundCreatedSessionRecordRecovery(
      classification as SessionReconciliationClassification,
      SESSION_TEST_PROJECT,
    );

    expect(recoverUnboundCreatedSessionRecordV2(stateDir, SESSION_TEST_PROJECT, authority)).toBe(true);
    expect(readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, record.sessionId)).toBeUndefined();
    expect(recoverUnboundCreatedSessionRecordV2(stateDir, SESSION_TEST_PROJECT, authority)).toBe(false);

    const [fresh] = classify([], [snapshot]);
    expect(fresh?.kind).toBe("container-only");
    expect(() => authorizeSessionContainerOrphanCleanup(
      fresh,
      SESSION_TEST_PROJECT,
      NETWORK,
      stateDir,
      LIFECYCLE_LOCK,
    )).not.toThrow();
    expect(fs.existsSync(sessionContainerRecordPath(stateDir, record.sessionId))).toBe(false);
  });

  test("accepts a stopped exact container that has not acquired its network endpoint", () => {
    const record = allocatedRecord();
    const snapshot = createdSnapshot(record, { sourceIp: undefined, internalNetworkId: undefined });
    const [classification] = classify([record], [snapshot]);

    expect(classification?.kind).toBe("unbound-created");
    expect(() => authorizeUnboundCreatedSessionRecordRecovery(
      classification as SessionReconciliationClassification,
      SESSION_TEST_PROJECT,
    )).not.toThrow();
  });

  test("rejects plain, copied, and forged recovery authority before touching the record", () => {
    const stateDir = temporaryState();
    const record = allocatedRecord();
    const snapshot = createdSnapshot(record);
    writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, record);

    const [plain] = classifySessionContainerReconciliation({
      expectedProject: SESSION_TEST_PROJECT,
      records: [record],
      containers: [snapshot],
    });
    expect(plain?.kind).toBe("unbound-created");
    expect(() => authorizeUnboundCreatedSessionRecordRecovery(plain, SESSION_TEST_PROJECT))
      .toThrow("not minted from exact reconciliation");

    const [exact] = classify([record], [snapshot]);
    const copiedClassification = { ...exact } as SessionReconciliationClassification;
    expect(() => authorizeUnboundCreatedSessionRecordRecovery(copiedClassification, SESSION_TEST_PROJECT))
      .toThrow("not minted from exact reconciliation");

    const authority = authorizeUnboundCreatedSessionRecordRecovery(exact, SESSION_TEST_PROJECT);
    const forgedAuthority = { ...authority } as SessionContainerCreateOutputRecoveryAuthority;
    expect(() => recoverUnboundCreatedSessionRecordV2(
      stateDir,
      SESSION_TEST_PROJECT,
      forgedAuthority,
    )).toThrow("unsealed");
    expect(readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, record.sessionId)).toEqual(record);
  });

  test("rejects running, mismatched, bound, leased, and ambiguous candidates", () => {
    const base = allocatedRecord();
    const cases: Array<{
      name: string;
      record: SessionContainerRecordV2;
      snapshots: SessionContainerSnapshot[];
    }> = [
      { name: "running", record: base, snapshots: [createdSnapshot(base, { running: true })] },
      {
        name: "source IP",
        record: base,
        snapshots: [createdSnapshot(base, { sourceIp: "172.31.90.21" })],
      },
      {
        name: "incarnation",
        record: base,
        snapshots: [createdSnapshot(base, {
          labels: {
            ...createdSnapshot(base).labels,
            "io.runfree.session-incarnation": "c".repeat(64),
          },
        })],
      },
      {
        name: "materialization",
        record: base,
        snapshots: [createdSnapshot(base, {
          labels: {
            ...createdSnapshot(base).labels,
            "io.runfree.session-agent-materialization-digest": `sha256:${"d".repeat(64)}`,
          },
        })],
      },
      {
        name: "bound",
        record: bindAllocatedSessionContainerIdV2(base, CONTAINER_ID),
        snapshots: [createdSnapshot(base)],
      },
      {
        name: "leased",
        record: transitionBoundAllocatedSessionContainerToProvisioningRunningV2(
          bindAllocatedSessionContainerIdV2(base, CONTAINER_ID),
          {
            admittedAt: "2026-08-08T12:00:01.000Z",
            leaseGeneration: "e".repeat(64),
            leaseExpiresAt: "2026-08-08T12:01:01.000Z",
          },
        ),
        snapshots: [createdSnapshot(base)],
      },
      {
        name: "ambiguous",
        record: base,
        snapshots: [
          createdSnapshot(base),
          createdSnapshot(base, { containerId: OTHER_CONTAINER_ID }),
        ],
      },
    ];

    for (const scenario of cases) {
      const classifications = classify([scenario.record], scenario.snapshots);
      expect(
        classifications.some((classification) => classification.kind === "unbound-created"),
        scenario.name,
      ).toBe(false);
    }
  });

  test("refuses removal if the exact persisted allocation changed after authorization", () => {
    const stateDir = temporaryState();
    const record = allocatedRecord();
    const snapshot = createdSnapshot(record);
    const [classification] = classify([record], [snapshot]);
    const authority = authorizeUnboundCreatedSessionRecordRecovery(classification, SESSION_TEST_PROJECT);
    writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, record);
    expect(removeExactSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, record)).toBe(true);
    const replacement = allocatedRecord({ displayName: "replacement" });
    writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, replacement);

    expect(() => recoverUnboundCreatedSessionRecordV2(
      stateDir,
      SESSION_TEST_PROJECT,
      authority,
    )).toThrow("changed before removal");
    expect(readSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, record.sessionId)).toEqual(replacement);
  });
});
