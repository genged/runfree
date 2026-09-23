import { EventEmitter } from "node:events";
import type { SpawnOptions } from "node:child_process";

import { beforeAll, describe, expect, test, vi } from "vitest";

import { sessionContainerStartAttachCommand } from "./session-container-docker.ts";
import { authorizeProvisioningRunningSessionContainer } from "./session-container-lifecycle-authorization.ts";
import {
  validateSessionContainerInspect,
  type SessionContainerProof,
} from "./session-container-proof.ts";
import { waitForRunningSessionContainerProof } from "./session-container-running-proof.ts";
import { startSessionContainerForeground } from "./session-container-start.ts";
import {
  sessionContainerCreatePlanFixture,
  sessionContainerInspectJsonFixture,
  sessionContainerRecordFixture,
  sessionContainerTemplateFixture,
  SESSION_TEST_PROJECT,
} from "./session-container.test-harness.ts";
import {
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";

const NETWORK_ID = "8".repeat(64);
const WRONG_NETWORK_ID = "f".repeat(64);
const LEASE = Object.freeze({
  admittedAt: "2026-08-08T12:00:01.000Z",
  leaseGeneration: "e".repeat(32),
  leaseExpiresAt: "2026-08-08T12:05:00.000Z",
});
const WRONG_PROJECT: SessionContainerProjectIdentity = Object.freeze({
  projectId: "abcdef012345",
  composeProject: "runfree-abcdef012345",
});

type LifecycleAuthorityFixture = Readonly<{
  allocated: SessionContainerRecordV2;
  provisioning: SessionContainerRecordV2;
  liveProof: SessionContainerProof;
  wrongPhaseProof: SessionContainerProof;
  foregroundReceipt: Awaited<ReturnType<typeof startSessionContainerForeground>>["receipt"];
}>;

function recordFixture(marker: "a" | "b", containerId: string): SessionContainerRecordV2 {
  const principalMarker = marker === "a" ? "c" : "d";
  return sessionContainerRecordFixture({
    containerId,
    overrides: {
      sessionIncarnation: marker.repeat(64),
      sessionPrincipal: principalMarker.repeat(64),
    },
  });
}

async function authorityFixture(marker: "a" | "b", containerId: string): Promise<LifecycleAuthorityFixture> {
  const allocated = recordFixture(marker, containerId);
  const preliminaryPlan = sessionContainerCreatePlanFixture({ record: allocated });
  const template = sessionContainerTemplateFixture();
  const provisioning = transitionBoundAllocatedSessionContainerToProvisioningRunningV2(allocated, LEASE);
  const provisioningPlan = sessionContainerCreatePlanFixture({
    record: provisioning,
    template,
    target: preliminaryPlan.generationTarget,
    generation: preliminaryPlan.sessionAgentGeneration,
  });
  const command = sessionContainerStartAttachCommand(provisioning, SESSION_TEST_PROJECT);
  const child = Object.assign(new EventEmitter(), {
    pid: marker === "a" ? 4242 : 4343,
    exitCode: null,
    signalCode: null,
    kill: vi.fn(() => true),
  });
  const handle = await startSessionContainerForeground(
    command,
    provisioning,
    SESSION_TEST_PROJECT,
    {
      dockerClientEnv: { PATH: "/usr/local/bin:/usr/bin:/bin" },
      spawn: (_executable: string, _args: readonly string[], _options: SpawnOptions) => {
        queueMicrotask(() => child.emit("spawn"));
        return child;
      },
    },
  );
  const runningInspectSource = sessionContainerInspectJsonFixture(provisioningPlan, { running: true });
  const liveProof = await waitForRunningSessionContainerProof(
    () => ({ status: 0, stdout: runningInspectSource, stderr: "" }),
    provisioningPlan,
    handle,
    { nowMs: () => 0, delay: async () => {} },
  );
  // The same inspection judged for the wrong lifecycle phase: a proof that is
  // valid bytes but names an authority this transition may not spend.
  const wrongPhaseProof = validateSessionContainerInspect(
    runningInspectSource,
    provisioningPlan,
    { kind: "active-running" },
  );
  return { allocated, provisioning, liveProof, wrongPhaseProof, foregroundReceipt: handle.receipt };
}

describe("session-container lifecycle authorization", () => {
  let first: LifecycleAuthorityFixture;
  let second: LifecycleAuthorityFixture;

  beforeAll(async () => {
    [first, second] = await Promise.all([
      authorityFixture("a", "3".repeat(64)),
      authorityFixture("b", "4".repeat(64)),
    ]);
  });

  test("authorizes provisioning-running from exact sealed external authority", () => {
    expect(authorizeProvisioningRunningSessionContainer(
      first.provisioning,
      SESSION_TEST_PROJECT,
      NETWORK_ID,
      first.foregroundReceipt,
      first.liveProof,
    ).record).toEqual(first.provisioning);
  });

  test("rejects forged or mismatched start and live authority for provisioning-running", () => {
    const forgedReceipt = { ...first.foregroundReceipt } as typeof first.foregroundReceipt;
    const forgedProof = { ...first.liveProof } as SessionContainerProof;
    const cases = [
      () => authorizeProvisioningRunningSessionContainer(first.allocated, SESSION_TEST_PROJECT, NETWORK_ID, first.foregroundReceipt, first.liveProof),
      () => authorizeProvisioningRunningSessionContainer(first.provisioning, SESSION_TEST_PROJECT, NETWORK_ID, forgedReceipt, first.liveProof),
      () => authorizeProvisioningRunningSessionContainer(first.provisioning, SESSION_TEST_PROJECT, NETWORK_ID, second.foregroundReceipt, first.liveProof),
      () => authorizeProvisioningRunningSessionContainer(first.provisioning, SESSION_TEST_PROJECT, NETWORK_ID, first.foregroundReceipt, forgedProof),
      () => authorizeProvisioningRunningSessionContainer(first.provisioning, SESSION_TEST_PROJECT, NETWORK_ID, first.foregroundReceipt, second.liveProof),
      () => authorizeProvisioningRunningSessionContainer(first.provisioning, SESSION_TEST_PROJECT, NETWORK_ID, first.foregroundReceipt, first.wrongPhaseProof),
      () => authorizeProvisioningRunningSessionContainer(first.provisioning, SESSION_TEST_PROJECT, WRONG_NETWORK_ID, first.foregroundReceipt, first.liveProof),
      () => authorizeProvisioningRunningSessionContainer(first.provisioning, WRONG_PROJECT, NETWORK_ID, first.foregroundReceipt, first.liveProof),
    ];

    for (const candidate of cases) expect(candidate).toThrow();
  });
});
