import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, test, vi } from "vitest";

import {
  assertSessionContainerAbsenceReceipt,
  creationAuthorizedSessionContainerRemoveCommand,
  creationAuthorizedSessionContainerStopCommand,
  executeSessionContainerCleanupCommand,
  executeSessionContainerCreate,
  proveSessionContainerAbsent,
  removeAbsentSessionContainerRecordV2,
  type SessionContainerAbsenceReceipt,
  type SessionContainerCleanupCommand,
  type SessionContainerCleanupExecutor,
  type SessionContainerCreationReceipt,
  type SessionContainerNetworkIdentity,
} from "./session-container-cleanup.ts";
import {
  sessionContainerCreateCommand,
  type SessionDockerCommand,
} from "./session-container-docker.ts";
import {
  SESSION_TEST_PROJECT,
  sessionContainerCreatePlanFixture,
  sessionContainerRecordFixture,
} from "./session-container.test-harness.ts";
import {
  sessionNamedVolumeExpectations,
  validateSessionNamedVolumeInspect,
} from "./session-named-volume-proof.ts";
import type { SessionContainerCreatePlan } from "./session-container-template.ts";
import {
  bindAllocatedSessionContainerIdV2,
  readSessionContainerRecordV2,
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2,
  type SessionContainerRecordV2,
  writeSessionContainerRecordV2,
} from "./session-containers.ts";
import type { CaptureResult } from "./types.ts";

const CONTAINER_ID = "3".repeat(64);
const OTHER_CONTAINER_ID = "4".repeat(64);
const NETWORK: SessionContainerNetworkIdentity = Object.freeze({
  networkId: "8".repeat(64),
  networkName: `${SESSION_TEST_PROJECT.composeProject}_agent_internal`,
  subnet: "172.31.90.0/24",
});

function success(stdout = ""): CaptureResult {
  return { status: 0, stdout, stderr: "" };
}

function namedVolumeProof(plan: SessionContainerCreatePlan) {
  const inspection = sessionNamedVolumeExpectations(plan).map((expected) => ({
    CreatedAt: "2026-08-08T11:59:00.000Z",
    Driver: "local",
    Labels: {
      "com.docker.compose.config-hash": `sha256:${"f".repeat(64)}`,
      "com.docker.compose.project": SESSION_TEST_PROJECT.composeProject,
      "com.docker.compose.version": "2.39.1",
      "com.docker.compose.volume": expected.logicalName,
    },
    Mountpoint: `/var/lib/docker/volumes/${expected.name}/_data`,
    Name: expected.name,
    Options: null,
    Scope: "local",
  }));
  return validateSessionNamedVolumeInspect(JSON.stringify(inspection), plan);
}

function allocatedRecord(marker = "a", sourceIp = "172.31.90.20"): SessionContainerRecordV2 {
  return sessionContainerRecordFixture({
    overrides: {
      sessionIncarnation: marker.repeat(64),
      sessionPrincipal: (marker === "a" ? "c" : "d").repeat(64),
      sourceIp,
    },
  });
}

function createAuthority(input: {
  containerId?: string;
  record?: SessionContainerRecordV2;
} = {}): {
  plan: SessionContainerCreatePlan;
  record: SessionContainerRecordV2;
  receipt: SessionContainerCreationReceipt;
} {
  const containerId = input.containerId ?? CONTAINER_ID;
  const plan = sessionContainerCreatePlanFixture({ record: input.record ?? allocatedRecord() });
  const command = sessionContainerCreateCommand(plan, namedVolumeProof(plan));
  const result = executeSessionContainerCreate(command, plan, () => success(`${containerId}\n`));
  return {
    plan,
    record: bindAllocatedSessionContainerIdV2(plan.record, result.containerId),
    receipt: result.receipt,
  };
}

function networkInspection(
  containers: Record<string, { Name: string; IPv4Address: string }> = {},
  overrides: Partial<{ Id: string; Name: string }> = {},
): string {
  return JSON.stringify([{
    Id: overrides.Id ?? NETWORK.networkId,
    Name: overrides.Name ?? NETWORK.networkName,
    Containers: containers,
  }]);
}

function absenceExecutor(input: {
  containerResult?: CaptureResult;
  networkResult?: CaptureResult;
} = {}): { executor: SessionContainerCleanupExecutor; calls: string[][] } {
  const calls: string[][] = [];
  const executor: SessionContainerCleanupExecutor = (_executable, args) => {
    calls.push([...args]);
    return args[0] === "container"
      ? input.containerResult ?? success()
      : input.networkResult ?? success(networkInspection({
        [OTHER_CONTAINER_ID]: {
          Name: "runfree-proxy",
          IPv4Address: "172.31.90.10/24",
        },
      }));
  };
  return { executor, calls };
}

describe("pre-admission session-container cleanup authority", () => {
  test("mints creation authority only from the sealed create command and exact Docker id", () => {
    const plan = sessionContainerCreatePlanFixture({ record: allocatedRecord() });
    const command = sessionContainerCreateCommand(plan, namedVolumeProof(plan));
    const calls: Array<{ args: readonly string[]; options: unknown }> = [];
    const executor: SessionContainerCleanupExecutor = (_executable, args, options) => {
      calls.push({ args, options });
      return success(`${CONTAINER_ID}\n`);
    };

    const created = executeSessionContainerCreate(command, plan, executor, { cwd: "/trusted" });
    const bound = bindAllocatedSessionContainerIdV2(plan.record, created.containerId);

    expect(created.containerId).toBe(CONTAINER_ID);
    expect(created.receipt).toMatchObject({
      containerId: CONTAINER_ID,
      sessionId: plan.record.sessionId,
      sessionIncarnation: plan.record.sessionIncarnation,
    });
    expect(() => creationAuthorizedSessionContainerStopCommand(
      bound,
      SESSION_TEST_PROJECT,
      created.receipt,
    )).not.toThrow();
    expect(calls).toEqual([{ args: command.args, options: { cwd: "/trusted" } }]);
  });

  test("fails create closed for forged authority, daemon errors, malformed ids, and oversized output", () => {
    const plan = sessionContainerCreatePlanFixture({ record: allocatedRecord() });
    const command = sessionContainerCreateCommand(plan, namedVolumeProof(plan));
    const forged = { ...command } as SessionDockerCommand;
    const otherPlan = sessionContainerCreatePlanFixture({ record: allocatedRecord("b", "172.31.90.21") });
    const neverCalled = vi.fn(() => success(`${CONTAINER_ID}\n`));

    expect(() => executeSessionContainerCreate(forged, plan, neverCalled)).toThrow("unsealed");
    expect(() => executeSessionContainerCreate(command, otherPlan, neverCalled)).toThrow("mismatched");
    expect(neverCalled).not.toHaveBeenCalled();

    for (const result of [
      { status: 1, stdout: "", stderr: "daemon unavailable" },
      success("short-id\n"),
      success(`${CONTAINER_ID}\n${OTHER_CONTAINER_ID}\n`),
      success("x".repeat(4097)),
    ]) {
      expect(() => executeSessionContainerCreate(command, plan, () => result)).toThrow();
    }
  });

  test("authorizes exact stop/remove commands only for the exact sealed creation", () => {
    const first = createAuthority();
    const second = createAuthority({
      containerId: OTHER_CONTAINER_ID,
      record: allocatedRecord("b", "172.31.90.21"),
    });
    const stop = creationAuthorizedSessionContainerStopCommand(
      first.record,
      SESSION_TEST_PROJECT,
      first.receipt,
    );
    const remove = creationAuthorizedSessionContainerRemoveCommand(
      first.record,
      SESSION_TEST_PROJECT,
      first.receipt,
    );
    const calls: string[][] = [];
    const executor: SessionContainerCleanupExecutor = (_executable, args) => {
      calls.push([...args]);
      return success();
    };

    expect(executeSessionContainerCleanupCommand(stop, executor).status).toBe(0);
    expect(executeSessionContainerCleanupCommand(remove, executor).status).toBe(0);
    expect(calls).toEqual([
      ["container", "stop", "--time", "10", CONTAINER_ID],
      ["container", "rm", CONTAINER_ID],
    ]);
    expect(stop.exactTarget).toBe(CONTAINER_ID);
    expect(remove.exactTarget).toBe(CONTAINER_ID);
    expect(remove.args).not.toContain("--force");

    const forgedReceipt = { ...first.receipt } as SessionContainerCreationReceipt;
    const destructiveExecutor = vi.fn(() => success());
    const attempts = [
      () => executeSessionContainerCleanupCommand(
        creationAuthorizedSessionContainerRemoveCommand(first.record, SESSION_TEST_PROJECT, forgedReceipt),
        destructiveExecutor,
      ),
      () => executeSessionContainerCleanupCommand(
        creationAuthorizedSessionContainerStopCommand(first.record, SESSION_TEST_PROJECT, second.receipt),
        destructiveExecutor,
      ),
      () => executeSessionContainerCleanupCommand(
        creationAuthorizedSessionContainerRemoveCommand(second.record, SESSION_TEST_PROJECT, first.receipt),
        destructiveExecutor,
      ),
      () => executeSessionContainerCleanupCommand({
        executable: "docker",
        args: ["container", "rm", "attacker-selected"],
        effect: "remove-creation-authorized-session-container",
        exactTarget: "attacker-selected",
      } as unknown as SessionContainerCleanupCommand, destructiveExecutor),
    ];

    for (const attempt of attempts) expect(attempt).toThrow();
    expect(destructiveExecutor).not.toHaveBeenCalled();
  });

  test("retains exact creation authority across the same lifecycle incarnation", () => {
    const created = createAuthority();
    const provisioning = transitionBoundAllocatedSessionContainerToProvisioningRunningV2(created.record, {
      admittedAt: "2026-08-08T12:00:01.000Z",
      leaseGeneration: "e".repeat(32),
      leaseExpiresAt: "2026-08-08T12:05:00.000Z",
    });
    const stop = creationAuthorizedSessionContainerStopCommand(
      provisioning,
      SESSION_TEST_PROJECT,
      created.receipt,
    );
    const remove = creationAuthorizedSessionContainerRemoveCommand(
      provisioning,
      SESSION_TEST_PROJECT,
      created.receipt,
    );
    const calls: string[][] = [];
    const executor: SessionContainerCleanupExecutor = (_executable, args) => {
      calls.push([...args]);
      return success();
    };

    executeSessionContainerCleanupCommand(stop, executor);
    executeSessionContainerCleanupCommand(remove, executor);

    expect(calls).toEqual([
      ["container", "stop", "--time", "10", CONTAINER_ID],
      ["container", "rm", CONTAINER_ID],
    ]);
    expect(remove.args).not.toContain("--force");
  });

  test("rejects creation-authorized cleanup for a forged receipt or different incarnation", () => {
    const first = createAuthority();
    const second = createAuthority({
      containerId: OTHER_CONTAINER_ID,
      record: allocatedRecord("b", "172.31.90.21"),
    });
    const provisioning = transitionBoundAllocatedSessionContainerToProvisioningRunningV2(first.record, {
      admittedAt: "2026-08-08T12:00:01.000Z",
      leaseGeneration: "e".repeat(32),
      leaseExpiresAt: "2026-08-08T12:05:00.000Z",
    });
    const forged = { ...first.receipt } as SessionContainerCreationReceipt;
    const executor = vi.fn(() => success());

    for (const attempt of [
      () => creationAuthorizedSessionContainerStopCommand(provisioning, SESSION_TEST_PROJECT, forged),
      () => creationAuthorizedSessionContainerRemoveCommand(provisioning, SESSION_TEST_PROJECT, second.receipt),
      () => creationAuthorizedSessionContainerRemoveCommand(second.record, SESSION_TEST_PROJECT, first.receipt),
    ]) {
      expect(attempt).toThrow();
    }
    expect(executor).not.toHaveBeenCalled();
  });
});

describe("session-container absence proof", () => {
  test("mints exact absence authority only after both Docker observations agree", () => {
    const { record } = createAuthority();
    const { executor, calls } = absenceExecutor();

    const receipt = proveSessionContainerAbsent(
      executor,
      record,
      SESSION_TEST_PROJECT,
      NETWORK,
      { cwd: "/trusted" },
    );

    expect(receipt).toMatchObject({
      containerId: CONTAINER_ID,
      sourceIp: record.sourceIp,
      networkId: NETWORK.networkId,
    });
    expect(() => assertSessionContainerAbsenceReceipt(
      receipt,
      record,
      SESSION_TEST_PROJECT,
      NETWORK,
    )).not.toThrow();
    expect(calls).toEqual([
      [
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--filter",
        `id=${CONTAINER_ID}`,
        "--format",
        "{{.ID}}",
      ],
      ["network", "inspect", NETWORK.networkId],
    ]);
  });

  test("does not inspect the network when the container observation is inconclusive", () => {
    const { record } = createAuthority();
    for (const containerResult of [
      { status: 1, stdout: "", stderr: "daemon unavailable" },
      success(`${CONTAINER_ID}\n`),
      success(`${OTHER_CONTAINER_ID}\n`),
      success("x".repeat(4097)),
    ]) {
      const { executor, calls } = absenceExecutor({ containerResult });
      expect(() => proveSessionContainerAbsent(
        executor,
        record,
        SESSION_TEST_PROJECT,
        NETWORK,
      )).toThrow();
      expect(calls).toHaveLength(1);
      expect(calls[0]?.slice(0, 2)).toEqual(["container", "ls"]);
    }
  });

  test("rejects daemon, malformed, oversized, and wrong-network inspection results", () => {
    const { record } = createAuthority();
    const failures = [
      { status: 1, stdout: "", stderr: "daemon unavailable" },
      success("not-json"),
      success("x".repeat(512 * 1024 + 1)),
      success(networkInspection({}, { Id: "9".repeat(64) })),
      success(networkInspection({}, { Name: "attacker-network" })),
    ];

    for (const networkResult of failures) {
      const { executor, calls } = absenceExecutor({ networkResult });
      expect(() => proveSessionContainerAbsent(
        executor,
        record,
        SESSION_TEST_PROJECT,
        NETWORK,
      )).toThrow();
      expect(calls).toHaveLength(2);
      expect(calls.every((args) => !args.includes("stop") && !args.includes("rm"))).toBe(true);
    }
  });

  test("rejects contradictory attachment ownership by exact container id or source IP", () => {
    const { record } = createAuthority();
    const contradictions = [
      networkInspection({
        [CONTAINER_ID]: {
          Name: "different-name",
          IPv4Address: "172.31.90.30/24",
        },
      }),
      networkInspection({
        [OTHER_CONTAINER_ID]: {
          Name: "different-container",
          IPv4Address: `${record.sourceIp}/24`,
        },
      }),
    ];

    for (const stdout of contradictions) {
      const { executor, calls } = absenceExecutor({ networkResult: success(stdout) });
      expect(() => proveSessionContainerAbsent(
        executor,
        record,
        SESSION_TEST_PROJECT,
        NETWORK,
      )).toThrow("still owns");
      expect(calls).toHaveLength(2);
    }
  });

  test("removes only the exact persisted record authorized by a sealed absence receipt", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-session-cleanup-"));
    const first = createAuthority();
    const second = createAuthority({
      containerId: OTHER_CONTAINER_ID,
      record: allocatedRecord("b", "172.31.90.21"),
    });
    writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, first.record);
    const receipt = proveSessionContainerAbsent(
      absenceExecutor().executor,
      first.record,
      SESSION_TEST_PROJECT,
      NETWORK,
    );
    const forged = { ...receipt } as SessionContainerAbsenceReceipt;
    const wrongNetwork = { ...NETWORK, networkId: "9".repeat(64) };

    const attempts = [
      () => removeAbsentSessionContainerRecordV2(
        stateDir,
        SESSION_TEST_PROJECT,
        first.record,
        NETWORK,
        forged,
      ),
      () => removeAbsentSessionContainerRecordV2(
        stateDir,
        SESSION_TEST_PROJECT,
        second.record,
        NETWORK,
        receipt,
      ),
      () => removeAbsentSessionContainerRecordV2(
        stateDir,
        SESSION_TEST_PROJECT,
        first.record,
        wrongNetwork,
        receipt,
      ),
    ];
    for (const attempt of attempts) {
      expect(attempt).toThrow();
      expect(readSessionContainerRecordV2(
        stateDir,
        SESSION_TEST_PROJECT,
        first.record.sessionId,
      )).toEqual(first.record);
    }

    expect(removeAbsentSessionContainerRecordV2(
      stateDir,
      SESSION_TEST_PROJECT,
      first.record,
      NETWORK,
      receipt,
    )).toBe(true);
    expect(readSessionContainerRecordV2(
      stateDir,
      SESSION_TEST_PROJECT,
      first.record.sessionId,
    )).toBeUndefined();
  });
});
