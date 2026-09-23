import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import {
  AGENT_PROJECT_IMAGE_ROLE,
  RUNFREE_DIGEST_SCHEMA_LABEL,
  RUNFREE_DIGEST_SCHEMA_VERSION,
  RUNFREE_IMAGE_INPUT_DIGEST_LABEL,
  RUNFREE_IMAGE_ROLE_LABEL,
} from "./constants.ts";
import {
  assertSessionContainerOrphanAbsenceReceipt,
  authorizeSessionContainerOrphanCleanup,
  executeSessionContainerCleanupCommand,
  orphanSessionContainerRemoveCommand,
  orphanSessionContainerStopCommand,
  proveSessionContainerOrphanAbsent,
  type SessionContainerCleanupCommand,
  type SessionContainerCleanupExecutor,
  type SessionContainerNetworkIdentity,
  type SessionContainerOrphanAbsenceReceipt,
  type SessionContainerOrphanCleanupAuthority,
} from "./session-container-cleanup.ts";
import {
  SESSION_TEST_PROJECT,
  sessionContainerRecordFixture,
} from "./session-container.test-harness.ts";
import {
  SESSION_CONTAINER_LABELS,
  sessionContainerLabels,
  sessionContainerQuarantineRoot,
  sessionContainerRecordsRoot,
  writeSessionContainerRecordV2,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import {
  classifySessionContainerReconciliation,
  inspectSessionContainerInventory,
  verifiedSessionContainerIdentity,
  type SessionContainerSnapshot,
  type SessionReconciliationClassification,
} from "./session-container-reconciliation.ts";
import type { CaptureResult } from "./types.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";

const CONTAINER_ID = "3".repeat(64);
const OTHER_CONTAINER_ID = "4".repeat(64);
const NETWORK: SessionContainerNetworkIdentity = Object.freeze({
  networkId: "8".repeat(64),
  networkName: `${SESSION_TEST_PROJECT.composeProject}_agent_internal`,
  subnet: "172.31.90.0/24",
});
const WRONG_PROJECT: SessionContainerProjectIdentity = Object.freeze({
  projectId: "abcdefabcdef",
  composeProject: "runfree-abcdefabcdef",
});
const LIFECYCLE_LOCK: ProjectLifecycleLock = {
  ownerToken: "a".repeat(64),
  assertHeld: vi.fn(),
  release: vi.fn(),
};
let stateDir: string;

beforeEach(() => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-session-orphan-"));
});

afterEach(() => {
  fs.rmSync(stateDir, { recursive: true, force: true });
});

function success(stdout = ""): CaptureResult {
  return { status: 0, stdout, stderr: "" };
}

function orphanRecord(): SessionContainerRecordV2 {
  return sessionContainerRecordFixture({
    overrides: {
      sessionIncarnation: "a".repeat(64),
      sessionPrincipal: "b".repeat(64),
    },
  });
}

function orphanSnapshot(overrides: Partial<SessionContainerSnapshot> = {}): SessionContainerSnapshot {
  const record = orphanRecord();
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
    running: false,
    ...overrides,
  };
}

function inventoryInspection(snapshot: SessionContainerSnapshot): string {
  return JSON.stringify([{
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
  }]);
}

function inventoryIds(count: number): readonly string[] {
  return Array.from({ length: count }, (_unused, index) => index.toString(16).padStart(64, "0"));
}

/** A container the project does not own: enough shape to parse, no session labels. */
function foreignSnapshotFor(containerId: string): SessionContainerSnapshot {
  return {
    containerId,
    containerName: `foreign-${containerId.slice(0, 12)}`,
    imageId: `sha256:${"e".repeat(64)}`,
    labels: {},
    running: false,
  };
}

function inventoryInspectionMany(snapshots: readonly SessionContainerSnapshot[]): string {
  return JSON.stringify(snapshots.map((snapshot) => JSON.parse(inventoryInspection(snapshot))[0]));
}

function orphanClassification(
  snapshot: SessionContainerSnapshot = orphanSnapshot(),
): Extract<SessionReconciliationClassification, { kind: "container-only" }> {
  const inventory = inspectSessionContainerInventory((_, args) => {
    if (args[1] === "ls") return success(`${snapshot.containerId}\n`);
    return success(inventoryInspection(snapshot));
  }, SESSION_TEST_PROJECT);
  const [classification] = classifySessionContainerReconciliation({
    expectedProject: SESSION_TEST_PROJECT,
    records: [],
    containers: inventory,
  });
  if (classification?.kind !== "container-only") {
    throw new Error(`fixture did not produce a container-only classification: ${classification?.kind ?? "missing"}`);
  }
  return classification;
}

function authority(
  classification: SessionReconciliationClassification = orphanClassification(),
): SessionContainerOrphanCleanupAuthority {
  return authorizeSessionContainerOrphanCleanup(
    classification,
    SESSION_TEST_PROJECT,
    NETWORK,
    stateDir,
    LIFECYCLE_LOCK,
  );
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
      : input.networkResult ?? success(networkInspection());
  };
  return { executor, calls };
}

describe("container-only session orphan cleanup", () => {
  test("takes a bounded all-ID inventory and inspects only those exact Docker ids", () => {
    const snapshot = orphanSnapshot();
    const calls: Array<{ args: readonly string[]; options: unknown }> = [];
    const inventory = inspectSessionContainerInventory((_executable, args, options) => {
      calls.push({ args: [...args], options });
      return args[1] === "ls"
        ? success(`${CONTAINER_ID}\n`)
        : success(inventoryInspection(snapshot));
    }, SESSION_TEST_PROJECT, { cwd: "/trusted" });

    expect(inventory).toHaveLength(1);
    expect(inventory[0]).toMatchObject({
      containerId: CONTAINER_ID,
      internalNetworkId: NETWORK.networkId,
      sourceIp: orphanRecord().sourceIp,
    });
    expect(calls).toEqual([
      {
        args: ["container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}"],
        options: { cwd: "/trusted", maxBuffer: 8 * 1024 * 1024 },
      },
      {
        args: ["container", "inspect", CONTAINER_ID],
        options: { cwd: "/trusted", maxBuffer: 8 * 1024 * 1024 },
      },
    ]);
    const [classification] = classifySessionContainerReconciliation({
      expectedProject: SESSION_TEST_PROJECT,
      records: [],
      containers: inventory,
    });
    expect(() => authorizeSessionContainerOrphanCleanup(
      classification as SessionReconciliationClassification,
      SESSION_TEST_PROJECT,
      NETWORK,
      stateDir,
      LIFECYCLE_LOCK,
    )).not.toThrow();
  });

  test("re-lists and retries once when an unrelated container disappears during inspection", () => {
    const target = orphanSnapshot();
    const squatterId = "5".repeat(64);
    const newlyListedSquatter = {
      Id: squatterId,
      Name: `/runfree-${SESSION_TEST_PROJECT.projectId}-session-rf-20260809-racer1`,
      Image: "attacker/image:latest",
      Config: { Labels: {} },
      State: { Running: false },
      NetworkSettings: { Networks: {} },
    };
    let listCalls = 0;
    let inspectCalls = 0;
    const calls: string[][] = [];
    const inventory = inspectSessionContainerInventory((_executable, args) => {
      calls.push([...args]);
      if (args[1] === "ls") {
        listCalls += 1;
        return success(listCalls === 1
          ? `${CONTAINER_ID}\n${OTHER_CONTAINER_ID}\n`
          : `${CONTAINER_ID}\n${squatterId}\n`);
      }
      inspectCalls += 1;
      return inspectCalls === 1
        ? { status: 1, stdout: "", stderr: `Error: No such object: ${OTHER_CONTAINER_ID}` }
        : success(JSON.stringify([
            JSON.parse(inventoryInspection(target))[0],
            newlyListedSquatter,
          ]));
    }, SESSION_TEST_PROJECT);

    expect(inventory).toHaveLength(2);
    expect(inventory[0]?.containerId).toBe(CONTAINER_ID);
    expect(calls).toEqual([
      ["container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}"],
      ["container", "inspect", CONTAINER_ID, OTHER_CONTAINER_ID],
      ["container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}"],
      ["container", "inspect", CONTAINER_ID, squatterId],
    ]);
    const classifications = classifySessionContainerReconciliation({
      expectedProject: SESSION_TEST_PROJECT,
      records: [],
      containers: inventory,
    });
    expect(classifications.map(({ kind }) => kind)).toEqual(["container-only", "untrusted-container"]);
    expect(() => authority(classifications[0])).not.toThrow();
  });

  test("turns a disappeared recorded project container into record-only without orphan authority", () => {
    const record = sessionContainerRecordFixture({
      containerId: CONTAINER_ID,
      overrides: {
        sessionIncarnation: "a".repeat(64),
        sessionPrincipal: "b".repeat(64),
      },
    });
    const foreign = {
      Id: OTHER_CONTAINER_ID,
      Name: "/unrelated-survivor",
      Image: `sha256:${"f".repeat(64)}`,
      Config: { Labels: {} },
      State: { Running: false },
      NetworkSettings: { Networks: {} },
    };
    let listCalls = 0;
    let inspectCalls = 0;
    const inventory = inspectSessionContainerInventory((_executable, args) => {
      if (args[1] === "ls") {
        listCalls += 1;
        return success(listCalls === 1
          ? `${CONTAINER_ID}\n${OTHER_CONTAINER_ID}\n`
          : `${OTHER_CONTAINER_ID}\n`);
      }
      inspectCalls += 1;
      return inspectCalls === 1
        ? { status: 1, stdout: "", stderr: `Error: No such object: ${CONTAINER_ID}` }
        : success(JSON.stringify([foreign]));
    }, SESSION_TEST_PROJECT);
    const classifications = classifySessionContainerReconciliation({
      expectedProject: SESSION_TEST_PROJECT,
      records: [record],
      containers: inventory,
    });

    expect(classifications).toEqual([{ kind: "record-only", record }]);
    expect(() => authorizeSessionContainerOrphanCleanup(
      classifications[0],
      SESSION_TEST_PROJECT,
      NETWORK,
      stateDir,
      LIFECYCLE_LOCK,
    )).toThrow("not minted from exact reconciliation");
  });

  test("refuses orphan authorization for a record quarantined by its own registry scan", () => {
    // The guard must hold even when the unreadable record is discovered by the
    // authorization's own enumeration: checking quarantine only before listing
    // would certify the freshly shrunk registry as exact.
    const recordsRoot = sessionContainerRecordsRoot(stateDir);
    fs.mkdirSync(recordsRoot, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(recordsRoot, "rf-20260814-zz9999.json"), "{", { mode: 0o600 });

    expect(() => authority()).toThrow("partially legible lifecycle registry");
  });

  test("refuses orphan authorization while quarantined unreadable records exist", () => {
    // An orphan claim proves that no record claims the container. With part of
    // the registry quarantined that proof is unavailable: the quarantined
    // record may be exactly the claim, so authorization must fail closed
    // instead of treating its container as removable.
    const quarantineRoot = sessionContainerQuarantineRoot(stateDir);
    fs.mkdirSync(quarantineRoot, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(quarantineRoot, "rf-20260814-zz9999.json"), "{", { mode: 0o600 });

    expect(() => authority()).toThrow("partially legible lifecycle registry");
  });

  test("fails closed without an unbounded retry when inspection identity remains uncertain", () => {
    let listCalls = 0;
    let inspectCalls = 0;
    const stableIdentityFailure = (_executable: "docker", args: readonly string[]): CaptureResult => {
      if (args[1] === "ls") {
        listCalls += 1;
        return success(`${CONTAINER_ID}\n`);
      }
      inspectCalls += 1;
      return { status: 1, stdout: "", stderr: "daemon inspection failure" };
    };
    // A fresh list still shows every refused id, so nothing churned and the
    // failure is the daemon's: fail closed without asking it the same thing.
    expect(() => inspectSessionContainerInventory(stableIdentityFailure, SESSION_TEST_PROJECT))
      .toThrow("could not inspect the exact session-container inventory");
    expect({ listCalls, inspectCalls }).toEqual({ listCalls: 1, inspectCalls: 1 });

    listCalls = 0;
    inspectCalls = 0;
    const repeatedChurn = (_executable: "docker", args: readonly string[]): CaptureResult => {
      if (args[1] === "ls") {
        listCalls += 1;
        return success(listCalls === 1
          ? `${CONTAINER_ID}\n${OTHER_CONTAINER_ID}\n`
          : `${CONTAINER_ID}\n`);
      }
      inspectCalls += 1;
      return { status: 1, stdout: "", stderr: `Error response from daemon: No such container: ${OTHER_CONTAINER_ID}` };
    };
    // The churned id is dropped on the fresh list's authority; the survivor is
    // still uninspectable, which is a stable failure for that id.
    expect(() => inspectSessionContainerInventory(repeatedChurn, SESSION_TEST_PROJECT))
      .toThrow("could not inspect the exact session-container inventory");
    expect({ listCalls, inspectCalls }).toEqual({ listCalls: 2, inspectCalls: 2 });
  });

  test("trusts the daemon over the list when a listed container reports as absent", () => {
    // Observed live: `container ls --all` still reported an id that
    // `container inspect` answered with "No such container". Inferring
    // existence from the list therefore misreads a departure as a daemon
    // failure and refuses the launch. The daemon's own reply is the authority.
    const ids = inventoryIds(3);
    const departing = ids[1];
    let listCalls = 0;
    const listedButGone = (_executable: "docker", args: readonly string[]): CaptureResult => {
      if (args[1] === "ls") {
        listCalls += 1;
        // Both lists still report every id, including the departing one.
        return success(`${ids.join("\n")}\n`);
      }
      const requested = args.slice(2);
      if (requested.includes(departing)) {
        return { status: 1, stdout: "", stderr: `Error response from daemon: No such container: ${departing}` };
      }
      return success(inventoryInspectionMany(requested.map(foreignSnapshotFor)));
    };

    const inventory = inspectSessionContainerInventory(listedButGone, SESSION_TEST_PROJECT);

    expect(inventory.map((container) => container.containerId).sort())
      .toEqual(ids.filter((id) => id !== departing).sort());
    expect(listCalls).toBe(2);
  });

  test("fails closed when a refusal names no missing container", () => {
    // An unreachable daemon, a timeout, or a buffer overrun is not churn.
    // Nothing is dropped and nothing is retried against the same ids.
    let inspectCalls = 0;
    const opaqueFailure = (_executable: "docker", args: readonly string[]): CaptureResult => {
      if (args[1] === "ls") return success(`${inventoryIds(2).join("\n")}\n`);
      inspectCalls += 1;
      return { status: 1, stdout: "", stderr: "Cannot connect to the Docker daemon at unix:///var/run/docker.sock." };
    };

    expect(() => inspectSessionContainerInventory(opaqueFailure, SESSION_TEST_PROJECT))
      .toThrow("Cannot connect to the Docker daemon");
    expect(inspectCalls).toBe(1);
  });

  test("repairs a churned chunk without re-inspecting chunks that already succeeded", () => {
    // The defect this pins: a single churn event anywhere used to discard every
    // chunk's work and re-inspect the whole host inventory, so a second churn
    // event in an already-inspected region failed the launch closed. Re-running
    // a successful inspection re-opens its window for no gain; the repair must
    // touch only what actually failed.
    const ids = inventoryIds(70);
    const vanished = ids[3];
    const survivors = ids.filter((id) => id !== vanished);
    const secondChunkIds = new Set(ids.slice(64));
    const inspected: string[][] = [];
    let listCalls = 0;

    const churnedFirstChunk = (_executable: "docker", args: readonly string[]): CaptureResult => {
      if (args[1] === "ls") {
        listCalls += 1;
        return success(`${(listCalls === 1 ? ids : survivors).join("\n")}\n`);
      }
      const requested = args.slice(2);
      inspected.push([...requested]);
      // The first chunk churns on the first pass. Any later inspection that
      // reaches into the second chunk churns too — which is exactly what the
      // old whole-inventory retry did to itself.
      if (requested.includes(vanished)) {
        return { status: 1, stdout: "", stderr: `Error response from daemon: No such container: ${vanished}` };
      }
      if (inspected.length > 2 && requested.some((id) => secondChunkIds.has(id))) {
        const missing = requested.find((id) => secondChunkIds.has(id)) ?? "";
        return { status: 1, stdout: "", stderr: `Error response from daemon: No such container: ${missing}` };
      }
      return success(inventoryInspectionMany(requested.map(foreignSnapshotFor)));
    };

    const inventory = inspectSessionContainerInventory(churnedFirstChunk, SESSION_TEST_PROJECT);

    expect(inventory.map((container) => container.containerId).sort())
      .toEqual([...survivors].sort());
    expect(listCalls).toBe(2);
    // Pass one inspects both chunks even though the first one failed.
    expect(inspected[0]).toEqual(ids.slice(0, 64));
    expect(inspected[1]).toEqual(ids.slice(64));
    // The repair covers only the failed chunk's survivors.
    expect(inspected.slice(2).flat().sort()).toEqual(ids.slice(0, 64).filter((id) => id !== vanished).sort());
    expect(inspected.slice(2).flat()).not.toContain(vanished);
  });

  test("drops only ids a fresh list proves gone, and takes no more than two lists", () => {
    const ids = inventoryIds(3);
    const vanished = ids[1];
    const survivors = ids.filter((id) => id !== vanished);
    let listCalls = 0;
    let inspectCalls = 0;

    const singleChurn = (_executable: "docker", args: readonly string[]): CaptureResult => {
      if (args[1] === "ls") {
        listCalls += 1;
        return success(`${(listCalls === 1 ? ids : survivors).join("\n")}\n`);
      }
      inspectCalls += 1;
      const requested = args.slice(2);
      if (requested.includes(vanished)) {
        return { status: 1, stdout: "", stderr: `Error response from daemon: No such container: ${vanished}` };
      }
      return success(inventoryInspectionMany(requested.map(foreignSnapshotFor)));
    };

    const inventory = inspectSessionContainerInventory(singleChurn, SESSION_TEST_PROJECT);

    expect(inventory.map((container) => container.containerId).sort()).toEqual([...survivors].sort());
    expect({ listCalls, inspectCalls }).toEqual({ listCalls: 2, inspectCalls: 2 });
  });

  test("tolerates arbitrary foreign metadata without hiding Runfree name, label, or IP squatters", () => {
    const exact = orphanSnapshot();
    const foreignId = OTHER_CONTAINER_ID;
    const foreign = {
      Id: foreignId,
      Name: `/${"x".repeat(300)}`,
      Image: "foreign/image:latest",
      Config: { Labels: { foreign: "x".repeat(4 * 1_024 + 1) } },
      State: { Running: "unknown" },
      NetworkSettings: "not-an-object",
    };
    const inventory = inspectSessionContainerInventory((_executable, args) => (
      args[1] === "ls"
        ? success(`${CONTAINER_ID}\n${foreignId}\n`)
        : success(JSON.stringify([
            JSON.parse(inventoryInspection(exact))[0],
            foreign,
          ]))
    ), SESSION_TEST_PROJECT);
    const classifications = classifySessionContainerReconciliation({
      expectedProject: SESSION_TEST_PROJECT,
      records: [],
      containers: inventory,
    });
    expect(inventory).toHaveLength(2);
    expect(classifications.map(({ kind }) => kind)).toEqual(["container-only"]);

    const record = orphanRecord();
    for (const raw of [
      {
        ...foreign,
        Name: `/${record.containerName}`,
      },
      {
        ...foreign,
        Name: "/ordinary-foreign-container",
        Config: { Labels: {
          [SESSION_CONTAINER_LABELS.managed]: true,
          [SESSION_CONTAINER_LABELS.projectId]: SESSION_TEST_PROJECT.projectId,
        } },
      },
    ]) {
      const [container] = inspectSessionContainerInventory((_executable, args) => (
        args[1] === "ls" ? success(`${foreignId}\n`) : success(JSON.stringify([raw]))
      ), SESSION_TEST_PROJECT);
      const [classification] = classifySessionContainerReconciliation({
        expectedProject: SESSION_TEST_PROJECT,
        records: [],
        containers: [container],
      });
      expect(classification?.kind).toBe("untrusted-container");
    }

    const ipSquatter = {
      ...foreign,
      Name: "/ordinary-foreign-container",
      NetworkSettings: {
        Networks: {
          [NETWORK.networkName]: {
            NetworkID: NETWORK.networkId,
            IPAddress: record.sourceIp,
          },
        },
      },
    };
    const [container] = inspectSessionContainerInventory((_executable, args) => (
      args[1] === "ls" ? success(`${foreignId}\n`) : success(JSON.stringify([ipSquatter]))
    ), SESSION_TEST_PROJECT);
    const [classification] = classifySessionContainerReconciliation({
      expectedProject: SESSION_TEST_PROJECT,
      records: [record],
      containers: [container],
    });
    expect(classification?.kind).toBe("mismatch");
  });

  test("ignores Compose control-plane and other-project session metadata but rejects current-project session squatters", () => {
    const composeParticipants = [
      { id: "5".repeat(64), name: "agent", role: "agent-project", ip: "172.31.90.11" },
      { id: "6".repeat(64), name: "proxy", role: "proxy-runtime", ip: "172.31.90.10" },
      { id: "7".repeat(64), name: "oauth-callback", role: "agent-runtime", ip: "172.31.90.12" },
    ].map(({ id, name, role, ip }) => ({
      Id: id,
      Name: `/${SESSION_TEST_PROJECT.composeProject}-${name}-1`,
      Image: `sha256:${id}`,
      Config: { Labels: {
        "com.docker.compose.project": SESSION_TEST_PROJECT.composeProject,
        "com.docker.compose.service": name,
        [SESSION_CONTAINER_LABELS.managed]: "true",
        [SESSION_CONTAINER_LABELS.projectId]: SESSION_TEST_PROJECT.projectId,
        [RUNFREE_IMAGE_ROLE_LABEL]: role,
      } },
      State: { Running: true },
      NetworkSettings: { Networks: {
        [NETWORK.networkName]: { NetworkID: NETWORK.networkId, IPAddress: ip },
      } },
    }));
    const otherProjectId = "abcdefabcdef";
    const otherSession = {
      Id: "8".repeat(64),
      Name: `/runfree-${otherProjectId}-session-rf-20260809-others1`,
      Image: `sha256:${"8".repeat(64)}`,
      Config: { Labels: {
        [SESSION_CONTAINER_LABELS.managed]: "true",
        [SESSION_CONTAINER_LABELS.role]: "session-agent",
        [SESSION_CONTAINER_LABELS.projectId]: otherProjectId,
        [SESSION_CONTAINER_LABELS.composeProject]: `runfree-${otherProjectId}`,
      } },
      State: { Running: false },
      NetworkSettings: { Networks: {} },
    };
    const currentSquatter = {
      Id: "9".repeat(64),
      Name: `/${orphanRecord().containerName}`,
      Image: "attacker/image:latest",
      Config: { Labels: {} },
      State: { Running: false },
      NetworkSettings: { Networks: {} },
    };
    const composeLabelSquatter = {
      Id: "a".repeat(64),
      Name: "/ordinary-compose-named-container",
      Image: "attacker/image:latest",
      Config: { Labels: {
        "com.docker.compose.project": SESSION_TEST_PROJECT.composeProject,
        "com.docker.compose.service": "attacker",
        [SESSION_CONTAINER_LABELS.managed]: "true",
        [SESSION_CONTAINER_LABELS.role]: "session-agent",
        [SESSION_CONTAINER_LABELS.projectId]: SESSION_TEST_PROJECT.projectId,
        [SESSION_CONTAINER_LABELS.composeProject]: SESSION_TEST_PROJECT.composeProject,
      } },
      State: { Running: false },
      NetworkSettings: { Networks: {} },
    };
    const inspection = [...composeParticipants, otherSession, currentSquatter, composeLabelSquatter];
    const inventory = inspectSessionContainerInventory((_executable, args) => (
      args[1] === "ls"
        ? success(`${inspection.map(({ Id }) => Id).join("\n")}\n`)
        : success(JSON.stringify(inspection))
    ), SESSION_TEST_PROJECT);
    const classifications = classifySessionContainerReconciliation({
      expectedProject: SESSION_TEST_PROJECT,
      records: [],
      containers: inventory,
    });

    expect(classifications).toHaveLength(2);
    expect(classifications).toEqual(expect.arrayContaining([
      expect.objectContaining({
        kind: "untrusted-container",
        container: expect.objectContaining({ containerId: currentSquatter.Id }),
      }),
      expect.objectContaining({
        kind: "untrusted-container",
        container: expect.objectContaining({ containerId: composeLabelSquatter.Id }),
      }),
    ]));
  });

  test("inspects a large exact inventory in bounded chunks and seals last-chunk orphan provenance", () => {
    const snapshots = Array.from({ length: 65 }, (_, index) => {
      const id = index.toString(16).padStart(64, "0");
      if (index === 64) {
        return JSON.parse(inventoryInspection(orphanSnapshot({ containerId: id })))[0];
      }
      return {
        Id: id,
        Name: `/foreign-${index}`,
        Image: `sha256:${"f".repeat(64)}`,
        Config: { Labels: {} },
        State: { Running: false },
        NetworkSettings: { Networks: {} },
      };
    });
    const byId = new Map(snapshots.map((snapshot) => [snapshot.Id as string, snapshot]));
    const inspectCalls: string[][] = [];
    const inventory = inspectSessionContainerInventory((_executable, args) => {
      if (args[1] === "ls") return success(`${snapshots.map(({ Id }) => Id).join("\n")}\n`);
      inspectCalls.push([...args]);
      return success(JSON.stringify(args.slice(2).map((id) => byId.get(id))));
    }, SESSION_TEST_PROJECT);

    expect(inventory).toHaveLength(65);
    expect(inspectCalls.map((args) => args.length - 2)).toEqual([64, 1]);
    const [classification] = classifySessionContainerReconciliation({
      expectedProject: SESSION_TEST_PROJECT,
      records: [],
      containers: inventory,
    });
    expect(classification?.kind).toBe("container-only");
    expect(() => authority(classification)).not.toThrow();

    let inspectIndex = 0;
    const oversizedSecondChunk = (_executable: "docker", args: readonly string[]): CaptureResult => {
      if (args[1] === "ls") return success(`${snapshots.map(({ Id }) => Id).join("\n")}\n`);
      inspectIndex += 1;
      return inspectIndex === 1
        ? success(JSON.stringify(args.slice(2).map((id) => byId.get(id))))
        : success("x".repeat(8 * 1_024 * 1_024 + 1));
    };
    expect(() => inspectSessionContainerInventory(
      oversizedSecondChunk,
      SESSION_TEST_PROJECT,
    )).toThrow("size limit");
    expect(inspectIndex).toBe(2);
  });

  test("rejects missing, cross-chunk duplicate, and unrequested IDs from a later inspect chunk", () => {
    const inspections = Array.from({ length: 65 }, (_, index) => ({
      Id: index.toString(16).padStart(64, "0"),
      Name: `/foreign-${index}`,
      Image: `sha256:${"f".repeat(64)}`,
      Config: { Labels: {} },
      State: { Running: false },
      NetworkSettings: { Networks: {} },
    }));
    const ids = inspections.map(({ Id }) => Id);
    const byId = new Map(inspections.map((inspection) => [inspection.Id, inspection]));
    for (const laterChunk of [
      [],
      [inspections[0]],
      [{ ...inspections[64], Id: "f".repeat(64) }],
    ]) {
      let inspectIndex = 0;
      const executor = (_executable: "docker", args: readonly string[]): CaptureResult => {
        if (args[1] === "ls") return success(`${ids.join("\n")}\n`);
        inspectIndex += 1;
        return success(JSON.stringify(inspectIndex === 1
          ? args.slice(2).map((id) => byId.get(id))
          : laterChunk));
      };
      expect(() => inspectSessionContainerInventory(executor, SESSION_TEST_PROJECT)).toThrow();
      expect(inspectIndex).toBe(2);
    }
  });

  test("rejects cumulative chunk output above the inventory-wide inspection limit", () => {
    const inspections = Array.from({ length: 65 }, (_, index) => ({
      Id: index.toString(16).padStart(64, "0"),
      Name: `/foreign-${index}`,
      Image: `sha256:${"f".repeat(64)}`,
      Config: { Labels: {} },
      State: { Running: false },
      NetworkSettings: { Networks: {} },
    }));
    const ids = inspections.map(({ Id }) => Id);
    let inspectIndex = 0;
    const executor = (_executable: "docker", args: readonly string[]): CaptureResult => {
      if (args[1] === "ls") return success(`${ids.join("\n")}\n`);
      inspectIndex += 1;
      const chunk = args.slice(2).map((id) => inspections.find((item) => item.Id === id));
      const padding = "x".repeat(inspectIndex === 1 ? 5 * 1_024 * 1_024 : 4 * 1_024 * 1_024);
      return success(JSON.stringify(chunk.map((item, index) => index === 0
        ? { ...item, Config: { Labels: { padding } } }
        : item)));
    };

    expect(() => inspectSessionContainerInventory(executor, SESSION_TEST_PROJECT))
      .toThrow("cumulative size limit");
    expect(inspectIndex).toBe(2);
  });

  test("fails inventory closed for daemon, malformed, duplicate, mismatched, and oversized observations", () => {
    for (const listResult of [
      { status: 1, stdout: "", stderr: "daemon unavailable" },
      success("short-id\n"),
      success(`${CONTAINER_ID}\n${CONTAINER_ID}\n`),
      success(CONTAINER_ID),
      success("x".repeat(128 * 1_024 + 1)),
    ]) {
      const executor = vi.fn(() => listResult);
      expect(() => inspectSessionContainerInventory(executor, SESSION_TEST_PROJECT)).toThrow();
      expect(executor).toHaveBeenCalledTimes(1);
    }

    for (const { inspectResult, expectedCalls } of [
      {
        inspectResult: { status: 1, stdout: "", stderr: "daemon unavailable" },
        expectedCalls: 2,
      },
      { inspectResult: success("not-json"), expectedCalls: 2 },
      {
        inspectResult: success(inventoryInspection(orphanSnapshot({ containerId: OTHER_CONTAINER_ID }))),
        expectedCalls: 2,
      },
      {
        inspectResult: success("x".repeat(8 * 1_024 * 1_024 + 1)),
        expectedCalls: 2,
      },
    ]) {
      const executor = vi.fn((_executable: "docker", args: readonly string[]) => (
        args[1] === "ls" ? success(`${CONTAINER_ID}\n`) : inspectResult
      ));
      expect(() => inspectSessionContainerInventory(executor, SESSION_TEST_PROJECT)).toThrow();
      expect(executor).toHaveBeenCalledTimes(expectedCalls);
    }
  });

  test("reconstructs sealed cleanup authority from each fresh exact reconciliation", () => {
    const firstClassification = orphanClassification();
    const secondClassification = orphanClassification(orphanSnapshot());
    const first = authority(firstClassification);
    const second = authority(secondClassification);

    expect(first).toMatchObject({
      projectId: SESSION_TEST_PROJECT.projectId,
      composeProject: SESSION_TEST_PROJECT.composeProject,
      containerId: CONTAINER_ID,
      containerName: orphanRecord().containerName,
      imageId: orphanRecord().selectedAgentImageId,
      sessionIncarnation: "a".repeat(64),
      sessionAgentGenerationDigest: orphanRecord().sessionAgentGenerationDigest,
      networkId: NETWORK.networkId,
    });
    expect(first).not.toBe(second);
    expect(() => orphanSessionContainerRemoveCommand(first)).not.toThrow();
    expect(() => orphanSessionContainerRemoveCommand(second)).not.toThrow();
  });

  test("refuses partial registry classifications and invalidates commands when the full registry changes", () => {
    const partial = orphanClassification();
    const record = {
      ...orphanRecord(),
      state: "provisioning-running" as const,
      containerId: CONTAINER_ID,
      admittedAt: "2026-08-08T12:00:01.000Z",
      leaseGeneration: "e".repeat(32),
      leaseExpiresAt: "2026-08-08T12:05:00.000Z",
    };
    writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, record);
    expect(() => authorizeSessionContainerOrphanCleanup(
      partial,
      SESSION_TEST_PROJECT,
      NETWORK,
      stateDir,
      LIFECYCLE_LOCK,
    )).toThrow("full lifecycle registry");

    fs.rmSync(stateDir, { recursive: true, force: true });
    fs.mkdirSync(stateDir, { recursive: true });
    const exact = authority(partial);
    const command = orphanSessionContainerRemoveCommand(exact);
    writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, record);
    const executor = vi.fn(() => success());
    expect(() => executeSessionContainerCleanupCommand(command, executor)).toThrow("registry changed");
    expect(executor).not.toHaveBeenCalled();
  });

  test("rechecks lifecycle-lock ownership before an orphan command reaches Docker", () => {
    let held = true;
    const lifecycleLock: ProjectLifecycleLock = {
      ownerToken: "b".repeat(64),
      assertHeld: () => {
        if (!held) throw new Error("lifecycle lock lost");
      },
      release: () => undefined,
    };
    const exact = authorizeSessionContainerOrphanCleanup(
      orphanClassification(),
      SESSION_TEST_PROJECT,
      NETWORK,
      stateDir,
      lifecycleLock,
    );
    const command = orphanSessionContainerRemoveCommand(exact);
    held = false;
    const executor = vi.fn(() => success());

    expect(() => executeSessionContainerCleanupCommand(command, executor)).toThrow("lifecycle lock lost");
    expect(executor).not.toHaveBeenCalled();
  });

  test("rejects forged, copied, mismatched, and untrusted classifications before Docker authority exists", () => {
    const exact = orphanClassification();
    const copied = { ...exact } as SessionReconciliationClassification;
    const identity = verifiedSessionContainerIdentity(orphanSnapshot(), SESSION_TEST_PROJECT);
    if (!identity) throw new Error("fixture identity is invalid");
    const forged = {
      kind: "container-only",
      container: orphanSnapshot(),
      identity,
    } as SessionReconciliationClassification;
    const [plainClassified] = classifySessionContainerReconciliation({
      expectedProject: SESSION_TEST_PROJECT,
      records: [],
      containers: [orphanSnapshot()],
    });
    const record = orphanRecord();
    const [mismatch] = classifySessionContainerReconciliation({
      expectedProject: SESSION_TEST_PROJECT,
      records: [{ ...record, containerId: CONTAINER_ID }],
      containers: [orphanSnapshot({ imageId: `sha256:${"f".repeat(64)}` })],
    });
    const untrustedSnapshot = orphanSnapshot();
    untrustedSnapshot.labels["io.runfree.untrusted-extra"] = "true";
    const [untrusted] = classifySessionContainerReconciliation({
      expectedProject: SESSION_TEST_PROJECT,
      records: [],
      containers: [untrustedSnapshot],
    });

    for (const classification of [copied, forged, plainClassified, mismatch, untrusted]) {
      expect(() => authorizeSessionContainerOrphanCleanup(
        classification as SessionReconciliationClassification,
        SESSION_TEST_PROJECT,
        NETWORK,
        stateDir,
        LIFECYCLE_LOCK,
      )).toThrow();
    }
    expect(() => authorizeSessionContainerOrphanCleanup(
      exact,
      WRONG_PROJECT,
      NETWORK,
      stateDir,
      LIFECYCLE_LOCK,
    )).toThrow("another project");
    expect(() => authorizeSessionContainerOrphanCleanup(exact, SESSION_TEST_PROJECT, {
      ...NETWORK,
      networkName: `${WRONG_PROJECT.composeProject}_agent_internal`,
    }, stateDir, LIFECYCLE_LOCK)).toThrow("expected project's internal network");
    expect(() => authority(orphanClassification(orphanSnapshot({
      internalNetworkId: "9".repeat(64),
    })))).toThrow("another internal network");
  });

  test("requires every managed identity label before classifying an orphan as trusted", () => {
    // The descriptive taxonomy labels are deliberately NOT identity: a session
    // container created before they existed cannot be relabelled, and refusing
    // its orphan would wedge the project on version skew. The taxonomy spec's
    // expand-migrate-contract rule requires the decoder to tolerate their
    // absence, so they are excluded here and their tolerance is pinned below.
    const descriptiveLabels: string[] = [
      SESSION_CONTAINER_LABELS.lifecycleOwner,
      SESSION_CONTAINER_LABELS.labelSchema,
    ];
    const requiredLabels = Object.keys(orphanSnapshot().labels)
      .filter((label) => !descriptiveLabels.includes(label));
    expect(requiredLabels).toContain(SESSION_CONTAINER_LABELS.sessionIncarnation);
    expect(requiredLabels).toContain(SESSION_CONTAINER_LABELS.sessionAgentGenerationDigest);

    for (const label of requiredLabels) {
      const snapshot = orphanSnapshot();
      delete snapshot.labels[label];
      const [classification] = classifySessionContainerReconciliation({
        expectedProject: SESSION_TEST_PROJECT,
        records: [],
        containers: [snapshot],
      });
      expect(classification?.kind, label).toBe("untrusted-container");
    }

    for (const label of descriptiveLabels) {
      const snapshot = orphanSnapshot();
      delete snapshot.labels[label];
      const [classification] = classifySessionContainerReconciliation({
        expectedProject: SESSION_TEST_PROJECT,
        records: [],
        containers: [snapshot],
      });
      expect(classification?.kind, `${label} must stay tolerated for pre-taxonomy sessions`)
        .toBe("container-only");
    }
  });

  test("mints only exact stop and non-force remove commands from the sealed authority", () => {
    const exact = authority();
    const stop = orphanSessionContainerStopCommand(exact);
    const remove = orphanSessionContainerRemoveCommand(exact);
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
    expect(stop.exactTarget).toBe(CONTAINER_ID);
    expect(remove.exactTarget).toBe(CONTAINER_ID);
    expect(remove.args).not.toContain("--force");
    expect(remove.args.every((arg) => !arg.startsWith("--filter"))).toBe(true);
  });

  test("rejects copied or field-mutated authority and unsealed commands before Docker", () => {
    const exact = authority();
    const destructiveExecutor = vi.fn(() => success());
    const mutations: Partial<SessionContainerOrphanCleanupAuthority>[] = [
      { containerId: OTHER_CONTAINER_ID },
      { containerName: "runfree-attacker-session" },
      { imageId: `sha256:${"f".repeat(64)}` },
      { sessionIncarnation: "c".repeat(64) },
      { sessionAgentGenerationDigest: `sha256:${"d".repeat(64)}` },
      { projectId: WRONG_PROJECT.projectId },
      { networkId: "9".repeat(64) },
    ];
    for (const mutation of mutations) {
      const forged = { ...exact, ...mutation } as SessionContainerOrphanCleanupAuthority;
      expect(() => orphanSessionContainerRemoveCommand(forged)).toThrow("unsealed");
    }
    expect(() => executeSessionContainerCleanupCommand({
      executable: "docker",
      args: ["container", "rm", OTHER_CONTAINER_ID],
      effect: "remove-orphan-session-container",
      exactTarget: OTHER_CONTAINER_ID,
    } as unknown as SessionContainerCleanupCommand, destructiveExecutor)).toThrow("unsealed");
    expect(destructiveExecutor).not.toHaveBeenCalled();
  });

  test("seals completion only after the exact container and internal-network endpoint are absent", () => {
    const exact = authority();
    const { executor, calls } = absenceExecutor();
    const receipt = proveSessionContainerOrphanAbsent(executor, exact, { cwd: "/trusted" });

    expect(receipt).toEqual({
      containerId: CONTAINER_ID,
      networkId: NETWORK.networkId,
      sourceIp: orphanRecord().sourceIp,
    });
    expect(() => assertSessionContainerOrphanAbsenceReceipt(receipt, exact)).not.toThrow();
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

    const forgedReceipt = { ...receipt } as SessionContainerOrphanAbsenceReceipt;
    const otherAuthority = authority(orphanClassification(orphanSnapshot({
      containerId: OTHER_CONTAINER_ID,
    })));
    expect(() => assertSessionContainerOrphanAbsenceReceipt(forgedReceipt, exact)).toThrow("unsealed");
    expect(() => assertSessionContainerOrphanAbsenceReceipt(receipt, otherAuthority)).toThrow("another cleanup authority");
  });

  test("fails absence closed before or during the exact internal-network re-check", () => {
    const exact = authority();
    const containerStillPresent = absenceExecutor({
      containerResult: success(`${CONTAINER_ID}\n`),
    });
    expect(() => proveSessionContainerOrphanAbsent(containerStillPresent.executor, exact)).toThrow("still exists");
    expect(containerStillPresent.calls).toHaveLength(1);

    const endpointStillPresent = absenceExecutor({
      networkResult: success(networkInspection({
        [CONTAINER_ID]: {
          Name: orphanRecord().containerName,
          IPv4Address: `${orphanRecord().sourceIp}/24`,
        },
      })),
    });
    expect(() => proveSessionContainerOrphanAbsent(endpointStillPresent.executor, exact)).toThrow("still owns");
    expect(endpointStillPresent.calls).toHaveLength(2);

    const sourceIpReused = absenceExecutor({
      networkResult: success(networkInspection({
        [OTHER_CONTAINER_ID]: {
          Name: "replacement-container",
          IPv4Address: `${orphanRecord().sourceIp}/24`,
        },
      })),
    });
    expect(() => proveSessionContainerOrphanAbsent(sourceIpReused.executor, exact)).toThrow("source IP still owns");
    expect(sourceIpReused.calls).toHaveLength(2);

    for (const networkResult of [
      { status: 1, stdout: "", stderr: "daemon unavailable" },
      success("not-json"),
      success(networkInspection({}, { Id: "9".repeat(64) })),
      success(networkInspection({}, { Name: "attacker-network" })),
      success("x".repeat(512 * 1024 + 1)),
    ]) {
      const failure = absenceExecutor({ networkResult });
      expect(() => proveSessionContainerOrphanAbsent(failure.executor, exact)).toThrow();
      expect(failure.calls).toHaveLength(2);
    }
  });
});
