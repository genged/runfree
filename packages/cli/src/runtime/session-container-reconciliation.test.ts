import { describe, expect, test } from "vitest";

import {
  AGENT_PROJECT_IMAGE_ROLE,
  RUNFREE_DIGEST_SCHEMA_LABEL,
  RUNFREE_DIGEST_SCHEMA_VERSION,
  RUNFREE_IMAGE_INPUT_DIGEST_LABEL,
  RUNFREE_IMAGE_ROLE_LABEL,
} from "./constants.ts";
import {
  effectiveControlPlaneFixture,
  sessionAgentMaterializationFixture,
} from "./session-container.test-harness.ts";

import {
  createAllocatedSessionContainerRecordV2,
  sessionContainerLabels,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import {
  accountSessionAgentImageReferences,
  allocateSessionSourceIp,
  classifySessionContainerReconciliation,
  exactSessionContainerCleanupTarget,
  inspectSessionContainerInventory,
  parseSessionNetworkAttachments,
  SESSION_CONTAINER_CONCURRENCY_CAP,
  type SessionContainerSnapshot,
  type SessionNetworkAttachment,
  unreferencedSessionAgentImageIds,
  unreferencedSessionAgentMaterializationDigests,
  verifiedSessionContainerIdentity,
} from "./session-container-reconciliation.ts";
import { createSessionLaunchTarget } from "./session-launch.ts";

const PROJECT = { projectId: "0123456789ab", composeProject: "runfree-0123456789ab" };
const NETWORK_ID = "9".repeat(64);
const CONTAINER_ID = "3".repeat(64);

function digest(character: string): string {
  return `sha256:${character.repeat(64)}`;
}

function allocated(index = 0): SessionContainerRecordV2 {
  const suffix = (index + 1).toString(36).padStart(6, "0");
  return createAllocatedSessionContainerRecordV2({
    sessionId: `rf-20260805-${suffix}`,
    sessionIncarnation: (index + 1).toString(16).padStart(64, "0"),
    sessionPrincipal: (index + 101).toString(16).padStart(64, "0"),
    displayName: `session ${index}`,
    command: "codex",
    launch: createSessionLaunchTarget({
      path: "/usr/local/bin/codex",
      args: ["--dangerously-bypass-approvals-and-sandbox"],
      interactive: true,
      tty: true,
    }),
    sourceIp: `172.31.90.${20 + index}`,
    materialization: sessionAgentMaterializationFixture(),
    effectiveControlPlane: effectiveControlPlaneFixture(),
    hostPid: 1234 + index,
    createdAt: "2026-08-05T12:00:00.000Z",
  });
}

function bound(index = 0, containerId = CONTAINER_ID): SessionContainerRecordV2 {
  return { ...allocated(index), containerId };
}

function provisioning(index = 0, containerId = CONTAINER_ID): SessionContainerRecordV2 {
  return {
    ...allocated(index),
    state: "provisioning-running",
    containerId,
    admittedAt: "2026-08-05T12:00:10.000Z",
    leaseGeneration: "4".repeat(32),
    leaseExpiresAt: "2026-08-05T12:01:10.000Z",
  };
}

function attachment(record: SessionContainerRecordV2): SessionNetworkAttachment {
  return {
    networkId: NETWORK_ID,
    networkName: `${PROJECT.composeProject}_agent_internal`,
    containerId: record.containerId ?? CONTAINER_ID,
    containerName: record.containerName,
    sourceIp: record.sourceIp,
  };
}

function snapshot(record: SessionContainerRecordV2, overrides: Partial<SessionContainerSnapshot> = {}): SessionContainerSnapshot {
  return {
    containerId: record.containerId ?? CONTAINER_ID,
    containerName: record.containerName,
    imageId: record.selectedAgentImageId,
    labels: {
      ...sessionContainerLabels(record, "0.3.0"),
      [RUNFREE_IMAGE_ROLE_LABEL]: AGENT_PROJECT_IMAGE_ROLE,
      [RUNFREE_DIGEST_SCHEMA_LABEL]: RUNFREE_DIGEST_SCHEMA_VERSION,
      [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: record.selectedAgentImageInputDigest,
    },
    ...(record.containerId !== undefined ? { sourceIp: record.sourceIp } : {}),
    running: record.state === "provisioning-running" || record.state === "attached",
    ...overrides,
  };
}

describe("session source-IP allocation", () => {
  test("parses exact Docker network identities and attachments", () => {
    const record = provisioning();
    const source = JSON.stringify([{
      Id: NETWORK_ID,
      Name: `${PROJECT.composeProject}_agent_internal`,
      Containers: {
        [CONTAINER_ID]: { Name: record.containerName, IPv4Address: `${record.sourceIp}/24` },
      },
    }]);
    expect(parseSessionNetworkAttachments(source, {
      networkId: NETWORK_ID,
      networkName: `${PROJECT.composeProject}_agent_internal`,
      subnet: "172.31.90.0/24",
    })).toEqual([attachment(record)]);
    expect(() => parseSessionNetworkAttachments(source.replace(NETWORK_ID, "8".repeat(64)), {
      networkId: NETWORK_ID,
      networkName: `${PROJECT.composeProject}_agent_internal`,
      subnet: "172.31.90.0/24",
    })).toThrow("different network");
  });

  test("allocates from the union of records, reserved roles, and exact Docker attachments", () => {
    const first = provisioning();
    expect(allocateSessionSourceIp({
      expectedProject: PROJECT,
      networkId: NETWORK_ID,
      networkName: `${PROJECT.composeProject}_agent_internal`,
      subnet: "172.31.90.0/24",
      reservedIps: ["172.31.90.10", "172.31.90.11", "172.31.90.12", "172.31.90.21"],
      records: [first],
      attachments: [
        attachment(first),
        { ...attachment(first), containerId: "8".repeat(64), containerName: "proxy", sourceIp: "172.31.90.10" },
      ],
    })).toBe("172.31.90.22");
  });

  test("fails closed on record/Docker disagreement, unknown peers, and cap exhaustion", () => {
    const record = provisioning();
    expect(() => allocateSessionSourceIp({
      expectedProject: PROJECT,
      networkId: NETWORK_ID,
      networkName: `${PROJECT.composeProject}_agent_internal`,
      subnet: "172.31.90.0/24",
      reservedIps: ["172.31.90.10"],
      records: [record],
      attachments: [{ ...attachment(record), sourceIp: "172.31.90.21" }],
    })).toThrow("disagrees");
    expect(() => allocateSessionSourceIp({
      expectedProject: PROJECT,
      networkId: NETWORK_ID,
      networkName: `${PROJECT.composeProject}_agent_internal`,
      subnet: "172.31.90.0/24",
      reservedIps: ["172.31.90.10"],
      records: [],
      attachments: [{ ...attachment(record), sourceIp: "172.31.90.30" }],
    })).toThrow("unknown Docker participant");
    expect(() => allocateSessionSourceIp({
      expectedProject: PROJECT,
      networkId: NETWORK_ID,
      networkName: `${PROJECT.composeProject}_agent_internal`,
      subnet: "172.31.90.0/24",
      reservedIps: [],
      records: Array.from({ length: SESSION_CONTAINER_CONCURRENCY_CAP }, (_, index) => allocated(index)),
      attachments: [],
    })).toThrow("concurrency cap reached");
  });

  test("does not reuse a bound allocated record IP or an attached revoking IP", () => {
    const first = bound();
    const second = { ...provisioning(1, "4".repeat(64)), state: "revoking" as const };
    expect(allocateSessionSourceIp({
      expectedProject: PROJECT,
      networkId: NETWORK_ID,
      networkName: `${PROJECT.composeProject}_agent_internal`,
      subnet: "172.31.90.0/24",
      reservedIps: [],
      records: [first, second],
      attachments: [attachment(second)],
    })).toBe("172.31.90.22");
  });

  test("allows no live endpoint for created records but requires one for running records", () => {
    const stopped = bound();
    expect(() => allocateSessionSourceIp({
      expectedProject: PROJECT,
      networkId: NETWORK_ID,
      networkName: `${PROJECT.composeProject}_agent_internal`,
      subnet: "172.31.90.0/24",
      reservedIps: [],
      records: [stopped],
      attachments: [],
    })).not.toThrow();
    expect(() => allocateSessionSourceIp({
      expectedProject: PROJECT,
      networkId: NETWORK_ID,
      networkName: `${PROJECT.composeProject}_agent_internal`,
      subnet: "172.31.90.0/24",
      reservedIps: [],
      records: [provisioning()],
      attachments: [],
    })).toThrow("network attachment disagrees");
  });
});

describe("session-container inventory inspection of real daemon output", () => {
  // These go through `inspectSessionContainerInventory`, which parses Docker's
  // actual JSON. The rest of this file builds `SessionContainerSnapshot` values
  // by hand and so never exercises that parser — which is precisely how the
  // stopped-endpoint defect shipped: every snapshot-level test set
  // `sourceIp: undefined` directly and passed, while the parser turned the same
  // container into malformed metadata.
  function inventory(inspectBody: readonly unknown[], ids: readonly string[] = [CONTAINER_ID]) {
    const executor = (_executable: string, args: readonly string[]) => {
      if (args.includes("ls")) return { status: 0, stdout: `${ids.join("\n")}\n`, stderr: "" };
      return { status: 0, stdout: JSON.stringify(inspectBody), stderr: "" };
    };
    return inspectSessionContainerInventory(executor, PROJECT);
  }

  function inspectJson(
    record: SessionContainerRecordV2,
    network: Record<string, unknown>,
    overrides: Record<string, unknown> = {},
  ) {
    return {
      Id: CONTAINER_ID,
      Name: `/${record.containerName}`,
      Image: record.selectedAgentImageId,
      State: { Running: false },
      Config: {
        Labels: {
          ...sessionContainerLabels(record, "0.3.0"),
          [RUNFREE_IMAGE_ROLE_LABEL]: AGENT_PROJECT_IMAGE_ROLE,
          [RUNFREE_DIGEST_SCHEMA_LABEL]: RUNFREE_DIGEST_SCHEMA_VERSION,
          [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: record.selectedAgentImageInputDigest,
        },
      },
      NetworkSettings: { Networks: { [`${PROJECT.composeProject}_agent_internal`]: network } },
      ...overrides,
    };
  }

  // Both shapes a created-but-unstarted container has been observed or is
  // plausibly reported in: `NetworkID` may already name the network the
  // container was created against, because the daemon knows that at create
  // time — only the *endpoint* is deferred to start. Requiring `NetworkID` to
  // be empty too is what made the first version of this fix ineffective, so
  // both are pinned here rather than assumed equivalent.
  for (const [label, networkId] of [["without a network id", ""], ["with the network id already set", NETWORK_ID]]) {
    test(`reads a created-but-never-started container ${label} as having no endpoint yet`, () => {
      const record = allocated();
      const [observed] = inventory([inspectJson(record, {
        IPAMConfig: { IPv4Address: record.sourceIp },
        NetworkID: networkId,
        EndpointID: "",
        IPAddress: "",
        IPPrefixLen: 0,
      })]);
      expect(observed.malformedInventoryMetadata).toBeUndefined();
      expect(observed.sourceIp).toBeUndefined();
      expect(verifiedSessionContainerIdentity(observed, PROJECT)).toBeDefined();
    });
  }

  test("still reads a running container with no endpoint as malformed", () => {
    // The load-bearing half. A running container must have an endpoint; if the
    // tolerance above extended to running containers it would weaken the
    // authority-bearing match, which requires an exact source IP.
    const record = allocated();
    const [observed] = inventory([inspectJson(
      record,
      { IPAMConfig: { IPv4Address: record.sourceIp }, NetworkID: "", EndpointID: "", IPAddress: "" },
      { State: { Running: true } },
    )]);
    expect(observed.malformedInventoryMetadata).toBe(true);
    expect(verifiedSessionContainerIdentity(observed, PROJECT)).toBeUndefined();
  });

  test("tolerates a base image's multi-line description label", () => {
    // The exact label that made every session container unreconcilable: Ubuntu
    // ships a multi-line `org.opencontainers.image.description`, Docker merges
    // image labels into `Config.Labels`, and condemning the whole set for one
    // foreign value marked the container's metadata malformed.
    const record = allocated();
    const container = inspectJson(record, {
      IPAMConfig: { IPv4Address: record.sourceIp },
      NetworkID: "",
      EndpointID: "",
      IPAddress: "",
    });
    (container.Config.Labels as Record<string, string>)["org.opencontainers.image.description"] =
      "The Ubuntu container image maintained by Canonical\n\nUbuntu is a Debian-based Linux operating system.";
    const [observed] = inventory([container]);
    expect(observed.malformedInventoryMetadata).toBeUndefined();
    expect(verifiedSessionContainerIdentity(observed, PROJECT)).toBeDefined();
    // Dropped from the map rather than trusted, but the container is not condemned.
    expect(observed.labels["org.opencontainers.image.description"]).toBeUndefined();
  });

  test("still condemns a container whose own Runfree label is malformed", () => {
    // The load-bearing half: state Runfree wrote and cannot explain is a real
    // signal, and must stay fatal.
    const record = allocated();
    const container = inspectJson(record, {
      IPAMConfig: { IPv4Address: record.sourceIp },
      NetworkID: "",
      EndpointID: "",
      IPAddress: "",
    });
    (container.Config.Labels as Record<string, string>)["io.runfree.session-id"] = "rf-2026\n0814-000001";
    const [observed] = inventory([container]);
    expect(observed.malformedInventoryMetadata).toBe(true);
    expect(verifiedSessionContainerIdentity(observed, PROJECT)).toBeUndefined();
  });

  test("drops an oversized foreign label without condemning the container", () => {
    const record = allocated();
    const container = inspectJson(record, {
      IPAMConfig: { IPv4Address: record.sourceIp },
      NetworkID: "",
      EndpointID: "",
      IPAddress: "",
    });
    (container.Config.Labels as Record<string, string>)["com.example.enormous"] = "x".repeat(5 * 1024);
    const [observed] = inventory([container]);
    expect(observed.malformedInventoryMetadata).toBeUndefined();
    expect(observed.labels["com.example.enormous"]).toBeUndefined();
  });

  test("still reads an assigned address with an invalid network id as malformed", () => {
    // Once an address is assigned the endpoint is validated exactly as before;
    // the tolerance above applies only to a container with no address at all.
    const record = allocated();
    const [observed] = inventory([inspectJson(record, {
      NetworkID: "not-a-network-id",
      EndpointID: NETWORK_ID,
      IPAddress: record.sourceIp,
    })]);
    expect(observed.malformedInventoryMetadata).toBe(true);
  });

  test("still reads a garbage endpoint as malformed", () => {
    const record = allocated();
    const [observed] = inventory([inspectJson(record, {
      NetworkID: NETWORK_ID,
      EndpointID: NETWORK_ID,
      IPAddress: "not-an-address",
    })]);
    expect(observed.malformedInventoryMetadata).toBe(true);
  });

  test("reads a fully attached running container as attached", () => {
    const record = provisioning();
    const [observed] = inventory([inspectJson(
      record,
      { NetworkID: NETWORK_ID, EndpointID: NETWORK_ID, IPAddress: record.sourceIp },
      { State: { Running: true } },
    )]);
    expect(observed.malformedInventoryMetadata).toBeUndefined();
    expect(observed.sourceIp).toBe(record.sourceIp);
  });
});

describe("session-container reconciliation", () => {
  test("reconciles a record whose container was created before the crash", () => {
    // The `after-create` crash: `docker create` succeeded, the process died
    // before the record captured the container id, and the container has no
    // endpoint because it never started. This must reconcile rather than
    // classify as an unrecoverable mismatch.
    const record = allocated();
    const created = snapshot(record, { containerId: CONTAINER_ID, sourceIp: undefined, running: false });
    const classes = classifySessionContainerReconciliation({
      expectedProject: PROJECT,
      records: [record],
      containers: [created],
    });
    expect(classes).toHaveLength(1);
    expect(classes[0]?.kind).not.toBe("mismatch");
  });

  test("matches a created container without a live endpoint and rejects a contradictory endpoint", () => {
    const record = bound();
    const withoutEndpoint = classifySessionContainerReconciliation({
      expectedProject: PROJECT,
      records: [record],
      containers: [snapshot(record, { sourceIp: undefined })],
    });
    expect(withoutEndpoint).toHaveLength(1);
    expect(withoutEndpoint[0]?.kind).toBe("matching");

    const contradictory = classifySessionContainerReconciliation({
      expectedProject: PROJECT,
      records: [record],
      containers: [snapshot(record, { sourceIp: "172.31.90.99" })],
    });
    expect(contradictory).toHaveLength(1);
    expect(contradictory[0]?.kind).toBe("mismatch");

    const startedBeforeLifecycleCas = classifySessionContainerReconciliation({
      expectedProject: PROJECT,
      records: [record],
      containers: [snapshot(record, { running: true, sourceIp: record.sourceIp })],
    });
    expect(startedBeforeLifecycleCas[0]?.kind).toBe("mismatch");

    const provisioningRecord = provisioning();
    const exitedBeforeRunningProof = classifySessionContainerReconciliation({
      expectedProject: PROJECT,
      records: [provisioningRecord],
      containers: [snapshot(provisioningRecord, { running: false, sourceIp: undefined })],
    });
    expect(exitedBeforeRunningProof[0]?.kind).toBe("mismatch");
  });

  test("classifies matching, record-only, exact orphan, mismatch, and untrusted containers", () => {
    const matchingRecord = provisioning();
    const recordOnly = allocated(1);
    const mismatchRecord = bound(2, "5".repeat(64));
    const orphanRecord = bound(3, "6".repeat(64));
    const exactOrphan = snapshot(orphanRecord);
    const mismatched = snapshot(mismatchRecord, { imageId: digest("f") });
    const forged = snapshot(bound(4, "7".repeat(64)), {
      labels: {
        ...sessionContainerLabels(bound(4, "7".repeat(64)), "0.3.0"),
        "com.docker.compose.project": PROJECT.composeProject,
      },
    });
    const classes = classifySessionContainerReconciliation({
      expectedProject: PROJECT,
      records: [matchingRecord, recordOnly, mismatchRecord],
      containers: [snapshot(matchingRecord), exactOrphan, mismatched, forged],
    });
    expect(classes.map((entry) => entry.kind).sort()).toEqual([
      "container-only",
      "matching",
      "mismatch",
      "record-only",
      "untrusted-container",
    ]);
    expect(classes.flatMap((entry) => exactSessionContainerCleanupTarget(entry) ?? [])).toEqual([exactOrphan.containerId]);
  });

  test("returns an exact teardown target only for matching revoking records", () => {
    const record = { ...provisioning(), state: "revoking" as const };
    for (const running of [false, true]) {
      const [classification] = classifySessionContainerReconciliation({
        expectedProject: PROJECT,
        records: [record],
        containers: [snapshot(record, { running, sourceIp: record.sourceIp })],
      });
      expect(classification?.kind).toBe("matching");
      expect(classification && exactSessionContainerCleanupTarget(classification)).toBe(CONTAINER_ID);
    }
    const [mismatch] = classifySessionContainerReconciliation({
      expectedProject: PROJECT,
      records: [record],
      containers: [snapshot(record, { imageId: digest("f") })],
    });
    expect(mismatch?.kind).toBe("mismatch");
    expect(mismatch && exactSessionContainerCleanupTarget(mismatch)).toBeUndefined();
  });

  test("rejects every selected materialization label mismatch before live identity matches", () => {
    const record = provisioning();
    for (const label of [
      "io.runfree.selected-agent-image-input-digest",
      "io.runfree.selected-agent-image-id",
      "io.runfree.session-agent-materialization-digest",
      "io.runfree.session-agent-generation-digest",
    ]) {
      const container = snapshot(record);
      container.labels[label] = digest("0");
      const [classification] = classifySessionContainerReconciliation({
        expectedProject: PROJECT,
        records: [record],
        containers: [container],
      });
      expect(classification?.kind, label).toBe("mismatch");
    }
  });

  test("classifies an unknown managed label as an exact record mismatch", () => {
    const record = provisioning();
    const container = snapshot(record);
    container.labels["io.runfree.unknown-session-identity"] = digest("0");
    const [classification] = classifySessionContainerReconciliation({
      expectedProject: PROJECT,
      records: [record],
      containers: [container],
    });
    expect(classification?.kind).toBe("mismatch");
  });

  test("retains every exact record, container, desired, and in-progress image reference", () => {
    const record = provisioning();
    const desiredSelected = digest("f");
    const progress = digest("7");
    const accounting = accountSessionAgentImageReferences({
      expectedProject: PROJECT,
      records: [record],
      containers: [snapshot(record)],
      desiredSelectedAgentImageId: desiredSelected,
      desiredSessionAgentMaterializationDigest: digest("6"),
      inProgressImageIds: [progress],
      inProgressSessionAgentMaterializationDigests: [digest("5")],
    });
    expect(accounting.images.map((entry) => entry.imageId)).toEqual([
      progress,
      record.selectedAgentImageId,
      desiredSelected,
    ].sort());
    expect(unreferencedSessionAgentImageIds([
      record.selectedAgentImageId,
      desiredSelected,
      digest("9"),
    ], accounting)).toEqual([digest("9")]);
    expect(accounting.materializations.map((entry) => entry.materializationDigest)).toEqual([
      digest("5"),
      digest("6"),
      record.sessionAgentMaterializationDigest,
    ].sort());
    expect(unreferencedSessionAgentMaterializationDigests([
      record.sessionAgentMaterializationDigest,
      digest("6"),
      digest("9"),
    ], accounting)).toEqual([digest("9")]);
  });

  test("malformed managed-looking containers block image cleanup", () => {
    const record = bound();
    const forged = snapshot(record, {
      labels: { ...sessionContainerLabels(record, "0.3.0"), "io.runfree.session-incarnation": "wrong" },
    });
    const accounting = accountSessionAgentImageReferences({
      expectedProject: PROJECT,
      records: [],
      containers: [forged],
    });
    expect(accounting.uncertainContainerIds).toEqual([CONTAINER_ID]);
    expect(unreferencedSessionAgentImageIds([digest("9")], accounting)).toEqual([]);
    expect(unreferencedSessionAgentMaterializationDigests([digest("9")], accounting)).toEqual([]);
  });

  test("retains the exact selected identity from a verified live container without a lifecycle record", () => {
    const record = bound();
    const accounting = accountSessionAgentImageReferences({
      expectedProject: PROJECT,
      records: [],
      containers: [snapshot(record)],
    });
    expect(accounting.images.map(({ imageId }) => imageId)).toEqual([record.selectedAgentImageId]);
  });
});
