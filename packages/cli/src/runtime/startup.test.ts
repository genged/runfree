import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { expect, test } from "vitest";

import {
  ephemeralHelperImage,
  planValidatedIngressForwardersForRebuild,
  planRuntimeUpgradeFromV2State,
} from "./startup.ts";
import { planValidatedIngressForwarders } from "./ingress-forwarder-ownership.ts";
import type { RuntimePlan } from "./plan.ts";
import type { CaptureResult, DockerContainerInspect, RuntimeContext, RuntimeIO } from "./types.ts";
import { sha256Digest } from "./component-state.ts";
import {
  createControlPlaneGenerationV2,
  publishControlPlaneMaterializationV2,
  selectEffectiveControlPlaneV2,
} from "./component-state-v2.ts";
import {
  controlPlaneMaterializationFixture,
  effectiveControlPlaneFixture,
  sessionContainerRecordFixture,
  sessionGenerationFixture,
  SESSION_TEST_PROJECT,
} from "./session-container.test-harness.ts";
import { writeSessionContainerRecordV2 } from "./session-containers.ts";
import { writeSessionHostStatus } from "./session-host-status.ts";
import {
  INGRESS_FORWARDER_COMMAND,
  INGRESS_FORWARDER_ENTRYPOINT,
  INGRESS_FORWARDER_IMAGE,
  ingressHostNetworkName,
} from "./ingress-forwarder.ts";
import {
  ingressHostNetworkInspectFixture,
} from "./ingress-forwarder.test-harness.ts";

const REBUILD_INGRESS_IMAGE_ID = `sha256:${"e".repeat(64)}`;

function rebuildIngressForwarder(
  configImage = INGRESS_FORWARDER_IMAGE,
  imageId = REBUILD_INGRESS_IMAGE_ID,
): DockerContainerInspect {
  const { composeProject, projectId } = SESSION_TEST_PROJECT;
  const hostPort = "3000";
  const hostNetwork = ingressHostNetworkName(projectId);
  const internalNetwork = `${composeProject}_agent_internal`;
  const bindings = { [`${hostPort}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: hostPort }] };
  return {
    Config: {
      Cmd: [...INGRESS_FORWARDER_COMMAND],
      Entrypoint: [INGRESS_FORWARDER_ENTRYPOINT],
      Env: [
        `INGRESS_HOST_PORT=${hostPort}`,
        "INGRESS_TARGET=172.30.0.20",
        `INGRESS_TARGET_PORT=${hostPort}`,
      ],
      Image: configImage,
      Labels: {
        "io.runfree.container-role": "ingress-forwarder",
        "io.runfree.ingress-purpose": "port",
        "io.runfree.project-id": projectId,
      },
      User: "65534:65534",
    },
    HostConfig: {
      AutoRemove: true,
      CapAdd: [],
      CapDrop: ["ALL"],
      NetworkMode: hostNetwork,
      PidsLimit: 64,
      PortBindings: bindings,
      Privileged: false,
      ReadonlyRootfs: true,
      SecurityOpt: ["no-new-privileges:true"],
    },
    Id: "f".repeat(64),
    Image: imageId,
    Mounts: [],
    Name: `/runfree-ingress-port-${projectId}-${hostPort}`,
    NetworkSettings: {
      Networks: {
        [hostNetwork]: { IPAddress: "172.31.0.3" },
        [internalNetwork]: { IPAddress: "172.30.0.31" },
      },
      Ports: bindings,
    },
    State: { Running: true },
  };
}

function rebuildForwarderIo(
  candidates: readonly DockerContainerInspect[],
  options: Readonly<{
    currentNetworkMissing?: boolean;
    hideForwardersFromDiscovery?: boolean;
  }> = {},
): {
  calls: string[][];
  io: RuntimeIO;
} {
  const calls: string[][] = [];
  const remaining = new Map(candidates.map((candidate) => [candidate.Name?.replace(/^\//, "") ?? "", candidate]));
  const byId = new Map(candidates.map((candidate) => [candidate.Id ?? "", candidate]));
  const result = (status: number, stdout = "", stderr = ""): CaptureResult => ({ status, stdout, stderr });
  const io = {
    capture: (_command: string, args: string[]) => {
      calls.push(args);
      if (args[0] === "image" && args[1] === "inspect") return result(0, REBUILD_INGRESS_IMAGE_ID);
      if (args[0] === "ps") {
        return result(0, options.hideForwardersFromDiscovery ? "" : [...remaining.keys()].join("\n"));
      }
      if (args[0] === "container" && args[1] === "inspect") {
        const candidate = remaining.get(args[2]) ?? byId.get(args[2]);
        return candidate ? result(0, JSON.stringify([candidate])) : result(1, "", `No such container: ${args[2]}`);
      }
      if (args[0] === "rm" && args[1] === "-f") {
        const candidate = byId.get(args[2]);
        if (!candidate) return result(1, "", `No such container: ${args[2]}`);
        remaining.delete(candidate.Name?.replace(/^\//, "") ?? "");
        byId.delete(args[2]);
        return result(0);
      }
      if (args[0] === "network" && args[1] === "inspect") {
        // The retired pre-v2 bridge name: current code must never inspect a
        // non-v2 bridge name as ownership or deletion authority.
        if (args[2] === `runfree-ingress-host-${SESSION_TEST_PROJECT.projectId}`) {
          throw new Error("retired bridge name must not be inspected as deletion authority");
        }
        if (options.currentNetworkMissing) {
          return result(1, "", `Error response from daemon: network ${args[2]} not found`);
        }
        const network = ingressHostNetworkInspectFixture(SESSION_TEST_PROJECT.projectId);
        network.Containers = Object.fromEntries(
          [...remaining.values()].flatMap((candidate) => candidate.Id
            ? [[candidate.Id, { Name: candidate.Name?.replace(/^\//, "") }]]
            : []),
        );
        return result(0, JSON.stringify([network]));
      }
      if (args[0] === "network" && args[1] === "rm") return result(0);
      throw new Error(`unexpected docker arguments: ${args.join(" ")}`);
    },
  } as RuntimeIO;
  return { calls, io };
}

test("rebuild removes only a shape-validated ingress forwarder by exact container id", () => {
  const candidate = rebuildIngressForwarder();
  const { calls, io } = rebuildForwarderIo([candidate]);
  const context = {
    env: {},
    project: { paths: {} },
    projectRoot: "/workspace/rebuild-forwarder",
  } as RuntimeContext;

  const plan = planValidatedIngressForwardersForRebuild(
    context,
    io,
    SESSION_TEST_PROJECT.projectId,
  );
  expect(plan.claimedContainerIds).toEqual([candidate.Id]);
  plan.remove();

  expect(calls).toContainEqual(["rm", "-f", candidate.Id]);
  expect(calls).not.toContainEqual(["rm", "-f", candidate.Name?.replace(/^\//, "")]);
});

test("rebuild refuses a label-spoofed ingress endpoint with different image bytes", () => {
  const candidate = rebuildIngressForwarder(
    INGRESS_FORWARDER_IMAGE,
    `sha256:${"d".repeat(64)}`,
  );
  const { calls, io } = rebuildForwarderIo([candidate]);
  const context = {
    env: {},
    project: { paths: {} },
    projectRoot: "/workspace/rebuild-forwarder",
  } as RuntimeContext;

  expect(() => planValidatedIngressForwardersForRebuild(
    context,
    io,
    SESSION_TEST_PROJECT.projectId,
  )).toThrow("does not use the resolved immutable ingress image");
  expect(calls.some((args) => args[0] === "image")).toBe(true);
  expect(calls.some((args) => args[0] === "rm")).toBe(false);
});

test("rebuild refuses a foreign endpoint visible only through the current managed network", () => {
  const candidate = rebuildIngressForwarder();
  candidate.Config = {
    ...candidate.Config,
    Labels: {
      ...candidate.Config?.Labels,
      "io.runfree.project-id": "abcdef012345",
    },
  };
  const { calls, io } = rebuildForwarderIo([candidate], {
    hideForwardersFromDiscovery: true,
  });
  const context = {
    env: {},
    project: { paths: {} },
    projectRoot: "/workspace/rebuild-forwarder",
  } as RuntimeContext;

  expect(() => planValidatedIngressForwardersForRebuild(
    context,
    io,
    SESSION_TEST_PROJECT.projectId,
  )).toThrow(/does not carry this project's exact ingress-forwarder labels/u);

  expect(calls.some((args) => args[0] === "rm")).toBe(false);
  expect(calls.some((args) => args[0] === "network" && args[1] === "rm")).toBe(false);
});

test("teardown refuses a labeled pinned-image candidate without one full container id", () => {
  // Fact 4 of the teardown proof: removal addresses the inspected full 64-hex
  // container ID. Labels and image bytes alone never authorize an rm.
  const candidate = rebuildIngressForwarder();
  candidate.Id = "abc123";
  const { calls, io } = rebuildForwarderIo([candidate], { currentNetworkMissing: true });
  const context = {
    env: {},
    project: { paths: {} },
    projectRoot: "/workspace/rebuild-forwarder",
  } as RuntimeContext;

  expect(() => planValidatedIngressForwarders(
    context,
    io,
    SESSION_TEST_PROJECT.projectId,
  )).toThrow("must have one full Docker container ID");
  expect(calls.some((args) => args[0] === "rm")).toBe(false);
});

test("teardown removes a proven forwarder even when the managed bridge is gone", () => {
  // A missing bridge is not a removal blocker: the container proof stands on
  // its own, and there is simply no network left to clean up.
  const candidate = rebuildIngressForwarder();
  const { calls, io } = rebuildForwarderIo([candidate], { currentNetworkMissing: true });
  const context = {
    env: {},
    project: { paths: {} },
    projectRoot: "/workspace/rebuild-forwarder",
  } as RuntimeContext;

  const plan = planValidatedIngressForwarders(context, io, SESSION_TEST_PROJECT.projectId);
  expect(plan.claimedContainerIds).toEqual([candidate.Id]);
  plan.remove();
  expect(calls).toContainEqual(["rm", "-f", candidate.Id]);
  expect(calls.some((args) => args[0] === "network" && args[1] === "rm")).toBe(false);
});

test("rebuild with no ingress candidates does not require the optional image", () => {
  const { calls, io } = rebuildForwarderIo([]);
  const context = {
    env: {},
    project: { paths: {} },
    projectRoot: "/workspace/rebuild-forwarder",
  } as RuntimeContext;

  const plan = planValidatedIngressForwardersForRebuild(
    context,
    io,
    SESSION_TEST_PROJECT.projectId,
  );

  expect(plan.claimedContainerIds).toEqual([]);
  expect(calls.some((args) => args[0] === "image")).toBe(false);
});

test("planner refuses a live proxy when its effective selection is missing", () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-orphan-proxy-plan-"));
  try {
    const desiredPlan = {
      projectId: SESSION_TEST_PROJECT.projectId,
      composeProjectName: SESSION_TEST_PROJECT.composeProject,
      paths: { stateDir },
      generationV2: sessionGenerationFixture().target,
    } as RuntimePlan;
    expect(planRuntimeUpgradeFromV2State(desiredPlan, {} as RuntimeContext, {
      serviceContainerIds: () => ["a".repeat(64)],
    } as never)).toEqual({
      action: "invalid",
      reason: "live proxy exists without an effective control-plane selection",
      services: [],
    });
  } finally {
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test("planner rolls a compatible proxy restart while a session is active", () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-proxy-rebind-proof-gate-"));
  try {
    const currentTarget = sessionGenerationFixture().target;
    const desiredTarget = {
      ...currentTarget,
      controlPlane: createControlPlaneGenerationV2({
        ...SESSION_TEST_PROJECT,
        proxyImageInputDigest: sha256Digest("proxy-after-proof-gate"),
        controlPlaneTopologyDigest: currentTarget.controlPlane.controlPlaneTopologyDigest,
        admissionContractEpoch: currentTarget.controlPlane.admissionContractEpoch,
      }),
    };
    const manifest = controlPlaneMaterializationFixture({ target: currentTarget });
    const selection = effectiveControlPlaneFixture({ target: currentTarget });
    publishControlPlaneMaterializationV2(stateDir, manifest);
    selectEffectiveControlPlaneV2(stateDir, selection);
    const desiredPlan = {
      projectId: SESSION_TEST_PROJECT.projectId,
      composeProjectName: SESSION_TEST_PROJECT.composeProject,
      paths: { stateDir },
      generationV2: desiredTarget,
    } as RuntimePlan;
    const activeSession = {
      command: "Codex CLI",
      containerTty: "<session-container>",
      name: "active",
      processCount: 1,
      sessionId: "rf-20260827-active1",
    };
    // Increment 6: a COMPATIBLE proxy change (same topology digest, same
    // admission epoch) rolls under live sessions through the durable rebind
    // transaction instead of deferring. Incompatible changes stay blocked;
    // that classification is pinned by upgrade-plan-v2 tests.
    expect(planRuntimeUpgradeFromV2State(desiredPlan, {
      projectRoot: "/workspace/rebind-proof-gate",
      project: { paths: { stateDir } },
      env: {},
    } as RuntimeContext, {
      serviceContainerIds: () => [selection.proxyContainerId],
      activeAgentSessions: () => [activeSession],
    } as never)).toEqual({
      action: "proxy-restart",
      services: ["proxy"],
    });
  } finally {
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

// Under the file-backed source there is no admission journal, so the planner's
// "a session admission is pending" evidence is the lifecycle registry itself:
// a record its owner stamped terminal, or an `allocated` record older than the
// allocation window that never bound a container. Anything else — including a
// young allocation and a bound record with no stamp — is normal state a
// compatible proxy roll must not be refused over.
const PENDING_ADMISSION_REFUSAL = {
  action: "invalid",
  reason: "pending session-admission transaction requires recovery",
  services: [],
} as const;

test.each([
  ["an allocated record older than the allocation window", "stale-allocated", true],
  ["a freshly allocated record", "fresh-allocated", false],
  ["a bound record its owner stamped terminal", "terminal-stamped", true],
  ["a bound record with no stamp", "bound", false],
])("the file-source planner treats %s as pending: %s", (_name, shape, pending) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-files-plan-"));
  try {
    const currentTarget = sessionGenerationFixture().target;
    const desiredTarget = {
      ...currentTarget,
      controlPlane: createControlPlaneGenerationV2({
        ...SESSION_TEST_PROJECT,
        proxyImageInputDigest: sha256Digest("proxy-after-files-plan"),
        controlPlaneTopologyDigest: currentTarget.controlPlane.controlPlaneTopologyDigest,
        admissionContractEpoch: currentTarget.controlPlane.admissionContractEpoch,
      }),
    };
    publishControlPlaneMaterializationV2(
      stateDir,
      controlPlaneMaterializationFixture({ target: currentTarget }),
    );
    const selection = effectiveControlPlaneFixture({ target: currentTarget });
    selectEffectiveControlPlaneV2(stateDir, selection);
    const record = sessionContainerRecordFixture({
      target: currentTarget,
      ...(shape === "stale-allocated" || shape === "fresh-allocated" ? {} : { containerId: "a".repeat(64) }),
      overrides: shape === "fresh-allocated" ? { createdAt: new Date().toISOString() } : {},
    });
    writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, record);
    if (shape === "terminal-stamped") {
      writeSessionHostStatus(stateDir, {
        v: 1,
        sessionId: record.sessionId,
        lastHeartbeatAt: "2026-09-07T12:00:00.000Z",
        aliveUntil: "2026-09-07T12:00:30.000Z",
        served: "served",
        terminal: "revoking",
      });
    }
    const desiredPlan = {
      projectId: SESSION_TEST_PROJECT.projectId,
      composeProjectName: SESSION_TEST_PROJECT.composeProject,
      paths: { stateDir },
      generationV2: desiredTarget,
    } as RuntimePlan;

    expect(planRuntimeUpgradeFromV2State(desiredPlan, {
      projectRoot: "/workspace/files-plan",
      project: { paths: { stateDir } },
      env: {},
    } as RuntimeContext, {
      serviceContainerIds: () => [selection.proxyContainerId],
      activeAgentSessions: () => [],
    } as never)).toEqual(pending
      ? PENDING_ADMISSION_REFUSAL
      : { action: "proxy-restart", services: ["proxy"] });
  } finally {
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

// Ruling D1: a helper runs the bound selected image id when the plan carries
// the prepared session agent for this exact reference, so its removal proof
// compares the immutable id; otherwise it runs the tag.
test("ephemeral helpers run the bound selected image id only when it belongs to the plan's image", () => {
  const selectedAgentImageId = `sha256:${"e".repeat(64)}`;
  const plan = (prepared?: { selectedAgentImageRef: string; selectedAgentImageId: string }) => ({
    activeRuntime: { agentImage: "runfree-agent:abc", ...(prepared ? { preparedSessionAgent: prepared } : {}) },
  }) as unknown as Parameters<typeof ephemeralHelperImage>[0];

  expect(ephemeralHelperImage(plan({ selectedAgentImageRef: "runfree-agent:abc", selectedAgentImageId }))).toBe(selectedAgentImageId);
  expect(ephemeralHelperImage(plan())).toBe("runfree-agent:abc");
  expect(ephemeralHelperImage(plan({ selectedAgentImageRef: "runfree-agent:other", selectedAgentImageId }))).toBe("runfree-agent:abc");
  expect(ephemeralHelperImage(plan({ selectedAgentImageRef: "runfree-agent:abc", selectedAgentImageId: "abc" }))).toBe("runfree-agent:abc");
});
