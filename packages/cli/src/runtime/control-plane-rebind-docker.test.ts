import { expect, test, vi } from "vitest";
import { REBIND_ATTEMPT_LABEL, REBIND_TRANSACTION_LABEL } from "./container-inventory.ts";
import { inspectRebindCreation } from "./control-plane-rebind-docker.ts";
import type { ControlPlaneRebindTransaction } from "./control-plane-rebind.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import type { RuntimeIO } from "./types.ts";

function fixture() {
  const projectId = "a".repeat(12);
  const composeProject = `runfree-${projectId}`;
  const proxyId = "b".repeat(64);
  const transactionId = "c".repeat(64);
  const proxy = { Id: proxyId, Image: "sha256:approved", State: { Running: true }, Config: { Labels: {
    "io.runfree.project-id": projectId, "io.runfree.container-role": "proxy",
    "com.docker.compose.project": composeProject, "com.docker.compose.service": "proxy",
    [REBIND_TRANSACTION_LABEL]: transactionId, [REBIND_ATTEMPT_LABEL]: "0",
  } } };
  const networks = ["agent_internal", "proxy_egress"].map((logical, index) => ({
    Id: String(index + 1).repeat(64), Name: `${composeProject}_${logical}`,
    Labels: { "com.docker.compose.project": composeProject }, Internal: index === 0, EnableIPv6: false,
    Containers: { [proxyId]: { IPv4Address: "172.30.0.2/24" } },
  }));
  let unavailable = false;
  const capture = vi.fn((_command: string, args: string[]) => {
    if (unavailable) return { status: 124, stdout: "", stderr: "deadline" };
    if (args[0] === "ps") return { status: 0, stdout: proxyId, stderr: "" };
    if (args[0] === "container" && args[1] === "inspect") return { status: 0, stdout: JSON.stringify([proxy]), stderr: "" };
    if (args[0] === "network" && args[1] === "inspect") return { status: 0, stdout: JSON.stringify(networks), stderr: "" };
    throw new Error(`unexpected Docker effect: ${args.join(" ")}`);
  });
  const input = {
    plan: { projectId, composeProjectName: composeProject, execution: { dockerClientEnv: {} }, network: { proxyIp: "172.30.0.2" } } as ActiveRuntimePlan,
    transaction: { transactionId, phase: "prepared", recovery: { candidateAttempt: 0 },
      oldControlPlane: { proxyContainerId: "d".repeat(64), proxyImageId: "sha256:old",
        networkIds: { agentInternal: networks[0].Id, proxyEgress: networks[1].Id } },
      candidateMaterialization: { proxyImageId: "sha256:approved" } } as ControlPlaneRebindTransaction,
    io: { capture } as unknown as RuntimeIO, assertAuthority: vi.fn(() => {}),
  };
  return { input, proxy, networks, capture, setUnavailable: (value: boolean) => { unavailable = value; } };
}

test.each(["image", "network", "marker", "endpoint", "unavailable", "fence"] as const)(
  "an interrupted creation with %s failure refuses before any mutation and accepts repaired evidence", (failure) => {
    const state = fixture();
    const original = structuredClone(state.proxy);
    if (failure === "image") state.proxy.Image = "sha256:foreign";
    if (failure === "network") state.networks[0].Id = "e".repeat(64);
    if (failure === "marker") state.proxy.Config.Labels[REBIND_TRANSACTION_LABEL] = "f".repeat(64);
    if (failure === "endpoint") state.networks[0].Containers["e".repeat(64)] = { IPv4Address: "172.30.0.2/24" };
    if (failure === "unavailable") state.setUnavailable(true);
    if (failure === "fence") state.input.assertAuthority.mockImplementation(() => { throw new Error("fence lost"); });
    expect(() => inspectRebindCreation(state.input)).toThrow();
    expect(state.proxy.State.Running).toBe(true);
    expect(state.capture.mock.calls.every(([, args]) => args[0] === "ps" || args[1] === "inspect")).toBe(true);
    if (failure === "fence") expect(state.capture).not.toHaveBeenCalled();
    Object.assign(state.proxy, original);
    state.networks[0].Id = "1".repeat(64);
    delete state.networks[0].Containers["e".repeat(64)];
    state.setUnavailable(false);
    state.input.assertAuthority.mockImplementation(() => {});
    expect(inspectRebindCreation(state.input)).toBe("recover");
    state.proxy.State.Running = false;
    expect(inspectRebindCreation(state.input)).toEqual({ stoppedProxyId: state.proxy.Id });
  },
);
