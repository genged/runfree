import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, test, vi } from "vitest";

import { createRuntimeComponentState, sha256Digest } from "./component-state.ts";
import {
  publishControlPlaneMaterializationV2,
  selectEffectiveControlPlaneV2,
  type ControlPlaneEffectiveSelectionV2,
} from "./component-state-v2.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import {
  ingressForwarderInspectFixture,
  ingressHostNetworkInspectFixture,
  INGRESS_FORWARDER_TEST_IMAGE_ID,
} from "./ingress-forwarder.test-harness.ts";
import { ingressHostNetworkName } from "./ingress-forwarder.ts";
import {
  controlPlaneMaterializationFixture,
  effectiveControlPlaneFixture,
  sessionGenerationFixture,
} from "./session-container.test-harness.ts";
import {
  allocateSessionSourceIpFromExactInternalNetworkBaseline,
  assertControlPlaneInternalParticipantAuthority,
  createControlPlaneInternalParticipantAuthority,
  validateExactInternalNetworkParticipantBaseline,
  type ControlPlaneInternalParticipantAuthority,
  type ExactControlPlaneInternalParticipant,
} from "./session-internal-network-baseline.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { RuntimeContext, RuntimeIO, RuntimeValidationComponents } from "./types.ts";

const SUBNET = "172.31.90.0/24";
const PROXY_IP = "172.31.90.10";
const LEGACY_IP = "172.31.90.11";
const CALLBACK_IP = "172.31.90.12";
const PROXY_ID = "7".repeat(64);
const INTERNAL_NETWORK_ID = "8".repeat(64);
type NetworkParticipant = Readonly<{
  containerId: string;
  containerName: string;
  sourceIp: string;
  endpointId: string;
}>;

function networkInspect(input: Readonly<{
  networkId: string;
  networkName: string;
  subnet?: string;
  participants: readonly NetworkParticipant[];
}>): string {
  return JSON.stringify([{
    Id: input.networkId,
    Name: input.networkName,
    Driver: "bridge",
    Internal: true,
    EnableIPv6: false,
    IPAM: { Config: [{ Subnet: input.subnet ?? SUBNET, Gateway: "172.31.90.1" }] },
    Containers: Object.fromEntries(input.participants.map((participant) => [
      participant.containerId,
      {
        Name: participant.containerName,
        EndpointID: participant.endpointId,
        IPv4Address: `${participant.sourceIp}/24`,
      },
    ])),
  }]);
}

function runtimeComponents(target: ReturnType<typeof sessionGenerationFixture>["target"]): RuntimeValidationComponents {
  return createRuntimeComponentState({
    embeddedAgentImageInputDigest: sha256Digest("embedded-agent"),
    selectedAgentImageInputDigest: sha256Digest("selected-agent"),
    selectedAgentImageKind: "project",
    proxyImageInputDigest: target.controlPlane.proxyImageInputDigest,
    topologyDigest: sha256Digest("runtime-topology"),
    hostHelperDigest: sha256Digest("host-helper"),
  });
}

function lock(): ProjectLifecycleLock {
  return {
    ownerToken: "participant-authority-test",
    assertHeld: vi.fn(),
    release: vi.fn(),
  };
}

function authorityFixture() {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-participant-authority-"));
  const target = sessionGenerationFixture().target;
  const materialization = controlPlaneMaterializationFixture({ target });
  const baseSelection = effectiveControlPlaneFixture({ target });
  const selection: ControlPlaneEffectiveSelectionV2 = {
    ...baseSelection,
    proxyContainerId: PROXY_ID,
    sidecarContainerIds: [],
    networkIds: {
      agentInternal: INTERNAL_NETWORK_ID,
      proxyEgress: "9".repeat(64),
    },
  };
  publishControlPlaneMaterializationV2(stateDir, materialization);
  selectEffectiveControlPlaneV2(stateDir, selection);

  const components = runtimeComponents(target);
  const composeProject = selection.composeProject;
  const projectRoot = "/workspace/project";
  const activeRuntimeRoot = "/runtime/active";
  const network = {
    subnet: SUBNET,
    proxyIp: PROXY_IP,
    agentIp: LEGACY_IP,
    callbackSidecarIp: CALLBACK_IP,
    proxyEgressSubnet: "172.31.91.0/24",
    proxyEgressGateway: "172.31.91.1",
    proxyEgressIp: "172.31.91.10",
  };
  const paths = {
    stateDir,
    controlProxyDir: "/state/control-proxy",
    proxyCaCertDir: "/state/proxy-ca/public",
    proxyCaKeyDir: "/state/proxy-ca/private",
  };
  const project = { config: { version: 4, project: {}, agents: {}, runtime: {} }, paths };
  const plan = {
    projectRoot,
    project,
    projectId: selection.projectId,
    composeProjectName: composeProject,
    paths,
    network,
    generationV2: target,
    components,
    mcpOAuth: {
      callbackPort: 48484,
      callbackUrl: "http://127.0.0.1:48484/callback",
    },
    execution: {
      dockerClientEnv: {},
      composeEnv: {
        RUNFREE_PROJECT_ID: selection.projectId,
        RUNFREE_COMPOSE_PROJECT_NAME: composeProject,
        RUNFREE_PROXY_CA_CERT_DIR: paths.proxyCaCertDir,
        RUNFREE_PROXY_CA_KEY_DIR: paths.proxyCaKeyDir,
        RUNFREE_EFFECTIVE_PROXY_DIR: paths.controlProxyDir,
        RUNFREE_MCP_OPERATION_POLICY_HOST_PATH: "/state/mcp-operation-policy.json",
        RUNFREE_SUBNET: network.subnet,
        RUNFREE_PROXY_IP: network.proxyIp,
        RUNFREE_CONTAINER_IP: network.agentIp,
        RUNFREE_CALLBACK_RELAY_IP: network.callbackSidecarIp,
        RUNFREE_PROXY_EGRESS_SUBNET: network.proxyEgressSubnet,
        RUNFREE_PROXY_EGRESS_GATEWAY: network.proxyEgressGateway,
        RUNFREE_PROXY_EGRESS_IP: network.proxyEgressIp,
        RUNFREE_WRITE_APPROVAL_HOLD_SECONDS: "120",
      },
    },
    activeRuntime: {
      activeRuntimeRoot,
      proxyImage: materialization.proxyImageRef,
    },
    runfreeVersion: selection.runfreeVersion,
  } as unknown as ActiveRuntimePlan;
  const proof: NonNullable<RuntimeContext["validatedRuntime"]> = {
    components: { ...target.controlPlane },
    contractHash: selection.securityContractHash,
    mcpOAuthCallbackPort: plan.mcpOAuth.callbackPort,
    mcpOAuthCallbackTopologyVersion: 2,
    projectId: selection.projectId,
    proofVersion: 4,
    proxyId: PROXY_ID,
  };
  const context = {
    projectRoot,
    project,
    runtimeRoot: activeRuntimeRoot,
    runtimeComponents: components,
    runtimeGenerationV2: target,
    network,
    validatedRuntime: proof,
  } as unknown as RuntimeContext & {
    network: NonNullable<RuntimeContext["network"]>;
    runtimeGenerationV2: NonNullable<RuntimeContext["runtimeGenerationV2"]>;
    validatedRuntime: NonNullable<RuntimeContext["validatedRuntime"]>;
  };
  const lifecycleLock = lock();
  const io = { capture: vi.fn(() => ({ status: 0, stdout: "", stderr: "" })) } as unknown as RuntimeIO;
  const mint = () => createControlPlaneInternalParticipantAuthority({ plan, context, lifecycleLock, io });
  const replaceEffective = (overrides: Partial<ControlPlaneEffectiveSelectionV2>): void => {
    selectEffectiveControlPlaneV2(stateDir, { ...selection, ...overrides });
  };
  return { context, io, lifecycleLock, materialization, mint, plan, proof, replaceEffective, selection };
}

function attachment(
  participant: ExactControlPlaneInternalParticipant,
  index: number,
): NetworkParticipant {
  return { ...participant, endpointId: String(index + 1).repeat(64) };
}

function ingressFixture(value: ReturnType<typeof authorityFixture>) {
  const container = ingressForwarderInspectFixture({
    projectId: value.selection.projectId,
    composeProject: value.selection.composeProject,
    hostPort: "3000",
    purpose: "port",
  });
  const hostNetwork = ingressHostNetworkInspectFixture(value.selection.projectId);
  hostNetwork.Containers = { [String(container.Id)]: { Name: container.Name?.slice(1) } };
  const internalName = `${value.selection.composeProject}_agent_internal`;
  container.NetworkSettings = { ...container.NetworkSettings, Networks: {
    [internalName]: { IPAddress: "172.31.90.20", NetworkID: INTERNAL_NETWORK_ID },
    [ingressHostNetworkName(value.selection.projectId)]: { IPAddress: "172.31.0.3", NetworkID: hostNetwork.Id },
  } };
  vi.mocked(value.io.capture).mockImplementation((_command, args) => {
    let stdout: string;
    if (args[0] === "ps") stdout = args.includes("-a") ? String(container.Name?.slice(1)) : "";
    else if (args[0] === "network" && args[1] === "inspect") stdout = JSON.stringify([hostNetwork]);
    else if (args[0] === "image" && args[1] === "inspect") stdout = INGRESS_FORWARDER_TEST_IMAGE_ID;
    else if (args[0] === "container" && args[1] === "inspect") stdout = JSON.stringify([container]);
    else throw new Error(`unexpected Docker effect: ${args.join(" ")}`);
    return { status: 0, stdout, stderr: "" };
  });
  const participant: NetworkParticipant = {
    containerId: String(container.Id),
    containerName: String(container.Name?.slice(1)),
    sourceIp: "172.31.90.20",
    endpointId: "5".repeat(64),
  };
  return { container, hostNetwork, participant };
}

function inspectForAuthority(
  authority: ControlPlaneInternalParticipantAuthority,
  additional: readonly NetworkParticipant[] = [],
): string {
  return networkInspect({
    networkId: authority.networkId,
    networkName: authority.networkName,
    subnet: authority.subnet,
    participants: [
      ...authority.participants.map(attachment),
      ...additional,
    ],
  });
}

function baseline(authority: ControlPlaneInternalParticipantAuthority) {
  return validateExactInternalNetworkParticipantBaseline({
    participantAuthority: authority,
    networkInspectJson: inspectForAuthority(authority),
    records: [],
  });
}

describe("control-plane internal participant authority", () => {
  test("reserves a shape-verified forwarder's address during session allocation", () => {
    const value = authorityFixture();
    const { participant } = ingressFixture(value);
    const authority = value.mint();
    const observedBaseline = validateExactInternalNetworkParticipantBaseline({
      participantAuthority: authority,
      networkInspectJson: inspectForAuthority(authority, [participant]),
      records: [],
    });
    expect(allocateSessionSourceIpFromExactInternalNetworkBaseline({ baseline: observedBaseline }))
      .toBe("172.31.90.21");
  });

  test.each([
    { containerId: "e".repeat(64) },
    { containerName: "foreign-forwarder" },
    { sourceIp: "172.31.90.22" },
  ])("rejects a network endpoint that differs from the inspected forwarder: %j", (drift) => {
    const value = authorityFixture();
    const { participant } = ingressFixture(value);
    const authority = value.mint();
    expect(() => validateExactInternalNetworkParticipantBaseline({
      participantAuthority: authority,
      networkInspectJson: inspectForAuthority(authority, [{ ...participant, ...drift }]),
      records: [],
    })).toThrow("ingress forwarder does not have its exact Docker internal-network endpoint");
  });

  test.each([
    ["foreign image", "does not use the resolved immutable ingress image", (value: ReturnType<typeof ingressFixture>) => { value.container.Image = `sha256:${"0".repeat(64)}`; }],
    ["privilege", "must not run privileged", (value: ReturnType<typeof ingressFixture>) => { value.container.HostConfig = { ...value.container.HostConfig, Privileged: true }; }],
    ["command", "must run the known socat forwarder command", (value: ReturnType<typeof ingressFixture>) => { value.container.Config = { ...value.container.Config, Cmd: ["-c", "sleep 3600"] }; }],
    ["publication", "must publish only 127.0.0.1:3000/tcp", (value: ReturnType<typeof ingressFixture>) => { value.container.HostConfig = { ...value.container.HostConfig, PortBindings: { "3000/tcp": [{ HostIp: "0.0.0.0", HostPort: "3000" }] } }; }],
    ["host bridge", "network isolation shape does not match", (value: ReturnType<typeof ingressFixture>) => { value.hostNetwork.Internal = true; }],
    ["stopped forwarder", "must be running", (value: ReturnType<typeof ingressFixture>) => { value.container.State = { ...value.container.State, Running: false }; }],
    ["foreign project", "does not carry this project's exact ingress-forwarder labels", (value: ReturnType<typeof ingressFixture>) => { value.container.Config = { ...value.container.Config, Labels: { ...value.container.Config?.Labels, "io.runfree.project-id": "fedcba987654" } }; }],
  ] as const)("refuses a forwarder with %s before any Docker mutation", (_label, diagnostic, mutate) => {
    const value = authorityFixture();
    mutate(ingressFixture(value));
    expect(() => value.mint()).toThrow(diagnostic);
    expect(vi.mocked(value.io.capture).mock.calls.every(([, args]) => args[0] === "ps" || args[1] === "inspect")).toBe(true);
    // Removing the refused utility reclaims admission; no poisoned authority
    // survives the failed observation.
    vi.mocked(value.io.capture).mockReturnValue({ status: 0, stdout: "", stderr: "" });
    expect(allocateSessionSourceIpFromExactInternalNetworkBaseline({ baseline: baseline(value.mint()) }))
      .toBe("172.31.90.20");
  });

  test("derives the exact proxy participant from validated durable authority", () => {
    const value = authorityFixture();
    const authority = value.mint();

    expect(authority).toEqual({
      version: 1,
      projectId: value.selection.projectId,
      composeProject: value.selection.composeProject,
      controlPlaneGenerationDigest: value.selection.controlPlaneGenerationDigest,
      controlPlaneMaterializationDigest: value.selection.controlPlaneMaterializationDigest,
      admissionContractEpoch: value.selection.admissionContractEpoch,
      networkId: INTERNAL_NETWORK_ID,
      networkName: `${value.selection.composeProject}_agent_internal`,
      subnet: SUBNET,
      ingressParticipants: [],
      participants: [
        {
          role: "request-proxy",
          containerId: PROXY_ID,
          containerName: `${value.selection.composeProject}-proxy-1`,
          sourceIp: PROXY_IP,
        },
      ],
    });
    expect(() => assertControlPlaneInternalParticipantAuthority(authority)).not.toThrow();
    expect(allocateSessionSourceIpFromExactInternalNetworkBaseline({ baseline: baseline(authority) }))
      .toBe("172.31.90.20");
  });

  test.each([
    ["plan project", (value: ReturnType<typeof authorityFixture>) => { value.plan.projectId = "fedcba987654"; }],
    ["Compose project", (value: ReturnType<typeof authorityFixture>) => { value.plan.composeProjectName = "runfree-fedcba987654"; }],
    ["generation", (value: ReturnType<typeof authorityFixture>) => {
      value.plan.generationV2.controlPlane.controlPlaneGenerationDigest = sha256Digest("other-generation");
    }],
    ["admission epoch", (value: ReturnType<typeof authorityFixture>) => {
      value.plan.generationV2.controlPlane.admissionContractEpoch += 1;
    }],
    ["proxy image", (value: ReturnType<typeof authorityFixture>) => {
      value.plan.activeRuntime.proxyImage = "runfree/proxy:other";
    }],
    ["context project root", (value: ReturnType<typeof authorityFixture>) => {
      value.context.projectRoot = "/workspace/other";
    }],
    ["context state root", (value: ReturnType<typeof authorityFixture>) => {
      value.context.project.paths.stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-other-state-"));
    }],
    ["active runtime root", (value: ReturnType<typeof authorityFixture>) => {
      value.context.runtimeRoot = "/runtime/other";
    }],
    ["runtime generation", (value: ReturnType<typeof authorityFixture>) => {
      value.context.runtimeGenerationV2 = {
        ...value.context.runtimeGenerationV2,
        controlPlane: { ...value.context.runtimeGenerationV2.controlPlane, admissionContractEpoch: 99 },
      };
    }],
    ["subnet", (value: ReturnType<typeof authorityFixture>) => { value.context.network.subnet = "172.31.92.0/24"; }],
    ["proxy IP", (value: ReturnType<typeof authorityFixture>) => { value.context.network.proxyIp = "172.31.90.30"; }],
    ["legacy IP", (value: ReturnType<typeof authorityFixture>) => { value.context.network.agentIp = "172.31.90.31"; }],
    ["proof version", (value: ReturnType<typeof authorityFixture>) => {
      value.context.validatedRuntime.proofVersion = 3 as 4;
    }],
    ["proof project", (value: ReturnType<typeof authorityFixture>) => {
      value.context.validatedRuntime.projectId = "fedcba987654";
    }],
    ["proxy ID", (value: ReturnType<typeof authorityFixture>) => {
      value.context.validatedRuntime.proxyId = "4".repeat(64);
    }],
    ["security contract", (value: ReturnType<typeof authorityFixture>) => {
      value.context.validatedRuntime.contractHash = sha256Digest("other-contract");
    }],
    ["runtime components", (value: ReturnType<typeof authorityFixture>) => {
      value.context.validatedRuntime.components = {
        ...value.context.validatedRuntime.components,
        controlPlaneTopologyDigest: sha256Digest("other-topology"),
      };
    }],
    ["callback port", (value: ReturnType<typeof authorityFixture>) => {
      value.context.validatedRuntime.mcpOAuthCallbackPort += 1;
    }],
    ["callback topology", (value: ReturnType<typeof authorityFixture>) => {
      value.context.validatedRuntime.mcpOAuthCallbackTopologyVersion = 1 as 2;
    }],
  ] as const)("rejects a cross-plan or proof mutation of %s", (_label, mutate) => {
    const value = authorityFixture();
    mutate(value);
    expect(value.mint).toThrow();
  });

  // The Compose mcp_callback relay participant is retired post-cutover (the MCP
  // OAuth callback is a per-session ingress forwarder, not an internal-network
  // participant), so its callback-mutation rejection cases retire with it.

  test.each([
    ["effective proxy ID", { proxyContainerId: "5".repeat(64) }],
    ["effective security hash", { securityContractHash: sha256Digest("other-contract") }],
  ] as const)("rejects a cross-effective mutation of %s", (_label, override) => {
    const value = authorityFixture();
    value.replaceEffective(override as Partial<ControlPlaneEffectiveSelectionV2>);
    expect(value.mint).toThrow("durable effective selection");
  });

  test("invalidates minted authority when durable effective identity changes", () => {
    const value = authorityFixture();
    const authority = value.mint();
    for (const override of [
      { proxyContainerId: "5".repeat(64) },
      { networkIds: { agentInternal: "5".repeat(64), proxyEgress: "9".repeat(64) } },
    ]) {
      value.replaceEffective(override);
      expect(() => assertControlPlaneInternalParticipantAuthority(authority))
        .toThrow("changed after participant authority was minted");
      value.replaceEffective({});
    }
  });

  test("rejects copied authority and plain participant arrays before parsing Docker evidence", () => {
    const authority = authorityFixture().mint();
    for (const forged of [
      { ...authority },
      authority.participants,
      [...authority.participants],
    ]) {
      expect(() => validateExactInternalNetworkParticipantBaseline({
        participantAuthority: forged as ControlPlaneInternalParticipantAuthority,
        networkInspectJson: "{malformed-docker-json",
        records: [],
      })).toThrow("was not minted by the canonical builder");
    }
  });
});

describe("exact internal-network participant baseline", () => {
  test("rejects unknown participants and mutations of every trusted endpoint field", () => {
    const authority = authorityFixture().mint();
    const exact = authority.participants.map(attachment);
    const unknown: NetworkParticipant = {
      containerId: "e".repeat(64),
      containerName: "unknown-peer",
      sourceIp: "172.31.90.13",
      endpointId: "f".repeat(64),
    };
    expect(() => validateExactInternalNetworkParticipantBaseline({
      participantAuthority: authority,
      networkInspectJson: networkInspect({
        networkId: authority.networkId,
        networkName: authority.networkName,
        participants: [...exact, unknown],
      }),
      records: [],
    })).toThrow("unknown participant");

    // Post-cutover the only fixed internal participant is the request proxy; the
    // legacy shared agent and Compose callback relay are retired.
    for (const role of ["request-proxy"] as const) {
      const index = authority.participants.findIndex((participant) => participant.role === role);
      for (const mutation of [
        { containerId: "f".repeat(64) },
        { containerName: "forged-container-name" },
        { sourceIp: "172.31.90.99" },
      ]) {
        const participants = exact.map((participant, candidateIndex) => (
          candidateIndex === index ? { ...participant, ...mutation } : participant
        ));
        expect(() => validateExactInternalNetworkParticipantBaseline({
          participantAuthority: authority,
          networkInspectJson: networkInspect({
            networkId: authority.networkId,
            networkName: authority.networkName,
            participants,
          }),
          records: [],
        })).toThrow();
      }
    }
  });

  test("rejects wrong network identity, name, and subnet", () => {
    const authority = authorityFixture().mint();
    const participants = authority.participants.map(attachment);
    expect(() => validateExactInternalNetworkParticipantBaseline({
      participantAuthority: authority,
      networkInspectJson: networkInspect({
        networkId: "f".repeat(64),
        networkName: authority.networkName,
        participants,
      }),
      records: [],
    })).toThrow("different network");
    expect(() => validateExactInternalNetworkParticipantBaseline({
      participantAuthority: authority,
      networkInspectJson: networkInspect({
        networkId: authority.networkId,
        networkName: "runfree-other_agent_internal",
        participants,
      }),
      records: [],
    })).toThrow("different network");
    expect(() => validateExactInternalNetworkParticipantBaseline({
      participantAuthority: authority,
      networkInspectJson: networkInspect({
        networkId: authority.networkId,
        networkName: authority.networkName,
        subnet: "172.31.91.0/24",
        participants,
      }),
      records: [],
    })).toThrow("effective topology");
  });

  test("rejects a copied baseline object", () => {
    const authority = authorityFixture().mint();
    const exactBaseline = baseline(authority);
    expect(() => allocateSessionSourceIpFromExactInternalNetworkBaseline({
      baseline: { ...exactBaseline } as typeof exactBaseline,
    })).toThrow("was not minted");
  });
});
