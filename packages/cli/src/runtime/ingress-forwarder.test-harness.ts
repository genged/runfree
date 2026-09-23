import type { IngressPurpose } from "./container-inventory.ts";
import {
  INGRESS_FORWARDER_COMMAND,
  INGRESS_FORWARDER_ENTRYPOINT,
  INGRESS_FORWARDER_IMAGE,
  ingressForwarderName,
  ingressHostNetworkName,
} from "./ingress-forwarder.ts";
import type { DockerContainerInspect, DockerNetworkInspect } from "./types.ts";

export const INGRESS_FORWARDER_TEST_IMAGE_ID = `sha256:${"e".repeat(64)}`;
export const INGRESS_HOST_NETWORK_TEST_ID = "d".repeat(64);

export function ingressHostNetworkInspectFixture(projectId: string): DockerNetworkInspect {
  return {
    Attachable: false,
    Containers: {},
    Driver: "bridge",
    EnableIPv4: true,
    EnableIPv6: false,
    Id: INGRESS_HOST_NETWORK_TEST_ID,
    IPAM: {
      Config: [{ Gateway: "172.31.0.1", Subnet: "172.31.0.0/16" }],
      Driver: "default",
      Options: {},
    },
    Ingress: false,
    Internal: false,
    Labels: {
      "io.runfree.managed": "true",
      "io.runfree.network-role": "ingress-host",
      "io.runfree.project-id": projectId,
    },
    Name: ingressHostNetworkName(projectId),
    Options: {},
    Scope: "local",
  };
}

export function ingressForwarderInspectFixture(input: Readonly<{
  composeProject: string;
  containerId?: string;
  hostPort: string;
  projectId: string;
  purpose: IngressPurpose;
  target?: string;
  targetPort?: string;
}>): DockerContainerInspect {
  const containerId = input.containerId ?? "f".repeat(64);
  const hostNetwork = ingressHostNetworkName(input.projectId);
  const internalNetwork = `${input.composeProject}_agent_internal`;
  const bindings = { [`${input.hostPort}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: input.hostPort }] };
  return {
    Config: {
      Cmd: [...INGRESS_FORWARDER_COMMAND],
      Entrypoint: [INGRESS_FORWARDER_ENTRYPOINT],
      Env: [
        `INGRESS_HOST_PORT=${input.hostPort}`,
        `INGRESS_TARGET=${input.target ?? "172.30.0.20"}`,
        `INGRESS_TARGET_PORT=${input.targetPort ?? input.hostPort}`,
      ],
      Image: INGRESS_FORWARDER_IMAGE,
      Labels: {
        "io.runfree.container-role": "ingress-forwarder",
        "io.runfree.ingress-purpose": input.purpose,
        "io.runfree.project-id": input.projectId,
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
    Id: containerId,
    Image: INGRESS_FORWARDER_TEST_IMAGE_ID,
    Mounts: [],
    Name: `/${ingressForwarderName(input.projectId, input.purpose, input.hostPort)}`,
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

export function missingContainerResult(target: string): Readonly<{ status: 1; stdout: ""; stderr: string }> {
  return { status: 1, stdout: "", stderr: `Error: No such container: ${target}` };
}

export function missingNetworkResult(target: string): Readonly<{ status: 1; stdout: ""; stderr: string }> {
  return { status: 1, stdout: "", stderr: `Error response from daemon: network ${target} not found` };
}
