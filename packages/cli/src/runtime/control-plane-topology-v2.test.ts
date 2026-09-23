import { describe, expect, test } from "vitest";

import type { RuntimeNetwork } from "../network.ts";
import {
  controlPlaneTopologyProjectionV2,
  type ControlPlaneTopologyRuntimePlanV2,
} from "./control-plane-topology-v2.ts";
import { runtimeTopologyGenerationV2 } from "./topology-digest-v2.ts";
import type { TopologyDigestJson } from "./topology-digest.ts";

const PROJECT_ID = "0123456789ab";
const COMPOSE_PROJECT = `runfree-${PROJECT_ID}`;

function network(overrides: Partial<RuntimeNetwork> = {}): RuntimeNetwork {
  return {
    subnet: "172.30.40.0/24",
    proxyIp: "172.30.40.10",
    agentIp: "172.30.40.11",
    callbackSidecarIp: "172.30.40.12",
    proxyEgressSubnet: "172.30.41.0/24",
    proxyEgressGateway: "172.30.41.1",
    proxyEgressIp: "172.30.41.10",
    ...overrides,
  };
}

function plan(overrides: {
  callback?: boolean;
  composeEnv?: Record<string, string | undefined>;
  network?: RuntimeNetwork;
  renderedCompose?: string;
} = {}): ControlPlaneTopologyRuntimePlanV2 & { renderedCompose: string } {
  const selectedNetwork = overrides.network ?? network();
  const paths = {
    controlProxyDir: "/host/state/control/effective/proxy",
    proxyCaCertDir: "/host/state/proxy-ca/public",
    proxyCaKeyDir: "/host/state/proxy-ca/private",
  };
  return {
    projectId: PROJECT_ID,
    composeProjectName: COMPOSE_PROJECT,
    network: selectedNetwork,
    paths,
    mcpOAuth: {
      callbackPort: 47123,
      callbackUrl: "http://127.0.0.1:47123/callback",
    },
    execution: {
      composeEnv: {
        RUNFREE_PROJECT_ID: PROJECT_ID,
        RUNFREE_COMPOSE_PROJECT_NAME: COMPOSE_PROJECT,
        RUNFREE_PROXY_CA_CERT_DIR: paths.proxyCaCertDir,
        RUNFREE_PROXY_CA_KEY_DIR: paths.proxyCaKeyDir,
        RUNFREE_EFFECTIVE_PROXY_DIR: paths.controlProxyDir,
        RUNFREE_MCP_OPERATION_POLICY_HOST_PATH: "/host/state/mcp-operation-policy.json",
        RUNFREE_SUBNET: selectedNetwork.subnet,
        RUNFREE_PROXY_IP: selectedNetwork.proxyIp,
        RUNFREE_CONTAINER_IP: selectedNetwork.agentIp,
        RUNFREE_CALLBACK_RELAY_IP: selectedNetwork.callbackSidecarIp,
        RUNFREE_PROXY_EGRESS_SUBNET: selectedNetwork.proxyEgressSubnet,
        RUNFREE_PROXY_EGRESS_GATEWAY: selectedNetwork.proxyEgressGateway,
        RUNFREE_PROXY_EGRESS_IP: selectedNetwork.proxyEgressIp,
        RUNFREE_WRITE_APPROVAL_HOLD_SECONDS: "120",
        ...overrides.composeEnv,
      },
    },
    renderedCompose: overrides.renderedCompose ?? "ignored: true",
  };
}

function digestStructure(value: unknown): TopologyDigestJson {
  return JSON.parse(JSON.stringify(value)) as TopologyDigestJson;
}

describe("control-plane topology projection v2", () => {
  test("binds the exact proxy trust-boundary shape and per-session admission identity", () => {
    const projection = controlPlaneTopologyProjectionV2(plan());

    expect(projection.admission).toEqual({
      identityMode: "source-ip-v1",
      registryPath: "/run/runfree-sessions",
    });
    expect(projection.proxy).toMatchObject({
      imageRole: "proxy",
      init: true,
      user: "image-default-root-entrypoint",
      privileged: false,
      readOnlyRootFilesystem: false,
      publishedPorts: [],
      capabilityAdd: ["NET_ADMIN"],
      capabilityDrop: ["NET_RAW"],
      securityOptions: ["no-new-privileges:true"],
      networks: [
        { network: "agent_internal", ipv4Address: "172.30.40.10", gatewayPriority: 0 },
        { network: "proxy_egress", ipv4Address: "172.30.41.10", gatewayPriority: 1 },
      ],
    });
    expect(projection.proxy.mounts).toEqual([
      {
        type: "bind",
        source: "/host/state/mcp-operation-policy.json",
        target: "/app/proxy/mcp-operation-policy.json",
        readOnly: true,
      },
      {
        type: "bind",
        source: "/host/state/control/effective/proxy",
        target: "/app/runfree-effective",
        readOnly: true,
      },
      { type: "bind", source: "/host/state/proxy-ca/private", target: "/ca/private", readOnly: false },
      { type: "bind", source: "/host/state/proxy-ca/public", target: "/ca/public", readOnly: false },
      {
        type: "volume",
        source: `${COMPOSE_PROJECT}_runfree-oauth-state`,
        target: "/run/runfree-oauth",
        readOnly: false,
      },
    ]);
    expect(projection.proxy.tmpfs).toEqual([
      { target: "/run/runfree-approvals/decisions", mode: "0755", uid: 0, gid: 0 },
      { target: "/run/runfree-approvals/pending", mode: "0700", uid: 1001, gid: 1001 },
      { target: "/run/runfree-proxy-audit", mode: "0755", uid: 0, gid: 0 },
      { target: "/run/runfree-proxy-audit-spool", mode: "0755", uid: 1001, gid: 1001 },
      { target: "/run/runfree-proxy-secrets", mode: "0700", uid: 1001, gid: 1001 },
      { target: "/run/runfree-proxy-status", mode: "0755", uid: 0, gid: 0 },
      { target: "/run/runfree-sessions", mode: "0755", uid: 0, gid: 0 },
    ]);
    expect(projection.proxy.environment).toMatchObject({
      RUNFREE_EFFECTIVE_PROXY_ROOT: "/app/runfree-effective",
      RUNFREE_SESSION_IDENTITY_MODE: "source-ip-v1",
      RUNFREE_SESSION_REGISTRY_DIR: "/run/runfree-sessions",
      RUNFREE_WRITE_APPROVAL_HOLD_SECONDS: "120",
      PROXY_SECRET_DIR: "/run/runfree-proxy-secrets",
      CA_KEY: "/ca/private/proxy-ca.key",
    });
    // No fixed-agent identity reaches the proxy: agents are admitted per
    // session by source IP.
    expect(projection.proxy.environment).not.toHaveProperty("RUNFREE_AGENT_IP");
    expect(projection.proxy.environment).not.toHaveProperty("RUNFREE_LEGACY_AGENT_SOURCE_IP");
    expect(projection.controlOwnedNamedVolumes).toEqual([{
      logicalName: "runfree-oauth-state",
      runtimeName: `${COMPOSE_PROJECT}_runfree-oauth-state`,
    }]);
    expect(projection.networks).toEqual([
      {
        logicalName: "agent_internal",
        runtimeName: `${COMPOSE_PROJECT}_agent_internal`,
        driver: "bridge",
        internal: true,
        enableIpv6: false,
        subnet: "172.30.40.0/24",
        driverOptions: { "com.docker.network.bridge.inhibit_ipv4": "true" },
      },
      {
        logicalName: "proxy_egress",
        runtimeName: `${COMPOSE_PROJECT}_proxy_egress`,
        driver: "bridge",
        internal: false,
        enableIpv6: false,
        subnet: "172.30.41.0/24",
        gateway: "172.30.41.1",
        driverOptions: {},
      },
    ]);
    expect(projection.utilities).toEqual({});
  });

  test("feeds only descriptor-backed changes into the control-plane digest", () => {
    const baselinePlan = plan({ renderedCompose: "malformed and irrelevant" });
    const sameDescriptors = plan({ renderedCompose: "completely different bytes" });
    const baselineProjection = controlPlaneTopologyProjectionV2(baselinePlan);
    expect(controlPlaneTopologyProjectionV2(sameDescriptors)).toEqual(baselineProjection);

    const digest = (projection: unknown) => runtimeTopologyGenerationV2({
      compose: "",
      interpolationValues: {},
      controlPlane: { structure: digestStructure(projection), runtimeSignatures: {} },
      sessionTemplate: { structure: { version: 1 }, runtimeSignatures: {} },
    });
    const changedNetwork = network({ proxyEgressGateway: "172.30.41.2" });
    const changed = digest(controlPlaneTopologyProjectionV2(plan({ network: changedNetwork })));
    const baseline = digest(baselineProjection);

    expect(changed.controlPlaneTopologyDigest).not.toBe(baseline.controlPlaneTopologyDigest);
    expect(changed.sessionTemplateDigest).toBe(baseline.sessionTemplateDigest);
  });

  test("mints the one admission source into every proxy environment it projects", () => {
    // The proxy refuses to start without it, so a projection that omitted it
    // would materialize a control plane that can never come up.
    expect(controlPlaneTopologyProjectionV2(plan()).proxy.environment.RUNFREE_SESSION_ADMISSION_SOURCE)
      .toBe("files");
  });

  test("fails closed for contradictory plan inputs before producing a projection", () => {
    expect(() => controlPlaneTopologyProjectionV2(plan({
      composeEnv: { RUNFREE_PROXY_IP: "172.30.40.99" },
    }))).toThrow("contradicts the runtime plan");
    expect(() => controlPlaneTopologyProjectionV2(plan({
      composeEnv: { RUNFREE_MCP_OPERATION_POLICY_HOST_PATH: undefined },
    }))).toThrow("must be non-empty bounded text");
    expect(() => controlPlaneTopologyProjectionV2(plan({
      composeEnv: { RUNFREE_WRITE_APPROVAL_HOLD_SECONDS: "301" },
    }))).toThrow("between 5 and 300 seconds");
    expect(() => controlPlaneTopologyProjectionV2(plan({
      network: network({ callbackSidecarIp: "172.30.40.10" }),
    }))).toThrow("participant IPs must be distinct");
  });
});
