import type { RuntimePlan } from "./plan.ts";

export const CONTROL_PLANE_TOPOLOGY_PROJECTION_VERSION_V2 = 1 as const;

type ControlPlaneMountV2 = Readonly<{
  type: "bind" | "volume";
  source: string;
  target: string;
  readOnly: boolean;
}>;

type ControlPlaneTmpfsV2 = Readonly<{
  target: string;
  mode: "0700" | "0755";
  uid: 0 | 1001;
  gid: 0 | 1001;
}>;

type ControlPlaneNetworkAttachmentV2 = Readonly<{
  network: "agent_internal" | "proxy_egress";
  ipv4Address?: string;
  gatewayPriority?: 0 | 1;
}>;

type ControlPlaneNetworkV2 = Readonly<{
  logicalName: "agent_internal" | "proxy_egress";
  runtimeName: string;
  driver: "bridge";
  internal: boolean;
  enableIpv6: false;
  subnet?: string;
  gateway?: string;
  driverOptions: Readonly<Record<string, string>>;
}>;

export type ControlPlaneTopologyProjectionV2 = Readonly<{
  schemaVersion: 2;
  projectionVersion: typeof CONTROL_PLANE_TOPOLOGY_PROJECTION_VERSION_V2;
  projectId: string;
  composeProject: string;
  admission: Readonly<{
    identityMode: "source-ip-v1";
    registryPath: "/run/runfree-sessions";
  }>;
  proxy: Readonly<{
    imageRole: "proxy";
    init: true;
    user: "image-default-root-entrypoint";
    privileged: false;
    readOnlyRootFilesystem: false;
    publishedPorts: readonly [];
    capabilityAdd: readonly ["NET_ADMIN"];
    capabilityDrop: readonly ["NET_RAW"];
    securityOptions: readonly ["no-new-privileges:true"];
    mounts: readonly ControlPlaneMountV2[];
    tmpfs: readonly ControlPlaneTmpfsV2[];
    environment: Readonly<Record<string, string>>;
    networks: readonly ControlPlaneNetworkAttachmentV2[];
  }>;
  // The fixed control plane carries no utility containers: the MCP OAuth
  // callback and VNC paths run as per-session ingress forwarders outside the
  // Compose generation.
  utilities: Readonly<Record<never, never>>;
  controlOwnedNamedVolumes: readonly [Readonly<{
    logicalName: "runfree-oauth-state";
    runtimeName: string;
  }>];
  networks: readonly ControlPlaneNetworkV2[];
}>;

export type ControlPlaneTopologyRuntimePlanV2 = Pick<
  RuntimePlan,
  "composeProjectName" | "mcpOAuth" | "network" | "projectId"
> & {
  execution: Pick<RuntimePlan["execution"], "composeEnv">;
  paths: Pick<RuntimePlan["paths"], "controlProxyDir" | "proxyCaCertDir" | "proxyCaKeyDir">;
};

const PROJECT_ID_PATTERN = /^[a-f0-9]{12}$/;
const COMPOSE_RESOURCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;

function sortedRecord(entries: Readonly<Record<string, string>>): Readonly<Record<string, string>> {
  return Object.freeze(
    Object.fromEntries(Object.entries(entries).sort(([left], [right]) => left.localeCompare(right))),
  );
}

function requireBoundedText(value: string | undefined, label: string): string {
  if (value === undefined || value.length === 0 || value.length > 4096 || /[\x00\r\n]/.test(value)) {
    throw new Error(`control-plane topology ${label} must be non-empty bounded text`);
  }
  return value;
}

function requireIpv4(value: string, label: string): string {
  const parts = value.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d+$/.test(part) || Number(part) > 255)) {
    throw new Error(`control-plane topology ${label} must be an exact IPv4 address`);
  }
  return value;
}

function requireIpv4Cidr(value: string, label: string): string {
  const match = /^(.*)\/(\d{1,2})$/.exec(value);
  if (!match || Number(match[2]) < 1 || Number(match[2]) > 32) {
    throw new Error(`control-plane topology ${label} must be an IPv4 CIDR`);
  }
  requireIpv4(match[1], label);
  return value;
}

function _requirePort(value: number, label: string): number {
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error(`control-plane topology ${label} must be a TCP port`);
  }
  return value;
}

function runtimeResourceName(composeProject: string, logicalName: string): string {
  if (!COMPOSE_RESOURCE_PATTERN.test(composeProject) || !COMPOSE_RESOURCE_PATTERN.test(logicalName)) {
    throw new Error("control-plane topology has an invalid Compose resource identity");
  }
  return `${composeProject}_${logicalName}`;
}

function requiredEnvironment(
  plan: ControlPlaneTopologyRuntimePlanV2,
  name: string,
  expected?: string,
): string {
  const value = requireBoundedText(plan.execution.composeEnv[name], `environment ${name}`);
  if (expected !== undefined && value !== expected) {
    throw new Error(`control-plane topology environment ${name} contradicts the runtime plan`);
  }
  return value;
}

function validatePlan(plan: ControlPlaneTopologyRuntimePlanV2): void {
  if (!PROJECT_ID_PATTERN.test(plan.projectId)
    || plan.composeProjectName !== `runfree-${plan.projectId}`) {
    throw new Error("control-plane topology has invalid project identity");
  }
  requireBoundedText(plan.paths.controlProxyDir, "effective proxy path");
  requireBoundedText(plan.paths.proxyCaCertDir, "public CA path");
  requireBoundedText(plan.paths.proxyCaKeyDir, "private CA path");
  requireIpv4Cidr(plan.network.subnet, "internal subnet");
  requireIpv4(plan.network.proxyIp, "proxy internal IP");
  requireIpv4(plan.network.agentIp, "reserved agent position IP");
  requireIpv4(plan.network.callbackSidecarIp, "reserved callback position IP");
  requireIpv4Cidr(plan.network.proxyEgressSubnet, "proxy egress subnet");
  requireIpv4(plan.network.proxyEgressGateway, "proxy egress gateway");
  requireIpv4(plan.network.proxyEgressIp, "proxy egress IP");
  if (new Set([
    plan.network.proxyIp,
    plan.network.agentIp,
    plan.network.callbackSidecarIp,
  ]).size !== 3) {
    throw new Error("control-plane topology internal participant IPs must be distinct");
  }

  requiredEnvironment(plan, "RUNFREE_PROJECT_ID", plan.projectId);
  requiredEnvironment(plan, "RUNFREE_COMPOSE_PROJECT_NAME", plan.composeProjectName);
  requiredEnvironment(plan, "RUNFREE_PROXY_CA_CERT_DIR", plan.paths.proxyCaCertDir);
  requiredEnvironment(plan, "RUNFREE_PROXY_CA_KEY_DIR", plan.paths.proxyCaKeyDir);
  requiredEnvironment(plan, "RUNFREE_EFFECTIVE_PROXY_DIR", plan.paths.controlProxyDir);
  requiredEnvironment(plan, "RUNFREE_SUBNET", plan.network.subnet);
  requiredEnvironment(plan, "RUNFREE_PROXY_IP", plan.network.proxyIp);
  requiredEnvironment(plan, "RUNFREE_CONTAINER_IP", plan.network.agentIp);
  requiredEnvironment(plan, "RUNFREE_PROXY_EGRESS_SUBNET", plan.network.proxyEgressSubnet);
  requiredEnvironment(plan, "RUNFREE_PROXY_EGRESS_GATEWAY", plan.network.proxyEgressGateway);
  requiredEnvironment(plan, "RUNFREE_PROXY_EGRESS_IP", plan.network.proxyEgressIp);
  const holdSeconds = Number(requiredEnvironment(plan, "RUNFREE_WRITE_APPROVAL_HOLD_SECONDS"));
  if (!Number.isInteger(holdSeconds) || holdSeconds < 5 || holdSeconds > 300) {
    throw new Error("control-plane topology write approval hold must be between 5 and 300 seconds");
  }
}

function proxyMounts(
  plan: ControlPlaneTopologyRuntimePlanV2,
  oauthVolume: string,
): readonly ControlPlaneMountV2[] {
  const mounts: ControlPlaneMountV2[] = [
    { type: "bind", source: plan.paths.controlProxyDir, target: "/app/runfree-effective", readOnly: true },
    {
      type: "bind",
      source: requiredEnvironment(plan, "RUNFREE_MCP_OPERATION_POLICY_HOST_PATH"),
      target: "/app/proxy/mcp-operation-policy.json",
      readOnly: true,
    },
    { type: "bind", source: plan.paths.proxyCaKeyDir, target: "/ca/private", readOnly: false },
    { type: "bind", source: plan.paths.proxyCaCertDir, target: "/ca/public", readOnly: false },
    { type: "volume", source: oauthVolume, target: "/run/runfree-oauth", readOnly: false },
  ];
  return Object.freeze(mounts.sort((left, right) => left.target.localeCompare(right.target)));
}

function proxyTmpfs(): readonly ControlPlaneTmpfsV2[] {
  const mounts: ControlPlaneTmpfsV2[] = [
    { target: "/run/runfree-approvals/decisions", mode: "0755", uid: 0, gid: 0 },
    { target: "/run/runfree-approvals/pending", mode: "0700", uid: 1001, gid: 1001 },
    { target: "/run/runfree-proxy-audit", mode: "0755", uid: 0, gid: 0 },
    { target: "/run/runfree-proxy-audit-spool", mode: "0755", uid: 1001, gid: 1001 },
    { target: "/run/runfree-proxy-secrets", mode: "0700", uid: 1001, gid: 1001 },
    { target: "/run/runfree-proxy-status", mode: "0755", uid: 0, gid: 0 },
    { target: "/run/runfree-sessions", mode: "0755", uid: 0, gid: 0 },
  ];
  return Object.freeze(mounts.sort((left, right) => left.target.localeCompare(right.target)));
}

function proxyEnvironment(
  plan: ControlPlaneTopologyRuntimePlanV2,
): Readonly<Record<string, string>> {
  return sortedRecord({
    CA_CERT: "/ca/public/proxy-ca.crt",
    CA_KEY: "/ca/private/proxy-ca.key",
    PROXY_AUDIT_MARKER_PATH: "/run/runfree-proxy-audit/active.json",
    PROXY_AUDIT_RESOLVED_HOSTS_PATH: "/run/runfree-proxy-audit/resolved-hosts.json",
    PROXY_AUDIT_SPOOL_PATH: "/run/runfree-proxy-audit-spool/spool.txt",
    PROXY_SECRET_DIR: "/run/runfree-proxy-secrets",
    RUNFREE_APPROVALS_DECISIONS_DIR: "/run/runfree-approvals/decisions",
    RUNFREE_APPROVALS_PENDING_DIR: "/run/runfree-approvals/pending",
    RUNFREE_EFFECTIVE_PROXY_ROOT: "/app/runfree-effective",
    RUNFREE_MCP_OPERATION_POLICY_PATH: "/app/proxy/mcp-operation-policy.json",
    RUNFREE_OAUTH_STATE_DIR: "/run/runfree-oauth",
    RUNFREE_PROJECT_ID: plan.projectId,
    RUNFREE_PROXY_EGRESS_GATEWAY: plan.network.proxyEgressGateway,
    RUNFREE_PROXY_EGRESS_IP: plan.network.proxyEgressIp,
    RUNFREE_PROXY_EGRESS_SUBNET: plan.network.proxyEgressSubnet,
    RUNFREE_PROXY_IP: plan.network.proxyIp,
    RUNFREE_SESSION_IDENTITY_MODE: "source-ip-v1",
    RUNFREE_SESSION_REGISTRY_DIR: "/run/runfree-sessions",
    // The one admission source: per-session files under the registry directory
    // above. The proxy refuses to start without this key, so a control plane
    // materialized by a pre-cutover CLI cannot be adopted by this one.
    RUNFREE_SESSION_ADMISSION_SOURCE: "files",
    RUNFREE_SUBNET: plan.network.subnet,
    RUNFREE_WRITE_APPROVAL_HOLD_SECONDS: requiredEnvironment(
      plan,
      "RUNFREE_WRITE_APPROVAL_HOLD_SECONDS",
    ),
  });
}

function controlNetworks(plan: ControlPlaneTopologyRuntimePlanV2): readonly ControlPlaneNetworkV2[] {
  const networks: ControlPlaneNetworkV2[] = [
    {
      logicalName: "agent_internal",
      runtimeName: runtimeResourceName(plan.composeProjectName, "agent_internal"),
      driver: "bridge",
      internal: true,
      enableIpv6: false,
      subnet: plan.network.subnet,
      driverOptions: { "com.docker.network.bridge.inhibit_ipv4": "true" },
    },
    {
      logicalName: "proxy_egress",
      runtimeName: runtimeResourceName(plan.composeProjectName, "proxy_egress"),
      driver: "bridge",
      internal: false,
      enableIpv6: false,
      subnet: plan.network.proxyEgressSubnet,
      gateway: plan.network.proxyEgressGateway,
      driverOptions: {},
    },
  ];
  return Object.freeze(networks.sort((left, right) => left.logicalName.localeCompare(right.logicalName)));
}

export function controlPlaneTopologyProjectionV2(
  plan: ControlPlaneTopologyRuntimePlanV2,
): ControlPlaneTopologyProjectionV2 {
  validatePlan(plan);
  const oauthVolume = runtimeResourceName(plan.composeProjectName, "runfree-oauth-state");
  return {
    schemaVersion: 2,
    projectionVersion: CONTROL_PLANE_TOPOLOGY_PROJECTION_VERSION_V2,
    projectId: plan.projectId,
    composeProject: plan.composeProjectName,
    admission: {
      identityMode: "source-ip-v1",
      registryPath: "/run/runfree-sessions",
    },
    proxy: {
      imageRole: "proxy",
      init: true,
      user: "image-default-root-entrypoint",
      privileged: false,
      readOnlyRootFilesystem: false,
      publishedPorts: [],
      capabilityAdd: ["NET_ADMIN"],
      capabilityDrop: ["NET_RAW"],
      securityOptions: ["no-new-privileges:true"],
      mounts: proxyMounts(plan, oauthVolume),
      tmpfs: proxyTmpfs(),
      environment: proxyEnvironment(plan),
      networks: [
        { network: "agent_internal", ipv4Address: plan.network.proxyIp, gatewayPriority: 0 },
        { network: "proxy_egress", ipv4Address: plan.network.proxyEgressIp, gatewayPriority: 1 },
      ],
    },
    utilities: {},
    controlOwnedNamedVolumes: [{
      logicalName: "runfree-oauth-state",
      runtimeName: oauthVolume,
    }],
    networks: controlNetworks(plan),
  };
}
