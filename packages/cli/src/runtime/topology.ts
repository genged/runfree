import { REBIND_ATTEMPT_LABEL, REBIND_TRANSACTION_LABEL } from "./container-inventory.ts";

import { resolveRuntimeNetwork } from "../network.ts";
import { runfreeLog } from "../warnings.ts";
import { runDockerExecRoot } from "./attach.ts";
import { dockerClientEnvOptions, parseDockerJson, serviceContainerId } from "./docker.ts";
import { composeProjectName, projectHash } from "./env.ts";
import {
  LINUX_CAPABILITY_BITS,
  bridgeInhibitIpv4Option,
  containerLogs,
  dockerNetworkGateways,
  dockerOptionIsTrue,
  validateProxyFirewall,
} from "./probes.ts";
import {
  applyDenyProbeBatchResult,
  denyProbeBatchScript,
  type DenyProbeSpec,
  failDenyProbeBatch,
} from "./deny-probe-batch.ts";
import { mcpOAuthCallbackPort } from "./mcp.ts";
import { validateInternalNetworkParticipants } from "./utility-containers.ts";
import type {
  DockerContainerInspect,
  DockerNetworkInspect,
  DockerPortBindings,
  RuntimeContext,
  RuntimeIO,
} from "./types.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import {
  observeDenyByDefaultViaFirewallV1,
  type DenyByDefaultObservationV1,
} from "./control-plane-deny-proof.ts";
import { EPHEMERAL_HELPER_FENCE_REQUIRED, runEphemeralHelper, type EphemeralHelperFence } from "./ephemeral-helper.ts";
import { ephemeralHelperAddress } from "./session-container-reconciliation.ts";

export type RuntimeTopologyIssue = {
  code: string;
  severity: "error";
  message: string;
  detail?: string;
};

export type TopologyAssertionInventoryEntry = {
  code: string;
  source: "docker-inspect" | "docker-network" | "exec-probe" | "proxy-probe" | "nftables-proof" | "git-proof";
};

export type RuntimeTopologyOptions = {
  progress?: boolean;
  verbose?: boolean;
  expectedProxyId?: string;
  onBoundaryViolation?(): void;
  /** Required for the deny-probe helper; without it the probes do not run. */
  helperFence?: EphemeralHelperFence;
  /** The image the helper runs: the bound selected image id when known. */
  helperImage?: string;
};

export type RuntimeTopologyValidationResult = Readonly<{
  issues: RuntimeTopologyIssue[];
  denyByDefaultBaseObservation?: DenyByDefaultObservationV1;
}>;

export const REQUIRED_TOPOLOGY_ASSERTIONS: readonly TopologyAssertionInventoryEntry[] = [
  { code: "agent-container-exists", source: "docker-inspect" },
  { code: "proxy-container-exists", source: "docker-inspect" },
  { code: "agent-network-count", source: "docker-inspect" },
  { code: "agent-network-unapproved-container", source: "docker-inspect" },
  { code: "agent-ip-matches-plan", source: "docker-inspect" },
  { code: "proxy-egress-ip-matches-plan", source: "docker-inspect" },
  { code: "internal-network-internal", source: "docker-network" },
  { code: "internal-network-ipv6-disabled", source: "docker-network" },
  { code: "internal-network-gateway-free", source: "docker-network" },
  { code: "proxy-egress-network-subnet", source: "docker-network" },
  { code: "agent-host-ports-denied", source: "docker-inspect" },
  { code: "agent-net-admin-dropped", source: "docker-inspect" },
  { code: "agent-net-raw-dropped", source: "docker-inspect" },
  { code: "proxy-net-admin-shape", source: "docker-inspect" },
  { code: "proxy-net-raw-dropped", source: "docker-inspect" },
  { code: "agent-pid1-identity", source: "exec-probe" },
  { code: "agent-no-new-privileges", source: "exec-probe" },
  { code: "git-layout-container-proof", source: "git-proof" },
  { code: "agent-proxy-reachability", source: "proxy-probe" },
  { code: "agent-direct-tcp-denied", source: "exec-probe" },
  { code: "agent-direct-dns-denied", source: "exec-probe" },
  { code: "agent-default-route-denied", source: "exec-probe" },
  { code: "agent-host-gateway-denied", source: "exec-probe" },
  { code: "agent-gateway-reachability-denied", source: "exec-probe" },
  { code: "raw-connect-disallowed-host-denied", source: "proxy-probe" },
  { code: "raw-connect-non-443-denied", source: "proxy-probe" },
  { code: "proxy-egress-route", source: "exec-probe" },
  { code: "proxy-nftables-shape", source: "nftables-proof" },
  { code: "proxy-fixed-agent-ingress", source: "nftables-proof" },
  { code: "proxy-dns-root-only", source: "exec-probe" },
  { code: "proxy-privileged-command-denied", source: "exec-probe" },
  { code: "utility-vnc-forwarder-shape", source: "docker-inspect" },
  { code: "utility-ingress-forwarder-shape", source: "docker-inspect" },
  { code: "utility-mcp-callback-relay-shape", source: "docker-inspect" },
];

export function formatTopologyIssues(issues: readonly RuntimeTopologyIssue[]): string[] {
  return issues.map((issue) => `[${issue.code}] ${issue.message}${issue.detail ? `: ${issue.detail}` : ""}`);
}

function codeForTopologyMessage(message: string): string {
  if (message.startsWith("agent container")) return "agent-container-exists";
  if (message.startsWith("proxy container")) return "proxy-container-exists";
  if (message.startsWith("agent networks") || message.includes("agent_internal must contain agent") || message.includes("agent_internal must contain proxy")) return "agent-network-count";
  if (message.startsWith("agent_internal contains unapproved container")) return "agent-network-unapproved-container";
  if (message.startsWith("agent internal IP")) return "agent-ip-matches-plan";
  if (message.startsWith("proxy egress IP")) return "proxy-egress-ip-matches-plan";
  if (message.includes("agent_internal must be an internal")) return "internal-network-internal";
  if (message.includes("IPv6 disabled") || message.includes("must not assign IPv6")) return "internal-network-ipv6-disabled";
  if (message.includes(bridgeInhibitIpv4Option())) return "internal-network-gateway-free";
  if (message.startsWith("proxy_egress subnet") || message.startsWith("proxy_egress gateway")) return "proxy-egress-network-subnet";
  if (message.includes("publish host ports")) return "agent-host-ports-denied";
  if (message.includes("agent must not add NET_ADMIN") || message.includes("agent must drop NET_ADMIN")) return "agent-net-admin-dropped";
  if (message.includes("agent must not add NET_RAW") || message.includes("agent must drop NET_RAW") || message.includes("agent effective capabilities")) return "agent-net-raw-dropped";
  if (message.includes("proxy must add NET_ADMIN") || message.includes("proxy PID 1 bounding capabilities must include NET_ADMIN")) return "proxy-net-admin-shape";
  if (message.includes("proxy must not add NET_RAW") || message.includes("proxy must drop NET_RAW") || message.includes("proxy PID 1 bounding capabilities must exclude NET_RAW")) return "proxy-net-raw-dropped";
  if (message.includes("PID 1")) return "agent-pid1-identity";
  if (message.includes("NoNewPrivs") || message.includes("no-new-privileges")) return "agent-no-new-privileges";
  if (message.startsWith("linked worktree")) return "git-layout-container-proof";
  if (message.startsWith("agent proxy reachability")) return "agent-proxy-reachability";
  if (message.startsWith("agent direct TCP") || message.startsWith("agent-position direct TCP")) return "agent-direct-tcp-denied";
  if (message.startsWith("agent direct external DNS") || message.startsWith("agent-position direct external DNS")) return "agent-direct-dns-denied";
  if (message.startsWith("agent default IPv4 route") || message.startsWith("agent-position default IPv4 route")) return "agent-default-route-denied";
  if (message.startsWith("agent Docker host gateway lookup") || message.startsWith("agent-position Docker host gateway lookup")) return "agent-host-gateway-denied";
  if (message.startsWith("agent Docker bridge gateway") || message.startsWith("agent-position Docker bridge gateway")) return "agent-gateway-reachability-denied";
  if (message.startsWith("proxy raw CONNECT disallowed host")) return "raw-connect-disallowed-host-denied";
  if (message.startsWith("proxy raw CONNECT non-HTTPS port")) return "raw-connect-non-443-denied";
  if (message.startsWith("proxy egress route") || message.includes("proxy default egress route")) return "proxy-egress-route";
  if (message.includes("fixed agent") || message.includes("agent ingress")) return "proxy-fixed-agent-ingress";
  if (message.includes("proxy root Docker DNS") || message.includes("proxy server UID DNS")) return "proxy-dns-root-only";
  if (message.includes("proxy server UID nftables") || message.includes("proxy server UID route administration")) return "proxy-privileged-command-denied";
  if (message.startsWith("vnc utility")) return "utility-vnc-forwarder-shape";
  if (message.startsWith("ingress forwarder")) return "utility-ingress-forwarder-shape";
  if (message.startsWith("MCP OAuth callback relay")) return "utility-mcp-callback-relay-shape";
  return "proxy-nftables-shape";
}

function structuredIssues(messages: readonly string[]): RuntimeTopologyIssue[] {
  return messages.map((message) => ({
    code: codeForTopologyMessage(message),
    severity: "error",
    message,
  }));
}

function topologyValidationResult(
  messages: readonly string[],
  observation?: DenyByDefaultObservationV1,
): RuntimeTopologyValidationResult {
  const issues = structuredIssues(messages);
  return Object.freeze({
    issues,
    ...(issues.length === 0 && observation ? { denyByDefaultBaseObservation: observation } : {}),
  });
}

function topologyProgress(options: RuntimeTopologyOptions, message: string): void {
  if (options.progress === true || options.verbose === true) {
    runfreeLog(`topology: ${message}`);
  }
}

function topologyVerbose(options: RuntimeTopologyOptions, message: string): void {
  if (options.verbose === true) {
    runfreeLog(`verbose: topology: ${message}`);
  }
}

function compactDiagnostic(value: string): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= 500) return compact;
  return `${compact.slice(0, 497)}...`;
}

function stringList(value: string[] | null | undefined): string[] {
  return Array.isArray(value) ? value : [];
}

function hasCapability(value: string[] | null | undefined, capability: string): boolean {
  return stringList(value).some((entry) => entry.toUpperCase().replace(/^CAP_/, "") === capability);
}

function isPortNumber(value: string | undefined): boolean {
  if (!value || !/^\d+$/.test(value)) return false;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 1 && parsed <= 65535;
}

function hasUnsafePublishedPortBindings(value: DockerPortBindings | null | undefined, allowLoopbackTcp: boolean): boolean {
  return Object.entries(value ?? {}).some(([containerPort, binding]) => {
    if (binding == null) return false;
    if (Array.isArray(binding)) {
      return binding.some((entry) => {
        if (
          allowLoopbackTcp
          && containerPort.endsWith("/tcp")
          && entry.HostIp === "127.0.0.1"
          && isPortNumber(entry.HostPort)
        ) {
          return false;
        }
        return true;
      });
    }
    return true;
  });
}

function containerNetworks(container: DockerContainerInspect): Record<string, { Gateway?: string; IPAddress?: string; GlobalIPv6Address?: string }> {
  return container.NetworkSettings?.Networks ?? {};
}


function assertExactNetworks(
  issues: string[],
  label: string,
  container: DockerContainerInspect,
  expected: string[],
): void {
  const actual = Object.keys(containerNetworks(container)).sort();
  const desired = [...expected].sort();
  if (actual.join("\0") !== desired.join("\0")) {
    issues.push(`${label} networks must be exactly ${desired.join(", ")}; got ${actual.join(", ") || "<none>"}`);
  }
}

function validateContainerShape(
  issues: string[],
  label: string,
  container: DockerContainerInspect,
  expectedNetworks: string[],
  options: { allowLoopbackTcpHostPorts?: boolean } = {},
): void {
  assertExactNetworks(issues, label, container, expectedNetworks);
  const transaction = container.Config?.Labels?.[REBIND_TRANSACTION_LABEL];
  const attempt = container.Config?.Labels?.[REBIND_ATTEMPT_LABEL];
  if (transaction !== undefined || attempt !== undefined) {
    if (label !== "proxy" || !/^[a-f0-9]{64}$/u.test(transaction ?? "") || !/^(0|[1-9][0-9]*)$/u.test(attempt ?? "")
      || !Number.isSafeInteger(Number(attempt))) issues.push(`${label} has invalid reserved proxy replacement labels`);
  }
  if (container.HostConfig?.NetworkMode === "host") {
    issues.push(`${label} must not use host networking`);
  }
  if (
    hasUnsafePublishedPortBindings(container.HostConfig?.PortBindings, options.allowLoopbackTcpHostPorts === true)
    || hasUnsafePublishedPortBindings(container.NetworkSettings?.Ports, options.allowLoopbackTcpHostPorts === true)
  ) {
    issues.push(options.allowLoopbackTcpHostPorts === true
      ? `${label} must only publish TCP host ports on 127.0.0.1`
      : `${label} must not publish host ports`);
  }
}

function validateProxyCapabilities(
  issues: string[],
  context: RuntimeContext,
  io: RuntimeIO,
  proxy: DockerContainerInspect,
  proxyId: string,
  onBoundaryViolation?: () => void,
): void {
  const initialIssues = issues.length;
  const capAdd = proxy.HostConfig?.CapAdd;
  const capDrop = proxy.HostConfig?.CapDrop;
  if (!hasCapability(capAdd, "NET_ADMIN")) {
    issues.push("proxy must add NET_ADMIN for the root firewall supervisor");
  }
  if (hasCapability(capAdd, "NET_RAW")) {
    issues.push("proxy must not add NET_RAW");
  }
  if (!hasCapability(capDrop, "NET_RAW")) {
    issues.push("proxy must drop NET_RAW");
  }
  if (issues.length > initialIssues) onBoundaryViolation?.();

  const result = runDockerExecRoot(context, io, proxyId, ["awk", "/CapBnd/ { print $2 }", "/proc/1/status"]);
  if (result.status !== 0) {
    const detail = compactDiagnostic(`${result.stderr}\n${result.stdout}`);
    issues.push(`proxy PID 1 capability inspection failed${detail ? `: ${detail}` : ""}`);
    return;
  }
  const capBnd = result.stdout.trim();
  if (!/^[0-9a-fA-F]+$/.test(capBnd)) {
    issues.push(`proxy PID 1 capability inspection returned invalid CapBnd: ${capBnd || "<empty>"}`);
    return;
  }
  const mask = BigInt(`0x${capBnd}`);
  if ((mask & (1n << LINUX_CAPABILITY_BITS.NET_ADMIN)) === 0n) {
    onBoundaryViolation?.();
    issues.push("proxy PID 1 bounding capabilities must include NET_ADMIN for firewall setup");
  }
  if ((mask & (1n << LINUX_CAPABILITY_BITS.NET_RAW)) !== 0n) {
    onBoundaryViolation?.();
    issues.push("proxy PID 1 bounding capabilities must exclude NET_RAW");
  }
}

function _parseKeyValueLines(stdout: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of stdout.split(/\r?\n/)) {
    const index = line.indexOf("=");
    if (index <= 0) continue;
    result[line.slice(0, index)] = line.slice(index + 1);
  }
  return result;
}

function containerStateIssue(label: string, container: DockerContainerInspect): string | undefined {
  if (container.State?.Running !== false) return undefined;
  const status = container.State.Status ?? "not running";
  const exitCode = Number.isInteger(container.State.ExitCode) ? ` exit=${container.State.ExitCode}` : "";
  const oom = container.State.OOMKilled ? " oom-killed" : "";
  const error = container.State.Error ? ` error=${container.State.Error}` : "";
  return `${label} container is ${status}${exitCode}${oom}${error}`;
}

function isActiveRuntimePlan(value: RuntimeContext | ActiveRuntimePlan): value is ActiveRuntimePlan {
  return "activeRuntime" in value;
}

function topologyContext(input: RuntimeContext | ActiveRuntimePlan): RuntimeContext {
  if (!isActiveRuntimePlan(input)) return input;
  return {
    projectRoot: input.projectRoot,
    project: input.project,
    runtimeRoot: input.activeRuntime.activeRuntimeRoot,
    baseRuntimeRoot: input.baseRuntimeRoot,
    agentImage: input.activeRuntime.agentImage,
    dependencyOverlayPlan: input.dependencyOverlays,
    gitRepositoryShape: input.gitRepositoryShape,
    gitLayoutPlan: input.gitLayout,
    env: input.execution.adminEnvProvider.resolveChildEnv(),
    network: input.network,
  };
}

export function validateRuntimeTopology(plan: ActiveRuntimePlan, io: RuntimeIO, options?: RuntimeTopologyOptions): RuntimeTopologyIssue[];
export function validateRuntimeTopology(context: RuntimeContext, io: RuntimeIO, options?: RuntimeTopologyOptions): RuntimeTopologyIssue[];
export function validateRuntimeTopology(
  input: RuntimeContext | ActiveRuntimePlan,
  io: RuntimeIO,
  options: RuntimeTopologyOptions = {},
): RuntimeTopologyIssue[] {
  return validateRuntimeTopologyWithProof(input, io, options).issues;
}

export function validateRuntimeTopologyWithProof(
  input: RuntimeContext | ActiveRuntimePlan,
  io: RuntimeIO,
  options: RuntimeTopologyOptions = {},
): RuntimeTopologyValidationResult {
  const context = topologyContext(input);
  const messages: string[] = [];
  let denyByDefaultBaseObservation: DenyByDefaultObservationV1 | undefined;
  const project = isActiveRuntimePlan(input) ? input.composeProjectName : composeProjectName(context.projectRoot);
  const internalNetwork = `${project}_agent_internal`;
  const egressNetwork = `${project}_proxy_egress`;
  topologyProgress(options, "locating runtime containers");
  topologyVerbose(options, `looking up Compose service containers for ${project}`);
  // The per-session runtime has no shared agent service. Startup validation
  // covers the fixed control plane (proxy + optional callback) and the agent
  // *position* on the internal network via an ephemeral helper; each session's
  // own container is validated by admission's running proof, not here.
  const proxyId = serviceContainerId(project, "proxy", context, io);
  const runtimeNetwork = isActiveRuntimePlan(input)
    ? input.network
    : context.network ?? resolveRuntimeNetwork(context.projectRoot, context.project, [], { persist: false });
  const projectId = isActiveRuntimePlan(input) ? input.projectId : projectHash(context.projectRoot);

  if (!proxyId) messages.push("proxy container was not found after runtime startup");
  if (!proxyId) return topologyValidationResult(messages);
  if (options.expectedProxyId !== undefined && proxyId !== options.expectedProxyId) {
    messages.push("proxy container changed after firewall readiness; retry runtime validation");
    return topologyValidationResult(messages);
  }

  topologyProgress(options, "inspecting runtime containers");
  topologyVerbose(options, `docker inspect ${proxyId}`);
  const inspect = parseDockerJson<DockerContainerInspect[]>(
    io.capture("docker", ["inspect", proxyId], dockerClientEnvOptions(context)),
    "docker inspect runtime containers",
  );
  if (!inspect || inspect.length !== 1) {
    messages.push("could not inspect runtime containers");
    return topologyValidationResult(messages);
  }
  const proxy = inspect[0];

  const beforeShape = messages.length;
  validateContainerShape(messages, "proxy", proxy, [internalNetwork, egressNetwork]);
  if (messages.length > beforeShape) options.onBoundaryViolation?.();

  const proxyStateIssue = containerStateIssue("proxy", proxy);
  if (proxyStateIssue) {
    const logs = containerLogs(context, io, proxyId);
    messages.push(`${proxyStateIssue}${logs ? `; recent logs: ${logs}` : ""}`);
  }

  const proxyInternal = containerNetworks(proxy)[internalNetwork];
  const proxyEgress = containerNetworks(proxy)[egressNetwork];
  if (proxyInternal?.IPAddress !== runtimeNetwork.proxyIp) {
    messages.push(`proxy internal IP must be ${runtimeNetwork.proxyIp}; got ${proxyInternal?.IPAddress || "<none>"}`);
  }
  if (!proxyEgress?.IPAddress) {
    messages.push("proxy must have an IPv4 address on proxy_egress");
  }
  if (proxyInternal?.GlobalIPv6Address || proxyEgress?.GlobalIPv6Address) {
    messages.push("runtime networks must not assign IPv6 addresses");
  }

  topologyProgress(options, "inspecting internal Docker network");
  topologyVerbose(options, `docker network inspect ${internalNetwork}`);
  const networkInspect = parseDockerJson<DockerNetworkInspect[]>(
    io.capture("docker", ["network", "inspect", internalNetwork], dockerClientEnvOptions(context)),
    "docker network inspect agent_internal",
  );
  const network = networkInspect?.[0];
  if (!network) {
    messages.push("could not inspect agent_internal network");
  } else {
    const beforeNetwork = messages.length;
    if (network.Internal !== true) messages.push("agent_internal must be an internal Docker network");
    if (network.EnableIPv6 === true) messages.push("agent_internal must have IPv6 disabled");
    if (!dockerOptionIsTrue(network.Options?.[bridgeInhibitIpv4Option()])) {
      messages.push(`agent_internal must set ${bridgeInhibitIpv4Option()}=true to remove the host bridge gateway`);
    }
    if (messages.length > beforeNetwork) options.onBoundaryViolation?.();
    const attachedEntries = Object.entries(network.Containers ?? {});
    const attachedIds = attachedEntries.map(([id]) => id);
    topologyVerbose(options, `inspecting ${attachedIds.length} internal-network participant container(s)`);
    const attachedInspect = attachedIds.length === 0
      ? []
      : parseDockerJson<DockerContainerInspect[]>(
        io.capture("docker", ["inspect", ...attachedIds], dockerClientEnvOptions(context)),
        "docker inspect agent_internal participants",
      );
    if (!attachedInspect || attachedInspect.length !== attachedIds.length) {
      messages.push("could not inspect agent_internal participants");
    } else {
      const participantIssues = validateInternalNetworkParticipants({
        attached: attachedInspect,
        callbackRelay: {
          port: String(mcpOAuthCallbackPort(context.projectRoot)),
        },
        internalNetwork,
        projectId,
        proxy,
      });
      for (const issue of participantIssues) {
        messages.push(issue.detail ? `${issue.message}: ${issue.detail}` : issue.message);
      }
    }
  }

  topologyProgress(options, "inspecting proxy egress Docker network");
  topologyVerbose(options, `docker network inspect ${egressNetwork}`);
  const egressNetworkInspect = parseDockerJson<DockerNetworkInspect[]>(
    io.capture("docker", ["network", "inspect", egressNetwork], dockerClientEnvOptions(context)),
    "docker network inspect proxy_egress",
  );
  const inspectedEgressNetwork = egressNetworkInspect?.[0];
  if (!inspectedEgressNetwork) {
    messages.push("could not inspect proxy_egress network");
  } else {
    if (inspectedEgressNetwork.EnableIPv6 === true) messages.push("proxy_egress must have IPv6 disabled");
    const egressSubnets = inspectedEgressNetwork.IPAM?.Config?.map((config) => config.Subnet).filter(Boolean) ?? [];
    const egressGateways = dockerNetworkGateways(inspectedEgressNetwork);
    if (!egressSubnets.includes(runtimeNetwork.proxyEgressSubnet)) {
      messages.push(`proxy_egress subnet must be ${runtimeNetwork.proxyEgressSubnet}; got ${egressSubnets.join(", ") || "<none>"}`);
    }
    if (!egressGateways.includes(runtimeNetwork.proxyEgressGateway)) {
      messages.push(`proxy_egress gateway must be ${runtimeNetwork.proxyEgressGateway}; got ${egressGateways.join(", ") || "<none>"}`);
    }
  }

  if (proxyStateIssue) {
    return topologyValidationResult(messages);
  }

  topologyProgress(options, "checking proxy capabilities and egress route");
  topologyVerbose(options, "inspecting proxy PID 1 capability bounding set");
  validateProxyCapabilities(messages, context, io, proxy, proxyId, options.onBoundaryViolation);

  if (proxyEgress?.IPAddress !== runtimeNetwork.proxyEgressIp) {
    messages.push(`proxy egress IP must be ${runtimeNetwork.proxyEgressIp}; got ${proxyEgress?.IPAddress || "<none>"}`);
  }

  if (isActiveRuntimePlan(input) && network?.Id !== undefined) {
    // Per-session confinement of the agent *position*: the same direct-egress
    // denial probes, run in ONE ephemeral helper on agent_internal rather than
    // one container per probe (L3). These prove properties of the network
    // topology (internal, no default route, no host gateway), which hold for
    // any container in that position, so co-location changes nothing about
    // what each probe proves; each session's own capability/PID1/no-new-privs
    // confinement is proven by admission's running proof, not here.
    topologyProgress(options, "checking agent-position confinement");
    const gatewayCandidates = Array.from(new Set([
      ...dockerNetworkGateways(network),
    ].filter((gateway): gateway is string => Boolean(gateway))));
    const probeSpecs: DenyProbeSpec[] = [
      { label: "agent-position direct TCP egress", command: "timeout 3 bash -c '</dev/tcp/1.1.1.1/443'" },
      { label: "agent-position direct external DNS", command: "dig +time=2 +tries=1 @1.1.1.1 example.com" },
      { label: "agent-position default IPv4 route", command: "ip -4 route show default | grep -q ." },
      { label: "agent-position Docker host gateway lookup", command: "getent hosts host.docker.internal" },
    ];
    for (const gateway of gatewayCandidates) {
      // Gateway addresses come from the daemon's network inspection and are
      // interpolated into a shell probe; refuse anything that is not a bare
      // IPv4 literal rather than passing it to bash.
      if (!/^\d{1,3}(\.\d{1,3}){3}$/u.test(gateway)) {
        messages.push(`agent-position Docker bridge gateway ${gateway} TCP reachability denial probe did not run: gateway is not IPv4`);
        continue;
      }
      probeSpecs.push({
        label: `agent-position Docker bridge gateway ${gateway} TCP reachability`,
        command: `timeout 3 bash -c '</dev/tcp/${gateway}/80'`,
      });
    }
    for (const spec of probeSpecs) topologyVerbose(options, `${spec.label} denial probe (batched)`);
    // The helper runs the untrusted agent image on agent_internal, so it is
    // pinned to the reserved block below the session pool instead of taking
    // Docker's dynamic pick, which could be a session's address. The attached
    // addresses come from the network inspection above: no extra Docker call.
    let helperIp: string | undefined;
    try {
      helperIp = ephemeralHelperAddress(
        {
          subnet: runtimeNetwork.subnet,
          proxyIp: runtimeNetwork.proxyIp,
          agentIp: runtimeNetwork.agentIp,
          callbackSidecarIp: runtimeNetwork.callbackSidecarIp,
          gateways: dockerNetworkGateways(network),
        },
        Object.values(network.Containers ?? {})
          .map((endpoint) => endpoint.IPv4Address?.split("/")[0] ?? "")
          .filter((address) => address !== ""),
      );
    } catch (error) {
      failDenyProbeBatch(messages, probeSpecs, error instanceof Error ? error.message : String(error));
    }
    if (helperIp !== undefined && options.helperFence === undefined) {
      failDenyProbeBatch(messages, probeSpecs, EPHEMERAL_HELPER_FENCE_REQUIRED);
    } else if (helperIp !== undefined) {
      const batch = runEphemeralHelper(context, io, {
        purpose: "deny-probe",
        projectId,
        image: options.helperImage ?? input.activeRuntime.agentImage,
        user: "1000:1000",
        networkId: network.Id as string,
        ip: helperIp,
        command: ["bash", "-c", denyProbeBatchScript(probeSpecs)],
      }, options.helperFence);
      applyDenyProbeBatchResult(messages, probeSpecs, batch, options.onBoundaryViolation, helperIp);
    }
  }

  // The firewall proof fetches and validates the live kernel nft table. It runs
  // before the deny-by-default minting on purpose: the post-cutover observation
  // is minted from that SAME validated fetch (no second `nft list`), so the
  // ruleset must be captured and proven first.
  topologyProgress(options, "checking proxy firewall");
  const firewallProof = validateProxyFirewall(messages, context, io, proxyId, runtimeNetwork, {
    onProbe: (label) => topologyVerbose(options, label),
    onBoundaryViolation: options.onBoundaryViolation,
    expectedEgressSource: proxyEgress?.IPAddress,
  });

  // A denied port-443 host is no longer rejected at the raw CONNECT guard: the
  // proxy accepts the tunnel and serves a synthetic in-tunnel 403 (see the
  // blocked-request feedback design). The pre-token-sync gate must therefore
  // prove the in-tunnel denial — that a disallowed host cannot reach upstream —
  // rather than a raw CONNECT 403. Non-443 and malformed CONNECTs stay pre-TLS
  // rejected and keep their raw-403 probe.
  topologyProgress(options, "checking proxy denial responses");
  // The disallowed-host tunnel-acceptance and in-tunnel-denial probes need an
  // *admitted* source: an unadmitted helper's CONNECT is rejected as an
  // unregistered peer before a tunnel is ever offered, so they cannot run from
  // the agent position here. They are proven from a real admitted session by
  // the live admission tranches.
  //
  // Per-session deny-by-default is minted from the live proxy firewall, not a
  // traffic probe. The per-session INPUT chain is `policy drop` and accepts
  // agent->proxy traffic only from @session_ipv4 on the internal interface, so
  // an unadmitted source is dropped at L3 before the proxy app is ever
  // reached. The firewall proof above already fetched and validated the exact
  // kernel ruleset; minting reuses that same validated input and fails closed
  // on any issue — it never issues a second `nft list`, and a dropped SYN or
  // dead proxy cannot false-pass it the way a live CONNECT probe could.
  if (isActiveRuntimePlan(input)) {
    if (firewallProof.nftablesProofInput === undefined) {
      messages.push("proxy firewall deny-by-default proof unavailable: the live nftables table was not captured");
    } else {
      try {
        denyByDefaultBaseObservation = observeDenyByDefaultViaFirewallV1({
          projectId: input.projectId,
          controlPlaneGenerationDigest: input.generationV2.controlPlane.controlPlaneGenerationDigest,
          proxyContainerId: proxyId,
          nftables: firewallProof.nftablesProofInput,
        });
      } catch (error) {
        messages.push(`proxy firewall deny-by-default proof failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  return topologyValidationResult(messages, denyByDefaultBaseObservation);
}
