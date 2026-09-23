import { PROJECT_ID_LABEL } from "./constants.ts";
import {
  INGRESS_PURPOSE_LABEL,
  INGRESS_PURPOSES,
  type IngressPurpose,
} from "./container-inventory.ts";
import {
  INGRESS_FORWARDER_COMMAND,
  INGRESS_FORWARDER_ENTRYPOINT,
  INGRESS_FORWARDER_IMAGE,
  ingressHostNetworkName,
} from "./ingress-forwarder.ts";
import type {
  DockerContainerInspect,
  DockerPortBindings,
} from "./types.ts";

export const UTILITY_ROLE_LABEL = "io.runfree.utility-role";
export const UTILITY_VERSION_LABEL = "io.runfree.utility-version";

export type UtilityTopologyIssue = {
  code: string;
  severity: "error";
  message: string;
  detail?: string;
};

export type InternalNetworkParticipantInput = {
  // Absent in the per-session runtime shape: there is no standing shared agent
  // participant. Session containers and ephemeral helpers join transiently and
  // are validated by admission / the helper contract, not here.
  attached: DockerContainerInspect[];
  // The deterministic MCP OAuth callback port, so the per-session
  // mcp-callback ingress forwarder can be held to publishing and forwarding
  // exactly that port.
  callbackRelay?: {
    port: string;
  };
  internalNetwork: string;
  projectId: string;
  proxy: DockerContainerInspect;
};

const CONTAINER_ROLE_LABEL = "io.runfree.container-role";
const INGRESS_FORWARDER_ROLE = "ingress-forwarder";
// A socat target is a container name/DNS label or an IPv4 address, and carries
// no shell-significant characters — the same shape the facility validates
// before minting (ingress-forwarder.ts TARGET_PATTERN).
const INGRESS_TARGET_PATTERN = /^[A-Za-z0-9_.-]+$/;
// The mcp-callback purpose targets a session by its internal IPv4 address,
// never a container name, so a stale or hardwired target is rejected rather
// than silently forwarded.
const IPV4_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$/;

function hasProjectRole(container: DockerContainerInspect, projectId: string, role: string): boolean {
  const labels = container.Config?.Labels ?? {};
  return labels[PROJECT_ID_LABEL] === projectId && labels[CONTAINER_ROLE_LABEL] === role;
}

function issue(code: string, message: string, detail?: string): UtilityTopologyIssue {
  return {
    code,
    severity: "error",
    message,
    ...(detail ? { detail } : {}),
  };
}

function stringList(value: string[] | null | undefined): string[] {
  return Array.isArray(value) ? value : [];
}

function containerName(container: DockerContainerInspect): string {
  return container.Name?.replace(/^\//, "") ?? "<unnamed>";
}

// Identity is the exact inspected container ID. Both sides come from full
// `docker inspect` output, so prefix leniency would only ever accept a
// short-ID collision, and a name match without an ID match is exactly the
// drift the participant validation exists to refuse.
function sameContainer(container: DockerContainerInspect, expected: DockerContainerInspect): boolean {
  return container.Id !== undefined && container.Id === expected.Id;
}

function hasCapability(value: string[] | null | undefined, capability: string): boolean {
  return stringList(value).some((entry) => entry.toUpperCase().replace(/^CAP_/, "") === capability);
}

function envMap(container: DockerContainerInspect): Record<string, string> {
  const result: Record<string, string> = {};
  for (const entry of stringList(container.Config?.Env)) {
    const index = entry.indexOf("=");
    if (index <= 0) continue;
    result[entry.slice(0, index)] = entry.slice(index + 1);
  }
  return result;
}

function isPortNumber(value: string | undefined): boolean {
  if (!value || !/^\d+$/.test(value)) return false;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 1 && parsed <= 65535;
}

function labels(container: DockerContainerInspect): Record<string, string> {
  return container.Config?.Labels ?? {};
}

function ingressHostPortFromName(name: string, projectId: string, purpose: IngressPurpose): string | undefined {
  const escapedProjectId = projectId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(`^runfree-ingress-${purpose}-${escapedProjectId}-(\\d+)$`).exec(name);
  if (!match || !isPortNumber(match[1])) return undefined;
  return match[1];
}

/**
 * Recognizes an ingress forwarder (the generalized facility), keyed on
 * `container-role=ingress-forwarder`. A role-labelled container whose name or
 * purpose label is malformed is deliberately *not* recognized here: it then
 * falls through to the unapproved-container refusal, which is fail-closed,
 * rather than being validated against a purpose it does not legibly claim.
 */
function maybeIngressForwarder(
  container: DockerContainerInspect,
  projectId: string,
): { purpose: IngressPurpose; hostPort: string } | undefined {
  const containerLabels = labels(container);
  if (containerLabels[PROJECT_ID_LABEL] !== projectId) return undefined;
  if (containerLabels[CONTAINER_ROLE_LABEL] !== INGRESS_FORWARDER_ROLE) return undefined;
  const purpose = containerLabels[INGRESS_PURPOSE_LABEL];
  if (purpose === undefined || !INGRESS_PURPOSES.includes(purpose as IngressPurpose)) return undefined;
  const typed = purpose as IngressPurpose;
  const hostPort = ingressHostPortFromName(containerName(container), projectId, typed);
  if (!hostPort) return undefined;
  return { purpose: typed, hostPort };
}

function arraysEqual(actual: readonly string[], expected: readonly string[]): boolean {
  return actual.length === expected.length && actual.every((value, index) => value === expected[index]);
}

/**
 * Exact match against the command the facility mints, not substring markers: a
 * marker check would also pass a container whose command merely mentions the
 * markers (e.g. in a shell comment) while running an arbitrary payload. The
 * entrypoint must be exactly `sh` and the command exactly `-c <the socat
 * script>`.
 */
function commandUsesKnownIngressSocatShape(container: DockerContainerInspect): boolean {
  const entrypoint = container.Config?.Entrypoint;
  const entrypointList = Array.isArray(entrypoint)
    ? entrypoint
    : (typeof entrypoint === "string" && entrypoint.length > 0 ? [entrypoint] : []);
  return arraysEqual(entrypointList, [INGRESS_FORWARDER_ENTRYPOINT])
    && arraysEqual(stringList(container.Config?.Cmd), INGRESS_FORWARDER_COMMAND);
}

function networkNames(container: DockerContainerInspect): string[] {
  return Object.keys(container.NetworkSettings?.Networks ?? {}).sort();
}

function bindingsMatchLoopbackPort(bindings: DockerPortBindings | null | undefined, hostPort: string): boolean {
  const entries = Object.entries(bindings ?? {})
    .filter(([, values]) => Array.isArray(values) && values.length > 0);
  if (entries.length !== 1) return false;
  const [[containerPort, values]] = entries;
  if (containerPort !== `${hostPort}/tcp`) return false;
  if (!Array.isArray(values) || values.length === 0) return false;
  return values.every((binding) => binding?.HostIp === "127.0.0.1" && binding.HostPort === hostPort);
}

function includesDockerSocket(container: DockerContainerInspect): boolean {
  const mounts = container.Mounts ?? [];
  if (mounts.some((mount) => mount.Source?.includes("/var/run/docker.sock") || mount.Destination?.includes("/var/run/docker.sock"))) {
    return true;
  }
  return stringList(container.HostConfig?.Binds).some((bind) => bind.includes("/var/run/docker.sock"));
}

function hasAnyMount(container: DockerContainerInspect): boolean {
  if ((container.Mounts ?? []).length > 0) return true;
  return stringList(container.HostConfig?.Binds).length > 0;
}

/**
 * The generalized ingress-forwarder validator: one hardened, loopback-only,
 * one-way host→agent bridge shape for every purpose. The bridge is identical
 * across purposes (same image, same generic socat splice, same hardening), so
 * the shared contract below is the whole security check; `purpose` is a
 * diagnostic, cross-checked against the label for consistency. Per-consumer
 * target semantics (VNC's agent target, the callback's session loopback) belong
 * to each consumer as it lands on the facility, not to this shape validator —
 * which cannot know a dynamic session's identity anyway.
 */
function validateIngressForwarder(
  container: DockerContainerInspect,
  input: InternalNetworkParticipantInput,
  purpose: IngressPurpose,
  hostPort: string,
  sessionAgentIps: readonly string[],
  options: Readonly<{
    requireLiveMcpTarget?: boolean;
    requireRunning?: boolean;
  }> = {},
): UtilityTopologyIssue[] {
  const issues: UtilityTopologyIssue[] = [];
  const name = containerName(container);
  const env = envMap(container);
  const networks = networkNames(container);
  const hostNetworks = networks.filter((network) => network !== input.internalNetwork);
  const user = container.Config?.User ?? "";
  const capAdd = container.HostConfig?.CapAdd;
  const pidsLimit = container.HostConfig?.PidsLimit;
  const expectedHostNetwork = ingressHostNetworkName(input.projectId);

  const invalid = (message: string, detail?: string) => {
    issues.push(issue("utility-ingress-forwarder-shape", message, detail));
  };

  if (options.requireRunning !== false && container.State?.Running !== true) {
    invalid(`ingress forwarder ${name} must be running`);
  }
  if (container.Config?.Image !== INGRESS_FORWARDER_IMAGE) {
    invalid(
      `ingress forwarder ${name} must use the pinned ingress image`,
      `got ${container.Config?.Image || "<none>"}`,
    );
  }
  if (container.HostConfig?.NetworkMode === "host") invalid(`ingress forwarder ${name} must not use host networking`);
  if (container.HostConfig?.AutoRemove !== true) invalid(`ingress forwarder ${name} must use Docker auto-remove`);
  // Corroborates that the forwarder was created on the derived host-ingress
  // bridge as its primary network — matching the facility's creation path
  // (`docker run --network <bridge>`, then attach agent_internal) — not on
  // agent_internal. This is a shape signal, not by itself proof of the socat
  // bind address: NetworkMode is creation-time only and does not fix Docker's
  // current endpoint ordering (that is GwPriority). The host→agent-only bind is
  // established at creation instead, by binding socat while only the host
  // bridge is attached, before agent_internal is connected
  // (ingress-forwarder.ts readiness gate). A post-hoc inspect cannot re-derive
  // socat's bound address, so this check backs that guarantee rather than
  // standing in for it.
  if (container.HostConfig?.NetworkMode !== expectedHostNetwork) {
    invalid(`ingress forwarder ${name} must be created on ${expectedHostNetwork} as its primary network`, `got ${container.HostConfig?.NetworkMode || "<none>"}`);
  }
  if (container.HostConfig?.Privileged === true) invalid(`ingress forwarder ${name} must not run privileged`);
  if (Array.isArray(capAdd) && capAdd.length > 0) invalid(`ingress forwarder ${name} must not add capabilities`);
  if (!hasCapability(container.HostConfig?.CapDrop, "ALL")) invalid(`ingress forwarder ${name} must drop all capabilities`);
  if (!stringList(container.HostConfig?.SecurityOpt).some((entry) => entry.toLowerCase() === "no-new-privileges:true")) {
    invalid(`ingress forwarder ${name} must set no-new-privileges:true`);
  }
  if (container.HostConfig?.ReadonlyRootfs !== true) invalid(`ingress forwarder ${name} must use a read-only root filesystem`);
  if (!Number.isInteger(pidsLimit) || (pidsLimit ?? 0) <= 0) invalid(`ingress forwarder ${name} must configure a positive PID limit`);
  if (user !== "65534:65534") invalid(`ingress forwarder ${name} must run as 65534:65534`, `got ${user || "<empty>"}`);
  if (includesDockerSocket(container)) invalid(`ingress forwarder ${name} must not mount the Docker socket`);
  if (hasAnyMount(container)) invalid(`ingress forwarder ${name} must not mount host paths or volumes`);
  if (networks.length !== 2 || !networks.includes(input.internalNetwork)
    || hostNetworks.length !== 1 || hostNetworks[0] !== expectedHostNetwork) {
    invalid(`ingress forwarder ${name} must attach only to agent_internal and ${expectedHostNetwork}`, `got ${networks.join(", ") || "<none>"}`);
  }
  if (!bindingsMatchLoopbackPort(container.HostConfig?.PortBindings, hostPort)
    || !bindingsMatchLoopbackPort(container.NetworkSettings?.Ports, hostPort)) {
    invalid(`ingress forwarder ${name} must publish only 127.0.0.1:${hostPort}/tcp`);
  }
  if (labels(container)[INGRESS_PURPOSE_LABEL] !== purpose) invalid(`ingress forwarder ${name} must label ingress-purpose=${purpose}`);
  if (env.INGRESS_HOST_PORT !== hostPort) invalid(`ingress forwarder ${name} must set INGRESS_HOST_PORT=${hostPort}`);
  if (!env.INGRESS_TARGET || !INGRESS_TARGET_PATTERN.test(env.INGRESS_TARGET)) invalid(`ingress forwarder ${name} must set a well-formed INGRESS_TARGET`);
  if (!isPortNumber(env.INGRESS_TARGET_PORT)) invalid(`ingress forwarder ${name} must set a numeric INGRESS_TARGET_PORT`);
  if (!commandUsesKnownIngressSocatShape(container)) invalid(`ingress forwarder ${name} must run the known socat forwarder command`);

  // Purpose-specific: the mcp-callback forwarder (hop 1 of the two-hop callback)
  // publishes the deterministic callback port and targets the *live session's*
  // internal IPv4 — never a hardwired or name-based target. vnc/port carry no
  // extra shape here:
  // their target correctness is owned by the creating command, and this
  // validator cannot know a session's dynamic identity for those.
  if (purpose === "mcp-callback") {
    const callbackPort = input.callbackRelay?.port;
    if (callbackPort !== undefined && hostPort !== callbackPort) {
      invalid(`mcp-callback forwarder ${name} must publish the callback port ${callbackPort}`, `got ${hostPort}`);
    }
    if (callbackPort !== undefined && env.INGRESS_TARGET_PORT !== callbackPort) {
      invalid(`mcp-callback forwarder ${name} must forward to the callback port ${callbackPort}`, `got ${env.INGRESS_TARGET_PORT || "<none>"}`);
    }
    const target = env.INGRESS_TARGET ?? "";
    if (!IPV4_PATTERN.test(target)) {
      invalid(`mcp-callback forwarder ${name} must target a session IPv4 address, not a name`, `got ${target || "<none>"}`);
    } else if (options.requireLiveMcpTarget !== false && !sessionAgentIps.includes(target)) {
      // A hardwired or stale target (a session that has since ended) points
      // the callback at no live session.
      invalid(`mcp-callback forwarder ${name} must target a live session's internal IP`, `got ${target}`);
    }
  }

  return issues;
}

/**
 * Exact ownership proof used before teardown removes a discovered utility.
 *
 * Four facts, nothing else: this project's `io.runfree.project-id` label, the
 * `ingress-forwarder` container-role label, and the inspected immutable image
 * ID equal to Docker's resolved ID for the pinned ingress image. The fourth
 * fact — removal addressed by the inspected full 64-hex container ID — is
 * enforced by the ownership planner that consumes this proof. Launch-time
 * shape (hardening flags, loopback-only publication, network membership, env,
 * command) is creation and live-topology authority, not deletion authority: a
 * live container that fails those checks is refused where it is found, while
 * teardown only needs proof that Runfree created the candidate.
 *
 * Accepted residual (plan 7b): a same-host writer minting these labels onto a
 * container running the pinned image could get it removed by our teardown.
 * Realistic writers of the labels are Runfree itself and the operator, and
 * the Docker daemon is trusted. Partial or conflicting labels still refuse,
 * never remove.
 */
export function validateIngressForwarderTeardownCandidate(input: Readonly<{
  container: DockerContainerInspect;
  expectedImageId?: string;
  projectId: string;
}>): UtilityTopologyIssue[] {
  const issues: UtilityTopologyIssue[] = [];
  const name = containerName(input.container);
  const containerLabels = labels(input.container);
  if (containerLabels[PROJECT_ID_LABEL] !== input.projectId
    || containerLabels[CONTAINER_ROLE_LABEL] !== INGRESS_FORWARDER_ROLE) {
    issues.push(issue(
      "utility-ingress-forwarder-shape",
      `container ${name} does not carry this project's exact ingress-forwarder labels`,
    ));
  }
  const immutableImageMatches = input.expectedImageId !== undefined
    && input.container.Image === input.expectedImageId;
  if (!immutableImageMatches) {
    issues.push(issue(
      "utility-ingress-forwarder-shape",
      `container ${name} does not use the resolved immutable ingress image`,
      `got ${input.container.Image || "<none>"}`,
    ));
  }
  return issues;
}

export function validateInternalNetworkParticipants(input: InternalNetworkParticipantInput): UtilityTopologyIssue[] {
  const issues: UtilityTopologyIssue[] = [];
  let sawProxy = false;

  // The live sessions' internal IPs, so an mcp-callback forwarder can be
  // checked to target one of them (never a hardwired or stale address). Read
  // from the same inspected set, so no registry or Docker access is needed here.
  const sessionAgentIps = input.attached
    .filter((container) => hasProjectRole(container, input.projectId, "session-agent"))
    .map((container) => container.NetworkSettings?.Networks?.[input.internalNetwork]?.IPAddress)
    .filter((ip): ip is string => typeof ip === "string");
  for (const container of input.attached) {
    if (sameContainer(container, input.proxy)) {
      sawProxy = true;
      continue;
    }

    const ingress = maybeIngressForwarder(container, input.projectId);
    if (ingress) {
      issues.push(...validateIngressForwarder(container, input, ingress.purpose, ingress.hostPort, sessionAgentIps));
      continue;
    }
    // Transient participants are legitimate but not validated here: a session
    // container is validated by its own admission proof, and an ephemeral
    // helper by the helper contract. Recognizing them by role keeps the
    // unapproved-container refusal for everything else while not condemning
    // the very containers per-session admission creates. Both carry the
    // project id, so a foreign container cannot borrow the role.
    if (hasProjectRole(container, input.projectId, "session-agent")
      || hasProjectRole(container, input.projectId, "ephemeral-helper")) {
      continue;
    }
    issues.push(issue(
      "agent-network-unapproved-container",
      `agent_internal contains unapproved container ${containerName(container)}`,
    ));
  }

  // The proxy is the one mandatory fixed participant.
  if (!sawProxy) {
    issues.push(issue("agent-network-count", "agent_internal must contain proxy"));
  }
  return issues;
}
