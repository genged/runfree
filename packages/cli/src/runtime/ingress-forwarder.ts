// The ingress forwarding facility: N hardened host→agent bridges, one shape.
//
// The proxy is the one governed egress door; ingress forwarders are N doors
// through one mechanism, each loopback-only and one-way (host → agent:port,
// never agent → host). Each is the same container — same image, same one-way
// socat splice, same hardening, same validator — parameterized only by ports,
// target, and a diagnostic purpose. VNC is the first consumer; `runfree
// forward` is the next; the per-session MCP OAuth callback is the third
// (retiring the bespoke Compose relay, cutover option C).
//
// The one-way invariant is an ORDERING, not a policy (spec I2): the socat
// listener binds `$(hostname -i)` at startup, which resolves to the host-facing
// interface because `agent_internal` is attached only *after* the listener is
// up. A connection arriving from the agent side hits no listener bound to that
// interface and is refused. The ordering is made real, not merely likely: the
// attach waits until socat is observed LISTENing (so `hostname -i` was already
// evaluated against the host-facing interface alone) before `agent_internal`
// exists on the container.
//
// The host-facing network is derived here from the project id, never taken from
// the caller: a caller-selected network could be a shared bridge other
// containers can reach, or `agent_internal` itself, either of which would
// dissolve the one-way property regardless of the loopback publication.

import { die } from "../errors.ts";
import {
  CONTAINER_ROLE_LABEL,
  INGRESS_PURPOSE_LABEL,
  ingressForwarderLabelArguments,
  projectIngressForwarderFilters,
  type IngressPurpose,
} from "./container-inventory.ts";
import { dockerClientEnvOptions, parseDockerJson } from "./docker.ts";
import type {
  CaptureResult,
  DockerContainerInspect,
  DockerNetworkInspect,
  RuntimeContext,
  RuntimeIO,
} from "./types.ts";

// Pin the multi-platform manifest. Teardown uses this immutable creation
// reference plus Docker's resolved image ID; a mutable tag cannot authorize
// deletion of a container that Runfree did not create.
export const INGRESS_FORWARDER_IMAGE = "alpine/socat@sha256:376403afeffc040ac30d8f3f67c43f47ccaf4d8916e80bfff2bc5736320abb10";
const FORWARDER_PREFIX = "runfree-ingress";
const HOST_NETWORK_PREFIX = "runfree-ingress-host-v2";

// Binds the listener to the host-facing interface only. The sidecar is created
// on the host-facing network with no other endpoint, so `hostname -i` resolves
// to that interface's address before `agent_internal` is attached; a later
// connection from the agent side finds no listener there. Generic env, not
// VNC's — the facility owns the bridge, callers own only their target.
const SOCAT_SCRIPT =
  'exec socat "TCP-LISTEN:${INGRESS_HOST_PORT},bind=$(hostname -i),fork,reuseaddr" "TCP:${INGRESS_TARGET}:${INGRESS_TARGET_PORT}"';

/**
 * The exact entrypoint and command every forwarder runs. Exported so the
 * topology validator can compare the full inspected command against this, not
 * substring markers — a marker match would also accept an arbitrary payload
 * that merely mentions the markers in a shell comment.
 */
export const INGRESS_FORWARDER_ENTRYPOINT = "sh";
export const INGRESS_FORWARDER_COMMAND: readonly string[] = ["-c", SOCAT_SCRIPT];

const PORT_PATTERN = /^\d{1,5}$/;
const NETWORK_NAME_PATTERN = /^[A-Za-z0-9_.-]+$/;
// A socat target is either a container name/DNS label or an IPv4 address; both
// fit this, and neither may carry shell-significant characters since the value
// is interpolated into the socat command's environment.
const TARGET_PATTERN = /^[A-Za-z0-9_.-]+$/;
// The three generic vars the bridge itself sets. `extraEnv` is appended after
// them and Docker keeps the last `-e` for a repeated name, so an extra entry
// reusing one of these would silently replace a validated value (redirecting
// the splice, or smuggling socat address syntax past TARGET_PATTERN). They are
// reserved: a purpose's extra env may never carry these names.
const RESERVED_INGRESS_ENV = new Set(["INGRESS_HOST_PORT", "INGRESS_TARGET", "INGRESS_TARGET_PORT"]);
// Bounded readiness poll before the `agent_internal` attach. socat binds within
// milliseconds of container start; docker exec round-trips pace the loop, so a
// small ceiling covers a slow start while still failing closed if socat never
// binds (e.g. it errored on its address and the `--rm` container is gone).
const READINESS_ATTEMPTS = 40;
const FULL_DOCKER_CONTAINER_ID_PATTERN = /^[a-f0-9]{64}$/;
const FULL_DOCKER_NETWORK_ID_PATTERN = /^[a-f0-9]{64}$/;
const INGRESS_HOST_NETWORK_ROLE_LABEL = "io.runfree.network-role";
const INGRESS_HOST_NETWORK_ROLE = "ingress-host";
const MANAGED_LABEL = "io.runfree.managed";
const PROJECT_ID_LABEL = "io.runfree.project-id";

export type IngressForwarderInput = Readonly<{
  purpose: IngressPurpose;
  projectId: string;
  /** Host loopback port to publish (`127.0.0.1:<hostPort>`). */
  hostPort: string;
  /** What the splice connects to inside the fence — a container name or IPv4. */
  target: string;
  /** Port on the target. */
  targetPort: string;
  /** The project's exact `agent_internal` network name. */
  internalNetwork: string;
  /**
   * Extra `--env` pairs a purpose asserts in its validator (VNC's `VNC_*`,
   * the callback's identity). The bridge itself needs only the three generic
   * INGRESS_* vars; these ride alongside for the purpose-specific shape check.
   */
  extraEnv?: Readonly<Record<string, string>>;
}>;

function docker(context: RuntimeContext, io: RuntimeIO, args: string[]): CaptureResult {
  return io.capture("docker", args, dockerClientEnvOptions(context));
}

function containerExists(context: RuntimeContext, io: RuntimeIO, name: string): boolean {
  return docker(context, io, ["container", "inspect", name]).status === 0;
}

function exactMissingContainer(stderr: string, target: string): boolean {
  const escaped = target.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(
    `^(?:Error response from daemon: |Error: )?No such (?:container|object): ${escaped}\\s*$`,
    "imu",
  ).test(stderr.trim());
}

/**
 * Removes a forwarder, distinguishing a real failure from an already-gone
 * `--rm` container. Only Docker's own definitive "No such container" is treated
 * as already-removed; every other non-zero result — including an unreachable
 * daemon — is unverifiable and reported as a possible surviving sidecar rather
 * than assumed gone. (A follow-up `inspect` would not resolve this: the same
 * outage that failed the removal fails the inspect, and "inspect errored" is
 * not proof the container is gone.)
 */
function removeForwarder(context: RuntimeContext, io: RuntimeIO, name: string): { ok: boolean; detail?: string } {
  const removed = docker(context, io, ["rm", "-f", name]);
  if (removed.status === 0) return { ok: true };
  const detail = removed.stderr.trim();
  // Only the canonical missing-target error for *this* container proves it is
  // gone: `Error: No such container: <name>`. A bare substring would also
  // accept a nested diagnostic from a failed force-kill (e.g. "cannot remove -
  // Cannot kill container ...: No such container: <runtime-id>"), where the
  // published sidecar may in fact survive.
  // Require the name to end at whitespace or end-of-line, not merely a word
  // boundary: a bare \b is satisfied between the trailing digit and a '-' or
  // '.', so `No such container: <name>-stale` (a different container) would
  // otherwise match. The `m` flag lets `$` close the canonical diagnostic line.
  if (exactMissingContainer(detail, name)) return { ok: true };
  return { ok: false, detail: detail || name };
}

function exactMissingNetwork(stderr: string, target: string): boolean {
  const escaped = target.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(
    `^(?:Error response from daemon: |Error: )?(?:No such (?:network|object): ${escaped}|network ${escaped} not found)\\s*$`,
    "imu",
  ).test(stderr.trim());
}

export type IngressHostNetworkProof = Readonly<{
  containerIds: readonly string[];
  id: string;
  name: string;
}>;

function isEmptyRecord(value: unknown): boolean {
  return typeof value === "object"
    && value !== null
    && !Array.isArray(value)
    && Object.keys(value).length === 0;
}

function defaultBridgeOptionsMatch(value: unknown): boolean {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  // Some daemons expose their address-family defaults as driver options too.
  // Accept only the same IPv4-only shape required of the top-level flags.
  return Object.entries(value).every(([key, option]) => (
    key === "com.docker.network.enable_ipv4" && option === "true"
    || key === "com.docker.network.enable_ipv6" && option === "false"
  ));
}

function ipv4Number(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const octets = value.split(".");
  if (octets.length !== 4) return undefined;
  let result = 0;
  for (const octet of octets) {
    if (!/^\d{1,3}$/u.test(octet)) return undefined;
    const parsed = Number(octet);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > 255) return undefined;
    result = (result * 256) + parsed;
  }
  return result;
}

function defaultBridgeIpamMatches(candidate: DockerNetworkInspect): boolean {
  const ipam = candidate.IPAM;
  if (!ipam || ipam.Driver !== "default") return false;
  const allowedIpamKeys = new Set(["Config", "Driver", "Options"]);
  if (Object.keys(ipam).some((key) => !allowedIpamKeys.has(key))) return false;
  if (ipam.Options !== undefined && ipam.Options !== null && !isEmptyRecord(ipam.Options)) return false;
  if (!Array.isArray(ipam.Config) || ipam.Config.length !== 1) return false;
  const config = ipam.Config[0];
  if (!config) return false;
  const allowedKeys = new Set(["AuxiliaryAddresses", "Gateway", "IPRange", "Subnet"]);
  if (Object.keys(config).some((key) => !allowedKeys.has(key))) return false;
  if (config.IPRange !== undefined && config.IPRange !== "") return false;
  if (config.AuxiliaryAddresses !== undefined
    && config.AuxiliaryAddresses !== null
    && !isEmptyRecord(config.AuxiliaryAddresses)) return false;
  const [subnetAddress, prefixText, ...extra] = (config.Subnet ?? "").split("/");
  if (extra.length > 0 || !/^\d{1,2}$/u.test(prefixText ?? "")) return false;
  const prefix = Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 1 || prefix > 30) return false;
  const subnet = ipv4Number(subnetAddress);
  const gateway = ipv4Number(config.Gateway);
  if (subnet === undefined || gateway === undefined) return false;
  const blockSize = 2 ** (32 - prefix);
  const network = Math.floor(subnet / blockSize) * blockSize;
  return subnet === network && gateway > network && gateway < network + blockSize - 1;
}

/**
 * Inspects the managed host bridge under one of two proofs:
 *
 * - `"creation"` (the launch path): the complete bridge shape — driver,
 *   isolation flags, address family, IPAM, options, configuration source —
 *   plus identity, because a listener is about to bind on this network and an
 *   unexpected shape would dissolve the one-way property.
 * - `"teardown"` (plan 7b): identity facts only — one network, its exact full
 *   64-hex ID, the versioned name, exact endpoint IDs, and the minted
 *   managed/project/network-role labels. Deletion needs proof Runfree created
 *   the bridge, not proof it still has a pristine shape; partial or
 *   conflicting labels still refuse, never remove.
 */
export function inspectIngressHostNetwork(
  context: RuntimeContext,
  io: RuntimeIO,
  projectId: string,
  proof: "creation" | "teardown" = "creation",
): IngressHostNetworkProof | undefined {
  const name = ingressHostNetworkName(projectId);
  const result = docker(context, io, ["network", "inspect", name]);
  if (result.status !== 0) {
    if (exactMissingNetwork(result.stderr, name)) return undefined;
    die(`could not inspect ingress host network ${name}: ${result.stderr.trim() || `exit ${result.status}`}`);
  }
  const parsed = parseDockerJson<DockerNetworkInspect[]>(result, `docker inspect ingress host network ${name}`);
  const candidate = parsed?.[0];
  const issues: string[] = [];
  let containerIds: string[] = [];
  if (!candidate || parsed.length !== 1) {
    issues.push("inspection did not return one network");
  } else {
    if (!FULL_DOCKER_NETWORK_ID_PATTERN.test(candidate.Id ?? "")) issues.push("network id is not exact");
    if (candidate.Name !== name) issues.push("network name does not match");
    if (proof === "creation") {
      if (candidate.Driver !== "bridge" || candidate.Scope !== "local") issues.push("network is not a local bridge");
      if (candidate.Internal !== false || candidate.Attachable !== false || candidate.Ingress !== false) {
        issues.push("network isolation shape does not match");
      }
      if (candidate.EnableIPv6 !== false
        || (candidate.EnableIPv4 !== undefined && candidate.EnableIPv4 !== true)) {
        issues.push("network address-family shape does not match");
      }
      if (!defaultBridgeIpamMatches(candidate)) issues.push("network IPAM shape does not match");
      // Named, not just counted: the daemon decides what it puts here (a
      // Docker Desktop populated one on the first live run of this check), and
      // an issue that does not say which key it saw leaves the operator with
      // `docker network inspect` as the only way to find out.
      if (!defaultBridgeOptionsMatch(candidate.Options)) {
        issues.push(`network driver options do not match: ${JSON.stringify(candidate.Options ?? {})}`);
      }
      if ((candidate.ConfigOnly !== undefined && candidate.ConfigOnly !== false)
        || (candidate.ConfigFrom?.Network ?? "") !== "") {
        issues.push("network configuration source does not match");
      }
    }
    containerIds = Object.keys(candidate.Containers ?? {}).sort();
    if (containerIds.some((id) => !FULL_DOCKER_CONTAINER_ID_PATTERN.test(id))) {
      issues.push("network endpoint id is not exact");
    }
    const labels = candidate.Labels ?? {};
    const currentLabels = labels[MANAGED_LABEL] === "true"
      && labels[PROJECT_ID_LABEL] === projectId
      && labels[INGRESS_HOST_NETWORK_ROLE_LABEL] === INGRESS_HOST_NETWORK_ROLE;
    if (!currentLabels) {
      if (labels[MANAGED_LABEL] !== "true") issues.push("managed label does not match");
      if (labels[PROJECT_ID_LABEL] !== projectId) issues.push("project label does not match");
      if (labels[INGRESS_HOST_NETWORK_ROLE_LABEL] !== INGRESS_HOST_NETWORK_ROLE) {
        issues.push("network role label does not match");
      }
    }
  }
  if (!candidate || issues.length > 0) {
    die(`refusing unverified ingress host network ${name}: ${issues.join("; ")}`);
  }
  return Object.freeze({
    containerIds: Object.freeze(containerIds),
    id: candidate.Id as string,
    name,
  });
}

export type ForcedIngressHostNetworkCleanup = Readonly<{
  detail?: string;
  kind: "absent" | "removed" | "retained";
}>;

/**
 * Runs only after forced destroy has swept project-labeled containers. It
 * removes a current, fully owned ingress bridge only when Docker proves it is
 * empty. Invalid or still-attached networks are retained for manual
 * inspection instead of blocking forced container and lifecycle recovery.
 */
export function removeValidatedEmptyManagedIngressHostNetworkAfterForcedSweep(
  context: RuntimeContext,
  io: RuntimeIO,
  projectId: string,
): ForcedIngressHostNetworkCleanup {
  let network: IngressHostNetworkProof | undefined;
  try {
    network = inspectIngressHostNetwork(context, io, projectId, "teardown");
  } catch (error) {
    return Object.freeze({
      detail: error instanceof Error ? error.message : String(error),
      kind: "retained",
    });
  }
  if (!network) return Object.freeze({ kind: "absent" });
  if (network.containerIds.length > 0) {
    return Object.freeze({
      detail: `ingress host network ${network.name} still has attached endpoints`,
      kind: "retained",
    });
  }
  const removed = docker(context, io, ["network", "rm", network.id]);
  if (removed.status !== 0 && !exactMissingNetwork(removed.stderr, network.id)) {
    die(removed.stderr.trim() || `failed to remove Docker network ${network.name}`);
  }
  return Object.freeze({ kind: "removed" });
}

export function ingressForwarderName(projectId: string, purpose: IngressPurpose, hostPort: string): string {
  return `${FORWARDER_PREFIX}-${purpose}-${projectId}-${hostPort}`;
}

export function ingressHostNetworkName(projectId: string): string {
  return `${HOST_NETWORK_PREFIX}-${projectId}`;
}

function assertInput(input: IngressForwarderInput): void {
  if (!PORT_PATTERN.test(input.hostPort) || Number(input.hostPort) < 1 || Number(input.hostPort) > 65535) {
    die(`ingress forwarder host port is invalid: ${input.hostPort}`);
  }
  if (!PORT_PATTERN.test(input.targetPort) || Number(input.targetPort) < 1 || Number(input.targetPort) > 65535) {
    die(`ingress forwarder target port is invalid: ${input.targetPort}`);
  }
  if (!TARGET_PATTERN.test(input.target)) die(`ingress forwarder target is invalid: ${input.target}`);
  if (!NETWORK_NAME_PATTERN.test(input.internalNetwork)) die(`ingress forwarder internal network is invalid: ${input.internalNetwork}`);
  if (input.internalNetwork === ingressHostNetworkName(input.projectId)) {
    die(`ingress forwarder internal network must not be the host-facing network: ${input.internalNetwork}`);
  }
  for (const [name, value] of Object.entries(input.extraEnv ?? {})) {
    if (RESERVED_INGRESS_ENV.has(name)) die(`ingress forwarder extra env may not set the reserved ingress var ${name}`);
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) die(`ingress forwarder env name is invalid: ${name}`);
    if (/[\r\n\0]/.test(value)) die(`ingress forwarder env value for ${name} contains a control character`);
  }
}

/**
 * The exact `docker run` argv for one forwarder, pure and testable.
 *
 * Every hardening flag is load-bearing: user 65534, cap-drop ALL, read-only,
 * no-new-privileges, bounded pids, no mounts, no Docker socket, `--rm`. The
 * publication is loopback-only (spec Non-goals: never `0.0.0.0`). The socat
 * command shape is fixed and the same for every purpose; only the target and
 * ports vary.
 */
export function ingressForwarderRunArguments(input: IngressForwarderInput): string[] {
  return [
    "run",
    "--rm",
    "-d",
    "--name",
    ingressForwarderName(input.projectId, input.purpose, input.hostPort),
    ...ingressForwarderLabelArguments(input.projectId, input.purpose),
    "--network",
    ingressHostNetworkName(input.projectId),
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges:true",
    "--read-only",
    "--pids-limit",
    "64",
    "--user",
    "65534:65534",
    "-p",
    `127.0.0.1:${input.hostPort}:${input.hostPort}`,
    "-e",
    `INGRESS_HOST_PORT=${input.hostPort}`,
    "-e",
    `INGRESS_TARGET=${input.target}`,
    "-e",
    `INGRESS_TARGET_PORT=${input.targetPort}`,
    ...Object.entries(input.extraEnv ?? {}).flatMap(([name, value]) => ["-e", `${name}=${value}`]),
    "--entrypoint",
    INGRESS_FORWARDER_ENTRYPOINT,
    INGRESS_FORWARDER_IMAGE,
    ...INGRESS_FORWARDER_COMMAND,
  ];
}

/**
 * Starts one ingress forwarder, dual-homing it after the host-facing bind so
 * the one-way invariant holds by construction (spec I2).
 *
 * Order: create the host-facing network if absent, refuse an unresolved name
 * collision, run the sidecar on the host-facing network only
 * (so its listener binds that interface), then connect it to `agent_internal`.
 * A failed connect removes the sidecar rather than leaving a half-homed
 * forwarder that publishes a port it cannot serve.
 */
export function startIngressForwarder(
  context: RuntimeContext,
  io: RuntimeIO,
  input: IngressForwarderInput,
  prevalidatedNetwork?: IngressHostNetworkProof,
): string {
  assertInput(input);
  // Build the run argv up front: it mints the labels, which reject an invalid
  // project id or purpose. Nothing mutates Docker until the whole input has
  // been validated, so a rejected input never leaves a created network behind.
  const runArgs = ingressForwarderRunArguments(input);
  const hostNetwork = ingressHostNetworkName(input.projectId);
  const name = ingressForwarderName(input.projectId, input.purpose, input.hostPort);
  const existing = docker(context, io, ["container", "inspect", name]);
  if (existing.status === 0) {
    die(`ingress forwarder ${name} already exists; validate and stop it before replacement`);
  }
  if (!exactMissingContainer(existing.stderr, name)) {
    die(`could not prove ingress forwarder name ${name} is unused: ${existing.stderr.trim() || `exit ${existing.status}`}`);
  }
  const existingHostNetwork = inspectIngressHostNetwork(context, io, input.projectId);
  if (existingHostNetwork && prevalidatedNetwork && existingHostNetwork.id !== prevalidatedNetwork.id) {
    die(`ingress host network ${hostNetwork} changed after ownership validation`);
  }
  if (!existingHostNetwork) {
    const created = docker(context, io, [
      "network",
      "create",
      "--label",
      `${MANAGED_LABEL}=true`,
      "--label",
      `${PROJECT_ID_LABEL}=${input.projectId}`,
      "--label",
      `${INGRESS_HOST_NETWORK_ROLE_LABEL}=${INGRESS_HOST_NETWORK_ROLE}`,
      hostNetwork,
    ]);
    if (created.status !== 0) die(created.stderr.trim() || `failed to create Docker network ${hostNetwork}`);
    const createdId = created.stdout.trim();
    let inspectedCreated: IngressHostNetworkProof | undefined;
    try {
      inspectedCreated = inspectIngressHostNetwork(context, io, input.projectId);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      if (!FULL_DOCKER_NETWORK_ID_PATTERN.test(createdId)) {
        die(`${reason}; Docker returned no exact ID for the newly created network, so it may remain`);
      }
      const cleanup = docker(context, io, ["network", "rm", createdId]);
      if (cleanup.status === 0 || exactMissingNetwork(cleanup.stderr, createdId)) die(reason);
      die(`${reason}; and cleanup failed, network ${createdId} may remain: ${cleanup.stderr.trim() || `exit ${cleanup.status}`}`);
    }
    if (!inspectedCreated) {
      if (FULL_DOCKER_NETWORK_ID_PATTERN.test(createdId)) {
        const cleanup = docker(context, io, ["network", "rm", createdId]);
        if (cleanup.status !== 0 && !exactMissingNetwork(cleanup.stderr, createdId)) {
          die(`newly created ingress host network ${hostNetwork} disappeared before validation; cleanup failed: ${cleanup.stderr.trim() || `exit ${cleanup.status}`}`);
        }
      }
      die(`newly created ingress host network ${hostNetwork} disappeared before validation`);
    }
    if (FULL_DOCKER_NETWORK_ID_PATTERN.test(createdId) && inspectedCreated.id !== createdId) {
      const cleanup = docker(context, io, ["network", "rm", createdId]);
      const reason = `ingress host network ${hostNetwork} changed after creation`;
      if (cleanup.status === 0 || exactMissingNetwork(cleanup.stderr, createdId)) die(reason);
      die(`${reason}; and cleanup failed, network ${createdId} may remain: ${cleanup.stderr.trim() || `exit ${cleanup.status}`}`);
    }
  }
  const run = docker(context, io, runArgs);
  if (run.status !== 0) die(run.stderr.trim() || `failed to start ingress forwarder ${name}`);
  let containerId = run.stdout.trim();
  if (!FULL_DOCKER_CONTAINER_ID_PATTERN.test(containerId)) {
    const inspected = docker(context, io, ["container", "inspect", name]);
    if (inspected.status !== 0) {
      if (exactMissingContainer(inspected.stderr, name)) {
        die(`Docker started ingress forwarder ${name} but returned no exact container ID; the container is already gone`);
      }
      die(
        `Docker started ingress forwarder ${name} but returned no exact container ID; `
        + `its identity could not be recovered and it may still be running: ${inspected.stderr.trim() || `exit ${inspected.status}`}`,
      );
    }
    const parsed = parseDockerJson<DockerContainerInspect[]>(
      inspected,
      `docker inspect newly started ingress forwarder ${name}`,
    );
    const candidate = parsed?.[0];
    const labels = candidate?.Config?.Labels ?? {};
    const recoveredId = candidate?.Id ?? "";
    if (!candidate
      || parsed.length !== 1
      || candidate.Name?.replace(/^\//, "") !== name
      || candidate.Config?.Image !== INGRESS_FORWARDER_IMAGE
      || labels[PROJECT_ID_LABEL] !== input.projectId
      || labels[CONTAINER_ROLE_LABEL] !== "ingress-forwarder"
      || labels[INGRESS_PURPOSE_LABEL] !== input.purpose
      || !FULL_DOCKER_CONTAINER_ID_PATTERN.test(recoveredId)) {
      die(`Docker started ingress forwarder ${name} but returned no exact container ID; its identity is unverified and it may still be running`);
    }
    containerId = recoveredId;
    dieAfterCleanup(
      context,
      io,
      containerId,
      name,
      `Docker started ingress forwarder ${name} but returned no exact container ID`,
    );
  }
  // Attach agent_internal only once socat is LISTENing on the host-facing
  // interface. Until then `hostname -i` has not been evaluated, and a premature
  // attach would let it observe two interfaces — dissolving the one-way bind.
  if (!waitForSocatBind(context, io, containerId, input.hostPort)) {
    dieAfterCleanup(context, io, containerId, name, `ingress forwarder ${name} did not begin listening on 127.0.0.1:${input.hostPort}`);
  }
  const connected = docker(context, io, ["network", "connect", input.internalNetwork, containerId]);
  if (connected.status !== 0) {
    dieAfterCleanup(
      context,
      io,
      containerId,
      name,
      connected.stderr.trim() || `failed to attach ${name} to ${input.internalNetwork}`,
    );
  }
  return name;
}

/**
 * Reports a startup failure, removing the sidecar first. If that removal itself
 * fails, the message says so rather than implying a clean rollback: a published
 * sidecar that outlives its failed startup is a live loopback path, not a
 * no-op. Never returns.
 */
function dieAfterCleanup(
  context: RuntimeContext,
  io: RuntimeIO,
  containerId: string,
  name: string,
  reason: string,
): never {
  const cleanup = removeForwarder(context, io, containerId);
  die(cleanup.ok ? reason : `${reason}; and cleanup failed, ${name} is still running: ${cleanup.detail}`);
}

/**
 * True once socat holds a LISTEN socket on `hostPort`. Reads `/proc/net/tcp`
 * inside the container (column 2 is `IP:PORT` in hex, column 4 is the TCP
 * state; `0A` is LISTEN) rather than depending on `ss`/`netstat` being present
 * in the image.
 */
function socatListening(context: RuntimeContext, io: RuntimeIO, name: string, hostPort: string): boolean {
  const portHex = Number(hostPort).toString(16).toUpperCase().padStart(4, "0");
  const script = `awk '$4=="0A" && $2 ~ /:${portHex}$/ {f=1} END{exit f?0:1}' /proc/net/tcp`;
  return docker(context, io, ["exec", name, "sh", "-c", script]).status === 0;
}

/** Polls until socat binds, or fails closed if the container dies first. */
function waitForSocatBind(context: RuntimeContext, io: RuntimeIO, name: string, hostPort: string): boolean {
  for (let attempt = 0; attempt < READINESS_ATTEMPTS; attempt += 1) {
    if (socatListening(context, io, name, hostPort)) return true;
    if (!containerExists(context, io, name)) return false;
  }
  return false;
}

/** This project's live ingress forwarder container names. */
export function listIngressForwarders(context: RuntimeContext, io: RuntimeIO, projectId: string): string[] {
  const result = docker(context, io, [
    "ps",
    "-a",
    ...projectIngressForwarderFilters(projectId),
    "--format",
    "{{.Names}}",
  ]);
  if (result.status !== 0) die(result.stderr.trim() || "could not list ingress forwarders");
  return result.stdout.trim().split(/\s+/).filter(Boolean);
}

function removeHostNetworkIfUnused(
  context: RuntimeContext,
  io: RuntimeIO,
  projectId: string,
  inspectedNetwork?: IngressHostNetworkProof,
  removedContainerIds: readonly string[] = [],
): void {
  if (inspectedNetwork?.containerIds.some((id) => !removedContainerIds.includes(id))) return;
  if (listIngressForwarders(context, io, projectId).length > 0) return;
  const network = inspectedNetwork ?? inspectIngressHostNetwork(context, io, projectId, "teardown");
  if (!network) return;
  const removed = docker(context, io, ["network", "rm", network.id]);
  if (removed.status !== 0 && !exactMissingNetwork(removed.stderr, network.id)) {
    die(removed.stderr.trim() || `failed to remove Docker network ${network.name}`);
  }
}

/**
 * Removes the named forwarders, then the host-facing network if none remain. A
 * failed removal is surfaced, never swallowed: a forwarder that outlives its
 * teardown is still a dual-homed, published ingress path, so reporting success
 * while one survives would hide a live hole. On failure the still-live
 * forwarder keeps the host network in use, so it is correctly left in place.
 */
export function stopIngressForwarders(
  context: RuntimeContext,
  io: RuntimeIO,
  projectId: string,
  names: readonly string[],
  inspectedNetwork?: IngressHostNetworkProof,
): void {
  const failures: string[] = [];
  for (const name of names) {
    const removed = removeForwarder(context, io, name);
    if (!removed.ok) failures.push(removed.detail ?? name);
  }
  removeHostNetworkIfUnused(context, io, projectId, inspectedNetwork, names);
  if (failures.length > 0) die(`failed to remove ingress forwarder(s): ${failures.join("; ")}`);
}

/**
 * Removes every ingress forwarder for this project, then the host-facing
 * network. Called from runtime stop/down/destroy so no dual-homed sidecar or
 * published loopback port outlives the runtime or blocks `agent_internal`
 * teardown.
 */
export function removeAllIngressForwarders(context: RuntimeContext, io: RuntimeIO, projectId: string): void {
  stopIngressForwarders(context, io, projectId, listIngressForwarders(context, io, projectId));
}
