// Exact discovery, removal, and stale reclaim of MCP OAuth callback forwarders.
//
// Capture-only and free of runtime-context dependencies, so the shared ordered
// session teardown (`session-file-teardown.ts`) and reconcile can prove a
// session's callback route gone before its record releases the address. See
// `session-mcp-callback.ts` for the lifecycle this serves.

import type * as childProcess from "node:child_process";

import { PROJECT_ID_LABEL } from "./constants.ts";
import {
  CONTAINER_ROLE_LABEL,
  INGRESS_PURPOSE_LABEL,
  projectIngressForwarderFilters,
  wholeProjectContainerFilters,
} from "./container-inventory.ts";
import { parseDockerJson } from "./docker.ts";
import { INGRESS_FORWARDER_IMAGE, ingressHostNetworkName } from "./ingress-forwarder.ts";
import type { CaptureResult, DockerContainerInspect, RuntimeIO } from "./types.ts";
import { validateIngressForwarderTeardownCandidate } from "./utility-containers.ts";

export const MCP_CALLBACK_PURPOSE = "mcp-callback" as const;

/** The forwarder env that binds it to its owning session. Asserted by topology validation. */
export const SESSION_CALLBACK_SESSION_ID_ENV = "RUNFREE_CALLBACK_SESSION_ID";
export const SESSION_CALLBACK_CONTAINER_ENV = "RUNFREE_CALLBACK_SESSION_CONTAINER";

const FULL_DOCKER_ID_PATTERN = /^[a-f0-9]{64}$/;
const SESSION_ID_LABEL = "io.runfree.session-id";
const DOCKER_IMAGE_ID_PATTERN = /^sha256:[a-f0-9]{64}$/;

export type DockerCapture = Pick<RuntimeIO, "capture">;

export type CaptureInput = Readonly<{
  io: DockerCapture;
  dockerOptions?: childProcess.SpawnSyncOptions;
  projectId: string;
}>;

function capture(input: CaptureInput, args: readonly string[]): CaptureResult {
  return input.io.capture("docker", [...args], { ...(input.dockerOptions ?? {}), maxBuffer: 8 * 1024 * 1024 });
}

export function envMap(container: DockerContainerInspect): Record<string, string> {
  const result: Record<string, string> = {};
  for (const entry of container.Config?.Env ?? []) {
    const index = entry.indexOf("=");
    if (index > 0) result[entry.slice(0, index)] = entry.slice(index + 1);
  }
  return result;
}


type ForwarderInventory = Readonly<{
  forwarders: readonly DockerContainerInspect[];
}>;

/**
 * This project's mcp-callback forwarders, inspected. Unknown is never absence:
 * a failed listing or inspection throws, so no caller releases an address or
 * reuses a port on a guess.
 */
export function inspectCallbackForwarders(input: CaptureInput): ForwarderInventory {
  // A forwarder can vanish between the listing and the inspection (another
  // exact removal, or `--rm` after its socat exited); one fresh listing
  // answers that race. A second failure is reported, never read as absence.
  let failure = "";
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const listed = capture(input, [
      "ps",
      "-a",
      "--no-trunc",
      ...projectIngressForwarderFilters(input.projectId),
      "--filter",
      `label=${INGRESS_PURPOSE_LABEL}=${MCP_CALLBACK_PURPOSE}`,
      "--format",
      "{{.ID}}",
    ]);
    if (listed.status !== 0) {
      throw new Error(`could not list MCP OAuth callback forwarders: ${listed.stderr.trim() || `exit ${listed.status}`}`);
    }
    const ids = listed.stdout.trim().split(/\s+/u).filter(Boolean);
    if (ids.some((id) => !FULL_DOCKER_ID_PATTERN.test(id))) {
      throw new Error("MCP OAuth callback forwarder listing returned an inexact container id");
    }
    if (ids.length === 0) return Object.freeze({ forwarders: Object.freeze([]) });
    const inspected = capture(input, ["container", "inspect", ...ids]);
    const parsed = inspected.status === 0
      ? parseDockerJson<DockerContainerInspect[]>(inspected, "docker inspect MCP OAuth callback forwarders")
      : undefined;
    if (Array.isArray(parsed) && parsed.length === ids.length
      && parsed.every((forwarder, index) => forwarder.Id === ids[index])) {
      return Object.freeze({ forwarders: Object.freeze(parsed) });
    }
    failure = inspected.stderr.trim() || `exit ${inspected.status}`;
  }
  throw new Error(`could not inspect MCP OAuth callback forwarders: ${failure}`);
}

export function forwarderHostPort(forwarder: DockerContainerInspect): number | undefined {
  const value = envMap(forwarder).INGRESS_HOST_PORT;
  if (value === undefined || !/^\d{1,5}$/u.test(value)) return undefined;
  return Number(value);
}

function resolvedIngressImageId(input: CaptureInput): string {
  const image = capture(input, ["image", "inspect", "--format", "{{.Id}}", INGRESS_FORWARDER_IMAGE]);
  const imageId = image.stdout.trim();
  if (image.status !== 0 || !DOCKER_IMAGE_ID_PATTERN.test(imageId)) {
    throw new Error(`could not resolve the immutable ingress forwarder image: ${image.stderr.trim() || "invalid Docker image id"}`);
  }
  return imageId;
}

function exactMissingContainer(stderr: string, target: string): boolean {
  return new RegExp(
    `^(?:Error response from daemon: |Error: )?No such container: ${target}\\s*$`,
    "imu",
  ).test(stderr.trim());
}

/**
 * Removes exact, ownership-proved forwarders by full container id. Deletion
 * authority is the project/role labels plus the resolved immutable image id —
 * the same four-fact teardown proof every ingress removal uses — never a name.
 */
function removeExactForwarders(input: CaptureInput, forwarders: readonly DockerContainerInspect[]): number {
  if (forwarders.length === 0) return 0;
  const imageId = resolvedIngressImageId(input);
  const failures: string[] = [];
  for (const forwarder of forwarders) {
    const id = forwarder.Id ?? "";
    const issues = validateIngressForwarderTeardownCandidate({ container: forwarder, expectedImageId: imageId, projectId: input.projectId });
    if (!FULL_DOCKER_ID_PATTERN.test(id) || issues.length > 0) {
      failures.push(`refusing to remove unverified MCP OAuth callback forwarder ${forwarder.Name ?? id}: ${
        issues.map((issue) => issue.message).join("; ") || "no exact container id"}`);
      continue;
    }
    const removed = capture(input, ["rm", "-f", id]);
    if (removed.status !== 0 && !exactMissingContainer(removed.stderr, id)) {
      failures.push(`Docker failed to remove MCP OAuth callback forwarder ${id}: ${removed.stderr.trim() || `exit ${removed.status}`}`);
    }
  }
  if (failures.length > 0) throw new Error(failures.join("; "));
  return forwarders.length;
}

/**
 * Removes every mcp-callback forwarder that routes to this session: the ones
 * bound to its session id, and any unbound (pre-2026-09-30) one that targets
 * its address. Throws when absence cannot be proved, so the caller keeps the
 * session record — and with it the address reservation — for a later retry.
 */
export function removeSessionMcpCallbackIngress(
  input: CaptureInput & Readonly<{ sessionId: string; sourceIp: string }>,
): number {
  const { forwarders } = inspectCallbackForwarders(input);
  const routed = forwarders.filter((forwarder) => {
    const env = envMap(forwarder);
    const boundSession = env[SESSION_CALLBACK_SESSION_ID_ENV];
    if (boundSession !== undefined) return boundSession === input.sessionId || env.INGRESS_TARGET === input.sourceIp;
    return env.INGRESS_TARGET === input.sourceIp;
  });
  return removeExactForwarders(input, routed);
}

/**
 * Whether an mcp-callback forwarder routes to exactly its one live owner:
 * running, attached to both its networks, bound (session id and exact session
 * container id), and its bound container a running session of this project
 * that carries the bound session id and holds the forwarder's target address.
 * Anything else is a dead or unowned route. Pure over inspected state.
 */
export function mcpCallbackForwarderRoutesToLiveOwner(
  forwarder: DockerContainerInspect,
  runningSessions: readonly DockerContainerInspect[],
  network: Readonly<{ projectId: string; internalNetwork: string }>,
): boolean {
  if (forwarder.State?.Running !== true) return false;
  const networks = forwarder.NetworkSettings?.Networks ?? {};
  if (!networks[network.internalNetwork] || !networks[ingressHostNetworkName(network.projectId)]) return false;
  const env = envMap(forwarder);
  const boundContainer = env[SESSION_CALLBACK_CONTAINER_ENV];
  const boundSession = env[SESSION_CALLBACK_SESSION_ID_ENV];
  if (boundContainer === undefined || boundSession === undefined) return false;
  const owner = runningSessions.find((container) => container.Id === boundContainer);
  return owner !== undefined
    && owner.State?.Running === true
    && owner.Config?.Labels?.[PROJECT_ID_LABEL] === network.projectId
    && owner.Config?.Labels?.[CONTAINER_ROLE_LABEL] === "session-agent"
    && owner.Config?.Labels?.[SESSION_ID_LABEL] === boundSession
    && owner.NetworkSettings?.Networks?.[network.internalNetwork]?.IPAddress === env.INGRESS_TARGET;
}

/**
 * Reclaims mcp-callback forwarders that route to no live owner (see
 * `mcpCallbackForwarderRoutesToLiveOwner`): a killed launcher's leftover, a
 * forwarder that never finished starting or attaching, and any unbound
 * forwarder from before session-owned callbacks (whose target cannot be tied
 * to one session, so it is never trusted as a route). Removing one cannot cut
 * a live session's route; leaving it would make every later admission's
 * participant proof refuse. Runs under the lifecycle lock; an inspection it
 * cannot complete throws rather than counting anything as dead.
 */
export function reclaimStaleSessionMcpCallbackForwarders(
  input: CaptureInput & Readonly<{ internalNetwork: string }>,
): number {
  const { forwarders } = inspectCallbackForwarders(input);
  if (forwarders.length === 0) return 0;
  const sessions = capture(input, [
    "ps",
    "--no-trunc",
    ...wholeProjectContainerFilters(input.projectId),
    "--filter",
    `label=${CONTAINER_ROLE_LABEL}=session-agent`,
    "--format",
    "{{.ID}}",
  ]);
  if (sessions.status !== 0) {
    throw new Error(`could not list running sessions: ${sessions.stderr.trim() || `exit ${sessions.status}`}`);
  }
  const sessionIds = sessions.stdout.trim().split(/\s+/u).filter(Boolean);
  if (sessionIds.some((id) => !FULL_DOCKER_ID_PATTERN.test(id))) {
    throw new Error("running session listing returned an inexact container id");
  }
  let running: readonly DockerContainerInspect[] = [];
  if (sessionIds.length > 0) {
    const inspected = capture(input, ["container", "inspect", ...sessionIds]);
    const parsed = inspected.status === 0
      ? parseDockerJson<DockerContainerInspect[]>(inspected, "docker inspect running sessions")
      : undefined;
    if (!Array.isArray(parsed) || parsed.length !== sessionIds.length) {
      throw new Error(`could not inspect running sessions: ${inspected.stderr.trim() || `exit ${inspected.status}`}`);
    }
    running = parsed;
  }
  const stale = forwarders.filter((forwarder) => !mcpCallbackForwarderRoutesToLiveOwner(forwarder, running, input));
  return removeExactForwarders(input, stale);
}
