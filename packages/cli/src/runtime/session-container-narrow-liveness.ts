import { parseStrictJson } from "../control/strict-json.ts";
import { isExactSessionSourceIpv4 } from "@runfree/runtime-contracts/session-registry";

import { SESSION_CONTAINER_INSPECT_MAX_BYTES } from "./session-container-proof.ts";
import { isRecord } from "../strict-primitives.ts";

const DOCKER_OBJECT_ID_PATTERN = /^[a-f0-9]{64}$/;

export type SessionContainerNarrowRunningIdentity = Readonly<{
  containerId: string;
  composeProject: string;
  networkId: string;
  sourceIp: string;
  dockerPid: number;
  dockerStartedAt: string;
  networkEndpointId: string;
}>;

// The five refusals below prove nothing about the inspected incarnation, so a
// consumer must treat them as "no observation" rather than as an observed
// change. The first three mean the answer never became one inspection of one
// container; the identity refusal is the caller's own argument being
// malformed, not Docker's answer; and `NetworkSettings` that is not even a
// record is an unreadable answer rather than an observed change. Every other
// message in this module names a field the inspection did resolve, and
// resolved differently.
//
// They are constants, exported, and used at their own throw sites because the
// heartbeat classifies on the exact text (`session-file-heartbeat.ts`,
// invariant 4): a message edited here but not there would silently reclassify
// a skipped beat as a mismatch, and a mismatch deletes a live session's file.
export const NARROW_LIVENESS_INVALID_IDENTITY = "session-container narrow running identity is invalid";
export const NARROW_LIVENESS_INSPECT_OVERSIZE = "Docker session container inspection exceeds the size limit";
export const NARROW_LIVENESS_INSPECT_MALFORMED = "Docker returned malformed session container inspection JSON";
export const NARROW_LIVENESS_INSPECT_NOT_EXACTLY_ONE = "Docker did not return exactly one session container inspection";
export const NARROW_LIVENESS_NETWORK_INSPECT_MALFORMED = "session container network inspection is malformed";

export const NARROW_LIVENESS_UNREADABLE_INSPECT_MESSAGES: ReadonlySet<string> = new Set([
  NARROW_LIVENESS_INSPECT_OVERSIZE,
  NARROW_LIVENESS_INSPECT_MALFORMED,
  NARROW_LIVENESS_INSPECT_NOT_EXACTLY_ONE,
  NARROW_LIVENESS_INVALID_IDENTITY,
  NARROW_LIVENESS_NETWORK_INSPECT_MALFORMED,
]);

function assertIdentity(identity: SessionContainerNarrowRunningIdentity): void {
  if (!DOCKER_OBJECT_ID_PATTERN.test(identity.containerId)
    || !DOCKER_OBJECT_ID_PATTERN.test(identity.networkId)
    || !DOCKER_OBJECT_ID_PATTERN.test(identity.networkEndpointId)
    || !Number.isSafeInteger(identity.dockerPid)
    || identity.dockerPid < 1
    || typeof identity.dockerStartedAt !== "string"
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(identity.dockerStartedAt)
    || identity.dockerStartedAt.startsWith("0001-")
    || !Number.isFinite(Date.parse(identity.dockerStartedAt))
    || !isExactSessionSourceIpv4(identity.sourceIp)
    || typeof identity.composeProject !== "string"
    || identity.composeProject.length < 1) {
    throw new Error(NARROW_LIVENESS_INVALID_IDENTITY);
  }
}

/**
 * Validates only mutable running-incarnation identity. Image, label, mount,
 * environment, route, and capability contracts belong to the one full proof.
 */
export function assertSessionContainerNarrowRunningInspect(
  source: string,
  identity: SessionContainerNarrowRunningIdentity,
): void {
  assertIdentity(identity);
  if (Buffer.byteLength(source) > SESSION_CONTAINER_INSPECT_MAX_BYTES) {
    throw new Error(NARROW_LIVENESS_INSPECT_OVERSIZE);
  }
  let parsed: unknown;
  try {
    parsed = parseStrictJson(source);
  } catch {
    throw new Error(NARROW_LIVENESS_INSPECT_MALFORMED);
  }
  if (!Array.isArray(parsed) || parsed.length !== 1 || !isRecord(parsed[0])) {
    throw new Error(NARROW_LIVENESS_INSPECT_NOT_EXACTLY_ONE);
  }
  const inspect = parsed[0];
  if (inspect.Id !== identity.containerId) {
    throw new Error("Docker inspected a different session container id");
  }
  if (!isRecord(inspect.State)
    || inspect.State.Running !== true
    || inspect.State.Status !== "running"
    || inspect.State.Dead !== false
    || inspect.State.Paused !== false
    || inspect.State.Restarting !== false
    || inspect.State.OOMKilled !== false
    || inspect.State.Error !== ""
    || inspect.State.ExitCode !== 0) {
    throw new Error("session container is not in exact running state");
  }
  if (inspect.State.Pid !== identity.dockerPid) {
    throw new Error("session container Docker process id changed");
  }
  if (inspect.State.StartedAt !== identity.dockerStartedAt) {
    throw new Error("session container Docker start identity changed");
  }
  if (!isRecord(inspect.NetworkSettings) || !isRecord(inspect.NetworkSettings.Networks)) {
    throw new Error(NARROW_LIVENESS_NETWORK_INSPECT_MALFORMED);
  }
  const entries = Object.entries(inspect.NetworkSettings.Networks);
  if (entries.length !== 1 || !isRecord(entries[0]?.[1])) {
    throw new Error("session container is not attached only to the selected network");
  }
  const [networkKey, network] = entries[0] as [string, Record<string, unknown>];
  const networkName = `${identity.composeProject}_agent_internal`;
  if ((networkKey !== identity.networkId && networkKey !== networkName)
    || network.NetworkID !== identity.networkId) {
    throw new Error("session container network identity changed");
  }
  if (network.IPAddress !== identity.sourceIp) {
    throw new Error("session container IPv4 address changed");
  }
  if (network.GlobalIPv6Address !== "") {
    throw new Error("session container acquired an IPv6 address");
  }
  if (isRecord(network.IPAMConfig)
    && network.IPAMConfig.IPv6Address !== undefined
    && network.IPAMConfig.IPv6Address !== "") {
    throw new Error("session container requested an IPv6 address");
  }
  if (network.EndpointID !== identity.networkEndpointId) {
    throw new Error("session container network endpoint identity changed");
  }
}
