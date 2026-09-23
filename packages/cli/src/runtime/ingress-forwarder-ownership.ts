import { die } from "../errors.ts";
import {
  INGRESS_FORWARDER_IMAGE,
  type IngressForwarderInput,
  type IngressHostNetworkProof,
  ingressForwarderName,
  inspectIngressHostNetwork,
  listIngressForwarders,
  startIngressForwarder,
  stopIngressForwarders,
} from "./ingress-forwarder.ts";
import { dockerClientEnvOptions, parseDockerJson } from "./docker.ts";
import type { DockerContainerInspect, RuntimeContext, RuntimeIO } from "./types.ts";
import { validateIngressForwarderTeardownCandidate } from "./utility-containers.ts";

const FULL_DOCKER_CONTAINER_ID_PATTERN = /^[a-f0-9]{64}$/;
const DOCKER_IMAGE_ID_PATTERN = /^sha256:[a-f0-9]{64}$/;

export type ValidatedIngressForwarderPlan = Readonly<{
  claimedContainerIds: readonly string[];
  hostNetwork?: IngressHostNetworkProof;
  remove: () => void;
}>;

function exactMissingContainer(stderr: string, target: string): boolean {
  const escaped = target.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(
    `^(?:Error response from daemon: |Error: )?No such (?:container|object): ${escaped}\\s*$`,
    "imu",
  ).test(stderr.trim());
}

/**
 * Resolves label/name discovery into exact immutable container ownership.
 *
 * `omitInvalid` is rebuild-only: an invalid candidate remains unclaimed so the
 * rebuild residue gate refuses before any effect. Normal command cleanup uses
 * the default refusal and leaves a lookalike untouched.
 */
export function planValidatedIngressForwarders(
  context: RuntimeContext,
  io: RuntimeIO,
  projectId: string,
  options: Readonly<{
    names?: readonly string[];
    omitInvalid?: boolean;
  }> = {},
): ValidatedIngressForwarderPlan {
  const names = [...new Set(options.names ?? listIngressForwarders(context, io, projectId))];
  const candidates: DockerContainerInspect[] = [];
  for (const name of names) {
    const result = io.capture(
      "docker",
      ["container", "inspect", name],
      dockerClientEnvOptions(context),
    );
    if (result.status !== 0) {
      if (exactMissingContainer(result.stderr, name)) continue;
      throw new Error(`could not inspect ingress forwarder ${name}: ${result.stderr.trim() || `exit ${result.status}`}`);
    }
    const inspected = parseDockerJson<DockerContainerInspect[]>(result, `docker inspect ingress forwarder ${name}`);
    const candidate = inspected?.[0];
    if (!candidate || inspected.length !== 1 || candidate.Name?.replace(/^\//, "") !== name) {
      throw new Error(`ingress forwarder ${name} did not resolve to one exact Docker container`);
    }
    candidates.push(candidate);
  }
  // The managed bridge has a versioned name and minted labels; only that
  // labeled, exact-ID identity ever becomes deletion authority. A foreign
  // bridge can reproduce a public name, so names alone never authorize
  // anything here. A missing bridge no longer blocks container removal: the
  // four-fact container proof stands on its own, and the bridge cleanup step
  // simply finds nothing to remove.
  const hostNetwork = inspectIngressHostNetwork(context, io, projectId, "teardown");

  const targetIds = new Set(candidates.flatMap((candidate) => candidate.Id ? [candidate.Id] : []));
  const validationCandidates = [...candidates];
  const endpointIds = new Set(hostNetwork?.containerIds ?? []);
  let networkInvalidReason: string | undefined;
  const byId = new Map(validationCandidates.flatMap((candidate) => candidate.Id ? [[candidate.Id, candidate] as const] : []));
  for (const endpointId of hostNetwork?.containerIds ?? []) {
    if (byId.has(endpointId)) continue;
    const result = io.capture(
      "docker",
      ["container", "inspect", endpointId],
      dockerClientEnvOptions(context),
    );
    if (result.status !== 0) {
      networkInvalidReason = `could not inspect ingress endpoint ${endpointId}: ${result.stderr.trim() || `exit ${result.status}`}`;
      break;
    }
    const inspected = parseDockerJson<DockerContainerInspect[]>(
      result,
      `docker inspect ingress endpoint ${endpointId}`,
    );
    const candidate = inspected?.[0];
    if (!candidate || inspected.length !== 1 || candidate.Id !== endpointId) {
      networkInvalidReason = `ingress endpoint ${endpointId} did not resolve to one exact Docker container`;
      break;
    }
    byId.set(endpointId, candidate);
    validationCandidates.push(candidate);
  }

  if (networkInvalidReason) {
    throw new Error(`refusing unverified ingress host network ${hostNetwork?.name ?? "<missing>"}: ${networkInvalidReason}`);
  }

  if (validationCandidates.length === 0) {
    return Object.freeze({
      claimedContainerIds: Object.freeze([]),
      ...(hostNetwork ? { hostNetwork } : {}),
      remove: () => stopIngressForwarders(context, io, projectId, [], hostNetwork),
    });
  }

  const imageResult = io.capture(
    "docker",
    ["image", "inspect", "--format", "{{.Id}}", INGRESS_FORWARDER_IMAGE],
    dockerClientEnvOptions(context),
  );
  const expectedImageId = imageResult.stdout.trim();
  if (imageResult.status !== 0 || !DOCKER_IMAGE_ID_PATTERN.test(expectedImageId)) {
    throw new Error(
      `could not resolve the immutable ingress forwarder image: ${imageResult.stderr.trim() || "invalid Docker image id"}`,
    );
  }

  const validatedIds: string[] = [];
  for (const candidate of validationCandidates) {
    const name = candidate.Name?.replace(/^\//, "") ?? "<unnamed>";
    const containerId = candidate.Id;
    const issues = validateIngressForwarderTeardownCandidate({
      container: candidate,
      expectedImageId,
      projectId,
    });
    if (!containerId || !FULL_DOCKER_CONTAINER_ID_PATTERN.test(containerId)) {
      issues.push({
        code: "utility-ingress-forwarder-shape",
        severity: "error",
        message: `ingress forwarder ${name} must have one full Docker container ID`,
      });
    }
    if (issues.length > 0) {
      if (containerId && endpointIds.has(containerId)) {
        throw new Error(`refusing unverified ingress forwarder ${name}: ${issues.map((issue) => issue.message).join("; ")}`);
      }
      if (options.omitInvalid) continue;
      throw new Error(
        `refusing to remove unverified ingress forwarder ${name}: ${issues.map((issue) => issue.message).join("; ")}`,
      );
    }
    if (containerId && targetIds.has(containerId)) validatedIds.push(containerId);
  }

  return Object.freeze({
    claimedContainerIds: Object.freeze([...validatedIds]),
    ...(hostNetwork ? { hostNetwork } : {}),
    remove: () => stopIngressForwarders(context, io, projectId, validatedIds, hostNetwork),
  });
}

/** Removes only exact, shape-validated forwarders and returns their count. */
export function removeValidatedIngressForwarders(
  context: RuntimeContext,
  io: RuntimeIO,
  projectId: string,
  names?: readonly string[],
): number {
  let plan: ValidatedIngressForwarderPlan;
  try {
    plan = planValidatedIngressForwarders(context, io, projectId, { names });
  } catch (error) {
    return die(error instanceof Error ? error.message : String(error));
  }
  plan.remove();
  return plan.claimedContainerIds.length;
}

/**
 * Replaces one exact forwarder on the current versioned, labeled host bridge.
 * Only that bridge is ever creation or deletion authority; an unowned
 * lookalike network is refused, never adopted.
 */
export function replaceValidatedIngressForwarder(
  context: RuntimeContext,
  io: RuntimeIO,
  projectId: string,
  input: IngressForwarderInput,
): string {
  const name = ingressForwarderName(projectId, input.purpose, input.hostPort);
  let plan: ValidatedIngressForwarderPlan;
  try {
    plan = planValidatedIngressForwarders(context, io, projectId, { names: [name] });
  } catch (error) {
    return die(error instanceof Error ? error.message : String(error));
  }
  plan.remove();
  return startIngressForwarder(context, io, input, plan.hostNetwork);
}

/** Rebuild leaves invalid candidates unclaimed for its pre-effect residue gate. */
export function planValidatedIngressForwardersForRebuild(
  context: RuntimeContext,
  io: RuntimeIO,
  projectId: string,
): ValidatedIngressForwarderPlan {
  return planValidatedIngressForwarders(context, io, projectId, { omitInvalid: true });
}
