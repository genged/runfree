import { wholeProjectContainerFilters } from "./container-inventory.ts";
import { parseStrictJson } from "../control/strict-json.ts";
import { CliError } from "../errors.ts";
import { remedy } from "../remedies.ts";
import { isRecord, stableJson } from "../strict-primitives.ts";
import {
  readEffectiveControlPlaneV2,
  type ControlPlaneEffectiveSelectionV2,
} from "./component-state-v2.ts";
import { controlPlaneTopologyProjectionV2 } from "./control-plane-topology-v2.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import { dockerClientEnvOptions, parseDockerJson } from "./docker.ts";
import { INGRESS_FORWARDER_IMAGE, ingressHostNetworkName, inspectIngressHostNetwork, listIngressForwarders } from "./ingress-forwarder.ts";
import { validateIngressForwarderTeardownCandidate, validateInternalNetworkParticipants } from "./utility-containers.ts";
import {
  allocateSessionSourceIp,
  parseSessionNetworkAttachments,
  type SessionNetworkAttachment,
} from "./session-container-reconciliation.ts";
import {
  assertSessionContainerRecordProject,
  parseSessionContainerRecordV2,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { DockerContainerInspect, RuntimeContext, RuntimeIO, RuntimeValidationComponents } from "./types.ts";

const DOCKER_OBJECT_ID_PATTERN = /^[a-f0-9]{64}$/;
const MAX_NETWORK_INSPECT_BYTES = 512 * 1024;

export type ExactControlPlaneInternalParticipant = Readonly<{
  role: "request-proxy";
  containerId: string;
  containerName: string;
  sourceIp: string;
}>;

export type ExactIngressInternalParticipant = Readonly<{
  containerId: string;
  containerName: string;
  sourceIp: string;
  imageId: string;
}>;

declare const controlPlaneInternalParticipantAuthorityBrand: unique symbol;

export type ControlPlaneInternalParticipantAuthority = Readonly<{
  readonly [controlPlaneInternalParticipantAuthorityBrand]: true;
  version: 1;
  projectId: string;
  composeProject: string;
  controlPlaneGenerationDigest: string;
  controlPlaneMaterializationDigest: string;
  admissionContractEpoch: number;
  networkId: string;
  networkName: string;
  subnet: string;
  participants: readonly ExactControlPlaneInternalParticipant[];
  ingressParticipants: readonly ExactIngressInternalParticipant[];
}>;

type ExactNetworkParticipant = Readonly<SessionNetworkAttachment & {
  networkEndpointId: string;
}>;

declare const exactInternalNetworkBaselineBrand: unique symbol;

export type ExactInternalNetworkParticipantBaseline = Readonly<{
  readonly [exactInternalNetworkBaselineBrand]: true;
  projectId: string;
  composeProject: string;
  controlPlaneGenerationDigest: string;
  admissionContractEpoch: number;
  networkId: string;
  networkName: string;
  subnet: string;
  participants: readonly ExactNetworkParticipant[];
}>;

const validatedBaselines = new WeakSet<object>();
const baselineBindings = new WeakMap<object, Readonly<{
  authority: ControlPlaneInternalParticipantAuthority;
  controlPlaneParticipants: readonly ExactNetworkParticipant[];
  records: readonly SessionContainerRecordV2[];
}>>();
const participantAuthorities = new WeakSet<object>();
const participantAuthorityBindings = new WeakMap<object, Readonly<{
  lifecycleLock: ProjectLifecycleLock;
  stateDir: string;
  durableSelectionSource: string;
  selection: ControlPlaneEffectiveSelectionV2;
  participants: readonly ExactControlPlaneInternalParticipant[];
  ingressParticipants: readonly ExactIngressInternalParticipant[];
}>>();

function sameRuntimeComponents(
  left: RuntimeValidationComponents,
  right: RuntimeValidationComponents,
): boolean {
  return left.digestSchemaVersion === right.digestSchemaVersion
    && left.selectedAgentImageInputDigest === right.selectedAgentImageInputDigest
    && left.proxyImageInputDigest === right.proxyImageInputDigest
    && left.topologyDigest === right.topologyDigest
    && left.runtimeGenerationDigest === right.runtimeGenerationDigest;
}

function activeRuntimeComponents(plan: ActiveRuntimePlan): RuntimeValidationComponents {
  const components = plan.activeRuntime.manifest?.components ?? plan.components;
  return {
    digestSchemaVersion: components.digestSchemaVersion,
    selectedAgentImageInputDigest: components.selectedAgentImageInputDigest,
    proxyImageInputDigest: components.proxyImageInputDigest,
    topologyDigest: components.topologyDigest,
    runtimeGenerationDigest: components.runtimeGenerationDigest,
  };
}

function exactDurableSelection(stateDir: string): Readonly<{
  selection: ControlPlaneEffectiveSelectionV2;
  source: string;
}> {
  const effective = readEffectiveControlPlaneV2(stateDir);
  if (!effective) throw new Error("control-plane participant authority requires a durable effective selection");
  return Object.freeze({
    selection: effective.selection,
    source: stableJson(effective),
  });
}

function participantAuthorityBinding(
  value: unknown,
): Readonly<{
  lifecycleLock: ProjectLifecycleLock;
  stateDir: string;
  durableSelectionSource: string;
  selection: ControlPlaneEffectiveSelectionV2;
  participants: readonly ExactControlPlaneInternalParticipant[];
  ingressParticipants: readonly ExactIngressInternalParticipant[];
}> {
  if (value === null || typeof value !== "object" || !participantAuthorities.has(value)) {
    throw new Error("control-plane participant authority was not minted by the canonical builder");
  }
  const authority = value as ControlPlaneInternalParticipantAuthority;
  const binding = participantAuthorityBindings.get(value);
  if (!binding
    || authority.projectId !== binding.selection.projectId
    || authority.composeProject !== binding.selection.composeProject
    || authority.controlPlaneGenerationDigest !== binding.selection.controlPlaneGenerationDigest
    || authority.controlPlaneMaterializationDigest !== binding.selection.controlPlaneMaterializationDigest
    || authority.admissionContractEpoch !== binding.selection.admissionContractEpoch
    || authority.networkId !== binding.selection.networkIds.agentInternal
    || authority.networkName !== `${binding.selection.composeProject}_agent_internal`
    || authority.participants !== binding.participants) {
    throw new Error("control-plane participant authority was not minted by the canonical builder");
  }
  binding.lifecycleLock.assertHeld();
  const current = exactDurableSelection(binding.stateDir);
  binding.lifecycleLock.assertHeld();
  if (current.source !== binding.durableSelectionSource) {
    throw new Error("durable effective control plane changed after participant authority was minted");
  }
  return binding;
}

export function createControlPlaneInternalParticipantAuthority(input: Readonly<{
  plan: ActiveRuntimePlan;
  context: RuntimeContext;
  lifecycleLock: ProjectLifecycleLock;
  io: RuntimeIO;
}>): ControlPlaneInternalParticipantAuthority {
  const { plan, context, lifecycleLock } = input;
  lifecycleLock.assertHeld();
  if (context.validatedRuntime?.proofVersion !== 4) {
    throw new Error("control-plane participant authority requires runtime validation proof v4");
  }
  const proof = context.validatedRuntime;
  if (context.projectRoot !== plan.projectRoot
    || context.project.paths.stateDir !== plan.paths.stateDir
    || context.runtimeRoot !== plan.activeRuntime.activeRuntimeRoot
    || context.runtimeGenerationV2 === undefined
    || stableJson(context.runtimeGenerationV2) !== stableJson(plan.generationV2)
    || context.network === undefined
    || stableJson(context.network) !== stableJson(plan.network)) {
    throw new Error("runtime context does not match the active runtime plan");
  }
  const activeComponents = activeRuntimeComponents(plan);
  // The proof binds the schema-v2 control-plane generation (session inputs are
  // attested by admission); the context still carries the composite state for
  // Compose interpolation and is checked against the plan separately.
  if (!context.runtimeComponents
    || !sameRuntimeComponents(context.runtimeComponents, activeComponents)
    || stableJson(proof.components) !== stableJson(plan.generationV2.controlPlane)
    || proof.projectId !== plan.projectId
    || proof.contractHash === undefined
    || !DOCKER_OBJECT_ID_PATTERN.test(proof.proxyId)) {
    throw new Error("runtime validation proof does not match the active runtime plan");
  }

  const topology = controlPlaneTopologyProjectionV2(plan);
  const internalNetwork = topology.networks.find((network) => network.logicalName === "agent_internal");
  const proxyInternal = topology.proxy.networks.find((network) => network.network === "agent_internal");
  if (!internalNetwork?.subnet || !proxyInternal?.ipv4Address) {
    throw new Error("active runtime plan has no exact internal participant topology");
  }
  if (proof.mcpOAuthCallbackPort !== plan.mcpOAuth.callbackPort
    || proof.mcpOAuthCallbackTopologyVersion !== 2) {
    throw new Error("runtime validation proof does not match the callback control plane");
  }

  const durable = exactDurableSelection(plan.paths.stateDir);
  lifecycleLock.assertHeld();
  const { selection } = durable;
  const expectedSidecars: never[] = [];
  if (selection.projectId !== plan.projectId
    || selection.composeProject !== plan.composeProjectName
    || selection.controlPlaneGenerationDigest
      !== plan.generationV2.controlPlane.controlPlaneGenerationDigest
    || selection.admissionContractEpoch !== plan.generationV2.controlPlane.admissionContractEpoch
    || selection.proxyContainerId !== proof.proxyId
    || selection.securityContractHash !== proof.contractHash
    || stableJson(selection.sidecarContainerIds) !== stableJson(expectedSidecars)
    || selection.networkIds.agentInternal === selection.networkIds.proxyEgress) {
    throw new Error("durable effective selection does not match the validated active runtime");
  }
  const effective = readEffectiveControlPlaneV2(plan.paths.stateDir);
  if (!effective
    || effective.manifest.controlPlaneMaterializationDigest
      !== selection.controlPlaneMaterializationDigest
    || effective.manifest.proxyImageRef !== plan.activeRuntime.proxyImage
    || effective.manifest.proxyImageId !== selection.proxyImageId
    || stableJson(effective.manifest.generation) !== stableJson(plan.generationV2.controlPlane)
    || effective.manifest.renderedControlPlaneSha256
      !== plan.generationV2.controlPlane.controlPlaneTopologyDigest) {
    throw new Error("durable effective materialization does not match the active runtime plan");
  }

  const participants = Object.freeze([
    Object.freeze({
      role: "request-proxy" as const,
      containerId: proof.proxyId,
      containerName: `${plan.composeProjectName}-proxy-1`,
      sourceIp: proxyInternal.ipv4Address,
    }),
    // There is no standing agent participant: sessions join and leave through
    // admission, and the baseline's job is exactly to know the fixed
    // control-plane participants they join beside.
  ]);
  const ids = participants.map((participant) => participant.containerId);
  const ips = participants.map((participant) => participant.sourceIp);
  if (new Set(ids).size !== ids.length || new Set(ips).size !== ips.length) {
    throw new Error("control-plane internal participant identities are not distinct");
  }
  let ingressParticipants: readonly ExactIngressInternalParticipant[];
  try {
    ingressParticipants = inspectIngressParticipants(input, selection, internalNetwork.runtimeName);
  } catch (error) {
    throw new CliError(`${error instanceof Error ? error.message : String(error)}; retry after repairing or stopping the forwarder, `
      + `or run \`${remedy.destroyForce()}\` to clear the project runtime and all its sessions`);
  }
  lifecycleLock.assertHeld();
  const authority = Object.freeze({
    version: 1 as const,
    projectId: selection.projectId,
    composeProject: selection.composeProject,
    controlPlaneGenerationDigest: selection.controlPlaneGenerationDigest,
    controlPlaneMaterializationDigest: selection.controlPlaneMaterializationDigest,
    admissionContractEpoch: selection.admissionContractEpoch,
    networkId: selection.networkIds.agentInternal,
    networkName: internalNetwork.runtimeName,
    subnet: internalNetwork.subnet,
    participants,
    ingressParticipants,
  }) as ControlPlaneInternalParticipantAuthority;
  participantAuthorities.add(authority);
  participantAuthorityBindings.set(authority, Object.freeze({
    lifecycleLock,
    stateDir: plan.paths.stateDir,
    durableSelectionSource: durable.source,
    selection,
    participants,
    ingressParticipants,
  }));
  return authority;
}

/** Utility membership is shape proof, never session or deletion authority. */
function inspectIngressParticipants(
  input: Readonly<{ plan: ActiveRuntimePlan; context: RuntimeContext; io: RuntimeIO; lifecycleLock: ProjectLifecycleLock }>,
  selection: ControlPlaneEffectiveSelectionV2,
  internalNetwork: string,
): readonly ExactIngressInternalParticipant[] {
  const { context, io, plan } = input;
  const names = listIngressForwarders(context, io, selection.projectId);
  if (names.length === 0) return Object.freeze([]);
  const hostNetwork = inspectIngressHostNetwork(context, io, selection.projectId);
  if (!hostNetwork) throw new Error("ingress participants require a verified host network");
  const options = { ...dockerClientEnvOptions(context), maxBuffer: 8 * 1024 * 1024 };
  const image = io.capture("docker", ["image", "inspect", "--format", "{{.Id}}", INGRESS_FORWARDER_IMAGE], options);
  const imageId = image.stdout.trim();
  if (image.status !== 0 || !/^sha256:[a-f0-9]{64}$/u.test(imageId)) {
    throw new Error("could not resolve the immutable ingress forwarder image");
  }
  const sessions = io.capture("docker", ["ps", "--no-trunc",
    ...wholeProjectContainerFilters(selection.projectId),
    "--filter", "label=io.runfree.container-role=session-agent", "--format", "{{.ID}}"], options);
  const sessionIds = sessions.stdout.trim().split(/\s+/u).filter(Boolean);
  if (sessions.status !== 0 || sessionIds.some((id) => !DOCKER_OBJECT_ID_PATTERN.test(id))) {
    throw new Error("could not inventory live ingress session targets");
  }
  const result = io.capture("docker", ["container", "inspect", ...names, ...sessionIds], options);
  if (result.status !== 0) throw new Error("could not inspect ingress participants and their session targets");
  const inspected = parseDockerJson<DockerContainerInspect[]>(result, "ingress participant inspection");
  if (!Array.isArray(inspected) || inspected.length !== names.length + sessionIds.length) {
    throw new Error("ingress participant inspection is incomplete");
  }
  const proxy = { Id: selection.proxyContainerId };
  const issues = validateInternalNetworkParticipants({
    attached: [proxy, ...inspected.slice(0, names.length), ...inspected.slice(names.length).filter((container) => container.State?.Running === true)],
    proxy,
    projectId: selection.projectId,
    internalNetwork,
    callbackRelay: { port: String(plan.mcpOAuth.callbackPort) },
  });
  const participants = inspected.slice(0, names.length).map((container, index) => {
    issues.push(...validateIngressForwarderTeardownCandidate({ container, expectedImageId: imageId, projectId: selection.projectId }));
    const containerId = container.Id ?? "";
    const containerName = container.Name?.replace(/^\//u, "") ?? "";
    const endpoint = container.NetworkSettings?.Networks?.[internalNetwork];
    if (!DOCKER_OBJECT_ID_PATTERN.test(containerId) || containerName !== names[index]
      || !hostNetwork.containerIds.includes(containerId)
      || container.NetworkSettings?.Networks?.[ingressHostNetworkName(selection.projectId)]?.NetworkID !== hostNetwork.id
      || endpoint?.NetworkID !== selection.networkIds.agentInternal
      || !endpoint.IPAddress) {
      throw new Error("ingress participant does not have its exact network identity");
    }
    return Object.freeze({ containerId, containerName, sourceIp: endpoint.IPAddress, imageId });
  });
  if (issues.length > 0) {
    throw new Error(`refusing ingress participants: ${issues.map((issue) => issue.message).join("; ")}`);
  }
  input.lifecycleLock.assertHeld();
  return Object.freeze(participants);
}

export function assertControlPlaneInternalParticipantAuthority(
  value: unknown,
): asserts value is ControlPlaneInternalParticipantAuthority {
  participantAuthorityBinding(value);
}

function assertExactNetworkConfiguration(
  source: string,
  expected: Readonly<{ networkId: string; networkName: string; subnet: string }>,
): Map<string, string> {
  if (Buffer.byteLength(source) > MAX_NETWORK_INSPECT_BYTES) {
    throw new Error("Docker internal-network inspection exceeds the size limit");
  }
  let parsed: unknown;
  try {
    parsed = parseStrictJson(source);
  } catch {
    throw new Error("Docker returned malformed internal-network inspection JSON");
  }
  if (!Array.isArray(parsed) || parsed.length !== 1 || !isRecord(parsed[0])) {
    throw new Error("Docker did not return exactly one internal-network inspection");
  }
  const network = parsed[0];
  if (network.Id !== expected.networkId || network.Name !== expected.networkName) {
    throw new Error("Docker internal-network inspection names a different network");
  }
  if (network.Driver !== "bridge" || network.Internal !== true || network.EnableIPv6 !== false) {
    throw new Error("Docker internal-network confinement differs from the effective topology");
  }
  if (!isRecord(network.IPAM)
    || !Array.isArray(network.IPAM.Config)
    || network.IPAM.Config.length !== 1
    || !isRecord(network.IPAM.Config[0])
    || network.IPAM.Config[0].Subnet !== expected.subnet) {
    throw new Error("Docker internal-network subnet differs from the effective topology");
  }
  if (!isRecord(network.Containers)) {
    throw new Error("Docker internal-network participant inventory is malformed");
  }
  const endpointIds = new Map<string, string>();
  for (const [containerId, value] of Object.entries(network.Containers)) {
    if (!DOCKER_OBJECT_ID_PATTERN.test(containerId)
      || !isRecord(value)
      || typeof value.EndpointID !== "string"
      || !DOCKER_OBJECT_ID_PATTERN.test(value.EndpointID)) {
      throw new Error("Docker internal-network endpoint identity is malformed");
    }
    endpointIds.set(containerId, value.EndpointID);
  }
  return endpointIds;
}

function exactNetworkParticipants(
  source: string,
  expected: Readonly<{ networkId: string; networkName: string; subnet: string }>,
): readonly ExactNetworkParticipant[] {
  const attachments = parseSessionNetworkAttachments(source, expected);
  const endpointIds = assertExactNetworkConfiguration(source, expected);
  const containerIds = new Set<string>();
  const sourceIps = new Set<string>();
  const endpointClaims = new Set<string>();
  const result = attachments.map((attachment): ExactNetworkParticipant => {
    const endpointId = endpointIds.get(attachment.containerId);
    if (!endpointId) throw new Error("Docker internal-network endpoint identity is missing");
    if (containerIds.has(attachment.containerId)) {
      throw new Error(`Docker internal-network container id is reused: ${attachment.containerId}`);
    }
    if (sourceIps.has(attachment.sourceIp)) {
      throw new Error(`Docker internal-network source IP is reused: ${attachment.sourceIp}`);
    }
    if (endpointClaims.has(endpointId)) {
      throw new Error(`Docker internal-network endpoint id is reused: ${endpointId}`);
    }
    containerIds.add(attachment.containerId);
    sourceIps.add(attachment.sourceIp);
    endpointClaims.add(endpointId);
    return Object.freeze({ ...attachment, networkEndpointId: endpointId });
  });
  return Object.freeze(result);
}

function exactParticipant(
  attachments: readonly ExactNetworkParticipant[],
  expected: Readonly<Pick<ExactNetworkParticipant, "containerId" | "containerName" | "sourceIp">>,
  label: string,
): ExactNetworkParticipant {
  const attachment = attachments.find((candidate) => candidate.containerId === expected.containerId);
  if (!attachment
    || attachment.containerName !== expected.containerName
    || attachment.sourceIp !== expected.sourceIp) {
    throw new Error(`${label} does not have its exact Docker internal-network endpoint`);
  }
  return attachment;
}

function assertBaseline(value: unknown): asserts value is ExactInternalNetworkParticipantBaseline {
  if (value === null || typeof value !== "object" || !validatedBaselines.has(value)) {
    throw new Error("internal-network participant baseline was not minted from exact Docker inspection");
  }
  const binding = baselineBindings.get(value);
  if (!binding) throw new Error("internal-network participant baseline binding is missing");
  participantAuthorityBinding(binding.authority);
}

export function validateExactInternalNetworkParticipantBaseline(input: Readonly<{
  participantAuthority: ControlPlaneInternalParticipantAuthority;
  networkInspectJson: string;
  records: readonly SessionContainerRecordV2[];
}>): ExactInternalNetworkParticipantBaseline {
  const authorityBinding = participantAuthorityBinding(input.participantAuthority);
  const selection = authorityBinding.selection;
  const network = Object.freeze({
    networkId: input.participantAuthority.networkId,
    networkName: input.participantAuthority.networkName,
    subnet: input.participantAuthority.subnet,
  });
  const attachments = exactNetworkParticipants(input.networkInspectJson, network);
  participantAuthorityBinding(input.participantAuthority);

  const expected = new Map<string, ExactNetworkParticipant>();
  const controlPlaneAttachments = authorityBinding.participants.map((participant) => {
    const attachment = exactParticipant(
      attachments,
      participant,
      `control-plane ${participant.role}`,
    );
    expected.set(attachment.containerId, attachment);
    return attachment;
  });
  for (const participant of authorityBinding.ingressParticipants) {
    const attachment = exactParticipant(attachments, participant, "ingress forwarder");
    if (expected.has(attachment.containerId)) throw new Error("ingress participant reuses a container identity");
    expected.set(attachment.containerId, attachment);
  }
  const records = input.records.map((record) => {
    const parsed = parseSessionContainerRecordV2(record);
    if (!parsed) throw new Error("internal-network baseline has an invalid lifecycle record");
    assertSessionContainerRecordProject(parsed, selection);
    if (parsed.controlPlaneGenerationDigest !== selection.controlPlaneGenerationDigest
      || parsed.admissionContractEpoch !== selection.admissionContractEpoch) {
      throw new Error("internal-network baseline lifecycle record belongs to another control plane");
    }
    if (parsed.containerId) {
      const attachment = exactParticipant(attachments, {
        containerId: parsed.containerId,
        containerName: parsed.containerName,
        sourceIp: parsed.sourceIp,
      }, `session-container ${parsed.sessionId}`);
      if (expected.has(attachment.containerId)) {
        throw new Error(`internal-network container id is reused: ${attachment.containerId}`);
      }
      expected.set(attachment.containerId, attachment);
    }
    return parsed;
  });
  if (expected.size !== attachments.length) {
    throw new Error("Docker internal network contains an unknown participant");
  }

  const baseline = Object.freeze({
    projectId: selection.projectId,
    composeProject: selection.composeProject,
    controlPlaneGenerationDigest: selection.controlPlaneGenerationDigest,
    admissionContractEpoch: selection.admissionContractEpoch,
    networkId: network.networkId,
    networkName: network.networkName,
    subnet: network.subnet,
    participants: attachments,
  }) as ExactInternalNetworkParticipantBaseline;
  validatedBaselines.add(baseline);
  baselineBindings.set(baseline, Object.freeze({
    authority: input.participantAuthority,
    controlPlaneParticipants: Object.freeze(controlPlaneAttachments),
    records: Object.freeze(records),
  }));
  return baseline;
}

export function allocateSessionSourceIpFromExactInternalNetworkBaseline(input: Readonly<{
  baseline: ExactInternalNetworkParticipantBaseline;
  reservedIps?: readonly string[];
  cap?: number;
}>): string {
  assertBaseline(input.baseline);
  const binding = baselineBindings.get(input.baseline);
  if (!binding) throw new Error("internal-network participant baseline binding is missing");
  return allocateSessionSourceIp({
    expectedProject: input.baseline,
    networkId: input.baseline.networkId,
    networkName: input.baseline.networkName,
    subnet: input.baseline.subnet,
    reservedIps: [
      ...binding.controlPlaneParticipants.map((participant) => participant.sourceIp),
      ...participantAuthorityBinding(binding.authority).ingressParticipants.map((participant) => participant.sourceIp),
      ...(input.reservedIps ?? []),
    ],
    records: binding.records,
    attachments: input.baseline.participants,
    ...(input.cap === undefined ? {} : { cap: input.cap }),
  });
}

// There is deliberately no stopped-network-target proof between allocation and
// start. Docker attaches the endpoint at container start and refuses a
// duplicate static address there, and the single post-start inspection holds
// the container to exactly one internal network at exactly the allocated
// address before activation spends it. A pre-start network re-read proved a
// moment Docker itself does not honour until start, so it was deleted rather
// than kept as ritual.
