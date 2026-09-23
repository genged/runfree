import { performance } from "node:perf_hooks";

import { parseStrictJson } from "../control/strict-json.ts";
import { isRecord } from "../strict-primitives.ts";
import {
  AGENT_PROJECT_IMAGE_ROLE,
  AGENT_RUNTIME_IMAGE_ROLE,
  PROJECT_ID_LABEL,
  RUNFREE_DIGEST_SCHEMA_LABEL,
  RUNFREE_DIGEST_SCHEMA_VERSION,
  RUNFREE_IMAGE_INPUT_DIGEST_LABEL,
  RUNFREE_IMAGE_ROLE_LABEL,
  RUNFREE_MANAGED_IMAGE_LABEL,
  RUNFREE_VERSION_LABEL,
  SELECTED_AGENT_IMAGE_LABEL_NAMES,
} from "./constants.ts";
import {
  SESSION_CONTAINER_CAPABILITY_DROPS,
  SESSION_CONTAINER_RESTART_POLICY,
  SESSION_CONTAINER_SECURITY_OPTIONS,
  SESSION_CONTAINER_STOP_SIGNAL,
  SESSION_CONTAINER_USER,
} from "./session-container-contract.ts";
import {
  assertSessionContainerCreatePlan,
  type SessionContainerCreatePlan,
} from "./session-container-template.ts";
import {
  assertSessionContainerRecordProject,
  parseSessionContainerRecordV2,
  SESSION_CONTAINER_LABELS,
  serializeSessionContainerRecordV2,
  sessionContainerLabels,
  type SessionContainerRecordV2,
} from "./session-containers.ts";

const DOCKER_OBJECT_ID_PATTERN = /^[a-f0-9]{64}$/;
// Docker Desktop's file-sharing prefix for a relayed host directory. Kept in
// step with the same prefix `normalizeHostPath` strips in `security-contract.ts`.
const DOCKER_DESKTOP_HOST_MOUNT_PREFIX = "/host_mnt";
export const SESSION_CONTAINER_INSPECT_MAX_BYTES = 512 * 1024;
const SESSION_CONTAINER_PROOF_MAX_AGE_MS = 5_000;

export class SessionContainerNotRunningYetError extends Error {
  constructor() {
    super("session container has not reached Docker running state");
    this.name = "SessionContainerNotRunningYetError";
  }
}

type DockerMount = {
  Type?: unknown;
  Name?: unknown;
  Source?: unknown;
  Destination?: unknown;
  RW?: unknown;
};

type DockerHostMount = {
  Type?: unknown;
  Source?: unknown;
  Target?: unknown;
  ReadOnly?: unknown;
  VolumeOptions?: unknown;
};

type DockerNetwork = {
  NetworkID?: unknown;
  EndpointID?: unknown;
  IPAddress?: unknown;
  IPAMConfig?: unknown;
  GlobalIPv6Address?: unknown;
};

type DockerSessionInspect = {
  Id?: unknown;
  Name?: unknown;
  Image?: unknown;
  Path?: unknown;
  Args?: unknown;
  Config?: unknown;
  HostConfig?: unknown;
  Mounts?: unknown;
  NetworkSettings?: unknown;
  State?: unknown;
};

export type SessionContainerProofPhase =
  | { kind: "provisioning-running" }
  | { kind: "active-running" };

declare const sessionContainerProofBrand: unique symbol;

export type SessionContainerProof = Readonly<{
  readonly [sessionContainerProofBrand]: true;
  phase: SessionContainerProofPhase["kind"];
  projectId: string;
  sessionIncarnation: string;
  sessionPrincipal: string;
  containerId: string;
  imageId: string;
  sessionAgentGenerationDigest: string;
  controlPlaneGenerationDigest: string;
  admissionContractEpoch: number;
  networkId: string;
  running: true;
  sourceIp: string;
  dockerPid: number;
  dockerStartedAt: string;
  networkEndpointId: string;
}>;

const validatedProofs = new WeakSet<object>();
const proofBindings = new WeakMap<object, Readonly<{
  lifecycleSource: string;
  mintedAtMonotonicMs: number;
}>>();

export function assertSessionContainerProof(
  proof: unknown,
  record: SessionContainerRecordV2,
  phase: SessionContainerProofPhase["kind"],
  networkId: string,
): asserts proof is SessionContainerProof {
  if (proof === null || typeof proof !== "object" || !validatedProofs.has(proof)) {
    throw new Error("session container proof was not minted by exact Docker inspection");
  }
  const parsedRecord = parseSessionContainerRecordV2(record);
  if (!parsedRecord || !parsedRecord.containerId) {
    throw new Error("session container proof requires an exact lifecycle record");
  }
  const parsed = proof as SessionContainerProof;
  if (parsed.phase !== phase
    || parsed.projectId !== parsedRecord.projectId
    || parsed.sessionIncarnation !== parsedRecord.sessionIncarnation
    || parsed.sessionPrincipal !== parsedRecord.sessionPrincipal
    || parsed.containerId !== parsedRecord.containerId
    || parsed.imageId !== parsedRecord.selectedAgentImageId
    || parsed.sessionAgentGenerationDigest !== parsedRecord.sessionAgentGenerationDigest
    || parsed.controlPlaneGenerationDigest !== parsedRecord.controlPlaneGenerationDigest
    || parsed.admissionContractEpoch !== parsedRecord.admissionContractEpoch
    || parsed.sourceIp !== parsedRecord.sourceIp
    || parsed.running !== true
    || parsed.networkId !== networkId) {
    throw new Error("session container proof belongs to a different lifecycle authority");
  }
}

export function assertFreshSessionContainerProof(
  proof: SessionContainerProof,
  options: Readonly<{ nowMonotonicMs?: () => number }> = {},
): void {
  const binding = proofBindings.get(proof);
  if (!binding) throw new Error("session container proof was not minted by exact Docker inspection");
  const age = (options.nowMonotonicMs ?? (() => performance.now()))() - binding.mintedAtMonotonicMs;
  if (!Number.isFinite(age) || age < 0 || age > SESSION_CONTAINER_PROOF_MAX_AGE_MS) {
    throw new Error("session container proof is too old to authorize a lifecycle effect");
  }
}

export function assertSessionContainerProofMintedForExactLifecycleRecord(
  proof: SessionContainerProof,
  record: SessionContainerRecordV2,
): void {
  const parsedRecord = parseSessionContainerRecordV2(record);
  const binding = proofBindings.get(proof);
  if (!parsedRecord || !binding || binding.lifecycleSource !== serializeSessionContainerRecordV2(parsedRecord)) {
    throw new Error("session container proof was minted for a different exact lifecycle record");
  }
}

/**
 * The one entry point for treating a proof as spendable authorization: minted
 * by exact Docker inspection, minted for this exact lifecycle record, still
 * binding this record/phase/network identity, and still fresh. Every consumer
 * that grants standing authority runs all of it; a caller that deliberately
 * wants a subset calls the individual asserts and says why at the call site.
 */
export function assertSpendableSessionContainerProof(
  proof: unknown,
  record: SessionContainerRecordV2,
  phase: SessionContainerProofPhase["kind"],
  networkId: string,
  options: Readonly<{ nowMonotonicMs?: () => number }> = {},
): asserts proof is SessionContainerProof {
  assertSessionContainerProof(proof, record, phase, networkId);
  assertSessionContainerProofMintedForExactLifecycleRecord(proof, record);
  assertFreshSessionContainerProof(proof, options);
}

function exactStringArray(value: unknown, expected: readonly string[]): boolean {
  return Array.isArray(value)
    && value.length === expected.length
    && value.every((entry, index) => entry === expected[index]);
}

// How the daemon spells things, in one place.
//
// Every assertion below reads Docker's inspect payload through these
// coercions instead of comparing raw JSON. Two daemon habits made the
// unmediated comparisons break on upgrade, both of them cosmetic:
//
//   1. A field carrying its zero value is either omitted from the payload
//      (`json:",omitempty"`) or spelled as an explicit `null`, varying by
//      field and by release. `Config.Cmd` is null for a container created
//      with an entrypoint override and no operands; `HostConfig.Init` and a
//      read-write mount's `ReadOnly` are absent outright.
//   2. The daemon re-spells values it normalized: capabilities come back in
//      the kernel's `CAP_`-prefixed form, and Docker Desktop names a relayed
//      bind source under a `/host_mnt` prefix.
//
// Neither changes what the container actually is, so neither should read as
// a violated contract. Absence is therefore resolved to the zero value and
// re-spellings are canonicalized here, once — a release that omits another
// field or renames another value is a change to this block, not to the
// assertions. The assertions stay exact: a zero value still has to be the
// zero value the plan asked for, and a canonicalized set still has to match
// element for element.

function absentAsFalse(value: unknown): unknown {
  return value === undefined || value === null ? false : value;
}

function absentAsList(value: unknown): unknown {
  return value === undefined || value === null ? [] : value;
}

function absentAsMap(value: unknown): unknown {
  return value === undefined || value === null ? {} : value;
}

function absentAsText(value: unknown): unknown {
  return value === undefined || value === null ? "" : value;
}

function absentAsZero(value: unknown): unknown {
  return value === undefined || value === null ? 0 : value;
}

/** Canonical capability name, matching `hasCapability` in `topology.ts`. */
function canonicalCapability(value: string): string {
  return value.toUpperCase().replace(/^CAP_/u, "");
}

function exactCapabilitySet(value: unknown, expected: readonly string[]): boolean {
  const observed = absentAsList(value);
  if (!Array.isArray(observed) || observed.some((entry) => typeof entry !== "string")) return false;
  const canonical = (observed as string[]).map(canonicalCapability).sort();
  const wanted = expected.map(canonicalCapability).sort();
  return canonical.length === wanted.length && canonical.every((entry, index) => entry === wanted[index]);
}

function emptyList(value: unknown): boolean {
  const observed = absentAsList(value);
  return Array.isArray(observed) && observed.length === 0;
}

function emptyMap(value: unknown): boolean {
  const observed = absentAsMap(value);
  return isRecord(observed) && Object.keys(observed).length === 0;
}

function requireExactContainerId(value: unknown, label: string): string {
  if (typeof value !== "string" || !DOCKER_OBJECT_ID_PATTERN.test(value)) {
    throw new Error(`${label} must be an exact Docker object id`);
  }
  return value;
}

function requireRunningStartedAt(value: unknown): string {
  if (typeof value !== "string"
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value)
    || value.startsWith("0001-")
    || !Number.isFinite(Date.parse(value))) {
    throw new Error("running session container start time is malformed");
  }
  return value;
}

function expectedMountSource(mount: SessionContainerCreatePlan["mounts"][number], observed: DockerMount): unknown {
  return mount.type === "volume" ? observed.Name : observed.Source;
}

function assertExactMounts(plan: SessionContainerCreatePlan, value: unknown): void {
  if (!Array.isArray(value) || value.length !== plan.mounts.length) {
    throw new Error("session container has an unexpected mount set");
  }
  const byTarget = new Map<string, DockerMount>();
  for (const entry of value) {
    if (!isRecord(entry) || typeof entry.Destination !== "string" || byTarget.has(entry.Destination)) {
      throw new Error("session container mount inspection is malformed");
    }
    byTarget.set(entry.Destination, entry);
  }
  for (const mount of plan.mounts) {
    const observed = byTarget.get(mount.target);
    if (!observed
      || observed.Type !== mount.type
      // The realized mount list names the same relayed bind source the mount
      // plan does, so it needs the same `/host_mnt` normalization.
      || !sameHostMountSource(mount, expectedMountSource(mount, observed))
      || absentAsFalse(observed.RW) !== !mount.readOnly) {
      throw new Error(`session container mount differs at ${mount.target}`);
    }
  }
}

function assertExactHostMounts(plan: SessionContainerCreatePlan, value: unknown): void {
  if (!Array.isArray(value) || value.length !== plan.mounts.length) {
    throw new Error("session container host mount plan differs");
  }
  const byTarget = new Map<string, DockerHostMount>();
  for (const entry of value) {
    if (!isRecord(entry) || typeof entry.Target !== "string" || byTarget.has(entry.Target)) {
      throw new Error("session container host mount inspection is malformed");
    }
    byTarget.set(entry.Target, entry);
  }
  for (const mount of plan.mounts) {
    const observed = byTarget.get(mount.target);
    const difference = observed ? hostMountDifference(mount, observed) : "absent";
    if (difference) {
      // The differing field is named because the target alone does not say
      // whether the mount was pointed somewhere else, silently made writable,
      // or merely encoded differently by the daemon. Only the field name is
      // reported; host paths stay out of the message.
      throw new Error(`session container host mount plan differs at ${mount.target}: ${difference}`);
    }
  }
}

/**
 * Compares a planned mount source against the source Docker reports back.
 *
 * Docker Desktop relays host directories through its file-sharing layer and can
 * report a bind source as the same absolute path under a `/host_mnt` prefix,
 * which is the same directory named differently rather than a different one.
 * `normalizeHostPath` in `security-contract.ts` already strips exactly this
 * prefix for the same reason. Only that one prefix is tolerated, only for bind
 * mounts — a volume source is a volume name, not a path — and the remaining
 * path still has to match the plan byte for byte.
 */
function sameHostMountSource(
  mount: SessionContainerCreatePlan["mounts"][number],
  observed: unknown,
): boolean {
  if (typeof observed !== "string") return false;
  if (observed === mount.source) return true;
  if (mount.type !== "bind" || !observed.startsWith(`${DOCKER_DESKTOP_HOST_MOUNT_PREFIX}/`)) return false;
  return observed.slice(DOCKER_DESKTOP_HOST_MOUNT_PREFIX.length) === mount.source;
}

/**
 * Names the first field of a planned mount the daemon did not honour.
 *
 * Docker omits `ReadOnly` and `VolumeOptions` from a mount spec whenever they
 * carry their zero value, so a read-write mount and a bind with no volume
 * options both arrive with the key missing rather than set to `false`/`null`.
 * Treating absence as the zero value is what the daemon means by it; a mount
 * that was actually made read-only, or that actually carries volume options,
 * still reports them and is still compared exactly.
 */
function hostMountDifference(
  mount: SessionContainerCreatePlan["mounts"][number],
  observed: DockerHostMount,
): string | undefined {
  if (observed.Type !== mount.type) return "type";
  if (!sameHostMountSource(mount, observed.Source)) return "source";
  if (absentAsFalse(observed.ReadOnly) !== mount.readOnly) return "read-only";
  const volumeOptions = absentAsMap(observed.VolumeOptions);
  if (!isRecord(volumeOptions)) return "volume options";
  if (mount.type === "volume" && absentAsFalse(volumeOptions.NoCopy) !== mount.noCopy) return "volume-nocopy";
  if (mount.type === "bind" && !emptyMap(observed.VolumeOptions)) return "unexpected volume options";
  return undefined;
}

function assertEnvironment(plan: SessionContainerCreatePlan, value: unknown): void {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new Error("session container environment inspection is malformed");
  }
  const observed = new Map<string, string>();
  for (const entry of value as string[]) {
    const separator = entry.indexOf("=");
    if (separator < 1) throw new Error("session container environment inspection is malformed");
    const name = entry.slice(0, separator);
    if (observed.has(name)) throw new Error(`session container environment is duplicated: ${name}`);
    observed.set(name, entry.slice(separator + 1));
  }
  const expectedEnvironment = plan.imageDeclarationProof.mergedEnvironment;
  if (observed.size !== Object.keys(expectedEnvironment).length) {
    throw new Error("session container environment has unexpected entries");
  }
  for (const [name, expected] of Object.entries(expectedEnvironment)) {
    if (observed.get(name) !== expected) throw new Error(`session container environment differs: ${name}`);
  }
}

function assertExactLabels(plan: SessionContainerCreatePlan, value: unknown): void {
  if (!isRecord(value)) throw new Error("session container labels are malformed");
  const expectedLabels = {
    ...sessionContainerLabels(plan.record, plan.runfreeVersion),
    [RUNFREE_MANAGED_IMAGE_LABEL]: "true",
    [RUNFREE_IMAGE_ROLE_LABEL]: plan.sessionAgentMaterialization.selectedAgentImageKind === "project"
      ? AGENT_PROJECT_IMAGE_ROLE
      : AGENT_RUNTIME_IMAGE_ROLE,
    [RUNFREE_DIGEST_SCHEMA_LABEL]: RUNFREE_DIGEST_SCHEMA_VERSION,
    [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: plan.record.selectedAgentImageInputDigest,
    [PROJECT_ID_LABEL]: plan.record.projectId,
    [RUNFREE_VERSION_LABEL]: plan.runfreeVersion,
  };
  for (const [name, expected] of Object.entries(expectedLabels)) {
    if (value[name] !== expected) throw new Error(`session container label differs: ${name}`);
  }
  const allowedRunfreeLabels = new Set<string>([
    ...SELECTED_AGENT_IMAGE_LABEL_NAMES,
    ...Object.values(SESSION_CONTAINER_LABELS),
  ]);
  for (const name of Object.keys(value)) {
    if (name.startsWith("io.runfree.") && !allowedRunfreeLabels.has(name)) {
      throw new Error(`session container has an unknown managed label: ${name}`);
    }
  }
  if (Object.keys(value).some((name) => name.startsWith("com.docker.compose."))) {
    throw new Error("session container must not carry Docker Compose ownership labels");
  }
}

function assertHostContract(plan: SessionContainerCreatePlan, value: unknown): void {
  if (!isRecord(value)) throw new Error("session container host configuration is malformed");
  if (value.NetworkMode !== plan.effectiveControlPlane.networkIds.agentInternal) {
    throw new Error("session container network mode differs from the selected internal network");
  }
  if (absentAsFalse(value.Privileged) !== false) throw new Error("session container is privileged");
  if (absentAsFalse(value.Init) !== false) throw new Error("session container has an unexpected init wrapper");
  if (absentAsFalse(value.AutoRemove) !== false) throw new Error("session container auto-remove contract differs");
  if (absentAsFalse(value.PublishAllPorts) !== false) {
    throw new Error("session container publishes all exposed ports");
  }
  const restartPolicy = absentAsMap(value.RestartPolicy);
  if (!isRecord(restartPolicy)
    || restartPolicy.Name !== SESSION_CONTAINER_RESTART_POLICY
    || absentAsZero(restartPolicy.MaximumRetryCount) !== 0) {
    throw new Error("session container restart policy differs");
  }
  if (!emptyList(value.CapAdd)) throw new Error("session container has added Linux capabilities");
  if (!exactCapabilitySet(value.CapDrop, SESSION_CONTAINER_CAPABILITY_DROPS)) {
    throw new Error("session container capability drops differ");
  }
  const securityOptions = absentAsList(value.SecurityOpt);
  if (!Array.isArray(securityOptions)
    || securityOptions.length !== 1
    || (securityOptions[0] !== "no-new-privileges"
      && securityOptions[0] !== SESSION_CONTAINER_SECURITY_OPTIONS[0])) {
    throw new Error("session container no-new-privileges contract differs");
  }
  if (!emptyMap(value.PortBindings)) throw new Error("session container publishes ports");
  if (!emptyList(value.ExtraHosts)) throw new Error("session container has host gateway aliases");
  if (!emptyList(value.Devices)) throw new Error("session container has added devices");
  if (!emptyList(value.DeviceRequests)) throw new Error("session container has requested devices");
  for (const key of ["Binds", "Dns", "DnsOptions", "DnsSearch", "Links", "VolumesFrom"] as const) {
    if (!emptyList(value[key])) throw new Error(`session container host ${key} contract differs`);
  }
  assertExactHostMounts(plan, value.Mounts);
}

function assertDeclaredVolumes(plan: SessionContainerCreatePlan, value: unknown): void {
  const expected = plan.imageDeclarationProof.declaredVolumeTargets;
  if (expected.length === 0) {
    if (!emptyMap(value)) throw new Error("session container has unexpected image volume declarations");
    return;
  }
  if (!isRecord(value)) throw new Error("session container image volume declarations are malformed");
  const observed = Object.keys(value).sort();
  if (observed.length !== expected.length || observed.some((target, index) => target !== expected[index])) {
    throw new Error("session container image volume declarations differ from preflight");
  }
}

function assertConfigContract(plan: SessionContainerCreatePlan, value: unknown): void {
  if (!isRecord(value)) throw new Error("session container configuration is malformed");
  if (value.Image !== plan.record.selectedAgentImageId) {
    throw new Error("session container configuration names a different selected image");
  }
  if (value.User !== SESSION_CONTAINER_USER) throw new Error("session container user differs");
  if (!exactStringArray(value.Entrypoint, [plan.record.launchPath])) {
    throw new Error("session container entrypoint differs from the exact launch contract");
  }
  if (!exactStringArray(absentAsList(value.Cmd), plan.record.launchArgs)) {
    throw new Error("session container command differs from the exact launch contract");
  }
  if (value.StopSignal !== SESSION_CONTAINER_STOP_SIGNAL) {
    throw new Error("session container stop signal differs from the launch contract");
  }
  if (value.WorkingDir !== plan.template.workingDirectory) throw new Error("session container working directory differs");
  if (value.OpenStdin !== plan.record.interactive || value.Tty !== plan.record.tty) {
    throw new Error("session container terminal contract differs");
  }
  const healthcheck = absentAsMap(value.Healthcheck);
  if (!isRecord(healthcheck) || !exactStringArray(healthcheck.Test, ["NONE"])) {
    throw new Error("session container healthcheck is not disabled");
  }
  assertDeclaredVolumes(plan, value.Volumes);
  assertEnvironment(plan, value.Env);
  assertExactLabels(plan, value.Labels);
}

function assertNetworks(
  plan: SessionContainerCreatePlan,
  record: SessionContainerRecordV2,
  value: unknown,
): Readonly<{ sourceIp: string; endpointId: string }> {
  if (!isRecord(value) || !isRecord(value.Networks)) {
    throw new Error("session container network inspection is malformed");
  }
  const entries = Object.entries(value.Networks);
  const networkId = plan.effectiveControlPlane.networkIds.agentInternal;
  const networkName = `${plan.expectedProject.composeProject}_agent_internal`;
  requireExactContainerId(networkId, "session network id");
  if (entries.length !== 1 || !isRecord(entries[0]?.[1])) {
    throw new Error("session container is not attached only to the selected internal network");
  }
  const networkKey = entries[0][0];
  const network = entries[0][1] as DockerNetwork;
  if ((networkKey !== networkId && networkKey !== networkName)
    || network.NetworkID !== networkId) {
    throw new Error("session container network identity differs");
  }
  if (!isRecord(network.IPAMConfig)
    || network.IPAMConfig.IPv4Address !== record.sourceIp
    || (network.IPAMConfig.IPv6Address !== undefined && network.IPAMConfig.IPv6Address !== "")
    || (network.IPAMConfig.LinkLocalIPs !== undefined
      && network.IPAMConfig.LinkLocalIPs !== null
      && (!Array.isArray(network.IPAMConfig.LinkLocalIPs) || network.IPAMConfig.LinkLocalIPs.length !== 0))
    || Object.keys(network.IPAMConfig).some((key) => (
      key !== "IPv4Address" && key !== "IPv6Address" && key !== "LinkLocalIPs"
    ))) {
    throw new Error("session container requested network identity differs");
  }
  if (network.IPAddress !== record.sourceIp) {
    throw new Error("running session container network identity differs");
  }
  if (absentAsText(network.GlobalIPv6Address) !== "") throw new Error("session container has an IPv6 address");
  const endpointId = requireExactContainerId(network.EndpointID, "session network endpoint id");
  return Object.freeze({ sourceIp: record.sourceIp, endpointId });
}

export function validateSessionContainerInspect(
  source: string,
  plan: SessionContainerCreatePlan,
  phase: SessionContainerProofPhase,
): SessionContainerProof {
  assertSessionContainerCreatePlan(plan);
  assertSessionContainerRecordProject(plan.record, plan.expectedProject);
  if (phase.kind !== "provisioning-running" && phase.kind !== "active-running") {
    throw new Error("session container proof phase is invalid");
  }
  if (Buffer.byteLength(source) > SESSION_CONTAINER_INSPECT_MAX_BYTES) {
    throw new Error("Docker session container inspection exceeds the size limit");
  }
  let parsed: unknown;
  try {
    parsed = parseStrictJson(source);
  } catch {
    throw new Error("Docker returned malformed session container inspection JSON");
  }
  if (!Array.isArray(parsed) || parsed.length !== 1 || !isRecord(parsed[0])) {
    throw new Error("Docker did not return exactly one session container inspection");
  }
  const inspect = parsed[0] as DockerSessionInspect;
  const containerId = requireExactContainerId(inspect.Id, "inspected session container id");
  if (!plan.record.containerId || containerId !== plan.record.containerId) {
    throw new Error("Docker inspected a different session container id");
  }
  if (inspect.Name !== `/${plan.record.containerName}`) throw new Error("session container name differs");
  if (inspect.Image !== plan.record.selectedAgentImageId) {
    throw new Error("session container selected immutable image id differs");
  }
  if (inspect.Path !== plan.record.launchPath
    || !exactStringArray(absentAsList(inspect.Args), plan.record.launchArgs)) {
    throw new Error("session container effective Path/Args differ from the exact launch contract");
  }
  assertConfigContract(plan, inspect.Config);
  assertHostContract(plan, inspect.HostConfig);
  assertExactMounts(plan, inspect.Mounts);
  if (!isRecord(inspect.State)
    || typeof inspect.State.Running !== "boolean"
    || typeof inspect.State.Status !== "string"
    || typeof inspect.State.Pid !== "number"
    || typeof inspect.State.StartedAt !== "string") {
    throw new Error("session container state inspection is malformed");
  }
  if (inspect.State.Dead !== false
    || inspect.State.Paused !== false
    || inspect.State.Restarting !== false
    || inspect.State.OOMKilled !== false
    || inspect.State.Error !== ""
    || inspect.State.ExitCode !== 0
    || inspect.State.Health !== undefined) {
    throw new Error("session container has unexpected Docker process state");
  }
  // A container that is still exactly "created" is the foreground start in
  // flight, not a violated contract: the static shape above already matched the
  // plan, and the caller polls again. Its network endpoint does not exist yet
  // (Docker attaches at start), so the network assertion runs only on the
  // running observation that actually mints a proof.
  if (inspect.State.Running === false
    && inspect.State.Status === "created"
    && inspect.State.Pid === 0) {
    throw new SessionContainerNotRunningYetError();
  }
  if (inspect.State.Running !== true) throw new Error("session container running state differs");
  if (inspect.State.Status !== "running" || !Number.isSafeInteger(inspect.State.Pid) || inspect.State.Pid < 1) {
    throw new Error("session container Docker-owned running state differs");
  }
  const network = assertNetworks(plan, plan.record, inspect.NetworkSettings);
  const dockerStartedAt = requireRunningStartedAt(inspect.State.StartedAt);
  const proof = Object.freeze({
    phase: phase.kind,
    projectId: plan.record.projectId,
    sessionIncarnation: plan.record.sessionIncarnation,
    sessionPrincipal: plan.record.sessionPrincipal,
    containerId,
    imageId: plan.record.selectedAgentImageId,
    sessionAgentGenerationDigest: plan.record.sessionAgentGenerationDigest,
    controlPlaneGenerationDigest: plan.record.controlPlaneGenerationDigest,
    admissionContractEpoch: plan.record.admissionContractEpoch,
    networkId: plan.effectiveControlPlane.networkIds.agentInternal,
    running: true,
    sourceIp: network.sourceIp,
    networkEndpointId: network.endpointId,
    dockerPid: inspect.State.Pid as number,
    dockerStartedAt,
  }) as SessionContainerProof;
  validatedProofs.add(proof);
  proofBindings.set(proof, Object.freeze({
    lifecycleSource: serializeSessionContainerRecordV2(plan.record),
    mintedAtMonotonicMs: performance.now(),
  }));
  return proof;
}
