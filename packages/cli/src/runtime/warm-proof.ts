// The warm-proof fingerprint (sub-second launch plan Task 2).
//
// A full runtime validation re-proves the whole control plane on every start:
// topology, the agent-position deny probes (a `docker run` of the untrusted
// agent image), the proxy firewall, the security contract, and the validation
// marker. Most of what it proves cannot change while the same proxy instance,
// networks, volumes, images, and daemon stay in place, so a warm session launch
// re-proves it from two Docker calls instead of about twenty: one type-less
// `docker inspect` of every object by id or exact name, and one root batch
// inside the proxy. It re-runs the same validators over that fresh evidence,
// then compares the facts with a host record the last full validation wrote.
//
// The record selects a path; it never authorizes. Every compared fact is
// observed live again, the record never feeds a validator, and anything short
// of an exact match — a missing, malformed, older-than-24-hour record, one
// changed fact, an unavailable observation, a live session in the registry —
// takes the full validation path, which deletes the record first and writes a
// fresh one after it succeeds. `runfree up` always takes the full path.
//
// What a match does not re-run (accepted, with its inputs bound): the
// agent-position deny-probe helper, the proxy server-UID denial batch, and the
// root Docker DNS liveness probe. Their results are functions of the network
// and its participants, the proxy instance and image, the ruleset shape, the
// agent image, and the daemon, all of which are in the fingerprint.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { firewallStatusPath, parseGenerationStatusLine } from "@runfree/runtime-contracts/proxy-status";

import { stableJson } from "../strict-primitives.ts";
import { exactKeySet, isRecord } from "../strict-primitives.ts";
import { CA_BUNDLE_FILE, PROXY_CA_FILE } from "./ca-bundle.ts";
import { ROOT_UID_GID, RUNTIME_VALIDATION_MARKER_PATH } from "./constants.ts";
import type { ControlPlaneEffectiveSelectionV2 } from "./component-state-v2.ts";
import type { DenyByDefaultObservationV1 } from "./control-plane-deny-proof.ts";
import { dockerClientEnvOptions, type DockerDaemonIdentity } from "./docker.ts";
import { composeProjectName } from "./env.ts";
import { launchHostRecordPath, readLaunchHostRecord, removeLaunchHostRecord, writeLaunchHostRecord } from "./launch-host-record.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import { firewallSectionBatchScript, parseFirewallSectionBatch, type FirewallSectionResult } from "./probes.ts";
import {
  createRuntimeSecurityContract,
  parseRuntimeSecurityContractProbe,
  runtimeSecurityContractProbeScript,
  validateRuntimeSecurityContractEvidence,
} from "./security-contract.ts";
import { assertComposeManagedLocalVolume } from "./session-named-volume-proof.ts";
import { listIpAssignmentsScript, parseIpAssignmentListing } from "./session-file-publisher.ts";
import { runtimeValidationMarkerProof, type RuntimeValidationProof } from "./state.ts";
import { validateRuntimeTopologyWithProof, type WarmTopologyEvidence } from "./topology.ts";
import type { DockerContainerInspect, DockerNetworkInspect, RuntimeContext, RuntimeIO } from "./types.ts";

export const WARM_PROOF_RECORD_NAME = "runtime-warm-proof.json";
export const WARM_PROOF_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const WARM_PROOF_RECORD_MAX_BYTES = 64 * 1024;
const WARM_INSPECT_MAX_BYTES = 4 * 1024 * 1024;
const WARM_BATCH_MAX_BYTES = 1024 * 1024;
const DOCKER_ID = /^[a-f0-9]{64}$/;
const IMAGE_ID = /^sha256:[a-f0-9]{64}$/;
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** Every fact a warm match must find unchanged, and nothing else. */
export type WarmProofFacts = Readonly<{
  projectId: string;
  composeProject: string;
  daemon: Readonly<{ id: string; serverVersion: string; kernelVersion: string }>;
  bootId: string;
  proxy: Readonly<{
    id: string;
    startedAt: string;
    pid: number;
    imageId: string;
    internalEndpointId: string;
    egressEndpointId: string;
  }>;
  networks: Readonly<{
    agentInternal: Readonly<{ id: string; name: string }>;
    proxyEgress: Readonly<{ id: string; name: string }>;
  }>;
  participants: readonly Readonly<{ id: string; ipv4: string; endpointId: string }>[];
  volumes: readonly Readonly<{
    name: string;
    createdAt: string;
    driver: string;
    mountpoint: string;
    labelsSha256: string;
    optionsSha256: string;
  }>[];
  agentImageId: string;
  controlPlaneGenerationDigest: string;
  controlPlaneMaterializationDigest: string;
  securityContractHash: string;
  effectivePolicyGeneration: string;
  gitLayoutSha256: string;
  proxyCaCertSha256: string;
  agentCaBundleSha256: string;
  markerSha256: string;
  nftShapeSha256: string;
}>;

type WarmProofRecordV1 = Readonly<{ version: 1; facts: WarmProofFacts; writtenAt: string }>;

const FACT_KEYS = [
  "projectId", "composeProject", "daemon", "bootId", "proxy", "networks", "participants", "volumes",
  "agentImageId", "controlPlaneGenerationDigest", "controlPlaneMaterializationDigest", "securityContractHash",
  "effectivePolicyGeneration", "gitLayoutSha256", "proxyCaCertSha256", "agentCaBundleSha256", "markerSha256",
  "nftShapeSha256",
] as const satisfies readonly (keyof WarmProofFacts)[];

export type WarmProofInput = Readonly<{
  plan: ActiveRuntimePlan;
  context: RuntimeContext;
  io: RuntimeIO;
  effective: ControlPlaneEffectiveSelectionV2;
  effectivePolicyGeneration: string;
  daemon: DockerDaemonIdentity | undefined;
  /** The image the deny-probe helper runs (`ephemeralHelperImage`): its id is bound. */
  agentImage: string;
  /** Compose-managed session volume logical names the plan mounts. */
  volumeLogicalNames: readonly string[];
  /** `serializeGitLayoutPlan` of the plan's layout. */
  gitLayout: string;
}>;

export type WarmValidation = Readonly<{
  /** The marker proof, re-judged from this launch's bytes. */
  runtimeProof: RuntimeValidationProof;
  proxyStartedAt: string;
  proxyPid: number;
  /** The Docker VM boot id the proxy reported. */
  bootId: string;
  /** `ip -> sha256 hex` of every IP assignment file the batch read; absent means none. */
  ipAssignmentDigests?: Readonly<Record<string, string>>;
}>;

/**
 * A warm-path verdict. Only `match` lets startup skip the full validation, and
 * it carries no security proof and no deny-by-default observation: those were
 * minted fresh to judge the evidence and are dropped here, so nothing that
 * proves, selects, re-proves, or restores a control plane can be handed one
 * from the warm path.
 */
export type WarmProofVerdict =
  | Readonly<{ kind: "match"; validation: WarmValidation }>
  | Readonly<{ kind: "mismatch"; field: string }>
  | Readonly<{ kind: "absent" }>
  | Readonly<{ kind: "unavailable"; reason: string }>
  | Readonly<{ kind: "skipped"; reason: string }>;

const sealedValidations = new WeakSet<object>();

export function assertWarmValidation(value: unknown): asserts value is WarmValidation {
  if (!value || typeof value !== "object" || !sealedValidations.has(value)) {
    throw new Error("warm validation was not minted by the warm-proof comparison");
  }
}

function sha256(value: string | Buffer): string {
  return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function hostFileSha256(filePath: string): string | undefined {
  try {
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4 * 1024 * 1024) return undefined;
    return sha256(fs.readFileSync(filePath));
  } catch {
    return undefined;
  }
}

/** The nft table with every set's element list removed: the shape, not the members. */
export function nftRulesetShapeSha256(rawJson: string): string | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJson);
  } catch {
    return undefined;
  }
  if (!isRecord(parsed) || !Array.isArray(parsed.nftables)) return undefined;
  const statements = parsed.nftables.map((statement: unknown) => {
    if (!isRecord(statement) || !isRecord(statement.set)) return statement;
    const { elem: _members, ...set } = statement.set;
    return { ...statement, set };
  });
  return sha256(stableJson({ nftables: statements }));
}

function warmBatchCommands(plan: ActiveRuntimePlan, securityProbe: string): string[] {
  const agentIp = plan.network.agentIp;
  if (!IPV4.test(agentIp)) throw new Error("agent address is not IPv4");
  const quoted = `'${securityProbe.replaceAll("'", "'\\''")}'`;
  return [
    "id -u",
    `ip -o route get ${agentIp}`,
    "ip -o route get 1.1.1.1",
    "awk '/CapBnd/ { print $2 }' /proc/1/status",
    "nft -j list table inet runfree_proxy",
    "nft list set inet runfree_proxy allowed_ipv4",
    `cat ${RUNTIME_VALIDATION_MARKER_PATH}`,
    `cat ${firewallStatusPath()}`,
    `sh -c ${quoted}`,
    "cat /proc/sys/kernel/random/boot_id",
    `node -e ${`'${listIpAssignmentsScript().replaceAll("'", "'\\''")}'`}`,
  ];
}

type WarmObservation = Readonly<{
  proxy: DockerContainerInspect;
  internalNetwork: DockerNetworkInspect;
  egressNetwork: DockerNetworkInspect;
  participants: readonly DockerContainerInspect[];
  volumes: readonly Record<string, unknown>[];
  agentImageId: string;
  sections: readonly FirewallSectionResult[];
}>;

function inspectObjects(input: WarmProofInput, targets: readonly string[]): unknown[] | string {
  const result = input.io.capture("docker", ["inspect", ...targets], {
    ...dockerClientEnvOptions(input.context),
    maxBuffer: WARM_INSPECT_MAX_BYTES,
  });
  if (result.status !== 0) return `docker inspect exited ${result.status}`;
  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    return "docker inspect output is not JSON";
  }
  if (!Array.isArray(parsed) || parsed.length !== targets.length) return "docker inspect returned an unexpected object count";
  return parsed;
}

const isContainer = (value: unknown): value is DockerContainerInspect => isRecord(value)
  && isRecord(value.State) && isRecord(value.Config) && isRecord(value.HostConfig) && typeof value.Id === "string";
const isNetwork = (value: unknown): value is DockerNetworkInspect => isRecord(value)
  && typeof value.Internal === "boolean" && typeof value.Id === "string" && typeof value.Name === "string"
  && !("State" in value) && !("Mountpoint" in value);
const isVolume = (value: unknown): value is Record<string, unknown> => isRecord(value)
  && typeof value.Name === "string" && typeof value.Driver === "string" && typeof value.Mountpoint === "string"
  && !("Id" in value);
const isImage = (value: unknown): value is Record<string, unknown> => isRecord(value)
  && typeof value.Id === "string" && isRecord(value.RootFS) && !("State" in value);

/**
 * Two Docker calls (three when a utility shares the internal network): every
 * object by id or exact name in one type-less inspect, each checked by shape
 * and identity, and one root batch inside the exact proxy.
 */
function observeWarmRuntime(input: WarmProofInput): WarmObservation | string {
  const { effective } = input;
  const proxyId = effective.proxyContainerId;
  const internalId = effective.networkIds.agentInternal;
  const egressId = effective.networkIds.proxyEgress;
  if (![proxyId, internalId, egressId].every((id) => DOCKER_ID.test(id))) return "the effective selection names no exact ids";
  const project = composeProjectName(input.context.projectRoot);
  const volumeNames = input.volumeLogicalNames.map((logicalName) => `${project}_${logicalName}`);
  const inspected = inspectObjects(input, [proxyId, internalId, egressId, input.agentImage, ...volumeNames]);
  if (typeof inspected === "string") return inspected;
  const [proxy, internalNetwork, egressNetwork, image, ...volumes] = inspected;
  if (!isContainer(proxy) || proxy.Id !== proxyId) return "the proxy object is not the exact proxy container";
  if (!isNetwork(internalNetwork) || internalNetwork.Id !== internalId || internalNetwork.Name !== `${project}_agent_internal`) {
    return "the internal network object is not the exact internal network";
  }
  if (!isNetwork(egressNetwork) || egressNetwork.Id !== egressId || egressNetwork.Name !== `${project}_proxy_egress`) {
    return "the egress network object is not the exact egress network";
  }
  if (!isImage(image) || typeof image.Id !== "string" || !IMAGE_ID.test(image.Id)) return "the agent image object is not an image";
  if (volumes.length !== volumeNames.length
    || volumes.some((volume, index) => !isVolume(volume) || volume.Name !== volumeNames[index])) {
    return "a session volume object is not the exact named volume";
  }
  const others = Object.keys(internalNetwork.Containers ?? {}).filter((id) => id !== proxyId);
  if (others.some((id) => !DOCKER_ID.test(id))) return "the internal network names a non-exact participant id";
  let participants: DockerContainerInspect[] = [proxy];
  if (others.length > 0) {
    const extra = inspectObjects(input, others);
    if (typeof extra === "string") return extra;
    if (extra.some((value, index) => !isContainer(value) || value.Id !== others[index])) {
      return "an internal-network participant is not the exact container";
    }
    participants = [proxy, ...(extra as DockerContainerInspect[])];
  }
  const proxyContract = createRuntimeSecurityContract(input.plan).containers.find((container) => container.name === "proxy");
  if (!proxyContract) return "the security contract has no proxy container";
  let commands: string[];
  try {
    commands = warmBatchCommands(input.plan, runtimeSecurityContractProbeScript(proxyContract));
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  const batch = input.io.capture("docker", ["exec", "--user", ROOT_UID_GID, proxyId, "sh", "-c", firewallSectionBatchScript(commands)], {
    ...dockerClientEnvOptions(input.context),
    maxBuffer: WARM_BATCH_MAX_BYTES,
  });
  const sections = parseFirewallSectionBatch(batch, commands.length);
  if (!sections) return "the proxy root batch was missing or garbled";
  return Object.freeze({
    proxy,
    internalNetwork,
    egressNetwork,
    participants,
    volumes: volumes as Record<string, unknown>[],
    agentImageId: image.Id,
    sections,
  });
}

type WarmJudgement =
  | Readonly<{ kind: "valid"; facts: WarmProofFacts; validation: WarmValidation }>
  | Readonly<{ kind: "invalid"; field: string }>;

/** Re-runs every applicable validator over the fresh evidence and derives the facts. */
function judgeWarmObservation(input: WarmProofInput, observation: WarmObservation): WarmJudgement {
  const invalid = (field: string): WarmJudgement => Object.freeze({ kind: "invalid", field });
  const { plan, effective } = input;
  const [uid, routeInternal, routeEgress, capBnd, nftTable, allowedSet, marker, firewallStatus, securityProbe, bootId, ipAssignments] =
    observation.sections as FirewallSectionResult[];
  if (uid.exit !== 0 || uid.body.trim() !== "0") return invalid("batch-identity");
  const daemon = input.daemon;
  if (!daemon) return invalid("daemon");
  if (daemon.liveRestoreEnabled) return invalid("daemon-live-restore");
  if (bootId.exit !== 0 || !/^[0-9a-f-]{36}$/.test(bootId.body.trim())) return invalid("boot-id");

  const proxy = observation.proxy;
  const state = proxy.State as Record<string, unknown>;
  const startedAt = state.StartedAt;
  const pid = state.Pid;
  if (state.Running !== true || state.Status !== "running" || state.Paused === true || state.Restarting === true
    || typeof startedAt !== "string" || !Number.isFinite(Date.parse(startedAt))
    || typeof pid !== "number" || !Number.isSafeInteger(pid) || pid <= 0) {
    return invalid("proxy-state");
  }
  if (proxy.Image !== effective.proxyImageId) return invalid("proxy-image");
  if (plan.generationV2.controlPlane.controlPlaneGenerationDigest !== effective.controlPlaneGenerationDigest
    || (plan.activeRuntime.controlPlaneMaterializationDigest ?? effective.controlPlaneMaterializationDigest)
      !== effective.controlPlaneMaterializationDigest) {
    return invalid("control-plane-selection");
  }

  const topologyIssues: string[] = [];
  const warmEvidence: WarmTopologyEvidence = Object.freeze({
    proxyId: effective.proxyContainerId,
    proxy,
    internalNetwork: observation.internalNetwork,
    participants: observation.participants,
    egressNetwork: observation.egressNetwork,
    capBnd,
    firewall: Object.freeze({ routes: [routeInternal, routeEgress], nftTable, allowedSet }),
  });
  const topology = validateRuntimeTopologyWithProof(plan, input.io, {
    warmEvidence,
    expectedProxyId: effective.proxyContainerId,
  });
  for (const issue of topology.issues) topologyIssues.push(issue.message);
  const deny: DenyByDefaultObservationV1 | undefined = topology.denyByDefaultBaseObservation;
  if (topologyIssues.length > 0 || !deny) return invalid("topology");

  const contract = createRuntimeSecurityContract(plan);
  if (securityProbe.exit !== 0) return invalid("security-contract");
  const security = validateRuntimeSecurityContractEvidence(
    contract,
    { proxy: { inspect: proxy, ...parseRuntimeSecurityContractProbe(securityProbe.body) } },
    { requireLiveProbes: true, scope: "startup" },
  );
  if (!security.ok || contract.contractHash !== effective.securityContractHash) return invalid("security-contract");

  const status = firewallStatus.exit === 0 ? parseGenerationStatusLine(firewallStatus.body) : undefined;
  let appliedAt: unknown;
  try { appliedAt = (JSON.parse(firewallStatus.body) as { appliedAt?: unknown }).appliedAt; } catch { /* Refused below. */ }
  if (!status || status.rulesetVerified !== true || status.controlGeneration !== input.effectivePolicyGeneration
    || typeof appliedAt !== "string" || !(Date.parse(appliedAt) >= Date.parse(startedAt))) {
    return invalid("firewall-readiness");
  }

  if (marker.exit !== 0) return invalid("marker");
  const markerProof = runtimeValidationMarkerProof(input.context, marker.body, effective.proxyContainerId, {
    contractHash: contract.contractHash,
  });
  if (!markerProof.proof || markerProof.issue || markerProof.proof.proxyId !== effective.proxyContainerId) {
    return invalid("marker");
  }

  const nftShape = nftRulesetShapeSha256(nftTable.body);
  if (!nftShape) return invalid("nft-shape");

  const project = composeProjectName(input.context.projectRoot);
  const volumes: WarmProofFacts["volumes"][number][] = [];
  for (const [index, volume] of observation.volumes.entries()) {
    const logicalName = input.volumeLogicalNames[index] as string;
    try {
      assertComposeManagedLocalVolume(JSON.stringify([volume]), { name: `${project}_${logicalName}`, logicalName, composeProject: project });
    } catch {
      return invalid("volumes");
    }
    if (typeof volume.CreatedAt !== "string") return invalid("volumes");
    volumes.push(Object.freeze({
      name: volume.Name as string,
      createdAt: volume.CreatedAt,
      driver: volume.Driver as string,
      mountpoint: volume.Mountpoint as string,
      labelsSha256: sha256(stableJson(volume.Labels ?? null)),
      optionsSha256: sha256(stableJson(volume.Options ?? null)),
    }));
  }

  const internalEndpoints = observation.internalNetwork.Containers ?? {};
  const participants = Object.entries(internalEndpoints).map(([id, endpoint]) => Object.freeze({
    id,
    ipv4: endpoint.IPv4Address ?? "",
    endpointId: endpoint.EndpointID ?? "",
  })).sort((left, right) => left.id.localeCompare(right.id));
  const proxyInternalEndpoint = internalEndpoints[effective.proxyContainerId]?.EndpointID;
  const proxyEgressEndpoint = observation.egressNetwork.Containers?.[effective.proxyContainerId]?.EndpointID;
  if (!proxyInternalEndpoint || !proxyEgressEndpoint) return invalid("proxy-endpoints");

  const certDir = input.context.project.paths.proxyCaCertDir;
  const proxyCaCertSha256 = hostFileSha256(path.join(certDir, PROXY_CA_FILE));
  const agentCaBundleSha256 = hostFileSha256(path.join(certDir, CA_BUNDLE_FILE));
  if (!proxyCaCertSha256 || !agentCaBundleSha256) return invalid("ca");

  const facts: WarmProofFacts = Object.freeze({
    projectId: plan.projectId,
    composeProject: plan.composeProjectName,
    daemon: Object.freeze({ id: daemon.id, serverVersion: daemon.serverVersion, kernelVersion: daemon.kernelVersion }),
    bootId: bootId.body.trim(),
    proxy: Object.freeze({
      id: effective.proxyContainerId,
      startedAt,
      pid,
      imageId: proxy.Image as string,
      internalEndpointId: proxyInternalEndpoint,
      egressEndpointId: proxyEgressEndpoint,
    }),
    networks: Object.freeze({
      agentInternal: Object.freeze({ id: observation.internalNetwork.Id as string, name: observation.internalNetwork.Name as string }),
      proxyEgress: Object.freeze({ id: observation.egressNetwork.Id as string, name: observation.egressNetwork.Name as string }),
    }),
    participants: Object.freeze(participants),
    volumes: Object.freeze(volumes),
    agentImageId: observation.agentImageId,
    controlPlaneGenerationDigest: effective.controlPlaneGenerationDigest,
    controlPlaneMaterializationDigest: effective.controlPlaneMaterializationDigest,
    securityContractHash: contract.contractHash,
    effectivePolicyGeneration: input.effectivePolicyGeneration,
    gitLayoutSha256: sha256(input.gitLayout),
    proxyCaCertSha256,
    agentCaBundleSha256,
    markerSha256: sha256(marker.body),
    nftShapeSha256: nftShape,
  });
  const validation = Object.freeze({
    runtimeProof: markerProof.proof,
    proxyStartedAt: startedAt,
    proxyPid: pid,
    bootId: bootId.body.trim(),
    // Not a fact the proof compares: the IP assignments this batch read, for
    // the launch's IP fence to use as its CAS precondition under the same held
    // lock (Task 6). A listing that failed is simply absent.
    ...(ipAssignments?.exit === 0 && parseIpAssignmentListing(ipAssignments.body)
      ? { ipAssignmentDigests: parseIpAssignmentListing(ipAssignments.body) }
      : {}),
  });
  sealedValidations.add(validation);
  return Object.freeze({ kind: "valid", facts, validation });
}

function parseWarmProofRecord(value: unknown): WarmProofRecordV1 | undefined {
  if (!isRecord(value) || !exactKeySet(value, ["version", "facts", "writtenAt"])) return undefined;
  if (value.version !== 1 || typeof value.writtenAt !== "string" || !Number.isFinite(Date.parse(value.writtenAt))) return undefined;
  if (!isRecord(value.facts) || !exactKeySet(value.facts, FACT_KEYS)) return undefined;
  return value as unknown as WarmProofRecordV1;
}

export function warmProofRecordPath(stateDir: string): string {
  return launchHostRecordPath(stateDir, WARM_PROOF_RECORD_NAME);
}

export function removeWarmProofRecord(stateDir: string): void {
  removeLaunchHostRecord(stateDir, WARM_PROOF_RECORD_NAME);
}

/**
 * The warm launch's one question: may this launch skip the full validation?
 * Never throws; every failure is a verdict that takes the full path.
 */
export function tryWarmRuntimeValidation(input: WarmProofInput, now: () => number = Date.now): WarmProofVerdict {
  try {
    const record = readLaunchHostRecord(input.plan.paths.stateDir, WARM_PROOF_RECORD_NAME, WARM_PROOF_RECORD_MAX_BYTES, parseWarmProofRecord);
    if (!record) return Object.freeze({ kind: "absent" });
    const age = now() - Date.parse(record.writtenAt);
    if (!(age >= 0 && age <= WARM_PROOF_MAX_AGE_MS)) return Object.freeze({ kind: "mismatch", field: "age" });
    const observation = observeWarmRuntime(input);
    if (typeof observation === "string") return Object.freeze({ kind: "unavailable", reason: observation });
    const judged = judgeWarmObservation(input, observation);
    if (judged.kind === "invalid") return Object.freeze({ kind: "mismatch", field: judged.field });
    for (const key of FACT_KEYS) {
      if (stableJson(judged.facts[key]) !== stableJson(record.facts[key])) {
        return Object.freeze({ kind: "mismatch", field: key });
      }
    }
    return Object.freeze({ kind: "match", validation: judged.validation });
  } catch (error) {
    return Object.freeze({ kind: "unavailable", reason: error instanceof Error ? error.message : String(error) });
  }
}

/**
 * After a full validation succeeded: observe once more and record the facts,
 * but only when the same warm judgement accepts them — a record the next
 * launch could never match is not written. Best effort; a failure only means
 * the next launch validates fully.
 */
export function recordWarmRuntimeProof(input: WarmProofInput, now: () => number = Date.now): "written" | string {
  try {
    const observation = observeWarmRuntime(input);
    if (typeof observation === "string") return observation;
    const judged = judgeWarmObservation(input, observation);
    if (judged.kind === "invalid") return `the fresh observation is not warm-valid: ${judged.field}`;
    const record: WarmProofRecordV1 = { version: 1, facts: judged.facts, writtenAt: new Date(now()).toISOString() };
    writeLaunchHostRecord(input.plan.paths.stateDir, WARM_PROOF_RECORD_NAME, `${JSON.stringify(record)}\n`);
    return "written";
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}
