

import { SESSION_ELIGIBILITY_PATH } from "@runfree/runtime-contracts/session-file";

import { ROOT_UID_GID } from "./constants.ts";
import {
  CONTROL_PLANE_PROOF_SCHEMA_VERSION,
  readControlPlaneMaterializationV2,
  readEffectiveControlPlaneV2,
  selectEffectiveControlPlaneV2,
  type ControlPlaneEffectiveSelectionV2,
  type ControlPlaneGenerationV2,
} from "./component-state-v2.ts";
import {
  assertDenyByDefaultFirewallObservationV1,
  DENY_BY_DEFAULT_BASE_PROOF_SCHEMA_VERSION,
  type DenyByDefaultObservationV1,
} from "./control-plane-deny-proof.ts";
import {
  assertRuntimeStartupSecurityContractProof,
  type RuntimeSecurityContractProof,
} from "./security-contract.ts";
import {
  listQuarantinedSessionContainerRecordNamesV2,
  listSessionContainerRecordsV2,
} from "./session-containers.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import type { RuntimeValidationProof } from "./state.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { CaptureResult, RuntimeIO } from "./types.ts";
import { strictStableJson, sha256Digest as sha256, isRecord } from "../strict-primitives.ts";
import { CliError } from "../errors.ts";
import { remedy } from "../remedies.ts";

const DOCKER_ID = /^[a-f0-9]{64}$/;
const MAX_INSPECT_BYTES = 512 * 1024;
// Deny-by-default for the session-file protocol is "the proxy holds no
// eligibility": every session file is refused by the proxy's own reader
// without it (invariant 9), so a newly selected control plane that has not
// published one serves nothing. The empty `session_ipv4` set below is the
// kernel half of the same claim.
const BASE_STATE_PATHS = [SESSION_ELIGIBILITY_PATH] as const;
const READ_BASE_STATE_SCRIPT = [
  "const fs = require('node:fs');",
  "process.stdout.write(JSON.stringify(process.argv.slice(1).map((file) => fs.existsSync(file))));",
].join(" ");

type Json = boolean | null | number | string | Json[] | { [key: string]: Json };

type ContainerInspect = {
  Id?: unknown;
  Image?: unknown;
  State?: { Running?: unknown };
  NetworkSettings?: {
    Networks?: Record<string, { NetworkID?: unknown }>;
  };
};

type LiveControlPlaneIdentity = Readonly<{
  proxyContainerId: string;
  proxyImageId: string;
  sidecarContainerIds: readonly ControlPlaneEffectiveSelectionV2["sidecarContainerIds"][number][];
  networkIds: ControlPlaneEffectiveSelectionV2["networkIds"];
}>;

type LiveControlPlaneEvidence = LiveControlPlaneIdentity & Readonly<{
  sessionEligibilityAbsent: true;
  sessionAdmissionFirewallIps: readonly string[];
}>;

function stableJson(value: Json): string {
  return strictStableJson(value, "control-plane proof contains a non-finite number");
}


function exactJson(result: CaptureResult, label: string): unknown {
  if (result.status !== 0) {
    const detail = result.stderr.trim() || result.stdout.trim() || `exit ${result.status}`;
    throw new Error(`${label} failed: ${detail}`);
  }
  if (Buffer.byteLength(result.stdout) > MAX_INSPECT_BYTES) throw new Error(`${label} exceeds the size limit`);
  try {
    return JSON.parse(result.stdout) as unknown;
  } catch {
    throw new Error(`${label} returned malformed JSON`);
  }
}


function exactRuntimeComponents(
  left: ControlPlaneGenerationV2,
  right: ControlPlaneGenerationV2,
): boolean {
  return left.schemaVersion === right.schemaVersion
    && left.projectId === right.projectId
    && left.composeProject === right.composeProject
    && left.proxyImageInputDigest === right.proxyImageInputDigest
    && left.controlPlaneTopologyDigest === right.controlPlaneTopologyDigest
    && left.admissionContractEpoch === right.admissionContractEpoch
    && left.controlPlaneGenerationDigest === right.controlPlaneGenerationDigest;
}

// Control-plane-scoped on purpose: the proof and contract must stay valid
// across session-agent rolls, or a template change would strand the durable
// effective selection while sessions are live.
function activeComponents(plan: ActiveRuntimePlan): ControlPlaneGenerationV2 {
  return { ...plan.generationV2.controlPlane };
}

function assertRuntimeProof(plan: ActiveRuntimePlan, proof: RuntimeValidationProof): void {
  if (proof.proofVersion !== 4
    || proof.projectId !== plan.projectId
    || !exactRuntimeComponents(proof.components, activeComponents(plan))
    || !DOCKER_ID.test(proof.proxyId)
    || typeof proof.contractHash !== "string") {
    throw new Error("runtime validation proof does not match the active control-plane plan");
  }
}

function parseEmptySessionSet(value: unknown): boolean {
  if (!isRecord(value) || !Array.isArray(value.nftables)) return false;
  const sets = value.nftables.flatMap((entry): Record<string, unknown>[] => {
    return isRecord(entry) && isRecord(entry.set) ? [entry.set] : [];
  }).filter((set) => set.family === "inet" && set.table === "runfree_proxy" && set.name === "session_ipv4");
  if (sets.length !== 1) return false;
  const elements = sets[0]?.elem;
  return elements === undefined || (Array.isArray(elements) && elements.length === 0);
}

function networkMap(container: ContainerInspect, expectedNames: readonly string[], label: string): Record<string, string> {
  const networks = container.NetworkSettings?.Networks;
  if (!networks || Object.keys(networks).sort().join("\0") !== [...expectedNames].sort().join("\0")) {
    throw new Error(`${label} has unexpected Docker network attachments`);
  }
  return Object.fromEntries(expectedNames.map((name) => {
    const id = networks[name]?.NetworkID;
    if (typeof id !== "string" || !DOCKER_ID.test(id)) throw new Error(`${label} has invalid Docker network identity`);
    return [name, id];
  }));
}

function inspectLiveControlPlaneIdentity(input: {
  plan: ActiveRuntimePlan;
  io: RuntimeIO;
  proxyContainerId: string;
  expectedProxyImageId: string;
  assertAuthority?: () => void;
}): LiveControlPlaneIdentity {
  const { plan, io } = input;
  input.assertAuthority?.();
  const containerIds = [input.proxyContainerId];
  const dockerOptions = { env: { ...plan.execution.dockerClientEnv } };
  const containerValue = exactJson(
    io.capture("docker", ["container", "inspect", ...containerIds], dockerOptions),
    "control-plane container inspection",
  );
  if (!Array.isArray(containerValue) || containerValue.length !== containerIds.length) {
    throw new Error("control-plane container inspection returned an unexpected object count");
  }
  const containers = new Map<string, ContainerInspect>();
  for (const entry of containerValue) {
    if (!isRecord(entry) || typeof entry.Id !== "string" || !DOCKER_ID.test(entry.Id) || containers.has(entry.Id)) {
      throw new Error("control-plane container inspection returned invalid identity");
    }
    containers.set(entry.Id, entry as ContainerInspect);
  }
  const proxy = containers.get(input.proxyContainerId);
  if (!proxy || proxy.State?.Running !== true || proxy.Image !== input.expectedProxyImageId) {
    throw new Error("running proxy container does not use the materialized immutable image");
  }
  const internalName = `${plan.composeProjectName}_agent_internal`;
  const egressName = `${plan.composeProjectName}_proxy_egress`;
  const proxyNetworks = networkMap(proxy, [internalName, egressName], "proxy container");

  const sidecarContainerIds: ControlPlaneEffectiveSelectionV2["sidecarContainerIds"] = [];

  input.assertAuthority?.();
  const networkNames = [internalName, egressName];
  const networkValue = exactJson(
    io.capture("docker", ["network", "inspect", ...networkNames], dockerOptions),
    "control-plane network inspection",
  );
  if (!Array.isArray(networkValue) || networkValue.length !== networkNames.length) {
    throw new Error("control-plane network inspection returned an unexpected object count");
  }
  const networks = new Map<string, string>();
  for (const entry of networkValue) {
    if (!isRecord(entry)
      || typeof entry.Name !== "string"
      || !networkNames.includes(entry.Name)
      || typeof entry.Id !== "string"
      || !DOCKER_ID.test(entry.Id)
      || networks.has(entry.Name)) {
      throw new Error("control-plane network inspection returned invalid identity");
    }
    networks.set(entry.Name, entry.Id);
  }
  if (new Set(networks.values()).size !== networkNames.length
    || proxyNetworks[internalName] !== networks.get(internalName)
    || proxyNetworks[egressName] !== networks.get(egressName)) {
    throw new Error("control-plane container endpoints contradict Docker network identity");
  }

  return Object.freeze({
    proxyContainerId: input.proxyContainerId,
    proxyImageId: input.expectedProxyImageId,
    sidecarContainerIds: Object.freeze(sidecarContainerIds),
    networkIds: Object.freeze({
      agentInternal: networks.get(internalName) as string,
      proxyEgress: networks.get(egressName) as string,
    }),
  });
}

function inspectLiveEvidence(input: {
  plan: ActiveRuntimePlan;
  proof: RuntimeValidationProof;
  io: RuntimeIO;
  lifecycleLock: ProjectLifecycleLock;
  expectedProxyImageId: string;
}): LiveControlPlaneEvidence {
  const { plan, proof, io, lifecycleLock } = input;
  const identity = inspectLiveControlPlaneIdentity({
    plan,
    io,
    proxyContainerId: proof.proxyId,
    expectedProxyImageId: input.expectedProxyImageId,
    assertAuthority: () => lifecycleLock.assertHeld(),
  });
  const dockerOptions = { env: { ...plan.execution.dockerClientEnv } };
  lifecycleLock.assertHeld();
  const baseState = exactJson(
    io.capture("docker", [
      "exec",
      "--user",
      ROOT_UID_GID,
      proof.proxyId,
      "node",
      "-e",
      READ_BASE_STATE_SCRIPT,
      ...BASE_STATE_PATHS,
    ], dockerOptions),
    "session-admission base-state inspection",
  );
  if (!Array.isArray(baseState)
    || baseState.length !== BASE_STATE_PATHS.length
    || baseState.some((present) => present !== false)) {
    throw new Error("session-admission base state is not deny-by-default");
  }
  lifecycleLock.assertHeld();
  const sessionSet = exactJson(
    io.capture("docker", [
      "exec",
      "--user",
      ROOT_UID_GID,
      proof.proxyId,
      "nft",
      "-j",
      "list",
      "set",
      "inet",
      "runfree_proxy",
      "session_ipv4",
    ], dockerOptions),
    "session-admission nftables base-set inspection",
  );
  if (!parseEmptySessionSet(sessionSet)) throw new Error("session-admission firewall base set is not empty");

  return Object.freeze({
    ...identity,
    sessionEligibilityAbsent: true,
    sessionAdmissionFirewallIps: Object.freeze([]),
  });
}

function assertNoSessionLifecycleRecords(plan: ActiveRuntimePlan): void {
  const records = listSessionContainerRecordsV2(plan.paths.stateDir, {
    projectId: plan.projectId,
    composeProject: plan.composeProjectName,
  });
  if (records.length !== 0) {
    throw new Error("control-plane selection requires session lifecycle reconciliation before token sync");
  }
  // A quarantined unreadable record is not "no records": the container it
  // named may still hold an internal-network address, so selection stays
  // refused until the residue is cleared.
  const quarantined = listQuarantinedSessionContainerRecordNamesV2(plan.paths.stateDir);
  if (quarantined.length !== 0) {
    throw new CliError(
      `control-plane selection refuses quarantined unreadable session record(s): ${quarantined.join(", ")}; `
      + `run \`${remedy.destroyForce()}\` to clear the residue (this destroys the whole project runtime and ends all of its sessions)`,
    );
  }
}

function matchingEffectiveControlPlaneV2(
  plan: ActiveRuntimePlan,
  proof: RuntimeValidationProof,
): ReturnType<typeof readEffectiveControlPlaneV2> {
  assertRuntimeProof(plan, proof);
  const effective = readEffectiveControlPlaneV2(plan.paths.stateDir);
  if (!effective) return undefined;
  const { selection, manifest } = effective;
  const expectedSidecar: never[] = [];
  return selection.projectId === plan.projectId
    && selection.composeProject === plan.composeProjectName
    && selection.controlPlaneGenerationDigest === plan.generationV2.controlPlane.controlPlaneGenerationDigest
    && selection.admissionContractEpoch === plan.generationV2.controlPlane.admissionContractEpoch
    && selection.proxyContainerId === proof.proxyId
    && selection.securityContractHash === proof.contractHash
    && JSON.stringify(selection.sidecarContainerIds) === JSON.stringify(expectedSidecar)
    && manifest.proxyImageRef === plan.activeRuntime.proxyImage
    && manifest.renderedControlPlaneSha256 === plan.generationV2.controlPlane.controlPlaneTopologyDigest
    ? effective
    : undefined;
}

export function effectiveControlPlaneMatchesRuntimeValidationV2(
  plan: ActiveRuntimePlan,
  proof: RuntimeValidationProof,
): boolean {
  try {
    return matchingEffectiveControlPlaneV2(plan, proof) !== undefined;
  } catch {
    return false;
  }
}

/**
 * Reuses a persisted effective selection only when one bounded Docker
 * container inspection and one bounded network inspection still prove its
 * exact immutable image, participants, network IDs, and endpoint bindings.
 * Dynamic admission state is deliberately outside this warm-path check.
 */
export function effectiveControlPlaneMatchesLiveRuntimeValidationV2(
  plan: ActiveRuntimePlan,
  proof: RuntimeValidationProof,
  io: RuntimeIO,
): boolean {
  try {
    const effective = matchingEffectiveControlPlaneV2(plan, proof);
    if (!effective) return false;
    const identity = inspectLiveControlPlaneIdentity({
      plan,
      io,
      proxyContainerId: proof.proxyId,
      expectedProxyImageId: effective.selection.proxyImageId,
    });
    return identity.proxyContainerId === effective.selection.proxyContainerId
      && identity.proxyImageId === effective.selection.proxyImageId
      && stableJson(identity.sidecarContainerIds as unknown as Json)
        === stableJson(effective.selection.sidecarContainerIds as unknown as Json)
      && stableJson(identity.networkIds as unknown as Json)
        === stableJson(effective.selection.networkIds as unknown as Json);
  } catch {
    return false;
  }
}

function proveControlPlaneCandidateV2(input: {
  plan: ActiveRuntimePlan;
  runtimeProof: RuntimeValidationProof;
  securityProof: RuntimeSecurityContractProof;
  denyByDefaultObservation: DenyByDefaultObservationV1;
  lifecycleLock: ProjectLifecycleLock;
  io: RuntimeIO;
  now?: () => Date;
  requireEmptyLifecycleRegistry: boolean;
}): ControlPlaneEffectiveSelectionV2 {
  const { plan, runtimeProof, securityProof, denyByDefaultObservation, lifecycleLock } = input;
  lifecycleLock.assertHeld();
  assertRuntimeProof(plan, runtimeProof);
  assertRuntimeStartupSecurityContractProof(securityProof, {
    runtimeId: plan.composeProjectName,
    components: activeComponents(plan),
    contractHash: runtimeProof.contractHash as string,
  });
  // The firewall-minted observation is the only deny-by-default evidence: its
  // proof is the live kernel ruleset (INPUT policy drop + @session_ipv4-only),
  // which covers ALL unadmitted sources rather than a single traffic probe.
  if (denyByDefaultObservation.origin !== "proxy-firewall") {
    throw new Error("deny-by-default observation has an unrecognized origin");
  }
  assertDenyByDefaultFirewallObservationV1(denyByDefaultObservation);
  if (denyByDefaultObservation.projectId !== plan.projectId
    || denyByDefaultObservation.controlPlaneGenerationDigest
      !== plan.generationV2.controlPlane.controlPlaneGenerationDigest
    || denyByDefaultObservation.proxyContainerId !== runtimeProof.proxyId) {
    throw new Error("deny-by-default observation belongs to another control-plane identity");
  }
  if (CONTROL_PLANE_PROOF_SCHEMA_VERSION !== DENY_BY_DEFAULT_BASE_PROOF_SCHEMA_VERSION) {
    throw new Error("control-plane proof schemas are inconsistent");
  }
  if (input.requireEmptyLifecycleRegistry) assertNoSessionLifecycleRecords(plan);
  const controlPlaneMaterializationDigest = plan.activeRuntime.controlPlaneMaterializationDigest;
  if (!controlPlaneMaterializationDigest) {
    throw new Error("validated control plane has no exact materialization identity");
  }
  const manifest = readControlPlaneMaterializationV2(
    plan.paths.stateDir,
    controlPlaneMaterializationDigest,
  );
  if (!manifest
    || manifest.projectId !== plan.projectId
    || manifest.composeProject !== plan.composeProjectName
    || manifest.generation.controlPlaneGenerationDigest
      !== plan.generationV2.controlPlane.controlPlaneGenerationDigest
    || manifest.proxyImageRef !== plan.activeRuntime.proxyImage
    || manifest.renderedControlPlaneSha256 !== plan.generationV2.controlPlane.controlPlaneTopologyDigest) {
    throw new Error("validated control plane has no exact immutable materialization");
  }

  const first = inspectLiveEvidence({
    plan,
    proof: runtimeProof,
    io: input.io,
    lifecycleLock,
    expectedProxyImageId: manifest.proxyImageId,
  });
  lifecycleLock.assertHeld();
  if (input.requireEmptyLifecycleRegistry) assertNoSessionLifecycleRecords(plan);
  const final = inspectLiveEvidence({
    plan,
    proof: runtimeProof,
    io: input.io,
    lifecycleLock,
    expectedProxyImageId: manifest.proxyImageId,
  });
  if (stableJson(first as unknown as Json) !== stableJson(final as unknown as Json)) {
    throw new Error("control-plane Docker identity changed before effective selection");
  }
  const denyByDefaultBaseProofHash = sha256(stableJson({
    schemaVersion: DENY_BY_DEFAULT_BASE_PROOF_SCHEMA_VERSION,
    projectId: plan.projectId,
    composeProject: plan.composeProjectName,
    controlPlaneGenerationDigest: plan.generationV2.controlPlane.controlPlaneGenerationDigest,
    controlPlaneMaterializationDigest: manifest.controlPlaneMaterializationDigest,
    observation: denyByDefaultObservation as unknown as Json,
    evidence: final as unknown as Json,
  }));
  const selection: ControlPlaneEffectiveSelectionV2 = {
    schemaVersion: 2,
    projectId: plan.projectId,
    composeProject: plan.composeProjectName,
    controlPlaneGenerationDigest: plan.generationV2.controlPlane.controlPlaneGenerationDigest,
    controlPlaneMaterializationDigest: manifest.controlPlaneMaterializationDigest,
    proxyContainerId: final.proxyContainerId,
    proxyImageId: final.proxyImageId,
    sidecarContainerIds: [],
    networkIds: { ...final.networkIds },
    securityContractHash: securityProof.contractHash,
    proofSchemaVersion: CONTROL_PLANE_PROOF_SCHEMA_VERSION,
    admissionContractEpoch: plan.generationV2.controlPlane.admissionContractEpoch,
    denyByDefaultBaseProofHash,
    selectedAt: (input.now?.() ?? new Date()).toISOString(),
    runfreeVersion: plan.runfreeVersion,
  };
  return selection;
}

/** Proves a materialized candidate without granting effective authority. */
export function proveCandidateControlPlaneV2(input: Omit<
  Parameters<typeof proveControlPlaneCandidateV2>[0],
  "requireEmptyLifecycleRegistry"
>): ControlPlaneEffectiveSelectionV2 {
  return proveControlPlaneCandidateV2({ ...input, requireEmptyLifecycleRegistry: false });
}

export function proveAndSelectEffectiveControlPlaneV2(input: Omit<
  Parameters<typeof proveControlPlaneCandidateV2>[0],
  "requireEmptyLifecycleRegistry"
>): ControlPlaneEffectiveSelectionV2 {
  const selection = proveControlPlaneCandidateV2({ ...input, requireEmptyLifecycleRegistry: true });
  input.lifecycleLock.assertHeld();
  selectEffectiveControlPlaneV2(input.plan.paths.stateDir, selection);
  return selection;
}

/**
 * Re-proves a rebind candidate that has already had a session-admission
 * snapshot published to it.
 *
 * The full candidate proof asserts the deny-all base state — absent selection
 * pointers, absent statuses, an empty `session_ipv4` set. That claim is only
 * true before the rebind publishes its snapshot; from the records-rebound
 * phase onward the published overlay legitimately exists, so re-running the
 * deny-all proof would refuse a healthy in-flight transaction (and permanently
 * wedge its crash recovery). This re-proof instead pins identity continuity:
 * the exact recorded container, immutable image, sidecar set, and network IDs
 * still hold live, the recorded authority still matches the active plan's
 * generation and materialization, and the validated runtime/security proofs
 * bind the same proxy. Snapshot correctness stays owned by the consumer
 * acknowledgement steps; `denyByDefaultBaseProofHash` is deliberately not
 * recomputed — it was minted once against this exact container before
 * publication and the container binding is what this check re-proves.
 */
export function reproveRecordedCandidateControlPlaneV2(input: {
  plan: ActiveRuntimePlan;
  recorded: ControlPlaneEffectiveSelectionV2;
  runtimeProof: RuntimeValidationProof;
  securityProof: RuntimeSecurityContractProof;
  lifecycleLock: ProjectLifecycleLock;
  io: RuntimeIO;
}): void {
  const { plan, recorded, runtimeProof, securityProof, lifecycleLock } = input;
  lifecycleLock.assertHeld();
  assertRuntimeProof(plan, runtimeProof);
  assertRuntimeStartupSecurityContractProof(securityProof, {
    runtimeId: plan.composeProjectName,
    components: activeComponents(plan),
    contractHash: runtimeProof.contractHash as string,
  });
  if (recorded.schemaVersion !== 2
    || recorded.proofSchemaVersion !== CONTROL_PLANE_PROOF_SCHEMA_VERSION
    || recorded.projectId !== plan.projectId
    || recorded.composeProject !== plan.composeProjectName
    || recorded.controlPlaneGenerationDigest !== plan.generationV2.controlPlane.controlPlaneGenerationDigest
    || recorded.admissionContractEpoch !== plan.generationV2.controlPlane.admissionContractEpoch
    || recorded.proxyContainerId !== runtimeProof.proxyId
    || recorded.securityContractHash !== runtimeProof.contractHash) {
    throw new Error("recorded rebind candidate contradicts the validated runtime");
  }
  const controlPlaneMaterializationDigest = plan.activeRuntime.controlPlaneMaterializationDigest;
  if (!controlPlaneMaterializationDigest
    || recorded.controlPlaneMaterializationDigest !== controlPlaneMaterializationDigest) {
    throw new CliError(
      "recorded rebind candidate has no exact materialization identity; "
      + `the pending rebind cannot complete against changed runtime inputs; run \`${remedy.rebuild()}\` to recover`,
    );
  }
  const manifest = readControlPlaneMaterializationV2(plan.paths.stateDir, controlPlaneMaterializationDigest);
  if (!manifest
    || manifest.projectId !== plan.projectId
    || manifest.composeProject !== plan.composeProjectName
    || manifest.generation.controlPlaneGenerationDigest
      !== plan.generationV2.controlPlane.controlPlaneGenerationDigest
    || manifest.proxyImageRef !== plan.activeRuntime.proxyImage
    || manifest.renderedControlPlaneSha256 !== plan.generationV2.controlPlane.controlPlaneTopologyDigest
    || manifest.proxyImageId !== recorded.proxyImageId) {
    throw new Error("recorded rebind candidate has no exact immutable materialization");
  }
  const identity = inspectLiveControlPlaneIdentity({
    plan,
    io: input.io,
    proxyContainerId: recorded.proxyContainerId,
    expectedProxyImageId: manifest.proxyImageId,
    assertAuthority: () => lifecycleLock.assertHeld(),
  });
  if (stableJson(identity.sidecarContainerIds as unknown as Json)
      !== stableJson(recorded.sidecarContainerIds as unknown as Json)
    || stableJson(identity.networkIds as unknown as Json)
      !== stableJson(recorded.networkIds as unknown as Json)) {
    throw new Error("recorded rebind candidate contradicts live Docker identity");
  }
}
