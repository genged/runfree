import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { readBoundedRegularFile, sha256Digest as sha256, exactKeySet as exactKeys, isRecord } from "../strict-primitives.ts";
import { fsyncDirectory } from "../safe-fs.ts";
import { strictStableJson } from "../strict-primitives.ts";

export const RUNTIME_STATE_SCHEMA_VERSION_V2 = 2 as const;
export const RUNTIME_ADMISSION_CONTRACT_EPOCH = 4 as const;
export const CONTROL_PLANE_PROOF_SCHEMA_VERSION = 1 as const;

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const PROJECT_ID_PATTERN = /^[a-f0-9]{12}$/;
const DOCKER_OBJECT_ID_PATTERN = /^[a-f0-9]{64}$/;
const MAX_STATE_FILE_BYTES = 64 * 1024;

type StrictJson = boolean | null | number | string | StrictJson[] | { [key: string]: StrictJson };

export type RuntimeTopologyGenerationV2 = {
  schemaVersion: typeof RUNTIME_STATE_SCHEMA_VERSION_V2;
  controlPlaneTopologyDigest: string;
  sessionTemplateDigest: string;
  topologyDigest: string;
};

export type ControlPlaneGenerationV2 = {
  schemaVersion: typeof RUNTIME_STATE_SCHEMA_VERSION_V2;
  projectId: string;
  composeProject: string;
  proxyImageInputDigest: string;
  controlPlaneTopologyDigest: string;
  admissionContractEpoch: number;
  controlPlaneGenerationDigest: string;
};

export type SessionAgentGenerationInputsV2 = {
  schemaVersion: typeof RUNTIME_STATE_SCHEMA_VERSION_V2;
  selectedAgentImageInputDigest: string;
  sessionTemplateDigest: string;
  admissionContractEpoch: number;
  sessionAgentGenerationDigest: string;
};

export type SessionAgentGenerationV2 = SessionAgentGenerationInputsV2 & {
  selectedAgentImageId: string;
};

export type SessionAgentSelectedImageKindV2 = "embedded" | "project";

export type SessionAgentMaterializationManifestV2 = {
  schemaVersion: typeof RUNTIME_STATE_SCHEMA_VERSION_V2;
  projectId: string;
  composeProject: string;
  generation: SessionAgentGenerationV2;
  selectedAgentImageRef: string;
  selectedAgentImageId: string;
  selectedAgentImageKind: SessionAgentSelectedImageKindV2;
  sessionTemplateArtifactSha256: string;
  sessionAgentMaterializationDigest: string;
};

export type LegacySessionAgentMaterializationManifestV2 = Omit<
  SessionAgentMaterializationManifestV2,
  "sessionTemplateArtifactSha256" | "sessionAgentMaterializationDigest"
> & {
  sessionAgentMaterializationDigest: string;
};

export type RetainedSessionAgentMaterializationManifestV2 =
  | SessionAgentMaterializationManifestV2
  | LegacySessionAgentMaterializationManifestV2;

export type SessionAgentDesiredSelectionV2 = {
  schemaVersion: typeof RUNTIME_STATE_SCHEMA_VERSION_V2;
  projectId: string;
  composeProject: string;
  sessionAgentGenerationDigest: string;
  sessionAgentMaterializationDigest: string;
  selectedAgentImageId: string;
};

export type ControlPlaneMaterializationManifestV2 = {
  schemaVersion: typeof RUNTIME_STATE_SCHEMA_VERSION_V2;
  projectId: string;
  composeProject: string;
  generation: ControlPlaneGenerationV2;
  proxyImageRef: string;
  proxyImageId: string;
  renderedControlPlaneSha256: string;
  // Which admission source the materialized proxy was started with. The CLI
  // mints `RUNFREE_SESSION_ADMISSION_SOURCE=files` into every proxy it
  // creates, so `files` is the only value this field ever carries. A manifest
  // without it was materialized by a pre-cutover CLI against a proxy that
  // reads a protocol this one no longer speaks: it fails to parse, the
  // selection reads as absent, and `runfree up` recreates the control plane.
  sessionAdmissionSource: "files";
  controlPlaneMaterializationDigest: string;
};

/**
 * The last session eligibility this host published into one exact proxy
 * container. Kept beside the effective control-plane selection so a repeated
 * publication of identical bytes costs no `docker exec`, and so a replaced
 * proxy — whose session-file directory starts empty — is never mistaken for a
 * proxy that already holds them.
 */
export type PublishedSessionEligibilityV2 = {
  schemaVersion: typeof RUNTIME_STATE_SCHEMA_VERSION_V2;
  projectId: string;
  composeProject: string;
  proxyContainerId: string;
  // Docker's `State.StartedAt` for that container. The container id alone is
  // not the incarnation: `runfree runtime reload-policy --force` restarts the
  // same container in place, and the proxy entrypoint recreates the session
  // file directory and removes `eligibility.json` on every start. Without the
  // start time the record would claim a file the restarted proxy no longer has.
  proxyStartedAt: string;
  eligibilitySha256: string;
};

export type ControlPlaneEffectiveSelectionV2 = {
  schemaVersion: typeof RUNTIME_STATE_SCHEMA_VERSION_V2;
  projectId: string;
  composeProject: string;
  controlPlaneGenerationDigest: string;
  controlPlaneMaterializationDigest: string;
  proxyContainerId: string;
  proxyImageId: string;
  // The fixed control plane has no sidecar containers; the key is retained in
  // the persisted schema (always empty) so current selections stay parseable,
  // and a retired relay-era selection carrying one fails parse closed.
  sidecarContainerIds: never[];
  networkIds: {
    agentInternal: string;
    proxyEgress: string;
  };
  securityContractHash: string;
  proofSchemaVersion: typeof CONTROL_PLANE_PROOF_SCHEMA_VERSION;
  admissionContractEpoch: number;
  denyByDefaultBaseProofHash: string;
  selectedAt: string;
  runfreeVersion: string;
};

export type RuntimeGenerationTargetV2 = {
  topology: RuntimeTopologyGenerationV2;
  controlPlane: ControlPlaneGenerationV2;
  sessionAgent: SessionAgentGenerationInputsV2;
};

function stableJson(value: StrictJson): string {
  return strictStableJson(value, "runtime generation inputs must contain finite numbers");
}




function requireDigest(value: string, label: string): string {
  if (!SHA256_PATTERN.test(value)) throw new Error(`${label} must be a full sha256 digest`);
  return value;
}

function validProjectIdentity(projectId: unknown, composeProject: unknown): projectId is string {
  return typeof projectId === "string"
    && PROJECT_ID_PATTERN.test(projectId)
    && composeProject === `runfree-${projectId}`;
}

function validAdmissionEpoch(value: unknown): value is number {
  return Number.isSafeInteger(value) && typeof value === "number" && value > 0;
}

function validIsoTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function validBoundedText(value: unknown, maximum: number): value is string {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maximum
    && !/[\x00-\x1f\x7f]/.test(value);
}

function validImageRef(value: unknown): value is string {
  return validBoundedText(value, 512)
    && value === value.trim()
    && !/\s/u.test(value);
}

export function runtimeTopologyDigestV2(input: {
  controlPlaneTopologyDigest: string;
  sessionTemplateDigest: string;
}): string {
  return sha256(stableJson({
    schemaVersion: RUNTIME_STATE_SCHEMA_VERSION_V2,
    controlPlaneTopologyDigest: requireDigest(
      input.controlPlaneTopologyDigest,
      "control-plane topology digest",
    ),
    sessionTemplateDigest: requireDigest(input.sessionTemplateDigest, "session template digest"),
  }));
}

export function createRuntimeTopologyGenerationV2(input: {
  controlPlaneTopologyDigest: string;
  sessionTemplateDigest: string;
}): RuntimeTopologyGenerationV2 {
  const base = {
    schemaVersion: RUNTIME_STATE_SCHEMA_VERSION_V2,
    controlPlaneTopologyDigest: requireDigest(input.controlPlaneTopologyDigest, "control-plane topology digest"),
    sessionTemplateDigest: requireDigest(input.sessionTemplateDigest, "session template digest"),
  } as const;
  return { ...base, topologyDigest: runtimeTopologyDigestV2(base) };
}

export function controlPlaneGenerationDigestV2(input: Omit<
  ControlPlaneGenerationV2,
  "controlPlaneGenerationDigest" | "composeProject" | "projectId"
>): string {
  if (input.schemaVersion !== RUNTIME_STATE_SCHEMA_VERSION_V2) {
    throw new Error("control-plane generation digest requires schema version 2");
  }
  if (!validAdmissionEpoch(input.admissionContractEpoch)) {
    throw new Error("admission contract epoch must be a positive safe integer");
  }
  return sha256(stableJson({
    schemaVersion: input.schemaVersion,
    proxyImageInputDigest: requireDigest(input.proxyImageInputDigest, "proxy image input digest"),
    controlPlaneTopologyDigest: requireDigest(input.controlPlaneTopologyDigest, "control-plane topology digest"),
    admissionContractEpoch: input.admissionContractEpoch,
  }));
}

export function createControlPlaneGenerationV2(input: {
  projectId: string;
  composeProject: string;
  proxyImageInputDigest: string;
  controlPlaneTopologyDigest: string;
  admissionContractEpoch: number;
}): ControlPlaneGenerationV2 {
  if (!validProjectIdentity(input.projectId, input.composeProject)) {
    throw new Error("control-plane generation has invalid project identity");
  }
  const base = {
    schemaVersion: RUNTIME_STATE_SCHEMA_VERSION_V2,
    projectId: input.projectId,
    composeProject: input.composeProject,
    proxyImageInputDigest: requireDigest(input.proxyImageInputDigest, "proxy image input digest"),
    controlPlaneTopologyDigest: requireDigest(input.controlPlaneTopologyDigest, "control-plane topology digest"),
    admissionContractEpoch: input.admissionContractEpoch,
  } as const;
  return { ...base, controlPlaneGenerationDigest: controlPlaneGenerationDigestV2(base) };
}

export function sessionAgentGenerationDigestV2(input: Omit<
  SessionAgentGenerationInputsV2,
  "sessionAgentGenerationDigest"
>): string {
  if (input.schemaVersion !== RUNTIME_STATE_SCHEMA_VERSION_V2) {
    throw new Error("session agent generation digest requires schema version 2");
  }
  if (!validAdmissionEpoch(input.admissionContractEpoch)) {
    throw new Error("admission contract epoch must be a positive safe integer");
  }
  return sha256(stableJson({
    schemaVersion: input.schemaVersion,
    selectedAgentImageInputDigest: requireDigest(
      input.selectedAgentImageInputDigest,
      "selected agent image input digest",
    ),
    sessionTemplateDigest: requireDigest(input.sessionTemplateDigest, "session template digest"),
    admissionContractEpoch: input.admissionContractEpoch,
  }));
}

export function createSessionAgentGenerationInputsV2(input: {
  selectedAgentImageInputDigest: string;
  sessionTemplateDigest: string;
  admissionContractEpoch: number;
}): SessionAgentGenerationInputsV2 {
  const base = {
    schemaVersion: RUNTIME_STATE_SCHEMA_VERSION_V2,
    selectedAgentImageInputDigest: requireDigest(
      input.selectedAgentImageInputDigest,
      "selected agent image input digest",
    ),
    sessionTemplateDigest: requireDigest(input.sessionTemplateDigest, "session template digest"),
    admissionContractEpoch: input.admissionContractEpoch,
  } as const;
  return { ...base, sessionAgentGenerationDigest: sessionAgentGenerationDigestV2(base) };
}

export function bindSessionAgentImageV2(
  inputs: SessionAgentGenerationInputsV2,
  selectedAgentImageId: string,
): SessionAgentGenerationV2 {
  const parsed = parseSessionAgentGenerationInputsV2(inputs);
  if (!parsed) throw new Error("session agent generation inputs are invalid");
  return {
    ...parsed,
    selectedAgentImageId: requireDigest(selectedAgentImageId, "selected agent image ID"),
  };
}

export function parseRuntimeTopologyGenerationV2(value: unknown): RuntimeTopologyGenerationV2 | undefined {
  if (!isRecord(value) || !exactKeys(value, [
    "schemaVersion",
    "controlPlaneTopologyDigest",
    "sessionTemplateDigest",
    "topologyDigest",
  ])) return undefined;
  if (value.schemaVersion !== RUNTIME_STATE_SCHEMA_VERSION_V2) return undefined;
  if (![value.controlPlaneTopologyDigest, value.sessionTemplateDigest, value.topologyDigest]
    .every((entry) => typeof entry === "string" && SHA256_PATTERN.test(entry))) return undefined;
  const parsed = value as RuntimeTopologyGenerationV2;
  return runtimeTopologyDigestV2(parsed) === parsed.topologyDigest ? parsed : undefined;
}

export function parseControlPlaneGenerationV2(value: unknown): ControlPlaneGenerationV2 | undefined {
  if (!isRecord(value) || !exactKeys(value, [
    "schemaVersion",
    "projectId",
    "composeProject",
    "proxyImageInputDigest",
    "controlPlaneTopologyDigest",
    "admissionContractEpoch",
    "controlPlaneGenerationDigest",
  ])) return undefined;
  if (value.schemaVersion !== RUNTIME_STATE_SCHEMA_VERSION_V2
    || typeof value.projectId !== "string"
    || typeof value.composeProject !== "string"
    || !validProjectIdentity(value.projectId, value.composeProject)
    || !validAdmissionEpoch(value.admissionContractEpoch)
    || typeof value.proxyImageInputDigest !== "string" || !SHA256_PATTERN.test(value.proxyImageInputDigest)
    || typeof value.controlPlaneTopologyDigest !== "string" || !SHA256_PATTERN.test(value.controlPlaneTopologyDigest)
    || typeof value.controlPlaneGenerationDigest !== "string" || !SHA256_PATTERN.test(value.controlPlaneGenerationDigest)) {
    return undefined;
  }
  const parsed = value as ControlPlaneGenerationV2;
  return controlPlaneGenerationDigestV2(parsed) === parsed.controlPlaneGenerationDigest ? parsed : undefined;
}

export function parseSessionAgentGenerationInputsV2(value: unknown): SessionAgentGenerationInputsV2 | undefined {
  if (!isRecord(value) || !exactKeys(value, [
    "schemaVersion",
    "selectedAgentImageInputDigest",
    "sessionTemplateDigest",
    "admissionContractEpoch",
    "sessionAgentGenerationDigest",
  ])) return undefined;
  if (value.schemaVersion !== RUNTIME_STATE_SCHEMA_VERSION_V2
    || !validAdmissionEpoch(value.admissionContractEpoch)
    || typeof value.selectedAgentImageInputDigest !== "string"
    || !SHA256_PATTERN.test(value.selectedAgentImageInputDigest)
    || typeof value.sessionTemplateDigest !== "string" || !SHA256_PATTERN.test(value.sessionTemplateDigest)
    || typeof value.sessionAgentGenerationDigest !== "string"
    || !SHA256_PATTERN.test(value.sessionAgentGenerationDigest)) return undefined;
  const parsed = value as SessionAgentGenerationInputsV2;
  return sessionAgentGenerationDigestV2(parsed) === parsed.sessionAgentGenerationDigest ? parsed : undefined;
}

export function parseSessionAgentGenerationV2(value: unknown): SessionAgentGenerationV2 | undefined {
  if (!isRecord(value) || !exactKeys(value, [
    "schemaVersion",
    "selectedAgentImageInputDigest",
    "selectedAgentImageId",
    "sessionTemplateDigest",
    "admissionContractEpoch",
    "sessionAgentGenerationDigest",
  ])) return undefined;
  if (typeof value.selectedAgentImageId !== "string" || !SHA256_PATTERN.test(value.selectedAgentImageId)) {
    return undefined;
  }
  const { selectedAgentImageId, ...generationInputs } = value;
  const parsed = parseSessionAgentGenerationInputsV2(generationInputs);
  return parsed ? { ...parsed, selectedAgentImageId } : undefined;
}

export type SessionAgentMaterializationInputsV2 = Omit<
  SessionAgentMaterializationManifestV2,
  "sessionAgentMaterializationDigest"
>;

const SESSION_AGENT_MATERIALIZATION_INPUT_KEYS = [
  "schemaVersion",
  "projectId",
  "composeProject",
  "generation",
  "selectedAgentImageRef",
  "selectedAgentImageId",
  "selectedAgentImageKind",
  "sessionTemplateArtifactSha256",
] as const;

function parseSessionAgentMaterializationInputsV2(
  value: unknown,
): SessionAgentMaterializationInputsV2 | undefined {
  if (!isRecord(value) || !exactKeys(value, SESSION_AGENT_MATERIALIZATION_INPUT_KEYS)) return undefined;
  if (value.schemaVersion !== RUNTIME_STATE_SCHEMA_VERSION_V2
    || typeof value.projectId !== "string"
    || typeof value.composeProject !== "string"
    || !validProjectIdentity(value.projectId, value.composeProject)
    || !validImageRef(value.selectedAgentImageRef)
    || typeof value.sessionTemplateArtifactSha256 !== "string"
    || !SHA256_PATTERN.test(value.sessionTemplateArtifactSha256)) return undefined;
  const generation = parseSessionAgentGenerationV2(value.generation);
  if (!generation
    || typeof value.selectedAgentImageId !== "string"
    || !SHA256_PATTERN.test(value.selectedAgentImageId)
    || generation.selectedAgentImageId !== value.selectedAgentImageId) return undefined;
  if (value.selectedAgentImageKind !== "embedded" && value.selectedAgentImageKind !== "project") {
    return undefined;
  }
  return {
    schemaVersion: RUNTIME_STATE_SCHEMA_VERSION_V2,
    projectId: value.projectId,
    composeProject: value.composeProject,
    generation,
    selectedAgentImageRef: value.selectedAgentImageRef,
    selectedAgentImageId: value.selectedAgentImageId,
    selectedAgentImageKind: value.selectedAgentImageKind,
    sessionTemplateArtifactSha256: value.sessionTemplateArtifactSha256,
  };
}

export function sessionAgentMaterializationDigestV2(input: SessionAgentMaterializationInputsV2): string {
  const parsed = parseSessionAgentMaterializationInputsV2(input);
  if (!parsed) throw new Error("session-agent materialization inputs are invalid");
  return sha256(stableJson(parsed as unknown as StrictJson));
}

export function createSessionAgentMaterializationManifestV2(input: Omit<
  SessionAgentMaterializationInputsV2,
  "schemaVersion"
>): SessionAgentMaterializationManifestV2 {
  const base = parseSessionAgentMaterializationInputsV2({
    schemaVersion: RUNTIME_STATE_SCHEMA_VERSION_V2,
    ...input,
  });
  if (!base) throw new Error("session-agent materialization inputs are invalid");
  return {
    ...base,
    sessionAgentMaterializationDigest: sessionAgentMaterializationDigestV2(base),
  };
}

export function parseSessionAgentMaterializationManifestV2(
  value: unknown,
): SessionAgentMaterializationManifestV2 | undefined {
  if (!isRecord(value) || !exactKeys(value, [
    ...SESSION_AGENT_MATERIALIZATION_INPUT_KEYS,
    "sessionAgentMaterializationDigest",
  ])) return undefined;
  if (typeof value.sessionAgentMaterializationDigest !== "string"
    || !SHA256_PATTERN.test(value.sessionAgentMaterializationDigest)) return undefined;
  const { sessionAgentMaterializationDigest, ...inputs } = value;
  const parsed = parseSessionAgentMaterializationInputsV2(inputs);
  if (!parsed || sessionAgentMaterializationDigestV2(parsed) !== sessionAgentMaterializationDigest) {
    return undefined;
  }
  return { ...parsed, sessionAgentMaterializationDigest };
}

const LEGACY_SESSION_AGENT_MATERIALIZATION_INPUT_KEYS = [
  "schemaVersion",
  "projectId",
  "composeProject",
  "generation",
  "selectedAgentImageRef",
  "selectedAgentImageId",
  "selectedAgentImageKind",
] as const;

/** Bounded parser for retention and explicit migration only. */
export function parseLegacySessionAgentMaterializationManifestV2(
  value: unknown,
): LegacySessionAgentMaterializationManifestV2 | undefined {
  if (!isRecord(value) || !exactKeys(value, [
    ...LEGACY_SESSION_AGENT_MATERIALIZATION_INPUT_KEYS,
    "sessionAgentMaterializationDigest",
  ])) return undefined;
  if (value.schemaVersion !== RUNTIME_STATE_SCHEMA_VERSION_V2
    || typeof value.projectId !== "string"
    || typeof value.composeProject !== "string"
    || !validProjectIdentity(value.projectId, value.composeProject)
    || !validImageRef(value.selectedAgentImageRef)
    || typeof value.selectedAgentImageId !== "string"
    || !SHA256_PATTERN.test(value.selectedAgentImageId)
    || (value.selectedAgentImageKind !== "embedded" && value.selectedAgentImageKind !== "project")
    || typeof value.sessionAgentMaterializationDigest !== "string"
    || !SHA256_PATTERN.test(value.sessionAgentMaterializationDigest)) return undefined;
  const generation = parseSessionAgentGenerationV2(value.generation);
  if (!generation || generation.selectedAgentImageId !== value.selectedAgentImageId) return undefined;
  const selectedAgentImageKind: SessionAgentSelectedImageKindV2 = value.selectedAgentImageKind;
  const legacyInputs = {
    schemaVersion: RUNTIME_STATE_SCHEMA_VERSION_V2,
    projectId: value.projectId,
    composeProject: value.composeProject,
    generation,
    selectedAgentImageRef: value.selectedAgentImageRef,
    selectedAgentImageId: value.selectedAgentImageId,
    selectedAgentImageKind,
  };
  if (sha256(stableJson(legacyInputs as unknown as StrictJson)) !== value.sessionAgentMaterializationDigest) {
    return undefined;
  }
  return { ...legacyInputs, sessionAgentMaterializationDigest: value.sessionAgentMaterializationDigest };
}

export function createSessionAgentDesiredSelectionV2(
  manifest: SessionAgentMaterializationManifestV2,
): SessionAgentDesiredSelectionV2 {
  const parsed = parseSessionAgentMaterializationManifestV2(manifest);
  if (!parsed) throw new Error("session-agent materialization manifest is invalid");
  return {
    schemaVersion: RUNTIME_STATE_SCHEMA_VERSION_V2,
    projectId: parsed.projectId,
    composeProject: parsed.composeProject,
    sessionAgentGenerationDigest: parsed.generation.sessionAgentGenerationDigest,
    sessionAgentMaterializationDigest: parsed.sessionAgentMaterializationDigest,
    selectedAgentImageId: parsed.selectedAgentImageId,
  };
}

export function parseSessionAgentDesiredSelectionV2(value: unknown): SessionAgentDesiredSelectionV2 | undefined {
  if (!isRecord(value) || !exactKeys(value, [
    "schemaVersion",
    "projectId",
    "composeProject",
    "sessionAgentGenerationDigest",
    "sessionAgentMaterializationDigest",
    "selectedAgentImageId",
  ])) return undefined;
  if (value.schemaVersion !== RUNTIME_STATE_SCHEMA_VERSION_V2
    || typeof value.projectId !== "string"
    || typeof value.composeProject !== "string"
    || !validProjectIdentity(value.projectId, value.composeProject)) return undefined;
  for (const key of [
    "sessionAgentGenerationDigest",
    "sessionAgentMaterializationDigest",
    "selectedAgentImageId",
  ] as const) {
    if (typeof value[key] !== "string" || !SHA256_PATTERN.test(value[key])) return undefined;
  }
  return value as SessionAgentDesiredSelectionV2;
}

export function parseRuntimeGenerationTargetV2(value: unknown): RuntimeGenerationTargetV2 | undefined {
  if (!isRecord(value) || !exactKeys(value, ["topology", "controlPlane", "sessionAgent"])) return undefined;
  const topology = parseRuntimeTopologyGenerationV2(value.topology);
  const controlPlane = parseControlPlaneGenerationV2(value.controlPlane);
  const sessionAgent = parseSessionAgentGenerationInputsV2(value.sessionAgent);
  if (!topology || !controlPlane || !sessionAgent) return undefined;
  if (controlPlane.controlPlaneTopologyDigest !== topology.controlPlaneTopologyDigest
    || sessionAgent.sessionTemplateDigest !== topology.sessionTemplateDigest
    || controlPlane.admissionContractEpoch !== sessionAgent.admissionContractEpoch) return undefined;
  return { topology, controlPlane, sessionAgent };
}

export type ControlPlaneMaterializationInputsV2 = Omit<
  ControlPlaneMaterializationManifestV2,
  "controlPlaneMaterializationDigest"
>;

const CONTROL_PLANE_MATERIALIZATION_INPUT_KEYS = [
  "schemaVersion",
  "projectId",
  "composeProject",
  "generation",
  "proxyImageRef",
  "proxyImageId",
  "renderedControlPlaneSha256",
  "sessionAdmissionSource",
] as const;

// Exactly one shape parses: today's key set with the admission source carrying
// its one legal value. A manifest missing the key was written by a pre-cutover
// CLI for a proxy running the retired transaction protocol, and reads as no
// materialization at all, so `runfree up` plans the control-plane change that
// recreates it.
function exactMaterializationKeys(
  value: Record<string, unknown>,
  extra: readonly string[],
): boolean {
  return exactKeys(value, [...CONTROL_PLANE_MATERIALIZATION_INPUT_KEYS, ...extra])
    && value.sessionAdmissionSource === "files";
}

function parseControlPlaneMaterializationInputsV2(
  value: unknown,
): ControlPlaneMaterializationInputsV2 | undefined {
  if (!isRecord(value) || !exactMaterializationKeys(value, [])) return undefined;
  if (value.schemaVersion !== RUNTIME_STATE_SCHEMA_VERSION_V2
    || typeof value.projectId !== "string"
    || typeof value.composeProject !== "string"
    || !validProjectIdentity(value.projectId, value.composeProject)
    || !validImageRef(value.proxyImageRef)
    || typeof value.proxyImageId !== "string"
    || !SHA256_PATTERN.test(value.proxyImageId)
    || typeof value.renderedControlPlaneSha256 !== "string"
    || !SHA256_PATTERN.test(value.renderedControlPlaneSha256)) return undefined;
  const generation = parseControlPlaneGenerationV2(value.generation);
  if (!generation
    || generation.projectId !== value.projectId
    || generation.composeProject !== value.composeProject
    || generation.controlPlaneTopologyDigest !== value.renderedControlPlaneSha256) {
    return undefined;
  }
  return {
    schemaVersion: RUNTIME_STATE_SCHEMA_VERSION_V2,
    projectId: value.projectId,
    composeProject: value.composeProject,
    generation,
    proxyImageRef: value.proxyImageRef,
    proxyImageId: value.proxyImageId,
    renderedControlPlaneSha256: value.renderedControlPlaneSha256,
    sessionAdmissionSource: "files",
  };
}

export function controlPlaneMaterializationDigestV2(input: ControlPlaneMaterializationInputsV2): string {
  const parsed = parseControlPlaneMaterializationInputsV2(input);
  if (!parsed) throw new Error("control-plane materialization inputs are invalid");
  return sha256(stableJson(parsed as unknown as StrictJson));
}

export function createControlPlaneMaterializationManifestV2(input: Omit<
  ControlPlaneMaterializationInputsV2,
  "schemaVersion"
>): ControlPlaneMaterializationManifestV2 {
  const base = parseControlPlaneMaterializationInputsV2({
    schemaVersion: RUNTIME_STATE_SCHEMA_VERSION_V2,
    ...input,
  });
  if (!base) throw new Error("v2 control-plane materialization inputs are invalid");
  return {
    ...base,
    controlPlaneMaterializationDigest: controlPlaneMaterializationDigestV2(base),
  };
}

export function parseControlPlaneMaterializationManifestV2(
  value: unknown,
): ControlPlaneMaterializationManifestV2 | undefined {
  if (!isRecord(value) || !exactMaterializationKeys(value, ["controlPlaneMaterializationDigest"])) {
    return undefined;
  }
  if (typeof value.controlPlaneMaterializationDigest !== "string"
    || !SHA256_PATTERN.test(value.controlPlaneMaterializationDigest)) return undefined;
  const { controlPlaneMaterializationDigest, ...inputs } = value;
  const parsed = parseControlPlaneMaterializationInputsV2(inputs);
  if (!parsed
    || controlPlaneMaterializationDigestV2(parsed) !== controlPlaneMaterializationDigest) return undefined;
  return { ...parsed, controlPlaneMaterializationDigest };
}

export function parseEffectiveControlPlaneSelectionV2(value: unknown): ControlPlaneEffectiveSelectionV2 | undefined {
  if (!isRecord(value) || !exactKeys(value, [
    "schemaVersion",
    "projectId",
    "composeProject",
    "controlPlaneGenerationDigest",
    "controlPlaneMaterializationDigest",
    "proxyContainerId",
    "proxyImageId",
    "sidecarContainerIds",
    "networkIds",
    "securityContractHash",
    "proofSchemaVersion",
    "admissionContractEpoch",
    "denyByDefaultBaseProofHash",
    "selectedAt",
    "runfreeVersion",
  ])) return undefined;
  if (value.schemaVersion !== RUNTIME_STATE_SCHEMA_VERSION_V2
    || typeof value.projectId !== "string"
    || typeof value.composeProject !== "string"
    || !validProjectIdentity(value.projectId, value.composeProject)
    || typeof value.controlPlaneGenerationDigest !== "string"
    || !SHA256_PATTERN.test(value.controlPlaneGenerationDigest)
    || typeof value.controlPlaneMaterializationDigest !== "string"
    || !SHA256_PATTERN.test(value.controlPlaneMaterializationDigest)
    || typeof value.proxyContainerId !== "string" || !DOCKER_OBJECT_ID_PATTERN.test(value.proxyContainerId)
    || typeof value.proxyImageId !== "string" || !SHA256_PATTERN.test(value.proxyImageId)
    || typeof value.securityContractHash !== "string" || !SHA256_PATTERN.test(value.securityContractHash)
    || value.proofSchemaVersion !== CONTROL_PLANE_PROOF_SCHEMA_VERSION
    || !validAdmissionEpoch(value.admissionContractEpoch)
    || typeof value.denyByDefaultBaseProofHash !== "string"
    || !SHA256_PATTERN.test(value.denyByDefaultBaseProofHash)
    || !validIsoTimestamp(value.selectedAt)
    || !validBoundedText(value.runfreeVersion, 128)
    || !Array.isArray(value.sidecarContainerIds)
    || !isRecord(value.networkIds)) return undefined;
  const networkIds = value.networkIds as Record<string, unknown>;
  const networkKeys = ["agentInternal", "proxyEgress"];
  if (!exactKeys(networkIds, networkKeys)
    || !networkKeys.every((key) => {
      const networkId = networkIds[key];
      return typeof networkId === "string" && DOCKER_OBJECT_ID_PATTERN.test(networkId);
    })) return undefined;
  // A relay-era selection carrying a sidecar (or its callback_host network)
  // was minted by an older binary and fails parse closed here.
  const sidecars: ControlPlaneEffectiveSelectionV2["sidecarContainerIds"] = [];
  if (value.sidecarContainerIds.length !== 0) return undefined;
  const allNetworkIds = networkKeys.map((key) => networkIds[key]);
  if (new Set(allNetworkIds).size !== allNetworkIds.length) return undefined;
  return {
    schemaVersion: RUNTIME_STATE_SCHEMA_VERSION_V2,
    projectId: value.projectId,
    composeProject: value.composeProject,
    controlPlaneGenerationDigest: value.controlPlaneGenerationDigest,
    controlPlaneMaterializationDigest: value.controlPlaneMaterializationDigest,
    proxyContainerId: value.proxyContainerId,
    proxyImageId: value.proxyImageId,
    sidecarContainerIds: sidecars,
    networkIds: networkIds as ControlPlaneEffectiveSelectionV2["networkIds"],
    securityContractHash: value.securityContractHash,
    proofSchemaVersion: CONTROL_PLANE_PROOF_SCHEMA_VERSION,
    admissionContractEpoch: value.admissionContractEpoch,
    denyByDefaultBaseProofHash: value.denyByDefaultBaseProofHash,
    selectedAt: value.selectedAt,
    runfreeVersion: value.runfreeVersion,
  };
}

function digestDirectoryName(digest: string, label: string): string {
  return requireDigest(digest, label).replace("sha256:", "sha256-");
}

export function controlPlaneV2Root(stateDir: string): string {
  return path.join(stateDir, "runtime", "v2", "control-plane");
}

export function controlPlaneMaterializationsRootV2(stateDir: string): string {
  return path.join(controlPlaneV2Root(stateDir), "materializations");
}

export function controlPlaneMaterializationRootV2(stateDir: string, materializationDigest: string): string {
  return path.join(
    controlPlaneMaterializationsRootV2(stateDir),
    digestDirectoryName(materializationDigest, "control-plane materialization digest"),
  );
}

export function controlPlaneMaterializationManifestPathV2(
  stateDir: string,
  materializationDigest: string,
): string {
  return path.join(controlPlaneMaterializationRootV2(stateDir, materializationDigest), "materialization.json");
}

export function controlPlaneEffectiveSelectionPathV2(stateDir: string): string {
  return path.join(controlPlaneV2Root(stateDir), "effective.json");
}

export function publishedSessionEligibilityPathV2(stateDir: string): string {
  return path.join(controlPlaneV2Root(stateDir), "published-eligibility.json");
}

export function sessionAgentV2Root(stateDir: string): string {
  return path.join(stateDir, "runtime", "v2", "session-agent");
}

export function sessionAgentMaterializationsRootV2(stateDir: string): string {
  return path.join(sessionAgentV2Root(stateDir), "materializations");
}

export function sessionAgentMaterializationRootV2(stateDir: string, materializationDigest: string): string {
  return path.join(
    sessionAgentMaterializationsRootV2(stateDir),
    digestDirectoryName(materializationDigest, "session-agent materialization digest"),
  );
}

export function sessionAgentMaterializationManifestPathV2(
  stateDir: string,
  materializationDigest: string,
): string {
  return path.join(sessionAgentMaterializationRootV2(stateDir, materializationDigest), "materialization.json");
}

export function sessionAgentTemplateArtifactPathV2(
  stateDir: string,
  materializationDigest: string,
): string {
  return path.join(sessionAgentMaterializationRootV2(stateDir, materializationDigest), "session-template.json");
}

export function sessionAgentDesiredSelectionPathV2(stateDir: string): string {
  return path.join(sessionAgentV2Root(stateDir), "desired.json");
}

function assertSafeDirectory(directory: string): void {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`runtime v2 state path is not a safe directory: ${directory}`);
  }
}

function ensureSafeStateDirectory(stateDir: string, target: string): void {
  const relative = path.relative(stateDir, target);
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("runtime v2 state target escapes the state directory");
  }
  if (!fs.existsSync(stateDir)) fs.mkdirSync(stateDir, { mode: 0o700 });
  assertSafeDirectory(stateDir);
  fsyncDirectory(path.dirname(stateDir));
  let current = stateDir;
  for (const segment of relative.split(path.sep)) {
    const parent = current;
    current = path.join(current, segment);
    try {
      fs.mkdirSync(current, { mode: 0o700 });
    } catch (error) {
      if (!error || typeof error !== "object" || !("code" in error) || error.code !== "EEXIST") throw error;
    }
    assertSafeDirectory(current);
    fsyncDirectory(parent);
  }
}

function safeStateReadPathExists(stateDir: string, filePath: string): boolean {
  const relative = path.relative(stateDir, filePath);
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("runtime v2 state read escapes the state directory");
  }
  let current = stateDir;
  for (const segment of relative.split(path.sep).slice(0, -1)) {
    try {
      assertSafeDirectory(current);
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return false;
      throw error;
    }
    current = path.join(current, segment);
  }
  try {
    assertSafeDirectory(current);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return false;
    throw error;
  }
  return true;
}

function readRegularStateFile(filePath: string): string | undefined {
  return readBoundedRegularFile(filePath, {
    maxBytes: MAX_STATE_FILE_BYTES,
    sizeRecheck: "cap",
    notFileMessage: (path) => `runtime v2 state path is not a bounded normal file: ${path}`,
    changedMessage: (path) => `runtime v2 state path changed during read: ${path}`,
  })?.source;
}

function assertReplaceableStateFile(filePath: string): void {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(filePath);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    throw new Error(`runtime v2 state destination is not a replaceable normal file: ${filePath}`);
  }
}

function writeCompleteTemporaryFile(parent: string, contents: string): string {
  const tmpPath = path.join(parent, `.runfree-${process.pid}-${crypto.randomBytes(8).toString("hex")}.tmp`);
  const descriptor = fs.openSync(
    tmpPath,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  try {
    fs.writeFileSync(descriptor, contents);
    fs.fchmodSync(descriptor, 0o600);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  return tmpPath;
}


function atomicReplaceStateFile(stateDir: string, filePath: string, contents: string): void {
  ensureSafeStateDirectory(stateDir, path.dirname(filePath));
  assertReplaceableStateFile(filePath);
  const tmpPath = writeCompleteTemporaryFile(path.dirname(filePath), contents);
  try {
    assertReplaceableStateFile(filePath);
    fs.renameSync(tmpPath, filePath);
  } finally {
    try {
      fs.unlinkSync(tmpPath);
    } catch {
      // The rename consumes the temporary path. Cleanup is best-effort only on
      // an earlier failure; the randomized name cannot carry authority.
    }
  }
  fsyncDirectory(path.dirname(filePath));
}

function publishImmutableStateFile(
  stateDir: string,
  filePath: string,
  contents: string,
  authorityLabel: string,
): void {
  ensureSafeStateDirectory(stateDir, path.dirname(filePath));
  const existing = readRegularStateFile(filePath);
  if (existing !== undefined) {
    if (existing !== contents) throw new Error(`existing ${authorityLabel} is contradictory`);
    fsyncDirectory(path.dirname(filePath));
    return;
  }
  const tmpPath = writeCompleteTemporaryFile(path.dirname(filePath), contents);
  try {
    try {
      fs.linkSync(tmpPath, filePath);
    } catch (error) {
      if (!error || typeof error !== "object" || !("code" in error) || error.code !== "EEXIST") throw error;
      const raced = readRegularStateFile(filePath);
      if (raced !== contents) throw new Error(`${authorityLabel} publication raced with contradictory state`);
    }
  } finally {
    fs.unlinkSync(tmpPath);
  }
  fsyncDirectory(path.dirname(filePath));
}

export function serializeControlPlaneMaterializationManifestV2(
  manifest: ControlPlaneMaterializationManifestV2,
): string {
  const parsed = parseControlPlaneMaterializationManifestV2(manifest);
  if (!parsed) throw new Error("v2 control-plane materialization manifest is invalid");
  return `${stableJson(parsed as unknown as StrictJson)}\n`;
}

export function publishControlPlaneMaterializationV2(
  stateDir: string,
  manifest: ControlPlaneMaterializationManifestV2,
): void {
  const contents = serializeControlPlaneMaterializationManifestV2(manifest);
  publishImmutableStateFile(
    stateDir,
    controlPlaneMaterializationManifestPathV2(stateDir, manifest.controlPlaneMaterializationDigest),
    contents,
    "v2 control-plane materialization",
  );
}

export function readControlPlaneMaterializationV2(
  stateDir: string,
  materializationDigest: string,
): ControlPlaneMaterializationManifestV2 | undefined {
  const manifestPath = controlPlaneMaterializationManifestPathV2(stateDir, materializationDigest);
  if (!safeStateReadPathExists(stateDir, manifestPath)) return undefined;
  const source = readRegularStateFile(manifestPath);
  if (source === undefined) return undefined;
  let value: unknown;
  try {
    value = JSON.parse(source) as unknown;
  } catch {
    throw new Error("v2 control-plane materialization manifest is malformed");
  }
  const parsed = parseControlPlaneMaterializationManifestV2(value);
  if (!parsed || parsed.controlPlaneMaterializationDigest !== materializationDigest) {
    throw new Error("v2 control-plane materialization manifest is invalid");
  }
  return parsed;
}

export function selectEffectiveControlPlaneV2(
  stateDir: string,
  selection: ControlPlaneEffectiveSelectionV2,
): void {
  const parsed = parseEffectiveControlPlaneSelectionV2(selection);
  if (!parsed) throw new Error("v2 control-plane effective selection is invalid");
  const manifest = readControlPlaneMaterializationV2(stateDir, parsed.controlPlaneMaterializationDigest);
  if (!manifest) throw new Error("cannot select a missing v2 control-plane materialization");
  if (manifest.projectId !== parsed.projectId
    || manifest.composeProject !== parsed.composeProject
    || manifest.generation.controlPlaneGenerationDigest !== parsed.controlPlaneGenerationDigest
    || manifest.proxyImageId !== parsed.proxyImageId
    || manifest.generation.admissionContractEpoch !== parsed.admissionContractEpoch) {
    throw new Error("v2 control-plane effective selection contradicts its materialization");
  }
  atomicReplaceStateFile(
    stateDir,
    controlPlaneEffectiveSelectionPathV2(stateDir),
    `${stableJson(parsed as unknown as StrictJson)}\n`,
  );
}

/**
 * The durable effective selection alone, without the materialization it names.
 *
 * The selection is the host-owned record of which proxy container this project
 * converged against, and a teardown fence needs exactly that. It is read on its
 * own so a manifest this CLI cannot parse — a control plane materialized before
 * the current admission contract — does not take the fence's only durable
 * evidence away with it. Every refusal about the selection's own bytes is kept.
 */
export function readEffectiveControlPlaneSelectionV2(
  stateDir: string,
): ControlPlaneEffectiveSelectionV2 | undefined {
  const selectionPath = controlPlaneEffectiveSelectionPathV2(stateDir);
  if (!safeStateReadPathExists(stateDir, selectionPath)) return undefined;
  const source = readRegularStateFile(selectionPath);
  if (source === undefined) return undefined;
  let value: unknown;
  try {
    value = JSON.parse(source) as unknown;
  } catch {
    throw new Error("v2 control-plane effective selection is malformed");
  }
  const selection = parseEffectiveControlPlaneSelectionV2(value);
  if (!selection) throw new Error("v2 control-plane effective selection is invalid");
  return selection;
}

export function readEffectiveControlPlaneV2(stateDir: string): {
  selection: ControlPlaneEffectiveSelectionV2;
  manifest: ControlPlaneMaterializationManifestV2;
} | undefined {
  const selection = readEffectiveControlPlaneSelectionV2(stateDir);
  if (!selection) return undefined;
  const manifest = readControlPlaneMaterializationV2(stateDir, selection.controlPlaneMaterializationDigest);
  if (!manifest) throw new Error("v2 control-plane effective selection references a missing materialization");
  if (manifest.projectId !== selection.projectId
    || manifest.composeProject !== selection.composeProject
    || manifest.generation.controlPlaneGenerationDigest !== selection.controlPlaneGenerationDigest
    || manifest.proxyImageId !== selection.proxyImageId
    || manifest.generation.admissionContractEpoch !== selection.admissionContractEpoch) {
    throw new Error("v2 control-plane effective selection contradicts its materialization");
  }
  return { selection, manifest };
}

/**
 * Docker's RFC3339 start time, up to nanosecond precision. The zero value
 * (`0001-...`) means the container never started, which cannot have received a
 * publication, so it is refused rather than recorded.
 */
export function validDockerStartedAt(value: unknown): value is string {
  return typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value)
    && !value.startsWith("0001-")
    && Number.isFinite(Date.parse(value));
}

export function parsePublishedSessionEligibilityV2(
  value: unknown,
): PublishedSessionEligibilityV2 | undefined {
  if (!isRecord(value) || !exactKeys(value, [
    "schemaVersion",
    "projectId",
    "composeProject",
    "proxyContainerId",
    "proxyStartedAt",
    "eligibilitySha256",
  ])) return undefined;
  if (value.schemaVersion !== RUNTIME_STATE_SCHEMA_VERSION_V2
    || typeof value.projectId !== "string"
    || typeof value.composeProject !== "string"
    || !validProjectIdentity(value.projectId, value.composeProject)
    || typeof value.proxyContainerId !== "string"
    || !DOCKER_OBJECT_ID_PATTERN.test(value.proxyContainerId)
    || !validDockerStartedAt(value.proxyStartedAt)
    || typeof value.eligibilitySha256 !== "string"
    || !SHA256_PATTERN.test(value.eligibilitySha256)) return undefined;
  return {
    schemaVersion: RUNTIME_STATE_SCHEMA_VERSION_V2,
    projectId: value.projectId,
    composeProject: value.composeProject,
    proxyContainerId: value.proxyContainerId,
    proxyStartedAt: value.proxyStartedAt,
    eligibilitySha256: value.eligibilitySha256,
  };
}

/**
 * Records which eligibility bytes this host last published into which exact
 * proxy container. Written only after the sealed publication succeeded, so a
 * crash in between costs one idempotent republication and never a skipped one.
 */
export function recordPublishedSessionEligibilityV2(
  stateDir: string,
  receipt: PublishedSessionEligibilityV2,
): void {
  const parsed = parsePublishedSessionEligibilityV2(receipt);
  if (!parsed) throw new Error("v2 published session eligibility record is invalid");
  atomicReplaceStateFile(
    stateDir,
    publishedSessionEligibilityPathV2(stateDir),
    `${stableJson(parsed as unknown as StrictJson)}\n`,
  );
}

/**
 * Reads that record. An absent, unreadable, or contradictory file is simply
 * "nothing is known to be published", which republishes.
 */
export function readPublishedSessionEligibilityV2(
  stateDir: string,
): PublishedSessionEligibilityV2 | undefined {
  const receiptPath = publishedSessionEligibilityPathV2(stateDir);
  if (!safeStateReadPathExists(stateDir, receiptPath)) return undefined;
  const source = readRegularStateFile(receiptPath);
  if (source === undefined) return undefined;
  let value: unknown;
  try {
    value = JSON.parse(source) as unknown;
  } catch {
    return undefined;
  }
  return parsePublishedSessionEligibilityV2(value);
}

/**
 * Removes the live-container selection after its runtime has been torn down.
 * Immutable materializations remain available for exact reuse and cleanup.
 */
export function clearEffectiveControlPlaneV2(stateDir: string): void {
  const selectionPath = controlPlaneEffectiveSelectionPathV2(stateDir);
  if (!safeStateReadPathExists(stateDir, selectionPath)) return;
  if (readRegularStateFile(selectionPath) === undefined) {
    fsyncDirectory(path.dirname(selectionPath));
    return;
  }
  try {
    fs.unlinkSync(selectionPath);
  } catch (error) {
    if (!error || typeof error !== "object" || !("code" in error) || error.code !== "ENOENT") throw error;
    fsyncDirectory(path.dirname(selectionPath));
    return;
  }
  fsyncDirectory(path.dirname(selectionPath));
}

export function serializeSessionAgentMaterializationManifestV2(
  manifest: SessionAgentMaterializationManifestV2,
): string {
  const parsed = parseSessionAgentMaterializationManifestV2(manifest);
  if (!parsed) throw new Error("v2 session-agent materialization manifest is invalid");
  return `${stableJson(parsed as unknown as StrictJson)}\n`;
}

export function serializeSessionAgentDesiredSelectionV2(selection: SessionAgentDesiredSelectionV2): string {
  const parsed = parseSessionAgentDesiredSelectionV2(selection);
  if (!parsed) throw new Error("v2 session-agent desired selection is invalid");
  return `${stableJson(parsed as unknown as StrictJson)}\n`;
}

export function publishSessionAgentMaterializationV2(
  stateDir: string,
  manifest: SessionAgentMaterializationManifestV2,
  sessionTemplateArtifact: string,
): void {
  const parsed = parseSessionAgentMaterializationManifestV2(manifest);
  if (!parsed) throw new Error("v2 session-agent materialization manifest is invalid");
  if (Buffer.byteLength(sessionTemplateArtifact, "utf8") > MAX_STATE_FILE_BYTES) {
    throw new Error("v2 session-template artifact is oversized");
  }
  if (sha256(sessionTemplateArtifact) !== parsed.sessionTemplateArtifactSha256) {
    throw new Error("v2 session-template artifact hash contradicts its materialization");
  }
  publishImmutableStateFile(
    stateDir,
    sessionAgentTemplateArtifactPathV2(stateDir, parsed.sessionAgentMaterializationDigest),
    sessionTemplateArtifact,
    "v2 session-template artifact",
  );
  publishImmutableStateFile(
    stateDir,
    sessionAgentMaterializationManifestPathV2(stateDir, parsed.sessionAgentMaterializationDigest),
    serializeSessionAgentMaterializationManifestV2(parsed),
    "v2 session-agent materialization",
  );
}

export function readSessionAgentTemplateArtifactV2(
  stateDir: string,
  manifest: SessionAgentMaterializationManifestV2,
): string {
  const parsed = parseSessionAgentMaterializationManifestV2(manifest);
  if (!parsed) throw new Error("v2 session-agent materialization manifest is invalid");
  const artifactPath = sessionAgentTemplateArtifactPathV2(
    stateDir,
    parsed.sessionAgentMaterializationDigest,
  );
  if (!safeStateReadPathExists(stateDir, artifactPath)) {
    throw new Error("v2 session-agent materialization is missing its session-template artifact");
  }
  const source = readRegularStateFile(artifactPath);
  if (source === undefined) {
    throw new Error("v2 session-agent materialization is missing its session-template artifact");
  }
  if (sha256(source) !== parsed.sessionTemplateArtifactSha256) {
    throw new Error("v2 session-template artifact hash does not match its materialization");
  }
  return source;
}

export function readSessionAgentMaterializationV2(
  stateDir: string,
  materializationDigest: string,
): SessionAgentMaterializationManifestV2 | undefined {
  const manifestPath = sessionAgentMaterializationManifestPathV2(stateDir, materializationDigest);
  if (!safeStateReadPathExists(stateDir, manifestPath)) return undefined;
  const source = readRegularStateFile(manifestPath);
  if (source === undefined) return undefined;
  let value: unknown;
  try {
    value = JSON.parse(source) as unknown;
  } catch {
    throw new Error("v2 session-agent materialization manifest is malformed");
  }
  const manifest = parseSessionAgentMaterializationManifestV2(value);
  if (!manifest || manifest.sessionAgentMaterializationDigest !== materializationDigest) {
    throw new Error("v2 session-agent materialization manifest is invalid");
  }
  return manifest;
}

export function readRetainedSessionAgentMaterializationV2(
  stateDir: string,
  materializationDigest: string,
): RetainedSessionAgentMaterializationManifestV2 | undefined {
  const manifestPath = sessionAgentMaterializationManifestPathV2(stateDir, materializationDigest);
  if (!safeStateReadPathExists(stateDir, manifestPath)) return undefined;
  const source = readRegularStateFile(manifestPath);
  if (source === undefined) return undefined;
  let value: unknown;
  try {
    value = JSON.parse(source) as unknown;
  } catch {
    throw new Error("retained v2 session-agent materialization manifest is malformed");
  }
  const current = parseSessionAgentMaterializationManifestV2(value);
  if (current) {
    if (current.sessionAgentMaterializationDigest !== materializationDigest) {
      throw new Error("retained v2 session-agent materialization manifest is invalid");
    }
    return current;
  }
  const legacy = parseLegacySessionAgentMaterializationManifestV2(value);
  if (!legacy || legacy.sessionAgentMaterializationDigest !== materializationDigest) {
    throw new Error("retained v2 session-agent materialization manifest is invalid");
  }
  return legacy;
}

function desiredSessionAgentSelectionMatchesMaterialization(
  selection: SessionAgentDesiredSelectionV2,
  manifest: SessionAgentMaterializationManifestV2,
): boolean {
  return selection.projectId === manifest.projectId
    && selection.composeProject === manifest.composeProject
    && selection.sessionAgentGenerationDigest === manifest.generation.sessionAgentGenerationDigest
    && selection.sessionAgentMaterializationDigest === manifest.sessionAgentMaterializationDigest
    && selection.selectedAgentImageId === manifest.selectedAgentImageId;
}

export function selectDesiredSessionAgentV2(
  stateDir: string,
  selection: SessionAgentDesiredSelectionV2,
): void {
  const parsed = parseSessionAgentDesiredSelectionV2(selection);
  if (!parsed) throw new Error("v2 session-agent desired selection is invalid");
  const manifest = readSessionAgentMaterializationV2(stateDir, parsed.sessionAgentMaterializationDigest);
  if (!manifest) throw new Error("cannot select a missing v2 session-agent materialization");
  readSessionAgentTemplateArtifactV2(stateDir, manifest);
  if (!desiredSessionAgentSelectionMatchesMaterialization(parsed, manifest)) {
    throw new Error("v2 session-agent desired selection contradicts its materialization");
  }
  atomicReplaceStateFile(
    stateDir,
    sessionAgentDesiredSelectionPathV2(stateDir),
    serializeSessionAgentDesiredSelectionV2(parsed),
  );
}

export function readDesiredSessionAgentV2(stateDir: string): {
  selection: SessionAgentDesiredSelectionV2;
  manifest: SessionAgentMaterializationManifestV2;
} | undefined {
  const selectionPath = sessionAgentDesiredSelectionPathV2(stateDir);
  if (!safeStateReadPathExists(stateDir, selectionPath)) return undefined;
  const source = readRegularStateFile(selectionPath);
  if (source === undefined) return undefined;
  let value: unknown;
  try {
    value = JSON.parse(source) as unknown;
  } catch {
    throw new Error("v2 session-agent desired selection is malformed");
  }
  const selection = parseSessionAgentDesiredSelectionV2(value);
  if (!selection) throw new Error("v2 session-agent desired selection is invalid");
  const manifest = readSessionAgentMaterializationV2(
    stateDir,
    selection.sessionAgentMaterializationDigest,
  );
  if (!manifest) throw new Error("v2 session-agent desired selection references a missing materialization");
  readSessionAgentTemplateArtifactV2(stateDir, manifest);
  if (!desiredSessionAgentSelectionMatchesMaterialization(selection, manifest)) {
    throw new Error("v2 session-agent desired selection contradicts its materialization");
  }
  return { selection, manifest };
}

export function readRetainedDesiredSessionAgentV2(stateDir: string):
  | Readonly<{
      selection: SessionAgentDesiredSelectionV2;
      manifest: SessionAgentMaterializationManifestV2;
      selectable: true;
    }>
  | Readonly<{
      selection: SessionAgentDesiredSelectionV2;
      manifest: LegacySessionAgentMaterializationManifestV2;
      selectable: false;
    }>
  | undefined {
  const selectionPath = sessionAgentDesiredSelectionPathV2(stateDir);
  if (!safeStateReadPathExists(stateDir, selectionPath)) return undefined;
  const source = readRegularStateFile(selectionPath);
  if (source === undefined) return undefined;
  let value: unknown;
  try {
    value = JSON.parse(source) as unknown;
  } catch {
    throw new Error("retained v2 session-agent desired selection is malformed");
  }
  const selection = parseSessionAgentDesiredSelectionV2(value);
  if (!selection) throw new Error("retained v2 session-agent desired selection is invalid");
  const manifest = readRetainedSessionAgentMaterializationV2(
    stateDir,
    selection.sessionAgentMaterializationDigest,
  );
  if (!manifest) {
    throw new Error("retained v2 session-agent desired selection references a missing materialization");
  }
  if (selection.projectId !== manifest.projectId
    || selection.composeProject !== manifest.composeProject
    || selection.sessionAgentGenerationDigest !== manifest.generation.sessionAgentGenerationDigest
    || selection.sessionAgentMaterializationDigest !== manifest.sessionAgentMaterializationDigest
    || selection.selectedAgentImageId !== manifest.selectedAgentImageId) {
    throw new Error("retained v2 session-agent desired selection contradicts its materialization");
  }
  const current = parseSessionAgentMaterializationManifestV2(manifest);
  return current
    ? { selection, manifest: current, selectable: true }
    : { selection, manifest: manifest as LegacySessionAgentMaterializationManifestV2, selectable: false };
}

