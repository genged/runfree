import { parseStrictJson } from "../control/strict-json.ts";
import {
  assertSessionContainerCreatePlan,
  type SessionContainerCreatePlan,
} from "./session-container-template.ts";
import { assertSessionContainerRecordProject } from "./session-containers.ts";
import { isRecord } from "../strict-primitives.ts";

export const SESSION_NAMED_VOLUME_INSPECT_MAX_BYTES = 256 * 1024;
export const SESSION_NAMED_VOLUME_MAX_COUNT = 64;

const COMPOSE_RESOURCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u;

type DockerVolumeInspectRecord = {
  Name?: unknown;
  Driver?: unknown;
  Scope?: unknown;
  Mountpoint?: unknown;
  Labels?: unknown;
  Options?: unknown;
};

export type SessionNamedVolumeExpectation = Readonly<{
  name: string;
  logicalName: string;
  targets: readonly string[];
}>;

export type SessionNamedVolumeInspectRequest = Readonly<{
  executable: "docker";
  args: readonly string[];
  exactNames: readonly string[];
}>;

declare const validatedSessionNamedVolumeProofBrand: unique symbol;

export type SessionNamedVolumeProof = Readonly<{
  readonly [validatedSessionNamedVolumeProofBrand]: true;
  composeProject: string;
  sessionId: string;
  sessionIncarnation: string;
  volumes: readonly Readonly<{
    name: string;
    logicalName: string;
    mountpoint: string;
    targets: readonly string[];
  }>[];
}>;

const validatedProofs = new WeakSet<object>();


function emptyRecordOrNull(value: unknown): boolean {
  return value === null || (isRecord(value) && Object.keys(value).length === 0);
}

function validComposeResource(value: string): boolean {
  return value.length <= 255
    && COMPOSE_RESOURCE_PATTERN.test(value)
    && !CONTROL_CHARACTER_PATTERN.test(value);
}

function requireComposeProject(plan: SessionContainerCreatePlan): string {
  assertSessionContainerCreatePlan(plan);
  assertSessionContainerRecordProject(plan.record, plan.expectedProject);
  const composeProject = plan.expectedProject.composeProject;
  if (!validComposeResource(composeProject)
    || composeProject !== `runfree-${plan.expectedProject.projectId}`) {
    throw new Error("session named-volume proof has invalid Compose project identity");
  }
  return composeProject;
}

function logicalVolumeName(physicalName: string, composeProject: string): string {
  if (!validComposeResource(physicalName)) {
    throw new Error("session named-volume mount has an invalid physical volume name");
  }
  const prefix = `${composeProject}_`;
  if (!physicalName.startsWith(prefix)) {
    throw new Error(`session named-volume mount is not owned by Compose project ${composeProject}`);
  }
  const logicalName = physicalName.slice(prefix.length);
  if (!validComposeResource(logicalName)) {
    throw new Error("session named-volume mount has an invalid logical volume name");
  }
  return logicalName;
}

export function sessionNamedVolumeExpectations(
  plan: SessionContainerCreatePlan,
): readonly SessionNamedVolumeExpectation[] {
  const composeProject = requireComposeProject(plan);
  const byName = new Map<string, { logicalName: string; targets: string[] }>();
  for (const mount of plan.mounts) {
    if (mount.type !== "volume") continue;
    const logicalName = logicalVolumeName(mount.source, composeProject);
    const current = byName.get(mount.source);
    if (current && current.logicalName !== logicalName) {
      throw new Error("session named-volume mount identity is ambiguous");
    }
    const targets = current?.targets ?? [];
    if (targets.includes(mount.target)) {
      throw new Error(`session named-volume mount target is duplicated: ${mount.target}`);
    }
    targets.push(mount.target);
    byName.set(mount.source, { logicalName, targets });
  }
  if (byName.size === 0) {
    throw new Error("session container plan has no named-volume mounts to prove");
  }
  if (byName.size > SESSION_NAMED_VOLUME_MAX_COUNT) {
    throw new Error(`session container plan exceeds ${SESSION_NAMED_VOLUME_MAX_COUNT} named volumes`);
  }
  return Object.freeze([...byName.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, value]) => Object.freeze({
      name,
      logicalName: value.logicalName,
      targets: Object.freeze([...value.targets].sort()),
    })));
}

export function sessionNamedVolumeInspectRequest(
  plan: SessionContainerCreatePlan,
): SessionNamedVolumeInspectRequest {
  const exactNames = Object.freeze(sessionNamedVolumeExpectations(plan).map((volume) => volume.name));
  return Object.freeze({
    executable: "docker",
    args: Object.freeze(["volume", "inspect", ...exactNames]),
    exactNames,
  });
}

function parseInspection(source: string): unknown[] {
  if (Buffer.byteLength(source) > SESSION_NAMED_VOLUME_INSPECT_MAX_BYTES) {
    throw new Error("Docker named-volume inspection exceeds the size limit");
  }
  let parsed: unknown;
  try {
    parsed = parseStrictJson(source);
  } catch {
    throw new Error("Docker returned malformed named-volume inspection JSON");
  }
  if (!Array.isArray(parsed)) {
    throw new Error("Docker named-volume inspection must be an array");
  }
  return parsed;
}

function requireMountpoint(value: unknown): string {
  if (typeof value !== "string"
    || value.length === 0
    || value.length > 4096
    || !value.startsWith("/")
    || CONTROL_CHARACTER_PATTERN.test(value)) {
    throw new Error("Docker named-volume mountpoint is invalid");
  }
  return value;
}

function validateInspectionRecord(
  value: unknown,
  expected: SessionNamedVolumeExpectation,
  composeProject: string,
): SessionNamedVolumeProof["volumes"][number] {
  if (!isRecord(value)) throw new Error("Docker named-volume inspection record is malformed");
  const record = value as DockerVolumeInspectRecord;
  if (record.Name !== expected.name) {
    throw new Error(`Docker inspected a different named volume: ${String(record.Name ?? "<missing>")}`);
  }
  if (record.Driver !== "local") {
    throw new Error(`session named volume ${expected.name} does not use the local driver`);
  }
  if (record.Scope !== "local") {
    throw new Error(`session named volume ${expected.name} does not have local scope`);
  }
  if (!emptyRecordOrNull(record.Options)) {
    throw new Error(`session named volume ${expected.name} has driver options`);
  }
  if (!isRecord(record.Labels)
    || record.Labels["com.docker.compose.project"] !== composeProject
    || record.Labels["com.docker.compose.volume"] !== expected.logicalName) {
    throw new Error(`session named volume ${expected.name} has invalid Compose ownership labels`);
  }
  return Object.freeze({
    name: expected.name,
    logicalName: expected.logicalName,
    mountpoint: requireMountpoint(record.Mountpoint),
    targets: expected.targets,
  });
}

export function validateSessionNamedVolumeInspect(
  source: string,
  plan: SessionContainerCreatePlan,
): SessionNamedVolumeProof {
  const composeProject = requireComposeProject(plan);
  const expected = sessionNamedVolumeExpectations(plan);
  const byName = new Map(expected.map((volume) => [volume.name, volume]));
  const parsed = parseInspection(source);
  if (parsed.length !== expected.length) {
    throw new Error("Docker named-volume inspection does not contain the exact expected volume set");
  }

  const proof = new Map<string, SessionNamedVolumeProof["volumes"][number]>();
  const mountpoints = new Set<string>();
  for (const value of parsed) {
    if (!isRecord(value) || typeof value.Name !== "string") {
      throw new Error("Docker named-volume inspection record is malformed");
    }
    const volume = byName.get(value.Name);
    if (!volume) throw new Error(`Docker inspected an unexpected named volume: ${value.Name}`);
    if (proof.has(value.Name)) throw new Error(`Docker inspected named volume more than once: ${value.Name}`);
    const inspected = validateInspectionRecord(value, volume, composeProject);
    if (mountpoints.has(inspected.mountpoint)) {
      throw new Error(`Docker named volumes share one physical mountpoint: ${inspected.mountpoint}`);
    }
    mountpoints.add(inspected.mountpoint);
    proof.set(value.Name, inspected);
  }

  const volumes = expected.map((volume) => {
    const inspected = proof.get(volume.name);
    if (!inspected) throw new Error(`Docker did not inspect expected named volume: ${volume.name}`);
    return inspected;
  });
  const result = Object.freeze({
    composeProject,
    sessionId: plan.record.sessionId,
    sessionIncarnation: plan.record.sessionIncarnation,
    volumes: Object.freeze(volumes),
  }) as SessionNamedVolumeProof;
  validatedProofs.add(result);
  return result;
}

/**
 * Validate a single Compose-managed local volume immediately after it is created
 * by `docker volume create`. Docker reuses an existing volume on the same
 * (local) driver and does not apply the requested labels, so a pre-placed
 * local-driver bind mount — or any wrong-shaped volume — would otherwise be
 * trusted by the dependency-volume ownership chown that runs before the
 * per-session named-volume proof. Enforces the same driver/scope/options/label
 * invariants as that proof for the one expected volume.
 */
export function assertComposeManagedLocalVolume(
  source: string,
  expected: Readonly<{ name: string; logicalName: string; composeProject: string }>,
): void {
  const parsed = parseInspection(source);
  if (parsed.length !== 1) {
    throw new Error(`Docker inspection for ${expected.name} did not return exactly one volume`);
  }
  validateInspectionRecord(
    parsed[0],
    { name: expected.name, logicalName: expected.logicalName, targets: [] },
    expected.composeProject,
  );
}

export function assertSessionNamedVolumeProof(
  plan: SessionContainerCreatePlan,
  proof: unknown,
): asserts proof is SessionNamedVolumeProof {
  if (!isRecord(proof) || !validatedProofs.has(proof)) {
    throw new Error("session named-volume proof was not minted by Docker inspection validation");
  }
  const expected = sessionNamedVolumeExpectations(plan);
  const candidate = proof as SessionNamedVolumeProof;
  if (candidate.composeProject !== plan.expectedProject.composeProject
    || candidate.sessionId !== plan.record.sessionId
    || candidate.sessionIncarnation !== plan.record.sessionIncarnation
    || candidate.volumes.length !== expected.length) {
    throw new Error("session named-volume proof belongs to a different session plan");
  }
  for (let index = 0; index < expected.length; index += 1) {
    const left = candidate.volumes[index];
    const right = expected[index];
    if (!left
      || !right
      || left.name !== right.name
      || left.logicalName !== right.logicalName
      || left.targets.length !== right.targets.length
      || left.targets.some((target, targetIndex) => target !== right.targets[targetIndex])) {
      throw new Error("session named-volume proof belongs to a different session plan");
    }
  }
}
