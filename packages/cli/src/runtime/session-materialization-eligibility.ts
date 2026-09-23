import { isDeepStrictEqual } from "node:util";

import {
  parseEffectiveControlPlaneSelectionV2,
  parseLegacySessionAgentMaterializationManifestV2,
  parseSessionAgentMaterializationManifestV2,
  readRetainedSessionAgentMaterializationV2,
  type ControlPlaneEffectiveSelectionV2,
  type RetainedSessionAgentMaterializationManifestV2,
  type SessionAgentMaterializationManifestV2,
} from "./component-state-v2.ts";
import {
  assertSessionContainerRecordProject,
  parseSessionContainerRecordV2,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";

// Matches the direct-session container cap. Keep the eligibility set at or
// below the number of containers Runfree can own concurrently.
const SESSION_MATERIALIZATION_ELIGIBILITY_MAX_RECORDS = 64;

function manifestMatchesRecord(
  manifest: RetainedSessionAgentMaterializationManifestV2,
  record: SessionContainerRecordV2,
): boolean {
  return manifest.sessionAgentMaterializationDigest === record.sessionAgentMaterializationDigest
    && manifest.selectedAgentImageRef === record.selectedAgentImageRef
    && manifest.selectedAgentImageId === record.selectedAgentImageId
    && manifest.generation.selectedAgentImageInputDigest === record.selectedAgentImageInputDigest
    && manifest.generation.sessionTemplateDigest === record.sessionTemplateDigest
    && manifest.generation.sessionAgentGenerationDigest === record.sessionAgentGenerationDigest
    && manifest.generation.admissionContractEpoch === record.admissionContractEpoch;
}

function addManifest(
  allowed: Map<string, RetainedSessionAgentMaterializationManifestV2>,
  manifest: RetainedSessionAgentMaterializationManifestV2,
  expectedProject: SessionContainerProjectIdentity,
  controlPlane: ControlPlaneEffectiveSelectionV2,
): void {
  const parsed = parseSessionAgentMaterializationManifestV2(manifest)
    ?? parseLegacySessionAgentMaterializationManifestV2(manifest);
  if (!parsed) throw new Error("session-agent eligibility contains an invalid materialization");
  if (parsed.projectId !== expectedProject.projectId
    || parsed.composeProject !== expectedProject.composeProject) {
    throw new Error("session-agent eligibility contains a materialization for another project");
  }
  if (parsed.generation.admissionContractEpoch !== controlPlane.admissionContractEpoch) {
    throw new Error("session-agent eligibility contains an incompatible admission epoch");
  }
  const existing = allowed.get(parsed.sessionAgentMaterializationDigest);
  if (existing && !isDeepStrictEqual(existing, parsed)) {
    throw new Error("session-agent eligibility contains a contradictory materialization claim");
  }
  allowed.set(parsed.sessionAgentMaterializationDigest, parsed);
}

/** Builds the complete bounded materialization set for one registry publish. */
export function classifySessionAgentMaterializationEligibilityV2(input: Readonly<{
  stateDir: string;
  expectedProject: SessionContainerProjectIdentity;
  effectiveControlPlane: ControlPlaneEffectiveSelectionV2;
  records: readonly SessionContainerRecordV2[];
  candidate?: SessionAgentMaterializationManifestV2;
  transactionCandidates?: readonly SessionAgentMaterializationManifestV2[];
}>): Readonly<{
  allowed: readonly RetainedSessionAgentMaterializationManifestV2[];
  invalidRecords: readonly SessionContainerRecordV2[];
}> {
  const controlPlane = parseEffectiveControlPlaneSelectionV2(input.effectiveControlPlane);
  if (!controlPlane) throw new Error("session-agent eligibility effective control plane is invalid");
  if (controlPlane.projectId !== input.expectedProject.projectId
    || controlPlane.composeProject !== input.expectedProject.composeProject) {
    throw new Error("session-agent eligibility effective control plane belongs to another project");
  }
  if (input.records.length > SESSION_MATERIALIZATION_ELIGIBILITY_MAX_RECORDS) {
    throw new Error("session-agent eligibility exceeds its bounded record limit");
  }

  const claims = [
    ["session id", new Set<string>()],
    ["session incarnation", new Set<string>()],
    ["session principal", new Set<string>()],
    ["container id", new Set<string>()],
    ["source IP", new Set<string>()],
  ] as const;
  const allowed = new Map<string, RetainedSessionAgentMaterializationManifestV2>();
  const invalidRecords: SessionContainerRecordV2[] = [];
  for (const candidate of input.records) {
    const record = parseSessionContainerRecordV2(candidate);
    if (!record) throw new Error("session-agent eligibility contains an invalid lifecycle record");
    assertSessionContainerRecordProject(record, input.expectedProject);
    const values = [record.sessionId, record.sessionIncarnation, record.sessionPrincipal, record.containerId, record.sourceIp];
    for (let index = 0; index < claims.length; index += 1) {
      const value = values[index];
      if (!value) continue;
      const [label, seen] = claims[index];
      if (seen.has(value)) throw new Error(`session-agent eligibility duplicates a ${label} claim`);
      seen.add(value);
    }
    if (record.controlPlaneGenerationDigest !== controlPlane.controlPlaneGenerationDigest
      || record.admissionContractEpoch !== controlPlane.admissionContractEpoch) {
      invalidRecords.push(record);
      continue;
    }
    let manifest: RetainedSessionAgentMaterializationManifestV2 | undefined;
    try {
      manifest = readRetainedSessionAgentMaterializationV2(
        input.stateDir,
        record.sessionAgentMaterializationDigest,
      );
    } catch {
      invalidRecords.push(record);
      continue;
    }
    if (!manifest || !manifestMatchesRecord(manifest, record)) {
      invalidRecords.push(record);
      continue;
    }
    addManifest(allowed, manifest, input.expectedProject, controlPlane);
  }

  if (input.candidate) addManifest(allowed, input.candidate, input.expectedProject, controlPlane);
  for (const candidate of input.transactionCandidates ?? []) {
    addManifest(allowed, candidate, input.expectedProject, controlPlane);
  }
  if (allowed.size === 0 || allowed.size > SESSION_MATERIALIZATION_ELIGIBILITY_MAX_RECORDS) {
    throw new Error("session-agent eligibility requires a bounded non-empty materialization set");
  }
  return Object.freeze({
    allowed: Object.freeze([...allowed.values()].sort((left, right) => (
      left.sessionAgentMaterializationDigest.localeCompare(right.sessionAgentMaterializationDigest)
    ))),
    invalidRecords: Object.freeze(invalidRecords),
  });
}

/** Strict wrapper for callers that cannot publish a revocation transition. */
export function compileAllowedSessionAgentMaterializationsV2(
  input: Parameters<typeof classifySessionAgentMaterializationEligibilityV2>[0],
): readonly RetainedSessionAgentMaterializationManifestV2[] {
  const classified = classifySessionAgentMaterializationEligibilityV2(input);
  if (classified.invalidRecords.length > 0) {
    throw new Error(`session ${classified.invalidRecords[0].sessionId} has no exact retained agent materialization`);
  }
  return classified.allowed;
}
