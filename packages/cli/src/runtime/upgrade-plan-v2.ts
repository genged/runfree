import {
  parseControlPlaneMaterializationManifestV2,
  parseEffectiveControlPlaneSelectionV2,
  parseRuntimeGenerationTargetV2,
  parseSessionAgentDesiredSelectionV2,
  parseSessionAgentMaterializationManifestV2,
  type ControlPlaneEffectiveSelectionV2,
  type ControlPlaneMaterializationManifestV2,
  type RuntimeGenerationTargetV2,
  type SessionAgentDesiredSelectionV2,
  type SessionAgentMaterializationManifestV2,
} from "./component-state-v2.ts";
import {
  parseSessionContainerRecordV2,
  SESSION_CONTAINER_RECORD_SCAN_LIMIT,
  type SessionContainerRecordV2,
} from "./session-containers.ts";

export type RuntimeUpgradeActionV2 =
  | { kind: "none" }
  | { kind: "select-session-agent" }
  | { kind: "restart-compatible-proxy" }
  | { kind: "block-incompatible"; reason: "admission-epoch" | "control-plane-topology" }
  | { kind: "refuse-invalid"; reason: string };

export type RuntimeUpgradeLiveProxyEvidenceV2 = Readonly<{
  projectId: string;
  composeProject: string;
  containerId: string;
  imageId: string;
}>;

export type RuntimeUpgradePendingTransactionV2 = Readonly<{
  projectId: string;
  composeProject: string;
  kind: "session-admission" | "control-plane-rebind";
}>;

export type RuntimeUpgradePlanInputV2 = Readonly<{
  desired: RuntimeGenerationTargetV2;
  desiredSessionAgent?: Readonly<{
    selection: SessionAgentDesiredSelectionV2;
    manifest: SessionAgentMaterializationManifestV2;
  }>;
  effectiveControlPlane?: Readonly<{
    selection: ControlPlaneEffectiveSelectionV2;
    manifest: ControlPlaneMaterializationManifestV2;
  }>;
  liveProxies?: readonly RuntimeUpgradeLiveProxyEvidenceV2[];
  lifecycleRecords: readonly SessionContainerRecordV2[];
  pendingTransaction?: RuntimeUpgradePendingTransactionV2;
}>;

function refuse(reason: string): RuntimeUpgradeActionV2 {
  return { kind: "refuse-invalid", reason };
}

function exactProject(
  value: Readonly<{ projectId: string; composeProject: string }>,
  desired: RuntimeGenerationTargetV2,
): boolean {
  return value.projectId === desired.controlPlane.projectId
    && value.composeProject === desired.controlPlane.composeProject;
}

function validateRecords(
  records: readonly SessionContainerRecordV2[],
  desired: RuntimeGenerationTargetV2,
): string | undefined {
  if (!Array.isArray(records) || records.length > SESSION_CONTAINER_RECORD_SCAN_LIMIT) {
    return "session lifecycle registry exceeds its bounded record limit";
  }
  const claims = {
    sessionId: new Set<string>(),
    sessionIncarnation: new Set<string>(),
    sessionPrincipal: new Set<string>(),
    containerId: new Set<string>(),
    sourceIp: new Set<string>(),
  };
  for (const candidate of records) {
    const record = parseSessionContainerRecordV2(candidate);
    if (!record) return "session lifecycle registry contains an invalid record";
    if (!exactProject(record, desired)) {
      return "session lifecycle registry contains a record for another project";
    }
    for (const [claim, values] of Object.entries(claims)) {
      const value = record[claim as keyof typeof claims] as string | undefined;
      if (!value) continue;
      if (values.has(value)) return `session lifecycle registry duplicates ${claim}`;
      values.add(value);
    }
  }
  return undefined;
}

/**
 * Classifies one exact schema-v2 desired/effective snapshot. The planner is
 * pure: materialization, selection, rebind, migration, and refusal stay in the
 * lifecycle coordinator that consumes the returned action.
 */
export function planRuntimeUpgradeV2(input: RuntimeUpgradePlanInputV2): RuntimeUpgradeActionV2 {
  const desired = parseRuntimeGenerationTargetV2(input.desired);
  if (!desired) return refuse("desired schema-v2 generation target is invalid");
  const recordIssue = validateRecords(input.lifecycleRecords, desired);
  if (recordIssue) return refuse(recordIssue);

  if (input.pendingTransaction) {
    if (!exactProject(input.pendingTransaction, desired)) {
      return refuse("pending lifecycle transaction belongs to another project");
    }
    return input.pendingTransaction.kind === "control-plane-rebind"
      ? { kind: "restart-compatible-proxy" }
      : refuse(`pending ${input.pendingTransaction.kind} transaction requires recovery`);
  }

  const desiredSession = input.desiredSessionAgent;
  if (desiredSession) {
    const selection = parseSessionAgentDesiredSelectionV2(desiredSession.selection);
    const manifest = parseSessionAgentMaterializationManifestV2(desiredSession.manifest);
    if (!selection || !manifest) return refuse("desired session-agent state is invalid");
    if (!exactProject(selection, desired) || !exactProject(manifest, desired)) {
      return refuse("desired session-agent state belongs to another project");
    }
    if (selection.sessionAgentGenerationDigest !== manifest.generation.sessionAgentGenerationDigest
      || selection.sessionAgentMaterializationDigest !== manifest.sessionAgentMaterializationDigest
      || selection.selectedAgentImageId !== manifest.selectedAgentImageId) {
      return refuse("desired session-agent selection contradicts its materialization");
    }
  }

  const liveProxies = input.liveProxies ?? [];
  if (liveProxies.length > 1) return refuse("live proxy evidence is duplicated");
  const liveProxy = liveProxies[0];
  if (liveProxy && !exactProject(liveProxy, desired)) {
    return refuse("live proxy belongs to another project");
  }

  const effective = input.effectiveControlPlane;
  if (!effective) {
    if (input.lifecycleRecords.length > 0) {
      return refuse("session lifecycle records exist without an effective control-plane selection");
    }
    if (liveProxy) return refuse("live proxy exists without an effective control-plane selection");
    return { kind: "none" };
  }

  const selection = parseEffectiveControlPlaneSelectionV2(effective.selection);
  const manifest = parseControlPlaneMaterializationManifestV2(effective.manifest);
  if (!selection || !manifest) return refuse("effective control-plane state is invalid");
  if (!exactProject(selection, desired) || !exactProject(manifest, desired)) {
    return refuse("effective control-plane state belongs to another project");
  }
  if (selection.controlPlaneGenerationDigest !== manifest.generation.controlPlaneGenerationDigest
    || selection.controlPlaneMaterializationDigest !== manifest.controlPlaneMaterializationDigest
    || selection.proxyImageId !== manifest.proxyImageId
    || selection.admissionContractEpoch !== manifest.generation.admissionContractEpoch) {
    return refuse("effective control-plane selection contradicts its materialization");
  }

  if (liveProxy) {
    if (liveProxy.containerId !== selection.proxyContainerId
      || liveProxy.imageId !== selection.proxyImageId) {
      return refuse("live proxy contradicts the effective control-plane selection");
    }
  }

  const current = manifest.generation;
  const target = desired.controlPlane;
  if (current.admissionContractEpoch !== target.admissionContractEpoch) {
    return input.lifecycleRecords.length > 0
      ? { kind: "block-incompatible", reason: "admission-epoch" }
      : { kind: "restart-compatible-proxy" };
  }
  if (current.controlPlaneTopologyDigest !== target.controlPlaneTopologyDigest) {
    return input.lifecycleRecords.length > 0
      ? { kind: "block-incompatible", reason: "control-plane-topology" }
      : { kind: "restart-compatible-proxy" };
  }
  if (current.controlPlaneGenerationDigest !== target.controlPlaneGenerationDigest || !liveProxy) {
    return { kind: "restart-compatible-proxy" };
  }

  if (!desiredSession
    || desiredSession.manifest.generation.sessionAgentGenerationDigest
      !== desired.sessionAgent.sessionAgentGenerationDigest) {
    return { kind: "select-session-agent" };
  }
  return { kind: "none" };
}
