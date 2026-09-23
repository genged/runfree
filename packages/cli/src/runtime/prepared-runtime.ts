import {
  readDesiredSessionAgentV2,
  readEffectiveControlPlaneV2,
  readSessionAgentTemplateArtifactV2,
  type ControlPlaneEffectiveSelectionV2,
  type ControlPlaneMaterializationManifestV2,
  type SessionAgentDesiredSelectionV2,
  type SessionAgentMaterializationManifestV2,
} from "./component-state-v2.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import { runtimeContextFromActivePlan } from "./plan.ts";
import { createRuntimeSecurityContract } from "./security-contract.ts";
import {
  parseSessionTemplateArtifactV1,
  type SessionTemplateArtifactV1,
} from "./session-template-artifact.ts";
import type { SessionContainerTemplate } from "./session-container-template.ts";
import { runtimeValidationMarkerStatus, type RuntimeValidationProof } from "./state.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";
import { stableJson } from "../strict-primitives.ts";

declare const preparedRuntimeBrand: unique symbol;

export type PreparedRuntime = Readonly<{
  readonly [preparedRuntimeBrand]: true;
  version: 1;
}>;

type PreparedRuntimeSnapshot = Readonly<{
  effective: Readonly<{
    selection: ControlPlaneEffectiveSelectionV2;
    manifest: ControlPlaneMaterializationManifestV2;
  }>;
  desired: Readonly<{
    selection: SessionAgentDesiredSelectionV2;
    manifest: SessionAgentMaterializationManifestV2;
  }>;
}>;

type PreparedRuntimeBinding = Readonly<{
  plan: ActiveRuntimePlan;
  context: RuntimeContext;
  snapshot: PreparedRuntimeSnapshot;
  snapshotIdentity: string;
  templateArtifactSource: string;
  templateArtifact: SessionTemplateArtifactV1;
  template: SessionContainerTemplate;
  validationProof: RuntimeValidationProof;
  securityContractHash: string;
}>;

export type ConsumedPreparedRuntime = PreparedRuntimeBinding;

const bindings = new WeakMap<object, PreparedRuntimeBinding>();
const consumed = new WeakSet<object>();


function readSnapshot(plan: ActiveRuntimePlan): PreparedRuntimeSnapshot {
  const stateDir = plan.paths.stateDir;
  const effective = readEffectiveControlPlaneV2(stateDir);
  if (!effective) throw new Error("prepared runtime requires a durable effective control plane");
  const desired = readDesiredSessionAgentV2(stateDir);
  if (!desired) throw new Error("prepared runtime requires a durable desired session agent");
  for (const value of [effective.selection, effective.manifest, desired.selection, desired.manifest]) {
    if (value.projectId !== plan.projectId || value.composeProject !== plan.composeProjectName) {
      throw new Error("prepared runtime durable state belongs to a different project");
    }
  }
  if (effective.manifest.generation.controlPlaneGenerationDigest
      !== plan.generationV2.controlPlane.controlPlaneGenerationDigest
    || desired.manifest.generation.sessionAgentGenerationDigest
      !== plan.generationV2.sessionAgent.sessionAgentGenerationDigest) {
    throw new Error("prepared runtime plan does not match its durable generation selections");
  }
  return Object.freeze({ effective, desired });
}

function readTemplateArtifact(
  plan: ActiveRuntimePlan,
  snapshot: PreparedRuntimeSnapshot,
): Readonly<{ source: string; artifact: SessionTemplateArtifactV1 }> {
  const source = readSessionAgentTemplateArtifactV2(plan.paths.stateDir, snapshot.desired.manifest);
  const artifact = parseSessionTemplateArtifactV1(source, {
    projectId: plan.projectId,
    composeProject: plan.composeProjectName,
    sessionTemplateDigest: snapshot.desired.manifest.generation.sessionTemplateDigest,
    artifactSha256: snapshot.desired.manifest.sessionTemplateArtifactSha256,
  });
  return { source, artifact };
}

function assertValidationProof(
  plan: ActiveRuntimePlan,
  snapshot: PreparedRuntimeSnapshot,
  proof: RuntimeValidationProof,
  contractHash: string,
): void {
  if (proof.projectId !== plan.projectId
    || proof.proxyId !== snapshot.effective.selection.proxyContainerId
    || proof.contractHash !== contractHash) {
    throw new Error("prepared runtime validation proof contradicts the durable control plane");
  }
}

/** The startup finalizer is the only production caller of this mint. */
export function mintPreparedRuntime(input: Readonly<{
  plan: ActiveRuntimePlan;
  validationProof: RuntimeValidationProof;
}>): PreparedRuntime {
  const snapshot = readSnapshot(input.plan);
  const template = readTemplateArtifact(input.plan, snapshot);
  const context = runtimeContextFromActivePlan(input.plan, {
    dependencyOverlayPlanChanged: false,
    gitLayoutPlanChanged: false,
    validatedRuntime: input.validationProof,
  });
  const securityContractHash = createRuntimeSecurityContract(input.plan).contractHash;
  if (!securityContractHash) {
    throw new Error("prepared runtime security contract has no exact hash");
  }
  assertValidationProof(input.plan, snapshot, input.validationProof, securityContractHash);
  const prepared = Object.freeze({ version: 1 as const }) as PreparedRuntime;
  bindings.set(prepared, Object.freeze({
    plan: input.plan,
    context: Object.freeze(context),
    snapshot,
    snapshotIdentity: stableJson(snapshot),
    templateArtifactSource: template.source,
    templateArtifact: template.artifact,
    template: template.artifact.template,
    validationProof: input.validationProof,
    securityContractHash,
  }));
  return prepared;
}

function preparedBinding(prepared: PreparedRuntime): PreparedRuntimeBinding {
  if (prepared === null || typeof prepared !== "object") {
    throw new Error("prepared runtime authority is invalid");
  }
  const binding = bindings.get(prepared);
  if (!binding || prepared.version !== 1) {
    throw new Error("prepared runtime authority was not minted by the startup finalizer");
  }
  return binding;
}

export function preparedRuntimeContext(prepared: PreparedRuntime): RuntimeContext {
  return preparedBinding(prepared).context;
}

/** The proxy container the prepared runtime was selected against. Diagnostic use only; grants no authority. */
export function preparedRuntimeProxyId(prepared: PreparedRuntime): string {
  return preparedBinding(prepared).snapshot.effective.selection.proxyContainerId;
}

export class StalePreparedRuntimeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StalePreparedRuntimeError";
  }
}

function validationMarkerIssueIsContradictory(issue: string): boolean {
  return issue.includes("malformed")
    || issue.includes("belongs to another project")
    || issue.includes("shared agent container is running")
    || issue.includes("sidecar is running but not required");
}

export function consumePreparedRuntime(input: Readonly<{
  preparedRuntime: PreparedRuntime;
  lifecycleLock: ProjectLifecycleLock;
  io: RuntimeIO;
}>): ConsumedPreparedRuntime {
  const binding = preparedBinding(input.preparedRuntime);
  if (consumed.has(input.preparedRuntime)) {
    throw new Error("prepared runtime authority was already consumed");
  }
  input.lifecycleLock.assertHeld();
  const currentSnapshot = readSnapshot(binding.plan);
  input.lifecycleLock.assertHeld();
  if (stableJson(currentSnapshot) !== binding.snapshotIdentity) {
    throw new StalePreparedRuntimeError("prepared runtime durable selection changed before admission");
  }
  const currentTemplate = readTemplateArtifact(binding.plan, currentSnapshot);
  if (currentTemplate.source !== binding.templateArtifactSource) {
    throw new Error("prepared runtime session-template artifact changed after publication");
  }
  const marker = runtimeValidationMarkerStatus(binding.context, input.io, {
    contractHash: binding.securityContractHash,
  });
  input.lifecycleLock.assertHeld();
  if (!marker.proof || marker.issue) {
    if (marker.issue && validationMarkerIssueIsContradictory(marker.issue)) {
      throw new Error(`prepared runtime validation proof is contradictory: ${marker.issue}`);
    }
    throw new StalePreparedRuntimeError(
      `prepared runtime validation proof changed before admission: ${marker.issue ?? "missing proof"}`,
    );
  }
  if (marker.proof.proxyId !== currentSnapshot.effective.selection.proxyContainerId) {
    throw new StalePreparedRuntimeError("prepared runtime proxy changed before admission");
  }
  assertValidationProof(binding.plan, currentSnapshot, marker.proof, binding.securityContractHash);
  consumed.add(input.preparedRuntime);
  return binding;
}
