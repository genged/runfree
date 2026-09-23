import {
  AGENT_PROJECT_IMAGE_ROLE,
  AGENT_RUNTIME_IMAGE_ROLE,
} from "./constants.ts";
import {
  createRuntimeTopologyGenerationV2,
  createSessionAgentGenerationInputsV2,
  parseRuntimeGenerationTargetV2,
  readDesiredSessionAgentV2,
  readEffectiveControlPlaneV2,
  readSessionAgentMaterializationV2,
  readSessionAgentTemplateArtifactV2,
  type ControlPlaneEffectiveSelectionV2,
  type ControlPlaneMaterializationManifestV2,
  type RuntimeGenerationTargetV2,
  type SessionAgentDesiredSelectionV2,
  type SessionAgentMaterializationManifestV2,
} from "./component-state-v2.ts";
import {
  readRuntimeGenerationManifest,
  runtimeMaterializationRoot,
} from "./component-state.ts";
import type { RuntimeDocker } from "./docker.ts";
import { inspectReusableManagedImage, type ManagedImageExpectation } from "./image-identity.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import {
  createBuiltinSessionLaunchTarget,
  createBuiltinSessionResumeLaunchTarget,
  createBuiltinSessionShellLaunchTarget,
} from "./session-builtin-launch.ts";
import {
  bindSessionContainerTemplateGenerationV2,
  createSessionContainerCreatePlan,
  type SessionContainerCreatePlan,
  type SessionContainerTemplate,
} from "./session-container-template.ts";
import { parseSessionTemplateArtifactV1 } from "./session-template-artifact.ts";
import {
  createAllocatedSessionContainerRecordV2,
  type AllocatedSessionContainerInputV2,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import {
  createSessionImageDeclarationProof,
  type SessionImageDeclarationProof,
} from "./session-image-declarations.ts";
import { createSessionLaunchTarget, type SessionLaunchTarget } from "./session-launch.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import { stableJson } from "../strict-primitives.ts";
import { CliError } from "../errors.ts";
import { remedy } from "../remedies.ts";

declare const sessionAdmissionDriverPreflightBrand: unique symbol;

export type SessionAdmissionDriverPreflight = Readonly<{
  readonly [sessionAdmissionDriverPreflightBrand]: true;
  version: 1;
  expectedProject: Readonly<SessionContainerProjectIdentity>;
  generationTarget: RuntimeGenerationTargetV2;
  effectiveControlPlane: ControlPlaneEffectiveSelectionV2;
  sessionAgentMaterialization: SessionAgentMaterializationManifestV2;
  template: SessionContainerTemplate;
  launch: SessionLaunchTarget;
  imageDeclarationProof: SessionImageDeclarationProof;
}>;

export type SessionAdmissionPreflightRuntimePlan = Pick<
  ActiveRuntimePlan,
  | "activeRuntime"
  | "composeProjectName"
  | "dependencyOverlays"
  | "execution"
  | "generationV2"
  | "gitLayout"
  | "project"
  | "projectId"
  | "projectRoot"
  | "runfreeVersion"
  | "sessionContainerTemplate"
>;

export type SessionAdmissionAllocatedRecordInput = Omit<
  AllocatedSessionContainerInputV2,
  "effectiveControlPlane" | "launch" | "materialization"
>;

type DurablePreflightSnapshot = Readonly<{
  effective: Readonly<{
    selection: ControlPlaneEffectiveSelectionV2;
    manifest: ControlPlaneMaterializationManifestV2;
  }>;
  desired: Readonly<{
    selection: SessionAgentDesiredSelectionV2;
    manifest: SessionAgentMaterializationManifestV2;
  }>;
  serialized: string;
}>;

type PreflightBinding = Readonly<{
  stateDir: string;
  lifecycleLock: ProjectLifecycleLock;
  serializedSnapshot: string;
  expectedProject: Readonly<SessionContainerProjectIdentity>;
  generationTarget: RuntimeGenerationTargetV2;
  effectiveControlPlane: ControlPlaneEffectiveSelectionV2;
  sessionAgentMaterialization: SessionAgentMaterializationManifestV2;
  template: SessionContainerTemplate;
  launch: SessionLaunchTarget;
  imageDeclarationProof: SessionImageDeclarationProof;
  runfreeVersion: string;
}>;

const preflightBindings = new WeakMap<object, PreflightBinding>();
const allocatedRecordBindings = new WeakMap<object, SessionAdmissionDriverPreflight>();


function durableSnapshot(
  stateDir: string,
  expectedProject: SessionContainerProjectIdentity,
): DurablePreflightSnapshot {
  const effective = readEffectiveControlPlaneV2(stateDir);
  if (!effective) throw new Error("session admission requires a durable effective control plane");
  const desired = readDesiredSessionAgentV2(stateDir);
  if (!desired) throw new Error("session admission requires a durable desired session agent");
  for (const identity of [effective.selection, effective.manifest, desired.selection, desired.manifest]) {
    if (identity.projectId !== expectedProject.projectId
      || identity.composeProject !== expectedProject.composeProject) {
      throw new Error("session admission durable state belongs to a different project");
    }
  }
  const serialized = stableJson({ effective, desired });
  return { effective, desired, serialized } as DurablePreflightSnapshot;
}

function sameGeneration(left: unknown, right: unknown): boolean {
  return stableJson(left) === stableJson(right);
}

function mixedRuntimeTarget(snapshot: DurablePreflightSnapshot): RuntimeGenerationTargetV2 {
  const desiredGeneration = snapshot.desired.manifest.generation;
  const sessionAgent = createSessionAgentGenerationInputsV2({
    selectedAgentImageInputDigest: desiredGeneration.selectedAgentImageInputDigest,
    sessionTemplateDigest: desiredGeneration.sessionTemplateDigest,
    admissionContractEpoch: desiredGeneration.admissionContractEpoch,
  });
  if (sessionAgent.sessionAgentGenerationDigest !== desiredGeneration.sessionAgentGenerationDigest) {
    throw new Error("desired session-agent materialization contradicts its session-agent generation");
  }
  const target = {
    topology: createRuntimeTopologyGenerationV2({
      controlPlaneTopologyDigest: snapshot.effective.manifest.generation.controlPlaneTopologyDigest,
      sessionTemplateDigest: desiredGeneration.sessionTemplateDigest,
    }),
    controlPlane: snapshot.effective.manifest.generation,
    sessionAgent,
  };
  const parsed = parseRuntimeGenerationTargetV2(target);
  if (!parsed) {
    throw new Error("effective control plane and desired session agent are not admission-compatible");
  }
  return Object.freeze({
    topology: Object.freeze({ ...parsed.topology }),
    controlPlane: Object.freeze({ ...parsed.controlPlane }),
    sessionAgent: Object.freeze({ ...parsed.sessionAgent }),
  });
}

function expectedManagedImage(
  materialization: SessionAgentMaterializationManifestV2,
): ManagedImageExpectation {
  return materialization.selectedAgentImageKind === "project"
    ? {
        inputDigest: materialization.generation.selectedAgentImageInputDigest,
        projectId: materialization.projectId,
        roles: [AGENT_PROJECT_IMAGE_ROLE],
      }
    : {
        inputDigest: materialization.generation.selectedAgentImageInputDigest,
        roles: [AGENT_RUNTIME_IMAGE_ROLE],
      };
}

function inspectManagedImage(
  docker: Pick<RuntimeDocker, "inspectImage">,
  reference: string,
  expected: ManagedImageExpectation,
) {
  // Always fresh: every preflight/rebind consumer is a ref-then-id cross-check
  // whose claim is that the reference resolves to the durable id NOW; the L5a
  // memo must never satisfy it (temporal-poisoning hazard).
  const image = docker.inspectImage(reference, { fresh: true });
  if (!image
    || !inspectReusableManagedImage({ inspectImage: () => image }, reference, expected)) {
    throw new Error(`selected session image failed exact managed identity inspection: ${reference}`);
  }
  return image;
}

function assertCurrentPreflight(preflight: SessionAdmissionDriverPreflight): PreflightBinding {
  if (preflight === null || typeof preflight !== "object") {
    throw new Error("session admission preflight authority is invalid");
  }
  const binding = preflightBindings.get(preflight);
  if (!binding
    || preflight.expectedProject !== binding.expectedProject
    || preflight.generationTarget !== binding.generationTarget
    || preflight.effectiveControlPlane !== binding.effectiveControlPlane
    || preflight.sessionAgentMaterialization !== binding.sessionAgentMaterialization
    || preflight.template !== binding.template
    || preflight.launch !== binding.launch
    || preflight.imageDeclarationProof !== binding.imageDeclarationProof) {
    throw new Error("session admission preflight authority was not minted by the canonical builder");
  }
  binding.lifecycleLock.assertHeld();
  const current = durableSnapshot(binding.stateDir, binding.expectedProject);
  binding.lifecycleLock.assertHeld();
  if (current.serialized !== binding.serializedSnapshot) {
    throw new Error("session admission durable desired/effective state changed after preflight");
  }
  return binding;
}

export type SessionAdmissionResumeRequest = Readonly<{
  conversationId?: string;
}>;

/**
 * What the session's first project-controlled process is.
 *
 * `builtin` mints the descriptor-owned agent argv — the default, or the
 * recovery spec's typed resume variant when `resume` is present. Everything
 * else about admission is identical either way: the argv is minted here by
 * the canonical builder, bound into the lifecycle record, and proven against
 * the created container; resume never revives an old container.
 *
 * `shell` mints the image's login-shell target and consults no configured
 * command at all: the shell is the escape hatch the custom-command refusal
 * points at, so project config must not be able to affect it.
 */
export type SessionAdmissionPreflightLaunch =
  | Readonly<{ kind: "builtin"; agentId: string; configuredCommand: string; resume?: SessionAdmissionResumeRequest }>
  | Readonly<{ kind: "shell" }>;

export function createSessionAdmissionDriverPreflight(input: Readonly<{
  runtime: SessionAdmissionPreflightRuntimePlan;
  lifecycleLock: ProjectLifecycleLock;
  docker: Pick<RuntimeDocker, "inspectImage">;
  launch: SessionAdmissionPreflightLaunch;
}>): SessionAdmissionDriverPreflight {
  const expectedProject = Object.freeze({
    projectId: input.runtime.projectId,
    composeProject: input.runtime.composeProjectName,
  });
  const stateDir = input.runtime.project.paths.stateDir;
  input.lifecycleLock.assertHeld();
  const snapshot = durableSnapshot(stateDir, expectedProject);
  input.lifecycleLock.assertHeld();

  const target = mixedRuntimeTarget(snapshot);
  if (!sameGeneration(input.runtime.generationV2.sessionAgent, target.sessionAgent)) {
    throw new CliError([
      "runtime plan does not match the durable desired session-agent generation",
      `recreate the runtime from the current project with: ${remedy.rebuild()}`,
    ].join("\n"));
  }
  const activeRuntimeManifest = input.runtime.activeRuntime.manifest;
  if (!activeRuntimeManifest) {
    throw new Error("session admission requires an exact active runtime materialization");
  }
  const expectedRuntimeRoot = runtimeMaterializationRoot(
    stateDir,
    activeRuntimeManifest.components.materializationDigest,
  );
  if (input.runtime.activeRuntime.activeRuntimeRoot !== expectedRuntimeRoot) {
    throw new Error("active runtime does not name its exact immutable materialization root");
  }
  input.lifecycleLock.assertHeld();
  const runtimeManifest = readRuntimeGenerationManifest(
    stateDir,
    activeRuntimeManifest.components.materializationDigest,
  );
  input.lifecycleLock.assertHeld();
  if (!runtimeManifest
    || runtimeManifest.projectId !== expectedProject.projectId
    || runtimeManifest.composeProject !== expectedProject.composeProject
    || stableJson(runtimeManifest) !== stableJson(activeRuntimeManifest)) {
    throw new Error("active runtime materialization is not exact durable host-helper authority");
  }

  input.lifecycleLock.assertHeld();
  const templateArtifactSource = readSessionAgentTemplateArtifactV2(
    stateDir,
    snapshot.desired.manifest,
  );
  const templateArtifact = parseSessionTemplateArtifactV1(templateArtifactSource, {
    projectId: expectedProject.projectId,
    composeProject: expectedProject.composeProject,
    sessionTemplateDigest: snapshot.desired.manifest.generation.sessionTemplateDigest,
    artifactSha256: snapshot.desired.manifest.sessionTemplateArtifactSha256,
  });
  input.lifecycleLock.assertHeld();
  const template = bindSessionContainerTemplateGenerationV2(templateArtifact.template, target);
  const launch = input.launch.kind === "shell"
    ? createBuiltinSessionShellLaunchTarget()
    : input.launch.resume
      ? createBuiltinSessionResumeLaunchTarget({
          agentId: input.launch.agentId,
          configuredCommand: input.launch.configuredCommand,
          ...(input.launch.resume.conversationId !== undefined
            ? { conversationId: input.launch.resume.conversationId }
            : {}),
        })
      : createBuiltinSessionLaunchTarget({
          agentId: input.launch.agentId,
          configuredCommand: input.launch.configuredCommand,
        });
  const imageExpectation = expectedManagedImage(snapshot.desired.manifest);

  input.lifecycleLock.assertHeld();
  const selectedByRef = inspectManagedImage(
    input.docker,
    snapshot.desired.manifest.selectedAgentImageRef,
    imageExpectation,
  );
  input.lifecycleLock.assertHeld();
  if (selectedByRef.id !== snapshot.desired.manifest.selectedAgentImageId) {
    throw new Error("selected session image reference no longer resolves to the durable image ID");
  }
  const selectedById = inspectManagedImage(
    input.docker,
    snapshot.desired.manifest.selectedAgentImageId,
    imageExpectation,
  );
  input.lifecycleLock.assertHeld();
  if (selectedById.id !== snapshot.desired.manifest.selectedAgentImageId
    || stableJson(selectedByRef) !== stableJson(selectedById)) {
    throw new Error("selected session image reference and immutable ID inspections disagree");
  }

  const imageDeclarationProof = createSessionImageDeclarationProof({
    image: selectedById,
    selectedAgentImageId: snapshot.desired.manifest.selectedAgentImageId,
    mounts: template.mounts,
    environment: template.environment,
  });
  input.lifecycleLock.assertHeld();

  const current = durableSnapshot(stateDir, expectedProject);
  input.lifecycleLock.assertHeld();
  if (current.serialized !== snapshot.serialized) {
    throw new Error("session admission durable desired/effective state changed during preflight");
  }

  const effectiveControlPlane = Object.freeze({
    ...snapshot.effective.selection,
    sidecarContainerIds: Object.freeze([]),
    networkIds: Object.freeze({ ...snapshot.effective.selection.networkIds }),
  }) as ControlPlaneEffectiveSelectionV2;
  const sessionAgentMaterialization = Object.freeze({
    ...snapshot.desired.manifest,
    generation: Object.freeze({ ...snapshot.desired.manifest.generation }),
  });
  const preflight = Object.freeze({
    version: 1 as const,
    expectedProject,
    generationTarget: target,
    effectiveControlPlane,
    sessionAgentMaterialization,
    template,
    launch,
    imageDeclarationProof,
  }) as SessionAdmissionDriverPreflight;
  preflightBindings.set(preflight, Object.freeze({
    stateDir,
    lifecycleLock: input.lifecycleLock,
    serializedSnapshot: snapshot.serialized,
    expectedProject,
    generationTarget: target,
    effectiveControlPlane,
    sessionAgentMaterialization,
    template,
    launch,
    imageDeclarationProof,
    runfreeVersion: input.runtime.runfreeVersion,
  }));
  return preflight;
}

/** Reconstructs an exact proof plan for one retained session from durable artifacts. */
export function createRetainedSessionRebindProofPlan(input: Readonly<{
  stateDir: string;
  expectedProject: SessionContainerProjectIdentity;
  replacementRecord: SessionContainerRecordV2;
  candidateControlPlane: ControlPlaneEffectiveSelectionV2;
  candidateMaterialization: ControlPlaneMaterializationManifestV2;
  docker: Pick<RuntimeDocker, "inspectImage">;
  lifecycleLock: ProjectLifecycleLock;
  runfreeVersion: string;
}>): SessionContainerCreatePlan {
  input.lifecycleLock.assertHeld();
  const materialization = readSessionAgentMaterializationV2(
    input.stateDir,
    input.replacementRecord.sessionAgentMaterializationDigest,
  );
  if (!materialization) throw new Error("retained session has no exact selectable agent materialization");
  const generationInputs = createSessionAgentGenerationInputsV2({
    selectedAgentImageInputDigest: materialization.generation.selectedAgentImageInputDigest,
    sessionTemplateDigest: materialization.generation.sessionTemplateDigest,
    admissionContractEpoch: materialization.generation.admissionContractEpoch,
  });
  const target = parseRuntimeGenerationTargetV2({
    topology: createRuntimeTopologyGenerationV2({
      controlPlaneTopologyDigest: input.candidateMaterialization.generation.controlPlaneTopologyDigest,
      sessionTemplateDigest: materialization.generation.sessionTemplateDigest,
    }),
    controlPlane: input.candidateMaterialization.generation,
    sessionAgent: generationInputs,
  });
  if (!target
    || target.sessionAgent.sessionAgentGenerationDigest
      !== materialization.generation.sessionAgentGenerationDigest) {
    throw new Error("retained session materialization is incompatible with the candidate control plane");
  }
  const artifactSource = readSessionAgentTemplateArtifactV2(input.stateDir, materialization);
  const artifact = parseSessionTemplateArtifactV1(artifactSource, {
    projectId: input.expectedProject.projectId,
    composeProject: input.expectedProject.composeProject,
    sessionTemplateDigest: materialization.generation.sessionTemplateDigest,
    artifactSha256: materialization.sessionTemplateArtifactSha256,
  });
  const template = bindSessionContainerTemplateGenerationV2(artifact.template, target);
  const expectation = expectedManagedImage(materialization);
  const byReference = inspectManagedImage(input.docker, materialization.selectedAgentImageRef, expectation);
  const byId = inspectManagedImage(input.docker, materialization.selectedAgentImageId, expectation);
  if (byReference.id !== materialization.selectedAgentImageId || stableJson(byReference) !== stableJson(byId)) {
    throw new Error("retained session image reference and immutable ID inspections disagree");
  }
  const imageDeclarationProof = createSessionImageDeclarationProof({
    image: byId,
    selectedAgentImageId: materialization.selectedAgentImageId,
    mounts: template.mounts,
    environment: template.environment,
  });
  input.lifecycleLock.assertHeld();
  return createSessionContainerCreatePlan({
    template,
    generationTarget: target,
    sessionAgentGeneration: materialization.generation,
    sessionAgentMaterialization: materialization,
    effectiveControlPlane: input.candidateControlPlane,
    launch: createSessionLaunchTarget({
      path: input.replacementRecord.launchPath,
      args: input.replacementRecord.launchArgs,
      interactive: input.replacementRecord.interactive,
      tty: input.replacementRecord.tty,
    }),
    record: input.replacementRecord,
    expectedProject: input.expectedProject,
    imageDeclarationProof,
    runfreeVersion: input.runfreeVersion,
  });
}

export function assertSessionAdmissionDriverPreflight(
  preflight: unknown,
): asserts preflight is SessionAdmissionDriverPreflight {
  assertCurrentPreflight(preflight as SessionAdmissionDriverPreflight);
}

export function createAllocatedSessionContainerRecordFromPreflight(
  preflight: SessionAdmissionDriverPreflight,
  input: SessionAdmissionAllocatedRecordInput,
): SessionContainerRecordV2 {
  const binding = assertCurrentPreflight(preflight);
  const record = Object.freeze(createAllocatedSessionContainerRecordV2({
    ...input,
    materialization: binding.sessionAgentMaterialization,
    effectiveControlPlane: binding.effectiveControlPlane,
    launch: binding.launch,
  }));
  allocatedRecordBindings.set(record, preflight);
  return record;
}

export function createSessionContainerCreatePlanFromPreflight(
  preflight: SessionAdmissionDriverPreflight,
  record: SessionContainerRecordV2,
): SessionContainerCreatePlan {
  const binding = assertCurrentPreflight(preflight);
  if (allocatedRecordBindings.get(record) !== preflight) {
    throw new Error("allocated session-container record was not minted by this preflight authority");
  }
  return createSessionContainerCreatePlan({
    expectedProject: binding.expectedProject,
    template: binding.template,
    generationTarget: binding.generationTarget,
    sessionAgentGeneration: binding.sessionAgentMaterialization.generation,
    sessionAgentMaterialization: binding.sessionAgentMaterialization,
    effectiveControlPlane: binding.effectiveControlPlane,
    launch: binding.launch,
    imageDeclarationProof: binding.imageDeclarationProof,
    record,
    runfreeVersion: binding.runfreeVersion,
  });
}
