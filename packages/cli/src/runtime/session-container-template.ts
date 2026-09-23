import fs from "node:fs";
import path from "node:path";

import {
  agentStateEnvironment,
  composeAgentEnvironment,
  composeAgentStateMounts,
} from "../agents.ts";
import type { ProjectInfo } from "../config.ts";
import { readActiveControlSelection, readEffectiveControlProvenance } from "../control/effective.ts";
import { inboxContainerDir } from "../inbox.ts";
import {
  completeAgentEnvironment,
  projectAgentEnvironmentOverrides,
} from "./agent-env.ts";
import { SELECTED_AGENT_IMAGE_LABEL_NAMES } from "./constants.ts";
import {
  parseEffectiveControlPlaneSelectionV2,
  parseRuntimeGenerationTargetV2,
  parseSessionAgentMaterializationManifestV2,
  parseSessionAgentGenerationV2,
  type ControlPlaneEffectiveSelectionV2,
  type RuntimeGenerationTargetV2,
  type SessionAgentMaterializationManifestV2,
  type SessionAgentGenerationV2,
} from "./component-state-v2.ts";
import {
  dependencyOverlayEnvironment,
  dependencyOverlayMountsForRoot,
  dependencyOverlayNamedVolumes,
  type DependencyOverlayPlan,
} from "./dependency-overlays.ts";
import { canonicalHostProjectRoot, type RuntimeGitLayoutPlan } from "./git-layout.ts";
import {
  claudeMcpConfigMount,
  mcpProjectMaskMounts,
} from "./mcp.ts";
import type { RuntimePlan } from "./plan.ts";
import {
  SESSION_CONTAINER_CAPABILITY_DROPS,
  SESSION_CONTAINER_RESTART_POLICY,
  SESSION_CONTAINER_SECURITY_OPTIONS,
  SESSION_CONTAINER_STOP_SIGNAL,
  SESSION_CONTAINER_USER,
  type SessionContainerMount,
} from "./session-container-contract.ts";
import {
  assertSessionImageDeclarationProof,
  type SessionImageDeclarationProof,
} from "./session-image-declarations.ts";
import { assertSessionLaunchTarget, type SessionLaunchTarget } from "./session-launch.ts";
import {
  assertSessionContainerTransitionV2,
  assertSessionContainerRecordProject,
  bindAllocatedSessionContainerIdV2,
  parseSessionContainerRecordV2,
  SESSION_CONTAINER_LABELS,
  serializeSessionContainerRecordV2,
  sessionContainerLabels,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import type { TopologyDigestJson } from "./topology-digest.ts";
import { exactKeySet as exactKeys, isRecord } from "../strict-primitives.ts";

const COMPOSE_VOLUME_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const COMPOSE_INTERPOLATION_PATTERN = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:-|-|:\?|\?)([^}]*))?\}/g;
const ENVIRONMENT_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const MAX_TEMPLATE_ENVIRONMENT_ENTRIES = 512;
const MAX_TEMPLATE_MOUNTS = 256;
const MAX_TEMPLATE_TEXT_LENGTH = 16 * 1024;

declare const sessionContainerTemplateBrand: unique symbol;

export type SessionContainerTemplate = Readonly<{
  readonly [sessionContainerTemplateBrand]: true;
  version: 1;
  environment: Readonly<Record<string, string>>;
  mounts: readonly SessionContainerMount[];
  workingDirectory: string;
}>;

type SessionContainerTemplateIdentity = Readonly<SessionContainerProjectIdentity>;

const validatedTemplates = new WeakMap<object, SessionContainerTemplateIdentity>();
type SessionContainerTemplateGenerationBinding = Readonly<{
  target: RuntimeGenerationTargetV2;
  sessionTemplateDigest: string;
}>;

const templateGenerationBindings = new WeakMap<object, SessionContainerTemplateGenerationBinding>();

declare const sessionContainerCreatePlanBrand: unique symbol;

export type SessionContainerCreatePlan = Readonly<{
  readonly [sessionContainerCreatePlanBrand]: true;
  expectedProject: SessionContainerTemplateIdentity;
  template: SessionContainerTemplate;
  generationTarget: RuntimeGenerationTargetV2;
  sessionAgentGeneration: SessionAgentGenerationV2;
  sessionAgentMaterialization: SessionAgentMaterializationManifestV2;
  effectiveControlPlane: ControlPlaneEffectiveSelectionV2;
  launch: SessionLaunchTarget;
  imageDeclarationProof: SessionImageDeclarationProof;
  record: SessionContainerRecordV2;
  runfreeVersion: string;
  environment: Readonly<Record<string, string>>;
  mounts: readonly SessionContainerMount[];
}>;

export type SessionContainerCreatePlanInput = Readonly<{
  expectedProject: SessionContainerProjectIdentity;
  template: SessionContainerTemplate;
  generationTarget: RuntimeGenerationTargetV2;
  sessionAgentGeneration: SessionAgentGenerationV2;
  sessionAgentMaterialization: SessionAgentMaterializationManifestV2;
  effectiveControlPlane: ControlPlaneEffectiveSelectionV2;
  launch: SessionLaunchTarget;
  imageDeclarationProof: SessionImageDeclarationProof;
  record: SessionContainerRecordV2;
  runfreeVersion: string;
}>;

const validatedCreatePlans = new WeakSet<object>();

export type SessionContainerTemplateInput = {
  projectRoot: string;
  project: ProjectInfo;
  composeProjectName: string;
  gitLayout: RuntimeGitLayoutPlan;
  dependencyOverlays: DependencyOverlayPlan;
  runtimeEnvironment: Readonly<Record<string, string | undefined>>;
  selectedAgentEnvironment: {
    source: string;
    displayPath: string;
    // Parameter env names declared by the selected generation's approved
    // services; see projectAgentEnvironmentOverrides.
    declaredParameterEnvNames?: string[];
  };
};

export function composeManagedVolumeName(composeProjectName: string, logicalName: string): string {
  if (!COMPOSE_VOLUME_NAME_PATTERN.test(composeProjectName)) {
    throw new Error(`invalid session-container Compose project name: ${composeProjectName || "<empty>"}`);
  }
  if (!COMPOSE_VOLUME_NAME_PATTERN.test(logicalName)) {
    throw new Error(`invalid session-container logical volume name: ${logicalName || "<empty>"}`);
  }
  return `${composeProjectName}_${logicalName}`;
}

function resolveComposeEnvironmentValue(
  value: string,
  environment: Readonly<Record<string, string | undefined>>,
): string {
  return value.replace(COMPOSE_INTERPOLATION_PATTERN, (_match, name: string, operator?: string, fallback = "") => {
    const selected = environment[name];
    const isSet = selected !== undefined;
    const isNonEmpty = isSet && selected !== "";
    if (operator === ":-") return isNonEmpty ? selected : fallback;
    if (operator === "-") return isSet ? selected : fallback;
    if (operator === ":?" && !isNonEmpty) throw new Error(fallback || `${name} is required`);
    if (operator === "?" && !isSet) throw new Error(fallback || `${name} is required`);
    return selected ?? "";
  });
}

function sortedEnvironment(environment: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(environment).sort(([left], [right]) => left.localeCompare(right)));
}

function sessionEnvironment(input: SessionContainerTemplateInput): Record<string, string> {
  const runtimeOwned = completeAgentEnvironment({
    ...composeAgentEnvironment(),
    ...dependencyOverlayEnvironment(input.dependencyOverlays),
  });
  const resolvedRuntimeOwned = Object.fromEntries(Object.entries(runtimeOwned).map(([name, value]) => [
    name,
    resolveComposeEnvironmentValue(value, input.runtimeEnvironment),
  ]));
  return sortedEnvironment({
    ...projectAgentEnvironmentOverrides(
      input.selectedAgentEnvironment.source,
      input.selectedAgentEnvironment.displayPath,
      { declaredParameterEnvNames: input.selectedAgentEnvironment.declaredParameterEnvNames ?? [] },
    ),
    ...resolvedRuntimeOwned,
  });
}

function bindMount(source: string, target: string, readOnly: boolean): SessionContainerMount {
  return { type: "bind", source, target, readOnly, noCopy: false };
}

function volumeMount(
  source: string,
  target: string,
  options: { readOnly: boolean; noCopy: boolean },
): SessionContainerMount {
  return { type: "volume", source, target, ...options };
}

function sessionMounts(input: SessionContainerTemplateInput): SessionContainerMount[] {
  // Canonicalized on both sides before comparing: the layout stored the root as
  // the filesystem names it, while the configured project root keeps whatever
  // spelling identity was derived from. Comparing those raw made one directory
  // reached through a symlink — every macOS project under `/tmp` or
  // `/var/folders` — look like a layout belonging to a different project.
  const projectRoot = canonicalHostProjectRoot(input.projectRoot);
  if (projectRoot !== input.gitLayout.hostProjectRoot) {
    throw new Error("session-container Git layout belongs to a different project root");
  }
  const stateEnvironment = agentStateEnvironment(input.project);
  const dependencyVolumeNames = new Set(dependencyOverlayNamedVolumes(input.dependencyOverlays));
  const mounts: SessionContainerMount[] = [
    bindMount(input.gitLayout.hostProjectRoot, input.gitLayout.containerProjectRoot, false),
    ...(input.gitLayout.kind === "relative-linked"
      ? [bindMount(input.gitLayout.hostGitCommonDir, input.gitLayout.containerGitCommonDir, false)]
      : []),
    ...composeAgentStateMounts().map((mount) => {
      const source = stateEnvironment[mount.sourceEnv];
      if (!source) throw new Error(`session-container agent state source is missing: ${mount.sourceEnv}`);
      return bindMount(source, mount.target, mount.readOnly === true);
    }),
    bindMount(input.project.paths.gitConfigPath, "/home/agent/.gitconfig", true),
    volumeMount(
      composeManagedVolumeName(input.composeProjectName, "runfree-commandhistory"),
      "/commandhistory",
      { readOnly: false, noCopy: true },
    ),
    bindMount(input.project.paths.proxyCaCertDir, "/etc/proxy-ca", true),
    ...[
      {
        type: "bind" as const,
        source: input.project.paths.inboxDir,
        target: inboxContainerDir(),
        readOnly: true,
      },
      claudeMcpConfigMount(input.project),
      ...mcpProjectMaskMounts(
        projectRoot,
        input.project,
        input.gitLayout.containerProjectRoot,
      ),
    ].map((mount) => bindMount(mount.source, mount.target, mount.readOnly === true)),
    ...dependencyOverlayMountsForRoot(
      input.dependencyOverlays,
      input.gitLayout.containerProjectRoot,
    ).map((mount): SessionContainerMount => {
      if (mount.type !== "volume" || !dependencyVolumeNames.has(mount.source)) {
        throw new Error(`session-container dependency mount is not a declared named volume: ${mount.source}`);
      }
      return volumeMount(composeManagedVolumeName(input.composeProjectName, mount.source), mount.target, {
        readOnly: mount.readOnly === true,
        noCopy: mount.noCopy === true,
      });
    }),
  ].sort((left, right) => left.target.localeCompare(right.target) || left.source.localeCompare(right.source));

  const targets = new Set<string>();
  for (const mount of mounts) {
    if (targets.has(mount.target)) throw new Error(`duplicate session-container template mount: ${mount.target}`);
    targets.add(mount.target);
  }
  return mounts;
}

export function createSessionContainerTemplate(
  input: SessionContainerTemplateInput,
): SessionContainerTemplate {
  const identityMatch = /^runfree-([a-f0-9]{12})$/u.exec(input.composeProjectName);
  if (!identityMatch?.[1]) {
    throw new Error("session-container template has invalid project identity");
  }
  if (!input.gitLayout.containerProjectRoot.startsWith("/")
    || path.posix.normalize(input.gitLayout.containerProjectRoot) !== input.gitLayout.containerProjectRoot) {
    throw new Error("session-container template working directory is not canonical");
  }
  const environment = Object.freeze(sessionEnvironment(input));
  const mounts = Object.freeze(sessionMounts(input).map((mount) => Object.freeze({ ...mount })));
  const template = Object.freeze({
    version: 1,
    environment,
    mounts,
    workingDirectory: input.gitLayout.containerProjectRoot,
  }) as SessionContainerTemplate;
  validatedTemplates.set(template, Object.freeze({
    projectId: identityMatch[1],
    composeProject: input.composeProjectName,
  }));
  return template;
}

export function assertSessionContainerTemplate(
  template: unknown,
): asserts template is SessionContainerTemplate {
  if (template === null || typeof template !== "object" || !validatedTemplates.has(template)) {
    throw new Error("session-container template was not minted by the canonical template builder");
  }
}



function boundedTemplateText(value: unknown): value is string {
  return typeof value === "string"
    && value.length > 0
    && value.length <= MAX_TEMPLATE_TEXT_LENGTH
    && !/[\u0000-\u001f\u007f-\u009f]/u.test(value);
}

/**
 * Restores a strict durable template without reading project or generated
 * environment files. The caller must separately verify the artifact hash and
 * topology projection before this value becomes launch authority.
 */
export function createSessionContainerTemplateFromArtifact(
  value: unknown,
  expectedProject: SessionContainerProjectIdentity,
): SessionContainerTemplate {
  if (!isRecord(value) || !exactKeys(value, ["version", "environment", "mounts", "workingDirectory"])) {
    throw new Error("session-template artifact has an invalid contract");
  }
  if (value.version !== 1 || !isRecord(value.environment) || !Array.isArray(value.mounts)) {
    throw new Error("session-template artifact has an invalid contract");
  }
  const environmentEntries = Object.entries(value.environment);
  if (environmentEntries.length > MAX_TEMPLATE_ENVIRONMENT_ENTRIES) {
    throw new Error("session-template artifact has too many environment entries");
  }
  const environment: Record<string, string> = {};
  for (const [name, entry] of environmentEntries) {
    if (!ENVIRONMENT_NAME_PATTERN.test(name)
      || typeof entry !== "string"
      || entry.length > MAX_TEMPLATE_TEXT_LENGTH
      || /[\u0000-\u001f\u007f-\u009f]/u.test(entry)) {
      throw new Error("session-template artifact has an invalid environment entry");
    }
    environment[name] = entry;
  }
  if (value.mounts.length > MAX_TEMPLATE_MOUNTS) {
    throw new Error("session-template artifact has too many mounts");
  }
  const mounts: SessionContainerMount[] = [];
  const targets = new Set<string>();
  for (const entry of value.mounts) {
    if (!isRecord(entry) || !exactKeys(entry, ["type", "source", "target", "readOnly", "noCopy"])) {
      throw new Error("session-template artifact has an invalid mount");
    }
    if ((entry.type !== "bind" && entry.type !== "volume")
      || !boundedTemplateText(entry.source)
      || !boundedTemplateText(entry.target)
      || !path.posix.isAbsolute(entry.target)
      || path.posix.normalize(entry.target) !== entry.target
      || typeof entry.readOnly !== "boolean"
      || typeof entry.noCopy !== "boolean"
      || targets.has(entry.target)) {
      throw new Error("session-template artifact has an invalid mount");
    }
    targets.add(entry.target);
    mounts.push({
      type: entry.type,
      source: entry.source,
      target: entry.target,
      readOnly: entry.readOnly,
      noCopy: entry.noCopy,
    });
  }
  if (!boundedTemplateText(value.workingDirectory)
    || !path.posix.isAbsolute(value.workingDirectory)
    || path.posix.normalize(value.workingDirectory) !== value.workingDirectory) {
    throw new Error("session-template artifact has an invalid working directory");
  }
  const template = Object.freeze({
    version: 1,
    environment: Object.freeze(Object.fromEntries(
      Object.entries(environment).sort(([left], [right]) => left.localeCompare(right)),
    )),
    mounts: Object.freeze(mounts.map((mount) => Object.freeze({ ...mount }))),
    workingDirectory: value.workingDirectory,
  }) as SessionContainerTemplate;
  validatedTemplates.set(template, Object.freeze({ ...expectedProject }));
  return template;
}

export function bindSessionContainerTemplateGenerationV2(
  template: SessionContainerTemplate,
  generationTarget: RuntimeGenerationTargetV2,
): SessionContainerTemplate {
  assertSessionContainerTemplate(template);
  const target = parseRuntimeGenerationTargetV2(generationTarget);
  if (!target) throw new Error("session-container runtime generation target is invalid");
  const identity = validatedTemplates.get(template);
  if (!identity
    || identity.projectId !== target.controlPlane.projectId
    || identity.composeProject !== target.controlPlane.composeProject) {
    throw new Error("session-container template belongs to a different runtime generation project");
  }
  const digest = target.sessionAgent.sessionTemplateDigest;
  const existing = templateGenerationBindings.get(template);
  if (existing !== undefined
    && (existing.target !== generationTarget || existing.sessionTemplateDigest !== digest)) {
    throw new Error("session-container template is already bound to a different session-agent generation");
  }
  templateGenerationBindings.set(template, Object.freeze({
    target: generationTarget,
    sessionTemplateDigest: digest,
  }));
  return template;
}

function exactTemplateIdentity(
  template: SessionContainerTemplate,
  expectedProject: SessionContainerProjectIdentity,
): SessionContainerTemplateIdentity {
  assertSessionContainerTemplate(template);
  const identity = validatedTemplates.get(template);
  if (!identity
    || identity.projectId !== expectedProject.projectId
    || identity.composeProject !== expectedProject.composeProject) {
    throw new Error("session-container template belongs to a different project");
  }
  return identity;
}

function freezeGenerationTarget(target: RuntimeGenerationTargetV2): RuntimeGenerationTargetV2 {
  return Object.freeze({
    topology: Object.freeze({ ...target.topology }),
    controlPlane: Object.freeze({ ...target.controlPlane }),
    sessionAgent: Object.freeze({ ...target.sessionAgent }),
  });
}

function assertSameGenerationField(label: string, left: unknown, right: unknown): void {
  if (left !== right) throw new Error(`session-container create plan has mismatched ${label}`);
}

export function createSessionContainerCreatePlan(
  input: SessionContainerCreatePlanInput,
): SessionContainerCreatePlan {
  const identity = exactTemplateIdentity(input.template, input.expectedProject);
  const target = parseRuntimeGenerationTargetV2(input.generationTarget);
  if (!target) throw new Error("session-container runtime generation target is invalid");
  const templateBinding = templateGenerationBindings.get(input.template);
  if (!templateBinding
    || templateBinding.target !== input.generationTarget
    || templateBinding.sessionTemplateDigest !== target.sessionAgent.sessionTemplateDigest) {
    throw new Error("session-container template is not bound to the selected runtime generation");
  }
  const generation = parseSessionAgentGenerationV2(input.sessionAgentGeneration);
  if (!generation) throw new Error("session-container bound agent generation is invalid");
  const materialization = parseSessionAgentMaterializationManifestV2(input.sessionAgentMaterialization);
  if (!materialization) throw new Error("session-container agent materialization is invalid");
  const effectiveControlPlane = parseEffectiveControlPlaneSelectionV2(input.effectiveControlPlane);
  if (!effectiveControlPlane) throw new Error("session-container effective control-plane selection is invalid");
  assertSessionLaunchTarget(input.launch);
  const record = parseSessionContainerRecordV2(input.record);
  if (!record) throw new Error("session-container lifecycle record is invalid");
  assertSessionContainerRecordProject(record, input.expectedProject);
  sessionContainerLabels(record, input.runfreeVersion);

  assertSameGenerationField("target project id", target.controlPlane.projectId, identity.projectId);
  assertSameGenerationField("target Compose project", target.controlPlane.composeProject, identity.composeProject);
  assertSameGenerationField(
    "selected agent image input digest",
    generation.selectedAgentImageInputDigest,
    target.sessionAgent.selectedAgentImageInputDigest,
  );
  assertSameGenerationField(
    "session template digest",
    generation.sessionTemplateDigest,
    target.sessionAgent.sessionTemplateDigest,
  );
  assertSameGenerationField(
    "session agent generation digest",
    generation.sessionAgentGenerationDigest,
    target.sessionAgent.sessionAgentGenerationDigest,
  );
  assertSameGenerationField(
    "agent admission contract epoch",
    generation.admissionContractEpoch,
    target.sessionAgent.admissionContractEpoch,
  );
  assertSameGenerationField(
    "record selected agent image id",
    record.selectedAgentImageId,
    generation.selectedAgentImageId,
  );
  assertSameGenerationField(
    "materialization session agent generation digest",
    materialization.generation.sessionAgentGenerationDigest,
    generation.sessionAgentGenerationDigest,
  );
  assertSameGenerationField("materialization project id", materialization.projectId, record.projectId);
  assertSameGenerationField("materialization Compose project", materialization.composeProject, record.composeProject);
  assertSameGenerationField("launch path", record.launchPath, input.launch.path);
  assertSameGenerationField("launch arguments", JSON.stringify(record.launchArgs), JSON.stringify(input.launch.args));
  assertSameGenerationField("launch interactive contract", record.interactive, input.launch.interactive);
  assertSameGenerationField("launch TTY contract", record.tty, input.launch.tty);
  assertSameGenerationField(
    "record selected agent image reference",
    record.selectedAgentImageRef,
    materialization.selectedAgentImageRef,
  );
  assertSameGenerationField(
    "record selected agent materialization image id",
    record.selectedAgentImageId,
    materialization.selectedAgentImageId,
  );
  assertSameGenerationField(
    "record session agent materialization digest",
    record.sessionAgentMaterializationDigest,
    materialization.sessionAgentMaterializationDigest,
  );
  assertSameGenerationField(
    "record selected agent image input digest",
    record.selectedAgentImageInputDigest,
    generation.selectedAgentImageInputDigest,
  );
  assertSameGenerationField(
    "record session template digest",
    record.sessionTemplateDigest,
    generation.sessionTemplateDigest,
  );
  assertSameGenerationField(
    "record session agent generation digest",
    record.sessionAgentGenerationDigest,
    generation.sessionAgentGenerationDigest,
  );
  assertSameGenerationField(
    "record control-plane generation digest",
    record.controlPlaneGenerationDigest,
    target.controlPlane.controlPlaneGenerationDigest,
  );
  assertSameGenerationField(
    "record admission contract epoch",
    record.admissionContractEpoch,
    target.controlPlane.admissionContractEpoch,
  );
  assertSameGenerationField("effective project id", effectiveControlPlane.projectId, record.projectId);
  assertSameGenerationField("effective Compose project", effectiveControlPlane.composeProject, record.composeProject);
  assertSameGenerationField(
    "effective control-plane generation digest",
    effectiveControlPlane.controlPlaneGenerationDigest,
    record.controlPlaneGenerationDigest,
  );
  assertSameGenerationField(
    "effective admission contract epoch",
    effectiveControlPlane.admissionContractEpoch,
    record.admissionContractEpoch,
  );
  assertSessionImageDeclarationProof(input.imageDeclarationProof, {
    selectedAgentImageId: record.selectedAgentImageId,
    mounts: input.template.mounts,
    environment: input.template.environment,
  });

  const frozenTarget = freezeGenerationTarget(target);
  const frozenGeneration = Object.freeze({ ...generation });
  const frozenMaterialization = Object.freeze({
    ...materialization,
    generation: Object.freeze({ ...materialization.generation }),
  });
  const frozenRecord = Object.freeze({
    ...record,
    launchArgs: Object.freeze([...record.launchArgs]),
  });
  const plan = Object.freeze({
    expectedProject: identity,
    template: input.template,
    generationTarget: frozenTarget,
    sessionAgentGeneration: frozenGeneration,
    sessionAgentMaterialization: frozenMaterialization,
    effectiveControlPlane: Object.freeze({
      ...effectiveControlPlane,
      networkIds: Object.freeze({ ...effectiveControlPlane.networkIds }),
      sidecarContainerIds: Object.freeze([]),
    }),
    launch: input.launch,
    imageDeclarationProof: input.imageDeclarationProof,
    record: frozenRecord,
    runfreeVersion: input.runfreeVersion,
    environment: input.template.environment,
    mounts: input.template.mounts,
  }) as SessionContainerCreatePlan;
  validatedCreatePlans.add(plan);
  return plan;
}

export function assertSessionContainerCreatePlan(
  plan: unknown,
): asserts plan is SessionContainerCreatePlan {
  if (plan === null || typeof plan !== "object" || !validatedCreatePlans.has(plan)) {
    throw new Error("session-container create plan was not minted by the canonical plan builder");
  }
}

export function bindSessionContainerCreatePlanRecord(
  plan: SessionContainerCreatePlan,
  nextRecord: SessionContainerRecordV2,
): SessionContainerCreatePlan {
  assertSessionContainerCreatePlan(plan);
  const parsedNext = parseSessionContainerRecordV2(nextRecord);
  if (!parsedNext) throw new Error("session-container create plan rebinding record is invalid");
  let authorizedNext: SessionContainerRecordV2;
  if (plan.record.state === "allocated"
    && plan.record.containerId === undefined
    && parsedNext.state === "allocated"
    && parsedNext.containerId !== undefined) {
    authorizedNext = bindAllocatedSessionContainerIdV2(plan.record, parsedNext.containerId);
  } else {
    assertSessionContainerTransitionV2(plan.record, parsedNext);
    authorizedNext = parsedNext;
  }
  if (serializeSessionContainerRecordV2(authorizedNext) !== serializeSessionContainerRecordV2(parsedNext)) {
    throw new Error("session-container create plan cannot rebind to a different lifecycle authority");
  }
  const templateBinding = templateGenerationBindings.get(plan.template);
  if (!templateBinding) throw new Error("session-container template generation binding was lost");
  return createSessionContainerCreatePlan({
    expectedProject: plan.expectedProject,
    template: plan.template,
    generationTarget: templateBinding.target,
    sessionAgentGeneration: plan.sessionAgentGeneration,
    sessionAgentMaterialization: plan.sessionAgentMaterialization,
    effectiveControlPlane: plan.effectiveControlPlane,
    launch: plan.launch,
    imageDeclarationProof: plan.imageDeclarationProof,
    record: parsedNext,
    runfreeVersion: plan.runfreeVersion,
  });
}

export function sessionContainerTopologyProjectionV2(
  template: SessionContainerTemplate,
): TopologyDigestJson {
  assertSessionContainerTemplate(template);
  return {
    schemaVersion: 2,
    createContract: {
      user: SESSION_CONTAINER_USER,
      init: false,
      stopSignal: SESSION_CONTAINER_STOP_SIGNAL,
      createdStopped: true,
      networkAtCreate: true,
      healthcheckDisabled: true,
      restartPolicy: SESSION_CONTAINER_RESTART_POLICY,
      securityOptions: [...SESSION_CONTAINER_SECURITY_OPTIONS],
      capabilityAdds: [],
      capabilityDrops: [...SESSION_CONTAINER_CAPABILITY_DROPS],
      launch: {
        path: "exact-absolute-per-session",
        args: "exact-per-session",
        interactive: "exact-per-session",
        tty: "exact-per-session",
        firstProjectControlledProcess: true,
        foregroundStartAttach: true,
        dockerExec: false,
      },
      runfreeLabelNames: Array.from(new Set([
        ...SELECTED_AGENT_IMAGE_LABEL_NAMES,
        ...Object.values(SESSION_CONTAINER_LABELS),
      ])).sort(),
      publishedPorts: [],
      hostGatewayAliases: [],
      devices: [],
    },
    admissionNetworkContract: {
      attachmentCount: 1,
      fixedIpv4: true,
      ipv6: false,
      externalDefaultRoute: false,
      directDns: false,
      proxyOnlyEgress: true,
    },
    environment: { ...template.environment },
    mounts: template.mounts.map((mount) => ({
      ...mount,
    })),
    workingDirectory: template.workingDirectory,
  };
}

export type SessionContainerTemplateRuntimePlan = Pick<
  RuntimePlan,
  "composeProjectName" | "dependencyOverlays" | "gitLayout" | "project" | "projectRoot" | "projectRuntimeRoot"
> & {
  execution: Pick<RuntimePlan["execution"], "composeEnv">;
};

// The selected generation's agent.env is required input: a missing file means
// the selection is broken, and the template must fail loudly rather than plan
// an empty agent environment.
function selectedAgentEnvironmentSource(selectedPath: string): string {
  return fs.readFileSync(selectedPath, "utf8");
}

// The selected generation's approved services declare which agent env names
// are parameters (values pass through) rather than credentials (placeholders).
// Recomputed from the verified approved subjects, like the provenance snapshot.
function selectedDeclaredParameterEnvNames(project: ProjectInfo): string[] {
  const active = readActiveControlSelection(project);
  if (!active) return [];
  const provenance = readEffectiveControlProvenance(project, active.controlGeneration);
  return Array.from(new Set(
    Object.values(provenance.selectedServices)
      .flatMap((entry) => (entry.resolved.parameters ?? []).map((parameter) => parameter.envVar)),
  )).sort();
}

export function sessionContainerTemplateForRuntimePlan(
  plan: SessionContainerTemplateRuntimePlan,
): SessionContainerTemplate {
  const selectedAgentEnvironmentPath = plan.execution.composeEnv.RUNFREE_AGENT_ENV_FILE;
  if (!selectedAgentEnvironmentPath) throw new Error("selected session-container agent environment is missing");
  return createSessionContainerTemplate({
    projectRoot: plan.projectRoot,
    project: plan.project,
    composeProjectName: plan.composeProjectName,
    gitLayout: plan.gitLayout,
    dependencyOverlays: plan.dependencyOverlays,
    runtimeEnvironment: plan.execution.composeEnv,
    selectedAgentEnvironment: {
      source: selectedAgentEnvironmentSource(selectedAgentEnvironmentPath),
      displayPath: selectedAgentEnvironmentPath,
      declaredParameterEnvNames: selectedDeclaredParameterEnvNames(plan.project),
    },
  });
}
