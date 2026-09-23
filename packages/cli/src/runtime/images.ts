import fs from "node:fs";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  readEffectiveRuntimeGeneration,
  createRuntimeComponentState,
  readRuntimeGenerationManifest,
  runtimeGenerationManifestPath,
  selectEffectiveRuntimeGeneration,
  serializeRuntimeGenerationManifest,
  sha256Digest,
  type RuntimeGenerationManifest,
} from "./component-state.ts";
import {
  type SessionAgentMaterializationManifestV2,
  type ControlPlaneMaterializationManifestV2,
  bindSessionAgentImageV2,
  createControlPlaneMaterializationManifestV2,
  createSessionAgentDesiredSelectionV2,
  createSessionAgentMaterializationManifestV2,
  publishControlPlaneMaterializationV2,
  publishSessionAgentMaterializationV2,
  controlPlaneMaterializationsRootV2,
  readControlPlaneMaterializationV2,
  readEffectiveControlPlaneV2,
  readRetainedDesiredSessionAgentV2,
  readRetainedSessionAgentMaterializationV2,
  selectDesiredSessionAgentV2,
  sessionAgentMaterializationsRootV2,
} from "./component-state-v2.ts";
import {
  agentBaseImageTag,
  agentBuildConfig,
  agentRuntimeImageTag,
  classifyAgentBuildContext,
  hasWideBuildContextApproval,
  projectAgentImageTag,
  proxyRuntimeImageTag,
  requireAgentBuildPaths,
  saveWideBuildContextApproval,
  selectedAgentImageInput,
  type AgentBuildPaths,
  type BuildContextManifestEntry,
  wideBuildContextApprovalPrompt,
} from "../agent-image.ts";
import {
  ApprovedImageBuildSnapshotError,
  approveNarrowImageBuildCandidate,
  approvedNarrowImageBuildForManifest,
  captureNarrowImageBuildCandidate,
  narrowImageBuildApprovalPrompt,
  readApprovedNarrowImageBuild,
} from "../control/image-approval.ts";
import { RUNFREE_RUNTIME_COMPONENTS, RUNFREE_VERSION } from "../embedded-assets.generated.ts";
import { die } from "../errors.ts";
import { runtimeInputBuildArgFlags } from "../runtime-inputs.ts";
import { flushWarnings, runfreeLog, warn } from "../warnings.ts";
import {
  AGENT_BASE_IMAGE_ROLE,
  AGENT_PROJECT_IMAGE_ROLE,
  AGENT_RUNTIME_IMAGE_ROLE,
  PROJECT_ID_LABEL,
  PROXY_RUNTIME_IMAGE_ROLE,
  RUNFREE_DIGEST_SCHEMA_LABEL,
  RUNFREE_DIGEST_SCHEMA_VERSION,
  RUNFREE_IMAGE_INPUT_DIGEST_LABEL,
  RUNFREE_IMAGE_ROLE_LABEL,
  RUNFREE_MANAGED_IMAGE_LABEL,
  RUNFREE_VERSION_LABEL,
} from "./constants.ts";
import {
  dependencyOverlayRuntimeSignature,
  writeDependencyOverlayPlan,
  writeDependencyOverlayRuntimeSignature,
} from "./dependency-overlays.ts";
import { composeProjectName, projectHash } from "./env.ts";
import { persistGitRepositoryLayout } from "./git-layout.ts";
import { runtimeContextFromPlan, type ActiveRuntimePlan, type RuntimePlan } from "./plan.ts";
import {
  createSessionTemplateArtifactV1,
  serializeSessionTemplateArtifactV1,
  sessionTemplateArtifactSha256,
} from "./session-template-artifact.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";
import { dockerClientEnvOptions, type RuntimeDocker } from "./docker.ts";
import { inspectReusableManagedImage, reusableManagedImage } from "./image-identity.ts";
import {
  accountSessionAgentImageReferences,
  inspectSessionContainerInventory,
  unreferencedSessionAgentImageIds,
  unreferencedSessionAgentMaterializationDigests,
} from "./session-container-reconciliation.ts";
import {
  listQuarantinedSessionContainerRecordNamesV2,
  listSessionContainerRecordsV2,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import { readProxySessionFiles } from "./session-reconcile.ts";
import { readControlPlaneRebindTransaction } from "./control-plane-rebind.ts";
import { remedy } from "../remedies.ts";

export type RuntimeMaterialization = {
  activeRuntimeRoot: string;
  composeFile: string;
  composeDirectory: string;
  runtimeDigest: string;
  materialized: boolean;
  agentImage: string;
  proxyImage: string;
  controlPlaneMaterializationDigest?: string;
  preparedSessionAgent?: SessionAgentMaterializationManifestV2;
  manifest?: RuntimeGenerationManifest;
  state: "desired" | "effective" | "legacy";
};

export class RuntimeImageBuildStatus extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "RuntimeImageBuildStatus";
    this.status = status;
  }
}

type RuntimeImageOptions = {
  verbose?: boolean;
};

function verboseRuntimeImage(options: RuntimeImageOptions | undefined, message: string): void {
  if (options?.verbose) runfreeLog(`verbose: ${message}`);
}

export function projectRuntimeRoot(context: RuntimeContext): string {
  return path.join(context.project.paths.stateDir, "runtime");
}

export function generatedRuntimeContextIfAvailable(context: RuntimeContext): RuntimeContext {
  const manifest = readEffectiveRuntimeGeneration(context.project.paths.stateDir);
  const legacyRoot = projectRuntimeRoot(context);
  const runtimeRoot = manifest
    ? path.dirname(runtimeGenerationManifestPath(context.project.paths.stateDir, manifest.components.materializationDigest))
    : legacyRoot;
  if (!fs.existsSync(path.join(runtimeRoot, "agent", "compose.yaml"))) return context;
  if (manifest && (
    manifest.projectId !== projectHash(context.projectRoot)
    || manifest.composeProject !== composeProjectName(context.projectRoot)
  )) {
    throw new Error("selected runtime generation belongs to another project");
  }
  return {
    ...context,
    baseRuntimeRoot: context.baseRuntimeRoot ?? context.runtimeRoot,
    runtimeRoot,
    ...(manifest ? { runtimeComponents: manifest.components, agentImage: manifest.images.agent } : {}),
  };
}

function sortedBuildArgs(args: Record<string, string> | undefined): Array<[string, string]> {
  return Object.entries(args ?? {}).sort(([left], [right]) => left.localeCompare(right));
}

function dockerBuildLabels(labels: Record<string, string>): string[] {
  return Object.entries(labels).flatMap(([name, value]) => ["--label", `${name}=${value}`]);
}

function runtimeImageBuildLabels(inputDigest: string): string[] {
  return dockerBuildLabels({
    [RUNFREE_MANAGED_IMAGE_LABEL]: "true",
    [RUNFREE_IMAGE_ROLE_LABEL]: AGENT_RUNTIME_IMAGE_ROLE,
    [RUNFREE_DIGEST_SCHEMA_LABEL]: RUNFREE_DIGEST_SCHEMA_VERSION,
    [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: inputDigest,
    [RUNFREE_VERSION_LABEL]: RUNFREE_VERSION,
  });
}

function proxyImageBuildLabels(inputDigest: string): string[] {
  return dockerBuildLabels({
    [RUNFREE_MANAGED_IMAGE_LABEL]: "true",
    [RUNFREE_IMAGE_ROLE_LABEL]: PROXY_RUNTIME_IMAGE_ROLE,
    [RUNFREE_DIGEST_SCHEMA_LABEL]: RUNFREE_DIGEST_SCHEMA_VERSION,
    [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: inputDigest,
    [RUNFREE_VERSION_LABEL]: RUNFREE_VERSION,
  });
}

function projectImageBuildLabels(context: RuntimeContext, inputDigest: string): string[] {
  return dockerBuildLabels({
    [RUNFREE_MANAGED_IMAGE_LABEL]: "true",
    [RUNFREE_IMAGE_ROLE_LABEL]: AGENT_PROJECT_IMAGE_ROLE,
    [RUNFREE_DIGEST_SCHEMA_LABEL]: RUNFREE_DIGEST_SCHEMA_VERSION,
    [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: inputDigest,
    [PROJECT_ID_LABEL]: projectHash(context.projectRoot),
    [RUNFREE_VERSION_LABEL]: RUNFREE_VERSION,
  });
}

function buildRuntimeAgentImage(
  runtimeRoot: string,
  inputDigest: string,
  docker: RuntimeDocker,
  force: boolean,
  options?: RuntimeImageOptions,
): number {
  const runtimeImage = agentRuntimeImageTag(inputDigest);
  const baseImage = agentBaseImageTag(inputDigest);
  const expected = {
    inputDigest,
    roles: [AGENT_RUNTIME_IMAGE_ROLE, AGENT_BASE_IMAGE_ROLE] as const,
  };
  if (!force) {
    const runtimePresent = reusableManagedImage(docker, runtimeImage, expected);
    const basePresent = reusableManagedImage(docker, baseImage, expected);
    if (runtimePresent && basePresent) {
      verboseRuntimeImage(options, `runtime agent image present: ${runtimeImage}`);
      return 0;
    }
    if (runtimePresent || basePresent) {
      const source = runtimePresent ? runtimeImage : baseImage;
      const target = runtimePresent ? baseImage : runtimeImage;
      verboseRuntimeImage(options, `retagging verified runtime agent image: ${source} -> ${target}`);
      const status = docker.tagImage(source, target);
      if (status !== 0) warn("Docker tag failed for the Runfree runtime agent image");
      return status;
    }
  }
  verboseRuntimeImage(options, `building runtime agent image: ${runtimeImage}`);
  const status = docker.buildImage([
    "--tag",
    runtimeImage,
    "--tag",
    baseImage,
    ...runtimeImageBuildLabels(inputDigest),
    ...runtimeInputBuildArgFlags(runtimeRoot, "agent-image"),
    "--file",
    path.join(runtimeRoot, "agent", "Dockerfile"),
    path.join(runtimeRoot, "agent"),
  ]);
  if (status !== 0) warn("Docker build failed for the Runfree runtime agent image");
  return status;
}

function buildRuntimeProxyImage(
  runtimeRoot: string,
  inputDigest: string,
  docker: RuntimeDocker,
  force: boolean,
  options?: RuntimeImageOptions,
): number {
  const image = proxyRuntimeImageTag(inputDigest);
  if (!force && reusableManagedImage(docker, image, {
    inputDigest,
    roles: [PROXY_RUNTIME_IMAGE_ROLE],
  })) {
    verboseRuntimeImage(options, `runtime proxy image present: ${image}`);
    return 0;
  }
  verboseRuntimeImage(options, `building runtime proxy image: ${image}`);
  const status = docker.buildImage([
    "--tag",
    image,
    ...proxyImageBuildLabels(inputDigest),
    ...runtimeInputBuildArgFlags(runtimeRoot, "proxy-image"),
    "--file",
    path.join(runtimeRoot, "proxy", "Dockerfile"),
    path.join(runtimeRoot, "proxy"),
  ]);
  if (status !== 0) warn("Docker build failed for the Runfree runtime proxy image");
  return status;
}

function warnImageCleanupFailure(action: string, status: number): void {
  if (status === 0) return;
  warn(`${action} failed with status ${status}; continuing without forcing image removal`);
}

const GC_IMAGE_INSPECT_MAX_BYTES = 16 * 1024 * 1024;

/**
 * The L5d pre-removal re-check: one uncached `docker image inspect id1…idN`.
 *
 * Fail-closed contract: overall exit status 0 is required (a vanished id fails
 * the whole cleanup rather than quietly shrinking the set), the output must be
 * a strict JSON array of exactly N elements matched by `Id` value — never
 * positionally — every listed id must appear exactly once, each element
 * re-verifies the managed/project/role labels, and stdout is bounded. Any
 * deviation throws, which `cleanupRunfreeImages` turns into a skipped cleanup.
 */
function exactManagedProjectAgentImageIds(
  context: RuntimeContext,
  io: RuntimeIO,
  projectId: string,
): string[] {
  const result = io.capture("docker", [
    "image", "ls", "--no-trunc", "--quiet",
    "--filter", `label=${RUNFREE_MANAGED_IMAGE_LABEL}=true`,
    "--filter", `label=${PROJECT_ID_LABEL}=${projectId}`,
    "--filter", `label=${RUNFREE_IMAGE_ROLE_LABEL}=${AGENT_PROJECT_IMAGE_ROLE}`,
  ], dockerClientEnvOptions(context));
  if (result.status !== 0 || Buffer.byteLength(result.stdout) > 128 * 1024) {
    throw new Error("Docker could not list the bounded managed project-agent image set");
  }
  const ids = result.stdout.trim().split(/\s+/u).filter(Boolean);
  if (ids.length > 1_024 || new Set(ids).size !== ids.length
    || ids.some((id) => !/^sha256:[a-f0-9]{64}$/u.test(id))) {
    throw new Error("Docker returned an invalid managed project-agent image set");
  }
  if (ids.length === 0) return ids;
  const inspect = io.capture("docker", ["image", "inspect", ...ids], {
    ...dockerClientEnvOptions(context),
    maxBuffer: GC_IMAGE_INSPECT_MAX_BYTES,
  });
  if (inspect.status !== 0 || Buffer.byteLength(inspect.stdout) > GC_IMAGE_INSPECT_MAX_BYTES) {
    throw new Error("managed project-agent images could not be re-inspected before cleanup");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(inspect.stdout);
  } catch {
    throw new Error("managed project-agent image re-inspection returned invalid JSON");
  }
  if (!Array.isArray(parsed) || parsed.length !== ids.length) {
    throw new Error("managed project-agent image re-inspection did not return exactly the listed set");
  }
  const labelsById = new Map<string, Record<string, unknown>>();
  for (const element of parsed as unknown[]) {
    if (!element || typeof element !== "object") {
      throw new Error("managed project-agent image re-inspection returned a malformed element");
    }
    const id = Reflect.get(element, "Id");
    if (typeof id !== "string" || labelsById.has(id)) {
      throw new Error("managed project-agent image re-inspection returned duplicate or unidentified elements");
    }
    const config = Reflect.get(element, "Config");
    const labels = config && typeof config === "object" ? Reflect.get(config, "Labels") : undefined;
    if (labels === undefined || labels === null || typeof labels !== "object" || Array.isArray(labels)) {
      throw new Error("managed project-agent image re-inspection returned unreadable labels");
    }
    labelsById.set(id, labels as Record<string, unknown>);
  }
  for (const id of ids) {
    const labels = labelsById.get(id);
    if (!labels
      || labels[RUNFREE_MANAGED_IMAGE_LABEL] !== "true"
      || labels[PROJECT_ID_LABEL] !== projectId
      || labels[RUNFREE_IMAGE_ROLE_LABEL] !== AGENT_PROJECT_IMAGE_ROLE) {
      throw new Error("managed project-agent image identity changed during cleanup inspection");
    }
  }
  return ids;
}

const MATERIALIZATION_DIRECTORY_PATTERN = /^sha256-([a-f0-9]{64})$/u;
const MATERIALIZATION_DIRECTORY_LIMIT = 1_024;
const MATERIALIZATION_FILE_SIZE_LIMIT = 128 * 1024;

function isMissing(error: unknown): boolean {
  return error instanceof Error && "code" in error && error.code === "ENOENT";
}

function exactMaterializationDigests(
  root: string,
  allowedFileNames: ReadonlySet<string>,
): string[] {
  let rootStat: fs.Stats;
  try {
    rootStat = fs.lstatSync(root);
  } catch (error) {
    if (isMissing(error)) return [];
    throw error;
  }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error(`runtime materialization root is unsafe: ${root}`);
  }
  const entries = fs.readdirSync(root);
  if (entries.length > MATERIALIZATION_DIRECTORY_LIMIT) {
    throw new Error("runtime materialization inventory exceeds its directory limit");
  }
  const digests: string[] = [];
  for (const entry of entries) {
    const digestHex = MATERIALIZATION_DIRECTORY_PATTERN.exec(entry)?.[1];
    if (!digestHex) throw new Error(`runtime materialization inventory contains an unknown entry: ${entry}`);
    const directory = path.join(root, entry);
    const directoryStat = fs.lstatSync(directory);
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
      throw new Error(`runtime materialization path is unsafe: ${directory}`);
    }
    const files = fs.readdirSync(directory);
    if (files.some((file) => !allowedFileNames.has(file))) {
      throw new Error(`runtime materialization contains an unknown entry: ${directory}`);
    }
    for (const file of files) {
      const filePath = path.join(directory, file);
      const stat = fs.lstatSync(filePath);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
        || stat.size > MATERIALIZATION_FILE_SIZE_LIMIT) {
        throw new Error(`runtime materialization file is unsafe: ${filePath}`);
      }
    }
    digests.push(`sha256:${digestHex}`);
  }
  return digests.sort();
}

function removeExactMaterialization(
  root: string,
  materializationDigest: string,
  allowedFileNames: ReadonlySet<string>,
): void {
  const digestHex = /^sha256:([a-f0-9]{64})$/u.exec(materializationDigest)?.[1];
  if (!digestHex) throw new Error("cleanup materialization digest is invalid");
  const directory = path.join(root, `sha256-${digestHex}`);
  const directoryStat = fs.lstatSync(directory);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
    throw new Error(`cleanup materialization path is unsafe: ${directory}`);
  }
  const files = fs.readdirSync(directory);
  if (files.some((file) => !allowedFileNames.has(file))) {
    throw new Error(`cleanup materialization contains an unknown entry: ${directory}`);
  }
  for (const file of files) {
    const filePath = path.join(directory, file);
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
      || stat.size > MATERIALIZATION_FILE_SIZE_LIMIT) {
      throw new Error(`cleanup materialization file is unsafe: ${filePath}`);
    }
  }
  for (const file of files) fs.unlinkSync(path.join(directory, file));
  fs.rmdirSync(directory);
}

/**
 * Refuses the cleanup while the proxy holds a session file no lifecycle record
 * claims.
 *
 * A file is the whole of a session's authority, so one the registry cannot
 * account for may belong to a running session whose
 * record was lost — and the image that session is running is exactly what an
 * image-reference scan built from records alone would call unreferenced. There
 * is no image id in the listing to retain individually, so the honest answer is
 * the whole-pass one: prove every served file maps to a record this scan
 * already counted, or prune nothing.
 *
 * A read the host could not make is not "no files" either; both refusals throw
 * into `cleanupRunfreeImages`'s own handler, which skips the cleanup and says
 * why. The reclamation is the next `up` once the proxy answers, or the
 * reconcile pass that deletes the orphan file.
 */
function assertProxySessionFilesAreRecorded(input: Readonly<{
  io: RuntimeIO;
  context: RuntimeContext;
  proxyId: string;
  records: readonly SessionContainerRecordV2[];
}>): void {
  const files = readProxySessionFiles({
    io: input.io,
    proxyId: input.proxyId,
    dockerOptions: dockerClientEnvOptions(input.context),
  });
  const recordKeys = new Set(input.records.map((record) => record.sessionPrincipal));
  const unaccounted = files.filter((file) => file.sessionKey === undefined || !recordKeys.has(file.sessionKey));
  if (unaccounted.length > 0) {
    throw new Error(
      `the proxy still serves ${unaccounted.length} session file(s) no lifecycle record claims`,
    );
  }
}

export type RuntimeCleanupCandidates = Readonly<{
  controlPlaneMaterializationDigest?: string;
  sessionAgentMaterializationDigest?: string;
}>;

export function cleanupRunfreeImages(
  context: RuntimeContext,
  docker: RuntimeDocker,
  io: RuntimeIO,
  currentCandidates: RuntimeCleanupCandidates = {},
): void {
  const projectId = projectHash(context.projectRoot);
  const build = agentBuildConfig(context.project.config);
  try {
    const expectedProject = { projectId, composeProject: composeProjectName(context.projectRoot) };
    if (listQuarantinedSessionContainerRecordNamesV2(context.project.paths.stateDir).length > 0) {
      throw new Error("the lifecycle registry contains quarantined records");
    }
    const records = listSessionContainerRecordsV2(context.project.paths.stateDir, expectedProject);
    const containers = inspectSessionContainerInventory(
      (executable, args, options) => io.capture(executable, [...args], options),
      expectedProject,
      dockerClientEnvOptions(context),
    );
    const desired = readRetainedDesiredSessionAgentV2(context.project.paths.stateDir);
    const effectiveControlPlane = readEffectiveControlPlaneV2(context.project.paths.stateDir);
    // There is no admission journal to consult, and the other thing that can
    // still be using an agent image is the proxy: a session whose record was
    // lost is still served from a file this host cannot attribute, so the
    // retained set is proved against that listing before anything is pruned.
    if (effectiveControlPlane) {
      assertProxySessionFilesAreRecorded({
        io,
        context,
        proxyId: effectiveControlPlane.selection.proxyContainerId,
        records,
      });
    }
    const rebind = readControlPlaneRebindTransaction(context.project.paths.stateDir, expectedProject);
    const inProgressRecords = [
      ...(rebind ? [...rebind.oldRecords, ...rebind.replacementRecords] : []),
    ];
    const accounting = accountSessionAgentImageReferences({
      expectedProject,
      records,
      containers,
      desiredSelectedAgentImageId: desired?.selection.selectedAgentImageId,
      desiredSessionAgentMaterializationDigest: desired?.selection.sessionAgentMaterializationDigest,
      inProgressImageIds: inProgressRecords.map((record) => record.selectedAgentImageId),
      inProgressSessionAgentMaterializationDigests: [
        ...inProgressRecords.map((record) => record.sessionAgentMaterializationDigest),
        ...(currentCandidates.sessionAgentMaterializationDigest
          ? [currentCandidates.sessionAgentMaterializationDigest]
          : []),
      ],
    });
    if (accounting.uncertainContainerIds.length > 0) {
      throw new Error("managed-looking session containers have ambiguous identity");
    }

    for (const reference of accounting.materializations) {
      const manifest = readRetainedSessionAgentMaterializationV2(
        context.project.paths.stateDir,
        reference.materializationDigest,
      );
      if (!manifest || manifest.projectId !== projectId || manifest.composeProject !== expectedProject.composeProject) {
        throw new Error("a retained session reference has no exact project materialization");
      }
    }

    const controlPlaneReferences = new Map<string, unknown>();
    const retainControlPlane = (digest: string | undefined, expected?: unknown): void => {
      if (!digest) return;
      const manifest = readControlPlaneMaterializationV2(context.project.paths.stateDir, digest);
      if (!manifest || manifest.projectId !== projectId || manifest.composeProject !== expectedProject.composeProject
        || (expected !== undefined && !isDeepStrictEqual(manifest, expected))) {
        throw new Error("a retained control-plane reference has no exact project materialization");
      }
      controlPlaneReferences.set(digest, manifest);
    };
    retainControlPlane(effectiveControlPlane?.selection.controlPlaneMaterializationDigest, effectiveControlPlane?.manifest);
    retainControlPlane(rebind?.oldMaterialization.controlPlaneMaterializationDigest, rebind?.oldMaterialization);
    retainControlPlane(rebind?.candidateMaterialization.controlPlaneMaterializationDigest, rebind?.candidateMaterialization);
    retainControlPlane(currentCandidates.controlPlaneMaterializationDigest);

    const sessionMaterializationCandidates = exactMaterializationDigests(
      sessionAgentMaterializationsRootV2(context.project.paths.stateDir),
      new Set(["materialization.json", "session-template.json"]),
    );
    const staleSessionMaterializations = unreferencedSessionAgentMaterializationDigests(
      sessionMaterializationCandidates,
      accounting,
    );
    const controlMaterializationCandidates = exactMaterializationDigests(
      controlPlaneMaterializationsRootV2(context.project.paths.stateDir),
      new Set(["materialization.json"]),
    );
    const staleControlMaterializations = controlMaterializationCandidates
      .filter((digest) => !controlPlaneReferences.has(digest));

    const staleImageIds = build
      ? unreferencedSessionAgentImageIds(
          exactManagedProjectAgentImageIds(context, io, projectId),
          accounting,
        )
      : [];

    for (const digest of staleSessionMaterializations) {
      removeExactMaterialization(
        sessionAgentMaterializationsRootV2(context.project.paths.stateDir),
        digest,
        new Set(["materialization.json", "session-template.json"]),
      );
    }
    for (const digest of staleControlMaterializations) {
      removeExactMaterialization(
        controlPlaneMaterializationsRootV2(context.project.paths.stateDir),
        digest,
        new Set(["materialization.json"]),
      );
    }
    if (staleImageIds.length > 0) {
      warnImageCleanupFailure("stale Runfree project image cleanup", docker.removeImages(staleImageIds));
    }
  } catch (error) {
    const detail = error instanceof Error ? `: ${error.message}` : "";
    warn(`stale Runfree runtime cleanup skipped because exact references could not be proved${detail}`);
  }
}

function preSandboxApprovalFailure(buildContext: string): never {
  die([
    `the agent image was not built: pre-sandbox Docker build context approval is required for "${buildContext}"`,
    "Docker build runs before the Runfree sandbox and can read files in that context or send them over the network.",
    `approve this wide context with: ${remedy.imageApproveContext()}`,
  ].join("\n"));
}

function exactImageApprovalFailure(buildContext: string): never {
  die([
    `the agent image was not built: exact pre-sandbox Docker build approval is required for "${buildContext}"`,
    "Docker build runs before the Runfree sandbox and can execute staged project files or send them over the network.",
    `review the staged content shown above and approve it with: ${remedy.imageApproveContext()}`,
  ].join("\n"));
}

// The approved snapshot a changed candidate would replace; a snapshot that
// fails verification is reported as "first approval" rather than aborting the
// prompt (the approval below republishes over it).
function previousApprovedNarrowImageBuild(context: RuntimeContext) {
  try {
    return readApprovedNarrowImageBuild(context.projectRoot, context.project);
  } catch {
    return undefined;
  }
}

function approveWideBuildContextIfNeeded(context: RuntimeContext, build: NonNullable<ReturnType<typeof agentBuildConfig>>, io: RuntimeIO): void {
  if (hasWideBuildContextApproval(context.projectRoot, build, context.project.paths.stateDir)) return;
  flushWarnings();
  if (!io.confirm(wideBuildContextApprovalPrompt(build))) {
    preSandboxApprovalFailure(build.context);
  }
  saveWideBuildContextApproval(context.projectRoot, build, context.project.paths.stateDir);
}

/**
 * Prepare the approved narrow build input, staging only when the approval does
 * not already match.
 *
 * `contextManifest` is the manifest the plan already carries: it is computed on
 * every launch by `selectedAgentImageInput`, and the image-build subject digest
 * needs nothing else. Checking the approval from it is what lets this run on a
 * cached launch without copying the whole context and throwing the copy away.
 */
function narrowAgentBuildPaths(
  context: RuntimeContext,
  build: NonNullable<ReturnType<typeof agentBuildConfig>>,
  io: RuntimeIO,
  contextManifest: readonly BuildContextManifestEntry[],
  options: { cached: boolean },
): AgentBuildPaths {
  let selected: AgentBuildPaths | undefined;
  try {
    selected = approvedNarrowImageBuildForManifest(context.projectRoot, context.project, { build, contextManifest });
  } catch (error) {
    // Only a failed snapshot verification falls through to a fresh prompt: the
    // corrupt snapshot is never built from, and the approval below republishes
    // over it. Selection-level errors (checkout binding, malformed record)
    // still abort here. An image prompt that meets a non-valid selection must
    // not be the thing that discards the configuration subjects — with `legacy`
    // refusing in the writer and `mismatch` starting from an empty base, this
    // path can no longer reach a one-subject write over live configuration
    // authority.
    if (!(error instanceof ApprovedImageBuildSnapshotError)) throw error;
    warn(`stored image-build approval failed verification and is discarded: ${error.message}`);
  }
  if (selected) return selected;

  // Only now is staging worth its cost: it is needed to build, and to show the
  // user which files the decision is about.
  const candidate = captureNarrowImageBuildCandidate(
    context.projectRoot,
    build,
    context.project.paths.controlCandidatesDir,
  );
  flushWarnings();
  // The prompt shows the content of the decision — staged files, the
  // Dockerfile, and the diff against the previously approved snapshot when
  // one exists (a first approval says so).
  if (!io.confirm(narrowImageBuildApprovalPrompt(candidate, previousApprovedNarrowImageBuild(context), {
    cached: options.cached,
    projectRoot: context.projectRoot,
  }))) {
    exactImageApprovalFailure(build.context);
  }
  return approveNarrowImageBuildCandidate(
    context.projectRoot,
    context.project,
    candidate,
    "interactive",
  ).approved;
}

function wideAgentBuildPaths(
  context: RuntimeContext,
  build: NonNullable<ReturnType<typeof agentBuildConfig>>,
  io: RuntimeIO,
): AgentBuildPaths {
  approveWideBuildContextIfNeeded(context, build, io);
  return requireAgentBuildPaths(context.projectRoot, build);
}

function materializeProjectRuntime(
  context: RuntimeContext,
  plan: RuntimePlan,
  sourceRuntimeRoot: string,
  options: {
    agentImage: string;
    proxyImage: string;
  },
): RuntimeMaterialization {
  const generatedRuntimeRoot = plan.projectRuntimeRoot;
  const tmpRoot = `${generatedRuntimeRoot}.${process.pid}.tmp`;
  const manifest: RuntimeGenerationManifest = {
    schemaVersion: 1,
    projectId: plan.projectId,
    composeProject: plan.composeProjectName,
    components: plan.components,
    images: {
      agent: options.agentImage,
      proxy: options.proxyImage,
    },
    renderedComposeSha256: sha256Digest(plan.renderedCompose),
  };
  const existing = readRuntimeGenerationManifest(
    context.project.paths.stateDir,
    plan.components.materializationDigest,
  );
  if (existing) {
    if (serializeRuntimeGenerationManifest(existing) !== serializeRuntimeGenerationManifest(manifest)) {
      die("existing runtime materialization contradicts the desired runtime generation manifest");
    }
    const composeFile = path.join(generatedRuntimeRoot, "agent", "compose.yaml");
    if (!fs.existsSync(composeFile) || sha256Digest(fs.readFileSync(composeFile)) !== manifest.renderedComposeSha256) {
      die("existing runtime materialization has modified Compose content");
    }
    return {
      activeRuntimeRoot: generatedRuntimeRoot,
      composeFile,
      composeDirectory: path.dirname(composeFile),
      runtimeDigest: plan.runtimeDigest,
      materialized: true,
      agentImage: options.agentImage,
      proxyImage: options.proxyImage,
      manifest,
      state: "desired",
    };
  }
  fs.mkdirSync(path.dirname(generatedRuntimeRoot), { recursive: true, mode: 0o700 });
  fs.rmSync(tmpRoot, { recursive: true, force: true });
  fs.mkdirSync(tmpRoot, { recursive: true, mode: 0o755 });
  fs.cpSync(path.join(sourceRuntimeRoot, "agent"), path.join(tmpRoot, "agent"), { recursive: true });
  fs.cpSync(path.join(sourceRuntimeRoot, "proxy"), path.join(tmpRoot, "proxy"), { recursive: true });
  fs.copyFileSync(path.join(sourceRuntimeRoot, "runtime-inputs.lock.json"), path.join(tmpRoot, "runtime-inputs.lock.json"));

  fs.writeFileSync(
    path.join(tmpRoot, "agent", "compose.yaml"),
    plan.renderedCompose,
  );
  fs.writeFileSync(
    path.join(tmpRoot, "generation.json"),
    serializeRuntimeGenerationManifest(manifest),
    { flag: "wx", mode: 0o600 },
  );
  try {
    fs.renameSync(tmpRoot, generatedRuntimeRoot);
  } catch (error) {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
    if (!(error && typeof error === "object" && "code" in error && error.code === "EEXIST")) throw error;
    const raced = readRuntimeGenerationManifest(context.project.paths.stateDir, plan.components.materializationDigest);
    if (!raced || serializeRuntimeGenerationManifest(raced) !== serializeRuntimeGenerationManifest(manifest)) {
      die("runtime materialization publication raced with contradictory state");
    }
  }
  return {
    activeRuntimeRoot: generatedRuntimeRoot,
    composeFile: path.join(generatedRuntimeRoot, "agent", "compose.yaml"),
    composeDirectory: path.join(generatedRuntimeRoot, "agent"),
    runtimeDigest: plan.runtimeDigest,
    materialized: true,
    agentImage: options.agentImage,
    proxyImage: options.proxyImage,
    manifest,
    state: "desired",
  };
}

function materializeDesiredSessionAgent(
  plan: RuntimePlan,
  docker: RuntimeDocker,
  input: {
    selectedAgentImageRef: string;
    selectedAgentImageInputDigest: string;
    selectedAgentImageKind: "embedded" | "project";
    deferSelection?: boolean;
  },
): SessionAgentMaterializationManifestV2 {
  const expectedSelectedAgentImage = input.selectedAgentImageKind === "project"
    ? {
        inputDigest: input.selectedAgentImageInputDigest,
        projectId: plan.projectId,
        roles: [AGENT_PROJECT_IMAGE_ROLE] as const,
      }
    : {
        inputDigest: input.selectedAgentImageInputDigest,
        roles: [AGENT_RUNTIME_IMAGE_ROLE] as const,
      };
  // Ref-then-id cross-check: both reads must hit the daemon (L5a must-bypass)
  // or a memoized ref read would vacuously agree with itself.
  const selectedAgentImageByRef = inspectReusableManagedImage(
    docker,
    input.selectedAgentImageRef,
    expectedSelectedAgentImage,
    { fresh: true },
  );
  if (!selectedAgentImageByRef) {
    throw new Error("selected agent image failed exact managed identity inspection");
  }
  const selectedAgentImage = inspectReusableManagedImage(
    docker,
    selectedAgentImageByRef.id,
    expectedSelectedAgentImage,
    { fresh: true },
  );
  if (!selectedAgentImage || selectedAgentImage.id !== selectedAgentImageByRef.id) {
    throw new Error("selected agent image ID failed exact managed identity inspection");
  }
  if (plan.generationV2.sessionAgent.selectedAgentImageInputDigest !== input.selectedAgentImageInputDigest) {
    throw new Error("selected agent image input contradicts the planned session-agent generation");
  }

  const generation = bindSessionAgentImageV2(
    plan.generationV2.sessionAgent,
    selectedAgentImage.id,
  );
  const sessionTemplateArtifact = serializeSessionTemplateArtifactV1(
    createSessionTemplateArtifactV1(plan),
  );
  const manifest = createSessionAgentMaterializationManifestV2({
    projectId: plan.projectId,
    composeProject: plan.composeProjectName,
    generation,
    selectedAgentImageRef: input.selectedAgentImageRef,
    selectedAgentImageId: selectedAgentImage.id,
    selectedAgentImageKind: input.selectedAgentImageKind,
    sessionTemplateArtifactSha256: sessionTemplateArtifactSha256(sessionTemplateArtifact),
  });
  publishSessionAgentMaterializationV2(plan.paths.stateDir, manifest, sessionTemplateArtifact);
  if (!input.deferSelection) selectDesiredSessionAgentV2(
    plan.paths.stateDir,
    createSessionAgentDesiredSelectionV2(manifest),
  );
  return manifest;
}

function materializeDesiredControlPlane(
  plan: RuntimePlan,
  docker: RuntimeDocker,
  proxyImageRef: string,
) {
  const expectedProxyImage = {
    inputDigest: plan.generationV2.controlPlane.proxyImageInputDigest,
    roles: [PROXY_RUNTIME_IMAGE_ROLE] as const,
  };
  // Ref-then-id cross-check: both reads must hit the daemon (L5a must-bypass).
  const proxyImageByRef = inspectReusableManagedImage(docker, proxyImageRef, expectedProxyImage, { fresh: true });
  if (!proxyImageByRef) {
    throw new Error("control-plane proxy image failed exact managed identity inspection");
  }
  const proxyImage = inspectReusableManagedImage(docker, proxyImageByRef.id, expectedProxyImage, { fresh: true });
  if (!proxyImage || proxyImage.id !== proxyImageByRef.id) {
    throw new Error("control-plane proxy image ID failed exact managed identity inspection");
  }
  const manifest = createControlPlaneMaterializationManifestV2({
    projectId: plan.projectId,
    composeProject: plan.composeProjectName,
    generation: plan.generationV2.controlPlane,
    proxyImageRef,
    proxyImageId: proxyImage.id,
    // The v2 topology digest is the SHA-256 of the canonical rendered
    // control-plane projection, including its owned interpolation inputs and
    // runtime signatures. It is the exact rendered control-plane identity;
    // the full legacy shared-agent Compose document is intentionally not.
    renderedControlPlaneSha256: plan.generationV2.controlPlane.controlPlaneTopologyDigest,
    // The admission source the proxy environment above was minted with. The
    // manifest carries it so a control plane materialized by a pre-cutover CLI
    // fails to parse rather than being adopted by this one.
    sessionAdmissionSource: "files",
  });
  publishControlPlaneMaterializationV2(plan.paths.stateDir, manifest);
  return manifest;
}

export function ensureRuntimeMaterialized(
  plan: RuntimePlan,
  options: { docker: RuntimeDocker; io: RuntimeIO; force: boolean; verbose?: boolean; deferSelection?: boolean },
): ActiveRuntimePlan {
  const context = runtimeContextFromPlan(plan);
  const sourceRuntimeRoot = plan.baseRuntimeRoot;
  const embeddedAgentInputDigest = RUNFREE_RUNTIME_COMPONENTS.agentImageInputDigest;
  const proxyInputDigest = RUNFREE_RUNTIME_COMPONENTS.proxyImageInputDigest;
  const defaultAgentImage = agentRuntimeImageTag(embeddedAgentInputDigest);
  const proxyImage = proxyRuntimeImageTag(proxyInputDigest);

  if (!plan.agentImage) {
    const runtimeStatus = buildRuntimeAgentImage(sourceRuntimeRoot, embeddedAgentInputDigest, options.docker, false, options);
    if (runtimeStatus !== 0) {
      throw new RuntimeImageBuildStatus(`runtime agent image build failed with status ${runtimeStatus}`, runtimeStatus);
    }
    const proxyStatus = buildRuntimeProxyImage(sourceRuntimeRoot, proxyInputDigest, options.docker, false, options);
    if (proxyStatus !== 0) {
      throw new RuntimeImageBuildStatus(`runtime proxy image build failed with status ${proxyStatus}`, proxyStatus);
    }
    const materialization = materializeProjectRuntime(context, plan, sourceRuntimeRoot, {
      agentImage: defaultAgentImage,
      proxyImage,
    });
    const controlPlane = materializeDesiredControlPlane(plan, options.docker, proxyImage);
    const preparedSessionAgent = materializeDesiredSessionAgent(plan, options.docker, {
      deferSelection: options.deferSelection,
      selectedAgentImageRef: defaultAgentImage,
      selectedAgentImageInputDigest: embeddedAgentInputDigest,
      selectedAgentImageKind: "embedded",
    });
    return withActiveRuntime(plan, {
      ...materialization,
      controlPlaneMaterializationDigest: controlPlane.controlPlaneMaterializationDigest,
      preparedSessionAgent,
    });
  }

  const build = plan.agentImage.build;
  const baseImage = plan.agentImage.baseImage;
  const projectImage = plan.agentImage.projectImage;
  console.log(`agent base image: ${baseImage}`);
  console.log(`agent build: ${build.dockerfile}`);
  console.log(`agent image: ${projectImage}`);

  const projectNeedsBuild = options.force || !reusableManagedImage(options.docker, projectImage, {
    inputDigest: plan.agentImage.inputDigest,
    projectId: plan.projectId,
    roles: [AGENT_PROJECT_IMAGE_ROLE],
  });
  if (!projectNeedsBuild) verboseRuntimeImage(options, `project agent image present: ${projectImage}`);
  // Approval preparation is independent of whether Docker needs to build: a
  // cached image carries exactly the authority a built one does, and gating
  // preparation on the build is what let a cache hit reach final selection with
  // no approval and refuse there instead of prompting.
  const buildPaths = plan.agentImage.contextKind === "narrow"
    ? narrowAgentBuildPaths(
      context,
      build,
      options.io,
      plan.agentImage.contextFingerprint as readonly BuildContextManifestEntry[],
      { cached: !projectNeedsBuild },
    )
    : projectNeedsBuild ? wideAgentBuildPaths(context, build, options.io) : undefined;

  const proxyStatus = buildRuntimeProxyImage(sourceRuntimeRoot, proxyInputDigest, options.docker, false, options);
  if (proxyStatus !== 0) {
    throw new RuntimeImageBuildStatus(`runtime proxy image build failed with status ${proxyStatus}`, proxyStatus);
  }

  if (projectNeedsBuild) {
    const runtimeStatus = buildRuntimeAgentImage(sourceRuntimeRoot, embeddedAgentInputDigest, options.docker, false, options);
    if (runtimeStatus !== 0) {
      throw new RuntimeImageBuildStatus(`runtime base image build failed with status ${runtimeStatus}`, runtimeStatus);
    }
  }

  if (projectNeedsBuild) {
    if (!buildPaths) {
      die("internal error: project build paths were not prepared");
    }
    if (plan.agentImage.contextKind === "narrow") {
      if (!("manifest" in buildPaths)
        || !("inputDigest" in buildPaths)
        || buildPaths.inputDigest !== plan.agentImage.inputDigest
        || JSON.stringify(buildPaths.manifest) !== JSON.stringify(plan.agentImage.contextFingerprint)) {
        die("approved agent build input changed after runtime planning; retry the command");
      }
    } else {
      const current = selectedAgentImageInput(plan.projectRoot, plan.project.config);
      if (current.kind !== "project" || current.digest !== plan.agentImage.inputDigest) {
        die("agent Dockerfile changed after runtime planning; retry the command");
      }
    }
    const projectBuildArgs = [
      "--tag",
      projectImage,
      ...projectImageBuildLabels(context, plan.agentImage.inputDigest),
      "--file",
      buildPaths.dockerfilePath,
      "--build-arg",
      `RUNFREE_BASE_IMAGE=${baseImage}`,
      "--build-arg",
      `RUNFREE_AGENT_IMAGE_DIGEST=${embeddedAgentInputDigest}`,
    ];
    for (const argument of plan.agentImage.referencedLegacyInjectedArguments) {
      warn(`project Dockerfile references legacy ${argument.name}; release changes will rebuild this image`);
      projectBuildArgs.push("--build-arg", `${argument.name}=${argument.value}`);
    }
    if (build.target) {
      projectBuildArgs.push("--target", build.target);
    }
    for (const [name, value] of sortedBuildArgs(build.args)) {
      projectBuildArgs.push("--build-arg", `${name}=${value}`);
    }
    projectBuildArgs.push(buildPaths.contextPath);

    verboseRuntimeImage(options, `building project agent image: ${projectImage}`);
    const status = options.docker.buildImage(projectBuildArgs);
    if (status !== 0) {
      throw new RuntimeImageBuildStatus(`project agent image build failed with status ${status}`, status);
    }
  }

  const materialization = materializeProjectRuntime(context, plan, sourceRuntimeRoot, {
    agentImage: projectImage,
    proxyImage,
  });
  const controlPlane = materializeDesiredControlPlane(plan, options.docker, proxyImage);
  const preparedSessionAgent = materializeDesiredSessionAgent(plan, options.docker, {
    deferSelection: options.deferSelection,
    selectedAgentImageRef: projectImage,
    selectedAgentImageInputDigest: plan.agentImage.inputDigest,
    selectedAgentImageKind: "project",
  });
  return withActiveRuntime(plan, {
    ...materialization,
    controlPlaneMaterializationDigest: controlPlane.controlPlaneMaterializationDigest,
    preparedSessionAgent,
  });
}

export function withActiveRuntime(plan: RuntimePlan, activeRuntime: RuntimeMaterialization): ActiveRuntimePlan {
  return { ...plan, activeRuntime };
}

/** Commit only the exact immutable artifacts prepared before the lifecycle lock. */
export function selectPreparedSessionAgent(plan: ActiveRuntimePlan, docker: RuntimeDocker): void {
  const manifest = plan.activeRuntime.preparedSessionAgent;
  if (!manifest) throw new Error("prepared agent materialization is missing; retry runtime preparation");
  const retained = readRetainedSessionAgentMaterializationV2(plan.paths.stateDir, manifest.sessionAgentMaterializationDigest);
  if (!retained || !isDeepStrictEqual(retained, manifest)) throw new Error("prepared agent materialization changed before selection");
  const agent = docker.inspectImage(manifest.selectedAgentImageRef, { fresh: true });
  const control = plan.activeRuntime.controlPlaneMaterializationDigest
    ? readControlPlaneMaterializationV2(plan.paths.stateDir, plan.activeRuntime.controlPlaneMaterializationDigest) : undefined;
  const proxy = control ? docker.inspectImage(control.proxyImageRef, { fresh: true }) : undefined;
  if (agent?.id !== manifest.selectedAgentImageId || !control || proxy?.id !== control.proxyImageId) {
    throw new Error("prepared image reference changed before selection; retry runtime preparation");
  }
  if (plan.agentImage && classifyAgentBuildContext(plan.projectRoot, plan.agentImage.build) === "narrow") {
    const approved = readApprovedNarrowImageBuild(plan.projectRoot, plan.project);
    if (approved?.inputDigest !== plan.agentImage.inputDigest) {
      throw new Error("image approval changed during preparation; review the current image before retrying");
    }
  }
  selectDesiredSessionAgentV2(plan.paths.stateDir, createSessionAgentDesiredSelectionV2(manifest));
}

/** A recovery finishes the journal's approved image, even with a newer host CLI. */
export function materializeRetainedRebindRuntimePlan(
  plan: ActiveRuntimePlan, candidate: ControlPlaneMaterializationManifestV2, docker: RuntimeDocker,
): ActiveRuntimePlan {
  if (candidate.controlPlaneMaterializationDigest === plan.activeRuntime.controlPlaneMaterializationDigest) return plan;
  if (candidate.projectId !== plan.projectId || candidate.composeProject !== plan.composeProjectName
    || candidate.generation.admissionContractEpoch !== plan.generationV2.controlPlane.admissionContractEpoch
    || candidate.renderedControlPlaneSha256 !== plan.generationV2.controlPlane.controlPlaneTopologyDigest) {
    throw new Error("pending proxy replacement requires a CLI with its exact compatible topology and admission contract");
  }
  const retained = readControlPlaneMaterializationV2(plan.paths.stateDir, candidate.controlPlaneMaterializationDigest);
  if (!isDeepStrictEqual(retained, candidate)) throw new Error("pending replacement materialization is missing or changed; restore the retained artifact before recovery");
  for (const reference of [candidate.proxyImageRef, candidate.proxyImageId]) {
    const image = inspectReusableManagedImage(docker, reference,
      { inputDigest: candidate.generation.proxyImageInputDigest, roles: [PROXY_RUNTIME_IMAGE_ROLE] }, { fresh: true });
    if (image?.id !== candidate.proxyImageId) throw new Error("pending replacement image is missing or changed; restore its exact immutable image before recovery");
  }
  const components = createRuntimeComponentState({ ...plan.components, proxyImageInputDigest: candidate.generation.proxyImageInputDigest });
  const retainedPlan: RuntimePlan = {
    ...plan, components,
    generationV2: { ...plan.generationV2, controlPlane: candidate.generation },
    projectRuntimeRoot: path.dirname(runtimeGenerationManifestPath(plan.paths.stateDir, components.materializationDigest)),
    execution: { ...plan.execution, composeEnv: { ...plan.execution.composeEnv,
      RUNFREE_PROXY_IMAGE: candidate.proxyImageRef, RUNFREE_PROXY_IMAGE_INPUT_DIGEST: candidate.generation.proxyImageInputDigest,
      RUNFREE_RUNTIME_GENERATION_DIGEST: components.runtimeGenerationDigest } },
  };
  const materialization = materializeProjectRuntime(runtimeContextFromPlan(retainedPlan), retainedPlan, plan.baseRuntimeRoot,
    { agentImage: plan.activeRuntime.agentImage, proxyImage: candidate.proxyImageRef });
  return withActiveRuntime(retainedPlan, { ...materialization,
    controlPlaneMaterializationDigest: candidate.controlPlaneMaterializationDigest,
    preparedSessionAgent: plan.activeRuntime.preparedSessionAgent });
}

export function existingActiveRuntimePlan(plan: RuntimePlan): ActiveRuntimePlan {
  const manifest = readEffectiveRuntimeGeneration(plan.paths.stateDir);
  if (manifest) {
    if (manifest.projectId !== plan.projectId || manifest.composeProject !== plan.composeProjectName) {
      throw new Error("selected runtime generation belongs to another project");
    }
    const runtimeRoot = path.dirname(runtimeGenerationManifestPath(
      plan.paths.stateDir,
      manifest.components.materializationDigest,
    ));
    return withActiveRuntime(plan, {
      activeRuntimeRoot: runtimeRoot,
      composeFile: path.join(runtimeRoot, "agent", "compose.yaml"),
      composeDirectory: path.join(runtimeRoot, "agent"),
      runtimeDigest: plan.runtimeDigest,
      materialized: true,
      agentImage: manifest.images.agent,
      proxyImage: manifest.images.proxy,
      manifest,
      state: "effective",
    });
  }
  const legacyRuntimeRoot = projectRuntimeRoot(runtimeContextFromPlan(plan));
  const runtimeRoot = fs.existsSync(path.join(legacyRuntimeRoot, "agent", "compose.yaml"))
    ? legacyRuntimeRoot
    : plan.baseRuntimeRoot;
  const agentImage = plan.agentImage?.projectImage ?? agentRuntimeImageTag(plan.components.embeddedAgentImageInputDigest);
  return withActiveRuntime(plan, {
    activeRuntimeRoot: runtimeRoot,
    composeFile: path.join(runtimeRoot, "agent", "compose.yaml"),
    composeDirectory: path.join(runtimeRoot, "agent"),
    runtimeDigest: plan.runtimeDigest,
    materialized: runtimeRoot === plan.projectRuntimeRoot,
    agentImage,
    proxyImage: proxyRuntimeImageTag(plan.components.proxyImageInputDigest),
    state: "legacy",
  });
}

export function selectEffectiveRuntimePlan(plan: ActiveRuntimePlan): ActiveRuntimePlan {
  const manifest = plan.activeRuntime.manifest;
  if (!manifest || plan.activeRuntime.state === "legacy") {
    throw new Error("cannot select a legacy runtime without a runtime generation manifest");
  }
  selectEffectiveRuntimeGeneration(plan.paths.stateDir, manifest.components.materializationDigest);
  const context = runtimeContextFromPlan(plan, { activeRuntime: plan.activeRuntime });
  writeDependencyOverlayPlan(context, plan.dependencyOverlays);
  writeDependencyOverlayRuntimeSignature(
    context,
    dependencyOverlayRuntimeSignature(plan.dependencyOverlays, plan.gitLayout.containerProjectRoot),
  );
  persistGitRepositoryLayout(context, plan.gitLayout);
  return withActiveRuntime(plan, { ...plan.activeRuntime, state: "effective" });
}

export function projectAgentImageMissing(context: RuntimeContext, docker: RuntimeDocker): boolean {
  if (!agentBuildConfig(context.project.config)) return false;
  const selected = selectedAgentImageInput(context.projectRoot, context.project.config);
  if (selected.kind !== "project") return true;
  const tag = projectAgentImageTag(context.projectRoot, selected.digest);
  return !reusableManagedImage(docker, tag, {
    inputDigest: selected.digest,
    projectId: projectHash(context.projectRoot),
    roles: [AGENT_PROJECT_IMAGE_ROLE],
  });
}
