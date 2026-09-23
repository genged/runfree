import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { beforeEach, expect, test } from "vitest";

import {
  agentRuntimeImageTag,
  projectAgentImageTag,
  proxyRuntimeImageTag,
  selectedAgentImageInput,
} from "../agent-image.ts";
import { defaultConfig, projectControlPaths } from "../config.ts";
import { RUNFREE_RUNTIME_COMPONENTS } from "../embedded-assets.generated.ts";
import {
  AGENT_PROJECT_IMAGE_ROLE,
  AGENT_RUNTIME_IMAGE_ROLE,
  PROJECT_ID_LABEL,
  PROXY_RUNTIME_IMAGE_ROLE,
  RUNFREE_DIGEST_SCHEMA_LABEL,
  RUNFREE_DIGEST_SCHEMA_VERSION,
  RUNFREE_IMAGE_INPUT_DIGEST_LABEL,
  RUNFREE_IMAGE_ROLE_LABEL,
  RUNFREE_MANAGED_IMAGE_LABEL,
} from "./constants.ts";
import {
  createRuntimeComponentState,
  readEffectiveRuntimeGeneration,
  runtimeGenerationManifestPath,
  runtimeMaterializationRoot,
  selectEffectiveRuntimeGeneration,
  serializeRuntimeGenerationManifest,
  sha256Digest,
} from "./component-state.ts";
import {
  CONTROL_PLANE_PROOF_SCHEMA_VERSION,
  RUNTIME_ADMISSION_CONTRACT_EPOCH,
  createControlPlaneGenerationV2,
  createControlPlaneMaterializationManifestV2,
  createSessionAgentGenerationInputsV2,
  controlPlaneMaterializationsRootV2,
  publishControlPlaneMaterializationV2,
  readControlPlaneMaterializationV2,
  readDesiredSessionAgentV2,
  selectEffectiveControlPlaneV2,
  sessionAgentMaterializationsRootV2,
} from "./component-state-v2.ts";
import {
  approveNarrowImageBuildCandidate,
  captureNarrowImageBuildCandidate,
} from "../control/image-approval.ts";
import {
  approveNetworkCandidate,
  approveRuntimeIsolationControl,
  readControlApprovalSelection,
  type ControlApprovalSelection,
} from "../control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../control/candidates.ts";
import { createDependencyOverlayPlan } from "./dependency-overlays.ts";
import type { DockerImageInspect } from "./docker.ts";
import { composeProjectName, projectHash } from "./env.ts";
import {
  cleanupRunfreeImages,
  ensureRuntimeMaterialized,
  selectPreparedSessionAgent,
  selectEffectiveRuntimePlan,
  withActiveRuntime,
} from "./images.ts";
import type { RuntimePlan } from "./plan.ts";
import {
  sessionContainerTemplateFixture,
} from "./session-container.test-harness.ts";
import { sessionContainerTopologyProjectionV2 } from "./session-container-template.ts";
import { composeInterpolationVariables } from "./topology-digest.ts";
import {
  createRuntimeTopologyProjectionArtifactV2,
  runtimeTopologyProjectionArtifactDigestV2,
} from "./topology-digest-v2.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-images-"));
});

function writeRuntimeAssets(runtimeRoot: string): void {
  const sourceRoot = process.cwd();
  fs.mkdirSync(path.join(runtimeRoot, "agent", "agent-tools"), { recursive: true });
  fs.mkdirSync(path.join(runtimeRoot, "proxy"), { recursive: true });
  fs.copyFileSync(
    path.join(sourceRoot, "packages", "agent-runtime", "agent", "compose.yaml"),
    path.join(runtimeRoot, "agent", "compose.yaml"),
  );
  fs.copyFileSync(
    path.join(sourceRoot, "packages", "agent-runtime", "agent", "inspect-active-sessions.sh"),
    path.join(runtimeRoot, "agent", "inspect-active-sessions.sh"),
  );
  fs.copyFileSync(
    path.join(sourceRoot, "packages", "agent-runtime", "runtime-inputs.lock.json"),
    path.join(runtimeRoot, "runtime-inputs.lock.json"),
  );
  fs.copyFileSync(
    path.join(sourceRoot, "packages", "agent-runtime", "agent", "agent-tools", "package-lock.json"),
    path.join(runtimeRoot, "agent", "agent-tools", "package-lock.json"),
  );
  fs.copyFileSync(
    path.join(sourceRoot, "packages", "proxy", "package-lock.json"),
    path.join(runtimeRoot, "proxy", "package-lock.json"),
  );
}

function defaultPlan(): RuntimePlan {
  const runtimeRoot = path.join(tmp, "runtime");
  const projectRoot = path.join(tmp, "project");
  const stateDir = path.join(tmp, "state");
  const runfreeDir = path.join(projectRoot, ".runfree");
  const paths = {
    ...projectControlPaths(stateDir),
    agentEnvPath: path.join(runfreeDir, "config", "agent.env"),
    claudeConfigPath: path.join(stateDir, "claude.json"),
    claudeMcpConfigPath: path.join(stateDir, "mounts", "claude-mcp.json"),
    claudeDir: path.join(stateDir, "claude"),
    configPath: path.join(runfreeDir, "runfree.json"),
    codexDir: path.join(stateDir, "codex"),
    gitConfigPath: path.join(stateDir, "gitconfig"),
    inboxDir: path.join(stateDir, "inbox"),
    mcpOAuthPolicyPath: path.join(stateDir, "oauth-mediation-policy.json"),
    policyPath: path.join(runfreeDir, "network-policy.json"),
    projectCodexDirMaskPath: path.join(stateDir, "mounts", "project-codex-mask"),
    proxyCaCertDir: path.join(stateDir, "proxy-ca", "public"),
    proxyCaKeyDir: path.join(stateDir, "proxy-ca", "private"),
    runfreeDir,
    sessionsDir: path.join(stateDir, "sessions"),
    stateDir,
    tokenConfigPath: path.join(stateDir, "tokens.json"),
  };
  fs.mkdirSync(projectRoot, { recursive: true });
  writeRuntimeAssets(runtimeRoot);
  const renderedCompose = fs.readFileSync(path.join(runtimeRoot, "agent", "compose.yaml"), "utf8");
  const components = createRuntimeComponentState({
    embeddedAgentImageInputDigest: RUNFREE_RUNTIME_COMPONENTS.agentImageInputDigest,
    selectedAgentImageInputDigest: RUNFREE_RUNTIME_COMPONENTS.agentImageInputDigest,
    selectedAgentImageKind: "embedded",
    proxyImageInputDigest: RUNFREE_RUNTIME_COMPONENTS.proxyImageInputDigest,
    topologyDigest: sha256Digest(renderedCompose),
    hostHelperDigest: RUNFREE_RUNTIME_COMPONENTS.hostHelperDigest,
  });
  const projectId = projectHash(projectRoot);
  const composeProject = composeProjectName(projectRoot);
  const sessionContainerTemplate = sessionContainerTemplateFixture();
  const composeEnv = Object.fromEntries(
    composeInterpolationVariables(renderedCompose).map((name) => [name, `test-${name.toLowerCase()}`]),
  );
  const sessionTemplateDigest = runtimeTopologyProjectionArtifactDigestV2(
    createRuntimeTopologyProjectionArtifactV2({
      compose: renderedCompose,
      interpolationValues: composeEnv,
      controlPlane: { structure: {}, runtimeSignatures: {} },
      sessionTemplate: {
        structure: sessionContainerTopologyProjectionV2(sessionContainerTemplate),
        runtimeSignatures: {},
      },
    }, "session-template"),
  );
  return {
    projectRoot,
    project: { config: defaultConfig(), paths },
    paths,
    projectId,
    composeProjectName: composeProject,
    baseRuntimeRoot: runtimeRoot,
    projectRuntimeRoot: runtimeMaterializationRoot(stateDir, components.materializationDigest),
    runtimeDigest: "sha256:test",
    components,
    generationV2: {
      topology: {},
      controlPlane: createControlPlaneGenerationV2({
        projectId,
        composeProject,
        proxyImageInputDigest: RUNFREE_RUNTIME_COMPONENTS.proxyImageInputDigest,
        controlPlaneTopologyDigest: sha256Digest("control-plane-topology"),
        admissionContractEpoch: RUNTIME_ADMISSION_CONTRACT_EPOCH,
      }),
      sessionAgent: createSessionAgentGenerationInputsV2({
        selectedAgentImageInputDigest: RUNFREE_RUNTIME_COMPONENTS.agentImageInputDigest,
        sessionTemplateDigest,
        admissionContractEpoch: RUNTIME_ADMISSION_CONTRACT_EPOCH,
      }),
    },
    sessionContainerTemplate,
    renderedCompose,
    runfreeVersion: "0.0.0-test",
    network: {
      agentIp: "172.30.0.11",
      callbackSidecarIp: "172.30.0.12",
      proxyEgressGateway: "172.31.0.1",
      proxyEgressSubnet: "172.31.0.0/24",
      proxyEgressIp: "172.31.0.10",
      proxyIp: "172.30.0.10",
      subnet: "172.30.0.0/24",
    },
    agentImage: undefined,
    dependencyOverlays: createDependencyOverlayPlan(projectRoot, { mode: "off" }),
    gitRepositoryShape: { kind: "none" },
    gitLayout: {
      version: 1,
      kind: "workspace",
      hostProjectRoot: projectRoot,
      containerProjectRoot: "/workspace",
      containerCompatRoot: "/workspaces/project",
    },
    mcpOAuth: {
      callbackPort: 48484,
      callbackUrl: "http://localhost:48484/callback",
    },
    execution: {
      adminEnvProvider: { dockerClient: {}, resolveChildEnv: () => ({}) },
      composeEnv,
      dockerClientEnv: {},
      runtimeInputBuildEnv: {},
    },
  } as RuntimePlan;
}

function narrowProjectPlan(): RuntimePlan {
  const plan = defaultPlan();
  const imageDir = path.join(plan.projectRoot, ".runfree", "image");
  fs.mkdirSync(imageDir, { recursive: true });
  fs.writeFileSync(path.join(imageDir, "Dockerfile"), "ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\nCOPY marker /marker\n");
  fs.writeFileSync(path.join(imageDir, "marker"), "approved\n");
  const config = defaultConfig();
  const build = { context: ".runfree/image", dockerfile: ".runfree/image/Dockerfile" };
  config.runtime.agent = { build };
  plan.project.config = config;
  const selected = selectedAgentImageInput(plan.projectRoot, config);
  if (selected.kind !== "project") throw new Error("expected project image input");
  plan.projectId = projectHash(plan.projectRoot);
  plan.composeProjectName = composeProjectName(plan.projectRoot);
  plan.agentImage = {
    build,
    baseImage: `runfree/agent-base:sha256-${"a".repeat(64)}`,
    contextFingerprint: selected.contextFingerprint,
    contextKind: selected.contextKind,
    inputDigest: selected.digest,
    projectImage: projectAgentImageTag(plan.projectRoot, selected.digest),
    referencedLegacyInjectedArguments: selected.referencedLegacyInjectedArguments,
  };
  plan.components = createRuntimeComponentState({
    embeddedAgentImageInputDigest: RUNFREE_RUNTIME_COMPONENTS.agentImageInputDigest,
    selectedAgentImageInputDigest: selected.digest,
    selectedAgentImageKind: "project",
    proxyImageInputDigest: RUNFREE_RUNTIME_COMPONENTS.proxyImageInputDigest,
    topologyDigest: sha256Digest(plan.renderedCompose),
    hostHelperDigest: RUNFREE_RUNTIME_COMPONENTS.hostHelperDigest,
  });
  plan.generationV2 = {
    ...plan.generationV2,
    sessionAgent: createSessionAgentGenerationInputsV2({
      selectedAgentImageInputDigest: selected.digest,
      sessionTemplateDigest: plan.generationV2.sessionAgent.sessionTemplateDigest,
      admissionContractEpoch: plan.generationV2.sessionAgent.admissionContractEpoch,
    }),
  };
  plan.projectRuntimeRoot = runtimeMaterializationRoot(plan.paths.stateDir, plan.components.materializationDigest);
  return plan;
}

function inspectedImage(tag: string): { id: string; labels: Record<string, string> } {
  const proxy = tag.startsWith("runfree/proxy-runtime:");
  return {
    id: `sha256:${(proxy ? "b" : "a").repeat(64)}`,
    labels: {
      [RUNFREE_MANAGED_IMAGE_LABEL]: "true",
      [RUNFREE_DIGEST_SCHEMA_LABEL]: RUNFREE_DIGEST_SCHEMA_VERSION,
      [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: proxy
        ? RUNFREE_RUNTIME_COMPONENTS.proxyImageInputDigest
        : RUNFREE_RUNTIME_COMPONENTS.agentImageInputDigest,
      [RUNFREE_IMAGE_ROLE_LABEL]: proxy ? PROXY_RUNTIME_IMAGE_ROLE : AGENT_RUNTIME_IMAGE_ROLE,
    },
  };
}

function buildLabels(args: readonly string[]): Record<string, string> {
  const labels: Record<string, string> = {};
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] !== "--label") continue;
    const value = args[index + 1] ?? "";
    const separator = value.indexOf("=");
    if (separator < 1) throw new Error("invalid test Docker label");
    labels[value.slice(0, separator)] = value.slice(separator + 1);
    index += 1;
  }
  return labels;
}

class RuntimeImageDocker {
  readonly builds: string[][];
  readonly tags: Array<[string, string]> = [];
  readonly images = new Map<string, DockerImageInspect>();
  readonly inspections: string[] = [];
  buildStatusForRole?: (role: string) => number;
  inspectOverride?: (reference: string, inspected: DockerImageInspect | undefined) => DockerImageInspect | undefined;
  private projectBuild = 0;

  constructor(builds: string[][] = []) {
    this.builds = builds;
    const runtime = inspectedImage(agentRuntimeImageTag());
    const proxy = inspectedImage(proxyRuntimeImageTag());
    this.store(runtime, agentRuntimeImageTag(), `runfree/agent-base:sha256-${RUNFREE_RUNTIME_COMPONENTS.agentImageInputDigest.slice(7)}`);
    this.store(proxy, proxyRuntimeImageTag());
  }

  private store(image: DockerImageInspect, ...references: string[]): void {
    const stored = { ...image, labels: { ...image.labels } };
    this.images.set(image.id, stored);
    for (const reference of references) this.images.set(reference, stored);
  }

  seedProject(plan: RuntimePlan, id = `sha256:${"c".repeat(64)}`): string {
    const reference = plan.agentImage?.projectImage;
    const inputDigest = plan.agentImage?.inputDigest;
    if (!reference || !inputDigest) throw new Error("test project image plan is missing");
    this.store({
      id,
      labels: {
        [RUNFREE_MANAGED_IMAGE_LABEL]: "true",
        [RUNFREE_DIGEST_SCHEMA_LABEL]: RUNFREE_DIGEST_SCHEMA_VERSION,
        [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: inputDigest,
        [RUNFREE_IMAGE_ROLE_LABEL]: AGENT_PROJECT_IMAGE_ROLE,
        [PROJECT_ID_LABEL]: plan.projectId,
      },
    }, reference);
    return id;
  }

  seedProxy(id: string): void {
    this.store({ ...inspectedImage(proxyRuntimeImageTag()), id }, proxyRuntimeImageTag());
  }

  inspectImage(reference: string): DockerImageInspect | undefined {
    this.inspections.push(reference);
    const image = this.images.get(reference);
    const inspected = image
      ? { ...image, labels: { ...image.labels }, ...(image.onBuild ? { onBuild: [...image.onBuild] } : {}) }
      : undefined;
    return this.inspectOverride ? this.inspectOverride(reference, inspected) : inspected;
  }

  imageExists(reference: string): boolean {
    return this.images.has(reference);
  }

  tagImage(source: string, target: string): number {
    this.tags.push([source, target]);
    const image = this.images.get(source);
    if (!image) return 1;
    this.images.set(target, image);
    return 0;
  }

  buildImage(args: string[]): number {
    this.builds.push([...args]);
    const labels = buildLabels(args);
    const role = labels[RUNFREE_IMAGE_ROLE_LABEL] ?? "unknown";
    const status = this.buildStatusForRole?.(role) ?? 0;
    if (status !== 0) return status;
    let id: string;
    if (role === AGENT_PROJECT_IMAGE_ROLE) {
      this.projectBuild += 1;
      id = sha256Digest(`project-build-${this.projectBuild}`);
    } else if (role === PROXY_RUNTIME_IMAGE_ROLE) {
      id = `sha256:${"b".repeat(64)}`;
    } else {
      id = `sha256:${"a".repeat(64)}`;
    }
    const references: string[] = [];
    for (let index = 0; index < args.length; index += 1) {
      if (args[index] === "--tag" && args[index + 1]) references.push(args[index + 1] as string);
    }
    this.store({ id, labels }, ...references);
    return 0;
  }
}

function projectBuildDocker(builds: string[][]) {
  return new RuntimeImageDocker(builds) as never;
}

test("default runtime materialization returns an active plan without mutating the input", () => {
  const plan = defaultPlan();
  const before = { ...plan };
  const docker = new RuntimeImageDocker();
  let selectedImageObservedAfterV1 = false;
  docker.inspectOverride = (reference, inspected) => {
    if (reference === agentRuntimeImageTag()
      && fs.existsSync(path.join(plan.projectRuntimeRoot, "generation.json"))) {
      selectedImageObservedAfterV1 = true;
      expect(readDesiredSessionAgentV2(plan.paths.stateDir)).toBeUndefined();
    }
    return inspected;
  };
  const active = ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { run: () => 0 } as never,
    force: false,
  });
  expect(plan).toEqual(before);
  expect("activeRuntime" in plan).toBe(false);
  expect(active.activeRuntime.activeRuntimeRoot).toBe(plan.projectRuntimeRoot);
  expect(active.activeRuntime.agentImage).toBe(agentRuntimeImageTag());
  expect(active.activeRuntime.proxyImage).toBe(proxyRuntimeImageTag());
  expect(active.activeRuntime.state).toBe("desired");
  expect(readControlPlaneMaterializationV2(
    plan.paths.stateDir,
    active.activeRuntime.controlPlaneMaterializationDigest as string,
  )).toMatchObject({
    projectId: plan.projectId,
    composeProject: plan.composeProjectName,
    generation: plan.generationV2.controlPlane,
    proxyImageRef: proxyRuntimeImageTag(),
    proxyImageId: `sha256:${"b".repeat(64)}`,
    renderedControlPlaneSha256: plan.generationV2.controlPlane.controlPlaneTopologyDigest,
  });
  expect(active.activeRuntime.manifest?.components).toEqual(plan.components);
  expect(readEffectiveRuntimeGeneration(plan.paths.stateDir)).toBeUndefined();
  expect(selectedImageObservedAfterV1).toBe(true);

  const desiredSessionAgent = readDesiredSessionAgentV2(plan.paths.stateDir);
  const selectedId = `sha256:${"a".repeat(64)}`;
  expect(desiredSessionAgent?.manifest).toMatchObject({
    projectId: plan.projectId,
    composeProject: plan.composeProjectName,
    selectedAgentImageRef: agentRuntimeImageTag(),
    selectedAgentImageId: selectedId,
    selectedAgentImageKind: "embedded",
  });
  expect(desiredSessionAgent?.manifest.generation).toEqual({
    ...plan.generationV2.sessionAgent,
    selectedAgentImageId: selectedId,
  });
  expect(docker.inspections).toContain(selectedId);

  const selected = selectEffectiveRuntimePlan(active);
  expect(selected.activeRuntime.state).toBe("effective");
  expect(readEffectiveRuntimeGeneration(plan.paths.stateDir)?.components).toEqual(plan.components);
});

test("published runtime materializations are reused but never overwritten", () => {
  const plan = defaultPlan();
  const docker = new RuntimeImageDocker() as never;
  const io = { run: () => 0 } as never;
  const first = ensureRuntimeMaterialized(plan, { docker, io, force: false });
  const manifestStat = fs.statSync(path.join(first.activeRuntime.activeRuntimeRoot, "generation.json"));
  const second = ensureRuntimeMaterialized(plan, { docker, io, force: false });
  expect(second.activeRuntime.activeRuntimeRoot).toBe(first.activeRuntime.activeRuntimeRoot);
  expect(fs.statSync(path.join(second.activeRuntime.activeRuntimeRoot, "generation.json")).ino).toBe(manifestStat.ino);

  fs.appendFileSync(second.activeRuntime.composeFile, "# modified\n");
  const desiredBeforeFailure = readDesiredSessionAgentV2(plan.paths.stateDir);
  expect(() => ensureRuntimeMaterialized(plan, { docker, io, force: false })).toThrow(
    "existing runtime materialization has modified Compose content",
  );
  expect(readDesiredSessionAgentV2(plan.paths.stateDir)).toEqual(desiredBeforeFailure);
});

/**
 * Record the narrow image-build approval without building.
 *
 * A cached project image carries exactly the authority a built one does, so a
 * cache-hit launch prepares approval too. A fixture that seeds the image but
 * not its approval is a project whose approval is genuinely missing, and it now
 * correctly prompts — these tests are about reuse, so they approve first.
 */
function approveNarrowImage(plan: RuntimePlan): void {
  const build = plan.agentImage?.build;
  if (!build) throw new Error("test narrow image plan is missing");
  const candidate = captureNarrowImageBuildCandidate(
    plan.projectRoot,
    build,
    plan.paths.controlCandidatesDir,
  );
  approveNarrowImageBuildCandidate(plan.projectRoot, plan.project, candidate, "typed-host-command");
}

test("project selection persists only its selected exact image identity", () => {
  const plan = narrowProjectPlan();
  const docker = new RuntimeImageDocker();
  const selectedId = docker.seedProject(plan);
  approveNarrowImage(plan);

  ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { confirm: () => { throw new Error("an approved cached project image must not prompt"); } } as never,
    force: false,
  });

  const desired = readDesiredSessionAgentV2(plan.paths.stateDir);
  expect(desired?.manifest).toMatchObject({
    selectedAgentImageRef: plan.agentImage?.projectImage,
    selectedAgentImageId: selectedId,
    selectedAgentImageKind: "project",
  });
  expect(desired?.manifest.generation.selectedAgentImageId).toBe(selectedId);
  expect(docker.inspections).toContain(selectedId);
});

test("same-input proxy image replacement publishes a new exact control-plane materialization", () => {
  const plan = defaultPlan();
  const docker = new RuntimeImageDocker();
  const options = {
    docker: docker as never,
    io: { run: () => 0 } as never,
    force: false,
  };
  const first = ensureRuntimeMaterialized(plan, options);
  const firstDigest = first.activeRuntime.controlPlaneMaterializationDigest as string;
  const firstManifest = readControlPlaneMaterializationV2(plan.paths.stateDir, firstDigest);
  const rebuiltProxyId = sha256Digest("rebuilt-proxy-image");
  docker.seedProxy(rebuiltProxyId);

  const second = ensureRuntimeMaterialized(plan, options);
  const secondDigest = second.activeRuntime.controlPlaneMaterializationDigest as string;

  expect(secondDigest).not.toBe(firstDigest);
  expect(readControlPlaneMaterializationV2(plan.paths.stateDir, firstDigest)).toEqual(firstManifest);
  expect(readControlPlaneMaterializationV2(plan.paths.stateDir, secondDigest)).toMatchObject({
    generation: plan.generationV2.controlPlane,
    proxyImageId: rebuiltProxyId,
  });
});

test("selected exact identity failure does not fall back to a previous desired session image", () => {
  const plan = narrowProjectPlan();
  const docker = new RuntimeImageDocker();
  const selectedId = docker.seedProject(plan);
  approveNarrowImage(plan);
  const io = { confirm: () => { throw new Error("an approved cached project image must not prompt"); } } as never;
  ensureRuntimeMaterialized(plan, { docker: docker as never, io, force: false });
  const previous = readDesiredSessionAgentV2(plan.paths.stateDir);
  docker.inspectOverride = (reference, inspected) => {
    return reference === selectedId ? undefined : inspected;
  };

  expect(() => ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io,
    force: false,
  })).toThrow("selected agent image ID failed exact managed identity inspection");
  expect(readDesiredSessionAgentV2(plan.paths.stateDir)).toEqual(previous);
});

test("proxy immutable-ID proof fails before publishing v2 control-plane or session selection", () => {
  const plan = defaultPlan();
  const docker = new RuntimeImageDocker();
  const proxyId = `sha256:${"b".repeat(64)}`;
  docker.inspectOverride = (reference, inspected) => reference === proxyId ? undefined : inspected;

  expect(() => ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { run: () => 0 } as never,
    force: false,
  })).toThrow("control-plane proxy image ID failed exact managed identity inspection");

  expect(fs.existsSync(controlPlaneMaterializationsRootV2(plan.paths.stateDir))).toBe(false);
  expect(readDesiredSessionAgentV2(plan.paths.stateDir)).toBeUndefined();
});

test("project image build failure leaves the previous desired session image selected", () => {
  const plan = narrowProjectPlan();
  const docker = new RuntimeImageDocker();
  docker.seedProject(plan);
  approveNarrowImage(plan);
  ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { confirm: () => { throw new Error("an approved cached project image must not prompt"); } } as never,
    force: false,
  });
  const previous = readDesiredSessionAgentV2(plan.paths.stateDir);
  docker.buildStatusForRole = (role) => role === AGENT_PROJECT_IMAGE_ROLE ? 41 : 0;

  expect(() => ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { confirm: () => true } as never,
    force: true,
  })).toThrow("project agent image build failed with status 41");
  expect(readDesiredSessionAgentV2(plan.paths.stateDir)).toEqual(previous);
});

test("forced same-input project rebuild selects a new exact materialization and retains the old one", () => {
  const plan = narrowProjectPlan();
  const docker = new RuntimeImageDocker();
  const io = { confirm: () => true } as never;
  ensureRuntimeMaterialized(plan, { docker: docker as never, io, force: false });
  const first = readDesiredSessionAgentV2(plan.paths.stateDir);
  ensureRuntimeMaterialized(plan, { docker: docker as never, io, force: true });
  const second = readDesiredSessionAgentV2(plan.paths.stateDir);

  expect(second?.manifest.generation.sessionAgentGenerationDigest)
    .toBe(first?.manifest.generation.sessionAgentGenerationDigest);
  expect(second?.manifest.selectedAgentImageId).not.toBe(first?.manifest.selectedAgentImageId);
  expect(second?.manifest.sessionAgentMaterializationDigest)
    .not.toBe(first?.manifest.sessionAgentMaterializationDigest);
  expect(fs.readdirSync(sessionAgentMaterializationsRootV2(plan.paths.stateDir))).toHaveLength(2);
});

test("cleanup removes only exact zero-reference materialization paths and is idempotent", () => {
  const plan = defaultPlan();
  const docker = new RuntimeImageDocker();
  const active = ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { run: () => 0 } as never,
    force: false,
  });
  const desired = readDesiredSessionAgentV2(plan.paths.stateDir);
  if (!desired || !active.activeRuntime.controlPlaneMaterializationDigest) {
    throw new Error("expected current v2 materializations");
  }
  const staleDigest = `sha256:${"e".repeat(64)}`;
  const staleDirectoryName = `sha256-${"e".repeat(64)}`;
  const staleSessionRoot = path.join(sessionAgentMaterializationsRootV2(plan.paths.stateDir), staleDirectoryName);
  const staleControlRoot = path.join(controlPlaneMaterializationsRootV2(plan.paths.stateDir), staleDirectoryName);
  fs.mkdirSync(staleSessionRoot, { recursive: true });
  fs.writeFileSync(path.join(staleSessionRoot, "session-template.json"), "artifact-only crash residue\n");
  fs.mkdirSync(staleControlRoot, { recursive: true });
  fs.writeFileSync(path.join(staleControlRoot, "materialization.json"), "incomplete crash residue\n");
  const io = {
    capture(command: string, args: string[]) {
      if (command === "docker" && args.slice(0, 3).join(" ") === "container ls --all") {
        return { status: 0, stdout: "", stderr: "" };
      }
      throw new Error(`unexpected cleanup command: ${command} ${args.join(" ")}`);
    },
  } as RuntimeIO;
  const context = {
    projectRoot: plan.projectRoot,
    project: plan.project,
    runtimeRoot: plan.baseRuntimeRoot,
    env: {},
  } satisfies RuntimeContext;
  const candidates = {
    controlPlaneMaterializationDigest: active.activeRuntime.controlPlaneMaterializationDigest,
    sessionAgentMaterializationDigest: desired.selection.sessionAgentMaterializationDigest,
  };

  cleanupRunfreeImages(context, docker as never, io, candidates);
  cleanupRunfreeImages(context, docker as never, io, candidates);

  expect(fs.existsSync(staleSessionRoot), staleDigest).toBe(false);
  expect(fs.existsSync(staleControlRoot), staleDigest).toBe(false);
  expect(fs.readdirSync(sessionAgentMaterializationsRootV2(plan.paths.stateDir))).toHaveLength(1);
  expect(fs.readdirSync(controlPlaneMaterializationsRootV2(plan.paths.stateDir))).toHaveLength(1);
});

test("cleanup refuses materialization deletion when an exact path contains a hard link", () => {
  const plan = defaultPlan();
  const docker = new RuntimeImageDocker();
  const active = ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { run: () => 0 } as never,
    force: false,
  });
  const desired = readDesiredSessionAgentV2(plan.paths.stateDir);
  if (!desired || !active.activeRuntime.controlPlaneMaterializationDigest) {
    throw new Error("expected current v2 materializations");
  }
  const staleRoot = path.join(
    sessionAgentMaterializationsRootV2(plan.paths.stateDir),
    `sha256-${"f".repeat(64)}`,
  );
  fs.mkdirSync(staleRoot, { recursive: true });
  const outside = path.join(tmp, "outside-materialization");
  fs.writeFileSync(outside, "do not remove\n");
  fs.linkSync(outside, path.join(staleRoot, "materialization.json"));
  const io = {
    capture(command: string, args: string[]) {
      if (command === "docker" && args.slice(0, 3).join(" ") === "container ls --all") {
        return { status: 0, stdout: "", stderr: "" };
      }
      throw new Error(`unexpected cleanup command: ${command} ${args.join(" ")}`);
    },
  } as RuntimeIO;

  cleanupRunfreeImages({
    projectRoot: plan.projectRoot,
    project: plan.project,
    runtimeRoot: plan.baseRuntimeRoot,
    env: {},
  }, docker as never, io, {
    controlPlaneMaterializationDigest: active.activeRuntime.controlPlaneMaterializationDigest,
    sessionAgentMaterializationDigest: desired.selection.sessionAgentMaterializationDigest,
  });

  expect(fs.readFileSync(outside, "utf8")).toBe("do not remove\n");
  expect(fs.existsSync(staleRoot)).toBe(true);
});

test("one verified embedded agent tag is retagged instead of rebuilding the same inputs", () => {
  const plan = defaultPlan();
  const docker = new RuntimeImageDocker();
  docker.images.delete(`runfree/agent-base:sha256-${RUNFREE_RUNTIME_COMPONENTS.agentImageInputDigest.slice(7)}`);
  ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { run: () => 0 } as never,
    force: false,
  });

  expect(docker.tags).toEqual([[agentRuntimeImageTag(), expect.stringMatching(/^runfree\/agent-base:sha256-/)]]);
  expect(docker.builds.filter((args) => buildLabels(args)[RUNFREE_IMAGE_ROLE_LABEL] === AGENT_RUNTIME_IMAGE_ROLE))
    .toEqual([]);
});

test("contradictory embedded labels rebuild one dual-tagged agent image", () => {
  const plan = defaultPlan();
  const docker = new RuntimeImageDocker();
  for (const reference of [agentRuntimeImageTag(), `runfree/agent-base:sha256-${RUNFREE_RUNTIME_COMPONENTS.agentImageInputDigest.slice(7)}`]) {
    const image = docker.images.get(reference);
    if (!image) throw new Error("missing test runtime image");
    docker.images.set(reference, {
      ...image,
      labels: {
        ...image.labels,
        [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: `sha256:${"b".repeat(64)}`,
      },
    });
  }
  ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { run: () => 0 } as never,
    force: false,
  });

  const runtimeBuilds = docker.builds.filter(
    (args) => buildLabels(args)[RUNFREE_IMAGE_ROLE_LABEL] === AGENT_RUNTIME_IMAGE_ROLE,
  );
  expect(runtimeBuilds).toHaveLength(1);
  expect(runtimeBuilds[0]).toEqual(expect.arrayContaining([
    "--tag",
    agentRuntimeImageTag(),
    "--tag",
    expect.stringMatching(/^runfree\/agent-base:sha256-/),
    "--label",
    `io.runfree.image-input-digest=${RUNFREE_RUNTIME_COMPONENTS.agentImageInputDigest}`,
  ]));
});

test("unapproved narrow project bytes fail before any Docker build", () => {
  const plan = narrowProjectPlan();
  const builds: string[][] = [];

  expect(() => ensureRuntimeMaterialized(plan, {
    docker: projectBuildDocker(builds),
    io: { confirm: () => false } as never,
    force: false,
  })).toThrow("exact pre-sandbox Docker build approval is required");

  expect(builds).toEqual([]);
  expect(fs.existsSync(plan.paths.controlApprovalsPath)).toBe(false);
});

test("narrow project build consumes the approved stage when desired bytes change during review", () => {
  const plan = narrowProjectPlan();
  const desiredMarker = path.join(plan.projectRoot, ".runfree", "image", "marker");
  const builds: string[][] = [];

  ensureRuntimeMaterialized(plan, {
    docker: projectBuildDocker(builds),
    io: {
      confirm: () => {
        fs.writeFileSync(desiredMarker, "drifted during review\n");
        return true;
      },
    } as never,
    force: false,
  });

  const projectBuild = builds.find((args) => args.includes(plan.agentImage?.projectImage ?? "missing"));
  const approvedContext = projectBuild?.at(-1);
  expect(approvedContext?.startsWith(path.join(plan.paths.controlApprovedDir, "image-build"))).toBe(true);
  expect(fs.readFileSync(path.join(approvedContext ?? "", "marker"), "utf8")).toBe("approved\n");
  expect(fs.readFileSync(desiredMarker, "utf8")).toBe("drifted during review\n");
});

test("corrupt stored image-build approval re-prompts and rebuilds from a replaced snapshot", () => {
  const plan = narrowProjectPlan();
  const docker = new RuntimeImageDocker();
  let prompts = 0;
  const io = { confirm: () => { prompts += 1; return true; } } as never;
  ensureRuntimeMaterialized(plan, { docker: docker as never, io, force: false });
  expect(prompts).toBe(1);

  const approvedRoot = path.join(plan.paths.controlApprovedDir, "image-build");
  const digestDirectory = fs.readdirSync(approvedRoot).find((entry) => !entry.startsWith("."));
  const approvedMarker = path.join(approvedRoot, digestDirectory ?? "missing", "context", "marker");
  fs.writeFileSync(approvedMarker, "corrupted after approval\n");

  ensureRuntimeMaterialized(plan, { docker: docker as never, io, force: true });

  expect(prompts).toBe(2);
  expect(fs.readFileSync(approvedMarker, "utf8")).toBe("approved\n");
});

test("corrupt stored approval with a declined re-prompt aborts without republishing", () => {
  const plan = narrowProjectPlan();
  const docker = new RuntimeImageDocker();
  ensureRuntimeMaterialized(plan, { docker: docker as never, io: { confirm: () => true } as never, force: false });

  const approvedRoot = path.join(plan.paths.controlApprovedDir, "image-build");
  const digestDirectory = fs.readdirSync(approvedRoot).find((entry) => !entry.startsWith("."));
  const approvedMarker = path.join(approvedRoot, digestDirectory ?? "missing", "context", "marker");
  fs.writeFileSync(approvedMarker, "corrupted after approval\n");
  const recordBefore = fs.readFileSync(plan.paths.controlApprovalsPath, "utf8");

  expect(() => ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { confirm: () => false } as never,
    force: true,
  })).toThrow("exact pre-sandbox Docker build approval is required");

  expect(fs.readFileSync(approvedMarker, "utf8")).toBe("corrupted after approval\n");
  expect(fs.readFileSync(plan.paths.controlApprovalsPath, "utf8")).toBe(recordBefore);
});

// Retired: "checkout-binding mismatch on stored approvals aborts instead of
// re-prompting" pinned the inverse of the current invariant — it asserted the
// image path throws and must not prompt, on the assumption that a mismatch had
// no recovery. The recovery gate now owns that case and runs before image
// materialization on every entry. This is its successor: the image path still
// must not prompt under a mismatch, and must not write a one-subject selection
// over the configuration approvals. The consent cases live in
// control/approval-recovery.test.ts.
test("a binding mismatch reaches the image path only through the recovery gate", () => {
  const plan = narrowProjectPlan();
  const docker = new RuntimeImageDocker();
  ensureRuntimeMaterialized(plan, { docker: docker as never, io: { confirm: () => true } as never, force: false });

  const approvalsPath = plan.paths.controlApprovalsPath;
  const selection = JSON.parse(fs.readFileSync(approvalsPath, "utf8")) as { checkoutBinding: { rootInode: string } };
  selection.checkoutBinding.rootInode = "999999999";
  const mismatched = `${JSON.stringify(selection, null, 2)}\n`;
  fs.writeFileSync(approvalsPath, mismatched);

  expect(() => ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { confirm: () => { throw new Error("the image path must not prompt under a mismatch"); } } as never,
    force: true,
  })).toThrow("the directory at this path was replaced");

  // The configuration subjects survive byte for byte: an image prompt is never
  // the thing that discards them.
  expect(fs.readFileSync(approvalsPath, "utf8")).toBe(mismatched);
});

test("a cached image with a valid approval needs no prompt, no build, and no staging", () => {
  const plan = narrowProjectPlan();
  const docker = new RuntimeImageDocker();
  ensureRuntimeMaterialized(plan, { docker: docker as never, io: { confirm: () => true } as never, force: false });
  docker.seedProject(plan);
  const buildsAfterFirst = docker.builds.length;
  const stagedRoot = path.join(plan.paths.controlCandidatesDir, "image-build");
  const candidatesBefore = fs.readdirSync(stagedRoot).length;

  ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { confirm: () => { throw new Error("a valid cached approval must not prompt"); } } as never,
    force: false,
  });

  expect(docker.builds.length).toBe(buildsAfterFirst);
  // Staging copies every file in the narrow context and then deletes the copy
  // again on an already-approved digest. Deriving the subject digest from the
  // manifest the plan already carries is what keeps that off every launch.
  expect(fs.readdirSync(stagedRoot).length).toBe(candidatesBefore);
});

test("a cached image with no approval prompts and refuses when declined", () => {
  const plan = narrowProjectPlan();
  const docker = new RuntimeImageDocker();
  ensureRuntimeMaterialized(plan, { docker: docker as never, io: { confirm: () => true } as never, force: false });
  docker.seedProject(plan);
  fs.rmSync(plan.paths.controlApprovalsPath);
  const buildsBefore = docker.builds.length;

  expect(() => ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { confirm: () => false } as never,
    force: false,
  })).toThrow("exact pre-sandbox Docker build approval is required");

  // The refusal lands before the sensitive side effect: no new build ran.
  expect(docker.builds.length).toBe(buildsBefore);
});

test("a cached image whose approved snapshot is corrupt cannot be used", () => {
  const plan = narrowProjectPlan();
  const docker = new RuntimeImageDocker();
  ensureRuntimeMaterialized(plan, { docker: docker as never, io: { confirm: () => true } as never, force: false });
  docker.seedProject(plan);
  const approvedRoot = path.join(plan.paths.controlApprovedDir, "image-build");
  const digestDirectory = fs.readdirSync(approvedRoot).find((entry) => !entry.startsWith("."));
  fs.writeFileSync(path.join(approvedRoot, digestDirectory ?? "missing", "context", "marker"), "corrupted\n");

  expect(() => ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { confirm: () => false } as never,
    force: false,
  })).toThrow("exact pre-sandbox Docker build approval is required");
});

/** The configuration consent a launch collects before the image path runs. */
function approveConfigurationSubjects(plan: RuntimePlan): string {
  fs.writeFileSync(plan.paths.policyPath, `{"version":2,"hosts":["example.com"]}\n`);
  const candidate = captureDesiredPolicyCandidate(plan.projectRoot, plan.paths.controlCandidatesDir);
  approveNetworkCandidate(plan.projectRoot, plan.project, candidate, "network-project", "interactive");
  approveNetworkCandidate(plan.projectRoot, plan.project, candidate, "network-local", "interactive");
  approveRuntimeIsolationControl(plan.projectRoot, plan.project, "interactive");
  return fs.readFileSync(plan.paths.controlApprovalsPath, "utf8");
}

// Image consent is separate from configuration consent and may follow it.
// Declining the image must start nothing and must not cost the configuration
// review, or every retry would re-ask for settings the operator already agreed
// to.
test("a declined image after configuration approval starts nothing and keeps the configuration consent", () => {
  const plan = narrowProjectPlan();
  const docker = new RuntimeImageDocker();
  const approved = approveConfigurationSubjects(plan);
  docker.seedProject(plan);
  const buildsBefore = docker.builds.length;

  expect(() => ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { confirm: () => false } as never,
    force: false,
  })).toThrow("exact pre-sandbox Docker build approval is required");

  expect(docker.builds.length).toBe(buildsBefore);
  expect(readDesiredSessionAgentV2(plan.paths.stateDir)).toBeUndefined();
  expect(fs.readFileSync(plan.paths.controlApprovalsPath, "utf8")).toBe(approved);

  // The retry approves the image and nothing else: the three configuration
  // records keep their original timestamps, so none of them was re-consented.
  ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { confirm: () => true } as never,
    force: false,
  });
  const after = readControlApprovalSelection(plan.projectRoot, plan.project);
  const before = JSON.parse(approved) as ControlApprovalSelection;
  expect(after?.subjects["image-build"]).toBeDefined();
  for (const subjectType of ["network-project", "network-local", "runtime-isolation"] as const) {
    expect(after?.subjects[subjectType]).toEqual(before.subjects[subjectType]);
  }
});

// The same decline under the deferred-selection entry, which is the one a
// per-session launch uses: preparation refuses before the commit, so the
// session image selected by the previous launch is the one still selected.
test("a declined image under deferred selection selects no session image", () => {
  const plan = narrowProjectPlan();
  const docker = new RuntimeImageDocker();
  approveConfigurationSubjects(plan);
  docker.seedProject(plan);
  approveNarrowImage(plan);
  const prepared = ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { confirm: () => { throw new Error("an approved cached image must not prompt"); } } as never,
    force: false,
    deferSelection: true,
  });
  expect(readDesiredSessionAgentV2(plan.paths.stateDir)).toBeUndefined();
  selectPreparedSessionAgent(prepared, docker as never);
  const selected = readDesiredSessionAgentV2(plan.paths.stateDir);
  expect(selected).toBeDefined();

  fs.rmSync(plan.paths.controlApprovalsPath);
  const buildsBefore = docker.builds.length;

  expect(() => ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { confirm: () => false } as never,
    force: false,
    deferSelection: true,
  })).toThrow("exact pre-sandbox Docker build approval is required");

  expect(docker.builds.length).toBe(buildsBefore);
  expect(readDesiredSessionAgentV2(plan.paths.stateDir)).toEqual(selected);
});

test("selectPreparedSessionAgent still refuses an approval that changed during preparation", () => {
  const plan = narrowProjectPlan();
  const docker = new RuntimeImageDocker();
  const active = ensureRuntimeMaterialized(plan, {
    docker: docker as never,
    io: { confirm: () => true } as never,
    force: false,
    deferSelection: true,
  });
  fs.rmSync(plan.paths.controlApprovalsPath);

  expect(() => selectPreparedSessionAgent(active, docker as never))
    .toThrow("image approval changed during preparation");
});

test("withActiveRuntime attaches materialization without mutating plan", () => {
  const plan = { baseRuntimeRoot: "/base" } as RuntimePlan;
  const materialization = {
    activeRuntimeRoot: "/active",
    composeFile: "/active/agent/compose.yaml",
    composeDirectory: "/active/agent",
    runtimeDigest: "sha256:test",
    materialized: true,
    agentImage: "runfree/agent:test",
    proxyImage: "runfree/proxy:test",
    state: "desired" as const,
  };
  const active = withActiveRuntime(plan, materialization);
  expect(active.activeRuntime.activeRuntimeRoot).toBe("/active");
  expect("activeRuntime" in plan).toBe(false);
});

test("cleanup removes exact zero-reference project image IDs; a v1 manifest reference confers no retention", () => {
  const plan = defaultPlan();
  const dockerfile = path.join(plan.projectRoot, ".runfree", "image", "Dockerfile");
  fs.mkdirSync(path.dirname(dockerfile), { recursive: true });
  fs.writeFileSync(dockerfile, "ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\n");
  plan.project.config = {
    ...defaultConfig(),
    runtime: {
      ...defaultConfig().runtime,
      agent: { build: { context: ".runfree/image", dockerfile: ".runfree/image/Dockerfile" } },
    },
  };
  const selected = selectedAgentImageInput(plan.projectRoot, plan.project.config);
  expect(selected.kind).toBe("project");
  if (selected.kind !== "project") throw new Error("expected project agent image");
  const desired = projectAgentImageTag(plan.projectRoot, selected.digest);
  const projectId = projectHash(plan.projectRoot);
  const projectPrefix = `runfree/agent-project:${projectId}-`;
  const effective = `${projectPrefix}${"b".repeat(64)}`;
  const effectiveId = `sha256:${"b".repeat(64)}`;
  const staleId = `sha256:${"d".repeat(64)}`;
  const manifest = {
    schemaVersion: 1 as const,
    projectId,
    composeProject: composeProjectName(plan.projectRoot),
    components: plan.components,
    images: { agent: effective, proxy: proxyRuntimeImageTag() },
    renderedComposeSha256: sha256Digest(plan.renderedCompose),
  };
  const manifestPath = runtimeGenerationManifestPath(plan.paths.stateDir, plan.components.materializationDigest);
  fs.mkdirSync(path.dirname(manifestPath), { recursive: true });
  fs.writeFileSync(manifestPath, serializeRuntimeGenerationManifest(manifest));
  selectEffectiveRuntimeGeneration(plan.paths.stateDir, plan.components.materializationDigest);

  const removed: string[][] = [];
  const removedIds = new Set<string>();
  const imageInspect = (id: string): DockerImageInspect | undefined => {
    const exactId = id === effective ? effectiveId : id;
    if (exactId !== effectiveId && exactId !== staleId) return undefined;
    return {
      architecture: "amd64",
      id: exactId,
      os: "linux",
      labels: {
        [RUNFREE_MANAGED_IMAGE_LABEL]: "true",
        [PROJECT_ID_LABEL]: projectId,
        [RUNFREE_IMAGE_ROLE_LABEL]: AGENT_PROJECT_IMAGE_ROLE,
      },
    };
  };
  const io = {
    capture(command: string, args: string[]) {
      if (command === "docker" && args.slice(0, 3).join(" ") === "container ls --all") {
        return { status: 0, stdout: "", stderr: "" };
      }
      if (command === "docker" && args.slice(0, 3).join(" ") === "image ls --no-trunc") {
        return {
          status: 0,
          stdout: [effectiveId, staleId].filter((id) => !removedIds.has(id)).join("\n"),
          stderr: "",
        };
      }
      // The L5d pre-removal re-check: ONE batched, uncached inspect of every
      // listed id, answered as a strict JSON array.
      if (command === "docker" && args.slice(0, 2).join(" ") === "image inspect") {
        const requested = args.slice(2);
        const inspections = requested.map((id) => {
          const image = imageInspect(id);
          if (!image) return undefined;
          return { Id: image.id, Config: { Labels: image.labels } };
        });
        if (inspections.some((image) => image === undefined)) {
          return { status: 1, stdout: "[]", stderr: "No such image" };
        }
        return { status: 0, stdout: JSON.stringify(inspections), stderr: "" };
      }
      throw new Error(`unexpected cleanup command: ${command} ${args.join(" ")}`);
    },
  } as RuntimeIO;
  cleanupRunfreeImages({
    projectRoot: plan.projectRoot,
    project: plan.project,
    runtimeRoot: plan.baseRuntimeRoot,
    env: {},
    runtimeComponents: plan.components,
    agentImage: desired,
  } satisfies RuntimeContext, {
    inspectImage: imageInspect,
    removeImages(refs: string[]) {
      removed.push(refs);
      for (const ref of refs) removedIds.add(ref);
      return 0;
    },
  } as never, io);
  cleanupRunfreeImages({
    projectRoot: plan.projectRoot,
    project: plan.project,
    runtimeRoot: plan.baseRuntimeRoot,
    env: {},
    runtimeComponents: plan.components,
    agentImage: desired,
  } satisfies RuntimeContext, {
    inspectImage: imageInspect,
    removeImages(refs: string[]) {
      removed.push(refs);
      for (const ref of refs) removedIds.add(ref);
      return 0;
    },
  } as never, io);

  // Both project images are unreferenced by any session, desired selection,
  // or in-progress transaction; the v1 materialization manifest naming one of
  // them no longer retains it. Removal stays exact-ID-only.
  expect(removed).toEqual([[effectiveId, staleId]]);
});

type GcInspectAnswer = (ids: string[], labels: Record<string, string>) => { status: number; stdout: string; stderr: string };

test.each<[string, GcInspectAnswer]>([
  // L5d fail-closed matrix for the ONE batched pre-removal re-inspection:
  // every deviation must skip cleanup entirely rather than shrink the set.
  ["a vanished id fails the whole batch", (ids) => ({ status: 1, stdout: "[]", stderr: `No such image: ${ids[0]}` })],
  ["a short array is not the listed set", (ids, labels) => ({
    status: 0,
    stdout: JSON.stringify(ids.slice(1).map((id) => ({ Id: id, Config: { Labels: labels } }))),
    stderr: "",
  })],
  ["duplicate elements are refused", (ids, labels) => ({
    status: 0,
    stdout: JSON.stringify(ids.map(() => ({ Id: ids[0], Config: { Labels: labels } }))),
    stderr: "",
  })],
  ["a foreign element is refused even at the right count", (ids, labels) => ({
    status: 0,
    stdout: JSON.stringify([
      { Id: `sha256:${"9".repeat(64)}`, Config: { Labels: labels } },
      ...ids.slice(1).map((id) => ({ Id: id, Config: { Labels: labels } })),
    ]),
    stderr: "",
  })],
  ["a label change between ls and inspect is refused", (ids, labels) => ({
    status: 0,
    stdout: JSON.stringify(ids.map((id, index) => ({
      Id: id,
      Config: { Labels: index === 0 ? { ...labels, [RUNFREE_IMAGE_ROLE_LABEL]: "agent-runtime" } : labels },
    }))),
    stderr: "",
  })],
])("cleanup removes nothing when %s", (_kind, inspectAnswer) => {
  const plan = defaultPlan();
  const dockerfile = path.join(plan.projectRoot, ".runfree", "image", "Dockerfile");
  fs.mkdirSync(path.dirname(dockerfile), { recursive: true });
  fs.writeFileSync(dockerfile, "ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\n");
  plan.project.config = {
    ...defaultConfig(),
    runtime: {
      ...defaultConfig().runtime,
      agent: { build: { context: ".runfree/image", dockerfile: ".runfree/image/Dockerfile" } },
    },
  };
  const labels = {
    [RUNFREE_MANAGED_IMAGE_LABEL]: "true",
    [PROJECT_ID_LABEL]: projectHash(plan.projectRoot),
    [RUNFREE_IMAGE_ROLE_LABEL]: AGENT_PROJECT_IMAGE_ROLE,
  };
  const staleIds = [`sha256:${"b".repeat(64)}`, `sha256:${"d".repeat(64)}`];
  const removed: string[][] = [];
  const io = {
    capture(command: string, args: string[]) {
      if (command === "docker" && args.slice(0, 3).join(" ") === "container ls --all") {
        return { status: 0, stdout: "", stderr: "" };
      }
      if (command === "docker" && args.slice(0, 3).join(" ") === "image ls --no-trunc") {
        return { status: 0, stdout: staleIds.join("\n"), stderr: "" };
      }
      if (command === "docker" && args.slice(0, 2).join(" ") === "image inspect") {
        return inspectAnswer(args.slice(2), labels);
      }
      throw new Error(`unexpected cleanup command: ${command} ${args.join(" ")}`);
    },
  } as RuntimeIO;
  cleanupRunfreeImages({
    projectRoot: plan.projectRoot,
    project: plan.project,
    runtimeRoot: plan.baseRuntimeRoot,
    env: {},
  }, {
    removeImages(refs: string[]) {
      removed.push(refs);
      return 0;
    },
  } as never, io);

  expect(removed).toEqual([]);
});

test("cleanup skips tagged deletion when live image references cannot be inspected", () => {
  const plan = defaultPlan();
  const dockerfile = path.join(plan.projectRoot, ".runfree", "image", "Dockerfile");
  fs.mkdirSync(path.dirname(dockerfile), { recursive: true });
  fs.writeFileSync(dockerfile, "ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\n");
  plan.project.config = {
    ...defaultConfig(),
    runtime: {
      ...defaultConfig().runtime,
      agent: { build: { context: ".runfree/image", dockerfile: ".runfree/image/Dockerfile" } },
    },
  };
  let listed = false;
  let removed = false;
  const io = {
    capture(command: string, args: string[]) {
      if (command === "docker" && args[0] === "container") {
        return { status: 1, stdout: "", stderr: "inspect failed" };
      }
      if (command === "docker" && args[0] === "image") listed = true;
      return { status: 0, stdout: "", stderr: "" };
    },
  } as RuntimeIO;
  cleanupRunfreeImages({
    projectRoot: plan.projectRoot,
    project: plan.project,
    runtimeRoot: plan.baseRuntimeRoot,
    env: {},
  }, {
    removeImages() {
      removed = true;
      return 0;
    },
  } as never, io);

  expect(listed).toBe(false);
  expect(removed).toBe(false);
});

test("a newer CLI materializes the retained pending candidate without selecting or rebuilding another proxy", async () => {
  const { materializeRetainedRebindRuntimePlan } = await import("./images.ts");
  const { createControlPlaneMaterializationManifestV2, publishControlPlaneMaterializationV2 } = await import("./component-state-v2.ts");
  const plan = defaultPlan();
  const docker = new RuntimeImageDocker();
  const active = ensureRuntimeMaterialized(plan, { docker: docker as never, io: { run: () => 0 } as never, force: false, deferSelection: true });
  const inputDigest = sha256Digest("older-approved-proxy");
  const proxyImageId = `sha256:${"e".repeat(64)}`;
  const proxyImageRef = proxyRuntimeImageTag(inputDigest);
  const retainedImage = { id: proxyImageId, labels: {
    [RUNFREE_MANAGED_IMAGE_LABEL]: "true", [RUNFREE_DIGEST_SCHEMA_LABEL]: RUNFREE_DIGEST_SCHEMA_VERSION,
    [RUNFREE_IMAGE_ROLE_LABEL]: PROXY_RUNTIME_IMAGE_ROLE, [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: inputDigest,
  } };
  docker.images.set(proxyImageRef, retainedImage);
  docker.images.set(proxyImageId, retainedImage);
  const candidate = createControlPlaneMaterializationManifestV2({
    projectId: plan.projectId, composeProject: plan.composeProjectName,
    generation: createControlPlaneGenerationV2({ ...plan.generationV2.controlPlane, proxyImageInputDigest: inputDigest }),
    proxyImageId, proxyImageRef, renderedControlPlaneSha256: plan.generationV2.controlPlane.controlPlaneTopologyDigest,
  
    sessionAdmissionSource: "files",
  });
  publishControlPlaneMaterializationV2(plan.paths.stateDir, candidate);
  const recovered = materializeRetainedRebindRuntimePlan(active, candidate, docker as never);
  expect(recovered.generationV2.controlPlane).toEqual(candidate.generation);
  expect(recovered.activeRuntime.proxyImage).toBe(proxyImageRef);
  expect(recovered.activeRuntime.manifest?.components.proxyImageInputDigest).toBe(inputDigest);
  expect(readEffectiveRuntimeGeneration(plan.paths.stateDir)).toBeUndefined();
  expect(readDesiredSessionAgentV2(plan.paths.stateDir)).toBeUndefined();
  expect(recovered.activeRuntime.preparedSessionAgent).toEqual(active.activeRuntime.preparedSessionAgent);
  expect(() => materializeRetainedRebindRuntimePlan(active, { ...candidate,
    renderedControlPlaneSha256: sha256Digest("changed-topology") }, docker as never)).toThrow("compatible topology");
});

// Image GC under the file-backed admission source.
//
// The proxy's session files are the other thing that can still be using an
// agent image: a session whose record was lost is still served, and pruning
// the image the proxy is serving would be the first destructive thing a
// routine `up` did. Under `files` the cleanup therefore reads the proxy's own
// session-file listing and refuses to prune while it holds a file no record
// claims. Under `generations` no such read happens at all.
function selectFileSourceControlPlane(plan: RuntimePlan, proxyContainerId: string): void {
  const proxyImageId = `sha256:${"a".repeat(64)}`;
  const manifest = createControlPlaneMaterializationManifestV2({
    projectId: plan.projectId,
    composeProject: plan.composeProjectName,
    generation: plan.generationV2.controlPlane,
    proxyImageRef: proxyRuntimeImageTag(),
    proxyImageId,
    renderedControlPlaneSha256: plan.generationV2.controlPlane.controlPlaneTopologyDigest,
    sessionAdmissionSource: "files",
  });
  publishControlPlaneMaterializationV2(plan.paths.stateDir, manifest);
  selectEffectiveControlPlaneV2(plan.paths.stateDir, {
    schemaVersion: 2,
    projectId: plan.projectId,
    composeProject: plan.composeProjectName,
    controlPlaneGenerationDigest: plan.generationV2.controlPlane.controlPlaneGenerationDigest,
    controlPlaneMaterializationDigest: manifest.controlPlaneMaterializationDigest,
    proxyContainerId,
    proxyImageId,
    sidecarContainerIds: [],
    networkIds: { agentInternal: "8".repeat(64), proxyEgress: "9".repeat(64) },
    securityContractHash: sha256Digest("security-contract"),
    proofSchemaVersion: CONTROL_PLANE_PROOF_SCHEMA_VERSION,
    admissionContractEpoch: plan.generationV2.controlPlane.admissionContractEpoch,
    denyByDefaultBaseProofHash: sha256Digest("deny-by-default-base-proof"),
    selectedAt: "2026-09-07T11:59:00.000Z",
    runfreeVersion: "0.3.0",
  });
}

test.each([
  ["a session file no record claims retains every image", true, false],
  ["an empty session-file set prunes exactly as it does today", false, true],
])("cleanup under the file source: %s", (_name, served, prunes) => {
  const plan = defaultPlan();
  const proxyContainerId = "7".repeat(64);
  const dockerfile = path.join(plan.projectRoot, ".runfree", "image", "Dockerfile");
  fs.mkdirSync(path.dirname(dockerfile), { recursive: true });
  fs.writeFileSync(dockerfile, "ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\n");
  plan.project.config = {
    ...defaultConfig(),
    runtime: {
      ...defaultConfig().runtime,
      agent: { build: { context: ".runfree/image", dockerfile: ".runfree/image/Dockerfile" } },
    },
  };
  selectFileSourceControlPlane(plan, proxyContainerId);
  const staleId = `sha256:${"d".repeat(64)}`;
  const labels = {
    [RUNFREE_MANAGED_IMAGE_LABEL]: "true",
    [PROJECT_ID_LABEL]: projectHash(plan.projectRoot),
    [RUNFREE_IMAGE_ROLE_LABEL]: AGENT_PROJECT_IMAGE_ROLE,
  };
  const removed: string[][] = [];
  const servedSetReads: string[][] = [];
  const io = {
    capture(command: string, args: string[]) {
      if (command === "docker" && args.slice(0, 3).join(" ") === "container ls --all") {
        return { status: 0, stdout: "", stderr: "" };
      }
      if (command === "docker" && args[0] === "exec") {
        servedSetReads.push(args);
        return {
          status: 0,
          stdout: served
            ? JSON.stringify([{ sessionKey: "b".repeat(64), sourceIp: "172.31.90.20", malformed: false }])
            : "[]",
          stderr: "",
        };
      }
      if (command === "docker" && args.slice(0, 3).join(" ") === "image ls --no-trunc") {
        return { status: 0, stdout: staleId, stderr: "" };
      }
      if (command === "docker" && args.slice(0, 2).join(" ") === "image inspect") {
        return {
          status: 0,
          stdout: JSON.stringify(args.slice(2).map((id) => ({ Id: id, Config: { Labels: labels } }))),
          stderr: "",
        };
      }
      throw new Error(`unexpected cleanup command: ${command} ${args.join(" ")}`);
    },
  } as RuntimeIO;
  cleanupRunfreeImages({
    projectRoot: plan.projectRoot,
    project: plan.project,
    runtimeRoot: plan.baseRuntimeRoot,
    env: {},
  }, {
    removeImages(refs: string[]) {
      removed.push(refs);
      return 0;
    },
  } as never, io);

  // The listing is read from the proxy the durable selection names, through
  // the sealed root-Node channel — never a shell.
  expect(servedSetReads).toHaveLength(1);
  expect(servedSetReads[0]?.slice(0, 6)).toEqual(["exec", "--user", "0:0", "-i", proxyContainerId, "node"]);
  expect(removed).toEqual(prunes ? [[staleId]] : []);
});

// No durable effective selection names no proxy, so there is nothing to read a
// session-file listing from — and cleanup must still run rather than refuse.
test("cleanup without a durable effective control plane never reads the proxy's session files", () => {
  const plan = defaultPlan();
  const dockerfile = path.join(plan.projectRoot, ".runfree", "image", "Dockerfile");
  fs.mkdirSync(path.dirname(dockerfile), { recursive: true });
  fs.writeFileSync(dockerfile, "ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\n");
  plan.project.config = {
    ...defaultConfig(),
    runtime: {
      ...defaultConfig().runtime,
      agent: { build: { context: ".runfree/image", dockerfile: ".runfree/image/Dockerfile" } },
    },
  };
  const staleId = `sha256:${"d".repeat(64)}`;
  const labels = {
    [RUNFREE_MANAGED_IMAGE_LABEL]: "true",
    [PROJECT_ID_LABEL]: projectHash(plan.projectRoot),
    [RUNFREE_IMAGE_ROLE_LABEL]: AGENT_PROJECT_IMAGE_ROLE,
  };
  const removed: string[][] = [];
  const io = {
    capture(command: string, args: string[]) {
      if (command === "docker" && args.slice(0, 3).join(" ") === "container ls --all") {
        return { status: 0, stdout: "", stderr: "" };
      }
      if (command === "docker" && args.slice(0, 3).join(" ") === "image ls --no-trunc") {
        return { status: 0, stdout: staleId, stderr: "" };
      }
      if (command === "docker" && args.slice(0, 2).join(" ") === "image inspect") {
        return {
          status: 0,
          stdout: JSON.stringify(args.slice(2).map((id) => ({ Id: id, Config: { Labels: labels } }))),
          stderr: "",
        };
      }
      throw new Error(`unexpected cleanup command: ${command} ${args.join(" ")}`);
    },
  } as RuntimeIO;
  cleanupRunfreeImages({
    projectRoot: plan.projectRoot,
    project: plan.project,
    runtimeRoot: plan.baseRuntimeRoot,
    env: {},
  }, {
    removeImages(refs: string[]) {
      removed.push(refs);
      return 0;
    },
  } as never, io);

  expect(removed).toEqual([[staleId]]);
});
