import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { beforeEach, describe, expect, test, vi, type Mock } from "vitest";

import { agentRuntimeImageTag } from "../agent-image.ts";
import {
  builtinAgent,
} from "../agents.ts";
import {
  defaultConfig,
  projectControlPaths,
  type ProjectInfo,
} from "../config.ts";
import { approveNetworkCandidate, approveRuntimeIsolationControl } from "../control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../control/candidates.ts";
import { publishEffectivePolicyGeneration } from "../control/effective.ts";
import { RUNFREE_RUNTIME_COMPONENTS } from "../embedded-assets.generated.ts";
import {
  AGENT_RUNTIME_IMAGE_ROLE,
  RUNFREE_DIGEST_SCHEMA_LABEL,
  RUNFREE_DIGEST_SCHEMA_VERSION,
  RUNFREE_IMAGE_INPUT_DIGEST_LABEL,
  RUNFREE_IMAGE_ROLE_LABEL,
  RUNFREE_MANAGED_IMAGE_LABEL,
} from "./constants.ts";
import {
  bindSessionAgentImageV2,
  createControlPlaneGenerationV2,
  createControlPlaneMaterializationManifestV2,
  createSessionAgentGenerationInputsV2,
  createSessionAgentDesiredSelectionV2,
  createSessionAgentMaterializationManifestV2,
  publishControlPlaneMaterializationV2,
  publishSessionAgentMaterializationV2,
  selectDesiredSessionAgentV2,
  selectEffectiveControlPlaneV2,
  type ControlPlaneEffectiveSelectionV2,
  type ControlPlaneGenerationV2,
} from "./component-state-v2.ts";
import {
  createRuntimeComponentState,
  runtimeMaterializationRoot,
  serializeRuntimeGenerationManifest,
  sha256Digest,
  type RuntimeGenerationManifest,
} from "./component-state.ts";
import type { DockerImageInspect } from "./docker.ts";
import { withActiveRuntime } from "./images.ts";
import {
  assertSessionAdmissionDriverPreflight,
  createAllocatedSessionContainerRecordFromPreflight,
  createSessionAdmissionDriverPreflight,
  createSessionContainerCreatePlanFromPreflight,
  type SessionAdmissionDriverPreflight,
} from "./session-admission-driver-preflight.ts";
import { createRuntimePlan, type ActiveRuntimePlan } from "./plan.ts";
import { SESSION_ENTRY_PATH } from "./session-launch.ts";
import {
  createSessionTemplateArtifactV1,
  serializeSessionTemplateArtifactV1,
  sessionTemplateArtifactSha256,
} from "./session-template-artifact.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { RuntimeContext } from "./types.ts";

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-session-driver-preflight-"));
});


// Runtime environment generation requires a selected effective control
// generation; publish a minimal one per fixture state dir (idempotent).
function ensureSelectedControls(projectRoot: string, project: ProjectInfo): void {
  if (fs.existsSync(path.join(project.paths.controlProxyDir, "active.json"))) return;
  fs.mkdirSync(path.dirname(project.paths.policyPath), { recursive: true });
  if (!fs.existsSync(project.paths.policyPath)) {
    fs.writeFileSync(project.paths.policyPath, '{"version":2,"hosts":[]}\n');
  }
  const candidate = captureDesiredPolicyCandidate(projectRoot, project.paths.controlCandidatesDir);
  approveNetworkCandidate(projectRoot, project, candidate, "network-project", "interactive");
  approveNetworkCandidate(projectRoot, project, candidate, "network-local", "interactive");
  approveRuntimeIsolationControl(projectRoot, project, "interactive");
  publishEffectivePolicyGeneration(projectRoot, project);
}

function projectInfo(projectRoot: string): ProjectInfo {
  const project = buildProjectInfo(projectRoot);
  ensureSelectedControls(projectRoot, project);
  return project;
}

function buildProjectInfo(projectRoot: string): ProjectInfo {
  const runfreeDir = path.join(projectRoot, ".runfree");
  const stateDir = path.join(tmp, "state");
  return {
    config: defaultConfig(),
    paths: {
      runfreeDir,
      agentEnvPath: path.join(runfreeDir, "config", "agent.env"),
      claudeConfigPath: path.join(stateDir, "claude.json"),
      claudeMcpConfigPath: path.join(stateDir, "mounts", "claude-mcp.json"),
      claudeDir: path.join(stateDir, "claude"),
      codexDir: path.join(stateDir, "codex"),
      configPath: path.join(runfreeDir, "runfree.json"),
      ...projectControlPaths(stateDir),
      gitConfigPath: path.join(stateDir, "gitconfig"),
      inboxDir: path.join(stateDir, "inbox"),
      projectCodexDirMaskPath: path.join(stateDir, "mounts", "project-codex-mask"),
      mcpOAuthPolicyPath: path.join(stateDir, "oauth-mediation-policy.json"),
      proxyCaCertDir: path.join(stateDir, "proxy-ca", "public"),
      proxyCaKeyDir: path.join(stateDir, "proxy-ca", "private"),
      policyPath: path.join(runfreeDir, "network-policy.json"),
      sessionsDir: path.join(stateDir, "sessions"),
      stateDir,
      tokenConfigPath: path.join(stateDir, "tokens.json"),
    },
  };
}

function writeRuntimeCompose(runtimeRoot: string): void {
  fs.mkdirSync(path.join(runtimeRoot, "agent"), { recursive: true });
  fs.copyFileSync(
    path.join(process.cwd(), "packages", "agent-runtime", "agent", "compose.yaml"),
    path.join(runtimeRoot, "agent", "compose.yaml"),
  );
}

function writeRuntimeMaterialization(
  stateDir: string,
  manifest: RuntimeGenerationManifest,
): string {
  const runtimeRoot = runtimeMaterializationRoot(stateDir, manifest.components.materializationDigest);
  fs.mkdirSync(path.join(runtimeRoot, "agent"), { recursive: true });
  fs.copyFileSync(
    path.join(process.cwd(), "packages", "agent-runtime", "agent", "inspect-active-sessions.sh"),
    path.join(runtimeRoot, "agent", "inspect-active-sessions.sh"),
  );
  fs.writeFileSync(path.join(runtimeRoot, "generation.json"), serializeRuntimeGenerationManifest(manifest));
  return runtimeRoot;
}

function lifecycleLock(): ProjectLifecycleLock & { assertHeld: Mock<() => void> } {
  return {
    ownerToken: "a".repeat(64),
    assertHeld: vi.fn<() => void>(),
    release: vi.fn<() => void>(),
  };
}

function fixture() {
  const projectRoot = path.join(tmp, "project");
  const sourceRuntimeRoot = path.join(tmp, "runtime-source");
  fs.mkdirSync(projectRoot, { recursive: true });
  writeRuntimeCompose(sourceRuntimeRoot);
  const project = projectInfo(projectRoot);
  const planned = createRuntimePlan({
    projectRoot,
    project,
    runtimeRoot: sourceRuntimeRoot,
    env: {},
    network: {
      agentIp: "172.83.0.11",
      callbackSidecarIp: "172.83.0.12",
      proxyEgressGateway: "172.83.1.1",
      proxyEgressIp: "172.83.1.10",
      proxyEgressSubnet: "172.83.1.0/24",
      proxyIp: "172.83.0.10",
      subnet: "172.83.0.0/24",
    },
  } as RuntimeContext, { dockerSubnets: [], persistNetwork: false });

  const desiredImageId = sha256Digest("desired-session-image-id");
  const desiredImageRef = agentRuntimeImageTag(planned.generationV2.sessionAgent.selectedAgentImageInputDigest);
  const templateArtifactSource = serializeSessionTemplateArtifactV1(
    createSessionTemplateArtifactV1(planned),
  );
  const desired = createSessionAgentMaterializationManifestV2({
    projectId: planned.projectId,
    composeProject: planned.composeProjectName,
    generation: bindSessionAgentImageV2(planned.generationV2.sessionAgent, desiredImageId),
    selectedAgentImageRef: desiredImageRef,
    selectedAgentImageId: desiredImageId,
    selectedAgentImageKind: "embedded",
    sessionTemplateArtifactSha256: sessionTemplateArtifactSha256(templateArtifactSource),
  });
  publishSessionAgentMaterializationV2(project.paths.stateDir, desired, templateArtifactSource);
  selectDesiredSessionAgentV2(project.paths.stateDir, createSessionAgentDesiredSelectionV2(desired));

  const activeComponents = createRuntimeComponentState({
    embeddedAgentImageInputDigest: RUNFREE_RUNTIME_COMPONENTS.agentImageInputDigest,
    selectedAgentImageInputDigest: sha256Digest("older-direct-session-input"),
    selectedAgentImageKind: "embedded",
    proxyImageInputDigest: RUNFREE_RUNTIME_COMPONENTS.proxyImageInputDigest,
    topologyDigest: sha256Digest("older-active-shared-runtime"),
    hostHelperDigest: RUNFREE_RUNTIME_COMPONENTS.hostHelperDigest,
  });
  const activeManifest: RuntimeGenerationManifest = {
    schemaVersion: 1,
    projectId: planned.projectId,
    composeProject: planned.composeProjectName,
    components: activeComponents,
    images: {
      agent: "runfree/agent-runtime:older-direct-session",
      proxy: "runfree/proxy-runtime:older-control-plane",
    },
    renderedComposeSha256: sha256Digest("older-compose"),
  };
  const activeRuntimeRoot = writeRuntimeMaterialization(project.paths.stateDir, activeManifest);
  const plan: ActiveRuntimePlan = withActiveRuntime(planned, {
    activeRuntimeRoot,
    composeFile: path.join(activeRuntimeRoot, "agent", "compose.yaml"),
    composeDirectory: path.join(activeRuntimeRoot, "agent"),
    runtimeDigest: planned.runtimeDigest,
    materialized: true,
    agentImage: activeManifest.images.agent,
    proxyImage: activeManifest.images.proxy,
    manifest: activeManifest,
    state: "effective",
  });

  const selectedImage: DockerImageInspect = {
    architecture: "amd64",
    environment: { IMAGE_DEFAULT: "safe" },
    id: desiredImageId,
    labels: {
      [RUNFREE_MANAGED_IMAGE_LABEL]: "true",
      [RUNFREE_DIGEST_SCHEMA_LABEL]: RUNFREE_DIGEST_SCHEMA_VERSION,
      [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: desired.generation.selectedAgentImageInputDigest,
      [RUNFREE_IMAGE_ROLE_LABEL]: AGENT_RUNTIME_IMAGE_ROLE,
    },
    os: "linux",
    volumes: [],
  };
  const lock = lifecycleLock();
  const setEffective = (
    generation: ControlPlaneGenerationV2 = planned.generationV2.controlPlane,
  ): ControlPlaneEffectiveSelectionV2 => {
    const proxyImageId = sha256Digest(generation.controlPlaneGenerationDigest);
    const materialization = createControlPlaneMaterializationManifestV2({
      projectId: planned.projectId,
      composeProject: planned.composeProjectName,
      generation,
      proxyImageRef: `runfree/proxy:${generation.controlPlaneGenerationDigest}`,
      proxyImageId,
      renderedControlPlaneSha256: generation.controlPlaneTopologyDigest,
    
      sessionAdmissionSource: "files",
    });
    publishControlPlaneMaterializationV2(project.paths.stateDir, materialization);
    const selection: ControlPlaneEffectiveSelectionV2 = {
      schemaVersion: 2,
      projectId: planned.projectId,
      composeProject: planned.composeProjectName,
      controlPlaneGenerationDigest: generation.controlPlaneGenerationDigest,
      controlPlaneMaterializationDigest: materialization.controlPlaneMaterializationDigest,
      proxyContainerId: "7".repeat(64),
      proxyImageId,
      sidecarContainerIds: [],
      networkIds: {
        agentInternal: "8".repeat(64),
        proxyEgress: "9".repeat(64),
      },
      securityContractHash: sha256Digest(`security-${generation.controlPlaneGenerationDigest}`),
      proofSchemaVersion: 1,
      admissionContractEpoch: generation.admissionContractEpoch,
      denyByDefaultBaseProofHash: sha256Digest(`base-${generation.controlPlaneGenerationDigest}`),
      selectedAt: "2026-08-09T12:00:00.000Z",
      runfreeVersion: "0.3.0",
    };
    selectEffectiveControlPlaneV2(project.paths.stateDir, selection);
    return selection;
  };
  const effective = setEffective(createControlPlaneGenerationV2({
    projectId: planned.projectId,
    composeProject: planned.composeProjectName,
    proxyImageInputDigest: planned.generationV2.controlPlane.proxyImageInputDigest,
    controlPlaneTopologyDigest: sha256Digest("older-compatible-control-plane"),
    admissionContractEpoch: planned.generationV2.sessionAgent.admissionContractEpoch,
  }));
  const docker = {
    inspectImage: vi.fn((_reference: string, _options?: { fresh?: boolean }): DockerImageInspect | undefined => selectedImage),
  };
  const build = (
    launchOverrides:
      | Partial<{ agentId: string; configuredCommand: string; resume: { conversationId?: string } }>
      | Readonly<{ kind: "shell" }> = {},
  ) =>
    createSessionAdmissionDriverPreflight({
      runtime: plan,
      lifecycleLock: lock,
      docker,
      launch: "kind" in launchOverrides
        ? { kind: "shell" }
        : {
            kind: "builtin",
            agentId: launchOverrides.agentId ?? "codex",
            configuredCommand: launchOverrides.configuredCommand
              ?? builtinAgent(launchOverrides.agentId ?? "codex")?.defaultCommand
              ?? "",
            ...(launchOverrides.resume ? { resume: launchOverrides.resume } : {}),
          },
    });
  return {
    build,
    desired,
    docker,
    effective,
    lock,
    plan,
    project,
    selectedImage,
    setEffective,
    templateArtifactSource,
  };
}

function recordInput() {
  return {
    sessionId: "rf-20260809-abcdef",
    displayName: "payments",
    command: "codex",
    sourceIp: "172.83.0.20",
    hostPid: 1234,
    createdAt: "2026-08-09T12:00:01.000Z",
  } as const;
}

describe("session admission driver preflight", () => {
  test("binds a fresh mixed-generation template", () => {
    const value = fixture();
    const preflight = value.build();

    expect(preflight.generationTarget.controlPlane.controlPlaneGenerationDigest)
      .toBe(value.effective.controlPlaneGenerationDigest);
    expect(preflight.generationTarget.sessionAgent.sessionAgentGenerationDigest)
      .toBe(value.desired.generation.sessionAgentGenerationDigest);

    const record = createAllocatedSessionContainerRecordFromPreflight(preflight, recordInput());
    const createPlan = createSessionContainerCreatePlanFromPreflight(preflight, record);
    expect(createPlan.record.selectedAgentImageId).toBe(value.desired.selectedAgentImageId);
    expect(createPlan.effectiveControlPlane.controlPlaneGenerationDigest)
      .toBe(value.effective.controlPlaneGenerationDigest);
    expect(value.lock.assertHeld.mock.calls.length).toBeGreaterThanOrEqual(12);
  });

  test("rejects a custom command before any container authority is minted", () => {
    const value = fixture();
    expect(() => value.build({ configuredCommand: "codex --profile attacker" }))
      .toThrow("supports only the exact codex built-in command");
  });

  test("binds the typed resume argv into the preflight launch and the allocated record", () => {
    const value = fixture();
    const conversationId = "0f8b1a2c-3d4e-4f5a-8b6c-7d8e9f0a1b2c";
    const preflight = value.build({
      agentId: "claude",
      configuredCommand: builtinAgent("claude")?.defaultCommand ?? "",
      resume: { conversationId },
    });

    // The typed target names the image's session entry; the agent launch is
    // its argv (activation-gate design D3).
    expect(preflight.launch.path).toBe(SESSION_ENTRY_PATH);
    expect(preflight.launch.args).toEqual([
      "/usr/local/bin/claude",
      "--dangerously-skip-permissions",
      "--add-dir",
      "/runfree/inbox",
      "--resume",
      conversationId,
    ]);
    const record = createAllocatedSessionContainerRecordFromPreflight(preflight, {
      ...recordInput(),
      command: "claude",
    });
    expect(record.launchPath).toBe(SESSION_ENTRY_PATH);
    expect(record.launchArgs[0]).toBe("/usr/local/bin/claude");
    expect(record.launchArgs.at(-1)).toBe(conversationId);
  });

  test("mints the login-shell target for a shell session and binds it into the record", () => {
    // The shell kind consults no configured command by construction — the
    // union has no field to carry one — so a project's custom agent command
    // cannot gate the escape hatch it is pointed at.
    const value = fixture();
    const preflight = value.build({ kind: "shell" });

    expect(preflight.launch.path).toBe(SESSION_ENTRY_PATH);
    expect(preflight.launch.args).toEqual(["/usr/bin/zsh", "-il"]);
    expect(preflight.launch.interactive).toBe(true);
    expect(preflight.launch.tty).toBe(true);

    const record = createAllocatedSessionContainerRecordFromPreflight(preflight, {
      ...recordInput(),
      command: "zsh -il",
    });
    expect(record.launchPath).toBe(SESSION_ENTRY_PATH);
    expect(record.launchArgs).toEqual(["/usr/bin/zsh", "-il"]);
  });

  test("rejects a resume request before any container authority when the agent lacks the capability", () => {
    const value = fixture();
    expect(() => value.build({
      agentId: "pi",
      configuredCommand: builtinAgent("pi")?.defaultCommand ?? "",
      resume: {},
    })).toThrow("resume is not supported");
    expect(() => value.build({
      resume: { conversationId: "not-a-uuid" },
    })).toThrow("not a valid conversation UUID");
  });

  test("uses the durable session-template artifact after mutable input changes", () => {
    const value = fixture();
    const agentEnvironmentPath = value.plan.execution.composeEnv.RUNFREE_AGENT_ENV_FILE;
    if (!agentEnvironmentPath) throw new Error("fixture omitted selected agent environment path");
    // The selected generation's agent.env is published read-only; force-write
    // it to model post-publication drift of durable state. The preflight must
    // keep using the durable session-template artifact, not re-read the file.
    fs.mkdirSync(path.dirname(agentEnvironmentPath), { recursive: true });
    if (fs.existsSync(agentEnvironmentPath)) fs.chmodSync(agentEnvironmentPath, 0o644);
    fs.writeFileSync(agentEnvironmentPath, "NEW_PROJECT_VALUE=changed\n");

    const preflight = value.build();
    expect(preflight.template.environment.NEW_PROJECT_VALUE).toBeUndefined();
    expect(value.docker.inspectImage).toHaveBeenCalled();
  });

  test("every preflight image inspection bypasses the L5a memo with an explicit fresh read", () => {
    // The ref-then-id cross-check's claim is temporal — "the reference still
    // resolves to the durable id NOW" — so a memoized inspect must never
    // satisfy it (the temporal-poisoning hazard from the latency design).
    const value = fixture();
    value.build();
    expect(value.docker.inspectImage.mock.calls.length).toBeGreaterThanOrEqual(2);
    for (const call of value.docker.inspectImage.mock.calls) {
      expect(call[1]).toEqual({ fresh: true });
    }
  });

  test("rejects stale desired state changed across Docker inspection", () => {
    const value = fixture();
    const replacementImageId = sha256Digest("replacement-image-id");
    const replacement = createSessionAgentMaterializationManifestV2({
      projectId: value.desired.projectId,
      composeProject: value.desired.composeProject,
      generation: bindSessionAgentImageV2(
        value.plan.generationV2.sessionAgent,
        replacementImageId,
      ),
      selectedAgentImageRef: "runfree/agent-runtime:replacement",
      selectedAgentImageId: replacementImageId,
      selectedAgentImageKind: value.desired.selectedAgentImageKind,
      sessionTemplateArtifactSha256: value.desired.sessionTemplateArtifactSha256,
    });
    publishSessionAgentMaterializationV2(
      value.project.paths.stateDir,
      replacement,
      value.templateArtifactSource,
    );
    value.docker.inspectImage.mockImplementationOnce(() => {
      selectDesiredSessionAgentV2(
        value.project.paths.stateDir,
        createSessionAgentDesiredSelectionV2(replacement),
      );
      return value.selectedImage;
    });

    expect(() => value.build()).toThrow("durable desired/effective state changed during preflight");
  });

  test("rejects a runtime plan stale against the already-selected desired generation", () => {
    const value = fixture();
    const generationInputs = createSessionAgentGenerationInputsV2({
      selectedAgentImageInputDigest: sha256Digest("new-agent-input"),
      sessionTemplateDigest: value.plan.generationV2.sessionAgent.sessionTemplateDigest,
      admissionContractEpoch: value.plan.generationV2.sessionAgent.admissionContractEpoch,
    });
    const selectedAgentImageId = sha256Digest("new-agent-image-id");
    const replacement = createSessionAgentMaterializationManifestV2({
      projectId: value.plan.projectId,
      composeProject: value.plan.composeProjectName,
      generation: bindSessionAgentImageV2(generationInputs, selectedAgentImageId),
      selectedAgentImageRef: "runfree/agent-runtime:new-agent",
      selectedAgentImageId,
      selectedAgentImageKind: "embedded",
      sessionTemplateArtifactSha256: value.desired.sessionTemplateArtifactSha256,
    });
    publishSessionAgentMaterializationV2(
      value.project.paths.stateDir,
      replacement,
      value.templateArtifactSource,
    );
    selectDesiredSessionAgentV2(
      value.project.paths.stateDir,
      createSessionAgentDesiredSelectionV2(replacement),
    );

    expect(() => value.build()).toThrow("runtime plan does not match the durable desired");
    expect(value.docker.inspectImage).not.toHaveBeenCalled();
  });

  test("rejects stale effective state changed across Docker inspection", () => {
    const value = fixture();
    const replacement = createControlPlaneGenerationV2({
      projectId: value.plan.projectId,
      composeProject: value.plan.composeProjectName,
      proxyImageInputDigest: value.plan.generationV2.controlPlane.proxyImageInputDigest,
      controlPlaneTopologyDigest: sha256Digest("new-compatible-control-plane"),
      admissionContractEpoch: value.plan.generationV2.sessionAgent.admissionContractEpoch,
    });
    value.docker.inspectImage.mockImplementationOnce(() => {
      value.setEffective(replacement);
      return value.selectedImage;
    });

    expect(() => value.build()).toThrow("durable desired/effective state changed during preflight");
  });

  test.each([
    {
      label: "mutable ref points to another ID",
      mutate: (image: DockerImageInspect) => ({ ...image, id: sha256Digest("wrong-id") }),
      message: "reference no longer resolves",
    },
    {
      label: "selected image platform is unsupported",
      mutate: (image: DockerImageInspect) => ({ ...image, architecture: "s390x" }),
      message: "platform is unsupported",
    },
  ])("rejects $label", ({ mutate, message }) => {
    const value = fixture();
    const changed = mutate(value.selectedImage);
    value.docker.inspectImage.mockImplementation(() => changed);
    expect(() => value.build()).toThrow(message);
  });

  test("rejects disagreement between image-ref and immutable-ID inspections", () => {
    const value = fixture();
    value.docker.inspectImage
      .mockImplementationOnce(() => value.selectedImage)
      .mockImplementationOnce(() => ({ ...value.selectedImage, architecture: "arm64" }));
    expect(() => value.build()).toThrow("reference and immutable ID inspections disagree");
  });

  test("rejects a missing selected image reference", () => {
    const value = fixture();
    value.docker.inspectImage.mockImplementationOnce(() => undefined);
    expect(() => value.build()).toThrow("failed exact managed identity inspection");
  });

  test("rejects an admission-epoch mismatch between the mixed generations", () => {
    const value = fixture();
    value.setEffective(createControlPlaneGenerationV2({
      projectId: value.plan.projectId,
      composeProject: value.plan.composeProjectName,
      proxyImageInputDigest: value.plan.generationV2.controlPlane.proxyImageInputDigest,
      controlPlaneTopologyDigest: sha256Digest("incompatible-control-plane"),
      admissionContractEpoch: value.plan.generationV2.sessionAgent.admissionContractEpoch + 1,
    }));
    expect(() => value.build()).toThrow("not admission-compatible");
    expect(value.docker.inspectImage).not.toHaveBeenCalled();
  });

  test("rejects copied preflight and caller-forged allocated-record authorities", () => {
    const value = fixture();
    const preflight = value.build();
    const copiedPreflight = { ...preflight } as unknown as SessionAdmissionDriverPreflight;
    expect(() => assertSessionAdmissionDriverPreflight(copiedPreflight))
      .toThrow("was not minted by the canonical builder");
    expect(() => createAllocatedSessionContainerRecordFromPreflight(copiedPreflight, recordInput()))
      .toThrow("was not minted by the canonical builder");

    const record = createAllocatedSessionContainerRecordFromPreflight(preflight, recordInput());
    expect(() => createSessionContainerCreatePlanFromPreflight(preflight, { ...record }))
      .toThrow("was not minted by this preflight authority");
  });

  test("rejects authority reuse after durable selection changes", () => {
    const value = fixture();
    const preflight = value.build();
    value.setEffective(createControlPlaneGenerationV2({
      projectId: value.plan.projectId,
      composeProject: value.plan.composeProjectName,
      proxyImageInputDigest: value.plan.generationV2.controlPlane.proxyImageInputDigest,
      controlPlaneTopologyDigest: sha256Digest("later-control-plane"),
      admissionContractEpoch: value.plan.generationV2.sessionAgent.admissionContractEpoch,
    }));
    expect(() => createAllocatedSessionContainerRecordFromPreflight(preflight, recordInput()))
      .toThrow("changed after preflight");
  });
});
