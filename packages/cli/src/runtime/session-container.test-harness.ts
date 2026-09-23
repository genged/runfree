import path from "node:path";

import type { ProjectInfo } from "../config.ts";
import {
  bindSessionAgentImageV2,
  CONTROL_PLANE_PROOF_SCHEMA_VERSION,
  createControlPlaneGenerationV2,
  createControlPlaneMaterializationManifestV2,
  createRuntimeTopologyGenerationV2,
  createSessionAgentMaterializationManifestV2,
  createSessionAgentGenerationInputsV2,
  RUNTIME_ADMISSION_CONTRACT_EPOCH,
  type ControlPlaneEffectiveSelectionV2,
  type ControlPlaneMaterializationManifestV2,
  type RuntimeGenerationTargetV2,
  type SessionAgentGenerationV2,
  type SessionAgentMaterializationManifestV2,
} from "./component-state-v2.ts";
import type { DependencyOverlayPlan } from "./dependency-overlays.ts";
import type { RuntimeGitLayoutPlan } from "./git-layout.ts";
import { sha256Digest } from "./component-state.ts";
import {
  AGENT_PROJECT_IMAGE_ROLE,
  AGENT_RUNTIME_IMAGE_ROLE,
  PROJECT_ID_LABEL,
  RUNFREE_DIGEST_SCHEMA_LABEL,
  RUNFREE_DIGEST_SCHEMA_VERSION,
  RUNFREE_IMAGE_INPUT_DIGEST_LABEL,
  RUNFREE_IMAGE_ROLE_LABEL,
  RUNFREE_MANAGED_IMAGE_LABEL,
  RUNFREE_VERSION_LABEL,
} from "./constants.ts";
import {
  SESSION_CONTAINER_CAPABILITY_DROPS,
  SESSION_CONTAINER_RESTART_POLICY,
  SESSION_CONTAINER_SECURITY_OPTIONS,
  SESSION_CONTAINER_STOP_SIGNAL,
  SESSION_CONTAINER_USER,
} from "./session-container-contract.ts";
import { createSessionLaunchTarget } from "./session-launch.ts";
import {
  validateSessionContainerInspect,
  type SessionContainerProof,
} from "./session-container-proof.ts";
import { createSessionImageDeclarationProof } from "./session-image-declarations.ts";
import {
  bindSessionContainerTemplateGenerationV2,
  createSessionContainerCreatePlan,
  createSessionContainerTemplate,
  type SessionContainerCreatePlan,
  type SessionContainerTemplate,
} from "./session-container-template.ts";
import {
  bindAllocatedSessionContainerIdV2,
  createAllocatedSessionContainerRecordV2,
  sessionContainerLabels,
  writeSessionContainerRecordV2,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import { projectHash } from "../project-identity.ts";
import { composeProjectName } from "./env.ts";

export const SESSION_TEST_PROJECT_ROOT = "/host/worktrees/payments";
export const SESSION_TEST_STATE_ROOT = "/host/runfree/state/payments";
export const SESSION_TEST_PROJECT: Readonly<SessionContainerProjectIdentity> = Object.freeze({
  projectId: "0123456789ab",
  composeProject: "runfree-0123456789ab",
});
export const SESSION_TEST_NETWORK_ENDPOINT_ID = "e".repeat(64);
export const SESSION_TEST_DOCKER_STARTED_AT = "2026-08-08T12:00:05.123456789Z";

export function sessionTestProjectInfo(): ProjectInfo {
  const runfreeDir = path.join(SESSION_TEST_PROJECT_ROOT, ".runfree");
  return {
    config: { version: 4, project: {}, agents: {}, runtime: {} },
    paths: {
      runfreeDir,
      agentEnvPath: path.join(runfreeDir, "config", "agent.env"),
      claudeConfigPath: path.join(SESSION_TEST_STATE_ROOT, "claude.json"),
      claudeMcpConfigPath: path.join(SESSION_TEST_STATE_ROOT, "mcp", "claude.json"),
      claudeDir: path.join(SESSION_TEST_STATE_ROOT, "claude"),
      codexDir: path.join(SESSION_TEST_STATE_ROOT, "codex"),
      configPath: path.join(runfreeDir, "runfree.json"),
      controlApprovalsPath: path.join(SESSION_TEST_STATE_ROOT, "control", "approvals.json"),
      controlAgentEnvPath: path.join(SESSION_TEST_STATE_ROOT, "control", "inputs", "agent.env"),
      controlMcpNetworkPolicyPath: path.join(SESSION_TEST_STATE_ROOT, "control", "mcp-network-policy.json"),
      controlApprovedDir: path.join(SESSION_TEST_STATE_ROOT, "control", "approved"),
      controlCandidatesDir: path.join(SESSION_TEST_STATE_ROOT, "control", "candidates"),
      controlConvergedPath: path.join(SESSION_TEST_STATE_ROOT, "control", "converged.json"),
      controlDir: path.join(SESSION_TEST_STATE_ROOT, "control"),
      controlEffectiveDir: path.join(SESSION_TEST_STATE_ROOT, "control", "effective"),
      controlLegacyEnforcedNetworkPath: path.join(SESSION_TEST_STATE_ROOT, "control", "legacy.json"),
      controlProxyActivePath: path.join(SESSION_TEST_STATE_ROOT, "control", "proxy-active.json"),
      controlProxyDir: path.join(SESSION_TEST_STATE_ROOT, "control", "effective", "proxy"),
      gitConfigPath: path.join(SESSION_TEST_STATE_ROOT, "gitconfig"),
      inboxDir: path.join(SESSION_TEST_STATE_ROOT, "inbox"),
      projectCodexDirMaskPath: path.join(SESSION_TEST_STATE_ROOT, "mounts", "project-codex"),
      mcpOAuthPolicyPath: path.join(SESSION_TEST_STATE_ROOT, "mcp-oauth-policy.json"),
      proxyCaCertDir: path.join(SESSION_TEST_STATE_ROOT, "proxy-ca", "public"),
      proxyCaKeyDir: path.join(SESSION_TEST_STATE_ROOT, "proxy-ca", "private"),
      policyPath: path.join(runfreeDir, "network-policy.json"),
      sessionsDir: path.join(SESSION_TEST_STATE_ROOT, "sessions"),
      stateDir: SESSION_TEST_STATE_ROOT,
      tokenConfigPath: path.join(SESSION_TEST_STATE_ROOT, "tokens.json"),
    },
  } as ProjectInfo;
}

export function sessionContainerInspectJsonFixture(
  plan: SessionContainerCreatePlan,
  options: { running?: boolean } = {},
): string {
  const running = options.running ?? false;
  const imageRole = plan.sessionAgentMaterialization.selectedAgentImageKind === "project"
    ? AGENT_PROJECT_IMAGE_ROLE
    : AGENT_RUNTIME_IMAGE_ROLE;
  const declaredVolumes = plan.imageDeclarationProof.declaredVolumeTargets.length === 0
    ? null
    : Object.fromEntries(plan.imageDeclarationProof.declaredVolumeTargets.map((target) => [target, {}]));
  return JSON.stringify([{
    Id: plan.record.containerId,
    Name: `/${plan.record.containerName}`,
    Image: plan.record.selectedAgentImageId,
    Path: plan.record.launchPath,
    Args: [...plan.record.launchArgs],
    Config: {
      Image: plan.record.selectedAgentImageId,
      User: SESSION_CONTAINER_USER,
      Entrypoint: [plan.record.launchPath],
      Cmd: [...plan.record.launchArgs],
      StopSignal: SESSION_CONTAINER_STOP_SIGNAL,
      WorkingDir: plan.template.workingDirectory,
      OpenStdin: plan.record.interactive,
      Tty: plan.record.tty,
      Healthcheck: { Test: ["NONE"] },
      Volumes: declaredVolumes,
      Env: Object.entries(plan.imageDeclarationProof.mergedEnvironment)
        .map(([name, value]) => `${name}=${value}`),
      Labels: {
        ...sessionContainerLabels(plan.record, plan.runfreeVersion),
        [RUNFREE_MANAGED_IMAGE_LABEL]: "true",
        [RUNFREE_IMAGE_ROLE_LABEL]: imageRole,
        [RUNFREE_DIGEST_SCHEMA_LABEL]: RUNFREE_DIGEST_SCHEMA_VERSION,
        [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: plan.record.selectedAgentImageInputDigest,
        [PROJECT_ID_LABEL]: plan.record.projectId,
        [RUNFREE_VERSION_LABEL]: plan.runfreeVersion,
      },
    },
    HostConfig: {
      NetworkMode: plan.effectiveControlPlane.networkIds.agentInternal,
      Privileged: false,
      Init: false,
      AutoRemove: false,
      PublishAllPorts: false,
      RestartPolicy: { Name: SESSION_CONTAINER_RESTART_POLICY, MaximumRetryCount: 0 },
      CapAdd: null,
      CapDrop: [...SESSION_CONTAINER_CAPABILITY_DROPS],
      SecurityOpt: [...SESSION_CONTAINER_SECURITY_OPTIONS],
      PortBindings: {},
      ExtraHosts: null,
      Devices: [],
      DeviceRequests: null,
      Binds: null,
      Dns: [],
      DnsOptions: [],
      DnsSearch: [],
      Links: null,
      VolumesFrom: null,
      Mounts: plan.mounts.map((mount) => ({
        Type: mount.type,
        Source: mount.source,
        Target: mount.target,
        ReadOnly: mount.readOnly,
        VolumeOptions: mount.type === "volume" ? { NoCopy: mount.noCopy } : null,
      })),
    },
    Mounts: plan.mounts.map((mount) => ({
      Type: mount.type,
      ...(mount.type === "volume"
        ? { Name: mount.source, Source: `/var/lib/docker/volumes/${mount.source}/_data` }
        : { Source: mount.source }),
      Destination: mount.target,
      RW: !mount.readOnly,
    })),
    State: {
      Running: running,
      Status: running ? "running" : "created",
      Pid: running ? 4242 : 0,
      StartedAt: running ? SESSION_TEST_DOCKER_STARTED_AT : "0001-01-01T00:00:00Z",
      Dead: false,
      Paused: false,
      Restarting: false,
      OOMKilled: false,
      Error: "",
      ExitCode: 0,
    },
    NetworkSettings: {
      Networks: {
        [running
          ? `${plan.expectedProject.composeProject}_agent_internal`
          : plan.effectiveControlPlane.networkIds.agentInternal]: {
          NetworkID: running ? plan.effectiveControlPlane.networkIds.agentInternal : "",
          EndpointID: running ? SESSION_TEST_NETWORK_ENDPOINT_ID : "",
          IPAddress: running ? plan.record.sourceIp : "",
          IPAMConfig: {
            IPv4Address: plan.record.sourceIp,
          },
          GlobalIPv6Address: "",
        },
      },
    },
  }]);
}

export function sessionTestGitLayout(): RuntimeGitLayoutPlan {
  return {
    version: 1,
    kind: "relative-linked",
    hostProjectRoot: SESSION_TEST_PROJECT_ROOT,
    hostGitDir: "/host/repos/payments/.git/worktrees/feature",
    hostGitCommonDir: "/host/repos/payments/.git",
    hostBase: "/host/repos/payments",
    projectRel: "../worktrees/payments",
    commonRel: "../repos/payments/.git",
    relativeGitDir: "../../repos/payments/.git/worktrees/feature",
    containerBase: "/runfree/git-layout/0123456789ab",
    containerProjectRoot: "/runfree/git-layout/0123456789ab/worktrees/payments",
    containerCompatRoot: "/workspace",
    containerGitCommonDir: "/runfree/git-layout/0123456789ab/repos/payments/.git",
    containerGitDir: "/runfree/git-layout/0123456789ab/repos/payments/.git/worktrees/feature",
  };
}

export function sessionTestDependencies(): DependencyOverlayPlan {
  return {
    version: 1,
    projectRoot: SESSION_TEST_PROJECT_ROOT,
    workspaceHash: SESSION_TEST_PROJECT.projectId,
    mode: "auto",
    packageManagers: ["pnpm"],
    roots: [],
    workspaceRoots: [],
    overlays: [{
      path: path.join(SESSION_TEST_PROJECT_ROOT, "node_modules"),
      hostRelativePath: "node_modules",
      volume: "runfree-deps-0123456789ab-node-modules",
      reason: "pnpm workspace root",
    }],
    ignoredCandidates: [],
    warnings: [],
    storeVolumes: [{
      ecosystem: "javascript",
      storeName: "pnpm",
      packageManager: "pnpm",
      volume: "runfree-deps-0123456789ab-pnpm-store",
      target: "/home/agent/.local/share/pnpm/store",
      environment: { NPM_CONFIG_STORE_DIR: "/home/agent/.local/share/pnpm/store" },
    }],
    installCommands: [],
  };
}

export function sessionContainerTemplateFixture(input: {
  sessionLiveProbeRoot?: string;
} = {}): SessionContainerTemplate {
  const gitLayout = sessionTestGitLayout();
  return createSessionContainerTemplate({
    projectRoot: SESSION_TEST_PROJECT_ROOT,
    project: sessionTestProjectInfo(),
    composeProjectName: SESSION_TEST_PROJECT.composeProject,
    gitLayout,
    dependencyOverlays: sessionTestDependencies(),
    runtimeEnvironment: {
      RUNFREE_PROJECT_NAME: "payments",
      RUNFREE_PROJECT_CONTAINER_ROOT: "/workspaces/payments",
      RUNFREE_PROJECT_COMPAT_ROOT: "/workspace",
      RUNFREE_PROJECT_PHYSICAL_ROOT: gitLayout.containerProjectRoot,
      RUNFREE_PROXY_IP: "172.31.90.10",
    },
    selectedAgentEnvironment: {
      displayPath: "/host/effective/agent.env",
      source: "GH_TOKEN=raw-secret\nTERM=xterm-256color\n",
    },
  });
}

export function sessionGenerationFixture(): {
  target: RuntimeGenerationTargetV2;
  generation: SessionAgentGenerationV2;
} {
  const topology = createRuntimeTopologyGenerationV2({
    controlPlaneTopologyDigest: sha256Digest("control-plane-topology"),
    sessionTemplateDigest: sha256Digest("session-template"),
  });
  const sessionAgent = createSessionAgentGenerationInputsV2({
    selectedAgentImageInputDigest: sha256Digest("agent-image-input"),
    sessionTemplateDigest: topology.sessionTemplateDigest,
    admissionContractEpoch: RUNTIME_ADMISSION_CONTRACT_EPOCH,
  });
  const target: RuntimeGenerationTargetV2 = {
    topology,
    controlPlane: createControlPlaneGenerationV2({
      ...SESSION_TEST_PROJECT,
      proxyImageInputDigest: sha256Digest("proxy-image-input"),
      controlPlaneTopologyDigest: topology.controlPlaneTopologyDigest,
      admissionContractEpoch: RUNTIME_ADMISSION_CONTRACT_EPOCH,
    }),
    sessionAgent,
  };
  return {
    target,
    generation: bindSessionAgentImageV2(sessionAgent, sha256Digest("agent-image-id")),
  };
}

export function sessionAgentMaterializationFixture(input: {
  generation?: SessionAgentGenerationV2;
} = {}): SessionAgentMaterializationManifestV2 {
  const generation = input.generation ?? sessionGenerationFixture().generation;
  return createSessionAgentMaterializationManifestV2({
    ...SESSION_TEST_PROJECT,
    generation,
    selectedAgentImageRef: "runfree/agent-project:test",
    selectedAgentImageId: generation.selectedAgentImageId,
    selectedAgentImageKind: "project",
    sessionTemplateArtifactSha256: sha256Digest("session-template-artifact"),
  });
}

export function effectiveControlPlaneFixture(input: {
  target?: RuntimeGenerationTargetV2;
  admissionContractEpoch?: number;
} = {}): ControlPlaneEffectiveSelectionV2 {
  const target = input.target ?? sessionGenerationFixture().target;
  const materialization = controlPlaneMaterializationFixture({ target });
  return {
    schemaVersion: 2,
    ...SESSION_TEST_PROJECT,
    controlPlaneGenerationDigest: target.controlPlane.controlPlaneGenerationDigest,
    controlPlaneMaterializationDigest: materialization.controlPlaneMaterializationDigest,
    proxyContainerId: "7".repeat(64),
    proxyImageId: sha256Digest("proxy-image-id"),
    sidecarContainerIds: [],
    networkIds: {
      agentInternal: "8".repeat(64),
      proxyEgress: "9".repeat(64),
    },
    securityContractHash: sha256Digest("security-contract"),
    proofSchemaVersion: CONTROL_PLANE_PROOF_SCHEMA_VERSION,
    admissionContractEpoch: input.admissionContractEpoch ?? target.controlPlane.admissionContractEpoch,
    denyByDefaultBaseProofHash: sha256Digest("deny-by-default-base-proof"),
    selectedAt: "2026-08-08T11:59:00.000Z",
    runfreeVersion: "0.3.0",
  };
}

export function controlPlaneMaterializationFixture(input: {
  target?: RuntimeGenerationTargetV2;
  proxyImageId?: string;
} = {}): ControlPlaneMaterializationManifestV2 {
  const target = input.target ?? sessionGenerationFixture().target;
  return createControlPlaneMaterializationManifestV2({
    ...SESSION_TEST_PROJECT,
    generation: target.controlPlane,
    proxyImageRef: "runfree/proxy:test",
    proxyImageId: input.proxyImageId ?? sha256Digest("proxy-image-id"),
    renderedControlPlaneSha256: target.controlPlane.controlPlaneTopologyDigest,
    sessionAdmissionSource: "files",
  });
}

export function sessionContainerRecordFixture(input: {
  target?: RuntimeGenerationTargetV2;
  generation?: SessionAgentGenerationV2;
  containerId?: string;
  overrides?: Partial<SessionContainerRecordV2>;
} = {}): SessionContainerRecordV2 {
  const defaults = sessionGenerationFixture();
  const target = input.target ?? defaults.target;
  const generation = input.generation ?? defaults.generation;
  const allocated = {
    ...createAllocatedSessionContainerRecordV2({
      sessionId: "rf-20260808-abcdef",
      displayName: "payments",
      command: "codex",
      launch: createSessionLaunchTarget({
        path: "/usr/local/bin/codex",
        args: ["--dangerously-bypass-approvals-and-sandbox"],
        interactive: true,
        tty: true,
      }),
      sourceIp: "172.31.90.20",
      materialization: sessionAgentMaterializationFixture({ generation }),
      effectiveControlPlane: effectiveControlPlaneFixture({ target }),
      hostPid: 123,
      createdAt: "2026-08-08T12:00:00.000Z",
    }),
    ...input.overrides,
  };
  return input.containerId === undefined
    ? allocated
    : bindAllocatedSessionContainerIdV2(allocated, input.containerId);
}

export function sessionContainerCreatePlanFixture(input: {
  template?: SessionContainerTemplate;
  target?: RuntimeGenerationTargetV2;
  generation?: SessionAgentGenerationV2;
  record?: SessionContainerRecordV2;
  containerId?: string;
  architecture?: "amd64" | "arm64";
} = {}): SessionContainerCreatePlan {
  const defaults = sessionGenerationFixture();
  const target = input.target ?? defaults.target;
  const generation = input.generation ?? defaults.generation;
  const template = bindSessionContainerTemplateGenerationV2(
    input.template ?? sessionContainerTemplateFixture(),
    target,
  );
  const record = input.record ?? sessionContainerRecordFixture({ target, generation, containerId: input.containerId });
  const launch = createSessionLaunchTarget({
    path: record.launchPath,
    args: record.launchArgs,
    interactive: record.interactive,
    tty: record.tty,
  });
  const imageDeclarationProof = createSessionImageDeclarationProof({
    image: {
      architecture: input.architecture ?? "amd64",
      id: record.selectedAgentImageId,
      labels: {},
      os: "linux",
      volumes: [],
    },
    selectedAgentImageId: record.selectedAgentImageId,
    mounts: template.mounts,
    environment: template.environment,
  });
  return createSessionContainerCreatePlan({
    expectedProject: SESSION_TEST_PROJECT,
    template,
    generationTarget: target,
    sessionAgentGeneration: generation,
    sessionAgentMaterialization: sessionAgentMaterializationFixture({ generation }),
    effectiveControlPlane: effectiveControlPlaneFixture({ target }),
    launch,
    imageDeclarationProof,
    record,
    runfreeVersion: "0.3.0",
  });
}

/**
 * A provisioning-running container proof, minted the same way production mints
 * it: from an exact Docker inspection of the started container. This is the
 * activation authority, so tests must not hand-construct one.
 */
export function sessionContainerRunningProofFixture(
  plan: SessionContainerCreatePlan,
): SessionContainerProof {
  return validateSessionContainerInspect(
    sessionContainerInspectJsonFixture(plan, { running: true }),
    plan,
    { kind: "provisioning-running" },
  );
}

/**
 * Persists a live attached session record for the fixture project so a test
 * can stand in front of the live-session control fence. Liveness classification
 * reads the host pid plus the RUNFREE_TEST_HOST_BOOT_ID and
 * RUNFREE_TEST_HOST_PROCESS_START values from `env`, so callers must launch
 * the code under test with the same values.
 */
export function writeLiveAttachedSessionContainerRecordFixture(input: {
  stateDir: string;
  projectRoot: string;
  env?: NodeJS.ProcessEnv;
  sessionId?: string;
  containerId?: string;
  leaseExpiresAt?: string;
}): SessionContainerRecordV2 {
  const projectId = projectHash(input.projectRoot);
  const composeProject = composeProjectName(input.projectRoot);
  const sessionId = input.sessionId ?? "rf-20260901-livesess";
  const base = sessionContainerRecordFixture({
    containerId: input.containerId ?? "c".repeat(64),
    overrides: {
      projectId,
      composeProject,
      sessionId,
      containerName: `runfree-${projectId}-session-${sessionId}`,
      hostPid: process.pid,
      hostBootId: input.env?.RUNFREE_TEST_HOST_BOOT_ID,
      hostProcessStart: input.env?.RUNFREE_TEST_HOST_PROCESS_START,
      createdAt: "2026-09-01T00:00:00.000Z",
    },
  });
  const record = {
    ...base,
    state: "attached" as const,
    admittedAt: "2026-09-01T00:00:00.000Z",
    leaseGeneration: "8".repeat(32),
    leaseExpiresAt: input.leaseExpiresAt ?? new Date(Date.now() + 5 * 60_000).toISOString(),
  };
  writeSessionContainerRecordV2(input.stateDir, { projectId, composeProject }, record);
  return record;
}
