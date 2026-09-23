import path from "node:path";

import { describe, expect, test } from "vitest";

import type { ProjectInfo } from "../config.ts";
import { RUNFREE_PLACEHOLDER_VALUE } from "../../../../scripts/services.ts";
import {
  bindSessionAgentImageV2,
  createControlPlaneGenerationV2,
  createRuntimeTopologyGenerationV2,
  createSessionAgentGenerationInputsV2,
  type RuntimeGenerationTargetV2,
  type SessionAgentGenerationV2,
} from "./component-state-v2.ts";
import { sha256Digest } from "./component-state.ts";
import type { DependencyOverlayPlan } from "./dependency-overlays.ts";
import type { RuntimeGitLayoutPlan } from "./git-layout.ts";
import {
  SESSION_TEST_PROJECT,
  effectiveControlPlaneFixture,
  sessionAgentMaterializationFixture,
  sessionContainerCreatePlanFixture,
  sessionContainerRecordFixture,
  sessionContainerTemplateFixture,
  sessionGenerationFixture,
} from "./session-container.test-harness.ts";
import {
  assertSessionContainerCreatePlan,
  bindSessionContainerCreatePlanRecord,
  bindSessionContainerTemplateGenerationV2,
  composeManagedVolumeName,
  createSessionContainerCreatePlan,
  createSessionContainerTemplate,
  sessionContainerTopologyProjectionV2,
  type SessionContainerCreatePlan,
  type SessionContainerCreatePlanInput,
  type SessionContainerTemplate,
  type SessionContainerTemplateInput,
} from "./session-container-template.ts";
import { createSessionImageDeclarationProof } from "./session-image-declarations.ts";
import { createSessionLaunchTarget } from "./session-launch.ts";
import {
  bindAllocatedSessionContainerIdV2,
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2,
  transitionProvisioningRunningSessionContainerToAttachedV2,
  type SessionContainerRecordV2,
} from "./session-containers.ts";

const PROJECT_ROOT = "/host/worktrees/payments";
const STATE_ROOT = "/host/runfree/state/payments";
const COMPOSE_PROJECT = "runfree-0123456789ab";

function project(): ProjectInfo {
  const runfreeDir = path.join(PROJECT_ROOT, ".runfree");
  return {
    config: { version: 4, project: {}, agents: {}, runtime: {} },
    paths: {
      runfreeDir,
      agentEnvPath: path.join(runfreeDir, "config", "agent.env"),
      claudeConfigPath: path.join(STATE_ROOT, "claude.json"),
      claudeMcpConfigPath: path.join(STATE_ROOT, "mcp", "claude.json"),
      claudeDir: path.join(STATE_ROOT, "claude"),
      codexDir: path.join(STATE_ROOT, "codex"),
      configPath: path.join(runfreeDir, "runfree.json"),
      controlApprovalsPath: path.join(STATE_ROOT, "control", "approvals.json"),
      controlAgentEnvPath: path.join(STATE_ROOT, "control", "inputs", "agent.env"),
      controlMcpNetworkPolicyPath: path.join(STATE_ROOT, "control", "mcp-network-policy.json"),
      controlApprovedDir: path.join(STATE_ROOT, "control", "approved"),
      controlCandidatesDir: path.join(STATE_ROOT, "control", "candidates"),
      controlConvergedPath: path.join(STATE_ROOT, "control", "converged.json"),
      controlDir: path.join(STATE_ROOT, "control"),
      controlEffectiveDir: path.join(STATE_ROOT, "control", "effective"),
      controlLegacyEnforcedNetworkPath: path.join(STATE_ROOT, "control", "legacy.json"),
      controlProxyActivePath: path.join(STATE_ROOT, "control", "proxy-active.json"),
      controlProxyDir: path.join(STATE_ROOT, "control", "effective", "proxy"),
      gitConfigPath: path.join(STATE_ROOT, "gitconfig"),
      inboxDir: path.join(STATE_ROOT, "inbox"),
      projectCodexDirMaskPath: path.join(STATE_ROOT, "mounts", "project-codex"),
      mcpOAuthPolicyPath: path.join(STATE_ROOT, "mcp-oauth-policy.json"),
      proxyCaCertDir: path.join(STATE_ROOT, "proxy-ca", "public"),
      proxyCaKeyDir: path.join(STATE_ROOT, "proxy-ca", "private"),
      policyPath: path.join(runfreeDir, "network-policy.json"),
      sessionsDir: path.join(STATE_ROOT, "sessions"),
      stateDir: STATE_ROOT,
      tokenConfigPath: path.join(STATE_ROOT, "tokens.json"),
    },
  } as ProjectInfo;
}

function gitLayout(): RuntimeGitLayoutPlan {
  return {
    version: 1,
    kind: "relative-linked",
    hostProjectRoot: PROJECT_ROOT,
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

function dependencies(): DependencyOverlayPlan {
  return {
    version: 1,
    projectRoot: PROJECT_ROOT,
    workspaceHash: "0123456789ab",
    mode: "auto",
    packageManagers: ["pnpm"],
    roots: [],
    workspaceRoots: [],
    overlays: [{
      path: path.join(PROJECT_ROOT, "node_modules"),
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

function input(overrides: Partial<SessionContainerTemplateInput> = {}): SessionContainerTemplateInput {
  return {
    projectRoot: PROJECT_ROOT,
    project: project(),
    composeProjectName: COMPOSE_PROJECT,
    gitLayout: gitLayout(),
    dependencyOverlays: dependencies(),
    runtimeEnvironment: {
      RUNFREE_PROJECT_NAME: "payments",
      RUNFREE_PROJECT_CONTAINER_ROOT: "/workspaces/payments",
      RUNFREE_PROJECT_COMPAT_ROOT: "/workspace",
      RUNFREE_PROJECT_PHYSICAL_ROOT: gitLayout().containerProjectRoot,
      RUNFREE_PROXY_IP: "172.31.90.10",
      RUNFREE_PROXY_CA_KEY_DIR: "/must/not/appear/private-ca",
      RUNFREE_EFFECTIVE_PROXY_DIR: "/must/not/appear/proxy-controls",
      DOCKER_CONFIG: "/must/not/appear/docker-config",
    },
    selectedAgentEnvironment: {
      displayPath: "/host/effective/agent.env",
      source: [
        "GH_TOKEN=raw-github-secret",
        "CUSTOM_API_KEY=raw-custom-secret",
        "HTTPS_PROXY=http://attacker.invalid:8080",
        "APPLE_ADS_CLIENT_ID=SEARCHADS.client-id",
        `APPLE_ADS_CLIENT_SECRET=runfree_oauth_secret_${"a".repeat(32)}`,
        "ACME_REGION=eu-1",
        "ACME_TOKEN=raw-acme-secret",
        "",
      ].join("\n"),
      declaredParameterEnvNames: ["ACME_REGION"],
    },
    ...overrides,
  };
}

function createPlanRuntimeInputs(input: {
  template: SessionContainerTemplate;
  target: RuntimeGenerationTargetV2;
  generation: SessionAgentGenerationV2;
  record: SessionContainerRecordV2;
}): Pick<
  SessionContainerCreatePlanInput,
  "effectiveControlPlane" | "imageDeclarationProof" | "launch"
> {
  const launch = createSessionLaunchTarget({
    path: input.record.launchPath,
    args: input.record.launchArgs,
    interactive: input.record.interactive,
    tty: input.record.tty,
  });
  const imageDeclarationProof = createSessionImageDeclarationProof({
    image: {
      architecture: "amd64",
      id: input.generation.selectedAgentImageId,
      labels: {},
      os: "linux",
      volumes: ["/commandhistory"],
      environment: {
        IMAGE_DEFAULT: "preserved",
        HTTPS_PROXY: "http://image.invalid:8080",
      },
    },
    selectedAgentImageId: input.generation.selectedAgentImageId,
    mounts: input.template.mounts,
    environment: input.template.environment,
  });
  return {
    effectiveControlPlane: effectiveControlPlaneFixture({ target: input.target }),
    launch,
    imageDeclarationProof,
  };
}

describe("canonical session-container template", () => {
  test("reproduces the complete safe agent mount and environment projection", () => {
    const template = createSessionContainerTemplate(input());
    const byTarget = new Map(template.mounts.map((mount) => [mount.target, mount]));
    const layout = gitLayout();
    if (layout.kind !== "relative-linked") throw new Error("test requires linked-worktree layout");

    expect([...byTarget]).toEqual(expect.arrayContaining([
      [layout.containerProjectRoot, expect.objectContaining({ source: PROJECT_ROOT, readOnly: false })],
      [layout.containerGitCommonDir, expect.objectContaining({ source: layout.hostGitCommonDir, readOnly: false })],
      ["/home/agent/.claude", expect.objectContaining({ source: path.join(STATE_ROOT, "claude"), readOnly: false })],
      ["/home/agent/.claude.json", expect.objectContaining({ source: path.join(STATE_ROOT, "claude.json"), readOnly: false })],
      ["/home/agent/.codex", expect.objectContaining({ source: path.join(STATE_ROOT, "codex"), readOnly: false })],
      ["/home/agent/.pi/agent", expect.objectContaining({ source: path.join(STATE_ROOT, "pi"), readOnly: false })],
      ["/home/agent/.gitconfig", expect.objectContaining({ readOnly: true })],
      ["/runfree/inbox", expect.objectContaining({ source: project().paths.inboxDir, readOnly: true })],
      ["/runfree/mcp/claude.json", expect.objectContaining({ readOnly: true })],
      ["/etc/proxy-ca", expect.objectContaining({ source: project().paths.proxyCaCertDir, readOnly: true })],
      ["/commandhistory", expect.objectContaining({
        source: `${COMPOSE_PROJECT}_runfree-commandhistory`,
        type: "volume",
        noCopy: true,
      })],
      [`${gitLayout().containerProjectRoot}/node_modules`, expect.objectContaining({
        source: `${COMPOSE_PROJECT}_runfree-deps-0123456789ab-node-modules`,
        type: "volume",
        noCopy: true,
      })],
      ["/home/agent/.local/share/pnpm/store", expect.objectContaining({
        source: `${COMPOSE_PROJECT}_runfree-deps-0123456789ab-pnpm-store`,
        type: "volume",
        noCopy: true,
      })],
    ]));
    expect(template.mounts.map((mount) => mount.target)).toEqual(
      [...template.mounts].map((mount) => mount.target).sort(),
    );
    expect(new Set(template.mounts.map((mount) => mount.target)).size).toBe(template.mounts.length);

    expect(template.environment).toMatchObject({
      ACME_REGION: "eu-1",
      ACME_TOKEN: RUNFREE_PLACEHOLDER_VALUE,
      APPLE_ADS_CLIENT_ID: "SEARCHADS.client-id",
      APPLE_ADS_CLIENT_SECRET: `runfree_oauth_secret_${"a".repeat(32)}`,
      CUSTOM_API_KEY: RUNFREE_PLACEHOLDER_VALUE,
      GH_TOKEN: RUNFREE_PLACEHOLDER_VALUE,
      HTTPS_PROXY: "http://172.31.90.10:8080",
      RUNFREE_PROJECT_NAME: "payments",
      RUNFREE_PROJECT_PHYSICAL_ROOT: gitLayout().containerProjectRoot,
      NPM_CONFIG_STORE_DIR: "/home/agent/.local/share/pnpm/store",
    });
    expect(JSON.stringify(template)).not.toContain("raw-github-secret");
    expect(JSON.stringify(template)).not.toContain("raw-custom-secret");
    expect(JSON.stringify(template)).not.toContain("raw-acme-secret");
    expect(JSON.stringify(template)).not.toContain("attacker.invalid");
    expect(JSON.stringify(template)).not.toContain("must/not/appear");
    expect(template.mounts.some((mount) => mount.target.startsWith("/ca/private"))).toBe(false);
    expect(template.mounts.some((mount) => mount.target.startsWith("/run/runfree-"))).toBe(false);
    expect(template.mounts.some((mount) => mount.source.includes("docker"))).toBe(false);
  });

  test("is canonical across selected-env and dependency input ordering", () => {
    const baseline = createSessionContainerTemplate(input());
    const reorderedDependencies = dependencies();
    reorderedDependencies.overlays.reverse();
    reorderedDependencies.storeVolumes.reverse();
    const reordered = createSessionContainerTemplate(input({
      dependencyOverlays: reorderedDependencies,
      selectedAgentEnvironment: {
        displayPath: "/host/effective/agent.env",
        source: [...input().selectedAgentEnvironment.source.trim().split("\n")].reverse().join("\n"),
        declaredParameterEnvNames: input().selectedAgentEnvironment.declaredParameterEnvNames,
      },
    }));
    expect(reordered).toEqual(baseline);
    expect(sessionContainerTopologyProjectionV2(reordered))
      .toEqual(sessionContainerTopologyProjectionV2(baseline));
  });

  test("projects the fixed stopped-create and admitted-network contracts", () => {
    const projection = sessionContainerTopologyProjectionV2(createSessionContainerTemplate(input()));
    expect(projection).toMatchObject({
      schemaVersion: 2,
      createContract: {
        user: "1000:1000",
        init: false,
        stopSignal: "SIGTERM",
        createdStopped: true,
        networkAtCreate: true,
        healthcheckDisabled: true,
        restartPolicy: "no",
        securityOptions: ["no-new-privileges:true"],
        capabilityAdds: [],
        capabilityDrops: ["NET_ADMIN", "NET_RAW"],
        launch: {
          path: "exact-absolute-per-session",
          args: "exact-per-session",
          interactive: "exact-per-session",
          tty: "exact-per-session",
          firstProjectControlledProcess: true,
          foregroundStartAttach: true,
          dockerExec: false,
        },
        runfreeLabelNames: [
          "io.runfree.admission-contract-epoch",
          "io.runfree.compose-project",
          "io.runfree.container-role",
          "io.runfree.digest-schema",
          "io.runfree.image-input-digest",
          "io.runfree.image-role",
          "io.runfree.label-schema",
          "io.runfree.lifecycle-owner",
          "io.runfree.managed",
          "io.runfree.project-id",
          "io.runfree.selected-agent-image-id",
          "io.runfree.selected-agent-image-input-digest",
          "io.runfree.session-agent-generation-digest",
          "io.runfree.session-agent-materialization-digest",
          "io.runfree.session-id",
          "io.runfree.session-incarnation",
          "io.runfree.session-template-digest",
          "io.runfree.version",
        ],
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
    });
    expect(projection).toMatchObject({
      mounts: expect.arrayContaining([expect.objectContaining({
        target: "/etc/proxy-ca",
        readOnly: true,
      })]),
    });
    expect(JSON.stringify(projection)).not.toMatch(/idle-v1|session-supervisor|finaliz|docker-exec/u);
  });

  test("fails closed for cross-project layouts and malformed volume identities", () => {
    expect(() => createSessionContainerTemplate(input({ projectRoot: "/host/other" })))
      .toThrow("different project root");
    expect(() => composeManagedVolumeName("bad/project", "volume"))
      .toThrow("Compose project name");
    expect(() => composeManagedVolumeName(COMPOSE_PROJECT, "bad/volume"))
      .toThrow("logical volume name");
  });

  test("rejects forged canonical templates and final create plans", () => {
    const template = sessionContainerTemplateFixture();
    const { target, generation } = sessionGenerationFixture();
    bindSessionContainerTemplateGenerationV2(template, target);
    const record = sessionContainerRecordFixture({ target, generation });
    const materialization = sessionAgentMaterializationFixture({ generation });
    const runtimeInputs = createPlanRuntimeInputs({
      template,
      target,
      generation,
      record,
    });
    const plan = createSessionContainerCreatePlan({
      expectedProject: SESSION_TEST_PROJECT,
      template,
      generationTarget: target,
      sessionAgentGeneration: generation,
      sessionAgentMaterialization: materialization,
      ...runtimeInputs,
      record,
      runfreeVersion: "0.3.0",
    });

    expect(Object.isFrozen(template)).toBe(true);
    expect(Object.isFrozen(template.environment)).toBe(true);
    expect(template.mounts.every(Object.isFrozen)).toBe(true);
    expect(Object.isFrozen(plan)).toBe(true);
    expect(Object.isFrozen(plan.record)).toBe(true);
    expect(Object.isFrozen(plan.record.launchArgs)).toBe(true);
    expect(Object.isFrozen(plan.effectiveControlPlane)).toBe(true);
    expect(Object.isFrozen(plan.launch)).toBe(true);
    expect(Object.isFrozen(plan.imageDeclarationProof)).toBe(true);
    expect(plan.environment).toBe(template.environment);
    expect(plan.mounts).toBe(template.mounts);
    expect(plan.effectiveControlPlane.controlPlaneGenerationDigest)
      .toBe(plan.record.controlPlaneGenerationDigest);
    expect(plan.effectiveControlPlane.admissionContractEpoch).toBe(plan.record.admissionContractEpoch);
    expect(plan.effectiveControlPlane.networkIds.agentInternal).toBe("8".repeat(64));
    expect(plan.launch).toMatchObject({
      path: record.launchPath,
      args: record.launchArgs,
      interactive: true,
      tty: true,
    });
    expect(plan.imageDeclarationProof).toMatchObject({
      selectedAgentImageId: record.selectedAgentImageId,
      declaredVolumeTargets: ["/commandhistory"],
      mergedEnvironment: expect.objectContaining({
        IMAGE_DEFAULT: "preserved",
        HTTPS_PROXY: template.environment.HTTPS_PROXY,
      }),
    });
    expect(() => sessionContainerTopologyProjectionV2({
      ...template,
    } as unknown as SessionContainerTemplate)).toThrow("was not minted");
    const otherTopology = createRuntimeTopologyGenerationV2({
      controlPlaneTopologyDigest: target.topology.controlPlaneTopologyDigest,
      sessionTemplateDigest: sha256Digest("other-session-template"),
    });
    expect(() => bindSessionContainerTemplateGenerationV2(template, {
      topology: otherTopology,
      controlPlane: target.controlPlane,
      sessionAgent: createSessionAgentGenerationInputsV2({
        selectedAgentImageInputDigest: target.sessionAgent.selectedAgentImageInputDigest,
        sessionTemplateDigest: otherTopology.sessionTemplateDigest,
        admissionContractEpoch: target.sessionAgent.admissionContractEpoch,
      }),
    })).toThrow("already bound");
    expect(() => createSessionContainerCreatePlan({
      expectedProject: SESSION_TEST_PROJECT,
      template: sessionContainerTemplateFixture(),
      generationTarget: target,
      sessionAgentGeneration: generation,
      sessionAgentMaterialization: materialization,
      ...runtimeInputs,
      record,
      runfreeVersion: "0.3.0",
    })).toThrow("not bound");

    for (const forged of [
      { ...plan, environment: { ...plan.environment, HTTPS_PROXY: "http://attacker:8080" } },
      { ...plan, mounts: plan.mounts.slice(1) },
    ] as unknown as SessionContainerCreatePlan[]) {
      expect(() => assertSessionContainerCreatePlan(forged)).toThrow("was not minted");
    }
  });

  test("rebinds a canonical create plan only through the exact lifecycle sequence", () => {
    const allocatedPlan = sessionContainerCreatePlanFixture();
    const boundRecord = bindAllocatedSessionContainerIdV2(allocatedPlan.record, "3".repeat(64));

    const boundPlan = bindSessionContainerCreatePlanRecord(allocatedPlan, boundRecord);

    expect(boundPlan).not.toBe(allocatedPlan);
    expect(boundPlan.record).toEqual(boundRecord);
    expect(Object.isFrozen(boundPlan)).toBe(true);
    expect(Object.isFrozen(boundPlan.record)).toBe(true);
    expect(() => assertSessionContainerCreatePlan(boundPlan)).not.toThrow();
    expect(boundPlan.template).toBe(allocatedPlan.template);
    expect(boundPlan.imageDeclarationProof).toBe(allocatedPlan.imageDeclarationProof);

    const provisioningRecord = transitionBoundAllocatedSessionContainerToProvisioningRunningV2(boundRecord, {
      admittedAt: "2026-08-08T12:00:01.000Z",
      leaseGeneration: "4".repeat(32),
      leaseExpiresAt: "2026-08-08T12:02:01.000Z",
    });
    const provisioningPlan = bindSessionContainerCreatePlanRecord(boundPlan, provisioningRecord);
    expect(provisioningPlan.record).toEqual(provisioningRecord);
    expect(() => assertSessionContainerCreatePlan(provisioningPlan)).not.toThrow();
  });

  test("rejects forged plans, cross-session rebinding, and skipped lifecycle states", () => {
    const allocatedPlan = sessionContainerCreatePlanFixture();
    const boundRecord = bindAllocatedSessionContainerIdV2(allocatedPlan.record, "3".repeat(64));
    const boundPlan = bindSessionContainerCreatePlanRecord(allocatedPlan, boundRecord);
    const provisioningRecord = transitionBoundAllocatedSessionContainerToProvisioningRunningV2(boundRecord, {
      admittedAt: "2026-08-08T12:00:01.000Z",
      leaseGeneration: "4".repeat(32),
      leaseExpiresAt: "2026-08-08T12:02:01.000Z",
    });
    const skippedRecord = transitionProvisioningRunningSessionContainerToAttachedV2(provisioningRecord);
    const crossSession = sessionContainerRecordFixture({
      containerId: "5".repeat(64),
      overrides: {
        sessionIncarnation: "6".repeat(64),
        sessionPrincipal: "7".repeat(64),
      },
    });

    expect(() => bindSessionContainerCreatePlanRecord(
      { ...allocatedPlan } as SessionContainerCreatePlan,
      boundRecord,
    )).toThrow("canonical plan builder");
    expect(() => bindSessionContainerCreatePlanRecord(allocatedPlan, crossSession))
      .toThrow(/different lifecycle authority|immutable/);
    expect(() => bindSessionContainerCreatePlanRecord(boundPlan, skippedRecord))
      .toThrow(/allocated -> attached/);
  });

  test("rejects every mismatched generation relationship", () => {
    const template = sessionContainerTemplateFixture();
    const baseline = sessionGenerationFixture();
    bindSessionContainerTemplateGenerationV2(template, baseline.target);
    const record = sessionContainerRecordFixture(baseline);
    const materialization = sessionAgentMaterializationFixture({ generation: baseline.generation });
    const runtimeInputs = createPlanRuntimeInputs({
      template,
      target: baseline.target,
      generation: baseline.generation,
      record,
    });
    const valid: SessionContainerCreatePlanInput = {
      expectedProject: SESSION_TEST_PROJECT,
      template,
      generationTarget: baseline.target,
      sessionAgentGeneration: baseline.generation,
      sessionAgentMaterialization: materialization,
      ...runtimeInputs,
      record,
      runfreeVersion: "0.3.0",
    };
    expect(() => createSessionContainerCreatePlan(valid)).not.toThrow();

    const otherImageInputs = createSessionAgentGenerationInputsV2({
      selectedAgentImageInputDigest: sha256Digest("other-agent-image-input"),
      sessionTemplateDigest: baseline.target.sessionAgent.sessionTemplateDigest,
      admissionContractEpoch: baseline.target.sessionAgent.admissionContractEpoch,
    });
    const otherTemplateInputs = createSessionAgentGenerationInputsV2({
      selectedAgentImageInputDigest: baseline.target.sessionAgent.selectedAgentImageInputDigest,
      sessionTemplateDigest: sha256Digest("other-session-template"),
      admissionContractEpoch: baseline.target.sessionAgent.admissionContractEpoch,
    });
    const otherEpochInputs = createSessionAgentGenerationInputsV2({
      selectedAgentImageInputDigest: baseline.target.sessionAgent.selectedAgentImageInputDigest,
      sessionTemplateDigest: baseline.target.sessionAgent.sessionTemplateDigest,
      admissionContractEpoch: baseline.target.sessionAgent.admissionContractEpoch + 1,
    });
    const otherControl = createControlPlaneGenerationV2({
      ...SESSION_TEST_PROJECT,
      proxyImageInputDigest: sha256Digest("other-proxy-image-input"),
      controlPlaneTopologyDigest: baseline.target.topology.controlPlaneTopologyDigest,
      admissionContractEpoch: baseline.target.controlPlane.admissionContractEpoch,
    });
    const otherProjectControl = createControlPlaneGenerationV2({
      projectId: "abcdef012345",
      composeProject: "runfree-abcdef012345",
      proxyImageInputDigest: baseline.target.controlPlane.proxyImageInputDigest,
      controlPlaneTopologyDigest: baseline.target.topology.controlPlaneTopologyDigest,
      admissionContractEpoch: baseline.target.controlPlane.admissionContractEpoch,
    });
    const otherSelectedImageId = sha256Digest("other-selected-image-id");
    const otherImageProof = createSessionImageDeclarationProof({
      image: { architecture: "amd64", id: otherSelectedImageId, labels: {}, os: "linux", volumes: [] },
      selectedAgentImageId: otherSelectedImageId,
      mounts: template.mounts,
      environment: template.environment,
    });

    const mutations: Array<[string, SessionContainerCreatePlanInput]> = [
      ["target project", { ...valid, generationTarget: { ...baseline.target, controlPlane: otherProjectControl } }],
      ["bound image input", {
        ...valid,
        sessionAgentGeneration: bindSessionAgentImageV2(otherImageInputs, baseline.generation.selectedAgentImageId),
      }],
      ["bound template", {
        ...valid,
        sessionAgentGeneration: bindSessionAgentImageV2(otherTemplateInputs, baseline.generation.selectedAgentImageId),
      }],
      ["bound generation digest", {
        ...valid,
        sessionAgentGeneration: {
          ...baseline.generation,
          sessionAgentGenerationDigest: sha256Digest("forged-session-generation"),
        },
      }],
      ["bound epoch", {
        ...valid,
        sessionAgentGeneration: bindSessionAgentImageV2(otherEpochInputs, baseline.generation.selectedAgentImageId),
      }],
      ["record selected image id", {
        ...valid,
        record: { ...record, selectedAgentImageId: otherSelectedImageId },
      }],
      ["record image input", {
        ...valid,
        record: { ...record, selectedAgentImageInputDigest: sha256Digest("other-agent-image-input") },
      }],
      ["record template", {
        ...valid,
        record: { ...record, sessionTemplateDigest: sha256Digest("other-session-template") },
      }],
      ["record session generation", {
        ...valid,
        record: { ...record, sessionAgentGenerationDigest: sha256Digest("other-session-generation") },
      }],
      ["record control generation", {
        ...valid,
        record: { ...record, controlPlaneGenerationDigest: otherControl.controlPlaneGenerationDigest },
      }],
      ["record epoch", {
        ...valid,
        record: { ...record, admissionContractEpoch: record.admissionContractEpoch + 1 },
      }],
      ["effective control generation", {
        ...valid,
        effectiveControlPlane: effectiveControlPlaneFixture({
          target: { ...baseline.target, controlPlane: otherControl },
        }),
      }],
      ["effective control epoch", {
        ...valid,
        effectiveControlPlane: {
          ...valid.effectiveControlPlane,
          admissionContractEpoch: valid.effectiveControlPlane.admissionContractEpoch + 1,
        },
      }],
      ["launch path", {
        ...valid,
        launch: createSessionLaunchTarget({
          path: "/usr/local/bin/other-agent",
          args: record.launchArgs,
          interactive: record.interactive,
          tty: record.tty,
        }),
      }],
      ["launch args", {
        ...valid,
        launch: createSessionLaunchTarget({
          path: record.launchPath,
          args: ["--different"],
          interactive: record.interactive,
          tty: record.tty,
        }),
      }],
      ["image declaration proof", {
        ...valid,
        imageDeclarationProof: otherImageProof,
      }],
      ["image declaration mount plan", {
        ...valid,
        imageDeclarationProof: createSessionImageDeclarationProof({
          image: { architecture: "amd64", id: record.selectedAgentImageId, labels: {}, os: "linux", volumes: [] },
          selectedAgentImageId: record.selectedAgentImageId,
          mounts: template.mounts.slice(1),
          environment: template.environment,
        }),
      }],
      ["image declaration environment plan", {
        ...valid,
        imageDeclarationProof: createSessionImageDeclarationProof({
          image: { architecture: "amd64", id: record.selectedAgentImageId, labels: {}, os: "linux", volumes: [] },
          selectedAgentImageId: record.selectedAgentImageId,
          mounts: template.mounts,
          environment: { ...template.environment, HTTPS_PROXY: "http://attacker.invalid:8080" },
        }),
      }],
    ];

    for (const [label, candidate] of mutations) {
      expect(() => createSessionContainerCreatePlan(candidate), label).toThrow();
    }
  });
});
