import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { beforeEach, expect, test } from "vitest";

import { defaultConfig, projectControlPaths, type ProjectInfo } from "../config.ts";
import { approveNetworkCandidate, approveRuntimeIsolationControl } from "../control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../control/candidates.ts";
import { publishEffectivePolicyGeneration } from "../control/effective.ts";
import {
  bindSessionAgentImageV2,
  createSessionAgentMaterializationManifestV2,
  parseRuntimeGenerationTargetV2,
} from "./component-state-v2.ts";
import { sha256Digest } from "./component-state.ts";
import {
  createRuntimePlan,
  runtimeContextFromPlan,
  runtimeDryRunOutput,
} from "./plan.ts";
import { createSessionContainerCreatePlan } from "./session-container-template.ts";
import { createAllocatedSessionContainerRecordV2 } from "./session-containers.ts";
import { createSessionLaunchTarget } from "./session-launch.ts";
import { createSessionImageDeclarationProof } from "./session-image-declarations.ts";
import type { RuntimeContext } from "./types.ts";

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-plan-"));
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

test("createRuntimePlan does not mutate RuntimeContext or retain host env secrets", () => {
  const projectRoot = path.join(tmp, "project");
  fs.mkdirSync(projectRoot, { recursive: true });
  writeRuntimeCompose(path.join(tmp, "runtime"));
  const context = {
    projectRoot,
    project: projectInfo(projectRoot),
    runtimeRoot: path.join(tmp, "runtime"),
    env: {
      PATH: "/bin",
      SECRET_TOKEN: "must-not-serialize",
      DOCKER_HOST: "unix:///docker.sock",
      RUNFREE_RUNTIME_DRY_RUN: "1",
    },
  } as RuntimeContext;

  const before = JSON.stringify(context);
  const plan = createRuntimePlan(context, { dockerSubnets: [], persistNetwork: false });

  expect(JSON.stringify(context)).toBe(before);
  expect(plan.baseRuntimeRoot).toBe(context.runtimeRoot);
  expect(plan.execution.dockerClientEnv.DOCKER_HOST).toBe("unix:///docker.sock");
  expect(JSON.stringify(plan)).not.toContain("must-not-serialize");
});

test("a context-supplied overlay plan drives every derived plan field", () => {
  // Startup discovers overlays with Git facts this call site cannot see and
  // supplies the result on the context. Deriving from anything else and
  // patching the field afterwards would leave the template and generation
  // describing a different overlay set.
  const projectRoot = path.join(tmp, "project");
  fs.mkdirSync(path.join(projectRoot, "node_modules"), { recursive: true });
  fs.mkdirSync(path.join(projectRoot, "pkg", "node_modules"), { recursive: true });
  fs.writeFileSync(path.join(projectRoot, "package.json"), '{"name":"p","version":"1.0.0"}\n');
  fs.writeFileSync(path.join(projectRoot, "package-lock.json"), '{"lockfileVersion":3}\n');
  fs.writeFileSync(path.join(projectRoot, "pkg", "package.json"), '{"name":"q","version":"1.0.0"}\n');
  fs.writeFileSync(path.join(projectRoot, "pkg", "package-lock.json"), '{"lockfileVersion":3}\n');
  writeRuntimeCompose(path.join(tmp, "runtime"));
  const context = {
    projectRoot,
    project: projectInfo(projectRoot),
    runtimeRoot: path.join(tmp, "runtime"),
    env: { RUNFREE_RUNTIME_DRY_RUN: "1" },
  } as RuntimeContext;

  const scanned = createRuntimePlan(context, { dockerSubnets: [], persistNetwork: false });
  const dropped = scanned.dependencyOverlays.overlays
    .find((overlay) => overlay.hostRelativePath === "pkg/node_modules");
  expect(dropped).toBeDefined();
  const supplied = {
    ...scanned.dependencyOverlays,
    overlays: scanned.dependencyOverlays.overlays.filter((overlay) => overlay !== dropped),
  };

  const plan = createRuntimePlan(
    { ...context, dependencyOverlayPlan: supplied },
    { dockerSubnets: [], persistNetwork: false },
  );

  expect(plan.dependencyOverlays.overlays).toEqual(supplied.overlays);
  expect(JSON.stringify(plan.sessionContainerTemplate)).not.toContain(dropped?.volume);
  expect(JSON.stringify(plan.renderedCompose ?? "")).not.toContain(dropped?.volume);
  expect(plan.generationV2).not.toEqual(scanned.generationV2);
});

test("mints the one admission source into the rendered proxy environment", () => {
  const projectRoot = path.join(tmp, "project");
  fs.mkdirSync(projectRoot, { recursive: true });
  writeRuntimeCompose(path.join(tmp, "runtime"));

  const plan = createRuntimePlan(
    {
      projectRoot,
      project: projectInfo(projectRoot),
      runtimeRoot: path.join(tmp, "runtime"),
      env: { RUNFREE_RUNTIME_DRY_RUN: "1" },
    } as RuntimeContext,
    { dockerSubnets: [], persistNetwork: false },
  );
  // The proxy refuses to start without it, so a render that omitted it would
  // materialize a control plane that can never come up.
  expect(plan.renderedCompose).toContain("      RUNFREE_SESSION_ADMISSION_SOURCE: files");
});

test("dry-run output excludes execution env providers", () => {
  const projectRoot = path.join(tmp, "project");
  fs.mkdirSync(projectRoot, { recursive: true });
  writeRuntimeCompose(path.join(tmp, "runtime"));
  const plan = createRuntimePlan({
    projectRoot,
    project: projectInfo(projectRoot),
    runtimeRoot: path.join(tmp, "runtime"),
    env: { SECRET_TOKEN: "hidden" },
  } as RuntimeContext, { dockerSubnets: [], persistNetwork: false });

  const output = runtimeDryRunOutput("up", plan);

  expect(JSON.stringify(output)).not.toContain("SECRET_TOKEN");
  expect(JSON.stringify(output)).not.toContain("execution");
  expect(output.composeFile).toBe(path.join(plan.projectRuntimeRoot, "agent", "compose.yaml"));
  expect(output.composeProjectName).toMatch(/^runfree-/);
});

test("createRuntimePlan preserves an already selected runtime network", () => {
  const projectRoot = path.join(tmp, "project");
  fs.mkdirSync(projectRoot, { recursive: true });
  writeRuntimeCompose(path.join(tmp, "runtime"));
  const network = {
    agentIp: "172.99.0.11",
    callbackSidecarIp: "172.99.0.12",
    proxyEgressGateway: "172.99.1.1",
    proxyEgressIp: "172.99.1.10",
    proxyEgressSubnet: "172.99.1.0/24",
    proxyIp: "172.99.0.10",
    subnet: "172.99.0.0/24",
  };

  const plan = createRuntimePlan({
    projectRoot,
    project: projectInfo(projectRoot),
    runtimeRoot: path.join(tmp, "runtime"),
    env: {},
    network,
  } as RuntimeContext, { dockerSubnets: ["172.99.0.0/24"], persistNetwork: false });

  expect(plan.network).toEqual(network);
  expect(plan.execution.composeEnv.RUNFREE_CONTAINER_IP).toBe(network.agentIp);
});

test("createRuntimePlan computes but does not select a schema-v2 generation target", () => {
  const projectRoot = path.join(tmp, "project");
  const runtimeRoot = path.join(tmp, "runtime");
  const project = projectInfo(projectRoot);
  fs.mkdirSync(projectRoot, { recursive: true });
  writeRuntimeCompose(runtimeRoot);
  const context = {
    projectRoot,
    project,
    runtimeRoot,
    env: {},
    network: {
      agentIp: "172.99.0.11",
      callbackSidecarIp: "172.99.0.12",
      proxyEgressGateway: "172.99.1.1",
      proxyEgressIp: "172.99.1.10",
      proxyEgressSubnet: "172.99.1.0/24",
      proxyIp: "172.99.0.10",
      subnet: "172.99.0.0/24",
    },
  } as RuntimeContext;

  const plan = createRuntimePlan(context, { dockerSubnets: [], persistNetwork: false });

  expect(parseRuntimeGenerationTargetV2(plan.generationV2)).toEqual(plan.generationV2);
  expect(runtimeContextFromPlan(plan).runtimeGenerationV2).toEqual(plan.generationV2);
  expect(fs.existsSync(path.join(project.paths.stateDir, "runtime", "v2"))).toBe(false);
});

test("stores and reuses the exact session template snapshot despite post-plan agent-env drift", () => {
  // The template's environment source is the SELECTED effective generation's
  // agent/agent.env (placeholders and handles only — raw project env files no
  // longer feed sessions). The generation payload is digest-verified when the
  // plan resolves it, but the durable template is the snapshot later
  // consumers reuse, so post-plan drift of the on-disk generation bytes must
  // never leak into a create plan built from the stored template.
  const projectRoot = path.join(tmp, "project");
  const runtimeRoot = path.join(tmp, "runtime");
  const project = projectInfo(projectRoot);
  writeRuntimeCompose(runtimeRoot);
  const context = {
    projectRoot,
    project,
    runtimeRoot,
    env: {},
    network: {
      agentIp: "172.99.0.11",
      callbackSidecarIp: "172.99.0.12",
      proxyEgressGateway: "172.99.1.1",
      proxyEgressIp: "172.99.1.10",
      proxyEgressSubnet: "172.99.1.0/24",
      proxyIp: "172.99.0.10",
      subnet: "172.99.0.0/24",
    },
  } as RuntimeContext;
  const plan = createRuntimePlan(context, { dockerSubnets: [], persistNetwork: false });
  const storedTemplate = plan.sessionContainerTemplate;

  // Simulate durable-state drift: the generation file is published read-only,
  // so loosen it first, then rewrite the bytes underneath the stored template.
  const agentEnvironmentPath = plan.execution.composeEnv.RUNFREE_AGENT_ENV_FILE as string;
  fs.chmodSync(agentEnvironmentPath, 0o644);
  fs.writeFileSync(agentEnvironmentPath, "APPLE_ADS_CLIENT_ID=SEARCHADS.drifted\n");

  const generation = bindSessionAgentImageV2(
    plan.generationV2.sessionAgent,
    sha256Digest("selected-agent-image-id"),
  );
  const materialization = createSessionAgentMaterializationManifestV2({
    projectId: plan.projectId,
    composeProject: plan.composeProjectName,
    generation,
    selectedAgentImageRef: "runfree/agent-project:test",
    selectedAgentImageId: generation.selectedAgentImageId,
    selectedAgentImageKind: "project",
    sessionTemplateArtifactSha256: sha256Digest("session-template-artifact"),
  });
  const launch = createSessionLaunchTarget({
    path: "/usr/local/bin/codex",
    args: ["--dangerously-bypass-approvals-and-sandbox"],
    interactive: true,
    tty: true,
  });
  const effectiveControlPlane = {
    schemaVersion: 2 as const,
    projectId: plan.projectId,
    composeProject: plan.composeProjectName,
    controlPlaneGenerationDigest: plan.generationV2.controlPlane.controlPlaneGenerationDigest,
    controlPlaneMaterializationDigest: sha256Digest("control-plane-materialization"),
    proxyContainerId: "1".repeat(64),
    proxyImageId: sha256Digest("proxy-image-id"),
    sidecarContainerIds: [],
    networkIds: { agentInternal: "2".repeat(64), proxyEgress: "3".repeat(64) },
    securityContractHash: sha256Digest("security-contract"),
    proofSchemaVersion: 1 as const,
    admissionContractEpoch: generation.admissionContractEpoch,
    denyByDefaultBaseProofHash: sha256Digest("deny-by-default-base-proof"),
    selectedAt: "2026-08-08T11:59:00.000Z",
    runfreeVersion: plan.runfreeVersion,
  };
  const record = createAllocatedSessionContainerRecordV2({
    sessionId: "rf-20260808-a1b2c3",
    displayName: "template binding",
    command: "codex",
    launch,
    sourceIp: "172.99.0.20",
    materialization,
    effectiveControlPlane,
    hostPid: 123,
    createdAt: "2026-08-08T12:00:00.000Z",
  });
  const createPlan = createSessionContainerCreatePlan({
    expectedProject: { projectId: plan.projectId, composeProject: plan.composeProjectName },
    template: plan.sessionContainerTemplate,
    generationTarget: plan.generationV2,
    sessionAgentGeneration: generation,
    sessionAgentMaterialization: materialization,
    effectiveControlPlane,
    launch,
    imageDeclarationProof: createSessionImageDeclarationProof({
      image: {
        architecture: "amd64",
        id: record.selectedAgentImageId,
        labels: {},
        os: "linux",
        volumes: [],
      },
      selectedAgentImageId: record.selectedAgentImageId,
      mounts: plan.sessionContainerTemplate.mounts,
      environment: plan.sessionContainerTemplate.environment,
    }),
    record,
    runfreeVersion: plan.runfreeVersion,
  });

  expect(plan.sessionContainerTemplate).toBe(storedTemplate);
  expect(createPlan.environment).toBe(storedTemplate.environment);
  expect(JSON.stringify(createPlan.environment)).not.toContain("SEARCHADS.drifted");
  // A fresh plan against the tampered generation fails closed on the payload
  // digest before any template is built.
  expect(() => createRuntimePlan(context, { dockerSubnets: [], persistNetwork: false }))
    .toThrow("agent/agent.env is corrupt");
});

test("schema-v2 planning isolates control-plane and session-template changes", () => {
  // Raw secrets in session environments are structurally gone post-cutover:
  // the template env comes from the immutable effective generation, which
  // carries placeholders/handles only (host-env secret non-serialization is
  // proven by the first test in this file). The load-bearing remaining
  // property is isolation: a session-template input change rolls only the
  // session-agent generation, and a control-plane input change rolls only the
  // control-plane generation.
  const projectRoot = path.join(tmp, "project");
  const runtimeRoot = path.join(tmp, "runtime");
  const project = projectInfo(projectRoot);
  fs.mkdirSync(path.join(projectRoot, "node_modules"), { recursive: true });
  fs.writeFileSync(path.join(projectRoot, "package.json"), '{"name":"p","version":"1.0.0"}\n');
  fs.writeFileSync(path.join(projectRoot, "package-lock.json"), '{"lockfileVersion":3}\n');
  writeRuntimeCompose(runtimeRoot);
  const baseNetwork = {
    agentIp: "172.99.0.11",
    callbackSidecarIp: "172.99.0.12",
    proxyEgressGateway: "172.99.1.1",
    proxyEgressIp: "172.99.1.10",
    proxyEgressSubnet: "172.99.1.0/24",
    proxyIp: "172.99.0.10",
    subnet: "172.99.0.0/24",
  };
  const plan = (overrides: Record<string, unknown> = {}) => createRuntimePlan({
    projectRoot,
    project,
    runtimeRoot,
    env: {},
    network: baseNetwork,
    ...overrides,
  } as RuntimeContext, { dockerSubnets: [], persistNetwork: false });

  const baseline = plan();
  expect(baseline.dependencyOverlays.overlays.length).toBeGreaterThan(0);

  // Session-template input change: a context-supplied overlay set without the
  // scanned overlay alters the session projection only.
  const sessionChange = plan({
    dependencyOverlayPlan: { ...baseline.dependencyOverlays, overlays: [] },
  });
  expect(sessionChange.generationV2.controlPlane).toEqual(baseline.generationV2.controlPlane);
  expect(sessionChange.generationV2.sessionAgent.sessionAgentGenerationDigest)
    .not.toBe(baseline.generationV2.sessionAgent.sessionAgentGenerationDigest);

  // Control-plane input change: the egress gateway alters the control-plane
  // projection only.
  const controlChange = plan({ network: { ...baseNetwork, proxyEgressGateway: "172.99.1.2" } });
  expect(controlChange.generationV2.controlPlane.controlPlaneGenerationDigest)
    .not.toBe(baseline.generationV2.controlPlane.controlPlaneGenerationDigest);
  expect(controlChange.generationV2.sessionAgent).toEqual(baseline.generationV2.sessionAgent);
});
