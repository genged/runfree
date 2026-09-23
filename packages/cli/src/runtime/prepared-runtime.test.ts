import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, expect, test } from "vitest";

import { defaultConfig, projectControlPaths, type ProjectInfo } from "../config.ts";
import { approveNetworkCandidate, approveRuntimeIsolationControl } from "../control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../control/candidates.ts";
import { publishEffectivePolicyGeneration } from "../control/effective.ts";
import { proxyRuntimeImageTag } from "../agent-image.ts";
import { projectHash } from "../project-identity.ts";
import {
  bindSessionAgentImageV2,
  CONTROL_PLANE_PROOF_SCHEMA_VERSION,
  createControlPlaneMaterializationManifestV2,
  createSessionAgentDesiredSelectionV2,
  createSessionAgentMaterializationManifestV2,
  publishControlPlaneMaterializationV2,
  publishSessionAgentMaterializationV2,
  selectDesiredSessionAgentV2,
  selectEffectiveControlPlaneV2,
} from "./component-state-v2.ts";
import { sha256Digest } from "./component-state.ts";
import { withActiveRuntime } from "./images.ts";
import { mcpOAuthCallbackPort } from "./mcp.ts";
import { createRuntimePlan } from "./plan.ts";
import {
  consumePreparedRuntime,
  mintPreparedRuntime,
  StalePreparedRuntimeError,
  type PreparedRuntime,
} from "./prepared-runtime.ts";
import { createRuntimeSecurityContract } from "./security-contract.ts";
import {
  createSessionTemplateArtifactV1,
  serializeSessionTemplateArtifactV1,
  sessionTemplateArtifactSha256,
} from "./session-template-artifact.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

let temporaryRoot: string;

beforeEach(() => {
  temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-prepared-runtime-"));
});

afterEach(() => fs.rmSync(temporaryRoot, { recursive: true, force: true }));


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
  const stateDir = path.join(temporaryRoot, "state");
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

function fixture() {
  const projectRoot = path.join(temporaryRoot, "project");
  const runtimeRoot = path.join(temporaryRoot, "runtime");
  fs.mkdirSync(path.join(runtimeRoot, "agent"), { recursive: true });
  fs.mkdirSync(projectRoot, { recursive: true });
  fs.copyFileSync(
    path.resolve("packages/agent-runtime/agent/compose.yaml"),
    path.join(runtimeRoot, "agent", "compose.yaml"),
  );
  const runtimePlan = createRuntimePlan({
    projectRoot,
    project: projectInfo(projectRoot),
    runtimeRoot,
    env: {},
  } as RuntimeContext, { dockerSubnets: [], persistNetwork: false });
  const proxyImageId = sha256Digest("prepared-proxy-image-id");
  const agentImageId = sha256Digest("prepared-agent-image-id");
  const controlManifest = createControlPlaneMaterializationManifestV2({
    projectId: runtimePlan.projectId,
    composeProject: runtimePlan.composeProjectName,
    generation: runtimePlan.generationV2.controlPlane,
    proxyImageRef: proxyRuntimeImageTag(runtimePlan.generationV2.controlPlane.proxyImageInputDigest),
    proxyImageId,
    renderedControlPlaneSha256: runtimePlan.generationV2.controlPlane.controlPlaneTopologyDigest,
  
    sessionAdmissionSource: "files",
  });
  const activePlan = withActiveRuntime(runtimePlan, {
    activeRuntimeRoot: runtimeRoot,
    composeFile: path.join(runtimeRoot, "agent", "compose.yaml"),
    composeDirectory: path.join(runtimeRoot, "agent"),
    runtimeDigest: runtimePlan.runtimeDigest,
    materialized: true,
    agentImage: "runfree/agent-runtime:prepared",
    proxyImage: controlManifest.proxyImageRef,
    state: "desired",
    controlPlaneMaterializationDigest: controlManifest.controlPlaneMaterializationDigest,
  });
  const templateArtifact = serializeSessionTemplateArtifactV1(createSessionTemplateArtifactV1(activePlan));
  const sessionManifest = createSessionAgentMaterializationManifestV2({
    projectId: activePlan.projectId,
    composeProject: activePlan.composeProjectName,
    generation: bindSessionAgentImageV2(activePlan.generationV2.sessionAgent, agentImageId),
    selectedAgentImageRef: activePlan.activeRuntime.agentImage,
    selectedAgentImageId: agentImageId,
    selectedAgentImageKind: "embedded",
    sessionTemplateArtifactSha256: sessionTemplateArtifactSha256(templateArtifact),
  });
  publishControlPlaneMaterializationV2(activePlan.paths.stateDir, controlManifest);
  publishSessionAgentMaterializationV2(activePlan.paths.stateDir, sessionManifest, templateArtifact);
  selectDesiredSessionAgentV2(activePlan.paths.stateDir, createSessionAgentDesiredSelectionV2(sessionManifest));
  const contractHash = createRuntimeSecurityContract(activePlan).contractHash;
  if (!contractHash) throw new Error("prepared-runtime fixture requires a security contract hash");
  const proxyId = "a".repeat(64);
  selectEffectiveControlPlaneV2(activePlan.paths.stateDir, {
    schemaVersion: 2,
    projectId: activePlan.projectId,
    composeProject: activePlan.composeProjectName,
    controlPlaneGenerationDigest: controlManifest.generation.controlPlaneGenerationDigest,
    controlPlaneMaterializationDigest: controlManifest.controlPlaneMaterializationDigest,
    proxyContainerId: proxyId,
    proxyImageId,
    sidecarContainerIds: [],
    networkIds: {
      agentInternal: "c".repeat(64),
      proxyEgress: "d".repeat(64),
    },
    securityContractHash: contractHash,
    proofSchemaVersion: CONTROL_PLANE_PROOF_SCHEMA_VERSION,
    admissionContractEpoch: controlManifest.generation.admissionContractEpoch,
    denyByDefaultBaseProofHash: sha256Digest("prepared-deny-proof"),
    selectedAt: "2026-08-27T00:00:00.000Z",
    runfreeVersion: "0.4.0",
  });
  const proof = {
    components: { ...activePlan.generationV2.controlPlane },
    contractHash,
    mcpOAuthCallbackPort: mcpOAuthCallbackPort(projectRoot),
    mcpOAuthCallbackTopologyVersion: 2 as const,
    projectId: projectHash(projectRoot),
    proofVersion: 4 as const,
    proxyId,
  };
  let liveProxyId = proxyId;
  let markerOverride: string | undefined;
  const marker = () => markerOverride
    ?? JSON.stringify({ ...proof, proxyId: liveProxyId, validatedAt: "2026-08-27T00:00:00.000Z" });
  const io = {
    capture(command: string, args: string[]) {
      if (command !== "docker") return { status: 0, stdout: "", stderr: "" };
      if (args[0] === "ps" && args.some((arg) => arg.includes("com.docker.compose.service=agent"))) {
        return { status: 0, stdout: "", stderr: "" };
      }
      if (args[0] === "ps" && args.some((arg) => arg.includes("com.docker.compose.service=proxy"))) {
        return { status: 0, stdout: `${liveProxyId}\n`, stderr: "" };
      }
      if (args[0] === "ps" && args.some((arg) => arg.includes("com.docker.compose.service=mcp_callback"))) {
        return { status: 0, stdout: "", stderr: "" };
      }
      if (args[0] === "exec" && args.includes("cat")) {
        return { status: 0, stdout: marker(), stderr: "" };
      }
      return { status: 1, stdout: "", stderr: "unexpected Docker call" };
    },
  } as RuntimeIO;
  const lifecycleLock: ProjectLifecycleLock = {
    ownerToken: "f".repeat(64),
    assertHeld: () => undefined,
    release: () => undefined,
  };
  return {
    activePlan,
    io,
    lifecycleLock,
    proof,
    sessionManifest,
    templateArtifact,
    replaceProxy: () => { liveProxyId = "9".repeat(64); },
    corruptMarker: () => { markerOverride = "{malformed"; },
    selectReplacementSession: () => {
      const replacementImageId = sha256Digest("replacement-prepared-agent-image-id");
      const replacement = createSessionAgentMaterializationManifestV2({
        projectId: activePlan.projectId,
        composeProject: activePlan.composeProjectName,
        generation: bindSessionAgentImageV2(activePlan.generationV2.sessionAgent, replacementImageId),
        selectedAgentImageRef: activePlan.activeRuntime.agentImage,
        selectedAgentImageId: replacementImageId,
        selectedAgentImageKind: "embedded",
        sessionTemplateArtifactSha256: sessionTemplateArtifactSha256(templateArtifact),
      });
      publishSessionAgentMaterializationV2(activePlan.paths.stateDir, replacement, templateArtifact);
      selectDesiredSessionAgentV2(activePlan.paths.stateDir, createSessionAgentDesiredSelectionV2(replacement));
    },
  };
}

test("rejects forged, copied, and reused prepared authority before launch effects", () => {
  const prepared = fixture();
  const authority = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });

  expect(() => consumePreparedRuntime({
    preparedRuntime: { version: 1 } as PreparedRuntime,
    lifecycleLock: prepared.lifecycleLock,
    io: prepared.io,
  })).toThrow("was not minted");
  expect(() => consumePreparedRuntime({
    preparedRuntime: { ...authority } as PreparedRuntime,
    lifecycleLock: prepared.lifecycleLock,
    io: prepared.io,
  })).toThrow("was not minted");
  expect(consumePreparedRuntime({
    preparedRuntime: authority,
    lifecycleLock: prepared.lifecycleLock,
    io: prepared.io,
  }).plan).toBe(prepared.activePlan);
  expect(() => consumePreparedRuntime({
    preparedRuntime: authority,
    lifecycleLock: prepared.lifecycleLock,
    io: prepared.io,
  })).toThrow("already consumed");
});

test("classifies a replaced live proxy as stale preparation", () => {
  const prepared = fixture();
  const authority = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });
  prepared.replaceProxy();

  expect(() => consumePreparedRuntime({
    preparedRuntime: authority,
    lifecycleLock: prepared.lifecycleLock,
    io: prepared.io,
  })).toThrow(StalePreparedRuntimeError);
});

test("classifies a valid durable desired-selection change as stale preparation", () => {
  const prepared = fixture();
  const authority = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });
  prepared.selectReplacementSession();

  expect(() => consumePreparedRuntime({
    preparedRuntime: authority,
    lifecycleLock: prepared.lifecycleLock,
    io: prepared.io,
  })).toThrow(StalePreparedRuntimeError);
});

test("does not classify malformed validation authority as retryable drift", () => {
  const prepared = fixture();
  const authority = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });
  prepared.corruptMarker();

  expect(() => consumePreparedRuntime({
    preparedRuntime: authority,
    lifecycleLock: prepared.lifecycleLock,
    io: prepared.io,
  })).toThrow("validation proof is contradictory");
});

test("rejects post-mint durable template corruption without consuming authority", () => {
  const prepared = fixture();
  const authority = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });
  const artifactPath = path.join(
    prepared.activePlan.paths.stateDir,
    "runtime",
    "v2",
    "session-agent",
    "materializations",
    prepared.sessionManifest.sessionAgentMaterializationDigest.replace("sha256:", "sha256-"),
    "session-template.json",
  );
  fs.writeFileSync(artifactPath, `${prepared.templateArtifact} `);

  expect(() => consumePreparedRuntime({
    preparedRuntime: authority,
    lifecycleLock: prepared.lifecycleLock,
    io: prepared.io,
  })).toThrow("artifact hash does not match");
});
