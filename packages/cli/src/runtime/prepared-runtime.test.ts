import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterAll, beforeAll, beforeEach, expect, test } from "vitest";

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
  attachLaunchHandoff,
  consumePreparedRuntime,
  disposeLaunchHandoff,
  mintPreparedRuntime,
  preparedRuntimeProxyId,
  StalePreparedRuntimeError,
  takeLaunchHandoff,
  type LaunchHandoff,
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

// Every test works at the same path so the approved-controls state, built
// once per file, can be copied in instead of re-approved (the slowest step).
let base: string;
let temporaryRoot: string;
let controlsSnapshot: string | undefined;

beforeAll(() => {
  base = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-prepared-runtime-"));
  temporaryRoot = path.join(base, "work");
});

afterAll(() => fs.rmSync(base, { recursive: true, force: true }));

beforeEach(() => {
  fs.rmSync(temporaryRoot, { recursive: true, force: true });
  fs.mkdirSync(temporaryRoot);
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
  if (controlsSnapshot) {
    fs.cpSync(controlsSnapshot, temporaryRoot, { recursive: true });
  } else {
    ensureSelectedControls(projectRoot, project);
    controlsSnapshot = path.join(base, "controls");
    fs.cpSync(temporaryRoot, controlsSnapshot, { recursive: true });
  }
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

test("preparedRuntimeProxyId reads the minted selection and survives consumption", () => {
  const prepared = fixture();
  const authority = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });

  expect(preparedRuntimeProxyId(authority)).toBe(prepared.proof.proxyId);

  consumePreparedRuntime({
    preparedRuntime: authority,
    lifecycleLock: prepared.lifecycleLock,
    io: prepared.io,
  });

  expect(preparedRuntimeProxyId(authority)).toBe(prepared.proof.proxyId);
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

test("a plan that differs from a durable selection is refused naming that generation family", () => {
  const prepared = fixture();
  const { generationV2 } = prepared.activePlan;
  const otherAgent = sha256Digest("other-session-agent-generation");
  expect(() => mintPreparedRuntime({
    plan: { ...prepared.activePlan, generationV2: { ...generationV2,
      sessionAgent: { ...generationV2.sessionAgent, sessionAgentGenerationDigest: otherAgent } } },
    validationProof: prepared.proof,
  })).toThrow(`prepared runtime plan does not match its durable desired session-agent selection (selected session agent generation ${generationV2.sessionAgent.sessionAgentGenerationDigest}, planned ${otherAgent})`);
  const otherControlPlane = sha256Digest("other-control-plane-generation");
  expect(() => mintPreparedRuntime({
    plan: { ...prepared.activePlan, generationV2: { ...generationV2,
      controlPlane: { ...generationV2.controlPlane, controlPlaneGenerationDigest: otherControlPlane } } },
    validationProof: prepared.proof,
  })).toThrow(`prepared runtime plan does not match its durable effective control-plane selection (selected control plane generation ${generationV2.controlPlane.controlPlaneGenerationDigest}, planned ${otherControlPlane})`);
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

  // The refusal consumed nothing: once the artifact is intact again, the same
  // authority is still admissible.
  fs.writeFileSync(artifactPath, prepared.templateArtifact);
  expect(consumePreparedRuntime({
    preparedRuntime: authority,
    lifecycleLock: prepared.lifecycleLock,
    io: prepared.io,
  }).plan).toBe(prepared.activePlan);
});

function handoffFor(prepared: ReturnType<typeof fixture>, lock: ProjectLifecycleLock): LaunchHandoff {
  return {
    lifecycleLock: lock,
    lockOwnerToken: lock.ownerToken,
    lockAcquiredAtMonotonicMs: performance.now(),
    proxy: { id: prepared.proof.proxyId, startedAt: "2026-06-13T00:00:00.000Z" },
    registryDigest: `sha256:${"0".repeat(64)}`,
    sessionState: { kind: "reconciled", inventoryClean: true, reservedSourceIps: [] },
  };
}

function countingLock(): ProjectLifecycleLock & { releases: number } {
  const lock = {
    ownerToken: "e".repeat(64),
    releases: 0,
    assertHeld: () => undefined,
    release: () => { lock.releases += 1; },
  };
  return lock;
}

test("a launch handoff is taken exactly once and a disposed untaken handoff releases its lock", () => {
  const prepared = fixture();
  const taken = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });
  const lock = countingLock();
  const handoff = handoffFor(prepared, lock);
  attachLaunchHandoff(taken, handoff);
  expect(() => attachLaunchHandoff(taken, handoff)).toThrow("already carries a launch handoff");
  expect(takeLaunchHandoff(taken)?.lockOwnerToken).toBe(lock.ownerToken);
  expect(takeLaunchHandoff(taken)).toBeUndefined();
  // Disposal after a take is a no-op: the taker owns the lock.
  disposeLaunchHandoff(taken);
  expect(lock.releases).toBe(0);

  const untaken = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });
  const other = countingLock();
  attachLaunchHandoff(untaken, handoffFor(prepared, other));
  disposeLaunchHandoff(untaken);
  disposeLaunchHandoff(untaken);
  expect(other.releases).toBe(1);
  expect(takeLaunchHandoff(untaken)).toBeUndefined();
});

test("a handoff's session state survives attach by reference", () => {
  // Attach copies the handoff, so a seal on the session state lives on the
  // nested object, which must reach the taker as the very same object.
  const prepared = fixture();
  const runtime = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });
  const handoff = handoffFor(prepared, countingLock());
  attachLaunchHandoff(runtime, handoff);
  expect(takeLaunchHandoff(runtime)?.sessionState).toBe(handoff.sessionState);
});

test("disposing a handoff whose release fails does not throw over the caller's own error", () => {
  const prepared = fixture();
  const runtime = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });
  const failing = { ...countingLock(), release: () => { throw new Error("lock directory vanished"); } };
  attachLaunchHandoff(runtime, handoffFor(prepared, failing));
  expect(() => disposeLaunchHandoff(runtime)).not.toThrow();
  expect(takeLaunchHandoff(runtime)).toBeUndefined();
});

test("a handoff whose lock owner changed is refused at attach", () => {
  const prepared = fixture();
  const authority = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });
  const lock = countingLock();
  expect(() => attachLaunchHandoff(authority, { ...handoffFor(prepared, lock), lockOwnerToken: "d".repeat(64) }))
    .toThrow("lock owner changed");
});

test("consumption under the handed-off lock skips the in-proxy marker re-read but still checks the durable snapshot", () => {
  const prepared = fixture();
  const authority = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });
  const lock = countingLock();
  const handoff = handoffFor(prepared, lock);
  let dockerCalls = 0;
  const countingIo = { capture: (...args: Parameters<RuntimeIO["capture"]>) => { dockerCalls += 1; return prepared.io.capture(...args); } } as RuntimeIO;
  // A marker the proxy could no longer serve would refuse today's consume;
  // under the continuously held lock it is not re-read at all.
  prepared.corruptMarker();

  const consumed = consumePreparedRuntime({ preparedRuntime: authority, lifecycleLock: lock, io: countingIo, handoff });

  expect(consumed.plan).toBe(prepared.activePlan);
  expect(dockerCalls).toBe(0);
});

test("consumption refuses a handoff under a different lock, and a durable selection change stays stale", () => {
  const prepared = fixture();
  const authority = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });
  const handoff = handoffFor(prepared, countingLock());
  expect(() => consumePreparedRuntime({
    preparedRuntime: authority,
    lifecycleLock: prepared.lifecycleLock,
    io: prepared.io,
    handoff,
  })).toThrow("does not hold the lock");

  const drifted = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });
  const lock = countingLock();
  prepared.selectReplacementSession();
  expect(() => consumePreparedRuntime({
    preparedRuntime: drifted,
    lifecycleLock: lock,
    io: prepared.io,
    handoff: handoffFor(prepared, lock),
  })).toThrow(StalePreparedRuntimeError);
});

test("consumption under a handoff refuses one that proved another proxy than the durable selection", () => {
  const prepared = fixture();
  const authority = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });
  const lock = countingLock();
  expect(() => consumePreparedRuntime({
    preparedRuntime: authority,
    lifecycleLock: lock,
    io: prepared.io,
    handoff: { ...handoffFor(prepared, lock), proxy: { id: "9".repeat(64), startedAt: "2026-06-13T00:00:00.000Z" } },
  })).toThrow(StalePreparedRuntimeError);
});

/** A lock that stops proving itself once released, as the lifecycle lock does. */
function releasableLock(ownerToken: string): ProjectLifecycleLock & { released: boolean } {
  const lock = {
    ownerToken,
    released: false,
    assertHeld: () => {
      if (lock.released) throw new Error("project lifecycle lock is no longer held");
    },
    release: () => { lock.released = true; },
  };
  return lock;
}

test("one-shot handoff cannot replay", () => {
  const prepared = fixture();
  const authority = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });
  const lock = releasableLock("a".repeat(64));
  attachLaunchHandoff(authority, handoffFor(prepared, lock));
  const taken = takeLaunchHandoff(authority);
  if (!taken) throw new Error("the handoff was not attached");
  // Neither the slot nor a second consumption hands the proof out again.
  expect(takeLaunchHandoff(authority)).toBeUndefined();
  expect(consumePreparedRuntime({ preparedRuntime: authority, lifecycleLock: lock, io: prepared.io, handoff: taken }).plan)
    .toBe(prepared.activePlan);
  expect(() => consumePreparedRuntime({ preparedRuntime: authority, lifecycleLock: lock, io: prepared.io, handoff: taken }))
    .toThrow("already consumed");
  // A taken handoff cannot be attached to the same authority a second time.
  expect(() => attachLaunchHandoff(authority, taken)).toThrow("already carries a launch handoff");
});

test("release/reacquire cannot reuse proof", () => {
  const prepared = fixture();
  // A lock released before the handoff is attached carries nothing.
  const released = releasableLock("b".repeat(64));
  const handoff = handoffFor(prepared, released);
  released.release();
  const unattached = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });
  expect(() => attachLaunchHandoff(unattached, handoff)).toThrow("no longer held");
  expect(takeLaunchHandoff(unattached)).toBeUndefined();

  // The proof startup took under one acquisition does not carry to the next:
  // a reacquired lock has a new owner, and admission under it refuses.
  const first = releasableLock("c".repeat(64));
  const authority = mintPreparedRuntime({ plan: prepared.activePlan, validationProof: prepared.proof });
  attachLaunchHandoff(authority, handoffFor(prepared, first));
  const taken = takeLaunchHandoff(authority);
  if (!taken) throw new Error("the handoff was not attached");
  first.release();
  const reacquired = releasableLock("d".repeat(64));
  expect(() => consumePreparedRuntime({ preparedRuntime: authority, lifecycleLock: reacquired, io: prepared.io, handoff: taken }))
    .toThrow("does not hold the lock");
  // The refusal consumed nothing: the full path under the new lock re-proves.
  expect(consumePreparedRuntime({ preparedRuntime: authority, lifecycleLock: prepared.lifecycleLock, io: prepared.io }).plan)
    .toBe(prepared.activePlan);
});
