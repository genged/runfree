import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, expect, test } from "vitest";

import { defaultConfig, projectControlPaths, type ProjectInfo } from "../config.ts";
import { approveNetworkCandidate, approveRuntimeIsolationControl } from "../control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../control/candidates.ts";
import { publishEffectivePolicyGeneration } from "../control/effective.ts";
import { createRuntimePlan } from "./plan.ts";
import {
  createSessionTemplateArtifactV1,
  parseSessionTemplateArtifactV1,
  serializeSessionTemplateArtifactV1,
  sessionTemplateArtifactSha256,
  type SessionTemplateArtifactV1,
} from "./session-template-artifact.ts";
import { sessionContainerTemplateInit } from "./session-container-template.ts";
import {
  runtimeTopologyProjectionArtifactDigestV2,
  type RuntimeTopologyProjectionArtifactV2,
} from "./topology-digest-v2.ts";
import type { RuntimeContext } from "./types.ts";

let temporaryRoot: string;

beforeEach(() => {
  temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-session-template-artifact-"));
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
  const plan = createRuntimePlan({
    projectRoot,
    project: projectInfo(projectRoot),
    runtimeRoot,
    env: {},
  } as RuntimeContext, { dockerSubnets: [], persistNetwork: false });
  const artifact = createSessionTemplateArtifactV1(plan);
  const source = serializeSessionTemplateArtifactV1(artifact);
  return {
    artifact,
    plan,
    source,
    expected: {
      projectId: plan.projectId,
      composeProject: plan.composeProjectName,
      sessionTemplateDigest: plan.generationV2.sessionAgent.sessionTemplateDigest,
      artifactSha256: sessionTemplateArtifactSha256(source),
    },
  };
}

test("round-trips one canonical artifact without reading mutable project input", () => {
  const { artifact, expected, source } = fixture();

  const parsed = parseSessionTemplateArtifactV1(source, expected);

  expect(serializeSessionTemplateArtifactV1(parsed)).toBe(source);
  expect(parsed.template).toEqual(artifact.template);
});

test("rejects unknown fields, truncation, hash drift, and topology drift", () => {
  const { expected, source } = fixture();
  const decoded = JSON.parse(source) as Record<string, unknown>;
  const unknownSource = `${JSON.stringify({ ...decoded, unknown: true })}\n`;
  expect(() => parseSessionTemplateArtifactV1(unknownSource, {
    ...expected,
    artifactSha256: sessionTemplateArtifactSha256(unknownSource),
  })).toThrow("invalid contract");
  expect(() => parseSessionTemplateArtifactV1(source.slice(0, -2), expected)).toThrow("hash does not match");
  expect(() => parseSessionTemplateArtifactV1(source, {
    ...expected,
    artifactSha256: sessionTemplateArtifactSha256("other"),
  })).toThrow("hash does not match");
  expect(() => parseSessionTemplateArtifactV1(source, {
    ...expected,
    sessionTemplateDigest: `sha256:${"f".repeat(64)}`,
  })).toThrow("topology digest does not match");
});

test("rejects template bytes that contradict their persisted topology projection", () => {
  const { expected, source } = fixture();
  const decoded = JSON.parse(source) as {
    template: { environment: Record<string, string> };
  };
  decoded.template.environment.RUNFREE_TAMPERED = "1";
  const changed = `${JSON.stringify(decoded)}\n`;

  expect(() => parseSessionTemplateArtifactV1(changed, {
    ...expected,
    artifactSha256: sessionTemplateArtifactSha256(changed),
  })).toThrow("topology does not describe its template");
});

/**
 * The bytes a runfree release before 2026-09-30 persisted for the same plan:
 * a version 1 template without an `init` key, and a stored projection whose
 * create contract says `init: false`. Built from today's artifact so the
 * rest of the contract stays exact; the digest is recomputed over the old
 * projection, as the old release computed it.
 */
function legacyArtifact(source: string, projectionInit = false) {
  const decoded = JSON.parse(source) as {
    template: Record<string, unknown>;
    topologyProjection: RuntimeTopologyProjectionArtifactV2 & {
      structure: { createContract: Record<string, unknown> };
    };
  };
  const { init: _init, ...template } = decoded.template;
  decoded.template = { ...template, version: 1 };
  decoded.topologyProjection.structure.createContract.init = projectionInit;
  const legacySource = serializeSessionTemplateArtifactV1(decoded as unknown as SessionTemplateArtifactV1);
  return {
    source: legacySource,
    sessionTemplateDigest: runtimeTopologyProjectionArtifactDigestV2(decoded.topologyProjection),
  };
}

test("a fresh artifact stores a version 2 template that runs under init", () => {
  const { artifact } = fixture();
  expect(artifact.template.version).toBe(2);
  expect(sessionContainerTemplateInit(artifact.template)).toBe(true);
  expect(artifact.topologyProjection.structure).toMatchObject({ createContract: { init: true } });
});

test("a pre-upgrade artifact (version 1, init false) still parses, stays canonical, and keeps init false", () => {
  const { expected, source } = fixture();
  const legacy = legacyArtifact(source);

  const parsed = parseSessionTemplateArtifactV1(legacy.source, {
    ...expected,
    sessionTemplateDigest: legacy.sessionTemplateDigest,
    artifactSha256: sessionTemplateArtifactSha256(legacy.source),
  });

  expect(serializeSessionTemplateArtifactV1(parsed)).toBe(legacy.source);
  expect(parsed.template.version).toBe(1);
  expect(sessionContainerTemplateInit(parsed.template)).toBe(false);
  // The two are different session templates, never one digest.
  expect(legacy.sessionTemplateDigest).not.toBe(expected.sessionTemplateDigest);
});

test("refuses a version 1 artifact whose stored projection claims an init wrapper", () => {
  const { expected, source } = fixture();
  const forged = legacyArtifact(source, true);
  expect(() => parseSessionTemplateArtifactV1(forged.source, {
    ...expected,
    sessionTemplateDigest: forged.sessionTemplateDigest,
    artifactSha256: sessionTemplateArtifactSha256(forged.source),
  })).toThrow("topology does not describe its template");
});

test("refuses a version 2 artifact whose stored projection denies its init wrapper", () => {
  const { expected, source } = fixture();
  const decoded = JSON.parse(source) as {
    topologyProjection: RuntimeTopologyProjectionArtifactV2 & {
      structure: { createContract: Record<string, unknown> };
    };
  };
  decoded.topologyProjection.structure.createContract.init = false;
  const changed = serializeSessionTemplateArtifactV1(decoded as unknown as SessionTemplateArtifactV1);
  expect(() => parseSessionTemplateArtifactV1(changed, {
    ...expected,
    sessionTemplateDigest: runtimeTopologyProjectionArtifactDigestV2(decoded.topologyProjection),
    artifactSha256: sessionTemplateArtifactSha256(changed),
  })).toThrow("topology does not describe its template");
});
