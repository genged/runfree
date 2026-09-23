import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, test, vi } from "vitest";

import {
  createRuntimeComponentState,
  runtimeGenerationManifestPath,
  runtimeMaterializationRoot,
  selectEffectiveRuntimeGeneration,
  serializeRuntimeGenerationManifest,
  sha256Digest,
  type RuntimeGenerationManifest,
} from "./component-state.ts";
import {
  bindSessionAgentImageV2,
  clearEffectiveControlPlaneV2,
  CONTROL_PLANE_PROOF_SCHEMA_VERSION,
  controlPlaneEffectiveSelectionPathV2,
  controlPlaneGenerationDigestV2,
  controlPlaneMaterializationManifestPathV2,
  createControlPlaneGenerationV2,
  createControlPlaneMaterializationManifestV2,
  createRuntimeTopologyGenerationV2,
  createSessionAgentDesiredSelectionV2,
  createSessionAgentGenerationInputsV2,
  createSessionAgentMaterializationManifestV2,
  parseControlPlaneGenerationV2,
  parseControlPlaneMaterializationManifestV2,
  parseEffectiveControlPlaneSelectionV2,
  parseRuntimeGenerationTargetV2,
  parseRuntimeTopologyGenerationV2,
  parseLegacySessionAgentMaterializationManifestV2,
  parseSessionAgentDesiredSelectionV2,
  parseSessionAgentGenerationInputsV2,
  parseSessionAgentGenerationV2,
  parseSessionAgentMaterializationManifestV2,
  publishControlPlaneMaterializationV2,
  publishedSessionEligibilityPathV2,
  publishSessionAgentMaterializationV2,
  readControlPlaneMaterializationV2,
  readDesiredSessionAgentV2,
  readEffectiveControlPlaneV2,
  readPublishedSessionEligibilityV2,
  readRetainedDesiredSessionAgentV2,
  readSessionAgentMaterializationV2,
  readSessionAgentTemplateArtifactV2,
  recordPublishedSessionEligibilityV2,
  RUNTIME_ADMISSION_CONTRACT_EPOCH,
  selectEffectiveControlPlaneV2,
  selectDesiredSessionAgentV2,
  serializeControlPlaneMaterializationManifestV2,
  serializeSessionAgentDesiredSelectionV2,
  serializeSessionAgentMaterializationManifestV2,
  sessionAgentDesiredSelectionPathV2,
  sessionAgentGenerationDigestV2,
  sessionAgentMaterializationManifestPathV2,
  sessionAgentTemplateArtifactPathV2,
  type ControlPlaneEffectiveSelectionV2,
  type ControlPlaneMaterializationManifestV2,
  type RuntimeGenerationTargetV2,
  type SessionAgentDesiredSelectionV2,
  type SessionAgentMaterializationManifestV2,
} from "./component-state-v2.ts";

const roots: string[] = [];
const PROJECT_ID = "0123456789ab";
const COMPOSE_PROJECT = `runfree-${PROJECT_ID}`;
const SESSION_TEMPLATE_ARTIFACT = "{}\n";

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function temporaryState(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-component-v2-"));
  roots.push(root);
  return root;
}

function digest(label: string): string {
  return sha256Digest(label);
}

function stableJsonForTest(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJsonForTest).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableJsonForTest(entry)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function target(overrides: {
  proxy?: string;
  controlPlaneTopology?: string;
  sessionTemplate?: string;
  epoch?: number;
} = {}): RuntimeGenerationTargetV2 {
  const epoch = overrides.epoch ?? RUNTIME_ADMISSION_CONTRACT_EPOCH;
  const topology = createRuntimeTopologyGenerationV2({
    controlPlaneTopologyDigest: overrides.controlPlaneTopology ?? digest("control-plane-topology"),
    sessionTemplateDigest: overrides.sessionTemplate ?? digest("session-template"),
  });
  return {
    topology,
    controlPlane: createControlPlaneGenerationV2({
      projectId: PROJECT_ID,
      composeProject: COMPOSE_PROJECT,
      proxyImageInputDigest: overrides.proxy ?? digest("proxy"),
      controlPlaneTopologyDigest: topology.controlPlaneTopologyDigest,
      admissionContractEpoch: epoch,
    }),
    sessionAgent: createSessionAgentGenerationInputsV2({
      selectedAgentImageInputDigest: digest("agent"),
      sessionTemplateDigest: topology.sessionTemplateDigest,
      admissionContractEpoch: epoch,
    }),
  };
}

function materialization(desired = target()): ControlPlaneMaterializationManifestV2 {
  return createControlPlaneMaterializationManifestV2({
    projectId: PROJECT_ID,
    composeProject: COMPOSE_PROJECT,
    generation: desired.controlPlane,
    proxyImageRef: "runfree/proxy-runtime:sha256-proxy",
    proxyImageId: digest("proxy-image-id"),
    renderedControlPlaneSha256: desired.controlPlane.controlPlaneTopologyDigest,
  
    sessionAdmissionSource: "files",
  });
}

function selection(desired = target()): ControlPlaneEffectiveSelectionV2 {
  const manifest = materialization(desired);
  return {
    schemaVersion: 2,
    projectId: PROJECT_ID,
    composeProject: COMPOSE_PROJECT,
    controlPlaneGenerationDigest: desired.controlPlane.controlPlaneGenerationDigest,
    controlPlaneMaterializationDigest: manifest.controlPlaneMaterializationDigest,
    proxyContainerId: "a".repeat(64),
    proxyImageId: digest("proxy-image-id"),
    sidecarContainerIds: [],
    networkIds: {
      agentInternal: "b".repeat(64),
      proxyEgress: "c".repeat(64),
    },
    securityContractHash: digest("security-contract"),
    proofSchemaVersion: CONTROL_PLANE_PROOF_SCHEMA_VERSION,
    admissionContractEpoch: desired.controlPlane.admissionContractEpoch,
    denyByDefaultBaseProofHash: digest("deny-by-default"),
    selectedAt: "2026-08-05T00:00:00.000Z",
    runfreeVersion: "0.2.0",
  };
}

function sessionAgentMaterialization(overrides: {
  desired?: RuntimeGenerationTargetV2;
  selectedAgentImageId?: string;
  selectedAgentImageRef?: string;
  selectedAgentImageKind?: "embedded" | "project";
} = {}): SessionAgentMaterializationManifestV2 {
  const desired = overrides.desired ?? target();
  const kind = overrides.selectedAgentImageKind ?? "project";
  const selectedAgentImageId = overrides.selectedAgentImageId ?? digest("selected-agent-image-id");
  return createSessionAgentMaterializationManifestV2({
    projectId: PROJECT_ID,
    composeProject: COMPOSE_PROJECT,
    generation: bindSessionAgentImageV2(desired.sessionAgent, selectedAgentImageId),
    selectedAgentImageRef: overrides.selectedAgentImageRef
      ?? (kind === "embedded" ? "runfree/agent-runtime:mutable-ref" : "runfree/agent-project:mutable-ref"),
    selectedAgentImageId,
    selectedAgentImageKind: kind,
    sessionTemplateArtifactSha256: digest(SESSION_TEMPLATE_ARTIFACT),
  });
}

function publishV1(stateDir: string): RuntimeGenerationManifest {
  const components = createRuntimeComponentState({
    embeddedAgentImageInputDigest: digest("embedded-agent"),
    selectedAgentImageInputDigest: digest("agent"),
    selectedAgentImageKind: "embedded",
    proxyImageInputDigest: digest("proxy"),
    topologyDigest: digest("legacy-monolithic-topology"),
    hostHelperDigest: digest("helpers"),
  });
  const manifest: RuntimeGenerationManifest = {
    schemaVersion: 1,
    projectId: PROJECT_ID,
    composeProject: COMPOSE_PROJECT,
    components,
    images: {
      agent: "runfree/agent-runtime:sha256-agent",
      proxy: "runfree/proxy-runtime:sha256-proxy",
    },
    renderedComposeSha256: digest("legacy-compose"),
  };
  fs.mkdirSync(runtimeMaterializationRoot(stateDir, components.materializationDigest), { recursive: true });
  fs.writeFileSync(
    runtimeGenerationManifestPath(stateDir, components.materializationDigest),
    serializeRuntimeGenerationManifest(manifest),
    { mode: 0o600 },
  );
  selectEffectiveRuntimeGeneration(stateDir, components.materializationDigest);
  return manifest;
}

describe("runtime generation v2 digest contracts", () => {
  test("matches the specified control-plane and session-agent digest payloads", () => {
    // Keep the fixed wire vector independent of the current compatibility epoch.
    const desired = target({ epoch: 3 });
    // Golden contract values catch field removal, field renaming, schema drift,
    // and unstable serialization without copying the production hash routine.
    expect(desired.controlPlane.controlPlaneGenerationDigest)
      .toBe("sha256:245dfedabc26a5692aac50cb34350c3042c571a64f9265e33bc45110209edbe6");
    expect(desired.sessionAgent.sessionAgentGenerationDigest)
      .toBe("sha256:dc6a76fe75d49bdbdd40f3b498157a92d611e3d99cc41506d710c8524ba4f939");
    expect(desired.topology.topologyDigest)
      .toBe("sha256:4e26d865724cf5576ba50289b520deef78fa4a1881ff6bf49ee28275b73baa1e");
  });

  test("treats the selected immutable image ID as proof outside the session input digest", () => {
    const inputs = target().sessionAgent;
    const first = bindSessionAgentImageV2(inputs, digest("image-id-1"));
    const second = bindSessionAgentImageV2(inputs, digest("image-id-2"));

    expect(first.sessionAgentGenerationDigest).toBe(second.sessionAgentGenerationDigest);
    expect(first.selectedAgentImageId).not.toBe(second.selectedAgentImageId);
    expect(parseSessionAgentGenerationV2(first)).toEqual(first);
    expect(parseSessionAgentGenerationV2(second)).toEqual(second);
  });

  test("rejects unknown fields, wrong schemas, stale digests, and inconsistent target projections", () => {
    const desired = target();
    expect(parseControlPlaneGenerationV2({ ...desired.controlPlane, unknown: true })).toBeUndefined();
    expect(parseControlPlaneGenerationV2({ ...desired.controlPlane, schemaVersion: 1 })).toBeUndefined();
    expect(parseControlPlaneGenerationV2({
      ...desired.controlPlane,
      proxyImageInputDigest: digest("tampered-proxy"),
    })).toBeUndefined();
    expect(parseRuntimeTopologyGenerationV2({
      ...desired.topology,
      sessionTemplateDigest: digest("tampered-template"),
    })).toBeUndefined();
    expect(parseSessionAgentGenerationInputsV2({
      ...desired.sessionAgent,
      admissionContractEpoch: 0,
    })).toBeUndefined();
    expect(parseSessionAgentGenerationV2({
      ...bindSessionAgentImageV2(desired.sessionAgent, digest("image-id")),
      unexpected: true,
    })).toBeUndefined();
    expect(parseRuntimeGenerationTargetV2({
      ...desired,
      sessionAgent: createSessionAgentGenerationInputsV2({
        ...desired.sessionAgent,
        sessionTemplateDigest: digest("other-template"),
      }),
    })).toBeUndefined();
  });

  test("recomputes digests instead of accepting caller-provided identity", () => {
    const desired = target();
    expect(controlPlaneGenerationDigestV2({
      ...desired.controlPlane,
      controlPlaneTopologyDigest: digest("changed-control-plane"),
    })).not.toBe(desired.controlPlane.controlPlaneGenerationDigest);
    expect(sessionAgentGenerationDigestV2({
      ...desired.sessionAgent,
      selectedAgentImageInputDigest: digest("changed-agent"),
    })).not.toBe(desired.sessionAgent.sessionAgentGenerationDigest);
    expect(() => controlPlaneGenerationDigestV2({
      ...desired.controlPlane,
      schemaVersion: 1 as never,
    })).toThrow("requires schema version 2");
    expect(() => sessionAgentGenerationDigestV2({
      ...desired.sessionAgent,
      schemaVersion: 1 as never,
    })).toThrow("requires schema version 2");
  });

  test("owns every compatibility input in the narrow generation that consumes it", () => {
    const baseline = target();
    const changedProxy = target({ proxy: digest("proxy-2") });
    const changedControlTopology = target({ controlPlaneTopology: digest("control-topology-2") });
    const changedSessionTemplate = target({ sessionTemplate: digest("session-template-2") });
    const changedEpoch = target({ epoch: RUNTIME_ADMISSION_CONTRACT_EPOCH + 1 });

    expect(changedProxy.controlPlane.controlPlaneGenerationDigest)
      .not.toBe(baseline.controlPlane.controlPlaneGenerationDigest);
    expect(changedProxy.sessionAgent.sessionAgentGenerationDigest)
      .toBe(baseline.sessionAgent.sessionAgentGenerationDigest);
    expect(changedControlTopology.controlPlane.controlPlaneGenerationDigest)
      .not.toBe(baseline.controlPlane.controlPlaneGenerationDigest);
    expect(changedControlTopology.sessionAgent.sessionAgentGenerationDigest)
      .toBe(baseline.sessionAgent.sessionAgentGenerationDigest);
    expect(changedSessionTemplate.controlPlane.controlPlaneGenerationDigest)
      .toBe(baseline.controlPlane.controlPlaneGenerationDigest);
    expect(changedSessionTemplate.sessionAgent.sessionAgentGenerationDigest)
      .not.toBe(baseline.sessionAgent.sessionAgentGenerationDigest);
    expect(changedEpoch.controlPlane.controlPlaneGenerationDigest)
      .not.toBe(baseline.controlPlane.controlPlaneGenerationDigest);
    expect(changedEpoch.sessionAgent.sessionAgentGenerationDigest)
      .not.toBe(baseline.sessionAgent.sessionAgentGenerationDigest);
  });
});

describe("v2 control-plane materialization and selection", () => {
  test("publishes immutable state and selects exact validated Docker evidence", () => {
    const stateDir = temporaryState();
    const desired = target();
    const manifest = materialization(desired);
    publishControlPlaneMaterializationV2(stateDir, manifest);
    publishControlPlaneMaterializationV2(stateDir, manifest);
    selectEffectiveControlPlaneV2(stateDir, selection(desired));

    expect(readControlPlaneMaterializationV2(
      stateDir,
      manifest.controlPlaneMaterializationDigest,
    )).toEqual(manifest);
    expect(fs.readFileSync(controlPlaneMaterializationManifestPathV2(
      stateDir,
      manifest.controlPlaneMaterializationDigest,
    ), "utf8")).toBe(serializeControlPlaneMaterializationManifestV2(manifest));
    expect(readEffectiveControlPlaneV2(stateDir)).toEqual({ manifest, selection: selection(desired) });
    expect(fs.statSync(controlPlaneMaterializationManifestPathV2(
      stateDir,
      manifest.controlPlaneMaterializationDigest,
    )).mode & 0o777).toBe(0o600);
    expect(fs.statSync(controlPlaneEffectiveSelectionPathV2(stateDir)).mode & 0o777).toBe(0o600);
    expect(parseEffectiveControlPlaneSelectionV2(selection(desired))).toEqual(selection(desired));
  });

  test("re-fsyncs parents when an immutable materialization already exists", () => {
    const stateDir = temporaryState();
    const manifest = materialization();
    publishControlPlaneMaterializationV2(stateDir, manifest);

    const fsyncSpy = vi.spyOn(fs, "fsyncSync");
    try {
      publishControlPlaneMaterializationV2(stateDir, manifest);
      expect(fsyncSpy).toHaveBeenCalled();
    } finally {
      fsyncSpy.mockRestore();
    }
  });

  test("clears only the effective live-container selection", () => {
    const stateDir = temporaryState();
    const desired = target();
    const manifest = materialization(desired);
    publishControlPlaneMaterializationV2(stateDir, manifest);
    selectEffectiveControlPlaneV2(stateDir, selection(desired));

    clearEffectiveControlPlaneV2(stateDir);
    clearEffectiveControlPlaneV2(stateDir);

    expect(readEffectiveControlPlaneV2(stateDir)).toBeUndefined();
    expect(readControlPlaneMaterializationV2(stateDir, manifest.controlPlaneMaterializationDigest)).toEqual(manifest);
  });

  test("fsyncs the selection parent on retry after unlink succeeded", () => {
    const stateDir = temporaryState();
    const desired = target();
    publishControlPlaneMaterializationV2(stateDir, materialization(desired));
    selectEffectiveControlPlaneV2(stateDir, selection(desired));
    const selectionPath = controlPlaneEffectiveSelectionPathV2(stateDir);

    const originalFsync = fs.fsyncSync.bind(fs);
    const firstFsync = vi.spyOn(fs, "fsyncSync").mockImplementationOnce(() => {
      throw new Error("simulated selection directory fsync failure");
    });
    try {
      expect(() => clearEffectiveControlPlaneV2(stateDir)).toThrow("simulated selection directory fsync failure");
    } finally {
      firstFsync.mockRestore();
    }
    expect(fs.existsSync(selectionPath)).toBe(false);

    const retryFsync = vi.spyOn(fs, "fsyncSync").mockImplementation(originalFsync);
    try {
      clearEffectiveControlPlaneV2(stateDir);
      expect(retryFsync).toHaveBeenCalled();
    } finally {
      retryFsync.mockRestore();
    }
  });

  test("requires a full immutable proxy image ID in materialization and effective selection", () => {
    const stateDir = temporaryState();
    const manifest = materialization();
    const effective = selection();
    const { proxyImageId: _manifestImageId, ...manifestWithoutImageId } = manifest;
    const { proxyImageId: _selectionImageId, ...selectionWithoutImageId } = effective;

    expect(() => serializeControlPlaneMaterializationManifestV2(
      manifestWithoutImageId as ControlPlaneMaterializationManifestV2,
    )).toThrow("manifest is invalid");
    expect(() => publishControlPlaneMaterializationV2(stateDir, {
      ...manifest,
      proxyImageId: "sha256:short",
    })).toThrow("manifest is invalid");
    expect(parseEffectiveControlPlaneSelectionV2(selectionWithoutImageId)).toBeUndefined();
    expect(parseEffectiveControlPlaneSelectionV2({
      ...effective,
      proxyImageId: "sha256:short",
    })).toBeUndefined();
    expect(fs.existsSync(controlPlaneEffectiveSelectionPathV2(stateDir))).toBe(false);
  });

  test("rejects proxy ref retagging and reconciles stored image-ID mutations before activation", () => {
    const stateDir = temporaryState();
    const desired = target();
    const manifest = materialization(desired);
    const effective = selection(desired);
    const retaggedImageId = digest("retagged-proxy-image-id");
    publishControlPlaneMaterializationV2(stateDir, manifest);

    // The mutable ref still has the same spelling, but its newly inspected ID
    // differs from the immutable materialization proof.
    expect(() => selectEffectiveControlPlaneV2(stateDir, {
      ...effective,
      proxyImageId: retaggedImageId,
    })).toThrow("contradicts its materialization");
    expect(fs.existsSync(controlPlaneEffectiveSelectionPathV2(stateDir))).toBe(false);

    selectEffectiveControlPlaneV2(stateDir, effective);
    const selectionPath = controlPlaneEffectiveSelectionPathV2(stateDir);
    fs.writeFileSync(selectionPath, `${JSON.stringify({
      ...effective,
      proxyImageId: retaggedImageId,
    })}\n`);
    expect(() => readEffectiveControlPlaneV2(stateDir)).toThrow("contradicts its materialization");

    selectEffectiveControlPlaneV2(stateDir, effective);
    const manifestPath = controlPlaneMaterializationManifestPathV2(
      stateDir,
      manifest.controlPlaneMaterializationDigest,
    );
    fs.writeFileSync(manifestPath, `${JSON.stringify({
      ...manifest,
      proxyImageId: retaggedImageId,
    })}\n`);
    expect(() => readEffectiveControlPlaneV2(stateDir)).toThrow("manifest is invalid");
  });

  test("records the admission source as a required exact-value field", () => {
    const stateDir = temporaryState();
    const desired = target();
    const flagged = createControlPlaneMaterializationManifestV2({
      projectId: PROJECT_ID,
      composeProject: COMPOSE_PROJECT,
      generation: desired.controlPlane,
      proxyImageRef: "runfree/proxy-runtime:sha256-proxy",
      proxyImageId: digest("proxy-image-id"),
      renderedControlPlaneSha256: desired.controlPlane.controlPlaneTopologyDigest,
      sessionAdmissionSource: "files",
    });

    expect(flagged.sessionAdmissionSource).toBe("files");
    publishControlPlaneMaterializationV2(stateDir, flagged);
    expect(readControlPlaneMaterializationV2(stateDir, flagged.controlPlaneMaterializationDigest))
      .toEqual(flagged);
    // Only the one literal the host can mint parses; anything else — a
    // pre-cutover manifest with no key included — is refused rather than read
    // as "not files".
    for (const source of ["generations", undefined] as const) {
      expect(parseControlPlaneMaterializationManifestV2({
        ...flagged,
        sessionAdmissionSource: source,
      })).toBeUndefined();
    }
    const { sessionAdmissionSource: _absent, ...legacy } = flagged;
    expect(parseControlPlaneMaterializationManifestV2(legacy)).toBeUndefined();
  });

  test("records the last published session eligibility beside the effective selection", () => {
    const stateDir = temporaryState();
    const receipt = {
      schemaVersion: 2,
      projectId: PROJECT_ID,
      composeProject: COMPOSE_PROJECT,
      proxyContainerId: "a".repeat(64),
      proxyStartedAt: "2026-08-08T12:00:05.123456789Z",
      eligibilitySha256: digest("eligibility-bytes"),
    } as const;

    expect(readPublishedSessionEligibilityV2(stateDir)).toBeUndefined();
    recordPublishedSessionEligibilityV2(stateDir, receipt);
    expect(readPublishedSessionEligibilityV2(stateDir)).toEqual(receipt);
    expect(fs.statSync(publishedSessionEligibilityPathV2(stateDir)).mode & 0o777).toBe(0o600);
    expect(path.dirname(publishedSessionEligibilityPathV2(stateDir)))
      .toBe(path.dirname(controlPlaneEffectiveSelectionPathV2(stateDir)));

    fs.writeFileSync(publishedSessionEligibilityPathV2(stateDir), '{"schemaVersion":2}\n');
    expect(readPublishedSessionEligibilityV2(stateDir)).toBeUndefined();
    // A container that never started cannot have received a publication.
    expect(() => recordPublishedSessionEligibilityV2(stateDir, {
      ...receipt,
      proxyStartedAt: "0001-01-01T00:00:00Z",
    })).toThrow("published session eligibility record is invalid");
  });

  test("publishes distinct immutable materializations when one generation resolves to a new proxy image ID", () => {
    const stateDir = temporaryState();
    const manifest = materialization();
    const rebuilt = createControlPlaneMaterializationManifestV2({
      projectId: manifest.projectId,
      composeProject: manifest.composeProject,
      generation: manifest.generation,
      proxyImageRef: manifest.proxyImageRef,
      proxyImageId: digest("rebuilt-proxy-image-id"),
      renderedControlPlaneSha256: manifest.renderedControlPlaneSha256,
      sessionAdmissionSource: "files",
    });
    publishControlPlaneMaterializationV2(stateDir, manifest);
    publishControlPlaneMaterializationV2(stateDir, rebuilt);

    expect(rebuilt.generation.controlPlaneGenerationDigest)
      .toBe(manifest.generation.controlPlaneGenerationDigest);
    expect(rebuilt.controlPlaneMaterializationDigest)
      .not.toBe(manifest.controlPlaneMaterializationDigest);
    expect(readControlPlaneMaterializationV2(stateDir, manifest.controlPlaneMaterializationDigest)).toEqual(manifest);
    expect(readControlPlaneMaterializationV2(stateDir, rebuilt.controlPlaneMaterializationDigest)).toEqual(rebuilt);

    const rebuiltSelection = {
      ...selection(),
      controlPlaneMaterializationDigest: rebuilt.controlPlaneMaterializationDigest,
      proxyImageId: rebuilt.proxyImageId,
    };
    expect(() => selectEffectiveControlPlaneV2(stateDir, {
      ...rebuiltSelection,
      controlPlaneMaterializationDigest: manifest.controlPlaneMaterializationDigest,
    })).toThrow("contradicts its materialization");
    selectEffectiveControlPlaneV2(stateDir, rebuiltSelection);
    expect(readEffectiveControlPlaneV2(stateDir)).toEqual({
      manifest: rebuilt,
      selection: rebuiltSelection,
    });
    expect(readControlPlaneMaterializationV2(stateDir, manifest.controlPlaneMaterializationDigest)).toEqual(manifest);
  });

  test("does not overwrite contradictory bytes at an exact materialization digest", () => {
    const stateDir = temporaryState();
    const manifest = materialization();
    const manifestPath = controlPlaneMaterializationManifestPathV2(
      stateDir,
      manifest.controlPlaneMaterializationDigest,
    );
    fs.mkdirSync(path.dirname(manifestPath), { recursive: true });
    fs.writeFileSync(manifestPath, "contradictory\n", { mode: 0o600 });

    expect(() => publishControlPlaneMaterializationV2(stateDir, manifest)).toThrow("contradictory");
    expect(fs.readFileSync(manifestPath, "utf8")).toBe("contradictory\n");
  });

  test("rejects a manifest copied under a different materialization identity", () => {
    const stateDir = temporaryState();
    const manifest = materialization();
    publishControlPlaneMaterializationV2(stateDir, manifest);
    const wrongDigest = digest("wrong-materialization");
    const wrongPath = controlPlaneMaterializationManifestPathV2(stateDir, wrongDigest);
    fs.mkdirSync(path.dirname(wrongPath), { recursive: true });
    fs.copyFileSync(
      controlPlaneMaterializationManifestPathV2(stateDir, manifest.controlPlaneMaterializationDigest),
      wrongPath,
    );

    expect(() => readControlPlaneMaterializationV2(stateDir, wrongDigest)).toThrow("manifest is invalid");
  });

  test("rejects missing, malformed, cross-project, and epoch-mismatched selections", () => {
    const stateDir = temporaryState();
    const desired = target();
    expect(() => selectEffectiveControlPlaneV2(stateDir, selection(desired))).toThrow("missing");
    publishControlPlaneMaterializationV2(stateDir, materialization(desired));
    expect(() => selectEffectiveControlPlaneV2(stateDir, {
      ...selection(desired),
      proxyContainerId: "short",
    })).toThrow("selection is invalid");
    expect(() => selectEffectiveControlPlaneV2(stateDir, {
      ...selection(desired),
      unexpected: true,
    } as ControlPlaneEffectiveSelectionV2)).toThrow("selection is invalid");
    expect(() => selectEffectiveControlPlaneV2(stateDir, {
      ...selection(desired),
      admissionContractEpoch: RUNTIME_ADMISSION_CONTRACT_EPOCH + 1,
    })).toThrow("contradicts");
    expect(() => selectEffectiveControlPlaneV2(stateDir, {
      ...selection(desired),
      projectId: "fedcba987654",
      composeProject: "runfree-fedcba987654",
    })).toThrow("contradicts");
    expect(() => publishControlPlaneMaterializationV2(stateDir, {
      ...materialization(desired),
      unexpected: true,
    } as ControlPlaneMaterializationManifestV2)).toThrow("manifest is invalid");
  });

  test("requires callback network proof exactly when the callback sidecar exists", () => {
    const stateDir = temporaryState();
    const desired = target();
    publishControlPlaneMaterializationV2(stateDir, materialization(desired));
    // Relay-era shapes (a sidecar entry, a callback_host network) were minted
    // by older binaries and must fail parse closed.
    expect(() => selectEffectiveControlPlaneV2(stateDir, {
      ...selection(desired),
      sidecarContainerIds: [{ role: "mcp-callback", containerId: "d".repeat(64) }],
    } as unknown as Parameters<typeof selectEffectiveControlPlaneV2>[1])).toThrow("selection is invalid");
    expect(() => selectEffectiveControlPlaneV2(stateDir, {
      ...selection(desired),
      networkIds: { ...selection(desired).networkIds, callbackHost: "e".repeat(64) },
    } as unknown as Parameters<typeof selectEffectiveControlPlaneV2>[1])).toThrow("selection is invalid");
    expect(() => selectEffectiveControlPlaneV2(stateDir, {
      ...selection(desired),
      networkIds: { agentInternal: "b".repeat(64), proxyEgress: "b".repeat(64) },
    })).toThrow("selection is invalid");
  });

  test("rejects symlink and hard-link destinations before host-state mutation", () => {
    const symlinkState = temporaryState();
    const outside = temporaryState();
    fs.mkdirSync(path.join(symlinkState, "runtime"));
    fs.symlinkSync(outside, path.join(symlinkState, "runtime", "v2"), "dir");
    expect(() => publishControlPlaneMaterializationV2(symlinkState, materialization())).toThrow("safe directory");
    expect(fs.readdirSync(outside)).toEqual([]);

    const hardLinkState = temporaryState();
    const desired = target();
    publishControlPlaneMaterializationV2(hardLinkState, materialization(desired));
    const outsideFile = path.join(outside, "selection.json");
    fs.writeFileSync(outsideFile, "untouched\n");
    fs.mkdirSync(path.dirname(controlPlaneEffectiveSelectionPathV2(hardLinkState)), { recursive: true });
    fs.linkSync(outsideFile, controlPlaneEffectiveSelectionPathV2(hardLinkState));
    expect(() => selectEffectiveControlPlaneV2(hardLinkState, selection(desired))).toThrow("replaceable normal file");
    expect(fs.readFileSync(outsideFile, "utf8")).toBe("untouched\n");

    expect(() => clearEffectiveControlPlaneV2(hardLinkState)).toThrow("bounded normal file");
    expect(fs.readFileSync(outsideFile, "utf8")).toBe("untouched\n");
  });

  test("rejects symlinked state parents before reading authority", () => {
    const sourceState = temporaryState();
    const desired = target();
    const manifest = materialization(desired);
    publishControlPlaneMaterializationV2(sourceState, manifest);
    selectEffectiveControlPlaneV2(sourceState, selection(desired));

    const redirectedState = temporaryState();
    fs.mkdirSync(path.join(redirectedState, "runtime"));
    fs.symlinkSync(path.join(sourceState, "runtime", "v2"), path.join(redirectedState, "runtime", "v2"), "dir");

    expect(() => readEffectiveControlPlaneV2(redirectedState)).toThrow("safe directory");
    expect(() => readControlPlaneMaterializationV2(
      redirectedState,
      manifest.controlPlaneMaterializationDigest,
    )).toThrow("safe directory");
  });
});

describe("v2 session-agent materialization and desired selection", () => {
  test("publishes immutable exact image provenance and atomically selects it for new sessions", () => {
    const stateDir = temporaryState();
    const manifest = sessionAgentMaterialization();
    const desired = createSessionAgentDesiredSelectionV2(manifest);

    publishSessionAgentMaterializationV2(stateDir, manifest, SESSION_TEMPLATE_ARTIFACT);
    publishSessionAgentMaterializationV2(stateDir, manifest, SESSION_TEMPLATE_ARTIFACT);
    selectDesiredSessionAgentV2(stateDir, desired);

    expect(parseSessionAgentMaterializationManifestV2(manifest)).toEqual(manifest);
    expect(parseSessionAgentDesiredSelectionV2(desired)).toEqual(desired);
    expect(readSessionAgentMaterializationV2(stateDir, manifest.sessionAgentMaterializationDigest)).toEqual(manifest);
    expect(readDesiredSessionAgentV2(stateDir)).toEqual({ manifest, selection: desired });
    const manifestPath = sessionAgentMaterializationManifestPathV2(
      stateDir,
      manifest.sessionAgentMaterializationDigest,
    );
    expect(fs.readFileSync(manifestPath, "utf8"))
      .toBe(serializeSessionAgentMaterializationManifestV2(manifest));
    expect(fs.readFileSync(sessionAgentDesiredSelectionPathV2(stateDir), "utf8"))
      .toBe(serializeSessionAgentDesiredSelectionV2(desired));
    expect(fs.statSync(manifestPath).mode & 0o777).toBe(0o600);
    expect(fs.statSync(sessionAgentDesiredSelectionPathV2(stateDir)).mode & 0o777).toBe(0o600);
    expect(manifestPath).toContain(
      `/runtime/v2/session-agent/materializations/${manifest.sessionAgentMaterializationDigest.replace("sha256:", "sha256-")}/`,
    );
  });

  test("keeps forced same-generation rebuild outputs side by side and selects only the exact desired tuple", () => {
    const stateDir = temporaryState();
    const first = sessionAgentMaterialization();
    const rebuilt = sessionAgentMaterialization({
      selectedAgentImageId: digest("rebuilt-selected-agent-image-id"),
    });

    expect(rebuilt.generation.sessionAgentGenerationDigest)
      .toBe(first.generation.sessionAgentGenerationDigest);
    expect(rebuilt.selectedAgentImageId).not.toBe(first.selectedAgentImageId);
    expect(rebuilt.sessionAgentMaterializationDigest).not.toBe(first.sessionAgentMaterializationDigest);

    publishSessionAgentMaterializationV2(stateDir, first, SESSION_TEMPLATE_ARTIFACT);
    publishSessionAgentMaterializationV2(stateDir, rebuilt, SESSION_TEMPLATE_ARTIFACT);
    selectDesiredSessionAgentV2(stateDir, createSessionAgentDesiredSelectionV2(first));
    expect(readDesiredSessionAgentV2(stateDir)?.manifest).toEqual(first);
    selectDesiredSessionAgentV2(stateDir, createSessionAgentDesiredSelectionV2(rebuilt));

    expect(readDesiredSessionAgentV2(stateDir)?.manifest).toEqual(rebuilt);
    expect(readSessionAgentMaterializationV2(stateDir, first.sessionAgentMaterializationDigest)).toEqual(first);
    expect(readSessionAgentMaterializationV2(stateDir, rebuilt.sessionAgentMaterializationDigest)).toEqual(rebuilt);
    expect(fs.existsSync(sessionAgentMaterializationManifestPathV2(
      stateDir,
      first.sessionAgentMaterializationDigest,
    ))).toBe(true);
  });

  test("binds only selected-image identity and never infers the selected image kind", () => {
    const embedded = sessionAgentMaterialization({ selectedAgentImageKind: "embedded" });
    const {
      schemaVersion: _schemaVersion,
      sessionAgentMaterializationDigest: _materializationDigest,
      ...embeddedInputs
    } = embedded;
    expect(embeddedInputs).toEqual({
      projectId: PROJECT_ID,
      composeProject: COMPOSE_PROJECT,
      generation: embedded.generation,
      selectedAgentImageRef: "runfree/agent-runtime:mutable-ref",
      selectedAgentImageId: embedded.selectedAgentImageId,
      selectedAgentImageKind: "embedded",
      sessionTemplateArtifactSha256: digest(SESSION_TEMPLATE_ARTIFACT),
    });

    expect(() => createSessionAgentMaterializationManifestV2({
      ...embeddedInputs,
      selectedAgentImageId: digest("different-embedded-image-id"),
    })).toThrow("inputs are invalid");
    expect(parseSessionAgentMaterializationManifestV2({
      ...sessionAgentMaterialization(),
      selectedAgentImageKind: undefined,
    })).toBeUndefined();
    expect(parseSessionAgentMaterializationManifestV2({
      ...sessionAgentMaterialization(),
      selectedAgentImageKind: "inferred-from-ref",
    })).toBeUndefined();
    expect(parseSessionAgentMaterializationManifestV2({
      ...sessionAgentMaterialization(),
      finalizedSessionImageId: digest("superseded-finalized-image"),
    })).toBeUndefined();
  });

  test("rejects old one-image and ambiguous materialization or selection spellings", () => {
    const manifest = sessionAgentMaterialization();
    const desired = createSessionAgentDesiredSelectionV2(manifest);
    const oldManifest = {
      schemaVersion: 2,
      projectId: manifest.projectId,
      composeProject: manifest.composeProject,
      generation: manifest.generation,
      imageRef: manifest.selectedAgentImageRef,
      imageId: manifest.selectedAgentImageId,
      sessionAgentMaterializationDigest: manifest.sessionAgentMaterializationDigest,
    };
    const oldSelection = {
      schemaVersion: 2,
      projectId: desired.projectId,
      composeProject: desired.composeProject,
      sessionAgentGenerationDigest: desired.sessionAgentGenerationDigest,
      imageId: desired.selectedAgentImageId,
    };

    expect(parseSessionAgentMaterializationManifestV2(oldManifest)).toBeUndefined();
    expect(parseSessionAgentDesiredSelectionV2(oldSelection)).toBeUndefined();
    expect(() => serializeSessionAgentMaterializationManifestV2(
      oldManifest as unknown as SessionAgentMaterializationManifestV2,
    )).toThrow("manifest is invalid");
    expect(() => serializeSessionAgentDesiredSelectionV2(
      oldSelection as unknown as SessionAgentDesiredSelectionV2,
    )).toThrow("selection is invalid");
    expect(parseSessionAgentMaterializationManifestV2({ ...manifest, imageId: manifest.selectedAgentImageId }))
      .toBeUndefined();
    expect(parseSessionAgentDesiredSelectionV2({ ...desired, imageId: desired.selectedAgentImageId }))
      .toBeUndefined();
    expect(parseSessionAgentDesiredSelectionV2({
      ...desired,
      finalizedSessionImageId: digest("superseded-finalized-image"),
    })).toBeUndefined();
  });

  test("rejects mutable-ref retag evidence and persisted identity mutations", () => {
    const stateDir = temporaryState();
    const manifest = sessionAgentMaterialization();
    const desired = createSessionAgentDesiredSelectionV2(manifest);
    publishSessionAgentMaterializationV2(stateDir, manifest, SESSION_TEMPLATE_ARTIFACT);

    expect(() => selectDesiredSessionAgentV2(stateDir, {
      ...desired,
      selectedAgentImageId: digest("retagged-selected-image-id"),
    })).toThrow("contradicts its materialization");
    expect(fs.existsSync(sessionAgentDesiredSelectionPathV2(stateDir))).toBe(false);

    selectDesiredSessionAgentV2(stateDir, desired);
    fs.writeFileSync(sessionAgentDesiredSelectionPathV2(stateDir), `${JSON.stringify({
      ...desired,
      selectedAgentImageId: digest("mutated-selected-image"),
    })}\n`);
    expect(() => readDesiredSessionAgentV2(stateDir)).toThrow("contradicts its materialization");

    const manifestPath = sessionAgentMaterializationManifestPathV2(
      stateDir,
      manifest.sessionAgentMaterializationDigest,
    );
    fs.writeFileSync(manifestPath, `${JSON.stringify({
      ...manifest,
      selectedAgentImageRef: "runfree/agent-project:retagged",
    })}\n`);
    expect(() => readSessionAgentMaterializationV2(
      stateDir,
      manifest.sessionAgentMaterializationDigest,
    )).toThrow("manifest is invalid");
  });

  test("never overwrites contradictory materialization bytes or selects a missing exact digest", () => {
    const stateDir = temporaryState();
    const manifest = sessionAgentMaterialization();
    publishSessionAgentMaterializationV2(stateDir, manifest, SESSION_TEMPLATE_ARTIFACT);
    const manifestPath = sessionAgentMaterializationManifestPathV2(
      stateDir,
      manifest.sessionAgentMaterializationDigest,
    );
    fs.writeFileSync(manifestPath, "{\"tampered\":true}\n");

    expect(() => publishSessionAgentMaterializationV2(
      stateDir,
      manifest,
      SESSION_TEMPLATE_ARTIFACT,
    )).toThrow("contradictory");
    expect(fs.readFileSync(manifestPath, "utf8")).toBe("{\"tampered\":true}\n");
    expect(() => selectDesiredSessionAgentV2(temporaryState(), createSessionAgentDesiredSelectionV2(manifest)))
      .toThrow("missing");
  });

  test("rejects copied identities and unsafe desired-state paths", () => {
    const sourceState = temporaryState();
    const manifest = sessionAgentMaterialization();
    publishSessionAgentMaterializationV2(sourceState, manifest, SESSION_TEMPLATE_ARTIFACT);
    const wrongDigest = digest("wrong-session-agent-materialization");
    const wrongPath = sessionAgentMaterializationManifestPathV2(sourceState, wrongDigest);
    fs.mkdirSync(path.dirname(wrongPath), { recursive: true });
    fs.copyFileSync(
      sessionAgentMaterializationManifestPathV2(sourceState, manifest.sessionAgentMaterializationDigest),
      wrongPath,
    );
    expect(() => readSessionAgentMaterializationV2(sourceState, wrongDigest)).toThrow("manifest is invalid");

    const symlinkState = temporaryState();
    const outside = temporaryState();
    fs.mkdirSync(path.join(symlinkState, "runtime", "v2"), { recursive: true });
    fs.symlinkSync(outside, path.join(symlinkState, "runtime", "v2", "session-agent"), "dir");
    expect(() => publishSessionAgentMaterializationV2(
      symlinkState,
      manifest,
      SESSION_TEMPLATE_ARTIFACT,
    )).toThrow("safe directory");
    expect(fs.readdirSync(outside)).toEqual([]);

    const hardLinkState = temporaryState();
    publishSessionAgentMaterializationV2(hardLinkState, manifest, SESSION_TEMPLATE_ARTIFACT);
    const outsideSelection = path.join(outside, "desired.json");
    fs.writeFileSync(outsideSelection, "untouched\n");
    fs.linkSync(outsideSelection, sessionAgentDesiredSelectionPathV2(hardLinkState));
    expect(() => selectDesiredSessionAgentV2(
      hardLinkState,
      createSessionAgentDesiredSelectionV2(manifest),
    )).toThrow("replaceable normal file");
    expect(fs.readFileSync(outsideSelection, "utf8")).toBe("untouched\n");
  });

  test("treats artifact-only publication residue as non-authorizing", () => {
    const stateDir = temporaryState();
    const manifest = sessionAgentMaterialization();
    const artifactPath = sessionAgentTemplateArtifactPathV2(
      stateDir,
      manifest.sessionAgentMaterializationDigest,
    );
    fs.mkdirSync(path.dirname(artifactPath), { recursive: true });
    fs.writeFileSync(artifactPath, SESSION_TEMPLATE_ARTIFACT, { mode: 0o600 });

    expect(readSessionAgentMaterializationV2(stateDir, manifest.sessionAgentMaterializationDigest))
      .toBeUndefined();
    expect(() => selectDesiredSessionAgentV2(
      stateDir,
      createSessionAgentDesiredSelectionV2(manifest),
    )).toThrow("missing");
    expect(fs.existsSync(sessionAgentDesiredSelectionPathV2(stateDir))).toBe(false);
  });

  test("rejects linked, symlinked, special, and oversized template artifacts", () => {
    const manifest = sessionAgentMaterialization();

    const symlinkState = temporaryState();
    publishSessionAgentMaterializationV2(symlinkState, manifest, SESSION_TEMPLATE_ARTIFACT);
    const symlinkPath = sessionAgentTemplateArtifactPathV2(
      symlinkState,
      manifest.sessionAgentMaterializationDigest,
    );
    const outside = path.join(temporaryState(), "outside-template.json");
    fs.writeFileSync(outside, SESSION_TEMPLATE_ARTIFACT);
    fs.unlinkSync(symlinkPath);
    fs.symlinkSync(outside, symlinkPath);
    expect(() => readSessionAgentTemplateArtifactV2(symlinkState, manifest)).toThrow("bounded normal file");

    const hardLinkState = temporaryState();
    publishSessionAgentMaterializationV2(hardLinkState, manifest, SESSION_TEMPLATE_ARTIFACT);
    const hardLinkPath = sessionAgentTemplateArtifactPathV2(
      hardLinkState,
      manifest.sessionAgentMaterializationDigest,
    );
    fs.linkSync(hardLinkPath, path.join(temporaryState(), "template-copy.json"));
    expect(() => readSessionAgentTemplateArtifactV2(hardLinkState, manifest)).toThrow("bounded normal file");

    const directoryState = temporaryState();
    publishSessionAgentMaterializationV2(directoryState, manifest, SESSION_TEMPLATE_ARTIFACT);
    const directoryPath = sessionAgentTemplateArtifactPathV2(
      directoryState,
      manifest.sessionAgentMaterializationDigest,
    );
    fs.unlinkSync(directoryPath);
    fs.mkdirSync(directoryPath);
    expect(() => readSessionAgentTemplateArtifactV2(directoryState, manifest)).toThrow("bounded normal file");

    expect(() => publishSessionAgentMaterializationV2(
      temporaryState(),
      manifest,
      "x".repeat(64 * 1024 + 1),
    )).toThrow("oversized");
  });

  test("keeps the previous exact manifest shape as retention-only evidence", () => {
    const stateDir = temporaryState();
    const current = sessionAgentMaterialization();
    const {
      sessionTemplateArtifactSha256: _artifactSha256,
      sessionAgentMaterializationDigest: _currentDigest,
      ...legacyInputs
    } = current;
    const legacy = {
      ...legacyInputs,
      sessionAgentMaterializationDigest: sha256Digest(stableJsonForTest(legacyInputs)),
    };
    expect(parseLegacySessionAgentMaterializationManifestV2(legacy)).toEqual(legacy);
    const manifestPath = sessionAgentMaterializationManifestPathV2(
      stateDir,
      legacy.sessionAgentMaterializationDigest,
    );
    fs.mkdirSync(path.dirname(manifestPath), { recursive: true });
    fs.writeFileSync(manifestPath, `${stableJsonForTest(legacy)}\n`, { mode: 0o600 });
    const selection = {
      ...createSessionAgentDesiredSelectionV2(current),
      sessionAgentMaterializationDigest: legacy.sessionAgentMaterializationDigest,
    };
    fs.mkdirSync(path.dirname(sessionAgentDesiredSelectionPathV2(stateDir)), { recursive: true });
    fs.writeFileSync(
      sessionAgentDesiredSelectionPathV2(stateDir),
      serializeSessionAgentDesiredSelectionV2(selection),
      { mode: 0o600 },
    );

    expect(readRetainedDesiredSessionAgentV2(stateDir)).toEqual({
      selection,
      manifest: legacy,
      selectable: false,
    });
    expect(() => readDesiredSessionAgentV2(stateDir)).toThrow("manifest is invalid");
  });
});

describe("v1 runtime-generation state stays out of v2 authority", () => {
  // The v1 materialization layout (generation.json / effective.json) is still
  // the live runtime-files record, but it must never parse as schema-v2
  // control-plane authority.
  test("does not parse a v1 effective selection as v2 state", () => {
    const stateDir = temporaryState();
    publishV1(stateDir);
    fs.mkdirSync(path.dirname(controlPlaneEffectiveSelectionPathV2(stateDir)), { recursive: true });
    fs.copyFileSync(path.join(stateDir, "runtime", "effective.json"), controlPlaneEffectiveSelectionPathV2(stateDir));

    expect(() => readEffectiveControlPlaneV2(stateDir)).toThrow("v2 control-plane effective selection is invalid");
  });
});
