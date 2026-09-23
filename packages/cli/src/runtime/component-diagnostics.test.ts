import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, expect, test } from "vitest";

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
  CONTROL_PLANE_PROOF_SCHEMA_VERSION,
  createControlPlaneGenerationV2,
  createControlPlaneMaterializationManifestV2,
  publishControlPlaneMaterializationV2,
  selectEffectiveControlPlaneV2,
} from "./component-state-v2.ts";
import {
  runtimeComponentDiagnosticLines,
  runtimeLifecycleStateDiagnosticLines,
} from "./component-diagnostics.ts";
import {
  controlPlaneMaterializationFixture,
  effectiveControlPlaneFixture,
  sessionGenerationFixture,
} from "./session-container.test-harness.ts";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function components(proxy = "proxy") {
  return createRuntimeComponentState({
    embeddedAgentImageInputDigest: sha256Digest("embedded"),
    selectedAgentImageInputDigest: sha256Digest("agent"),
    selectedAgentImageKind: "embedded",
    proxyImageInputDigest: sha256Digest(proxy),
    topologyDigest: sha256Digest("topology"),
    hostHelperDigest: sha256Digest("helper"),
  });
}

test("component diagnostics distinguish unchanged inputs from the required action", () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-component-diagnostics-"));
  roots.push(stateDir);
  const current = sessionGenerationFixture().target;
  const desired = {
    ...current,
    controlPlane: createControlPlaneGenerationV2({
      projectId: current.controlPlane.projectId,
      composeProject: current.controlPlane.composeProject,
      proxyImageInputDigest: sha256Digest("new-proxy"),
      controlPlaneTopologyDigest: current.controlPlane.controlPlaneTopologyDigest,
      admissionContractEpoch: current.controlPlane.admissionContractEpoch,
    }),
  };
  publishControlPlaneMaterializationV2(stateDir, controlPlaneMaterializationFixture({ target: current }));
  selectEffectiveControlPlaneV2(stateDir, effectiveControlPlaneFixture({ target: current }));
  const output = runtimeComponentDiagnosticLines({
    action: "proxy-restart",
    desired,
    stateDir,
  }).join("\n");

  expect(output).toContain(`generation: ${current.controlPlane.controlPlaneGenerationDigest}`);
  expect(output).toContain(`${desired.controlPlane.proxyImageInputDigest}  restart required`);
  expect(output).toContain(`${desired.controlPlane.controlPlaneTopologyDigest}  unchanged`);
  expect(output).toContain("upgrade action: proxy restart");
});

test("lifecycle diagnostics show the selected v2 control plane alongside inert v1 materialization state", () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-component-diagnostics-"));
  roots.push(stateDir);
  const projectId = "0123456789ab";
  const composeProject = `runfree-${projectId}`;
  const v1Components = components();
  const v1Manifest: RuntimeGenerationManifest = {
    schemaVersion: 1,
    projectId,
    composeProject,
    components: v1Components,
    images: { agent: "agent:image", proxy: "proxy:image" },
    renderedComposeSha256: sha256Digest("compose"),
  };
  fs.mkdirSync(runtimeMaterializationRoot(stateDir, v1Components.materializationDigest), { recursive: true });
  fs.writeFileSync(
    runtimeGenerationManifestPath(stateDir, v1Components.materializationDigest),
    serializeRuntimeGenerationManifest(v1Manifest),
  );
  selectEffectiveRuntimeGeneration(stateDir, v1Components.materializationDigest);

  const generation = createControlPlaneGenerationV2({
    projectId,
    composeProject,
    proxyImageInputDigest: sha256Digest("v2-proxy"),
    controlPlaneTopologyDigest: sha256Digest("control-plane-topology"),
    admissionContractEpoch: 1,
  });
  const proxyImageId = sha256Digest("v2-proxy-image-id");
  const controlPlaneMaterialization = createControlPlaneMaterializationManifestV2({
    projectId,
    composeProject,
    generation,
    proxyImageRef: "proxy:v2",
    proxyImageId,
    renderedControlPlaneSha256: generation.controlPlaneTopologyDigest,
  
    sessionAdmissionSource: "files",
  });
  publishControlPlaneMaterializationV2(stateDir, controlPlaneMaterialization);
  selectEffectiveControlPlaneV2(stateDir, {
    schemaVersion: 2,
    projectId,
    composeProject,
    controlPlaneGenerationDigest: generation.controlPlaneGenerationDigest,
    controlPlaneMaterializationDigest: controlPlaneMaterialization.controlPlaneMaterializationDigest,
    proxyContainerId: "a".repeat(64),
    proxyImageId,
    sidecarContainerIds: [],
    networkIds: { agentInternal: "b".repeat(64), proxyEgress: "c".repeat(64) },
    securityContractHash: sha256Digest("security-contract"),
    proofSchemaVersion: CONTROL_PLANE_PROOF_SCHEMA_VERSION,
    admissionContractEpoch: 1,
    denyByDefaultBaseProofHash: sha256Digest("deny-by-default"),
    selectedAt: "2026-08-05T00:00:00.000Z",
    runfreeVersion: "0.3.0",
  });

  const output = runtimeLifecycleStateDiagnosticLines(stateDir).join("\n");
  expect(output).toContain("launch behavior: per-session schema v2");
  // The v1 materialization layout persists on disk but is never reported as
  // migration evidence — the migrate-legacy-v1 path no longer exists.
  expect(output).not.toContain("legacy v1 migration evidence");
  expect(output).toContain(`effective control plane: ${generation.controlPlaneGenerationDigest}`);
  expect(output).toContain("admission epoch: 1");
  expect(output).toContain("control-plane rebind: none");
});
