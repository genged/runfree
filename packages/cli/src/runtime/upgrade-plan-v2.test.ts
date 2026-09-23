import { describe, expect, test } from "vitest";

import {
  createSessionAgentDesiredSelectionV2,
  createSessionAgentMaterializationManifestV2,
} from "./component-state-v2.ts";
import { createRuntimeGenerationTargetV2 } from "./generation-plan-v2.ts";
import { sha256Digest } from "./component-state.ts";
import {
  controlPlaneMaterializationFixture,
  effectiveControlPlaneFixture,
  sessionContainerRecordFixture,
} from "./session-container.test-harness.ts";
import { planRuntimeUpgradeV2 } from "./upgrade-plan-v2.ts";

const projectId = "0123456789ab";
const composeProject = `runfree-${projectId}`;
const id = (value: string) => sha256Digest(value);

function target(overrides: { proxy?: string; agent?: string; control?: string; session?: string; epoch?: number } = {}) {
  return createRuntimeGenerationTargetV2({
    projectId,
    composeProject,
    proxyImageInputDigest: id(overrides.proxy ?? "proxy"),
    selectedAgentImageInputDigest: id(overrides.agent ?? "agent"),
    admissionContractEpoch: overrides.epoch ?? 3,
    topology: {
      compose: "services:\n  proxy:\n    image: ${RUNFREE_PROXY_IMAGE}",
      interpolationValues: {
        RUNFREE_PROXY_IMAGE: "proxy",
      },
      controlPlane: { structure: { value: overrides.control ?? "control" }, runtimeSignatures: {} },
      sessionTemplate: { structure: { value: overrides.session ?? "session" }, runtimeSignatures: {} },
    },
  });
}

function state(generation = target()) {
  const controlManifest = controlPlaneMaterializationFixture({ target: generation });
  const controlSelection = effectiveControlPlaneFixture({ target: generation });
  const sessionManifest = createSessionAgentMaterializationManifestV2({
    projectId,
    composeProject,
    generation: { ...generation.sessionAgent, selectedAgentImageId: id("agent-image") },
    selectedAgentImageRef: "runfree/agent:test",
    selectedAgentImageId: id("agent-image"),
    selectedAgentImageKind: "embedded",
    sessionTemplateArtifactSha256: id("template-artifact"),
  });
  return {
    effectiveControlPlane: { selection: controlSelection, manifest: controlManifest },
    desiredSessionAgent: { selection: createSessionAgentDesiredSelectionV2(sessionManifest), manifest: sessionManifest },
    liveProxies: [{ projectId, composeProject, containerId: controlSelection.proxyContainerId, imageId: controlSelection.proxyImageId }],
  };
}

describe("schema-v2 runtime upgrade planner", () => {
  test("classifies current, session-agent, compatible proxy, and incompatible changes", () => {
    const baseline = target();
    const current = state(baseline);
    expect(planRuntimeUpgradeV2({ desired: baseline, ...current, lifecycleRecords: [] })).toEqual({ kind: "none" });
    expect(planRuntimeUpgradeV2({
      desired: baseline,
      effectiveControlPlane: current.effectiveControlPlane,
      desiredSessionAgent: current.desiredSessionAgent,
      lifecycleRecords: [],
    })).toEqual({ kind: "restart-compatible-proxy" });
    expect(planRuntimeUpgradeV2({ desired: target({ agent: "other" }), ...current, lifecycleRecords: [] }))
      .toEqual({ kind: "select-session-agent" });
    expect(planRuntimeUpgradeV2({ desired: target({ proxy: "other" }), ...current, lifecycleRecords: [] }))
      .toEqual({ kind: "restart-compatible-proxy" });

    const active = [sessionContainerRecordFixture()];
    expect(planRuntimeUpgradeV2({ desired: target({ epoch: 4 }), ...current, lifecycleRecords: active }))
      .toEqual({ kind: "block-incompatible", reason: "admission-epoch" });
    expect(planRuntimeUpgradeV2({ desired: target({ control: "other" }), ...current, lifecycleRecords: active }))
      .toEqual({ kind: "block-incompatible", reason: "control-plane-topology" });
  });

  test("does not reduce a missing desired session selection to a warm token sync", () => {
    const desired = target();
    const current = state(desired);
    expect(planRuntimeUpgradeV2({
      desired,
      effectiveControlPlane: current.effectiveControlPlane,
      liveProxies: current.liveProxies,
      lifecycleRecords: [],
    })).toEqual({ kind: "select-session-agent" });
  });

  test("refuses contradictory live evidence without an effective selection", () => {
    const desired = target();
    const current = state(desired);
    expect(planRuntimeUpgradeV2({
      desired,
      liveProxies: current.liveProxies,
      lifecycleRecords: [],
    })).toEqual({
      kind: "refuse-invalid",
      reason: "live proxy exists without an effective control-plane selection",
    });
    expect(planRuntimeUpgradeV2({
      desired,
      lifecycleRecords: [sessionContainerRecordFixture()],
    })).toEqual({
      kind: "refuse-invalid",
      reason: "session lifecycle records exist without an effective control-plane selection",
    });
    expect(planRuntimeUpgradeV2({
      desired,
      ...current,
      liveProxies: [{ ...current.liveProxies[0], containerId: id("other").slice("sha256:".length) }],
      lifecycleRecords: [],
    })).toEqual({ kind: "refuse-invalid", reason: "live proxy contradicts the effective control-plane selection" });
  });

  test("refuses duplicate proxies and resumes a durable rebind transaction", () => {
    const desired = target();
    const current = state(desired);
    expect(planRuntimeUpgradeV2({
      desired,
      ...current,
      liveProxies: [current.liveProxies[0], { ...current.liveProxies[0], containerId: "e".repeat(64) }],
      lifecycleRecords: [],
    })).toEqual({ kind: "refuse-invalid", reason: "live proxy evidence is duplicated" });
    expect(planRuntimeUpgradeV2({
      desired,
      ...current,
      lifecycleRecords: [],
      pendingTransaction: { projectId, composeProject, kind: "control-plane-rebind" },
    })).toEqual({ kind: "restart-compatible-proxy" });
  });
});
