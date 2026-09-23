import { expect, test } from "vitest";

import { createRuntimeComponentState, sha256Digest } from "./component-state.ts";
import {
  effectiveControlPlaneComponentEvidenceIssue,
  runtimeComponentEvidenceIssue,
  tokenSyncComponentEvidenceIssue,
} from "./upgrade-classification.ts";
import type { RuntimeContainer } from "./types.ts";

const components = createRuntimeComponentState({
  embeddedAgentImageInputDigest: sha256Digest("embedded"),
  selectedAgentImageInputDigest: sha256Digest("session-agent"),
  selectedAgentImageKind: "embedded",
  proxyImageInputDigest: sha256Digest("proxy"),
  topologyDigest: sha256Digest("proxy-only-topology"),
  hostHelperDigest: sha256Digest("helper"),
});
const identity = { composeProject: "runfree-0123456789ab", projectId: "0123456789ab" };
const proxy = {
  id: "a".repeat(64),
  service: "proxy",
  digestSchemaVersion: "1",
  proxyImageInputDigest: components.proxyImageInputDigest,
  topologyDigest: components.topologyDigest,
  imageRef: "runfree/proxy:expected",
  ...identity,
} satisfies RuntimeContainer;

const effective = {
  selection: {
    schemaVersion: 2 as const,
    ...identity,
    controlPlaneGenerationDigest: `sha256:${"1".repeat(64)}`,
    controlPlaneMaterializationDigest: `sha256:${"2".repeat(64)}`,
    proxyContainerId: proxy.id,
    proxyImageId: `sha256:${"3".repeat(64)}`,
    sidecarContainerIds: [],
    networkIds: {
      agentInternal: "b".repeat(64),
      proxyEgress: "c".repeat(64),
    },
    securityContractHash: `sha256:${"4".repeat(64)}`,
    proofSchemaVersion: 1 as const,
    admissionContractEpoch: 3,
    denyByDefaultBaseProofHash: `sha256:${"5".repeat(64)}`,
    selectedAt: "2026-08-27T00:00:00.000Z",
    runfreeVersion: "1.0.0",
  },
  manifest: {
    schemaVersion: 2 as const,
    ...identity,
    generation: {
      schemaVersion: 2 as const,
      ...identity,
      proxyImageInputDigest: components.proxyImageInputDigest,
      controlPlaneTopologyDigest: `sha256:${"6".repeat(64)}`,
      admissionContractEpoch: 3,
      controlPlaneGenerationDigest: `sha256:${"1".repeat(64)}`,
    },
    proxyImageRef: proxy.imageRef,
    proxyImageId: `sha256:${"3".repeat(64)}`,
    renderedControlPlaneSha256: `sha256:${"6".repeat(64)}`,
    sessionAdmissionSource: "files" as const,
    controlPlaneMaterializationDigest: `sha256:${"2".repeat(64)}`,
  },
};

test("accepts one exact proxy-only control plane", () => {
  expect(runtimeComponentEvidenceIssue(
    [proxy],
    components,
    { agent: "unused", proxy: proxy.imageRef },
    identity,
  )).toBeUndefined();
});

test("uses schema-v2 effective identity when a session-only change makes composite labels stale", () => {
  const staleCompositeLabels = {
    ...proxy,
    running: true,
    topologyDigest: `sha256:${"7".repeat(64)}`,
  };
  expect(effectiveControlPlaneComponentEvidenceIssue(
    [staleCompositeLabels],
    effective,
    identity,
  )).toBeUndefined();
  expect(effectiveControlPlaneComponentEvidenceIssue(
    [{ ...staleCompositeLabels, id: "8".repeat(64) }],
    effective,
    identity,
  )).toMatchObject({ kind: "contradictory", message: expect.stringContaining("identity") });
});

test("rejects a leftover pre-cutover Compose agent as migration evidence", () => {
  const legacyAgent = {
    id: "b".repeat(64),
    service: "agent",
    digestSchemaVersion: "1",
    agentImageInputDigest: components.selectedAgentImageInputDigest,
    topologyDigest: components.topologyDigest,
    imageRef: "runfree/agent:legacy",
    ...identity,
  } satisfies RuntimeContainer;

  expect(runtimeComponentEvidenceIssue([proxy, legacyAgent], components, undefined, identity)).toEqual({
    kind: "contradictory",
    message: "runtime contains a leftover legacy Compose agent outside the schema-v2 control plane",
  });
});

test("distinguishes missing, duplicate, image, and project contradictions", () => {
  expect(runtimeComponentEvidenceIssue([], components)).toMatchObject({ kind: "missing" });
  expect(runtimeComponentEvidenceIssue([proxy, { ...proxy, id: "c".repeat(64) }], components))
    .toMatchObject({ kind: "duplicate", message: expect.stringContaining("proxy") });
  expect(runtimeComponentEvidenceIssue(
    [{ ...proxy, imageRef: "runfree/proxy:wrong" }],
    components,
    { agent: "unused", proxy: proxy.imageRef },
    identity,
  )).toMatchObject({ kind: "contradictory", message: expect.stringContaining("image references") });
  expect(runtimeComponentEvidenceIssue(
    [{ ...proxy, projectId: "ffffffffffff" }],
    components,
    undefined,
    identity,
  )).toMatchObject({ kind: "contradictory", message: expect.stringContaining("project identity") });
});

test("a pending rebind suspends old-container pinning; the warm path keeps it", () => {
  // Mid-rebind the candidate proxy is a NEW container while the durable
  // selection still names the old one. Same generation, matching plan
  // components: with a pending rebind transaction validation must accept the
  // candidate; without one the warm path must still refuse the unknown
  // container before any sensitive side effect.
  const candidateProxy = { ...proxy, id: "9".repeat(64), running: true };
  const base = {
    containers: [candidateProxy],
    effectiveControlPlane: effective,
    desiredControlPlaneGenerationDigest: effective.manifest.generation.controlPlaneGenerationDigest,
    components,
    images: { agent: "unused", proxy: proxy.imageRef },
    identity,
  };
  expect(tokenSyncComponentEvidenceIssue({ ...base, pendingControlPlaneRebind: true })).toBeUndefined();
  expect(tokenSyncComponentEvidenceIssue({ ...base, pendingControlPlaneRebind: false })).toMatchObject({
    kind: "contradictory",
    message: "runtime container identity contradicts the effective control-plane selection",
  });
  // The suspension never weakens the component check itself: a candidate whose
  // labels contradict the plan components still refuses mid-rebind.
  expect(tokenSyncComponentEvidenceIssue({
    ...base,
    pendingControlPlaneRebind: true,
    containers: [{ ...candidateProxy, proxyImageInputDigest: `sha256:${"e".repeat(64)}` }],
  })).toMatchObject({ kind: "contradictory" });
});
