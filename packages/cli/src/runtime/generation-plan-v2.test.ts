import { describe, expect, test } from "vitest";

import { sha256Digest } from "./component-state.ts";
import { RUNTIME_ADMISSION_CONTRACT_EPOCH } from "./component-state-v2.ts";
import {
  createRuntimeGenerationTargetV2,
  type RuntimeGenerationPlanInputV2,
} from "./generation-plan-v2.ts";

const PROJECT_ID = "0123456789ab";

function input(
  overrides: Partial<Omit<RuntimeGenerationPlanInputV2, "topology">> & {
    topology?: Partial<RuntimeGenerationPlanInputV2["topology"]>;
  } = {},
): RuntimeGenerationPlanInputV2 {
  const topology: RuntimeGenerationPlanInputV2["topology"] = {
    compose: [
      "services:",
      "  agent:",
      "    image: ${RUNFREE_AGENT_IMAGE:?required}",
      "    volumes:",
      "      - ${RUNFREE_PROJECT_ROOT}:/workspace",
      "  proxy:",
      "    image: ${RUNFREE_PROXY_IMAGE:?required}",
      "    networks:",
      "      internal:",
      "        ipv4_address: ${RUNFREE_PROXY_IP}",
      "      egress:",
      "        ipv4_address: ${RUNFREE_PROXY_EGRESS_IP}",
    ].join("\n"),
    interpolationValues: {
      RUNFREE_AGENT_IMAGE: "runfree/agent:input",
      RUNFREE_PROJECT_ROOT: "/project",
      RUNFREE_PROXY_IMAGE: "runfree/proxy:input",
      RUNFREE_PROXY_EGRESS_IP: "172.30.1.10",
      RUNFREE_PROXY_IP: "172.30.0.10",
    },
    controlPlane: {
      structure: { networks: ["agent_internal", "proxy_egress"], services: ["proxy"] },
      runtimeSignatures: { firewallContract: 1 },
    },
    sessionTemplate: {
      structure: { entrypoint: ["/usr/bin/sleep", "infinity"], user: "1000" },
      runtimeSignatures: { mountContract: 1 },
    },
    ...overrides.topology,
  };
  return {
    projectId: PROJECT_ID,
    composeProject: `runfree-${PROJECT_ID}`,
    proxyImageInputDigest: sha256Digest("proxy-image-input"),
    selectedAgentImageInputDigest: sha256Digest("agent-image-input"),
    admissionContractEpoch: RUNTIME_ADMISSION_CONTRACT_EPOCH,
    ...overrides,
    topology,
  };
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

describe("schema-v2 runtime generation planning", () => {
  test("computes one strict target from canonical topology and image inputs without mutation", () => {
    const planInput = deepFreeze(input());
    const before = structuredClone(planInput);

    const first = createRuntimeGenerationTargetV2(planInput);
    const second = createRuntimeGenerationTargetV2(planInput);

    expect(second).toEqual(first);
    expect(planInput).toEqual(before);
    expect(first.controlPlane.controlPlaneTopologyDigest)
      .toBe(first.topology.controlPlaneTopologyDigest);
    expect(first.sessionAgent.sessionTemplateDigest).toBe(first.topology.sessionTemplateDigest);
    expect(first.controlPlane.admissionContractEpoch)
      .toBe(first.sessionAgent.admissionContractEpoch);
  });

  test("keeps image inputs in their owning component generations", () => {
    const baseline = createRuntimeGenerationTargetV2(input());
    const proxyChanged = createRuntimeGenerationTargetV2(input({
      proxyImageInputDigest: sha256Digest("other-proxy-image-input"),
    }));
    const agentChanged = createRuntimeGenerationTargetV2(input({
      selectedAgentImageInputDigest: sha256Digest("other-agent-image-input"),
    }));

    expect(proxyChanged.topology).toEqual(baseline.topology);
    expect(proxyChanged.controlPlane.controlPlaneGenerationDigest)
      .not.toBe(baseline.controlPlane.controlPlaneGenerationDigest);
    expect(proxyChanged.sessionAgent).toEqual(baseline.sessionAgent);
    expect(agentChanged.topology).toEqual(baseline.topology);
    expect(agentChanged.controlPlane).toEqual(baseline.controlPlane);
    expect(agentChanged.sessionAgent.sessionAgentGenerationDigest)
      .not.toBe(baseline.sessionAgent.sessionAgentGenerationDigest);
  });

  test("projects topology changes into only the component that owns them", () => {
    const baseline = createRuntimeGenerationTargetV2(input());
    const controlPlaneChanged = createRuntimeGenerationTargetV2(input({
      topology: {
        interpolationValues: {
          ...input().topology.interpolationValues,
          RUNFREE_PROXY_EGRESS_IP: "172.30.1.20",
        },
      },
    }));
    const sessionChanged = createRuntimeGenerationTargetV2(input({
      topology: {
        interpolationValues: {
          ...input().topology.interpolationValues,
          RUNFREE_PROJECT_ROOT: "/other-project",
        },
      },
    }));

    expect(controlPlaneChanged.controlPlane.controlPlaneGenerationDigest)
      .not.toBe(baseline.controlPlane.controlPlaneGenerationDigest);
    expect(controlPlaneChanged.sessionAgent).toEqual(baseline.sessionAgent);
    expect(sessionChanged.controlPlane).toEqual(baseline.controlPlane);
    expect(sessionChanged.sessionAgent.sessionAgentGenerationDigest)
      .not.toBe(baseline.sessionAgent.sessionAgentGenerationDigest);
  });

  test("fails closed on invalid identity, digests, epoch, or unclassified topology inputs", () => {
    expect(() => createRuntimeGenerationTargetV2(input({ composeProject: "wrong-project" })))
      .toThrow("invalid project identity");
    expect(() => createRuntimeGenerationTargetV2(input({ proxyImageInputDigest: "proxy:latest" })))
      .toThrow("full sha256 digest");
    expect(() => createRuntimeGenerationTargetV2(input({ admissionContractEpoch: 0 })))
      .toThrow("positive safe integer");
    expect(() => createRuntimeGenerationTargetV2(input({
      topology: {
        compose: `${input().topology.compose}\n    hostname: \${RUNFREE_UNKNOWN_HOSTNAME}`,
      },
    }))).toThrow("has no v2 projection");
  });
});
