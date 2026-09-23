import fs from "node:fs";
import path from "node:path";

import { describe, expect, test } from "vitest";

import { composeAgentStateMounts } from "../agents.ts";
import { inboxMount } from "../inbox.ts";
import { renderRuntimeCompose } from "./compose.ts";
import { composeInterpolationVariables } from "./topology-digest.ts";
import {
  RUNTIME_COMPOSE_INTERPOLATION_PROJECTIONS_V2,
  runtimeTopologyGenerationV2,
  type RuntimeTopologyDigestInputV2,
} from "./topology-digest-v2.ts";

const CANONICAL_COMPOSE = fs.readFileSync(path.resolve("packages/agent-runtime/agent/compose.yaml"), "utf8");

function input(overrides: Partial<RuntimeTopologyDigestInputV2> = {}): RuntimeTopologyDigestInputV2 {
  return {
    compose: [
      "services:",
      "  agent:",
      "    image: ${RUNFREE_AGENT_IMAGE:?required}",
      "    volumes:",
      "      - ${RUNFREE_PROJECT_ROOT}:/workspace",
      "    labels:",
      "      project: ${RUNFREE_PROJECT_ID}",
      "  proxy:",
      "    image: ${RUNFREE_PROXY_IMAGE:?required}",
      "    networks:",
      "      internal:",
      "        ipv4_address: ${RUNFREE_PROXY_IP}",
      "      egress:",
      "        ipv4_address: ${RUNFREE_PROXY_EGRESS_IP}",
      "    labels:",
      "      version: ${RUNFREE_VERSION}",
    ].join("\n"),
    interpolationValues: {
      RUNFREE_AGENT_IMAGE: "runfree/agent:sha256-agent",
      RUNFREE_PROJECT_ROOT: "/project",
      RUNFREE_PROJECT_ID: "0123456789ab",
      RUNFREE_PROXY_IMAGE: "runfree/proxy:sha256-proxy",
      RUNFREE_PROXY_EGRESS_IP: "172.30.1.10",
      RUNFREE_PROXY_IP: "172.30.0.10",
      RUNFREE_VERSION: "0.3.0",
    },
    controlPlane: {
      structure: { services: ["proxy"], networks: ["agent_internal", "proxy_egress"] },
      runtimeSignatures: { firewall: { contract: 1 } },
    },
    sessionTemplate: {
      structure: { entrypoint: ["sleep", "infinity"], mounts: ["/workspace"] },
      runtimeSignatures: { mountPolicy: { contract: 1 } },
    },
    ...overrides,
  };
}

function canonicalRenderedCompose(): string {
  return renderRuntimeCompose(CANONICAL_COMPOSE, {
    agentStateMounts: composeAgentStateMounts(),
    agentVolumes: [inboxMount()],
  });
}

describe("runtime topology generation v2", () => {
  test("is deterministic and independent of input object ordering", () => {
    const first = runtimeTopologyGenerationV2(input());
    const second = runtimeTopologyGenerationV2(input({
      interpolationValues: {
        RUNFREE_VERSION: "0.3.0",
        RUNFREE_PROXY_IP: "172.30.0.10",
        RUNFREE_PROXY_IMAGE: "runfree/proxy:sha256-proxy",
        RUNFREE_PROXY_EGRESS_IP: "172.30.1.10",
        RUNFREE_PROJECT_ROOT: "/project",
        RUNFREE_PROJECT_ID: "0123456789ab",
        RUNFREE_AGENT_IMAGE: "runfree/agent:sha256-agent",
      },
      controlPlane: {
        structure: { networks: ["agent_internal", "proxy_egress"], services: ["proxy"] },
        runtimeSignatures: { firewall: { contract: 1 } },
      },
    }));

    expect(second).toEqual(first);
  });

  test("keeps control-plane and session-template changes in their own projections", () => {
    const baseline = runtimeTopologyGenerationV2(input());
    const sessionValue = runtimeTopologyGenerationV2(input({
      interpolationValues: { ...input().interpolationValues, RUNFREE_PROJECT_ROOT: "/other-project" },
    }));
    expect(sessionValue.controlPlaneTopologyDigest).toBe(baseline.controlPlaneTopologyDigest);
    expect(sessionValue.sessionTemplateDigest).not.toBe(baseline.sessionTemplateDigest);
    expect(sessionValue.topologyDigest).not.toBe(baseline.topologyDigest);

    const controlValue = runtimeTopologyGenerationV2(input({
      interpolationValues: { ...input().interpolationValues, RUNFREE_PROXY_EGRESS_IP: "172.30.1.20" },
    }));
    expect(controlValue.controlPlaneTopologyDigest).not.toBe(baseline.controlPlaneTopologyDigest);
    expect(controlValue.sessionTemplateDigest).toBe(baseline.sessionTemplateDigest);
    expect(controlValue.topologyDigest).not.toBe(baseline.topologyDigest);
  });

  test("binds shared topology inputs into both projections", () => {
    const baseline = runtimeTopologyGenerationV2(input());
    const changed = runtimeTopologyGenerationV2(input({
      interpolationValues: { ...input().interpolationValues, RUNFREE_PROJECT_ID: "fedcba987654" },
    }));

    expect(changed.controlPlaneTopologyDigest).not.toBe(baseline.controlPlaneTopologyDigest);
    expect(changed.sessionTemplateDigest).not.toBe(baseline.sessionTemplateDigest);
  });

  test("binds the legacy agent address into both projections until bridge drain", () => {
    const baselineInput = input({
      compose: `${input().compose}\n    legacy-agent-ip: \${RUNFREE_CONTAINER_IP}`,
      interpolationValues: {
        ...input().interpolationValues,
        RUNFREE_CONTAINER_IP: "172.30.0.11",
      },
    });
    const baseline = runtimeTopologyGenerationV2(baselineInput);
    const changed = runtimeTopologyGenerationV2({
      ...baselineInput,
      interpolationValues: {
        ...baselineInput.interpolationValues,
        RUNFREE_CONTAINER_IP: "172.30.0.21",
      },
    });

    expect(changed.controlPlaneTopologyDigest).not.toBe(baseline.controlPlaneTopologyDigest);
    expect(changed.sessionTemplateDigest).not.toBe(baseline.sessionTemplateDigest);
  });

  test.each([
    ["proxy listener", "RUNFREE_PROXY_IP", "172.30.0.20"],
    ["internal subnet", "RUNFREE_SUBNET", "172.30.20.0/24"],
  ])("binds the shared session-network %s into both projections", (_label, name, changedValue) => {
    const baselineInput = input({
      compose: `${input().compose}\n    network-contract: \${${name}}`,
      interpolationValues: { ...input().interpolationValues, [name]: name === "RUNFREE_SUBNET" ? "172.30.0.0/24" : "172.30.0.10" },
    });
    const baseline = runtimeTopologyGenerationV2(baselineInput);
    const changed = runtimeTopologyGenerationV2({
      ...baselineInput,
      interpolationValues: { ...baselineInput.interpolationValues, [name]: changedValue },
    });

    expect(changed.controlPlaneTopologyDigest).not.toBe(baseline.controlPlaneTopologyDigest);
    expect(changed.sessionTemplateDigest).not.toBe(baseline.sessionTemplateDigest);
  });

  test("keeps image identity and diagnostic version outside topology projections", () => {
    const baseline = runtimeTopologyGenerationV2(input());
    const changed = runtimeTopologyGenerationV2(input({
      interpolationValues: {
        ...input().interpolationValues,
        RUNFREE_AGENT_IMAGE: "runfree/agent:sha256-other",
        RUNFREE_PROXY_IMAGE: "runfree/proxy:sha256-other",
        RUNFREE_VERSION: "9.9.9",
      },
    }));

    expect(changed).toEqual(baseline);
  });

  test("binds explicit structural and runtime-signature changes", () => {
    const baseline = runtimeTopologyGenerationV2(input());
    const control = runtimeTopologyGenerationV2(input({
      controlPlane: {
        ...input().controlPlane,
        structure: { services: ["proxy", "mcp-callback"] },
      },
    }));
    expect(control.controlPlaneTopologyDigest).not.toBe(baseline.controlPlaneTopologyDigest);
    expect(control.sessionTemplateDigest).toBe(baseline.sessionTemplateDigest);

    const session = runtimeTopologyGenerationV2(input({
      sessionTemplate: {
        ...input().sessionTemplate,
        runtimeSignatures: { mountPolicy: { contract: 2 } },
      },
    }));
    expect(session.controlPlaneTopologyDigest).toBe(baseline.controlPlaneTopologyDigest);
    expect(session.sessionTemplateDigest).not.toBe(baseline.sessionTemplateDigest);
  });

  test("fails closed for unclassified, valueless, and non-JSON projection inputs", () => {
    expect(() => runtimeTopologyGenerationV2(input({
      compose: `${input().compose}\n    user: \${RUNFREE_UNCLASSIFIED_USER}`,
    }))).toThrow("has no v2 projection");
    expect(() => runtimeTopologyGenerationV2(input({
      interpolationValues: { RUNFREE_PROXY_IP: "172.30.0.10" },
    }))).toThrow("has no normalized v2 value");
    expect(() => runtimeTopologyGenerationV2(input({
      controlPlane: {
        ...input().controlPlane,
        runtimeSignatures: { invalid: Number.NaN },
      },
    }))).toThrow("finite numbers");
  });

  test("classifies every interpolation in the canonical Compose render", () => {
    const compose = canonicalRenderedCompose();
    const variables = composeInterpolationVariables(compose);

    // Post-cutover the render carries no Compose MCP callback relay sidecar;
    // the callback is a per-session ingress forwarder outside the generation.
    expect(compose.includes("  mcp_callback:")).toBe(false);
    expect(variables.includes("RUNFREE_CALLBACK_RELAY_IP")).toBe(false);
    expect(variables.every((name) => Object.hasOwn(RUNTIME_COMPOSE_INTERPOLATION_PROJECTIONS_V2, name))).toBe(true);
    expect(() => runtimeTopologyGenerationV2({
      compose,
      interpolationValues: Object.fromEntries(variables.map((name) => [name, `value:${name}`])),
      controlPlane: { structure: compose, runtimeSignatures: {} },
      sessionTemplate: { structure: compose, runtimeSignatures: {} },
    })).not.toThrow();
  });
});
