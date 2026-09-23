import fs from "node:fs";
import path from "node:path";

import { describe, expect, test } from "vitest";

import { composeAgentStateMounts } from "../agents.ts";
import { inboxMount } from "../inbox.ts";
import { renderRuntimeCompose } from "./compose.ts";
import {
  composeInterpolationVariables,
  RUNTIME_COMPOSE_INTERPOLATION_CLASSES,
  runtimeTopologyDigest,
  type RuntimeTopologyDigestInput,
} from "./topology-digest.ts";

const CANONICAL_COMPOSE = fs.readFileSync(path.resolve("packages/agent-runtime/agent/compose.yaml"), "utf8");

function canonicalRenderedCompose(): string {
  return renderRuntimeCompose(CANONICAL_COMPOSE, {
    agentStateMounts: composeAgentStateMounts(),
    agentVolumes: [inboxMount()],
  });
}

function interpolationValues(compose: string): Record<string, string> {
  return Object.fromEntries(composeInterpolationVariables(compose).map((name) => [name, `value:${name}`]));
}

function input(overrides: Partial<RuntimeTopologyDigestInput> = {}): RuntimeTopologyDigestInput {
  return {
    compose: [
      "services:",
      "  agent:",
      "    image: ${RUNFREE_AGENT_IMAGE:?required}",
      "    networks:",
      "      internal:",
      "        ipv4_address: ${RUNFREE_CONTAINER_IP:-172.30.0.11}",
      "    labels:",
      "      io.runfree.version: ${RUNFREE_VERSION}",
      "  proxy:",
      "    image: ${RUNFREE_PROXY_IMAGE:?required}",
    ].join("\n"),
    interpolationValues: {
      RUNFREE_AGENT_IMAGE: "runfree/agent:sha256-agent",
      RUNFREE_CONTAINER_IP: "172.30.0.11",
      RUNFREE_PROXY_IMAGE: "runfree/proxy:sha256-proxy",
      RUNFREE_VERSION: "1.0.0",
    },
    runtimeSignatures: {
      dependencyOverlays: { mounts: [], version: 1 },
      gitLayout: { kind: "workspace", version: 1 },
    },
    ...overrides,
  };
}

describe("runtime topology digest", () => {
  test("is deterministic and insensitive to input object key ordering", () => {
    const first = runtimeTopologyDigest(input());
    const second = runtimeTopologyDigest(input({
      interpolationValues: {
        RUNFREE_VERSION: "1.0.0",
        RUNFREE_PROXY_IMAGE: "runfree/proxy:sha256-proxy",
        RUNFREE_CONTAINER_IP: "172.30.0.11",
        RUNFREE_AGENT_IMAGE: "runfree/agent:sha256-agent",
      },
      runtimeSignatures: {
        gitLayout: { version: 1, kind: "workspace" },
        dependencyOverlays: { version: 1, mounts: [] },
      },
    }));

    expect(first).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(second).toBe(first);
  });

  test("changes for rendered Compose, topology values, and runtime signatures", () => {
    const baseline = runtimeTopologyDigest(input());

    expect(runtimeTopologyDigest(input({ compose: `${input().compose}\n    read_only: true` }))).not.toBe(baseline);
    expect(runtimeTopologyDigest(input({
      interpolationValues: { ...input().interpolationValues, RUNFREE_CONTAINER_IP: "172.30.0.12" },
    }))).not.toBe(baseline);
    expect(runtimeTopologyDigest(input({
      runtimeSignatures: {
        ...input().runtimeSignatures,
        dependencyOverlays: { mounts: [{ source: "deps", target: "/workspace/node_modules" }], version: 1 },
      },
    }))).not.toBe(baseline);
  });

  test("excludes image references and informational values", () => {
    const baseline = runtimeTopologyDigest(input());
    const changed = runtimeTopologyDigest(input({
      interpolationValues: {
        ...input().interpolationValues,
        RUNFREE_AGENT_IMAGE: "runfree/agent:sha256-new",
        RUNFREE_PROXY_IMAGE: "runfree/proxy:sha256-new",
        RUNFREE_VERSION: "2.0.0",
      },
    }));

    expect(changed).toBe(baseline);
  });

  test("does not recreate a runtime when the selected effective agent env generation rotates", () => {
    const compose = `${input().compose}\n    env_file: \${RUNFREE_AGENT_ENV_FILE:?required}`;
    const baseline = runtimeTopologyDigest(input({
      compose,
      interpolationValues: {
        ...input().interpolationValues,
        RUNFREE_AGENT_ENV_FILE: "/state/control/effective/generations/old/agent/agent.env",
      },
    }));

    expect(runtimeTopologyDigest(input({
      compose,
      interpolationValues: {
        ...input().interpolationValues,
        RUNFREE_AGENT_ENV_FILE: "/state/control/effective/generations/new/agent/agent.env",
      },
    }))).toBe(baseline);
  });

  test("extracts nested and unbraced variables while ignoring escaped dollars", () => {
    expect(composeInterpolationVariables([
      "value: ${PRIMARY:-${FALLBACK}}",
      "other: $UNBRACED",
      "literal: $${NOT_INTERPOLATED}",
    ].join("\n"))).toEqual(["FALLBACK", "PRIMARY", "UNBRACED"]);
  });

  test("classifies every interpolation in the canonical Compose render", () => {
    const compose = canonicalRenderedCompose();
    const variables = composeInterpolationVariables(compose);

    expect(variables.length).toBeGreaterThan(0);
    // Post-cutover the render carries no Compose MCP callback relay sidecar;
    // the callback is a per-session ingress forwarder outside the generation.
    expect(compose.includes("  mcp_callback:")).toBe(false);
    expect(variables.includes("RUNFREE_CALLBACK_RELAY_IP")).toBe(false);
    expect(variables.every((name) => Object.hasOwn(RUNTIME_COMPOSE_INTERPOLATION_CLASSES, name))).toBe(true);
    expect(() => runtimeTopologyDigest({
      compose,
      interpolationValues: interpolationValues(compose),
      runtimeSignatures: {},
    })).not.toThrow();
  });

  test("assigns image and digest-label interpolation to non-topology owners", () => {
    expect(RUNTIME_COMPOSE_INTERPOLATION_CLASSES).toMatchObject({
      RUNFREE_AGENT_IMAGE: "agent-image-input",
      RUNFREE_PROXY_IMAGE: "proxy-image-input",
      RUNFREE_AGENT_IMAGE_INPUT_DIGEST: "agent-image-input",
      RUNFREE_PROXY_IMAGE_INPUT_DIGEST: "proxy-image-input",
      RUNFREE_AGENT_ENV_FILE: "informational",
      RUNFREE_RUNTIME_GENERATION_DIGEST: "informational",
      RUNFREE_TOPOLOGY_DIGEST: "informational",
      RUNFREE_VERSION: "informational",
    });
  });

  test("fails closed for unclassified, valueless, malformed, and non-JSON inputs", () => {
    expect(() => runtimeTopologyDigest(input({
      compose: `${input().compose}\n    user: \${RUNFREE_AGENT_USER}`,
    }))).toThrow("runtime Compose interpolation variable is unclassified: RUNFREE_AGENT_USER");
    expect(() => runtimeTopologyDigest(input({
      interpolationValues: { RUNFREE_CONTAINER_IP: "172.30.0.11" },
    }))).toThrow("runtime Compose interpolation variable has no normalized value: RUNFREE_AGENT_IMAGE");
    expect(() => runtimeTopologyDigest(input({ compose: "services: ${BROKEN" }))).toThrow("missing a closing brace");
    expect(() => runtimeTopologyDigest(input({
      runtimeSignatures: { callbackPort: Number.NaN },
    }))).toThrow("must contain finite numbers");
  });
});
