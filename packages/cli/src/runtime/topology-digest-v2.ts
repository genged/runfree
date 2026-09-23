

import {
  composeInterpolationVariables,
  type TopologyDigestJson,
} from "./topology-digest.ts";
import {
  createRuntimeTopologyGenerationV2,
  type RuntimeTopologyGenerationV2,
} from "./component-state-v2.ts";
import { strictStableJson, sha256Digest as sha256 } from "../strict-primitives.ts";

export type ComposeInterpolationProjectionV2 =
  | "agent-image-input"
  | "proxy-image-input"
  | "control-plane-topology-input"
  | "session-template-input"
  | "shared-topology-input"
  | "informational";

export type RuntimeTopologyDigestInputV2 = {
  compose: string;
  interpolationValues: Readonly<Record<string, string | undefined>>;
  controlPlane: {
    structure: TopologyDigestJson;
    runtimeSignatures: Readonly<Record<string, TopologyDigestJson>>;
  };
  sessionTemplate: {
    structure: TopologyDigestJson;
    runtimeSignatures: Readonly<Record<string, TopologyDigestJson>>;
  };
};

export type RuntimeTopologyProjectionArtifactV2 = Readonly<{
  schemaVersion: 2;
  projection: "control-plane" | "session-template";
  structure: TopologyDigestJson;
  interpolationInputs: TopologyDigestJson[];
  runtimeSignatures: Readonly<Record<string, TopologyDigestJson>>;
}>;

const INTERPOLATION_PROJECTIONS = new Set<ComposeInterpolationProjectionV2>([
  "agent-image-input",
  "proxy-image-input",
  "control-plane-topology-input",
  "session-template-input",
  "shared-topology-input",
  "informational",
]);

// This is the schema-v2 lifecycle owner for every value the current canonical
// Compose renderer can emit. The structural projection is supplied separately:
// interpolation ownership alone cannot safely split one YAML document into a
// shared control plane and a dynamic session-container template.
export const RUNTIME_COMPOSE_INTERPOLATION_PROJECTIONS_V2 = Object.freeze({
  RUNFREE_AGENT_ENV_FILE: "informational",
  RUNFREE_AGENT_IMAGE: "agent-image-input",
  RUNFREE_AGENT_IMAGE_INPUT_DIGEST: "agent-image-input",
  RUNFREE_AGENT_STATE_CLAUDE_CONFIG_DIR: "session-template-input",
  RUNFREE_AGENT_STATE_CLAUDE_CONFIG_JSON: "session-template-input",
  RUNFREE_AGENT_STATE_CODEX_HOME: "session-template-input",
  RUNFREE_AGENT_STATE_PI_AGENT_DIR: "session-template-input",
  RUNFREE_CALLBACK_RELAY_IP: "control-plane-topology-input",
  RUNFREE_CLAUDE_MCP_CONFIG_HOST_PATH: "session-template-input",
  RUNFREE_COMPOSE_PROJECT_NAME: "shared-topology-input",
  // Shared until the request-only legacy bridge drains: the proxy consumes
  // this fixed address as the legacy principal while new session templates
  // also reserve it out of the dynamic pool.
  RUNFREE_CONTAINER_IP: "shared-topology-input",
  RUNFREE_DIGEST_SCHEMA: "informational",
  RUNFREE_EFFECTIVE_PROXY_DIR: "control-plane-topology-input",
  RUNFREE_GIT_COMMON_DIR: "session-template-input",
  RUNFREE_GIT_CONFIG: "session-template-input",
  RUNFREE_INBOX_DIR: "session-template-input",
  RUNFREE_MCP_OPERATION_POLICY_HOST_PATH: "control-plane-topology-input",
  RUNFREE_PROJECT_COMPAT_ROOT: "session-template-input",
  RUNFREE_PROJECT_CONTAINER_ROOT: "session-template-input",
  RUNFREE_PROJECT_ID: "shared-topology-input",
  RUNFREE_PROJECT_NAME: "session-template-input",
  RUNFREE_PROJECT_PHYSICAL_ROOT: "session-template-input",
  RUNFREE_PROJECT_ROOT: "session-template-input",
  RUNFREE_PROXY_CA_CERT_DIR: "shared-topology-input",
  RUNFREE_PROXY_CA_KEY_DIR: "control-plane-topology-input",
  RUNFREE_PROXY_EGRESS_GATEWAY: "control-plane-topology-input",
  RUNFREE_PROXY_EGRESS_IP: "control-plane-topology-input",
  RUNFREE_PROXY_EGRESS_SUBNET: "control-plane-topology-input",
  RUNFREE_PROXY_IMAGE: "proxy-image-input",
  RUNFREE_PROXY_IMAGE_INPUT_DIGEST: "proxy-image-input",
  // The proxy listener address is both control-plane shape and an agent-visible
  // routing value in the session environment projection.
  RUNFREE_PROXY_IP: "shared-topology-input",
  RUNFREE_RUNTIME_DIGEST: "informational",
  RUNFREE_RUNTIME_GENERATION_DIGEST: "informational",
  // Sessions are created stopped on this exact internal network; activation
  // follows stopped-shape and provisioning/live proof.
  RUNFREE_SUBNET: "shared-topology-input",
  RUNFREE_TOPOLOGY_DIGEST: "informational",
  RUNFREE_VERSION: "informational",
  RUNFREE_WRITE_APPROVAL_HOLD_SECONDS: "control-plane-topology-input",
} as const satisfies Readonly<Record<string, ComposeInterpolationProjectionV2>>);

function stableJson(value: TopologyDigestJson): string {
  return strictStableJson(value, "runtime topology v2 inputs must contain finite numbers");
}


function projectionInputs(
  input: RuntimeTopologyDigestInputV2,
  projection: "control-plane" | "session-template",
): TopologyDigestJson[] {
  return composeInterpolationVariables(input.compose).flatMap((name): TopologyDigestJson[] => {
    const classification: ComposeInterpolationProjectionV2 | undefined =
      RUNTIME_COMPOSE_INTERPOLATION_PROJECTIONS_V2[
        name as keyof typeof RUNTIME_COMPOSE_INTERPOLATION_PROJECTIONS_V2
      ];
    if (!INTERPOLATION_PROJECTIONS.has(classification)) {
      throw new Error(`runtime Compose interpolation variable has no v2 projection: ${name}`);
    }
    if (!Object.hasOwn(input.interpolationValues, name)) {
      throw new Error(`runtime Compose interpolation variable has no normalized v2 value: ${name}`);
    }
    const owned = classification === "shared-topology-input"
      || (projection === "control-plane" && classification === "control-plane-topology-input")
      || (projection === "session-template" && classification === "session-template-input");
    return owned ? [[name, classification, input.interpolationValues[name] ?? null]] : [];
  });
}

export function createRuntimeTopologyProjectionArtifactV2(
  input: RuntimeTopologyDigestInputV2,
  projection: "control-plane" | "session-template",
): RuntimeTopologyProjectionArtifactV2 {
  const details = projection === "control-plane" ? input.controlPlane : input.sessionTemplate;
  return Object.freeze({
    schemaVersion: 2,
    projection,
    structure: details.structure,
    interpolationInputs: projectionInputs(input, projection),
    runtimeSignatures: details.runtimeSignatures,
  });
}

export function runtimeTopologyProjectionArtifactDigestV2(
  artifact: RuntimeTopologyProjectionArtifactV2,
): string {
  return sha256(stableJson(artifact as unknown as TopologyDigestJson));
}

function projectionDigest(
  input: RuntimeTopologyDigestInputV2,
  projection: "control-plane" | "session-template",
): string {
  return runtimeTopologyProjectionArtifactDigestV2(
    createRuntimeTopologyProjectionArtifactV2(input, projection),
  );
}

export function runtimeTopologyGenerationV2(
  input: RuntimeTopologyDigestInputV2,
): RuntimeTopologyGenerationV2 {
  return createRuntimeTopologyGenerationV2({
    controlPlaneTopologyDigest: projectionDigest(input, "control-plane"),
    sessionTemplateDigest: projectionDigest(input, "session-template"),
  });
}
