
import { strictStableJson, sha256Digest } from "../strict-primitives.ts";

export const RUNTIME_TOPOLOGY_DIGEST_SCHEMA_VERSION = 1 as const;

export type ComposeInterpolationClass =
  | "agent-image-input"
  | "proxy-image-input"
  | "topology-input"
  | "informational";

export type TopologyDigestJson =
  | boolean
  | null
  | number
  | string
  | TopologyDigestJson[]
  | { [key: string]: TopologyDigestJson };

export type RuntimeTopologyDigestInput = {
  compose: string;
  interpolationValues: Readonly<Record<string, string | undefined>>;
  runtimeSignatures: Readonly<Record<string, TopologyDigestJson>>;
};

const INTERPOLATION_CLASSES = new Set<ComposeInterpolationClass>([
  "agent-image-input",
  "proxy-image-input",
  "topology-input",
  "informational",
]);

// Central lifecycle ownership for every interpolation variable that the
// canonical renderer can emit. Keep digest label values informational: image
// identity is tracked by its own component and the topology/generation values
// would otherwise introduce a hash cycle.
export const RUNTIME_COMPOSE_INTERPOLATION_CLASSES = Object.freeze({
  // The selected host-owned generation is overlaid into every attached agent
  // session. Rotating this immutable path must not recreate an otherwise
  // validated runtime; the next cold container creation still consumes it.
  RUNFREE_AGENT_ENV_FILE: "informational",
  RUNFREE_AGENT_IMAGE: "agent-image-input",
  RUNFREE_AGENT_IMAGE_INPUT_DIGEST: "agent-image-input",
  RUNFREE_AGENT_STATE_CLAUDE_CONFIG_DIR: "topology-input",
  RUNFREE_AGENT_STATE_CLAUDE_CONFIG_JSON: "topology-input",
  RUNFREE_AGENT_STATE_CODEX_HOME: "topology-input",
  RUNFREE_AGENT_STATE_PI_AGENT_DIR: "topology-input",
  RUNFREE_CALLBACK_RELAY_IP: "topology-input",
  RUNFREE_CLAUDE_MCP_CONFIG_HOST_PATH: "topology-input",
  RUNFREE_COMPOSE_PROJECT_NAME: "topology-input",
  RUNFREE_CONTAINER_IP: "topology-input",
  RUNFREE_DIGEST_SCHEMA: "informational",
  RUNFREE_GIT_COMMON_DIR: "topology-input",
  RUNFREE_GIT_CONFIG: "topology-input",
  RUNFREE_INBOX_DIR: "topology-input",
  RUNFREE_EFFECTIVE_PROXY_DIR: "topology-input",
  RUNFREE_MCP_OPERATION_POLICY_HOST_PATH: "topology-input",
  RUNFREE_PROJECT_COMPAT_ROOT: "topology-input",
  RUNFREE_PROJECT_CONTAINER_ROOT: "topology-input",
  RUNFREE_PROJECT_ID: "topology-input",
  RUNFREE_PROJECT_NAME: "topology-input",
  RUNFREE_PROJECT_PHYSICAL_ROOT: "topology-input",
  RUNFREE_PROJECT_ROOT: "topology-input",
  RUNFREE_PROXY_CA_CERT_DIR: "topology-input",
  RUNFREE_PROXY_CA_KEY_DIR: "topology-input",
  RUNFREE_PROXY_EGRESS_GATEWAY: "topology-input",
  RUNFREE_PROXY_EGRESS_IP: "topology-input",
  RUNFREE_PROXY_EGRESS_SUBNET: "topology-input",
  RUNFREE_PROXY_IMAGE: "proxy-image-input",
  RUNFREE_PROXY_IMAGE_INPUT_DIGEST: "proxy-image-input",
  RUNFREE_PROXY_IP: "topology-input",
  RUNFREE_RUNTIME_DIGEST: "informational",
  RUNFREE_RUNTIME_GENERATION_DIGEST: "informational",
  RUNFREE_SUBNET: "topology-input",
  RUNFREE_TOPOLOGY_DIGEST: "informational",
  RUNFREE_VERSION: "informational",
  RUNFREE_WRITE_APPROVAL_HOLD_SECONDS: "topology-input",
} as const satisfies Readonly<Record<string, ComposeInterpolationClass>>);

function interpolationEnd(source: string, start: number): number {
  let depth = 1;
  for (let index = start; index < source.length; index += 1) {
    if (source[index] === "$" && source[index + 1] === "$") {
      index += 1;
      continue;
    }
    if (source[index] === "$" && source[index + 1] === "{") {
      depth += 1;
      index += 1;
      continue;
    }
    if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  throw new Error("runtime Compose interpolation is missing a closing brace");
}

function collectInterpolationVariables(source: string, variables: Set<string>): void {
  for (let index = 0; index < source.length; index += 1) {
    if (source[index] !== "$") continue;
    if (source[index + 1] === "$") {
      index += 1;
      continue;
    }
    if (source[index + 1] === "{") {
      const end = interpolationEnd(source, index + 2);
      const expression = source.slice(index + 2, end);
      const nameMatch = /^([A-Za-z_][A-Za-z0-9_]*)(.*)$/s.exec(expression);
      if (!nameMatch || (nameMatch[2] !== "" && !/^(:?[-+?])/.test(nameMatch[2]))) {
        throw new Error(`invalid runtime Compose interpolation: \${${expression}}`);
      }
      variables.add(nameMatch[1]);
      collectInterpolationVariables(nameMatch[2], variables);
      index = end;
      continue;
    }
    const nameMatch = /^[A-Za-z_][A-Za-z0-9_]*/.exec(source.slice(index + 1));
    if (nameMatch) {
      variables.add(nameMatch[0]);
      index += nameMatch[0].length;
    }
  }
}

export function composeInterpolationVariables(compose: string): string[] {
  const variables = new Set<string>();
  collectInterpolationVariables(compose, variables);
  return [...variables].sort((left, right) => left.localeCompare(right));
}

function stableJson(value: TopologyDigestJson): string {
  return strictStableJson(value, "runtime topology digest inputs must contain finite numbers");
}

export function runtimeTopologyDigest(input: RuntimeTopologyDigestInput): string {
  const interpolationInputs: TopologyDigestJson[] = composeInterpolationVariables(input.compose).map((name) => {
    const classification: ComposeInterpolationClass | undefined =
      RUNTIME_COMPOSE_INTERPOLATION_CLASSES[name as keyof typeof RUNTIME_COMPOSE_INTERPOLATION_CLASSES];
    if (!INTERPOLATION_CLASSES.has(classification)) {
      throw new Error(`runtime Compose interpolation variable is unclassified: ${name}`);
    }
    if (!Object.hasOwn(input.interpolationValues, name)) {
      throw new Error(`runtime Compose interpolation variable has no normalized value: ${name}`);
    }
    return classification === "topology-input"
      ? [name, classification, input.interpolationValues[name] ?? null]
      : [name, classification];
  });
  const payload: TopologyDigestJson = {
    schemaVersion: RUNTIME_TOPOLOGY_DIGEST_SCHEMA_VERSION,
    compose: input.compose,
    interpolationInputs,
    runtimeSignatures: input.runtimeSignatures,
  };
  return sha256Digest(stableJson(payload));
}
