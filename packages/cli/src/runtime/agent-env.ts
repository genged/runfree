import { composeAgentEnvironment } from "../agents.ts";
import { RUNFREE_RUNTIME_TARGETS } from "./mount-target-policy.ts";
import {
  RUNFREE_PLACEHOLDER_VALUE,
  SERVICES,
} from "../../../../scripts/services.ts";
import { dependencyStoreEnvironmentNames } from "./dependency-stores.ts";

export const BASE_AGENT_ENVIRONMENT = {
  SHELL: "/usr/bin/zsh",
  TERM: "xterm-256color",
  COLORTERM: "truecolor",
  RUNFREE_CONTAINER: "1",
  // The session entry's wait bound (activation-gate design D4). Host-rendered
  // into the pinned session environment so it is proven by inspection and
  // cannot be set from project agent.env (RUNFREE_ names are runtime-owned).
  // Must exceed the worst-case activation budget: registration and activation
  // acknowledgement waits plus the running-proof maximum.
  RUNFREE_SESSION_ENTRY_TIMEOUT_MS: "60000",
  RUNFREE_CLAUDE_MCP_CONFIG: RUNFREE_RUNTIME_TARGETS.claudeMcpConfig,
  RUNFREE_INBOX_CONTAINER_DIR: RUNFREE_RUNTIME_TARGETS.inbox,
  RUNFREE_PROJECT_NAME: "${RUNFREE_PROJECT_NAME:-project}",
  RUNFREE_PROJECT_CONTAINER_ROOT: "${RUNFREE_PROJECT_CONTAINER_ROOT:-/workspaces/project}",
  RUNFREE_PROJECT_COMPAT_ROOT: "${RUNFREE_PROJECT_COMPAT_ROOT:-/workspace}",
  RUNFREE_PROJECT_PHYSICAL_ROOT: "${RUNFREE_PROJECT_PHYSICAL_ROOT:-/workspace}",
  PROXY_IP: "${RUNFREE_PROXY_IP:-172.30.0.10}",
  HTTPS_PROXY: "http://${RUNFREE_PROXY_IP:-172.30.0.10}:8080",
  HTTP_PROXY: "http://${RUNFREE_PROXY_IP:-172.30.0.10}:8080",
  https_proxy: "http://${RUNFREE_PROXY_IP:-172.30.0.10}:8080",
  http_proxy: "http://${RUNFREE_PROXY_IP:-172.30.0.10}:8080",
  ALL_PROXY: "http://${RUNFREE_PROXY_IP:-172.30.0.10}:8080",
  all_proxy: "http://${RUNFREE_PROXY_IP:-172.30.0.10}:8080",
  NO_PROXY: "localhost,127.0.0.1",
  no_proxy: "localhost,127.0.0.1",
  // NODE_EXTRA_CA_CERTS is additive on top of Node's built-in roots, so the
  // proxy CA alone is complete for it. Every *file-based* trust variable below
  // points at the host-rendered combined bundle (system roots + proxy CA,
  // cutover decision D-4): the old values either lacked real roots for
  // audit-mode passthrough TLS (proxy-ca.crt alone) or lacked the proxy CA in
  // session containers, which never run the legacy root trust-store exec
  // (/etc/ssl/certs/ca-certificates.crt before update-ca-certificates).
  NODE_EXTRA_CA_CERTS: "/etc/proxy-ca/proxy-ca.crt",
  NODE_USE_ENV_PROXY: "1",
  GIT_SSL_CAINFO: "/etc/proxy-ca/ca-bundle.crt",
  // Command-scope defaults outrank repository includes and config.worktree,
  // including includes that match only the container's /workspace path.
  // This prevents accidental absolute links; explicit git -c/flags can override.
  GIT_CONFIG_COUNT: "1",
  GIT_CONFIG_KEY_0: "worktree.useRelativePaths",
  GIT_CONFIG_VALUE_0: "true",
  CURL_CA_BUNDLE: "/etc/proxy-ca/ca-bundle.crt",
  UV_SYSTEM_CERTS: "1",
  SSL_CERT_FILE: "/etc/proxy-ca/ca-bundle.crt",
  REQUESTS_CA_BUNDLE: "/etc/proxy-ca/ca-bundle.crt",
} as const;

export const DEFAULT_AGENT_PLACEHOLDER_ENVIRONMENT = {
  GH_TOKEN: RUNFREE_PLACEHOLDER_VALUE,
  GITHUB_TOKEN: RUNFREE_PLACEHOLDER_VALUE,
} as const;

const ATTACH_SESSION_ENV_NAMES = [
  "RUNFREE_AGENT_COMMAND",
  "RUNFREE_RESUME_COMMAND",
  "RUNFREE_RESUME_SESSION",
  "RUNFREE_TERMINAL_TITLE",
  "RUNFREE_SESSION_ID",
  "RUNFREE_SESSION_COMMAND",
  "RUNFREE_SESSION_AGENT_COMMAND",
  "RUNFREE_SESSION_STARTED_AT",
] as const;

const RUNTIME_CONTEXT_ENV_NAMES = [
  "RUNFREE_GIT_COMMON_DIR",
  "RUNFREE_GIT_LAYOUT_KIND",
  "RUNFREE_INBOX_CONTAINER_DIR",
  "RUNFREE_INBOX_DIR",
] as const;

const DOCKER_EXEC_OVERRIDE_ENV_NAMES = ["HOME", "SHELL"] as const;

// Minimal structural view of a service's agent-visible env; SERVICES (the
// default argument below) satisfies it, which is what enforces assignability.
type ServiceEnvDescriptor = {
  credential?: { agentEnv: string[] };
  oauthCredential?: {
    seeds: Array<{ field: "refresh_token" | "client_secret"; envVar: string }>;
  };
  parameters?: Array<{ envVar: string }>;
};

// Agent env names whose value is visible to the agent as written: OAuth seed
// handles (validated as handles) and declared non-secret service parameters.
export type ServiceOAuthVisibleAgentEnvKind = "refresh_token" | "client_secret" | "parameter";

function oauthAgentEnvironmentValue(kind: ServiceOAuthVisibleAgentEnvKind, value: string): string {
  if (kind === "parameter") return value;
  const prefix = kind === "refresh_token" ? "runfree_oauth_refresh_" : "runfree_oauth_secret_";
  return new RegExp(`^${prefix}[A-Za-z0-9_-]{32,}$`).test(value) ? value : RUNFREE_PLACEHOLDER_VALUE;
}

export function completeAgentEnvironment(extraEnv: Record<string, string> = {}): Record<string, string> {
  return {
    ...BASE_AGENT_ENVIRONMENT,
    ...extraEnv,
    ...DEFAULT_AGENT_PLACEHOLDER_ENVIRONMENT,
  };
}

export function serviceAgentEnvNames(
  services: Record<string, ServiceEnvDescriptor> = SERVICES,
): string[] {
  return Array.from(new Set([
    ...Object.values(services).flatMap((svc) => svc.credential?.agentEnv ?? []),
    ...Object.keys(DEFAULT_AGENT_PLACEHOLDER_ENVIRONMENT),
  ])).sort();
}

export function serviceOAuthVisibleAgentEnvKinds(
  services: Record<string, ServiceEnvDescriptor> = SERVICES,
): Record<string, ServiceOAuthVisibleAgentEnvKind> {
  const entries: Array<[string, ServiceOAuthVisibleAgentEnvKind]> = [];
  for (const svc of Object.values(services)) {
    for (const seed of svc.oauthCredential?.seeds ?? []) entries.push([seed.envVar, seed.field]);
    for (const parameter of svc.parameters ?? []) entries.push([parameter.envVar, "parameter"]);
  }
  return Object.fromEntries(entries.sort(([left], [right]) => left.localeCompare(right)));
}

export function runtimeOwnedAgentEnvNames(): string[] {
  return Array.from(new Set([
    ...Object.keys(BASE_AGENT_ENVIRONMENT),
    ...Object.keys(DEFAULT_AGENT_PLACEHOLDER_ENVIRONMENT),
    ...Object.keys(composeAgentEnvironment()),
    ...dependencyStoreEnvironmentNames(),
    ...ATTACH_SESSION_ENV_NAMES,
    ...RUNTIME_CONTEXT_ENV_NAMES,
    ...DOCKER_EXEC_OVERRIDE_ENV_NAMES,
  ])).sort();
}

export function projectAgentEnvironmentOverrides(
  source: string,
  displayPath: string,
  options: {
    // Env names declared as parameters by the selected effective generation's
    // approved services (user-defined services are not in SERVICES). Their
    // recorded values pass through like curated parameters; a runtime-owned
    // name is still dropped.
    declaredParameterEnvNames?: Iterable<string>;
  } = {},
): Record<string, string> {
  const servicePlaceholders = new Set(serviceAgentEnvNames());
  const oauthVisibleKinds = serviceOAuthVisibleAgentEnvKinds();
  const runtimeOwned = new Set(runtimeOwnedAgentEnvNames());
  const declaredParameters = new Set(options.declaredParameterEnvNames ?? []);
  const entries = new Map<string, string>();
  for (const line of source.split(/\r?\n/)) {
    if (line.trim() === "" || line.trimStart().startsWith("#")) continue;
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!match) throw new Error(`invalid agent env line in ${displayPath}: ${line}`);
    const [_, name, value] = match;
    if (entries.has(name)) throw new Error(`duplicate agent env name in ${displayPath}: ${name}`);
    if (/[\u0000-\u001f\u007f-\u009f]/u.test(value)) {
      throw new Error(`invalid agent env value in ${displayPath}: ${name}`);
    }
    const oauthKind = oauthVisibleKinds[name];
    if (oauthKind !== undefined) {
      entries.set(name, oauthAgentEnvironmentValue(oauthKind, value));
      continue;
    }
    if (declaredParameters.has(name) && !runtimeOwned.has(name)) {
      entries.set(name, value);
      continue;
    }
    if (servicePlaceholders.has(name)) {
      entries.set(name, RUNFREE_PLACEHOLDER_VALUE);
      continue;
    }
    if (runtimeOwned.has(name)) continue;
    entries.set(name, RUNFREE_PLACEHOLDER_VALUE);
  }
  return Object.fromEntries([...entries].sort(([left], [right]) => left.localeCompare(right)));
}

export function assertServiceAgentEnvNamesAreSafe(
  services: Record<string, ServiceEnvDescriptor> = SERVICES,
): void {
  const runtimeOwned = new Set(runtimeOwnedAgentEnvNames());
  const defaultPlaceholders = new Set(Object.keys(DEFAULT_AGENT_PLACEHOLDER_ENVIRONMENT));
  for (const [serviceName, svc] of Object.entries(services)) {
    for (const name of svc.credential?.agentEnv ?? []) {
      if (defaultPlaceholders.has(name)) continue;
      if (runtimeOwned.has(name)) {
        throw new Error(`service ${serviceName} agent env ${name} collides with runtime-owned agent env`);
      }
    }
    for (const seed of svc.oauthCredential?.seeds ?? []) {
      if (runtimeOwned.has(seed.envVar)) {
        throw new Error(`service ${serviceName} OAuth agent env ${seed.envVar} collides with runtime-owned agent env`);
      }
    }
    for (const parameter of svc.parameters ?? []) {
      if (runtimeOwned.has(parameter.envVar)) {
        throw new Error(`service ${serviceName} parameter env ${parameter.envVar} collides with runtime-owned agent env`);
      }
    }
  }
}

assertServiceAgentEnvNamesAreSafe();
