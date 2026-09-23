import path from "node:path";

import { agentStateEnvironment } from "../agents.ts";
import { resolveDefaultAgentCommand, type ProjectInfo } from "../config.ts";
import { agentRuntimeImageTag, effectiveRuntimeDigest, proxyRuntimeImageTag } from "../agent-image.ts";
import { RUNFREE_VERSION } from "../embedded-assets.generated.ts";
import { readActiveControlSelection, verifyEffectivePolicyGeneration } from "../control/effective.ts";
import type { RuntimeGitLayoutPlan } from "./git-layout.ts";
import { inboxContainerDir } from "../inbox.ts";
import { mcpOAuthCallbackPort, mcpOAuthCallbackUrl } from "./mcp.ts";
import { networkFromSubnet, type RuntimeNetwork } from "../network.ts";
import { composeProjectName, projectHash, projectIdentity } from "../project-identity.ts";
import type { RuntimeComponentState } from "./component-state.ts";
export { composeProjectName, projectHash } from "../project-identity.ts";

export type RuntimeEnvironmentOptions = {
  gitLayout?: RuntimeGitLayoutPlan;
  runtimeDigest?: string;
  agentImage?: string;
  proxyImage?: string;
  components?: RuntimeComponentState;
};

const DOCKER_CLIENT_ENV_ALLOWLIST = [
  "PATH",
  "DOCKER_HOST",
  "DOCKER_CONTEXT",
  "DOCKER_CONFIG",
  "DOCKER_TLS_VERIFY",
  "DOCKER_CERT_PATH",
  "SSH_AUTH_SOCK",
] as const;

function mcpOperationPolicyPath(project: ProjectInfo): string {
  return project.paths.mcpOperationPolicyPath ?? path.join(project.paths.stateDir, "mcp-operation-policy.json");
}

function selectedAgentEnvironmentPath(project: ProjectInfo): string {
  const active = readActiveControlSelection(project);
  if (!active) throw new Error("selected effective controls are required before runtime environment generation");
  return verifyEffectivePolicyGeneration(project, active.controlGeneration).agentEnvPath;
}

export function dockerClientEnvironment(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = {
    DOCKER_CLI_HINTS: "false",
  };
  for (const name of DOCKER_CLIENT_ENV_ALLOWLIST) {
    const value = env[name];
    if (value !== undefined) result[name] = value;
  }
  if (env.RUNFREE_TEST_FAKE_DOCKER === "1") {
    for (const [name, value] of Object.entries(env)) {
      if (name.startsWith("FAKE_") && value !== undefined) result[name] = value;
    }
  }
  return result;
}

function generatedRunfreeEnvironment(
  projectRoot: string,
  project: ProjectInfo,
  runtimeRoot: string,
  network?: RuntimeNetwork,
  options: RuntimeEnvironmentOptions = {},
): NodeJS.ProcessEnv {
  const runtime = project.config.runtime ?? {};
  const runtimeOverrides: NodeJS.ProcessEnv = {};
  const runtimeNetwork = network ?? (
    runtime.subnet && runtime.proxyIp && runtime.agentIp
      ? { ...networkFromSubnet(runtime.subnet), proxyIp: runtime.proxyIp, agentIp: runtime.agentIp }
      : undefined
  );
  if (runtimeNetwork) {
    runtimeOverrides.RUNFREE_SUBNET = runtimeNetwork.subnet;
    runtimeOverrides.RUNFREE_PROXY_IP = runtimeNetwork.proxyIp;
    runtimeOverrides.RUNFREE_CONTAINER_IP = runtimeNetwork.agentIp;
    runtimeOverrides.RUNFREE_PROXY_EGRESS_SUBNET = runtimeNetwork.proxyEgressSubnet;
    runtimeOverrides.RUNFREE_PROXY_EGRESS_GATEWAY = runtimeNetwork.proxyEgressGateway;
    runtimeOverrides.RUNFREE_PROXY_EGRESS_IP = runtimeNetwork.proxyEgressIp;
  }

  const runtimeDigest = options.runtimeDigest ?? effectiveRuntimeDigest(projectRoot, project.config);
  const identity = projectIdentity(projectRoot, project.config);
  const gitLayout = options.gitLayout;
  const physicalRoot = gitLayout?.containerProjectRoot ?? identity.compatRoot;
  const compatRoot = gitLayout?.containerCompatRoot ?? identity.compatRoot;
  const gitLayoutEnvironment: NodeJS.ProcessEnv = gitLayout?.kind === "relative-linked"
    ? {
      RUNFREE_GIT_COMMON_DIR: gitLayout.hostGitCommonDir,
      RUNFREE_GIT_LAYOUT_KIND: gitLayout.kind,
    }
    : {
      RUNFREE_GIT_LAYOUT_KIND: "workspace",
    };

  return {
    RUNFREE_PROJECT_ROOT: projectRoot,
    RUNFREE_PROJECT_ID: projectHash(projectRoot),
    RUNFREE_PROJECT_NAME: identity.name,
    RUNFREE_PROJECT_CONTAINER_ROOT: identity.containerRoot,
    RUNFREE_PROJECT_COMPAT_ROOT: compatRoot,
    RUNFREE_PROJECT_PHYSICAL_ROOT: physicalRoot,
    RUNFREE_INBOX_DIR: project.paths.inboxDir,
    RUNFREE_INBOX_CONTAINER_DIR: inboxContainerDir(),
    RUNFREE_AGENT_ENV_FILE: selectedAgentEnvironmentPath(project),
    RUNFREE_EFFECTIVE_PROXY_DIR: project.paths.controlProxyDir,
    RUNFREE_MCP_OAUTH_CALLBACK_PORT: String(mcpOAuthCallbackPort(projectRoot)),
    RUNFREE_MCP_OAUTH_CALLBACK_URL: mcpOAuthCallbackUrl(projectRoot),
    RUNFREE_MCP_OPERATION_POLICY_HOST_PATH: mcpOperationPolicyPath(project),
    RUNFREE_AGENT_COMMAND: resolveDefaultAgentCommand(project.config)
      ?? "claude --dangerously-skip-permissions --add-dir /runfree/inbox",
    RUNFREE_AGENT_IMAGE: options.agentImage ?? agentRuntimeImageTag(),
    RUNFREE_PROXY_IMAGE: options.proxyImage ?? proxyRuntimeImageTag(),
    ...agentStateEnvironment(project),
    RUNFREE_CLAUDE_DIR: project.paths.claudeDir,
    RUNFREE_CLAUDE_JSON: project.paths.claudeConfigPath,
    RUNFREE_CLAUDE_MCP_CONFIG_HOST_PATH: project.paths.claudeMcpConfigPath,
    RUNFREE_CODEX_HOME: project.paths.codexDir,
    RUNFREE_GIT_CONFIG: project.paths.gitConfigPath,
    RUNFREE_PROXY_CA_CERT_DIR: project.paths.proxyCaCertDir,
    RUNFREE_PROXY_CA_KEY_DIR: project.paths.proxyCaKeyDir,
    RUNFREE_PACKAGE_ROOT: runtimeRoot,
    RUNFREE_RUNTIME_ROOT: runtimeRoot,
    RUNFREE_RUNTIME_DIGEST: runtimeDigest,
    ...(options.components ? {
      RUNFREE_AGENT_IMAGE_INPUT_DIGEST: options.components.selectedAgentImageInputDigest,
      RUNFREE_PROXY_IMAGE_INPUT_DIGEST: options.components.proxyImageInputDigest,
      RUNFREE_TOPOLOGY_DIGEST: options.components.topologyDigest,
      RUNFREE_RUNTIME_GENERATION_DIGEST: options.components.runtimeGenerationDigest,
    } : {}),
    RUNFREE_VERSION,
    RUNFREE_COMPOSE_PROJECT_NAME: composeProjectName(projectRoot),
    RUNFREE_STATE_DIR: project.paths.stateDir,
    // Host-resolved and validated (config.ts, 5-300s); the proxy never reads
    // runfree.json. Also folded into the runtime security-contract hash.
    RUNFREE_WRITE_APPROVAL_HOLD_SECONDS: String(runtime.writeApprovalHoldSeconds ?? 120),
    ...gitLayoutEnvironment,
    ...runtimeOverrides,
  };
}

export function composeRuntimeEnvironment(
  projectRoot: string,
  project: ProjectInfo,
  runtimeRoot: string,
  env: NodeJS.ProcessEnv = process.env,
  network?: RuntimeNetwork,
  options: RuntimeEnvironmentOptions = {},
): NodeJS.ProcessEnv {
  return {
    ...dockerClientEnvironment(env),
    ...generatedRunfreeEnvironment(projectRoot, project, runtimeRoot, network, options),
  };
}

export function runtimeEnvironment(
  projectRoot: string,
  project: ProjectInfo,
  runtimeRoot: string,
  env: NodeJS.ProcessEnv = process.env,
  network?: RuntimeNetwork,
  options: RuntimeEnvironmentOptions = {},
): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = {
    ...env,
    DOCKER_CLI_HINTS: "false",
    ...generatedRunfreeEnvironment(projectRoot, project, runtimeRoot, network, options),
  };
  delete result.RUNFREE_TOKEN_CONFIG_PATH;
  delete result.RUNFREE_SOURCE_CONFIG_PATH;
  delete result.RUNFREE_POLICY_DIR;
  delete result.RUNFREE_POLICY_FILE;
  delete result.RUNFREE_PROJECT_RUNFREE_DIR;
  delete result.RUNFREE_OAUTH_POLICY_HOST_PATH;
  delete result.RUNFREE_MCP_OAUTH_POLICY_HOST_PATH;
  return result;
}
