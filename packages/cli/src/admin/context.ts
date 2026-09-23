import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { projectHash, composeProjectName } from "../project-identity.ts";
import { runfreeConfigRoot } from "../paths.ts";
import { isPathInsideByRealpath } from "../safe-fs.ts";
import { dockerClientEnvironment } from "../runtime/env.ts";
import { CliError } from "../errors.ts";
import { projectRunfreePath } from "../runfree-consumer-registry.ts";
import type { AdminState } from "./types.ts";

const scriptPath = fileURLToPath(import.meta.url);

export type AdminContext = {
  agentEnvPath?: string;
  projectRoot?: string;
  packageRoot?: string;
  policyPath?: string;
  policyAccess?: AdminState["policyAccess"];
  effectiveControlSelected?: boolean;
  oauthPolicyPath?: string;
  tokenConfigPath?: string;
  sourceConfigPath?: string;
  stateDir?: string;
  env?: NodeJS.ProcessEnv;
  processRunner?: AdminState["processRunner"];
  runtimeContext?: AdminState["runtimeContext"];
  validatedRuntime?: AdminState["validatedRuntime"];
};

// An admin refusal. It is a CliError so `main()` renders it like every other
// refusal when it escapes; `runAdminAction` renders it and returns the status
// when it is raised inside an admin action. Either way it is rendered exactly
// once, after any buffered warnings, and never as a stack trace.
export class AdminExit extends CliError {
  constructor(message: string, status = 1) {
    super(message, status);
    this.name = "AdminExit";
  }
}

function displayProjectPath(projectRoot: string, filePath: string): string {
  return path.isAbsolute(filePath) && isPathInsideByRealpath(projectRoot, filePath)
    ? path.relative(projectRoot, filePath)
    : filePath;
}

function testOnlyPathOverride(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const value = env[name];
  if (!value) return undefined;
  if (env.RUNFREE_TEST_FAKE_DOCKER !== "1") {
    throw new AdminExit(`${name} is test-only; host-owned token source paths are managed by Runfree`);
  }
  return value;
}

function assertHostOwnedConfigPath(projectRoot: string, label: string, filePath: string): string {
  const resolved = path.resolve(filePath);
  if (isPathInsideByRealpath(projectRoot, resolved)) {
    throw new AdminExit(`${label} must be outside the project: ${displayProjectPath(projectRoot, resolved)}`);
  }
  return resolved;
}

export function die(message: string): never {
  throw new AdminExit(message);
}

export function createAdminState(context: AdminContext = {}): AdminState {
  const env = context.env ?? process.env;
  const childEnv: NodeJS.ProcessEnv = {
    ...env,
    DOCKER_CLI_HINTS: "false",
  };
  const packageRoot = context.packageRoot
    ?? env.RUNFREE_PACKAGE_ROOT
    ?? path.resolve(path.dirname(scriptPath), "../../../..");
  const projectRoot = context.projectRoot ?? env.RUNFREE_PROJECT_ROOT ?? packageRoot;
  const projectId = env.RUNFREE_PROJECT_ID ?? projectHash(projectRoot);
  const configRoot = runfreeConfigRoot(env);
  const policyPath = context.policyPath
    ?? env.RUNFREE_NETWORK_POLICY_PATH
    ?? projectRunfreePath(projectRoot, "networkPolicy");
  const agentEnvPath = context.agentEnvPath
    ?? env.RUNFREE_AGENT_ENV_FILE
    ?? projectRunfreePath(projectRoot, "agentEnv");
  const stateDir = context.stateDir
    ?? env.RUNFREE_STATE_DIR
    ?? path.join(os.homedir(), ".local", "state", "runfree");

  return {
    projectRoot,
    packageRoot,
    policyPath,
    policyAccess: context.policyAccess ?? "legacy-editable",
    effectiveControlSelected: context.effectiveControlSelected ?? true,
    oauthPolicyPath: context.oauthPolicyPath
      ?? env.RUNFREE_OAUTH_POLICY_HOST_PATH
      ?? env.RUNFREE_MCP_OAUTH_POLICY_HOST_PATH,
    tokenConfigPath: assertHostOwnedConfigPath(
      projectRoot,
      "token source config path",
      context.tokenConfigPath
        ?? testOnlyPathOverride(env, "RUNFREE_TOKEN_CONFIG_PATH")
        ?? path.join(configRoot, "projects", projectId, "tokens.json"),
    ),
    sourceConfigPath: assertHostOwnedConfigPath(
      projectRoot,
      "source registry path",
      context.sourceConfigPath
        ?? testOnlyPathOverride(env, "RUNFREE_SOURCE_CONFIG_PATH")
        ?? path.join(configRoot, "sources.json"),
    ),
    agentEnvPath,
    stateDir,
    syncStatusPath: path.join(stateDir, "token-sync-status.json"),
    projectId,
    composeProjectName: env.RUNFREE_COMPOSE_PROJECT_NAME ?? composeProjectName(projectRoot),
    env: {
      child: childEnv,
      dockerClient: dockerClientEnvironment(childEnv),
    },
    ...(context.processRunner ? { processRunner: context.processRunner } : {}),
    runtimeContext: context.runtimeContext,
    validatedRuntime: context.validatedRuntime,
  };
}
