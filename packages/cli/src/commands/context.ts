// Command context passed to yargs handlers.
//
// Handlers use this instead of reaching into process globals. The methods are
// lazy: pure commands like `version` and `project-id` never trigger asset
// materialization or project-config reads because they never call the
// corresponding accessor. See the spec's "Context Object" section.

import path from "node:path";

import { effectiveRuntimeDigest } from "../agent-image.ts";
import type { AdminContext } from "../admin/context.ts";
import { materializeAssets, type MaterializedAssets } from "../assets.ts";
import {
  assertProjectPolicy,
  ensureProject,
  projectInfo,
  QUIESCED_CONFIG_MIGRATION,
  type ProjectInfo,
} from "../config.ts";
import { assertConfigCurrent } from "../config-notice.ts";
import { readActiveEffectiveControl } from "../control/effective.ts";
import { runtimeEnvironment } from "../runtime/env.ts";
import type { RuntimeContext } from "../runtime/types.ts";

export type EnsureProjectOptions = {
  migrateConfig?: boolean;
  migrationProof?: typeof QUIESCED_CONFIG_MIGRATION;
};

export type RunfreeCommandContext = {
  env: NodeJS.ProcessEnv;
  projectRoot: string;
  // The leading command/agent token being dispatched (empty for bare `runfree`).
  // Informational; handlers resolve their own command via yargs.
  commandName: string;
  invocationCwd: string;
  assets(): MaterializedAssets;
  templatesDir(): string;
  projectInfo(): ProjectInfo;
  ensureProject(options?: EnsureProjectOptions): ProjectInfo;
  adminContext(): AdminContext;
  sourceAdminContext(): AdminContext;
  runtimeContext(): RuntimeContext;
};

export function createCommandContext(input: {
  projectRoot: string;
  invocationCwd: string;
  commandName: string;
  env: NodeJS.ProcessEnv;
}): RunfreeCommandContext {
  let cachedAssets: MaterializedAssets | undefined;
  const assets = (): MaterializedAssets => {
    if (!cachedAssets) cachedAssets = materializeAssets(input.env);
    return cachedAssets;
  };
  const templatesDir = (): string => path.join(assets().runtimeDir, "templates");
  return {
    env: input.env,
    projectRoot: input.projectRoot,
    commandName: input.commandName,
    invocationCwd: input.invocationCwd,
    assets,
    templatesDir,
    projectInfo: () => projectInfo(input.projectRoot, input.env),
    ensureProject: (options) =>
      ensureProject(input.projectRoot, templatesDir(), input.env, options ?? {}),
    // Build the AdminContext for admin command modules: assert the config is
    // current on the read-only project, then ensure the project and derive the
    // admin runtime env. The admin runtime env keeps host runtime-path leakage
    // out of Docker reloads.
    adminContext: (): AdminContext => {
      assertConfigCurrent(projectInfo(input.projectRoot, input.env));
      const project = ensureProject(input.projectRoot, templatesDir(), input.env, {});
      const effective = readActiveEffectiveControl(project);
      return {
        agentEnvPath: project.paths.controlAgentEnvPath,
        projectRoot: input.projectRoot,
        packageRoot: assets().runtimeDir,
        policyPath: effective?.networkPolicyPath ?? project.paths.controlProxyActivePath,
        policyAccess: "effective-read-only",
        effectiveControlSelected: effective !== undefined,
        oauthPolicyPath: effective?.oauthPolicyPath,
        tokenConfigPath: project.paths.tokenConfigPath,
        stateDir: project.paths.stateDir,
        env: !effective
          ? {
              ...input.env,
              RUNFREE_PROJECT_ROOT: input.projectRoot,
              RUNFREE_STATE_DIR: project.paths.stateDir,
              RUNFREE_CLAUDE_JSON: project.paths.claudeConfigPath,
              RUNFREE_CLAUDE_MCP_CONFIG_HOST_PATH: project.paths.claudeMcpConfigPath,
              RUNFREE_CODEX_HOME: project.paths.codexDir,
              RUNFREE_MCP_OPERATION_POLICY_HOST_PATH: project.paths.mcpOperationPolicyPath,
            }
          : runtimeEnvironment(input.projectRoot, project, assets().runtimeDir, input.env, undefined, {
              runtimeDigest: effectiveRuntimeDigest(input.projectRoot, project.config),
            }),
      };
    },
    // Minimal admin context for `source` inspection/management. Source commands
    // manage host-owned source config, not project policy, so this must NOT
    // ensure the project (source list/show stay non-initializing).
    sourceAdminContext: (): AdminContext => ({
      projectRoot: input.projectRoot,
      packageRoot: assets().runtimeDir,
      env: input.env,
    }),
    // Build the RuntimeContext for runtime command modules: read the project,
    // assert the config is current and the project policy is present, then
    // materialize runtime assets
    // for the compose root. Runtime commands depend on a configured project, so
    // unlike `source` this asserts policy up front.
    runtimeContext: (): RuntimeContext => {
      const project = projectInfo(input.projectRoot, input.env);
      assertConfigCurrent(project);
      assertProjectPolicy(project);
      return {
        projectRoot: input.projectRoot,
        project,
        runtimeRoot: assets().runtimeDir,
        env: input.env,
      };
    },
  };
}
