import type { SpawnSyncOptions, SpawnSyncReturns } from "node:child_process";

import type { RuntimeDocker } from "../runtime/docker.ts";
import type { RuntimeContext } from "../runtime/types.ts";
import type { TokenResolutionReceipt } from "../token-resolution.ts";

export type TokenSource =
  | ({ source: "env"; env: string } & TokenRefreshConfig)
  | ({ source: "1password"; ref: string } & TokenRefreshConfig)
  | ({ source: "named"; name: string } & TokenRefreshConfig)
  | ({ source: "file"; path: string } & TokenRefreshConfig)
  | ({ source: "cmd"; command: string } & TokenRefreshConfig);

export type TokenRefreshConfig = {
  refreshEverySeconds?: number;
  runfreeUserServiceOwner?: string;
};

export type AdminProcessRunner = (
  command: string,
  args: string[],
  options: SpawnSyncOptions,
) => SpawnSyncReturns<string>;

export type AdminState = {
  projectRoot: string;
  packageRoot: string;
  policyPath: string;
  policyAccess: "effective-read-only" | "legacy-editable";
  effectiveControlSelected: boolean;
  oauthPolicyPath?: string;
  tokenConfigPath: string;
  sourceConfigPath: string;
  agentEnvPath: string;
  stateDir: string;
  syncStatusPath: string;
  projectId: string;
  composeProjectName: string;
  env: {
    child: NodeJS.ProcessEnv;
    dockerClient: NodeJS.ProcessEnv;
  };
  docker?: RuntimeDocker;
  processRunner?: AdminProcessRunner;
  runtimeContext?: RuntimeContext;
  validatedRuntime?: RuntimeContext["validatedRuntime"];
  tokenResolutionReceipts?: TokenResolutionReceipt[];
};
