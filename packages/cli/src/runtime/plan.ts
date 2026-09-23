import fs from "node:fs";
import path from "node:path";
import { SESSION_ADMISSION_MAX_RECORDS } from "@runfree/runtime-contracts/session-admission";
import { SESSION_FILE_SCHEMA_VERSION } from "@runfree/runtime-contracts/session-file";

import {
  agentBaseImageTag,
  agentBuildConfig,
  agentRuntimeImageTag,
  effectiveRuntimeDigest,
  projectAgentImageTag,
  proxyRuntimeImageTag,
  selectedAgentImageInput,
  type BuildContextManifestEntry,
  type LegacyInjectedBuildArgument,
} from "../agent-image.ts";
import type { AgentBuildConfig, ProjectInfo } from "../config.ts";
import { RUNFREE_RUNTIME_COMPONENTS, RUNFREE_VERSION } from "../embedded-assets.generated.ts";
import { resolveRuntimeNetwork, type RuntimeNetwork } from "../network.ts";
import { projectHash } from "../project-identity.ts";
import { runfreeConfigRoot, runfreeDataRoot, runfreeStateRoot } from "../paths.ts";
import { runtimeInputBuildEnvironment } from "../runtime-inputs.ts";
import {
  createDependencyOverlayPlan,
  persistedDependencyOverlayPlan,
  dependencyOverlayRuntimeSignature,
  serializeDependencyOverlayRuntimeSignature,
  type DependencyOverlayPlan,
} from "./dependency-overlays.ts";
import {
  createRuntimeComponentState,
  readEffectiveRuntimeGeneration,
  runtimeGenerationManifestPath,
  runtimeMaterializationRoot,
  type RuntimeComponentState,
} from "./component-state.ts";
import {
  RUNTIME_ADMISSION_CONTRACT_EPOCH,
  type RuntimeGenerationTargetV2,
} from "./component-state-v2.ts";
import { controlPlaneTopologyProjectionV2 } from "./control-plane-topology-v2.ts";
import {
  composeProjectName,
  composeRuntimeEnvironment,
  dockerClientEnvironment,
  runtimeEnvironment,
} from "./env.ts";
import {
  classifyGitRepository,
  gitLayoutPlanForShape,
  serializeGitLayoutPlan,
  type GitRepositoryShape,
  type RuntimeGitLayoutPlan,
} from "./git-layout.ts";
import {
  mcpOAuthCallbackPort,
  mcpOAuthCallbackUrl,
} from "./mcp.ts";
import { createRuntimeGenerationTargetV2 } from "./generation-plan-v2.ts";
import type { RuntimeMaterialization } from "./images.ts";
import { renderProjectRuntimeCompose } from "./rendered-compose.ts";
import {
  bindSessionContainerTemplateGenerationV2,
  sessionContainerTemplateForRuntimePlan,
  sessionContainerTopologyProjectionV2,
  type SessionContainerTemplate,
} from "./session-container-template.ts";
import {
  composeInterpolationVariables,
  runtimeTopologyDigest,
  type TopologyDigestJson,
} from "./topology-digest.ts";
import type { RuntimeContext } from "./types.ts";

export type SanitizedDockerClientEnvironment = Readonly<Record<string, string>>;
export type GeneratedRuntimeEnvironment = Readonly<Record<string, string>>;
export type RuntimeInputBuildEnvironment = Readonly<Record<string, string>>;

export type AdminEnvironmentProvider = {
  dockerClient: SanitizedDockerClientEnvironment;
  resolveChildEnv(): NodeJS.ProcessEnv;
};

export type RuntimePlanAgentImage = {
  build: AgentBuildConfig;
  baseImage: string;
  contextFingerprint: readonly BuildContextManifestEntry[] | Readonly<{ dockerfileSha256: string }>;
  projectImage: string;
  inputDigest: string;
  referencedLegacyInjectedArguments: readonly LegacyInjectedBuildArgument[];
  contextKind: "narrow" | "wide";
};

export type RuntimePlanPaths = ProjectInfo["paths"];

export type RuntimePlan = {
  projectRoot: string;
  project: ProjectInfo;
  projectId: string;
  composeProjectName: string;
  baseRuntimeRoot: string;
  projectRuntimeRoot: string;
  runtimeDigest: string;
  components: RuntimeComponentState;
  generationV2: RuntimeGenerationTargetV2;
  sessionContainerTemplate: SessionContainerTemplate;
  renderedCompose: string;
  runfreeVersion: string;
  network: RuntimeNetwork;
  paths: RuntimePlanPaths;
  gitRepositoryShape: GitRepositoryShape;
  gitLayout: RuntimeGitLayoutPlan;
  dependencyOverlays: DependencyOverlayPlan;
  mcpOAuth: {
    callbackPort: number;
    callbackUrl: string;
  };
  execution: {
    dockerClientEnv: SanitizedDockerClientEnvironment;
    composeEnv: GeneratedRuntimeEnvironment;
    adminEnvProvider: AdminEnvironmentProvider;
    runtimeInputBuildEnv: RuntimeInputBuildEnvironment;
  };
  agentImage?: RuntimePlanAgentImage;
};

export type ActiveRuntimePlan = RuntimePlan & {
  activeRuntime: RuntimeMaterialization;
};

type RuntimeContextFromPlanOptions = {
  activeRuntime?: RuntimeMaterialization;
  dependencyOverlayPlanChanged?: boolean;
  gitLayoutPlanChanged?: boolean;
  validatedRuntime?: RuntimeContext["validatedRuntime"];
};

function stringEnvironment(env: NodeJS.ProcessEnv): Record<string, string> {
  return Object.fromEntries(
    Object.entries(env).filter((entry): entry is [string, string] => typeof entry[1] === "string"),
  );
}

function topologyJson(value: unknown): TopologyDigestJson {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) throw new Error("runtime topology projection is not JSON serializable");
  return JSON.parse(serialized) as TopologyDigestJson;
}

function runtimeInputEnvironment(runtimeRoot: string): RuntimeInputBuildEnvironment {
  try {
    return stringEnvironment(runtimeInputBuildEnvironment(runtimeRoot));
  } catch {
    return {};
  }
}

/**
 * The overlay set every derived field of this plan is built from.
 *
 * Compose output, the topology digest, the session container template, and the
 * generation target are all computed from this one answer, so a caller that
 * knows which set applies must be able to say so rather than have this guess.
 * Startup supplies its freshly prepared plan; active-runtime reconstruction
 * supplies the persisted one. The scan below is the last resort for a caller
 * with neither, and it cannot see the Git ignore/track facts startup uses.
 */
function dependencyOverlayPlan(context: RuntimeContext): DependencyOverlayPlan {
  if (context.dependencyOverlayPlan) return context.dependencyOverlayPlan;
  return createDependencyOverlayPlan(context.projectRoot, {
    mode: context.project.config.runtime.dependencyOverlays ?? "auto",
    ignoredRootPaths: [
      runfreeConfigRoot(context.env),
      runfreeDataRoot(context.env),
      runfreeStateRoot(context.env),
    ],
  });
}

function planAgentImage(context: RuntimeContext): RuntimePlanAgentImage | undefined {
  const build = agentBuildConfig(context.project.config);
  if (!build) return undefined;
  const selected = selectedAgentImageInput(context.projectRoot, context.project.config);
  if (selected.kind !== "project") throw new Error("internal error: project agent image identity is missing");
  return {
    build,
    baseImage: agentBaseImageTag(),
    contextFingerprint: selected.contextFingerprint,
    projectImage: projectAgentImageTag(context.projectRoot, selected.digest),
    inputDigest: selected.digest,
    referencedLegacyInjectedArguments: selected.referencedLegacyInjectedArguments,
    contextKind: selected.contextKind,
  };
}

export function createRuntimePlan(
  context: RuntimeContext,
  options: { dockerSubnets: string[]; persistNetwork: boolean },
): RuntimePlan {
  const requestedRuntimeRoot = context.baseRuntimeRoot ?? context.runtimeRoot;
  const developmentRuntimeRoot = path.join(requestedRuntimeRoot, "packages", "agent-runtime");
  const sourceRuntimeRoot = !fs.existsSync(path.join(requestedRuntimeRoot, "agent", "compose.yaml"))
      && fs.existsSync(path.join(developmentRuntimeRoot, "agent", "compose.yaml"))
    ? developmentRuntimeRoot
    : requestedRuntimeRoot;
  const runtimeDigest = effectiveRuntimeDigest(context.projectRoot, context.project.config);
  const network = context.network ?? resolveRuntimeNetwork(context.projectRoot, context.project, options.dockerSubnets, {
    persist: options.persistNetwork,
  });
  const gitRepositoryShape = classifyGitRepository(context.projectRoot);
  const gitLayout = gitLayoutPlanForShape(context.projectRoot, gitRepositoryShape);
  const dependencyOverlays = dependencyOverlayPlan(context);
  const agentImage = planAgentImage(context);
  const agentImageTag = agentImage?.projectImage;
  const dockerClientEnv = stringEnvironment(dockerClientEnvironment(context.env));
  const preliminaryComposeEnv = stringEnvironment(composeRuntimeEnvironment(
    context.projectRoot,
    context.project,
    sourceRuntimeRoot,
    context.env,
    network,
    {
      agentImage: agentImageTag,
      gitLayout,
      runtimeDigest,
    },
  ));
  const renderContext: RuntimeContext = {
    ...context,
    dependencyOverlayPlan: dependencyOverlays,
    gitLayoutPlan: gitLayout,
    network,
  };
  const renderedCompose = renderProjectRuntimeCompose({
    context: renderContext,
    dependencyPlan: dependencyOverlays,
    gitLayout,
    sourceRuntimeRoot,
  });
  const selectedAgentImageInputDigest = agentImage?.inputDigest ?? RUNFREE_RUNTIME_COMPONENTS.agentImageInputDigest;
  const topologyInterpolationValues: Record<string, string | undefined> = {
    ...preliminaryComposeEnv,
    RUNFREE_AGENT_IMAGE_INPUT_DIGEST: selectedAgentImageInputDigest,
    RUNFREE_PROXY_IMAGE_INPUT_DIGEST: RUNFREE_RUNTIME_COMPONENTS.proxyImageInputDigest,
    RUNFREE_TOPOLOGY_DIGEST: undefined,
    RUNFREE_RUNTIME_GENERATION_DIGEST: undefined,
  };
  for (const name of composeInterpolationVariables(renderedCompose)) {
    if (!Object.hasOwn(topologyInterpolationValues, name)) topologyInterpolationValues[name] = undefined;
  }
  const topologyDigest = runtimeTopologyDigest({
    compose: renderedCompose,
    interpolationValues: topologyInterpolationValues,
    runtimeSignatures: {
      dependencyOverlays: JSON.parse(serializeDependencyOverlayRuntimeSignature(
        dependencyOverlayRuntimeSignature(dependencyOverlays, gitLayout.containerProjectRoot),
      )) as TopologyDigestJson,
      gitLayout: JSON.parse(serializeGitLayoutPlan(gitLayout)) as TopologyDigestJson,
      mcpOAuth: {
        callbackPort: mcpOAuthCallbackPort(context.projectRoot),
        callbackUrl: mcpOAuthCallbackUrl(context.projectRoot),
      },
    },
  });
  const components = createRuntimeComponentState({
    embeddedAgentImageInputDigest: RUNFREE_RUNTIME_COMPONENTS.agentImageInputDigest,
    selectedAgentImageInputDigest,
    selectedAgentImageKind: agentImage ? "project" : "embedded",
    proxyImageInputDigest: RUNFREE_RUNTIME_COMPONENTS.proxyImageInputDigest,
    topologyDigest,
    hostHelperDigest: RUNFREE_RUNTIME_COMPONENTS.hostHelperDigest,
  });
  const composeEnv = stringEnvironment(composeRuntimeEnvironment(
    context.projectRoot,
    context.project,
    sourceRuntimeRoot,
    context.env,
    network,
    {
      agentImage: agentImageTag,
      components,
      gitLayout,
      runtimeDigest,
    },
  ));
  const adminEnvProvider: AdminEnvironmentProvider = {
    dockerClient: dockerClientEnv,
    resolveChildEnv: () => runtimeEnvironment(
      context.projectRoot,
      context.project,
      context.runtimeRoot,
      context.env,
      network,
      {
        agentImage: agentImageTag,
        components,
        gitLayout,
        runtimeDigest,
      },
    ),
  };

  const basePlan: Omit<RuntimePlan, "generationV2" | "sessionContainerTemplate"> = {
    projectRoot: context.projectRoot,
    project: context.project,
    projectId: projectHash(context.projectRoot),
    composeProjectName: composeProjectName(context.projectRoot),
    baseRuntimeRoot: sourceRuntimeRoot,
    projectRuntimeRoot: runtimeMaterializationRoot(context.project.paths.stateDir, components.materializationDigest),
    runtimeDigest,
    components,
    renderedCompose,
    runfreeVersion: RUNFREE_VERSION,
    network,
    paths: { ...context.project.paths },
    gitRepositoryShape,
    gitLayout,
    dependencyOverlays,
    mcpOAuth: {
      callbackPort: mcpOAuthCallbackPort(context.projectRoot),
      callbackUrl: mcpOAuthCallbackUrl(context.projectRoot),
    },
    execution: {
      dockerClientEnv,
      composeEnv,
      adminEnvProvider,
      runtimeInputBuildEnv: runtimeInputEnvironment(sourceRuntimeRoot),
    },
    ...(agentImage ? { agentImage } : {}),
  };
  const sessionTemplate = sessionContainerTemplateForRuntimePlan(basePlan);
  const generationV2 = createRuntimeGenerationTargetV2({
    projectId: basePlan.projectId,
    composeProject: basePlan.composeProjectName,
    proxyImageInputDigest: RUNFREE_RUNTIME_COMPONENTS.proxyImageInputDigest,
    selectedAgentImageInputDigest,
    admissionContractEpoch: RUNTIME_ADMISSION_CONTRACT_EPOCH,
    topology: {
      compose: renderedCompose,
      interpolationValues: Object.fromEntries(
        composeInterpolationVariables(renderedCompose).map((name) => [
          name,
          basePlan.execution.composeEnv[name] ?? topologyInterpolationValues[name],
        ]),
      ),
      controlPlane: {
        structure: topologyJson(controlPlaneTopologyProjectionV2(basePlan)),
        runtimeSignatures: {
          sessionAdmission: {
            schemaVersion: SESSION_FILE_SCHEMA_VERSION,
            maxRecords: SESSION_ADMISSION_MAX_RECORDS,
          },
        },
      },
      sessionTemplate: {
        structure: sessionContainerTopologyProjectionV2(sessionTemplate),
        runtimeSignatures: {},
      },
    },
  });
  return {
    ...basePlan,
    generationV2,
    sessionContainerTemplate: bindSessionContainerTemplateGenerationV2(sessionTemplate, generationV2),
  };
}

export function activeRuntimePlanFromContext(context: RuntimeContext): ActiveRuntimePlan {
  // Reconstruction, not planning: this must reproduce the generation the live
  // runtime was created from, and the persisted plan is the record of the
  // overlay set startup created named volumes for. Re-scanning here would see
  // gitignored worktrees those volumes were never created for, and the session
  // container template built from this plan would demand them.
  const persisted = context.dependencyOverlayPlan ? undefined : persistedDependencyOverlayPlan(context);
  const planContext = persisted ? { ...context, dependencyOverlayPlan: persisted } : context;
  const plan = createRuntimePlan(planContext, { dockerSubnets: [], persistNetwork: false });
  const manifest = readEffectiveRuntimeGeneration(context.project.paths.stateDir);
  if (manifest && (manifest.projectId !== plan.projectId || manifest.composeProject !== plan.composeProjectName)) {
    throw new Error("selected runtime generation belongs to another project");
  }
  const components = manifest?.components ?? context.runtimeComponents ?? plan.components;
  const activeRuntimeRoot = manifest
    ? path.dirname(runtimeGenerationManifestPath(context.project.paths.stateDir, manifest.components.materializationDigest))
    : context.runtimeRoot;
  return {
    ...plan,
    components,
    activeRuntime: {
      activeRuntimeRoot,
      composeFile: path.join(activeRuntimeRoot, "agent", "compose.yaml"),
      composeDirectory: path.join(activeRuntimeRoot, "agent"),
      runtimeDigest: plan.runtimeDigest,
      materialized: true,
      agentImage: manifest?.images.agent
        ?? context.agentImage
        ?? plan.agentImage?.projectImage
        ?? agentRuntimeImageTag(components.selectedAgentImageInputDigest),
      proxyImage: manifest?.images.proxy ?? proxyRuntimeImageTag(components.proxyImageInputDigest),
      ...(manifest ? { manifest } : {}),
      state: manifest ? "effective" : "legacy",
    },
  };
}

export function runtimeContextFromPlan(
  plan: RuntimePlan,
  options: RuntimeContextFromPlanOptions = {},
): RuntimeContext {
  const activeRuntime = options.activeRuntime;
  const runtimeRoot = activeRuntime?.activeRuntimeRoot ?? plan.baseRuntimeRoot;
  const agentImage = activeRuntime?.agentImage ?? plan.agentImage?.projectImage ?? agentRuntimeImageTag();
  const proxyImage = activeRuntime?.proxyImage ?? proxyRuntimeImageTag();
  const components = activeRuntime?.manifest?.components ?? plan.components;
  const env = {
    ...plan.execution.adminEnvProvider.resolveChildEnv(),
    RUNFREE_AGENT_IMAGE: agentImage,
    RUNFREE_PACKAGE_ROOT: runtimeRoot,
    RUNFREE_PROXY_IMAGE: proxyImage,
    RUNFREE_AGENT_IMAGE_INPUT_DIGEST: components.selectedAgentImageInputDigest,
    RUNFREE_PROXY_IMAGE_INPUT_DIGEST: components.proxyImageInputDigest,
    RUNFREE_TOPOLOGY_DIGEST: components.topologyDigest,
    RUNFREE_RUNTIME_GENERATION_DIGEST: components.runtimeGenerationDigest,
    RUNFREE_RUNTIME_DIGEST: plan.runtimeDigest,
    RUNFREE_RUNTIME_ROOT: runtimeRoot,
  };

  return {
    projectRoot: plan.projectRoot,
    project: { ...plan.project, paths: plan.paths },
    runtimeRoot,
    baseRuntimeRoot: plan.baseRuntimeRoot,
    agentImage,
    runtimeComponents: components,
    runtimeGenerationV2: plan.generationV2,
    dependencyOverlayPlan: plan.dependencyOverlays,
    ...(options.dependencyOverlayPlanChanged !== undefined
      ? { dependencyOverlayPlanChanged: options.dependencyOverlayPlanChanged }
      : {}),
    gitRepositoryShape: plan.gitRepositoryShape,
    gitLayoutPlan: plan.gitLayout,
    ...(options.gitLayoutPlanChanged !== undefined ? { gitLayoutPlanChanged: options.gitLayoutPlanChanged } : {}),
    ...(options.validatedRuntime ? { validatedRuntime: options.validatedRuntime } : {}),
    env,
    network: plan.network,
  };
}

export function runtimeContextFromActivePlan(
  plan: ActiveRuntimePlan,
  options: Omit<RuntimeContextFromPlanOptions, "activeRuntime"> = {},
): RuntimeContext {
  return runtimeContextFromPlan(plan, { ...options, activeRuntime: plan.activeRuntime });
}

export function runtimeDryRunOutput(command: string, plan: RuntimePlan): {
  command: string;
  projectRoot: string;
  baseRuntimeRoot: string;
  projectRuntimeRoot: string;
  composeFile: string;
  composeProjectName: string;
  env: Record<string, string | undefined>;
  network: RuntimeNetwork;
} {
  const env = plan.execution.composeEnv;
  return {
    command,
    projectRoot: plan.projectRoot,
    baseRuntimeRoot: plan.baseRuntimeRoot,
    projectRuntimeRoot: plan.projectRuntimeRoot,
    composeFile: path.join(plan.projectRuntimeRoot, "agent", "compose.yaml"),
    composeProjectName: plan.composeProjectName,
    env: {
      RUNFREE_AGENT_IMAGE: env.RUNFREE_AGENT_IMAGE,
      RUNFREE_PROXY_IMAGE: env.RUNFREE_PROXY_IMAGE,
      RUNFREE_CLAUDE_DIR: env.RUNFREE_CLAUDE_DIR,
      RUNFREE_CLAUDE_JSON: env.RUNFREE_CLAUDE_JSON,
      RUNFREE_CLAUDE_MCP_CONFIG_HOST_PATH: env.RUNFREE_CLAUDE_MCP_CONFIG_HOST_PATH,
      RUNFREE_CODEX_HOME: env.RUNFREE_CODEX_HOME,
      RUNFREE_PROJECT_NAME: env.RUNFREE_PROJECT_NAME,
      RUNFREE_PROJECT_CONTAINER_ROOT: env.RUNFREE_PROJECT_CONTAINER_ROOT,
      RUNFREE_PROJECT_COMPAT_ROOT: env.RUNFREE_PROJECT_COMPAT_ROOT,
      RUNFREE_PROJECT_PHYSICAL_ROOT: env.RUNFREE_PROJECT_PHYSICAL_ROOT,
      RUNFREE_GIT_LAYOUT_KIND: env.RUNFREE_GIT_LAYOUT_KIND,
      RUNFREE_GIT_COMMON_DIR: env.RUNFREE_GIT_COMMON_DIR,
      RUNFREE_GIT_CONFIG: env.RUNFREE_GIT_CONFIG,
      RUNFREE_EFFECTIVE_PROXY_DIR: env.RUNFREE_EFFECTIVE_PROXY_DIR,
      RUNFREE_AGENT_STATE_CLAUDE_CONFIG_DIR: env.RUNFREE_AGENT_STATE_CLAUDE_CONFIG_DIR,
      RUNFREE_AGENT_STATE_CLAUDE_CONFIG_JSON: env.RUNFREE_AGENT_STATE_CLAUDE_CONFIG_JSON,
      RUNFREE_AGENT_STATE_CODEX_HOME: env.RUNFREE_AGENT_STATE_CODEX_HOME,
      RUNFREE_AGENT_STATE_PI_AGENT_DIR: env.RUNFREE_AGENT_STATE_PI_AGENT_DIR,
      RUNFREE_MCP_OAUTH_CALLBACK_PORT: env.RUNFREE_MCP_OAUTH_CALLBACK_PORT,
      RUNFREE_MCP_OAUTH_CALLBACK_URL: env.RUNFREE_MCP_OAUTH_CALLBACK_URL,
      RUNFREE_MCP_OPERATION_POLICY_HOST_PATH: env.RUNFREE_MCP_OPERATION_POLICY_HOST_PATH,
      RUNFREE_PROXY_CA_CERT_DIR: env.RUNFREE_PROXY_CA_CERT_DIR,
      RUNFREE_PROXY_CA_KEY_DIR: env.RUNFREE_PROXY_CA_KEY_DIR,
      RUNFREE_RUNTIME_DIGEST: env.RUNFREE_RUNTIME_DIGEST,
      RUNFREE_AGENT_IMAGE_INPUT_DIGEST: env.RUNFREE_AGENT_IMAGE_INPUT_DIGEST,
      RUNFREE_PROXY_IMAGE_INPUT_DIGEST: env.RUNFREE_PROXY_IMAGE_INPUT_DIGEST,
      RUNFREE_TOPOLOGY_DIGEST: env.RUNFREE_TOPOLOGY_DIGEST,
      RUNFREE_RUNTIME_GENERATION_DIGEST: env.RUNFREE_RUNTIME_GENERATION_DIGEST,
      RUNFREE_VERSION: env.RUNFREE_VERSION,
      DOCKER_CLI_HINTS: env.DOCKER_CLI_HINTS,
    },
    network: plan.network,
  };
}
