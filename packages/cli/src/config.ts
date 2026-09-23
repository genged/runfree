import fs from "node:fs";
import path from "node:path";

import { validateDesiredNetworkPolicy } from "@runfree/runtime-contracts/desired-network-policy";

import { die } from "./errors.ts";
import { runfreeConfigRoot, runfreeStateRoot, resolveProjectPath } from "./paths.ts";
import { projectHash } from "./project-identity.ts";
import {
  ensureSafeProjectDir,
  assertOptionalNormalProjectDirectory,
  isPathInsideByRealpath,
  safeCopyProjectFile,
  safeReadProjectFile,
  safeReplaceProjectFile,
} from "./safe-fs.ts";
import {
  PROJECT_RUNFREE_PATHS,
  projectRunfreePath,
} from "./runfree-consumer-registry.ts";
import { builtinAgent, defaultBuiltinAgentCommands } from "./agents.ts";
import type { DependencyOverlayMode } from "./runtime/dependency-overlays.ts";
import { migrateLegacyDesiredPolicy } from "./control/legacy-migration.ts";
import { importProvenLegacyNetworkApproval } from "./control/legacy-enforced-import.ts";
import { isRecord } from "./strict-primitives.ts";

export const RUNFREE_CONFIG_VERSION = 4;
export const QUIESCED_CONFIG_MIGRATION = Symbol("runfree.quiesced-config-migration");

const DEFAULT_NETWORK_POLICY_PATH = PROJECT_RUNFREE_PATHS.networkPolicy;
const DEFAULT_AGENT_BUILD_CONTEXT = PROJECT_RUNFREE_PATHS.image;
const DEFAULT_AGENT_DOCKERFILE_PATH = `${PROJECT_RUNFREE_PATHS.image}/Dockerfile`;
const DEFAULT_AGENT_DOCKERIGNORE_PATH = ".runfree/image/.dockerignore";
const DEFAULT_AGENT_DOCKERFILE = [
  "ARG RUNFREE_BASE_IMAGE=runfree/agent-base:missing-runfree-base-image-build-arg",
  "FROM ${RUNFREE_BASE_IMAGE}",
  "",
  "USER root",
  "# Add project-specific packages here, for example browser dependencies.",
  "",
  "USER agent",
  "",
].join("\n");
const DEFAULT_AGENT_DOCKERIGNORE = "# Build size hints only; Runfree validates the whole selected context.\n";

export type AgentCommandConfig = {
  command: string;
  resumeCommand?: string;
};

export type AgentsConfig = {
  default: string;
} & Record<string, AgentCommandConfig | string>;

export type AgentBuildConfig = {
  context: string;
  dockerfile: string;
  target?: string;
  args?: Record<string, string>;
};

export type RuntimeAgentConfig = {
  build?: AgentBuildConfig;
};

export type WriteApprovalMode = "allow" | "ask" | "deny";

export type RunfreeConfig = {
  version: number;
  project: {
    name?: string;
  };
  agents: AgentsConfig;
  runtime: {
    subnet?: string;
    proxyIp?: string;
    agentIp?: string;
    dependencyOverlays?: DependencyOverlayMode;
    agent?: RuntimeAgentConfig;
    // Project-wide default for the write class of requests to hosts without a
    // per-host writeAction rule. Compiled by the CLI into the policy file's
    // top-level writeApproval; the proxy never reads this config.
    writeApproval?: WriteApprovalMode;
    // How long an approve-on-write hold waits for a human decision. Validated
    // host-side (5-300s), passed to the proxy as runtime env, and folded into
    // the runtime security-contract hash — changing it recreates the runtime.
    writeApprovalHoldSeconds?: number;
  };
};

export type ProjectInfo = {
  config: RunfreeConfig;
  configMigrated?: ConfigMigrationNotice;
  configMigration?: ConfigMigrationNotice;
  paths: {
    runfreeDir: string;
    agentEnvPath: string;
    claudeConfigPath: string;
    claudeMcpConfigPath: string;
    claudeDir: string;
    codexDir: string;
    configPath: string;
    controlApprovalsPath: string;
    controlAgentEnvPath: string;
    controlMcpNetworkPolicyPath: string;
    controlApprovedDir: string;
    controlCandidatesDir: string;
    controlConvergedPath: string;
    controlDir: string;
    controlEffectiveDir: string;
    controlLegacyEnforcedNetworkPath: string;
    controlProxyActivePath: string;
    controlProxyDir: string;
    gitConfigPath: string;
    inboxDir: string;
    projectCodexDirMaskPath: string;
    mcpOperationPolicyPath?: string;
    mcpOAuthPolicyPath: string;
    proxyCaCertDir: string;
    proxyCaKeyDir: string;
    policyPath: string;
    sessionsDir: string;
    stateDir: string;
    tokenConfigPath: string;
  };
};

export type ConfigMigrationNotice = {
  fromVersion: number;
  // Authority-preserving downgrades the migration had to make, phrased for the
  // user (a service record it could not prove, kept as direct hosts).
  notes?: string[];
  toVersion: number;
};

export type AgentImageInitResult = {
  project: ProjectInfo;
  dockerfilePath: string;
  dockerfileCreated: boolean;
  configUpdated: boolean;
};

export function projectControlPaths(stateDir: string) {
  const controlDir = path.join(stateDir, "control");
  const controlEffectiveDir = path.join(controlDir, "effective");
  const controlProxyDir = path.join(controlEffectiveDir, "proxy");
  return {
    controlApprovalsPath: path.join(controlDir, "approvals.json"),
    controlAgentEnvPath: path.join(controlDir, "inputs", "agent.env"),
    controlMcpNetworkPolicyPath: path.join(controlDir, "inputs", "mcp-network-policy.json"),
    controlApprovedDir: path.join(controlDir, "approved"),
    controlCandidatesDir: path.join(controlDir, "candidates"),
    controlConvergedPath: path.join(controlEffectiveDir, "converged.json"),
    controlDir,
    controlEffectiveDir,
    controlLegacyEnforcedNetworkPath: path.join(controlDir, "legacy-enforced-network.json"),
    controlProxyActivePath: path.join(controlProxyDir, "active.json"),
    controlProxyDir,
  };
}

type ConfigReadResult = {
  config: RunfreeConfig;
  migration?: ConfigMigrationNotice;
};

export function defaultConfig(): RunfreeConfig {
  return {
    version: RUNFREE_CONFIG_VERSION,
    project: {},
    agents: {
      default: "claude",
      ...defaultBuiltinAgentCommands(),
    },
    runtime: {
      dependencyOverlays: "auto",
    },
  };
}

function mergeObjectConfig<T extends Record<string, unknown>>(defaultValue: T, value: unknown, label: string): T {
  if (value === undefined) return defaultValue;
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    die(`${label} must be an object`);
  }
  return { ...defaultValue, ...value };
}

function validateAgentCommandConfig(value: unknown, label: string): AgentCommandConfig {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    die(`${label} must be an object`);
  }
  const command = (value as { command?: unknown }).command;
  if (typeof command !== "string" || command.trim() === "") {
    die(`${label}.command must be a non-empty string`);
  }
  const resumeCommand = (value as { resumeCommand?: unknown }).resumeCommand;
  if (resumeCommand !== undefined && (typeof resumeCommand !== "string" || resumeCommand.trim() === "")) {
    die(`${label}.resumeCommand must be a non-empty string`);
  }
  for (const key of Object.keys(value)) {
    if (key !== "command" && key !== "resumeCommand") {
      die(`${label}.${key} is not supported; agent config only supports command and resumeCommand`);
    }
  }
  return { command, ...(typeof resumeCommand === "string" ? { resumeCommand } : {}) };
}

function validateConfigVersion(value: unknown): number {
  if (value === undefined) return RUNFREE_CONFIG_VERSION;
  if (!Number.isInteger(value) || typeof value !== "number" || value < 1) {
    die("version must be a positive integer");
  }
  if (value > RUNFREE_CONFIG_VERSION) {
    die([
      `this project's config is version ${value}, newer than this installation supports (version ${RUNFREE_CONFIG_VERSION})`,
      "install a newer release of runfree with the same method you used for this one; the config is not invalid",
      "`runfree update` explains the install options",
    ].join("\n"));
  }
  return value;
}


function validateNonEmptyString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    die(`${label} must be a non-empty string`);
  }
  return value;
}

function validateBuildPathInsideProject(projectRoot: string, value: string, label: string): void {
  const resolved = path.resolve(projectRoot, value);
  const root = path.resolve(projectRoot);
  const relative = path.relative(root, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    die(`${label} must resolve inside the project root`);
  }
}

function validateAgentBuildConfig(projectRoot: string, value: unknown): AgentBuildConfig {
  if (!isRecord(value)) {
    die("runtime.agent.build must be an object");
  }

  const context = value.context === undefined ? "." : validateNonEmptyString(value.context, "runtime.agent.build.context");
  const dockerfile = validateNonEmptyString(value.dockerfile, "runtime.agent.build.dockerfile");
  validateBuildPathInsideProject(projectRoot, context, "runtime.agent.build.context");
  validateBuildPathInsideProject(projectRoot, dockerfile, "runtime.agent.build.dockerfile");

  let target: string | undefined;
  if (value.target !== undefined) {
    target = validateNonEmptyString(value.target, "runtime.agent.build.target");
  }

  let args: Record<string, string> | undefined;
  if (value.args !== undefined) {
    if (!isRecord(value.args)) {
      die("runtime.agent.build.args must be an object");
    }
    args = {};
    for (const [name, argValue] of Object.entries(value.args)) {
      if (name.trim() === "") {
        die("runtime.agent.build.args names must be non-empty");
      }
      if (name.startsWith("RUNFREE_")) {
        die(`runtime.agent.build.args.${name} uses a reserved RUNFREE_ build arg`);
      }
      if (typeof argValue !== "string") {
        die(`runtime.agent.build.args.${name} must be a string`);
      }
      args[name] = argValue;
    }
  }

  return {
    context,
    dockerfile,
    ...(target === undefined ? {} : { target }),
    ...(args === undefined ? {} : { args }),
  };
}

function validateRuntimeAgentConfig(projectRoot: string, value: unknown): RuntimeAgentConfig {
  if (!isRecord(value)) {
    die("runtime.agent must be an object");
  }
  if ("image" in value && value.image !== undefined) {
    die("runtime.agent.image is not supported; use runtime.agent.build.dockerfile");
  }
  return {
    ...(value.build === undefined ? {} : { build: validateAgentBuildConfig(projectRoot, value.build) }),
  };
}

function normalizeAgentsConfig(defaults: AgentsConfig, value: unknown, legacyAgent: AgentCommandConfig | undefined): AgentsConfig {
  const agents: AgentsConfig = { ...defaults };
  const configuredAgents = value === undefined ? undefined : value;
  const explicitAgentNames = new Set<string>();

  if (configuredAgents !== undefined) {
    if (configuredAgents === null || Array.isArray(configuredAgents) || typeof configuredAgents !== "object") {
      die("agents must be an object");
    }
    for (const [name, entry] of Object.entries(configuredAgents as Record<string, unknown>)) {
      if (name === "default") {
        if (typeof entry !== "string" || entry.trim() === "") {
          die("agents.default must be a non-empty string");
        }
        agents.default = entry;
        continue;
      }
      agents[name] = validateAgentCommandConfig(entry, `agents.${name}`);
      explicitAgentNames.add(name);
    }
  }

  if (legacyAgent && !explicitAgentNames.has("claude")) {
    agents.claude = legacyAgent;
  }

  if (!resolveAgentCommand({ agents }, agents.default)) {
    die(`agents.default references unknown agent: ${agents.default}`);
  }
  return agents;
}

function validateRuntimeConfig(
  projectRoot: string,
  runtime: RunfreeConfig["runtime"],
  configVersion: number,
): RunfreeConfig["runtime"] {
  const supportedKeys = new Set([
    "subnet",
    "proxyIp",
    "agentIp",
    "dependencyOverlays",
    "agent",
    "writeApprovalHoldSeconds",
    ...(configVersion < 4 ? ["writeApproval"] : []),
  ]);
  for (const key of Object.keys(runtime)) {
    if (!supportedKeys.has(key)) {
      die(`runtime.${key} is not supported by config version ${configVersion}`);
    }
  }
  for (const key of ["subnet", "proxyIp", "agentIp"] as const) {
    const value = runtime[key];
    if (value === undefined) continue;
    if (typeof value !== "string" || value.trim() === "") {
      die(`runtime.${key} must be a non-empty string`);
    }
  }
  if (runtime.agent !== undefined) {
    runtime.agent = validateRuntimeAgentConfig(projectRoot, runtime.agent);
  }
  if (runtime.dependencyOverlays !== undefined
    && runtime.dependencyOverlays !== "auto"
    && runtime.dependencyOverlays !== "off") {
    die("runtime.dependencyOverlays must be either \"auto\" or \"off\"");
  }
  if (runtime.writeApproval !== undefined
    && runtime.writeApproval !== "allow"
    && runtime.writeApproval !== "ask"
    && runtime.writeApproval !== "deny") {
    die("runtime.writeApproval must be \"allow\", \"ask\", or \"deny\"");
  }
  if (runtime.writeApprovalHoldSeconds !== undefined
    && (!Number.isInteger(runtime.writeApprovalHoldSeconds)
      || runtime.writeApprovalHoldSeconds < 5
      || runtime.writeApprovalHoldSeconds > 300)) {
    die("runtime.writeApprovalHoldSeconds must be an integer between 5 and 300");
  }
  return runtime;
}

function validateProjectConfig(value: unknown): { config: RunfreeConfig["project"]; legacyKeys: string[] } {
  if (value === undefined) return { config: {}, legacyKeys: [] };
  if (!isRecord(value)) {
    die("project must be an object");
  }

  const config: RunfreeConfig["project"] = {};
  const legacyKeys: string[] = [];
  for (const key of Object.keys(value)) {
    if (key !== "name") legacyKeys.push(key);
  }
  if (value.name !== undefined) {
    config.name = validateNonEmptyString(value.name, "project.name");
  }
  return { config, legacyKeys };
}

export function resolveAgentCommand(config: Pick<RunfreeConfig, "agents">, agentName: string): string | undefined {
  const entry = config.agents[agentName];
  if (entry && typeof entry === "object" && typeof entry.command === "string") {
    const descriptor = builtinAgent(agentName);
    if (descriptor?.legacyDefaultCommands?.includes(entry.command)) return descriptor.defaultCommand;
    return entry.command;
  }
  return undefined;
}

export function resolveAgentResumeCommand(
  config: Pick<RunfreeConfig, "agents">,
  agentName: string,
): string | undefined {
  const entry = config.agents[agentName];
  return entry && typeof entry === "object" && typeof entry.resumeCommand === "string"
    ? entry.resumeCommand
    : undefined;
}

export function resolveDefaultAgentName(config: Pick<RunfreeConfig, "agents">): string {
  return config.agents.default;
}

export function resolveDefaultAgentCommand(config: Pick<RunfreeConfig, "agents">): string | undefined {
  return resolveAgentCommand(config, resolveDefaultAgentName(config));
}

function readConfigPath(projectRoot: string): string {
  return projectRunfreePath(projectRoot, "config");
}

function readConfigResultFromPath(projectRoot: string, configPath: string): ConfigReadResult {
  const source = safeReadProjectFile(projectRoot, configPath);
  if (source === undefined) return { config: defaultConfig() };
  try {
    const defaults = defaultConfig();
    const parsed = JSON.parse(source) as Partial<RunfreeConfig> & {
      agent?: unknown;
      agents?: unknown;
      paths?: unknown;
      project?: unknown;
      version?: unknown;
    };
    const version = validateConfigVersion(parsed.version);
    const agent = parsed.agent === undefined
      ? undefined
      : validateAgentCommandConfig(parsed.agent, "agent");
    const agents = normalizeAgentsConfig(defaults.agents, parsed.agents, agent);
    const project = validateProjectConfig(parsed.project);
    const runtime = validateRuntimeConfig(
      projectRoot,
      mergeObjectConfig(defaults.runtime, parsed.runtime, "runtime") as RunfreeConfig["runtime"],
      version,
    );
    const config: RunfreeConfig = {
      version,
      project: project.config,
      agents,
      runtime,
    };
    const needsMigration = version < RUNFREE_CONFIG_VERSION
      || parsed.agent !== undefined
      || project.legacyKeys.length > 0
      || parsed.paths !== undefined;
    return {
      config,
      migration: needsMigration
        ? { fromVersion: version, toVersion: RUNFREE_CONFIG_VERSION }
        : undefined,
    };
  } catch (error) {
    die(`invalid ${path.relative(projectRoot, configPath)}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function readConfigResult(projectRoot: string): ConfigReadResult {
  assertOptionalNormalProjectDirectory(
    projectRoot,
    projectRunfreePath(projectRoot, "root"),
    "project .runfree root",
  );
  return readConfigResultFromPath(projectRoot, readConfigPath(projectRoot));
}

export function readConfig(projectRoot: string): RunfreeConfig {
  return readConfigResult(projectRoot).config;
}

export function projectInfo(projectRoot: string, env: NodeJS.ProcessEnv = process.env): ProjectInfo {
  const { config, migration } = readConfigResult(projectRoot);
  const runfreeDir = projectRunfreePath(projectRoot, "root");
  const policyPath = projectRunfreePath(projectRoot, "networkPolicy");
  const stateDir = path.join(runfreeStateRoot(env), "projects", projectHash(projectRoot));
  const claudeDir = path.join(stateDir, "claude");
  const codexDir = path.join(stateDir, "codex");
  const mountsDir = path.join(stateDir, "mounts");
  return {
    config,
    configMigration: migration,
    paths: {
      runfreeDir,
      agentEnvPath: projectRunfreePath(projectRoot, "agentEnv"),
      claudeConfigPath: path.join(stateDir, "claude.json"),
      claudeMcpConfigPath: path.join(mountsDir, "claude-mcp.json"),
      claudeDir,
      codexDir,
      configPath: readConfigPath(projectRoot),
      ...projectControlPaths(stateDir),
      gitConfigPath: path.join(stateDir, "gitconfig"),
      inboxDir: path.join(stateDir, "inbox"),
      projectCodexDirMaskPath: path.join(mountsDir, "project-codex-mask"),
      mcpOperationPolicyPath: path.join(stateDir, "mcp-operation-policy.json"),
      mcpOAuthPolicyPath: path.join(stateDir, "oauth-mediation-policy.json"),
      proxyCaCertDir: path.join(stateDir, "proxy-ca", "public"),
      proxyCaKeyDir: path.join(stateDir, "proxy-ca", "private"),
      policyPath,
      sessionsDir: path.join(stateDir, "sessions"),
      stateDir,
      tokenConfigPath: path.join(runfreeConfigRoot(env), "projects", projectHash(projectRoot), "tokens.json"),
    },
  };
}

function migrateProjectConfig(project: ProjectInfo, env: NodeJS.ProcessEnv, notes: string[]): boolean {
  if (!project.configMigration || !fs.existsSync(project.paths.configPath)) return false;
  const projectRoot = path.dirname(project.paths.runfreeDir);
  const raw = JSON.parse(fs.readFileSync(project.paths.configPath, "utf8")) as Record<string, unknown>;
  copyConfiguredPolicyIfPresent(projectRoot, raw, DEFAULT_NETWORK_POLICY_PATH, project.paths.policyPath);
  const legacyPolicy = safeReadProjectFile(projectRoot, project.paths.policyPath);
  const desiredPolicy = migrateLegacyDesiredPolicy({
    configWriteApproval: project.config.runtime.writeApproval,
    onNote: (note) => notes.push(note),
    policy: legacyPolicy === undefined ? { hosts: [] } : JSON.parse(legacyPolicy) as unknown,
    services: raw.services,
  });
  safeReplaceProjectFile(
    projectRoot,
    project.paths.policyPath,
    `${JSON.stringify(desiredPolicy, null, 2)}\n`,
    0o600,
  );
  const runtime = { ...project.config.runtime };
  delete runtime.writeApproval;
  const migrated: Record<string, unknown> = {
    ...raw,
    version: RUNFREE_CONFIG_VERSION,
    agents: project.config.agents,
    runtime,
  };
  delete migrated.agent;
  delete migrated.project;
  delete migrated.paths;
  delete migrated.services;
  if (Object.keys(project.config.project).length > 0) migrated.project = project.config.project;
  safeReplaceProjectFile(projectRoot, project.paths.configPath, `${JSON.stringify(migrated, null, 2)}\n`, 0o600);
  const migratedProject = projectInfo(projectRoot, env);
  importProvenLegacyNetworkApproval(projectRoot, project, migratedProject, desiredPolicy);
  return true;
}

function assertHostOwnedPathOutsideProject(projectRoot: string, filePath: string, label: string): void {
  if (isPathInsideByRealpath(projectRoot, filePath)) {
    die(`${label} must be outside the project: ${filePath}`);
  }
}

function configuredNetworkPolicyPath(raw: Record<string, unknown>, fallback: string): string {
  if (!isRecord(raw.paths)) return fallback;
  const configured = raw.paths.networkPolicy;
  if (typeof configured !== "string" || configured.trim() === "") return fallback;
  return configured;
}

function copyConfiguredPolicyIfPresent(
  projectRoot: string,
  raw: Record<string, unknown>,
  fallbackPolicyPath: string,
  destinationPath: string,
): void {
  const sourcePath = resolveProjectPath(projectRoot, configuredNetworkPolicyPath(raw, fallbackPolicyPath));
  if (path.resolve(sourcePath) === path.resolve(destinationPath)) return;
  if (!fs.existsSync(sourcePath) || fs.existsSync(destinationPath)) return;
  safeCopyProjectFile(projectRoot, sourcePath, destinationPath, 0o600);
}

function ensureRunfreeLocalGitignore(project: ProjectInfo): void {
  const projectRoot = path.dirname(project.paths.runfreeDir);
  const ignorePath = projectRunfreePath(projectRoot, "gitignore");
  const entries = ["state/", "config/tokens.json", "config/agent.env"];
  ensureSafeProjectDir(projectRoot, project.paths.runfreeDir, 0o700);
  const current = safeReadProjectFile(projectRoot, ignorePath) ?? "";
  const missing = entries.filter((entry) => !current.split(/\r?\n/).includes(entry));
  if (missing.length === 0) return;
  const prefix = current === "" || current.endsWith("\n") ? "" : "\n";
  safeReplaceProjectFile(projectRoot, ignorePath, `${current}${prefix}${missing.join("\n")}\n`, 0o600);
}

export function ensureProject(
  projectRoot: string,
  templatesDir: string,
  env: NodeJS.ProcessEnv = process.env,
  options: { migrateConfig?: boolean; migrationProof?: typeof QUIESCED_CONFIG_MIGRATION } = {},
): ProjectInfo {
  let project = projectInfo(projectRoot, env);
  let configMigrated: ConfigMigrationNotice | undefined;
  fs.mkdirSync(projectRoot, { recursive: true, mode: 0o755 });
  ensureSafeProjectDir(projectRoot, project.paths.runfreeDir, 0o700);
  ensureSafeProjectDir(projectRoot, path.dirname(project.paths.configPath), 0o700);
  ensureSafeProjectDir(projectRoot, path.dirname(project.paths.policyPath), 0o700);
  fs.mkdirSync(project.paths.stateDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(project.paths.claudeDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(project.paths.codexDir, { recursive: true, mode: 0o700 });
  assertHostOwnedPathOutsideProject(projectRoot, project.paths.tokenConfigPath, "token source config path");
  fs.mkdirSync(path.dirname(project.paths.tokenConfigPath), { recursive: true, mode: 0o700 });
  if (!fs.existsSync(project.paths.claudeConfigPath)) {
    fs.writeFileSync(project.paths.claudeConfigPath, "{}\n", { mode: 0o600 });
  }
  ensureRunfreeLocalGitignore(project);

  if (!fs.existsSync(project.paths.configPath)) {
    safeReplaceProjectFile(projectRoot, project.paths.configPath, fs.readFileSync(path.join(templatesDir, "runfree.json")), 0o600);
  } else if (options.migrateConfig && project.configMigration) {
    if (options.migrationProof !== QUIESCED_CONFIG_MIGRATION) {
      die("project config migration requires a quiesced runtime transaction; run: runfree init");
    }
    const notes: string[] = [];
    if (migrateProjectConfig(project, env, notes)) {
      configMigrated = notes.length > 0
        ? { ...project.configMigration, notes }
        : project.configMigration;
    }
  }
  if (!fs.existsSync(project.paths.policyPath)) {
    safeReplaceProjectFile(projectRoot, project.paths.policyPath, fs.readFileSync(path.join(templatesDir, "network-policy.json")), 0o600);
  }

  project = projectInfo(projectRoot, env);
  project.configMigrated = configMigrated;
  return project;
}

// Raw (unknown-key-preserving) read of .runfree/runfree.json. The typed
// config drops unknown top-level keys such as `services`; any rewrite that
// must preserve them has to go through this raw object.
export function readRawProjectConfig(projectRoot: string, configPath: string): Record<string, unknown> {
  assertOptionalNormalProjectDirectory(
    projectRoot,
    projectRunfreePath(projectRoot, "root"),
    "project .runfree root",
  );
  const raw = safeReadProjectFile(projectRoot, configPath);
  if (raw === undefined) return {};
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch (error) {
    die(`invalid ${path.relative(projectRoot, configPath)}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export function ensureProjectAgentImage(
  projectRoot: string,
  templatesDir: string,
  env: NodeJS.ProcessEnv = process.env,
  options: { migrationProof?: typeof QUIESCED_CONFIG_MIGRATION } = {},
): AgentImageInitResult {
  const project = ensureProject(projectRoot, templatesDir, env, {
    migrateConfig: true,
    migrationProof: options.migrationProof,
  });
  const existingBuild = project.config.runtime.agent?.build;
  const usesDefaultDockerfile = existingBuild === undefined || existingBuild.dockerfile === DEFAULT_AGENT_DOCKERFILE_PATH;
  const dockerfilePath = path.resolve(projectRoot, existingBuild?.dockerfile ?? DEFAULT_AGENT_DOCKERFILE_PATH);
  const rawConfig = existingBuild ? undefined : readRawProjectConfig(projectRoot, project.paths.configPath);
  let dockerfileCreated = false;

  if (usesDefaultDockerfile) {
    const existingDockerfile = safeReadProjectFile(projectRoot, dockerfilePath);
    if (existingDockerfile === undefined) {
      safeReplaceProjectFile(projectRoot, dockerfilePath, DEFAULT_AGENT_DOCKERFILE, 0o600);
      dockerfileCreated = true;
    }
    if (safeReadProjectFile(projectRoot, path.resolve(projectRoot, DEFAULT_AGENT_DOCKERIGNORE_PATH)) === undefined) {
      safeReplaceProjectFile(projectRoot, path.resolve(projectRoot, DEFAULT_AGENT_DOCKERIGNORE_PATH), DEFAULT_AGENT_DOCKERIGNORE, 0o600);
    }
  }

  let configUpdated = false;
  if (!existingBuild) {
    const runtimeAgent: RuntimeAgentConfig = {
      ...(project.config.runtime.agent ?? {}),
      build: {
        context: DEFAULT_AGENT_BUILD_CONTEXT,
        dockerfile: DEFAULT_AGENT_DOCKERFILE_PATH,
      },
    };
    const updated: Record<string, unknown> = {
      ...(rawConfig ?? {}),
      version: RUNFREE_CONFIG_VERSION,
      agents: project.config.agents,
      runtime: {
        ...project.config.runtime,
        agent: runtimeAgent,
      },
    };
    delete updated.agent;
    delete updated.project;
    delete updated.paths;
    if (Object.keys(project.config.project).length > 0) updated.project = project.config.project;
    safeReplaceProjectFile(projectRoot, project.paths.configPath, `${JSON.stringify(updated, null, 2)}\n`, 0o600);
    configUpdated = true;
  }

  return {
    project,
    dockerfilePath,
    dockerfileCreated,
    configUpdated,
  };
}

export function assertProjectPolicy(project: ProjectInfo): void {
  const projectRoot = path.dirname(project.paths.runfreeDir);
  const raw = safeReadProjectFile(projectRoot, project.paths.policyPath);
  if (raw === undefined) {
    die(`missing project network policy: ${project.paths.policyPath}\nrun: runfree init`);
  }
  try {
    validateDesiredNetworkPolicy(JSON.parse(raw) as unknown);
  } catch (error) {
    die(`invalid project network policy: ${error instanceof Error ? error.message : String(error)}`);
  }
}
