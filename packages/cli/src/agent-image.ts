
import fs from "node:fs";
import path from "node:path";

import { agentDescriptorRuntimeInputs } from "./agents.ts";
import type { AgentBuildConfig, RunfreeConfig } from "./config.ts";
import {
  RUNFREE_RUNTIME_COMPONENTS,
  RUNFREE_RUNTIME_DIGEST,
  RUNFREE_VERSION,
} from "./embedded-assets.generated.ts";
import { die } from "./errors.ts";
import { projectHash } from "./project-identity.ts";
import { PROJECT_RUNFREE_PATHS } from "./runfree-consumer-registry.ts";
import {
  assertNormalDirectory,
  assertNormalFile,
  assertPathInside,
  copyRegularFileNoFollow,
  isPathInside,
  relativeDisplay,
  statKind,
} from "./safe-fs.ts";
import { stableJson, sha256Hex as sha256 } from "./strict-primitives.ts";

export type AgentBuildPaths = {
  contextPath: string;
  dockerfilePath: string;
};

export type AgentBuildContextKind = "narrow" | "wide";

export type BuildContextManifestEntry = {
  mode: number;
  path: string;
  type: "directory";
} | {
  mode: number;
  path: string;
  sha256: string;
  size: number;
  type: "file";
};

export type StagedAgentBuildContext = AgentBuildPaths & {
  kind: "narrow";
  manifest: BuildContextManifestEntry[];
};

const RUNFREE_IMAGE_DIGEST_PREFIX = "sha256:";
const NARROW_AGENT_BUILD_CONTEXT = PROJECT_RUNFREE_PATHS.image;
const BUILD_CONTEXT_STAGE_DIR = "build-context";
const WIDE_CONTEXT_APPROVAL_FILE = "approved-build-contexts.json";
const WIDE_CONTEXT_APPROVAL_SCHEMA_VERSION = 1;


function sha256Label(value: string | Buffer): string {
  return `${RUNFREE_IMAGE_DIGEST_PREFIX}${sha256(value)}`;
}

function digestTag(digest: string): string {
  return digest.replace(/^sha256:/, "sha256-");
}


export function normalizedAgentBuildConfig(build: AgentBuildConfig): AgentBuildConfig {
  const sortedArgs = build.args
    ? Object.fromEntries(Object.entries(build.args).sort(([left], [right]) => left.localeCompare(right)))
    : undefined;
  return {
    context: build.context,
    dockerfile: build.dockerfile,
    ...(build.target === undefined ? {} : { target: build.target }),
    ...(sortedArgs === undefined ? {} : { args: sortedArgs }),
  };
}

function assertRealpathInside(rootPath: string, targetPath: string, message: string): void {
  const realRoot = fs.realpathSync.native(rootPath);
  const realTarget = fs.realpathSync.native(targetPath);
  if (!isPathInside(realRoot, realTarget)) {
    die(message);
  }
}

function assertDockerfileInsideContext(contextPath: string, dockerfilePath: string): void {
  if (!isPathInside(contextPath, dockerfilePath)) {
    die("Dockerfile must resolve inside the agent build context");
  }
}

export function agentBuildConfig(config: RunfreeConfig): AgentBuildConfig | undefined {
  return config.runtime.agent?.build;
}

export function resolveAgentBuildPaths(projectRoot: string, build: AgentBuildConfig): AgentBuildPaths {
  const contextPath = path.resolve(projectRoot, build.context);
  const dockerfilePath = path.resolve(projectRoot, build.dockerfile);
  assertPathInside(projectRoot, contextPath, "runtime.agent.build.context");
  assertPathInside(projectRoot, dockerfilePath, "runtime.agent.build.dockerfile");
  return { contextPath, dockerfilePath };
}

export function requireAgentBuildPaths(projectRoot: string, build: AgentBuildConfig): AgentBuildPaths {
  const paths = resolveAgentBuildPaths(projectRoot, build);
  assertNormalDirectory(projectRoot, paths.contextPath, "agent build context");
  assertNormalFile(projectRoot, paths.dockerfilePath, "agent Dockerfile");
  assertDockerfileInsideContext(paths.contextPath, paths.dockerfilePath);
  assertRealpathInside(projectRoot, paths.contextPath, "runtime.agent.build.context real path must resolve inside the project root");
  assertRealpathInside(projectRoot, paths.dockerfilePath, "runtime.agent.build.dockerfile real path must resolve inside the project root");
  assertRealpathInside(paths.contextPath, paths.dockerfilePath, "Dockerfile real path must resolve inside the agent build context");
  return paths;
}

export function classifyAgentBuildContext(projectRoot: string, build: AgentBuildConfig): AgentBuildContextKind {
  const contextPath = path.resolve(projectRoot, build.context);
  const narrowRoot = path.resolve(projectRoot, NARROW_AGENT_BUILD_CONTEXT);
  return isPathInside(narrowRoot, contextPath) ? "narrow" : "wide";
}

type SourceBuildContextEntry = {
  path: string;
  relativePath: string;
  stat: fs.Stats;
};

function validateBuildContextTree(projectRoot: string, contextPath: string): SourceBuildContextEntry[] {
  const rootStat = assertNormalDirectory(projectRoot, contextPath, "agent build context");
  const projectRealPath = fs.realpathSync.native(projectRoot);
  const rootRealPath = fs.realpathSync.native(contextPath);
  if (!isPathInside(projectRealPath, rootRealPath)) {
    die("agent build context real path must resolve inside the project root");
  }
  const entries: SourceBuildContextEntry[] = [];

  const visit = (entryPath: string, stat: fs.Stats = fs.lstatSync(entryPath)): void => {
    const relativePath = relativeDisplay(contextPath, entryPath);
    if (stat.isSymbolicLink()) {
      die(`agent build context contains symlink: ${relativePath}`);
    }
    if (stat.isDirectory()) {
      const realPath = fs.realpathSync.native(entryPath);
      if (!isPathInside(rootRealPath, realPath)) {
        die(`agent build context path escapes selected context: ${relativePath}`);
      }
      if (relativePath !== ".") entries.push({ path: entryPath, relativePath, stat });
      for (const child of fs.readdirSync(entryPath).sort((left, right) => left.localeCompare(right))) {
        visit(path.join(entryPath, child));
      }
      return;
    }
    if (stat.isFile()) {
      if (stat.nlink !== 1) {
        die(`agent build context contains hard link: ${relativePath}`);
      }
      const realPath = fs.realpathSync.native(entryPath);
      if (!isPathInside(rootRealPath, realPath)) {
        die(`agent build context path escapes selected context: ${relativePath}`);
      }
      entries.push({ path: entryPath, relativePath, stat });
      return;
    }
    die(`agent build context contains ${statKind(stat)}: ${relativePath}`);
  };

  visit(contextPath, rootStat);
  return entries.sort((left, right) => left.relativePath.localeCompare(right.relativePath));
}

function manifestEntry(entry: SourceBuildContextEntry): BuildContextManifestEntry {
  const mode = entry.stat.mode & 0o777;
  if (entry.stat.isDirectory()) {
    return {
      mode,
      path: entry.relativePath,
      type: "directory",
    };
  }
  const contents = fs.readFileSync(entry.path);
  return {
    mode,
    path: entry.relativePath,
    sha256: sha256Label(contents),
    size: entry.stat.size,
    type: "file",
  };
}

function buildContextManifest(projectRoot: string, contextPath: string): BuildContextManifestEntry[] {
  return validateBuildContextTree(projectRoot, contextPath).map(manifestEntry);
}

export function stagedAgentBuildContextManifest(contextPath: string): BuildContextManifestEntry[] {
  return buildContextManifest(contextPath, contextPath);
}

export function stageAgentBuildContext(projectRoot: string, build: AgentBuildConfig, stateDir: string): StagedAgentBuildContext {
  if (classifyAgentBuildContext(projectRoot, build) !== "narrow") {
    die("only .runfree/image agent build contexts can be staged automatically");
  }
  const { contextPath, dockerfilePath } = requireAgentBuildPaths(projectRoot, build);
  const entries = validateBuildContextTree(projectRoot, contextPath);
  const manifest = entries.map(manifestEntry);
  const stagingRoot = path.join(stateDir, BUILD_CONTEXT_STAGE_DIR);
  const tmpRoot = `${stagingRoot}.${process.pid}.${Date.now().toString(36)}.tmp`;
  fs.rmSync(tmpRoot, { recursive: true, force: true });
  fs.mkdirSync(path.dirname(stagingRoot), { recursive: true, mode: 0o700 });
  fs.mkdirSync(tmpRoot, { recursive: false, mode: 0o700 });
  try {
    for (const entry of entries) {
      const destinationPath = path.join(tmpRoot, entry.relativePath);
      if (entry.stat.isDirectory()) {
        fs.mkdirSync(destinationPath, { recursive: false, mode: entry.stat.mode & 0o777 });
        fs.chmodSync(destinationPath, entry.stat.mode & 0o777);
        continue;
      }
      fs.mkdirSync(path.dirname(destinationPath), { recursive: true, mode: 0o700 });
      copyRegularFileNoFollow(entry.path, destinationPath, entry.stat);
    }
    fs.rmSync(stagingRoot, { recursive: true, force: true });
    fs.renameSync(tmpRoot, stagingRoot);
    fs.chmodSync(stagingRoot, 0o700);
  } catch (error) {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
    throw error;
  }

  const dockerfileRelativePath = path.relative(contextPath, dockerfilePath);
  return {
    contextPath: stagingRoot,
    dockerfilePath: path.join(stagingRoot, dockerfileRelativePath),
    kind: "narrow",
    manifest,
  };
}

type WideBuildContextApproval = {
  approvedAt: string;
  build: AgentBuildConfig;
  context: string;
  dockerfile: string;
  dockerfileSha256: string;
  key: string;
  projectHash: string;
  schemaVersion: number;
  wide: true;
};

type WideBuildContextApprovalFile = {
  approvals: Record<string, WideBuildContextApproval>;
  projectHash: string;
  schemaVersion: number;
};

function wideBuildContextApprovalPayload(projectRoot: string, build: AgentBuildConfig): Omit<WideBuildContextApproval, "approvedAt" | "key"> {
  if (classifyAgentBuildContext(projectRoot, build) !== "wide") {
    die("agent build context is already narrow and does not require wide-context approval");
  }
  const { dockerfilePath } = requireAgentBuildPaths(projectRoot, build);
  return {
    build: normalizedAgentBuildConfig(build),
    context: build.context,
    dockerfile: build.dockerfile,
    dockerfileSha256: sha256Label(fs.readFileSync(dockerfilePath)),
    projectHash: projectHash(projectRoot),
    schemaVersion: WIDE_CONTEXT_APPROVAL_SCHEMA_VERSION,
    wide: true,
  };
}

function wideBuildContextApprovalKey(projectRoot: string, build: AgentBuildConfig): string {
  return sha256(JSON.stringify(wideBuildContextApprovalPayload(projectRoot, build)));
}

export function wideBuildContextApprovalPath(stateDir: string): string {
  return path.join(stateDir, WIDE_CONTEXT_APPROVAL_FILE);
}

function emptyApprovalFile(projectRoot: string): WideBuildContextApprovalFile {
  return {
    approvals: {},
    projectHash: projectHash(projectRoot),
    schemaVersion: WIDE_CONTEXT_APPROVAL_SCHEMA_VERSION,
  };
}

function readWideBuildContextApprovals(projectRoot: string, stateDir: string): WideBuildContextApprovalFile {
  const approvalPath = wideBuildContextApprovalPath(stateDir);
  if (!fs.existsSync(approvalPath)) return emptyApprovalFile(projectRoot);
  try {
    const parsed = JSON.parse(fs.readFileSync(approvalPath, "utf8")) as Partial<WideBuildContextApprovalFile>;
    if (
      parsed.schemaVersion !== WIDE_CONTEXT_APPROVAL_SCHEMA_VERSION
      || parsed.projectHash !== projectHash(projectRoot)
      || parsed.approvals === undefined
      || parsed.approvals === null
      || Array.isArray(parsed.approvals)
      || typeof parsed.approvals !== "object"
    ) {
      return emptyApprovalFile(projectRoot);
    }
    return parsed as WideBuildContextApprovalFile;
  } catch {
    return emptyApprovalFile(projectRoot);
  }
}

export function hasWideBuildContextApproval(projectRoot: string, build: AgentBuildConfig, stateDir: string): boolean {
  if (classifyAgentBuildContext(projectRoot, build) !== "wide") return true;
  const approvalKey = wideBuildContextApprovalKey(projectRoot, build);
  return readWideBuildContextApprovals(projectRoot, stateDir).approvals[approvalKey]?.key === approvalKey;
}

export function saveWideBuildContextApproval(projectRoot: string, build: AgentBuildConfig, stateDir: string): void {
  const payload = wideBuildContextApprovalPayload(projectRoot, build);
  const key = sha256(JSON.stringify(payload));
  const approvals = readWideBuildContextApprovals(projectRoot, stateDir);
  approvals.approvals[key] = {
    ...payload,
    approvedAt: new Date().toISOString(),
    key,
  };
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const approvalPath = wideBuildContextApprovalPath(stateDir);
  const tmpPath = `${approvalPath}.${process.pid}.${Date.now().toString(36)}.tmp`;
  fs.writeFileSync(tmpPath, `${JSON.stringify(approvals, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(tmpPath, approvalPath);
  fs.chmodSync(approvalPath, 0o600);
}

export function wideBuildContextApprovalPrompt(build: AgentBuildConfig): string {
  return [
    `This project wants to build a Runfree agent image with build context "${build.context}".`,
    "Docker build runs before the Runfree sandbox and can read files in that",
    "context or send them over the network. Approve this build context for this",
    "project and Dockerfile? [y/N] ",
  ].join("\n");
}

export type LegacyInjectedBuildArgument = Readonly<{
  name: "RUNFREE_RUNTIME_DIGEST" | "RUNFREE_VERSION";
  value: string;
}>;

export type SelectedAgentImageInput =
  | Readonly<{
    digest: string;
    kind: "embedded";
  }>
  | Readonly<{
    contextFingerprint: readonly BuildContextManifestEntry[] | Readonly<{ dockerfileSha256: string }>;
    contextKind: AgentBuildContextKind;
    digest: string;
    kind: "project";
    referencedLegacyInjectedArguments: readonly LegacyInjectedBuildArgument[];
  }>;

function dockerfileIdentifierTokens(dockerfile: Buffer): ReadonlySet<string> {
  return new Set(dockerfile.toString("utf8").match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? []);
}

export function selectedProjectAgentImageInput(
  build: AgentBuildConfig,
  contextKind: AgentBuildContextKind,
  contextFingerprint: readonly BuildContextManifestEntry[] | Readonly<{ dockerfileSha256: string }>,
  dockerfile: Buffer,
  inputs: {
    embeddedAgentImageInputDigest?: string;
    legacyRuntimeDigest?: string;
    version?: string;
  } = {},
): Extract<SelectedAgentImageInput, { kind: "project" }> {
  const embeddedAgentImageInputDigest = inputs.embeddedAgentImageInputDigest
    ?? RUNFREE_RUNTIME_COMPONENTS.agentImageInputDigest;
  const tokens = dockerfileIdentifierTokens(dockerfile);
  const referencedLegacyInjectedArguments: LegacyInjectedBuildArgument[] = [];
  if (tokens.has("RUNFREE_RUNTIME_DIGEST")) {
    referencedLegacyInjectedArguments.push({
      name: "RUNFREE_RUNTIME_DIGEST",
      value: inputs.legacyRuntimeDigest ?? RUNFREE_RUNTIME_DIGEST,
    });
  }
  if (tokens.has("RUNFREE_VERSION")) {
    referencedLegacyInjectedArguments.push({ name: "RUNFREE_VERSION", value: inputs.version ?? RUNFREE_VERSION });
  }
  referencedLegacyInjectedArguments.sort(({ name: left }, { name: right }) => left.localeCompare(right));
  const digest = sha256Label(stableJson({
    schemaVersion: RUNFREE_RUNTIME_COMPONENTS.schemaVersion,
    embeddedAgentImageInputDigest,
    normalizedBuildConfig: normalizedAgentBuildConfig(build),
    contextKind,
    contextFingerprint,
    referencedLegacyInjectedArguments,
  }));
  return {
    contextFingerprint,
    contextKind,
    digest,
    kind: "project",
    referencedLegacyInjectedArguments,
  };
}

export function selectedAgentImageInput(
  projectRoot: string,
  config: RunfreeConfig,
  inputs: {
    embeddedAgentImageInputDigest?: string;
    legacyRuntimeDigest?: string;
    version?: string;
  } = {},
): SelectedAgentImageInput {
  const embeddedAgentImageInputDigest = inputs.embeddedAgentImageInputDigest
    ?? RUNFREE_RUNTIME_COMPONENTS.agentImageInputDigest;
  const build = agentBuildConfig(config);
  if (!build) return { digest: embeddedAgentImageInputDigest, kind: "embedded" };

  const { contextPath, dockerfilePath } = requireAgentBuildPaths(projectRoot, build);
  const dockerfile = fs.readFileSync(dockerfilePath);
  const contextKind = classifyAgentBuildContext(projectRoot, build);
  const contextFingerprint = contextKind === "narrow"
    ? buildContextManifest(projectRoot, contextPath)
    : { dockerfileSha256: sha256Label(dockerfile) };
  return selectedProjectAgentImageInput(build, contextKind, contextFingerprint, dockerfile, {
    ...inputs,
    embeddedAgentImageInputDigest,
  });
}

/** @deprecated Use component state and selectedAgentImageInput. */
export function effectiveRuntimeDigest(projectRoot: string, config: RunfreeConfig): string {
  const runtimeInputs = {
    agents: agentDescriptorRuntimeInputs(),
    runtimeDigest: RUNFREE_RUNTIME_DIGEST,
    version: RUNFREE_VERSION,
  };
  const build = agentBuildConfig(config);
  if (!build) return sha256Label(JSON.stringify(runtimeInputs));

  const { contextPath, dockerfilePath } = requireAgentBuildPaths(projectRoot, build);
  const contextKind = classifyAgentBuildContext(projectRoot, build);
  const payload = {
    ...runtimeInputs,
    build: normalizedAgentBuildConfig(build),
    dockerfile: sha256Label(fs.readFileSync(dockerfilePath)),
    ...(contextKind === "narrow" ? { contextManifest: buildContextManifest(projectRoot, contextPath) } : {}),
  };
  return `${RUNFREE_IMAGE_DIGEST_PREFIX}${sha256(JSON.stringify(payload))}`;
}

export function agentBaseImageTag(inputDigest: string = RUNFREE_RUNTIME_COMPONENTS.agentImageInputDigest): string {
  return `runfree/agent-base:${digestTag(inputDigest)}`;
}

export function agentRuntimeImageTag(inputDigest: string = RUNFREE_RUNTIME_COMPONENTS.agentImageInputDigest): string {
  return `runfree/agent-runtime:${digestTag(inputDigest)}`;
}

export function proxyRuntimeImageTag(inputDigest: string = RUNFREE_RUNTIME_COMPONENTS.proxyImageInputDigest): string {
  return `runfree/proxy-runtime:${digestTag(inputDigest)}`;
}

export function projectAgentImageTag(projectRoot: string, inputDigest: string): string {
  return `runfree/agent-project:${projectHash(projectRoot)}-${digestTag(inputDigest)}`;
}
