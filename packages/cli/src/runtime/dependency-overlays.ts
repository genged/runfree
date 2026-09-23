import { resolveAgentExecTarget } from "./agent-exec-target.ts";
import fs from "node:fs";
import path from "node:path";

import { die } from "../errors.ts";
import { runfreeConfigRoot, runfreeDataRoot, runfreeStateRoot } from "../paths.ts";
import { projectHash } from "../project-identity.ts";
import { atomicReplaceFile } from "../safe-fs.ts";
import { flushWarnings, runfreeLog, warn } from "../warnings.ts";
import { projectPhysicalRoot, runDockerExecRoot } from "./attach.ts";
import type { RuntimeComposeMount } from "./compose.ts";
import { AGENT_UID_GID } from "./constants.ts";
import { dependencyArtifactKindForRelativePath } from "./dependency-artifacts.ts";
import {
  dependencyStoreEnvironmentNames,
  runtimeToolStoreVolumes,
  type DependencyEcosystem,
  type DependencyStoreVolume,
  type DependencyToolName,
  type JavaScriptPackageManagerName,
  type PythonPackageManagerName,
  type RuntimeToolStoreName,
} from "./dependency-stores.ts";
import { dockerClientEnvOptions, envOptions, parseDockerJson, shellSingleQuote, type RuntimeDocker } from "./docker.ts";
import { composeProjectName } from "./env.ts";
import { prepareGitRepositoryLayoutResult, readPersistedGitLayoutPlan } from "./git-layout.ts";
import { runEphemeralHelper } from "./ephemeral-helper.ts";
import { dependencyArtifactTarget, normalizeContainerPath } from "./mount-target-policy.ts";
import { composeManagedVolumeName } from "./session-container-template.ts";
import { assertComposeManagedLocalVolume } from "./session-named-volume-proof.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";

export type {
  DependencyEcosystem,
  DependencyStoreVolume,
  DependencyToolName,
  JavaScriptPackageManagerName,
  PythonPackageManagerName,
  RuntimeToolStoreName,
} from "./dependency-stores.ts";
import { remedy } from "../remedies.ts";

export type DependencyOverlayMode = "auto" | "off";

export type DependencyConfidence = "high" | "medium" | "low";

export type DependencyRoot = {
  ecosystem: DependencyEcosystem;
  tool: DependencyToolName;
  hostRelativePath: string;
  evidence: string;
  confidence: DependencyConfidence;
  reason: string;
  packageManager?: JavaScriptPackageManagerName;
};

export type DependencyWorkspaceRoot = DependencyRoot;

export type DependencyOverlay = {
  path: string;
  hostRelativePath: string;
  volume: string;
  reason: string;
};

export type DependencyIgnoredCandidate = {
  hostRelativePath: string;
  reason: string;
};

export type DependencyWarning = {
  hostRelativePath: string;
  reason: string;
};

export type DependencyInstallCommand = {
  ecosystem: DependencyEcosystem;
  tool: DependencyToolName;
  hostRelativePath: string;
  packageManager?: JavaScriptPackageManagerName;
  command: string;
};

export type DependencyOverlayPlan = {
  version: 1;
  projectRoot: string;
  workspaceHash: string;
  mode: DependencyOverlayMode;
  packageManagers: JavaScriptPackageManagerName[];
  roots: DependencyRoot[];
  workspaceRoots: DependencyWorkspaceRoot[];
  overlays: DependencyOverlay[];
  ignoredCandidates: DependencyIgnoredCandidate[];
  warnings: DependencyWarning[];
  storeVolumes: DependencyStoreVolume[];
  installCommands: DependencyInstallCommand[];
  installCommand?: string;
};

export type DependencyOverlayRuntimeMountSignature = {
  type: "volume";
  source: string;
  target: string;
  noCopy: boolean;
};

export type DependencyOverlayRuntimeSignature = {
  version: 1;
  mounts: DependencyOverlayRuntimeMountSignature[];
  namedVolumes: string[];
  environment: Record<string, string>;
};

export type DependencyOverlayPlanOptions = {
  mode?: DependencyOverlayMode;
  gitIgnoredPaths?: string[];
  gitTrackedPaths?: string[];
  gitUntrackedPaths?: string[];
  ignoredRootPaths?: string[];
};

const PACKAGE_MANAGER_PRIORITY: JavaScriptPackageManagerName[] = ["pnpm", "npm", "yarn", "bun"];
const PYTHON_MANAGER_PRIORITY: PythonPackageManagerName[] = ["uv", "poetry", "pipenv", "pdm", "hatch", "pip"];
const ECOSYSTEM_ORDER: DependencyEcosystem[] = ["javascript", "python"];
const RUNTIME_TOOL_STORE_ORDER: RuntimeToolStoreName[] = [
  "pnpm",
  "npm",
  "yarn",
  "bun",
  "pip",
  "uv",
  "poetry",
  "pipenv",
  "pdm",
  "hatch-cache",
  "hatch-data",
];
const SKIPPED_SCAN_DIRS = new Set([".git", ".runfree"]);

function posixRelative(relativePath: string): string {
  const normalized = relativePath.replaceAll(path.sep, path.posix.sep).replace(/\/+$/g, "");
  return normalized === "" ? "." : normalized;
}

function normalizeInputRelativePath(value: string): string {
  const withoutNul = value.replace(/\0/g, "");
  const normalized = path.posix.normalize(withoutNul.replaceAll("\\", "/").replace(/\/+$/g, ""));
  return normalized === "" ? "." : normalized;
}

function assertSafeRelativePath(relativePath: string): void {
  if (relativePath === ".") return;
  if (path.posix.isAbsolute(relativePath) || relativePath.split("/").includes("..")) {
    throw new Error(`dependency overlay path escapes the project root: ${relativePath}`);
  }
}

function projectPath(projectRoot: string, relativePath: string): string {
  assertSafeRelativePath(relativePath);
  return relativePath === "." ? projectRoot : path.join(projectRoot, ...relativePath.split("/"));
}

function hasFile(projectRoot: string, relativePath: string): boolean {
  try {
    return fs.statSync(projectPath(projectRoot, relativePath)).isFile();
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return false;
    throw error;
  }
}

function isPythonVirtualEnv(projectRoot: string, hostRelativePath: string): boolean {
  if (dependencyArtifactKindForRelativePath(hostRelativePath) !== "python-venv") return false;
  return hasFile(projectRoot, path.posix.join(normalizeInputRelativePath(hostRelativePath), "pyvenv.cfg"));
}

function readPackageJson(projectRoot: string, relativeRoot: string): Record<string, unknown> | undefined {
  const packagePath = path.join(projectPath(projectRoot, relativeRoot), "package.json");
  if (!fs.existsSync(packagePath)) return undefined;
  try {
    const parsed = JSON.parse(fs.readFileSync(packagePath, "utf8")) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : undefined;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`could not parse ${posixRelative(path.relative(projectRoot, packagePath))}: ${detail}`);
  }
}

function packageManagerFromPackageJson(pkg: Record<string, unknown> | undefined): JavaScriptPackageManagerName | undefined {
  const packageManager = typeof pkg?.packageManager === "string" ? pkg.packageManager : "";
  for (const manager of PACKAGE_MANAGER_PRIORITY) {
    if (packageManager.startsWith(`${manager}@`)) return manager;
  }
  return undefined;
}

function detectPackageManager(projectRoot: string, relativeRoot: string, pkg: Record<string, unknown> | undefined): JavaScriptPackageManagerName | undefined {
  const explicit = packageManagerFromPackageJson(pkg);
  if (explicit) return explicit;
  const root = projectPath(projectRoot, relativeRoot);
  if (fs.existsSync(path.join(root, "pnpm-lock.yaml")) || fs.existsSync(path.join(root, "pnpm-workspace.yaml"))) return "pnpm";
  if (fs.existsSync(path.join(root, "package-lock.json")) || fs.existsSync(path.join(root, "npm-shrinkwrap.json"))) return "npm";
  if (fs.existsSync(path.join(root, "yarn.lock")) || fs.existsSync(path.join(root, ".yarnrc.yml"))) return "yarn";
  if (fs.existsSync(path.join(root, "bun.lock")) || fs.existsSync(path.join(root, "bun.lockb"))) return "bun";
  return undefined;
}

function splitInlineYamlList(value: string): string[] {
  const parts: string[] = [];
  let current = "";
  let quote: "'" | "\"" | undefined;
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if (quote) {
      current += char;
      if (char === quote && value[index - 1] !== "\\") quote = undefined;
      continue;
    }
    if (char === "'" || char === "\"") {
      quote = char;
      current += char;
      continue;
    }
    if (char === ",") {
      parts.push(current.trim());
      current = "";
      continue;
    }
    current += char;
  }
  if (current.trim() !== "") parts.push(current.trim());
  return parts;
}

function parseYamlStringValue(raw: string): string {
  const value = raw.trim().replace(/\s+#.*$/, "");
  if (value === "" || value === "|" || value === ">" || value.includes("&") || value.startsWith("*")) {
    throw new Error("unsupported pnpm-workspace.yaml packages syntax");
  }
  return value.replace(/^['"]|['"]$/g, "");
}

function parseYamlListBlock(source: string, key: string): string[] {
  const lines = source.split(/\r?\n/);
  const inlineIndex = lines.findIndex((line) => line.trim().startsWith(`${key}:`));
  if (inlineIndex !== -1) {
    const inline = lines[inlineIndex];
    const value = inline.trim().slice(`${key}:`.length).replace(/\s+#.*$/, "").trim();
    if (value !== "") {
      if (!value.startsWith("[") || !value.endsWith("]")) {
        throw new Error("unsupported pnpm-workspace.yaml packages syntax");
      }
      return splitInlineYamlList(value.slice(1, -1)).map(parseYamlStringValue);
    }
  }
  const start = inlineIndex !== -1 ? inlineIndex : lines.findIndex((line) => line.trim() === `${key}:`);
  if (start === -1) return [];
  const values: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (line.trim() === "" || line.trim().startsWith("#")) continue;
    if (/^\S/.test(line) && !line.trim().startsWith("-")) break;
    const match = /^\s*-\s*(.+?)\s*(?:#.*)?$/.exec(line);
    if (!match) {
      if (/^\s+\S/.test(line)) throw new Error("unsupported pnpm-workspace.yaml packages syntax");
      continue;
    }
    values.push(parseYamlStringValue(match[1]));
  }
  return values;
}

function pnpmWorkspacePatterns(projectRoot: string): string[] {
  const workspacePath = path.join(projectRoot, "pnpm-workspace.yaml");
  if (!fs.existsSync(workspacePath)) return [];
  return parseYamlListBlock(fs.readFileSync(workspacePath, "utf8"), "packages");
}

function packageJsonWorkspacePatterns(pkg: Record<string, unknown> | undefined): string[] {
  const workspaces = pkg?.workspaces;
  if (Array.isArray(workspaces)) return workspaces.filter((value): value is string => typeof value === "string");
  if (workspaces && typeof workspaces === "object" && !Array.isArray(workspaces)) {
    const packages = (workspaces as { packages?: unknown }).packages;
    if (Array.isArray(packages)) return packages.filter((value): value is string => typeof value === "string");
  }
  return [];
}

function workspacePatterns(projectRoot: string, manager: JavaScriptPackageManagerName, pkg: Record<string, unknown> | undefined): string[] {
  return manager === "pnpm" ? pnpmWorkspacePatterns(projectRoot) : packageJsonWorkspacePatterns(pkg);
}

function normalizeIgnoredRootPaths(projectRoot: string, values: string[] = []): string[] {
  const roots = new Set<string>();
  for (const value of values) {
    const resolved = path.resolve(value);
    if (resolved === projectRoot) continue;
    if (!resolved.startsWith(`${projectRoot}${path.sep}`)) continue;
    roots.add(posixRelative(path.relative(projectRoot, resolved)));
  }
  return [...roots].sort();
}

function pathInsideIgnoredRoot(relativePath: string, ignoredRoots: string[]): boolean {
  const normalized = normalizeInputRelativePath(relativePath);
  return ignoredRoots.some((root) => normalized === root || normalized.startsWith(`${root}/`));
}

function dependencyArtifactReason(projectRoot: string, hostRelativePath: string): string | undefined {
  const kind = dependencyArtifactKindForRelativePath(hostRelativePath);
  if (kind === undefined) return undefined;
  if (kind === "python-venv") return isPythonVirtualEnv(projectRoot, hostRelativePath)
    ? "python dependency dir observed on host"
    : undefined;
  if (kind === "python-pypackages") return undefined;
  return "git ignored dependency dir observed on host";
}

function ignoredDependencyScanRootPaths(projectRoot: string, gitIgnoredPaths: string[] = []): string[] {
  const roots = new Set<string>();
  for (const ignoredPath of gitIgnoredPaths) {
    const hostRelativePath = normalizeInputRelativePath(ignoredPath);
    if (hostRelativePath === "." || dependencyArtifactReason(projectRoot, hostRelativePath)) continue;
    roots.add(hostRelativePath);
  }
  return [...roots].sort();
}

function scanPackageJsonRoots(projectRoot: string, ignoredRootPaths: string[] = []): string[] {
  const roots: string[] = [];
  function visit(dir: string, relativeDir: string): void {
    if (relativeDir !== "" && pathInsideIgnoredRoot(relativeDir, ignoredRootPaths)) return;
    if (relativeDir !== "" && dependencyArtifactKindForRelativePath(relativeDir) !== undefined) return;
    const packagePath = path.join(dir, "package.json");
    if (fs.existsSync(packagePath)) roots.push(relativeDir === "" ? "." : posixRelative(relativeDir));
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (SKIPPED_SCAN_DIRS.has(entry.name)) continue;
      visit(path.join(dir, entry.name), path.posix.join(relativeDir, entry.name));
    }
  }
  visit(projectRoot, "");
  return Array.from(new Set(roots)).sort();
}

function matchSegment(pattern: string, value: string): boolean {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]");
  return new RegExp(`^${escaped}$`).test(value);
}

function matchGlob(pattern: string, value: string): boolean {
  const patternParts = normalizeInputRelativePath(pattern).split("/");
  const valueParts = normalizeInputRelativePath(value).split("/");
  function match(patternIndex: number, valueIndex: number): boolean {
    if (patternIndex === patternParts.length) return valueIndex === valueParts.length;
    const part = patternParts[patternIndex];
    if (part === "**") {
      for (let next = valueIndex; next <= valueParts.length; next += 1) {
        if (match(patternIndex + 1, next)) return true;
      }
      return false;
    }
    if (valueIndex >= valueParts.length) return false;
    return matchSegment(part, valueParts[valueIndex]) && match(patternIndex + 1, valueIndex + 1);
  }
  return match(0, 0);
}

function expandWorkspaceRoots(projectRoot: string, patterns: string[], ignoredRootPaths: string[]): string[] {
  const includes = patterns.filter((pattern) => !pattern.startsWith("!")).map(normalizeInputRelativePath);
  const excludes = patterns.filter((pattern) => pattern.startsWith("!")).map((pattern) => normalizeInputRelativePath(pattern.slice(1)));
  const packageRoots = scanPackageJsonRoots(projectRoot, ignoredRootPaths);
  const matched = new Set<string>();
  for (const pattern of includes) {
    assertSafeRelativePath(pattern);
    for (const root of packageRoots) {
      if (root !== "." && matchGlob(pattern, root)) matched.add(root);
    }
  }
  for (const pattern of excludes) {
    assertSafeRelativePath(pattern);
    for (const root of [...matched]) {
      if (matchGlob(pattern, root)) matched.delete(root);
    }
  }
  return [...matched].sort();
}

function yarnNodeModulesEnabled(projectRoot: string, pkg: Record<string, unknown> | undefined): boolean {
  const yarnRc = path.join(projectRoot, ".yarnrc.yml");
  if (fs.existsSync(yarnRc)) {
    const match = /^\s*nodeLinker:\s*['"]?([^'"\s#]+)['"]?/m.exec(fs.readFileSync(yarnRc, "utf8"));
    if (match?.[1] === "node-modules") return true;
    if (match?.[1] === "pnp") return false;
  }
  const packageManager = typeof pkg?.packageManager === "string" ? pkg.packageManager : "";
  if (packageManager.startsWith("yarn@")) return packageManager.startsWith("yarn@1.");
  return true;
}

function shouldOverlayNodeModules(projectRoot: string, manager: JavaScriptPackageManagerName, pkg: Record<string, unknown> | undefined): boolean {
  return manager !== "yarn" || yarnNodeModulesEnabled(projectRoot, pkg);
}

function addUnique<T>(values: T[], value: T, key: (value: T) => string): void {
  if (!values.some((existing) => key(existing) === key(value))) values.push(value);
}

function overlayVolumeName(workspaceHash: string, hostRelativePath: string): string {
  const normalized = normalizeInputRelativePath(hostRelativePath);
  const basename = normalized.split("/").at(-1) ?? normalized;
  let suffix: string;
  if (normalized === "node_modules") {
    suffix = "root-node-modules";
  } else if (basename === ".venv" || basename === "venv") {
    const prefix = normalized.split("/").slice(0, -1).join("-");
    suffix = prefix ? `${prefix}-python-venv` : "python-venv";
  } else if (basename === "__pypackages__") {
    const prefix = normalized.split("/").slice(0, -1).join("-");
    suffix = prefix ? `${prefix}-python-pypackages` : "python-pypackages";
  } else {
    suffix = normalized.replace(/^\.+/, "").replace(/[^a-zA-Z0-9_.-]+/g, "-").replace(/^-+|-+$/g, "");
  }
  return `runfree-deps-${workspaceHash}-${suffix || "root"}`;
}

function validateOverlayTarget(projectRoot: string, hostRelativePath: string): void {
  const parts = hostRelativePath === "." ? [] : hostRelativePath.split("/");
  let parent = projectRoot;
  for (const part of parts.slice(0, -1)) {
    parent = path.join(parent, part);
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(parent);
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") break;
      throw error;
    }
    const parentRelativePath = posixRelative(path.relative(projectRoot, parent));
    if (stat.isSymbolicLink()) throw new Error(`dependency overlay parent is a symlink: ${parentRelativePath}`);
    if (!stat.isDirectory()) throw new Error(`dependency overlay parent is not a directory: ${parentRelativePath}`);
  }

  const target = projectPath(projectRoot, hostRelativePath);
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(target);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
  if (stat.isFile()) throw new Error(`dependency overlay target is a file: ${hostRelativePath}`);
  if (stat.isSymbolicLink()) throw new Error(`dependency overlay target is a symlink: ${hostRelativePath}`);
}

function addOverlay(
  overlays: DependencyOverlay[],
  projectRoot: string,
  workspaceHash: string,
  hostRelativePath: string,
  reason: string,
  options: { validateTarget?: boolean } = {},
): void {
  const normalized = normalizeInputRelativePath(hostRelativePath);
  assertSafeRelativePath(normalized);
  if (options.validateTarget ?? true) validateOverlayTarget(projectRoot, normalized);
  addUnique(overlays, {
    hostRelativePath: normalized,
    path: `/workspace/${normalized}`,
    volume: overlayVolumeName(workspaceHash, normalized),
    reason,
  }, (overlay) => overlay.hostRelativePath);
}

function trackedPathSet(paths: string[] = []): Set<string> {
  return new Set(paths.map(normalizeInputRelativePath));
}

function hasTrackedPathUnder(hostRelativePath: string, trackedPaths: Set<string>): boolean {
  const normalized = normalizeInputRelativePath(hostRelativePath);
  return trackedPaths.has(normalized) || Array.from(trackedPaths).some((trackedPath) => trackedPath.startsWith(`${normalized}/`));
}

function installCommandForRoot(projectRoot: string, relativeRoot: string, manager: JavaScriptPackageManagerName, pkg: Record<string, unknown> | undefined): string {
  const root = projectPath(projectRoot, relativeRoot);
  if (manager === "pnpm") return "pnpm install --frozen-lockfile";
  if (manager === "npm") {
    return fs.existsSync(path.join(root, "package-lock.json")) || fs.existsSync(path.join(root, "npm-shrinkwrap.json"))
      ? "npm ci"
      : "npm install";
  }
  if (manager === "yarn") {
    const packageManager = typeof pkg?.packageManager === "string" ? pkg.packageManager : "";
    if (packageManager === "" && fs.existsSync(path.join(root, "yarn.lock")) && !fs.existsSync(path.join(root, ".yarnrc.yml"))) {
      return "yarn install --frozen-lockfile";
    }
    return packageManager.startsWith("yarn@1.") ? "yarn install --frozen-lockfile" : "yarn install --immutable";
  }
  return "bun install --frozen-lockfile";
}

function readTextFile(projectRoot: string, relativePath: string): string | undefined {
  const filePath = projectPath(projectRoot, relativePath);
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
}

function hasTomlSection(source: string | undefined, section: string): boolean {
  if (!source) return false;
  const escaped = section.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^\\s*\\[${escaped}\\]\\s*(?:#.*)?$`, "m").test(source);
}

function directoryFileNames(projectRoot: string, relativeRoot: string): string[] {
  try {
    return fs.readdirSync(projectPath(projectRoot, relativeRoot), { withFileTypes: true })
      .filter((entry) => entry.isFile())
      .map((entry) => entry.name)
      .sort();
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return [];
    throw error;
  }
}

function requirementsFiles(projectRoot: string, relativeRoot: string): string[] {
  return directoryFileNames(projectRoot, relativeRoot)
    .filter((name) => /^requirements.*\.(txt|in)$/.test(name))
    .sort();
}

function selectedRequirementsFile(projectRoot: string, relativeRoot: string): string | undefined {
  const files = requirementsFiles(projectRoot, relativeRoot);
  if (files.includes("requirements.txt")) return "requirements.txt";
  if (files.includes("requirements-dev.txt")) return "requirements-dev.txt";
  return files.find((name) => /^requirements.*\.txt$/.test(name)) ?? files[0];
}

function isCommonFixtureOrExamplePath(relativeRoot: string): boolean {
  if (relativeRoot === ".") return false;
  const segments = relativeRoot.split("/");
  return segments.some((segment) => ["fixture", "fixtures", "example", "examples"].includes(segment));
}

type PythonRootDetection = {
  tool: PythonPackageManagerName;
  evidence: string;
  confidence: DependencyConfidence;
  reason: string;
};

function pythonDetectionForRoot(projectRoot: string, relativeRoot: string): PythonRootDetection | undefined {
  const root = projectPath(projectRoot, relativeRoot);
  const pyproject = readTextFile(projectRoot, path.posix.join(relativeRoot, "pyproject.toml"));
  const hasRootFile = (name: string): boolean => fs.existsSync(path.join(root, name));
  const fixtureOrExample = isCommonFixtureOrExamplePath(relativeRoot);
  const nested = relativeRoot !== ".";
  const genericConfidence: DependencyConfidence = nested || fixtureOrExample ? "low" : "medium";
  const detections: Partial<Record<PythonPackageManagerName, PythonRootDetection>> = {};

  if (hasRootFile("uv.lock")) {
    detections.uv = { tool: "uv", evidence: "uv.lock", confidence: "high", reason: "uv lockfile" };
  } else if (hasTomlSection(pyproject, "tool.uv")) {
    detections.uv = { tool: "uv", evidence: "pyproject.toml [tool.uv]", confidence: "high", reason: "uv project config" };
  }

  if (hasRootFile("poetry.lock")) {
    detections.poetry = { tool: "poetry", evidence: "poetry.lock", confidence: "high", reason: "Poetry lockfile" };
  } else if (hasTomlSection(pyproject, "tool.poetry")) {
    detections.poetry = { tool: "poetry", evidence: "pyproject.toml [tool.poetry]", confidence: "high", reason: "Poetry project config" };
  }

  if (hasRootFile("Pipfile.lock")) {
    detections.pipenv = { tool: "pipenv", evidence: "Pipfile.lock", confidence: "high", reason: "Pipenv lockfile" };
  } else if (hasRootFile("Pipfile")) {
    detections.pipenv = { tool: "pipenv", evidence: "Pipfile", confidence: "high", reason: "Pipenv project file" };
  }

  if (hasRootFile("pdm.lock")) {
    detections.pdm = { tool: "pdm", evidence: "pdm.lock", confidence: "high", reason: "PDM lockfile" };
  } else if (hasRootFile(".pdm-python")) {
    detections.pdm = { tool: "pdm", evidence: ".pdm-python", confidence: "high", reason: "PDM project Python marker" };
  } else if (hasTomlSection(pyproject, "tool.pdm")) {
    detections.pdm = { tool: "pdm", evidence: "pyproject.toml [tool.pdm]", confidence: "high", reason: "PDM project config" };
  }

  if (hasRootFile("hatch.toml")) {
    detections.hatch = { tool: "hatch", evidence: "hatch.toml", confidence: "high", reason: "Hatch project config" };
  } else if (hasTomlSection(pyproject, "tool.hatch")) {
    detections.hatch = { tool: "hatch", evidence: "pyproject.toml [tool.hatch]", confidence: "high", reason: "Hatch pyproject config" };
  }

  const requirement = selectedRequirementsFile(projectRoot, relativeRoot);
  if (requirement) {
    detections.pip = {
      tool: "pip",
      evidence: requirement,
      confidence: genericConfidence,
      reason: "pip requirements file",
    };
  } else if (hasTomlSection(pyproject, "project")) {
    detections.pip = {
      tool: "pip",
      evidence: "pyproject.toml [project]",
      confidence: genericConfidence,
      reason: "generic Python project metadata",
    };
  } else if (hasTomlSection(pyproject, "build-system")) {
    detections.pip = {
      tool: "pip",
      evidence: "pyproject.toml [build-system]",
      confidence: genericConfidence,
      reason: "generic Python build metadata",
    };
  }

  for (const tool of PYTHON_MANAGER_PRIORITY) {
    const detection = detections[tool];
    if (detection) return detection;
  }
  return undefined;
}

function scanPythonRootPaths(projectRoot: string, ignoredRootPaths: string[]): string[] {
  const roots: string[] = [];
  function visit(dir: string, relativeDir: string): void {
    if (relativeDir !== "" && pathInsideIgnoredRoot(relativeDir, ignoredRootPaths)) return;
    if (relativeDir !== "" && dependencyArtifactKindForRelativePath(relativeDir) !== undefined) return;
    const relativeRoot = relativeDir === "" ? "." : posixRelative(relativeDir);
    if (pythonDetectionForRoot(projectRoot, relativeRoot)) roots.push(relativeRoot);
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (SKIPPED_SCAN_DIRS.has(entry.name)) continue;
      visit(path.join(dir, entry.name), path.posix.join(relativeDir, entry.name));
    }
  }
  visit(projectRoot, "");
  return Array.from(new Set(roots)).sort();
}

const PYTHON_INDEX_CONFIG_FILES = new Set(["pip.conf", "uv.toml", "poetry.toml", ".pypirc", "Pipfile", "pyproject.toml"]);
const CREDENTIAL_BEARING_URL_PATTERN = /\bhttps?:\/\/[^/?#\s'"]+@[^/?#\s'"]+/i;

function scanPythonCredentialWarnings(projectRoot: string, ignoredRootPaths: string[]): DependencyWarning[] {
  const warnings: DependencyWarning[] = [];
  function visit(dir: string, relativeDir: string): void {
    if (relativeDir !== "" && pathInsideIgnoredRoot(relativeDir, ignoredRootPaths)) return;
    if (relativeDir !== "" && dependencyArtifactKindForRelativePath(relativeDir) !== undefined) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const relativePath = relativeDir === "" ? entry.name : path.posix.join(relativeDir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIPPED_SCAN_DIRS.has(entry.name)) visit(path.join(dir, entry.name), relativePath);
        continue;
      }
      if (!entry.isFile() || !PYTHON_INDEX_CONFIG_FILES.has(entry.name)) continue;
      const source = readTextFile(projectRoot, relativePath);
      if (source && CREDENTIAL_BEARING_URL_PATTERN.test(source)) {
        addUnique(warnings, {
          hostRelativePath: normalizeInputRelativePath(relativePath),
          reason: "Python package index config may contain a credential-bearing URL; use exact-host allowlisting plus proxy token policy instead",
        }, (warning) => warning.hostRelativePath);
      }
    }
  }
  visit(projectRoot, "");
  return warnings.sort(compareDependencyPath);
}

function pythonToolStores(tool: PythonPackageManagerName): RuntimeToolStoreName[] {
  if (tool === "hatch") return ["hatch-cache", "hatch-data"];
  return [tool];
}

function pythonInstallCommandForRoot(projectRoot: string, relativeRoot: string, detection: PythonRootDetection): string {
  const root = projectPath(projectRoot, relativeRoot);
  if (detection.tool === "uv") return "uv sync";
  if (detection.tool === "poetry") return "poetry install";
  if (detection.tool === "pipenv") return fs.existsSync(path.join(root, "Pipfile.lock")) ? "pipenv sync" : "pipenv install";
  if (detection.tool === "pdm") return "pdm sync";
  if (detection.tool === "hatch") return "hatch env create";
  const requirement = selectedRequirementsFile(projectRoot, relativeRoot);
  if (requirement) return `python -m venv .venv && .venv/bin/python -m pip install -r ${shellSingleQuote(requirement)}`;
  return "python -m venv .venv && .venv/bin/python -m pip install -e .";
}

function shouldPredictPythonVenv(tool: PythonPackageManagerName): boolean {
  return tool !== "hatch";
}

function dependencyRootKey(root: Pick<DependencyRoot, "ecosystem" | "hostRelativePath">): string {
  return `${root.ecosystem}:${root.hostRelativePath}`;
}

function compareDependencyPath(left: { hostRelativePath: string }, right: { hostRelativePath: string }): number {
  return left.hostRelativePath.localeCompare(right.hostRelativePath);
}

function compareDependencyRoot(left: Pick<DependencyRoot, "ecosystem" | "hostRelativePath">, right: Pick<DependencyRoot, "ecosystem" | "hostRelativePath">): number {
  const pathCompare = left.hostRelativePath.localeCompare(right.hostRelativePath);
  if (pathCompare !== 0) return pathCompare;
  return ECOSYSTEM_ORDER.indexOf(left.ecosystem) - ECOSYSTEM_ORDER.indexOf(right.ecosystem);
}

function addDependencyRoot(
  roots: DependencyRoot[],
  workspaceRoots: DependencyWorkspaceRoot[],
  root: DependencyRoot,
  options: { installRoot: boolean },
): void {
  addUnique(roots, root, dependencyRootKey);
  if (options.installRoot) addUnique(workspaceRoots, root, dependencyRootKey);
}

function addInstallCommand(
  installCommands: DependencyInstallCommand[],
  command: DependencyInstallCommand,
): void {
  addUnique(installCommands, command, (entry) => `${entry.ecosystem}:${entry.hostRelativePath}`);
}

function activeRuntimeToolStores(workspaceRoots: DependencyWorkspaceRoot[]): RuntimeToolStoreName[] {
  const selected = new Set<RuntimeToolStoreName>();
  for (const root of workspaceRoots) {
    if (root.ecosystem === "javascript") {
      selected.add(root.tool as JavaScriptPackageManagerName);
      continue;
    }
    for (const store of pythonToolStores(root.tool as PythonPackageManagerName)) selected.add(store);
  }
  return RUNTIME_TOOL_STORE_ORDER.filter((store) => selected.has(store));
}

export function createDependencyOverlayPlan(projectRootInput: string, options: DependencyOverlayPlanOptions = {}): DependencyOverlayPlan {
  const projectRoot = fs.realpathSync(projectRootInput);
  const workspaceHash = projectHash(projectRoot);
  const roots: DependencyRoot[] = [];
  const workspaceRoots: DependencyWorkspaceRoot[] = [];
  const overlays: DependencyOverlay[] = [];
  const ignoredCandidates: DependencyIgnoredCandidate[] = [];
  const warnings: DependencyWarning[] = [];
  const installCommands: DependencyInstallCommand[] = [];
  const ignoredRootPaths = normalizeIgnoredRootPaths(projectRoot, options.ignoredRootPaths);
  const packageScanIgnoredRootPaths = Array.from(new Set([
    ...ignoredRootPaths,
    ...ignoredDependencyScanRootPaths(projectRoot, options.gitIgnoredPaths),
  ])).sort();
  const trackedPaths = trackedPathSet(options.gitTrackedPaths);
  const rootPackageJson = readPackageJson(projectRoot, ".");
  const rootManager = detectPackageManager(projectRoot, ".", rootPackageJson);
  const validateOverlayTargets = options.mode !== "off";
  const addUntrackedOverlay = (hostRelativePath: string, reason: string): void => {
    if (hasTrackedPathUnder(hostRelativePath, trackedPaths)) return;
    addOverlay(overlays, projectRoot, workspaceHash, hostRelativePath, reason, { validateTarget: validateOverlayTargets });
  };

  if (rootManager) {
    const rootNodeModules = shouldOverlayNodeModules(projectRoot, rootManager, rootPackageJson);
    addDependencyRoot(roots, workspaceRoots, {
      ecosystem: "javascript",
      tool: rootManager,
      hostRelativePath: ".",
      packageManager: rootManager,
      evidence: "package.json",
      confidence: "high",
      reason: `${rootManager} workspace root`,
    }, { installRoot: true });
    addInstallCommand(installCommands, {
      ecosystem: "javascript",
      tool: rootManager,
      hostRelativePath: ".",
      packageManager: rootManager,
      command: installCommandForRoot(projectRoot, ".", rootManager, rootPackageJson),
    });
    if (rootNodeModules) {
      addUntrackedOverlay("node_modules", `${rootManager} workspace root`);
    }
    for (const workspaceRoot of expandWorkspaceRoots(projectRoot, workspacePatterns(projectRoot, rootManager, rootPackageJson), packageScanIgnoredRootPaths)) {
      addDependencyRoot(roots, workspaceRoots, {
        ecosystem: "javascript",
        tool: rootManager,
        hostRelativePath: workspaceRoot,
        packageManager: rootManager,
        evidence: "workspace pattern",
        confidence: "high",
        reason: `${rootManager} workspace package`,
      }, { installRoot: true });
      if (rootNodeModules) {
        addUntrackedOverlay(path.posix.join(workspaceRoot, "node_modules"), `${rootManager} workspace package`);
      }
    }
  }

  for (const packageRoot of scanPackageJsonRoots(projectRoot, packageScanIgnoredRootPaths)) {
    if (packageRoot === "." || workspaceRoots.some((entry) => entry.ecosystem === "javascript" && entry.hostRelativePath === packageRoot)) continue;
    const pkg = readPackageJson(projectRoot, packageRoot);
    const manager = detectPackageManager(projectRoot, packageRoot, pkg);
    if (!manager) continue;
    addDependencyRoot(roots, workspaceRoots, {
      ecosystem: "javascript",
      tool: manager,
      hostRelativePath: packageRoot,
      packageManager: manager,
      evidence: "package.json",
      confidence: "high",
      reason: `${manager} nested project`,
    }, { installRoot: true });
    addInstallCommand(installCommands, {
      ecosystem: "javascript",
      tool: manager,
      hostRelativePath: packageRoot,
      packageManager: manager,
      command: installCommandForRoot(projectRoot, packageRoot, manager, pkg),
    });
    if (shouldOverlayNodeModules(projectPath(projectRoot, packageRoot), manager, pkg)) {
      addUntrackedOverlay(path.posix.join(packageRoot, "node_modules"), `${manager} nested project`);
    }
  }

  for (const pythonRoot of scanPythonRootPaths(projectRoot, packageScanIgnoredRootPaths)) {
    const detection = pythonDetectionForRoot(projectRoot, pythonRoot);
    if (!detection) continue;
    const installRoot = detection.confidence !== "low";
    addDependencyRoot(roots, workspaceRoots, {
      ecosystem: "python",
      tool: detection.tool,
      hostRelativePath: pythonRoot,
      evidence: detection.evidence,
      confidence: detection.confidence,
      reason: detection.reason,
    }, { installRoot });
    if (!installRoot) continue;
    if (shouldPredictPythonVenv(detection.tool)) {
      addUntrackedOverlay(path.posix.join(pythonRoot, ".venv"), `predicted ${detection.tool} project virtualenv`);
    }
    addInstallCommand(installCommands, {
      ecosystem: "python",
      tool: detection.tool,
      hostRelativePath: pythonRoot,
      command: pythonInstallCommandForRoot(projectRoot, pythonRoot, detection),
    });
  }

  for (const ignoredPath of options.gitIgnoredPaths ?? []) {
    const hostRelativePath = normalizeInputRelativePath(ignoredPath);
    if (pathInsideIgnoredRoot(hostRelativePath, ignoredRootPaths)) continue;
    const reason = dependencyArtifactReason(projectRoot, hostRelativePath);
    if (reason) {
      addUntrackedOverlay(hostRelativePath, reason);
    } else {
      addUnique(ignoredCandidates, {
        hostRelativePath,
        reason: "ignored directory did not match dependency artifact allowlist",
      }, (entry) => entry.hostRelativePath);
    }
  }

  overlays.sort((left, right) => left.hostRelativePath.localeCompare(right.hostRelativePath));
  roots.sort(compareDependencyRoot);
  workspaceRoots.sort(compareDependencyRoot);
  ignoredCandidates.sort((left, right) => left.hostRelativePath.localeCompare(right.hostRelativePath));
  installCommands.sort(compareDependencyRoot);
  const packageManagers = PACKAGE_MANAGER_PRIORITY.filter((manager) => workspaceRoots.some((entry) => entry.ecosystem === "javascript" && entry.packageManager === manager));
  const storeNames = activeRuntimeToolStores(workspaceRoots);
  warnings.push(...scanPythonCredentialWarnings(projectRoot, packageScanIgnoredRootPaths));

  return {
    version: 1,
    projectRoot,
    workspaceHash,
    mode: options.mode ?? "auto",
    packageManagers,
    roots,
    workspaceRoots,
    overlays,
    ignoredCandidates,
    warnings,
    storeVolumes: runtimeToolStoreVolumes(workspaceHash, storeNames),
    installCommands,
    installCommand: installCommands[0]?.command,
  };
}

export function dependencyOverlayMounts(plan: DependencyOverlayPlan): RuntimeComposeMount[] {
  if (plan.mode === "off") return [];
  return dependencyOverlayMountsForRoot(plan, "/workspace");
}

export function dependencyOverlayMountsForRoot(plan: DependencyOverlayPlan, projectContainerRoot: string): RuntimeComposeMount[] {
  if (plan.mode === "off") return [];
  const containerRoot = normalizeContainerPath(projectContainerRoot);
  const targetForOverlay = (overlay: DependencyOverlay): string => {
    return overlay.hostRelativePath === "."
      ? containerRoot
      : dependencyArtifactTarget(containerRoot, overlay.hostRelativePath);
  };
  return [
    ...plan.overlays.map((overlay) => ({
      type: "volume" as const,
      source: overlay.volume,
      target: targetForOverlay(overlay),
      noCopy: true,
    })),
    ...plan.storeVolumes.map((store) => ({
      type: "volume" as const,
      source: store.volume,
      target: store.target,
      noCopy: true,
    })),
  ];
}

export function dependencyOverlayNamedVolumes(plan: DependencyOverlayPlan): string[] {
  if (plan.mode === "off") return [];
  return [
    ...plan.overlays.map((overlay) => overlay.volume),
    ...plan.storeVolumes.map((store) => store.volume),
  ];
}

export function dependencyOverlayEnvironment(plan: DependencyOverlayPlan): Record<string, string> {
  if (plan.mode === "off") return {};
  return Object.assign({}, ...plan.storeVolumes.map((store) => store.environment)) as Record<string, string>;
}

export function dependencyOverlayInstallCommand(plan: DependencyOverlayPlan): string | undefined {
  return dependencyOverlayInstallCommands(plan).at(0)?.command;
}

function normalizeDependencyInstallCommand(command: DependencyInstallCommand): DependencyInstallCommand {
  if (command.ecosystem && command.tool) return command;
  const packageManager = command.packageManager ?? planPackageManagerFallback(command);
  return {
    ecosystem: "javascript",
    tool: packageManager,
    hostRelativePath: command.hostRelativePath,
    packageManager,
    command: command.command,
  };
}

function planPackageManagerFallback(command: DependencyInstallCommand): JavaScriptPackageManagerName {
  return command.packageManager ?? "npm";
}

export function dependencyOverlayInstallCommands(plan: DependencyOverlayPlan): DependencyInstallCommand[] {
  if (Array.isArray(plan.installCommands)) return plan.installCommands.map(normalizeDependencyInstallCommand);
  return plan.installCommand
    ? [{
      ecosystem: "javascript",
      tool: plan.packageManagers[0] ?? "npm",
      hostRelativePath: ".",
      packageManager: plan.packageManagers[0] ?? "npm",
      command: plan.installCommand,
    }]
    : [];
}

export function serializeDependencyOverlayPlan(plan: DependencyOverlayPlan): string {
  return `${JSON.stringify(plan, null, 2)}\n`;
}

function sortedRecord(record: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(record).sort(([left], [right]) => left.localeCompare(right)));
}

function normalizeRuntimeSignature(signature: DependencyOverlayRuntimeSignature): DependencyOverlayRuntimeSignature {
  return {
    version: 1,
    mounts: [...signature.mounts].sort((left, right) => {
      const target = left.target.localeCompare(right.target);
      if (target !== 0) return target;
      return left.source.localeCompare(right.source);
    }),
    namedVolumes: Array.from(new Set(signature.namedVolumes)).sort(),
    environment: sortedRecord(signature.environment),
  };
}

export function dependencyOverlayRuntimeSignature(
  plan: DependencyOverlayPlan,
  projectContainerRoot: string,
): DependencyOverlayRuntimeSignature {
  return normalizeRuntimeSignature({
    version: 1,
    mounts: dependencyOverlayMountsForRoot(plan, projectContainerRoot)
      .filter((mount): mount is RuntimeComposeMount & { type: "volume"; source: string; target: string } => mount.type === "volume")
      .map((mount) => ({
        type: "volume",
        source: mount.source,
        target: mount.target,
        noCopy: mount.noCopy === true,
      })),
    namedVolumes: dependencyOverlayNamedVolumes(plan),
    environment: dependencyOverlayEnvironment(plan),
  });
}

export function serializeDependencyOverlayRuntimeSignature(signature: DependencyOverlayRuntimeSignature): string {
  return `${JSON.stringify(normalizeRuntimeSignature(signature), null, 2)}\n`;
}

function dependencyOverlayRuntimeSignatureEmpty(signature: DependencyOverlayRuntimeSignature): boolean {
  return signature.mounts.length === 0
    && signature.namedVolumes.length === 0
    && Object.keys(signature.environment).length === 0;
}

function dependencyOverlayRuntimeSignaturesEqual(
  left: DependencyOverlayRuntimeSignature,
  right: DependencyOverlayRuntimeSignature,
): boolean {
  return serializeDependencyOverlayRuntimeSignature(left) === serializeDependencyOverlayRuntimeSignature(right);
}

export type PreparedDependencyOverlayPlan = {
  changed: boolean;
  diagnosticChanged: boolean;
  needsLiveRuntimeInspection: boolean;
  plan: DependencyOverlayPlan;
  runtimeSignature: DependencyOverlayRuntimeSignature;
  previousStateIssue?: string;
};

function compactDiagnostic(value: string): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= 500) return compact;
  return `${compact.slice(0, 497)}...`;
}

function dependencyOverlayVolumeTargets(context: RuntimeContext): string[] {
  const plan = context.dependencyOverlayPlan;
  if (!plan || plan.mode === "off") return [];
  return dependencyOverlayMountsForRoot(plan, projectPhysicalRoot(context))
    .filter((mount) => mount.type === "volume")
    .map((mount) => mount.target);
}

function dependencyVolumeCommandIssue(label: string, target: string, result: CaptureResult): string | undefined {
  if (result.status === 0) return undefined;
  const detail = compactDiagnostic(`${result.stderr}\n${result.stdout}`);
  return `${label} failed for ${target}${detail ? `: ${detail}` : ""}`;
}

type DependencyVolumeOwnershipOptions = {
  verbose?: boolean;
};

const AGENT_UID = AGENT_UID_GID.split(":")[0];
const DEPENDENCY_VOLUME_MISSING_STATUS = 21;
const DEPENDENCY_VOLUME_NOT_MOUNTPOINT_STATUS = 22;
const DEPENDENCY_VOLUME_CHECK_SCRIPT = [
  "set -eu",
  "target=$1",
  "probe=$2",
  "if [ ! -d \"$target\" ]; then printf 'missing\\n' >&2; exit 21; fi",
  "if ! mountpoint -q -- \"$target\"; then printf 'not-mountpoint\\n' >&2; exit 22; fi",
  "owner=$(stat -c '%u:%g' -- \"$target\")",
  "printf 'owner=%s\\n' \"$owner\"",
  `if [ "$owner" != "${AGENT_UID_GID}" ]; then`,
  "  printf 'fixedOwner=%s\\n' \"$owner\"",
  `  chown ${AGENT_UID_GID} -- "$target"`,
  "fi",
  `sudo -u "#${AGENT_UID}" -- sh -c 'touch -- "$1" && rm -f -- "$1"' runfree-dependency-volume-write-probe "$probe"`,
].join("\n");

function dependencyVolumeVerbose(options: DependencyVolumeOwnershipOptions | undefined, message: string): void {
  if (options?.verbose) runfreeLog(`verbose: ${message}`);
}

function dependencyVolumeValidationIssue(target: string, result: CaptureResult): string | undefined {
  if (result.status === 0) return undefined;
  if (result.status === DEPENDENCY_VOLUME_MISSING_STATUS) return `dependency volume target is missing: ${target}`;
  if (result.status === DEPENDENCY_VOLUME_NOT_MOUNTPOINT_STATUS) return `dependency volume target is not a mount point: ${target}`;
  return dependencyVolumeCommandIssue("dependency volume validation", target, result);
}

/**
 * Ensures every Compose-managed named volume a session mounts exists with the
 * exact ownership labels the session named-volume proof requires.
 *
 * `runfree-commandhistory` is always mounted; dependency-overlay volumes are
 * mounted only when overlays are active. Before the per-session cutover the
 * shared `agent` Compose service mounted all of these, so `compose up` created
 * them with the Compose ownership labels. That service is gone, and Compose does
 * not create a declared volume no started service mounts — so nothing creates
 * them and every session launch fails its named-volume inspection. This restores
 * the one creation the removed service used to trigger. Idempotent and
 * fail-closed; the driver still re-proves each volume at launch.
 */
export function ensureComposeManagedSessionVolumes(
  context: RuntimeContext,
  docker: RuntimeDocker,
): number {
  const project = composeProjectName(context.projectRoot);
  const logicalNames = ["runfree-commandhistory"];
  const plan = context.dependencyOverlayPlan;
  if (plan && plan.mode !== "off") {
    for (const mount of dependencyOverlayMountsForRoot(plan, projectPhysicalRoot(context))) {
      if (mount.type === "volume") logicalNames.push(mount.source);
    }
  }
  for (const logicalName of logicalNames) {
    if (docker.createComposeManagedVolume(project, logicalName) !== 0) {
      warn(`could not ensure the Compose-managed session volume ${logicalName}`);
      return 1;
    }
  }
  return 0;
}

export function ensureDependencyVolumeOwnership(
  context: RuntimeContext,
  io: RuntimeIO,
  docker: RuntimeDocker,
  options: DependencyVolumeOwnershipOptions = {},
): number {
  const targets = dependencyOverlayVolumeTargets(context);
  if (targets.length === 0) return 0;
  const project = composeProjectName(context.projectRoot);
  const target = resolveAgentExecTarget(project, docker);
  const agentId = target?.containerId;
  if (!agentId) {
    // Post-cutover shape: no shared agent service exists, and per-session
    // containers must not be exec targets for preparation. The typed
    // ephemeral helper prepares the same volumes instead.
    return ensureDependencyVolumeOwnershipWithoutAgent(context, io, options);
  }

  for (const target of targets) {
    dependencyVolumeVerbose(options, `checking dependency volume ${target} (mount, owner, write probe)`);
    const probe = `${target.replace(/\/+$/g, "")}/.runfree-write-test-${process.pid}`;
    const check = runDockerExecRoot(context, io, agentId, [
      "sh",
      "-c",
      DEPENDENCY_VOLUME_CHECK_SCRIPT,
      "runfree-dependency-volume-check",
      target,
      probe,
    ]);
    if (check.stdout.includes("fixedOwner=")) {
      runfreeLog(`fixing dependency volume owner: ${target}`);
    }
    const checkIssue = dependencyVolumeValidationIssue(target, check);
    if (checkIssue) {
      warn(checkIssue);
      return check.status;
    }
    const owner = /(?:^|\n)owner=([^\n]+)/.exec(check.stdout)?.[1];
    if (owner) dependencyVolumeVerbose(options, `dependency volume ${target} owner ${owner}`);
  }

  return 0;
}

// Fixed shallow scratch mountpoint root for dependency-volume preparation.
// Owning and write-probing a volume acts on the *volume*, whose result is
// independent of the path it is mounted at inside the throwaway helper — so
// prep mounts every volume at an index-keyed leaf under this root, not at the
// real (often deep) store target. The helper runs `--read-only`, so the
// script's own `mountpoint -q` check fails closed on any daemon that did not
// materialize these mountpoints. The session create-plan proof — not this
// step — validates what sessions actually mount at real targets.
const DEPENDENCY_PREP_MOUNTPOINT = "/mnt/runfree-dep-prep";

export function dependencyPrepMountpoint(index: number): string {
  return `${DEPENDENCY_PREP_MOUNTPOINT}/${index}`;
}

// L2 record framing: results are keyed by host-assigned index in
// host-declared order, and carry only that index plus numeric `stat` owners —
// never content-derived names or real targets. Missing, duplicated,
// reordered, unrecognized, or extra records fail the launch; a nonzero batch
// exit (including a timeout, which `capture` maps to nonzero) fails it for
// every volume.
const DEPENDENCY_PREP_FIX_RECORD_PATTERN = /^RUNFREE_DEP_PREP (\d+) owner=(\d+:\d+) fixed=([01])$/u;
const DEPENDENCY_PREP_PROBE_RECORD_PATTERN = /^RUNFREE_DEP_PREP (\d+) probe=ok$/u;
const DEPENDENCY_PREP_OUTPUT_MAX_BYTES = 64 * 1024;
const DEPENDENCY_PREP_FAILED_INDEX_PATTERN = /(?:^|\n)(?:missing|not-mountpoint|probe-create) (\d+)(?:\r?\n|$)/u;

/**
 * The batched root+CHOWN ownership script (L2): one run mounting every volume,
 * looping the per-volume existence/mountpoint/owner check. Unlike the
 * exec-mode script it neither sudos (no-new-privileges forbids setuid) nor
 * probes writability — the write probe is its own unprivileged batch run,
 * which is a stronger claim anyway: it proves the agent uid can write with
 * *no* capabilities, not that a sudo-wielding root could. Any per-volume
 * failure exits nonzero so no partial "prepared" result can escape.
 */
export function dependencyPrepFixScript(count: number): string {
  if (!Number.isInteger(count) || count < 1) throw new Error("dependency prep requires at least one volume");
  const lines: string[] = [
    "set -u",
    "runfree_check() {",
    "  runfree_index=$1",
    "  runfree_target=$2",
    "  if [ ! -d \"$runfree_target\" ]; then printf 'missing %s\\n' \"$runfree_index\" >&2; exit 21; fi",
    "  if ! mountpoint -q -- \"$runfree_target\"; then printf 'not-mountpoint %s\\n' \"$runfree_index\" >&2; exit 22; fi",
    "  runfree_owner=$(stat -c '%u:%g' -- \"$runfree_target\") || exit 23",
    "  runfree_fixed=0",
    `  if [ "$runfree_owner" != "${AGENT_UID_GID}" ]; then`,
    "    runfree_fixed=1",
    `    chown ${AGENT_UID_GID} -- "$runfree_target" || exit 24`,
    "  fi",
    "  printf 'RUNFREE_DEP_PREP %s owner=%s fixed=%s\\n' \"$runfree_index\" \"$runfree_owner\" \"$runfree_fixed\"",
    "}",
  ];
  for (let index = 0; index < count; index += 1) {
    lines.push(`runfree_check ${index} ${dependencyPrepMountpoint(index)}`);
  }
  lines.push("exit 0");
  return lines.join("\n");
}

/**
 * The batched agent-uid write-probe script (L2). The probe file is created
 * no-clobber (`set -C`, i.e. O_EXCL): co-mounting every volume makes the
 * predictable probe filename a cross-volume symlink write primitive otherwise
 * — with no-clobber, a pre-planted entry (file OR symlink, dangling included)
 * fails the probe instead of following it.
 */
export function dependencyPrepProbeScript(count: number, probeFileName: string): string {
  if (!Number.isInteger(count) || count < 1) throw new Error("dependency prep requires at least one volume");
  if (!/^[A-Za-z0-9._-]+$/u.test(probeFileName)) throw new Error("dependency prep probe file name is invalid");
  const lines: string[] = [
    "set -u",
    "runfree_probe() {",
    "  runfree_index=$1",
    "  runfree_file=$2",
    "  if ! ( set -C; : > \"$runfree_file\" ) 2>/dev/null; then printf 'probe-create %s\\n' \"$runfree_index\" >&2; exit 25; fi",
    "  rm -f -- \"$runfree_file\" || exit 26",
    "  printf 'RUNFREE_DEP_PREP %s probe=ok\\n' \"$runfree_index\"",
    "}",
  ];
  for (let index = 0; index < count; index += 1) {
    lines.push(`runfree_probe ${index} ${dependencyPrepMountpoint(index)}/${probeFileName}`);
  }
  lines.push("exit 0");
  return lines.join("\n");
}

export type DependencyPrepFixRecord = Readonly<{ index: number; owner: string; fixed: boolean }>;

function strictDependencyPrepRecords(stdout: string, count: number): string[] | undefined {
  if (Buffer.byteLength(stdout) > DEPENDENCY_PREP_OUTPUT_MAX_BYTES) return undefined;
  const records = stdout.split(/\r?\n/u).filter((line) => line.trim() !== "");
  if (records.length !== count) return undefined;
  return records;
}

/** Strict indexed parse of the fix run's records; undefined = fail the launch. */
export function parseDependencyPrepFixRecords(stdout: string, count: number): DependencyPrepFixRecord[] | undefined {
  const records = strictDependencyPrepRecords(stdout, count);
  if (!records) return undefined;
  const parsed: DependencyPrepFixRecord[] = [];
  for (let index = 0; index < count; index += 1) {
    const match = DEPENDENCY_PREP_FIX_RECORD_PATTERN.exec(records[index]);
    if (!match || Number(match[1]) !== index) return undefined;
    parsed.push(Object.freeze({ index, owner: match[2], fixed: match[3] === "1" }));
  }
  return parsed;
}

/** Strict indexed parse of the probe run's records; false = fail the launch. */
export function parseDependencyPrepProbeRecords(stdout: string, count: number): boolean {
  const records = strictDependencyPrepRecords(stdout, count);
  if (!records) return false;
  for (let index = 0; index < count; index += 1) {
    const match = DEPENDENCY_PREP_PROBE_RECORD_PATTERN.exec(records[index]);
    if (!match || Number(match[1]) !== index) return false;
  }
  return true;
}

type DependencyPrepVolume = Readonly<{ name: string; logicalName: string; realTargets: readonly string[] }>;

function dependencyPrepFailureTarget(volumes: readonly DependencyPrepVolume[], stderr: string): string {
  const index = Number(DEPENDENCY_PREP_FAILED_INDEX_PATTERN.exec(stderr)?.[1] ?? Number.NaN);
  return volumes[index]?.realTargets[0] ?? "dependency volumes";
}

/**
 * Re-proves that every prep target is a plain, correctly labelled, optionless
 * Compose-managed local volume before ANY helper mounts it (L2 constraint 1).
 * One batched `docker volume inspect`; elements are matched by `Name`, never
 * positionally, and any missing, duplicate, foreign, or malformed record
 * aborts before a `dependency-prep` container exists.
 */
function assertDependencyPrepVolumes(
  context: RuntimeContext,
  io: RuntimeIO,
  project: string,
  volumes: readonly DependencyPrepVolume[],
): string | undefined {
  const inspected = io.capture(
    "docker",
    ["volume", "inspect", ...volumes.map((volume) => volume.name)],
    dockerClientEnvOptions(context),
  );
  if (inspected.status !== 0) {
    return `dependency volume inspection failed before preparation: ${compactDiagnostic(inspected.stderr) || `exit ${inspected.status}`}`;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(inspected.stdout);
  } catch {
    return "dependency volume inspection returned invalid JSON before preparation";
  }
  if (!Array.isArray(parsed) || parsed.length !== volumes.length) {
    return "dependency volume inspection did not return exactly the prep volume set";
  }
  const recordsByName = new Map<string, unknown>();
  for (const record of parsed as unknown[]) {
    const name = record && typeof record === "object" ? Reflect.get(record, "Name") : undefined;
    if (typeof name !== "string" || recordsByName.has(name)) {
      return "dependency volume inspection returned duplicate or unnamed volumes";
    }
    recordsByName.set(name, record);
  }
  for (const volume of volumes) {
    const record = recordsByName.get(volume.name);
    if (!record) return `dependency volume inspection is missing ${volume.name}`;
    try {
      assertComposeManagedLocalVolume(JSON.stringify([record]), {
        name: volume.name,
        logicalName: volume.logicalName,
        composeProject: project,
      });
    } catch (error) {
      return `refusing dependency volume ${volume.name}: ${error instanceof Error ? error.message : String(error)}`;
    }
  }
  return undefined;
}

/**
 * Prepares dependency volumes with no agent container at all (D-2/D-5, L2).
 *
 * Two hardened `--rm` runs of the selected agent image IN TOTAL on no network
 * — not two per volume: a root run that may only chown (`--cap-drop ALL
 * --cap-add CHOWN`) mounting every volume at an indexed scratch leaf, then an
 * agent-uid run with no capabilities write-probing each, no-clobber. Volumes
 * are deduped by physical volume name and re-proven Compose-managed local
 * volumes before either helper runs. Volumes are mounted by this function, so
 * the mountpoint check validates the helper's own wiring rather than
 * Compose's — the session create-plan proof owns validating what sessions
 * actually mount.
 */
function ensureDependencyVolumeOwnershipWithoutAgent(
  context: RuntimeContext,
  io: RuntimeIO,
  options: DependencyVolumeOwnershipOptions,
): number {
  const plan = context.dependencyOverlayPlan;
  if (!plan || plan.mode === "off") return 0;
  const image = context.agentImage;
  if (!image) {
    warn("dependency volume ownership setup failed: no selected agent image is available");
    return 1;
  }
  const project = composeProjectName(context.projectRoot);
  const projectId = projectHash(context.projectRoot);
  const volumesByName = new Map<string, { name: string; logicalName: string; realTargets: string[] }>();
  for (const mount of dependencyOverlayMountsForRoot(plan, projectPhysicalRoot(context))) {
    if (mount.type !== "volume") continue;
    const name = composeManagedVolumeName(project, mount.source);
    const existing = volumesByName.get(name);
    if (existing) {
      existing.realTargets.push(mount.target);
    } else {
      volumesByName.set(name, { name, logicalName: mount.source, realTargets: [mount.target] });
    }
  }
  const volumes: DependencyPrepVolume[] = [...volumesByName.values()];
  if (volumes.length === 0) return 0;

  const volumeIssue = assertDependencyPrepVolumes(context, io, project, volumes);
  if (volumeIssue) {
    warn(volumeIssue);
    return 1;
  }

  for (const volume of volumes) {
    dependencyVolumeVerbose(options, `preparing dependency volume ${volume.realTargets.join(", ")} (owner fix, write probe, batched)`);
  }
  const prepVolumes = volumes.map((volume, index) => ({ name: volume.name, target: dependencyPrepMountpoint(index) }));

  const fix = runEphemeralHelper(context, io, {
    purpose: "dependency-prep",
    projectId,
    image,
    user: "0:0",
    capabilities: ["CHOWN"],
    volumes: prepVolumes,
    command: ["sh", "-c", dependencyPrepFixScript(volumes.length), "runfree-dependency-volume-fix"],
  });
  if (fix.status !== 0) {
    const target = dependencyPrepFailureTarget(volumes, fix.stderr);
    const issue = dependencyVolumeValidationIssue(target, fix);
    warn(issue ?? `dependency volume validation failed for ${target}`);
    return fix.status;
  }
  const fixRecords = parseDependencyPrepFixRecords(fix.stdout, volumes.length);
  if (!fixRecords) {
    warn("dependency volume preparation records were missing, duplicated, or garbled; refusing the launch");
    return 1;
  }
  for (const record of fixRecords) {
    const volume = volumes[record.index];
    if (record.fixed) runfreeLog(`fixing dependency volume owner: ${volume.realTargets.join(", ")}`);
    dependencyVolumeVerbose(options, `dependency volume ${volume.realTargets[0]} owner ${record.owner}`);
  }

  const probeRun = runEphemeralHelper(context, io, {
    purpose: "dependency-prep",
    projectId,
    image,
    user: AGENT_UID_GID,
    volumes: prepVolumes,
    command: ["sh", "-c", dependencyPrepProbeScript(volumes.length, `.runfree-write-test-${process.pid}`), "runfree-dependency-volume-write-probe"],
  });
  if (probeRun.status !== 0) {
    const target = dependencyPrepFailureTarget(volumes, probeRun.stderr);
    warn(dependencyVolumeCommandIssue("dependency volume write probe", target, probeRun)
      ?? `dependency volume write probe failed for ${target}`);
    return probeRun.status;
  }
  if (!parseDependencyPrepProbeRecords(probeRun.stdout, volumes.length)) {
    warn("dependency volume write-probe records were missing, duplicated, or garbled; refusing the launch");
    return 1;
  }

  return 0;
}

function dependencyOverlayPlanPath(context: RuntimeContext): string {
  return path.join(context.project.paths.stateDir, "dependency-overlays.json");
}

function dependencyOverlayRuntimeSignaturePath(context: RuntimeContext): string {
  return path.join(context.project.paths.stateDir, "dependency-overlays.signature.json");
}

function parseNulSeparatedPaths(value: string): string[] {
  return value.split("\0").map((entry) => entry.trim()).filter(Boolean);
}

// The agent can write the repository config. Disable its fsmonitor value
// before host Git reads the index, or Git can execute a project-controlled
// hook outside the container during status and dry-run overlay scans. Use an
// empty value because Git 2.35.1 and older treat boolean `false` as a hook name.
const DISABLE_REPOSITORY_FSMONITOR = ["-c", "core.fsmonitor="] as const;

function collectGitIgnoredDependencyPaths(context: RuntimeContext, io: RuntimeIO): string[] {
  const result = io.capture(
    "git",
    [
      ...DISABLE_REPOSITORY_FSMONITOR,
      "-C",
      context.projectRoot,
      "ls-files",
      "--others",
      "--ignored",
      "--exclude-standard",
      "--directory",
      "-z",
    ],
    envOptions(context.env),
  );
  return result.status === 0 ? parseNulSeparatedPaths(result.stdout) : [];
}

function collectGitTrackedDependencyPaths(context: RuntimeContext, io: RuntimeIO): string[] {
  const result = io.capture(
    "git",
    [...DISABLE_REPOSITORY_FSMONITOR, "-C", context.projectRoot, "ls-files", "-z"],
    envOptions(context.env),
  );
  return result.status === 0 ? parseNulSeparatedPaths(result.stdout) : [];
}

function readPersistedFile(filePath: string): string | undefined {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
}

function readPersistedDependencyOverlayPlan(context: RuntimeContext): string | undefined {
  return readPersistedFile(dependencyOverlayPlanPath(context));
}

function readPersistedDependencyOverlayRuntimeSignatureSource(context: RuntimeContext): string | undefined {
  return readPersistedFile(dependencyOverlayRuntimeSignaturePath(context));
}

function isStringRecord(value: unknown): value is Record<string, string> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return Object.values(value as Record<string, unknown>).every((entry) => typeof entry === "string");
}

function parsePersistedDependencyOverlayPlan(source: string): { plan?: DependencyOverlayPlan; error?: string } {
  try {
    const parsed = JSON.parse(source) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { error: "plan is not an object" };
    const plan = parsed as Partial<DependencyOverlayPlan>;
    if (plan.version !== 1) return { error: "plan version is not supported" };
    if (plan.mode !== undefined && plan.mode !== "auto" && plan.mode !== "off") return { error: "plan mode is not supported" };
    if (!Array.isArray(plan.overlays)) return { error: "plan overlays must be an array" };
    if (!Array.isArray(plan.storeVolumes)) return { error: "plan storeVolumes must be an array" };
    for (const overlay of plan.overlays as Partial<DependencyOverlay>[]) {
      if (typeof overlay?.hostRelativePath !== "string" || typeof overlay.volume !== "string") {
        return { error: "plan overlay entries must include hostRelativePath and volume strings" };
      }
    }
    for (const store of plan.storeVolumes as Partial<DependencyStoreVolume>[]) {
      if (typeof store?.volume !== "string" || typeof store.target !== "string" || !isStringRecord(store.environment)) {
        return { error: "plan store volume entries must include volume, target, and string environment values" };
      }
    }
    return { plan: parsed as DependencyOverlayPlan };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

function parsePersistedDependencyOverlayRuntimeSignature(
  source: string,
): { signature?: DependencyOverlayRuntimeSignature; error?: string } {
  try {
    const parsed = JSON.parse(source) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { error: "signature is not an object" };
    const signature = parsed as Partial<DependencyOverlayRuntimeSignature>;
    if (signature.version !== 1) return { error: "signature version is not supported" };
    if (!Array.isArray(signature.mounts)) return { error: "signature mounts must be an array" };
    if (!Array.isArray(signature.namedVolumes)) return { error: "signature namedVolumes must be an array" };
    if (!isStringRecord(signature.environment)) return { error: "signature environment must contain string values" };
    const mounts: DependencyOverlayRuntimeMountSignature[] = [];
    for (const mount of signature.mounts as Partial<DependencyOverlayRuntimeMountSignature>[]) {
      if (mount?.type !== "volume" || typeof mount.source !== "string" || typeof mount.target !== "string" || typeof mount.noCopy !== "boolean") {
        return { error: "signature mount entries must include type, source, target, and noCopy" };
      }
      mounts.push({ type: "volume", source: mount.source, target: mount.target, noCopy: mount.noCopy });
    }
    if (!signature.namedVolumes.every((volume) => typeof volume === "string")) {
      return { error: "signature namedVolumes must contain strings" };
    }
    return {
      signature: normalizeRuntimeSignature({
        version: 1,
        mounts,
        namedVolumes: signature.namedVolumes,
        environment: signature.environment,
      }),
    };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

function derivePreviousDependencyOverlayRuntimeSignature(
  context: RuntimeContext,
  previousPlan: DependencyOverlayPlan,
): { signature?: DependencyOverlayRuntimeSignature; error?: string } {
  const previousGitLayout = readPersistedGitLayoutPlan(context);
  if (previousGitLayout) {
    return { signature: dependencyOverlayRuntimeSignature(previousPlan, previousGitLayout.containerProjectRoot) };
  }
  const workspaceSignature = dependencyOverlayRuntimeSignature(previousPlan, "/workspace");
  if (dependencyOverlayRuntimeSignatureEmpty(workspaceSignature)) return { signature: workspaceSignature };
  return { error: "previous dependency overlay signature is missing and previous Git layout is unavailable" };
}

function currentDependencyOverlayContainerRoot(context: RuntimeContext): string {
  return context.gitLayoutPlan?.containerProjectRoot
    ?? prepareGitRepositoryLayoutResult(context).plan.containerProjectRoot;
}

function readPreviousDependencyOverlayRuntimeSignature(
  context: RuntimeContext,
): { signature?: DependencyOverlayRuntimeSignature; planSource?: string; missingPlan: boolean; error?: string } {
  const signatureSource = readPersistedDependencyOverlayRuntimeSignatureSource(context);
  const planSource = readPersistedDependencyOverlayPlan(context);
  if (signatureSource !== undefined) {
    const parsed = parsePersistedDependencyOverlayRuntimeSignature(signatureSource);
    return parsed.error
      ? { planSource, missingPlan: planSource === undefined, error: `could not parse dependency overlay runtime signature: ${parsed.error}` }
      : { signature: parsed.signature, planSource, missingPlan: planSource === undefined };
  }
  if (planSource === undefined) return { missingPlan: true };
  const previousPlan = parsePersistedDependencyOverlayPlan(planSource);
  if (previousPlan.error) {
    return { planSource, missingPlan: false, error: `could not parse dependency overlay plan: ${previousPlan.error}` };
  }
  const derived = derivePreviousDependencyOverlayRuntimeSignature(context, previousPlan.plan as DependencyOverlayPlan);
  return derived.error
    ? { planSource, missingPlan: false, error: derived.error }
    : { signature: derived.signature, planSource, missingPlan: false };
}

/**
 * A plan that mounts nothing, for a caller that must build a runtime plan
 * before overlay discovery is possible.
 *
 * Startup's bootstrap plan exists to resolve the network and seed the Docker
 * adapters; every overlay-derived field it produces is replaced once the
 * prepared plan exists. Discovering for it would walk trees the prepared plan
 * excludes — it has no Git ignore/track facts yet — and can fail validation on
 * entries startup would never mount, failing the real command where status and
 * dry run succeed.
 */
export function emptyDependencyOverlayPlan(projectRootInput: string): DependencyOverlayPlan {
  const projectRoot = fs.realpathSync(projectRootInput);
  return {
    version: 1,
    projectRoot,
    workspaceHash: projectHash(projectRoot),
    mode: "off",
    packageManagers: [],
    roots: [],
    workspaceRoots: [],
    overlays: [],
    ignoredCandidates: [],
    warnings: [],
    storeVolumes: [],
    installCommands: [],
  };
}

/**
 * The plan startup last persisted, when it still describes this project and
 * the configured mode.
 *
 * Startup discovers overlays with the project's Git ignore and track facts,
 * persists the result, and creates named volumes from exactly that. Any later
 * consumer that re-discovers without those facts gets a different overlay set
 * — gitignored worktrees and agent directories reappear — and then requires
 * named volumes startup never created. The persisted plan is the record of
 * what exists, so consumers outside startup read it rather than guessing.
 */
export function persistedDependencyOverlayPlan(context: RuntimeContext): DependencyOverlayPlan | undefined {
  const source = readPersistedDependencyOverlayPlan(context);
  if (source === undefined) return undefined;
  const parsed = parsePersistedDependencyOverlayPlan(source);
  if (!parsed.plan) {
    // An absent record and an unreadable one are different answers. Falling
    // back to a scan here would derive a different overlay set than the one
    // the runtime's named volumes were created from, and every session launch
    // would fail on a volume that does not exist. Startup rewrites this record
    // from its own discovery, so name the command that does it.
    throw new Error([
      `dependency overlay record ${dependencyOverlayPlanPath(context)} is unreadable: ${parsed.error ?? "invalid"}`,
      `recreate it from the current project with: ${remedy.rebuild()}`,
    ].join("\n"));
  }
  // The parser accepts a version-1 plan with no `mode`: the field postdates
  // that shape and its absence means "auto", which is how every other reader
  // treats it. Rejecting those here would send active reconstruction back to
  // the fresh scan this record exists to avoid.
  const mode = context.project.config.runtime.dependencyOverlays ?? "auto";
  if ((parsed.plan.mode ?? "auto") !== mode) return undefined;
  let projectRoot: string;
  try {
    projectRoot = fs.realpathSync(context.projectRoot);
  } catch {
    return undefined;
  }
  return parsed.plan.projectRoot === projectRoot ? parsed.plan : undefined;
}

export function prepareDependencyOverlayPlan(context: RuntimeContext, io: RuntimeIO): DependencyOverlayPlan {
  return prepareDependencyOverlayPlanResult(context, io).plan;
}

export function prepareDependencyOverlayPlanResult(context: RuntimeContext, io: RuntimeIO): PreparedDependencyOverlayPlan {
  let plan: DependencyOverlayPlan;
  try {
    plan = createDependencyOverlayPlan(context.projectRoot, {
      mode: context.project.config.runtime.dependencyOverlays ?? "auto",
      gitIgnoredPaths: collectGitIgnoredDependencyPaths(context, io),
      gitTrackedPaths: collectGitTrackedDependencyPaths(context, io),
      ignoredRootPaths: [
        runfreeConfigRoot(context.env),
        runfreeDataRoot(context.env),
        runfreeStateRoot(context.env),
      ],
    });
  } catch (error) {
    die(`dependency overlay plan failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  const runtimeSignature = dependencyOverlayRuntimeSignature(plan, currentDependencyOverlayContainerRoot(context));
  const previous = readPreviousDependencyOverlayRuntimeSignature(context);
  const changed = previous.error !== undefined
    ? true
    : previous.signature === undefined
      ? !dependencyOverlayRuntimeSignatureEmpty(runtimeSignature)
      : !dependencyOverlayRuntimeSignaturesEqual(previous.signature, runtimeSignature);
  const serialized = serializeDependencyOverlayPlan(plan);
  const diagnosticChanged = previous.error !== undefined
    || (previous.planSource === undefined
      ? previous.signature !== undefined || !dependencyOverlayRuntimeSignatureEmpty(runtimeSignature)
      : previous.planSource !== serialized);
  const needsLiveRuntimeInspection = previous.signature === undefined
    && previous.planSource === undefined
    && previous.error === undefined
    && dependencyOverlayRuntimeSignatureEmpty(runtimeSignature);
  return {
    changed,
    diagnosticChanged,
    needsLiveRuntimeInspection,
    plan,
    runtimeSignature,
    previousStateIssue: previous.error,
  };
}

// Both records are read by other processes while startup rewrites them — a
// per-session launch reconstructs the active plan from the plan record. Replace
// them atomically so a reader sees the previous record or the next one, never a
// truncated file it would reject as unreadable.
export function writeDependencyOverlayPlan(context: RuntimeContext, plan: DependencyOverlayPlan): void {
  atomicReplaceFile(dependencyOverlayPlanPath(context), serializeDependencyOverlayPlan(plan), 0o600);
}

export function writeDependencyOverlayRuntimeSignature(
  context: RuntimeContext,
  signature: DependencyOverlayRuntimeSignature,
): void {
  atomicReplaceFile(
    dependencyOverlayRuntimeSignaturePath(context),
    serializeDependencyOverlayRuntimeSignature(signature),
    0o600,
  );
}

const DEPENDENCY_OVERLAY_ENV_NAMES = new Set(dependencyStoreEnvironmentNames());

function dependencyVolumePrefix(context: RuntimeContext): string {
  return `runfree-deps-${projectHash(fs.realpathSync(context.projectRoot))}-`;
}

type DockerInspectMount = {
  Name?: string;
  Source?: string;
  Destination?: string;
  Target?: string;
  Type?: string;
};

type DockerInspectContainer = {
  Config?: { Env?: string[] };
  Mounts?: DockerInspectMount[];
};

function runningAgentDependencyOverlayState(
  context: RuntimeContext,
  io: RuntimeIO,
  docker: RuntimeDocker,
): "absent" | "present" | "unknown" {
  const target = resolveAgentExecTarget(composeProjectName(context.projectRoot), docker);
  if (!target) return "absent";
  const agentId = target.containerId;
  const inspected = parseDockerJson<DockerInspectContainer[]>(
    io.capture("docker", ["inspect", agentId], dockerClientEnvOptions(context)),
    "dependency overlay runtime inspection",
  );
  const agent = inspected?.[0];
  if (!agent) return "unknown";
  const prefix = dependencyVolumePrefix(context);
  const hasDependencyMount = (agent.Mounts ?? []).some((mount) => {
    const name = mount.Name ?? "";
    const source = mount.Source ?? "";
    return mount.Type === "volume" && (name.startsWith(prefix) || path.basename(source).startsWith(prefix));
  });
  if (hasDependencyMount) return "present";
  const hasDependencyEnv = (agent.Config?.Env ?? []).some((entry) => {
    const name = entry.split("=", 1)[0] ?? "";
    return DEPENDENCY_OVERLAY_ENV_NAMES.has(name);
  });
  return hasDependencyEnv ? "present" : "absent";
}

export function dependencyOverlayMissingEmptySignatureRuntimeDrift(
  prepared: PreparedDependencyOverlayPlan,
  context: RuntimeContext,
  io: RuntimeIO,
  docker: RuntimeDocker,
): boolean {
  if (!prepared.needsLiveRuntimeInspection) return false;
  const liveState = runningAgentDependencyOverlayState(context, io, docker);
  if (liveState === "absent") return false;
  warn(liveState === "present"
    ? "dependency overlay state exists in the running runtime but no persisted plan/signature was found"
    : "dependency overlay runtime inspection failed while persisted plan/signature state is missing");
  return true;
}

function printDependencyOverlayPlan(plan: DependencyOverlayPlan, changed: boolean): void {
  console.log("dependency overlays");
  console.log(`mode: ${plan.mode ?? "auto"}`);
  console.log(`package managers: ${plan.packageManagers.join(", ") || "none"}`);
  const roots = plan.roots ?? plan.workspaceRoots ?? [];
  if (roots.length === 0) {
    console.log("dependency roots: none");
  } else {
    console.log("dependency roots:");
    for (const root of roots) {
      console.log(`  ${root.hostRelativePath}: ${root.ecosystem} ${root.tool} (${root.evidence}, ${root.confidence})`);
    }
  }
  const installCommands = dependencyOverlayInstallCommands(plan);
  if (installCommands.length === 0) {
    console.log("install commands: none");
  } else {
    console.log("install commands:");
    for (const command of installCommands) {
      console.log(`  ${command.hostRelativePath}: ${command.ecosystem} ${command.tool}: ${command.command}`);
    }
  }
  console.log(`workspace roots: ${plan.workspaceRoots.map((entry) => `${entry.ecosystem}:${entry.hostRelativePath}`).join(", ") || "none"}`);
  if (plan.overlays.length === 0) {
    console.log("overlays: none");
  } else {
    console.log("overlays:");
    for (const overlay of plan.overlays) {
      console.log(`  ${overlay.path} -> ${overlay.volume} (${overlay.reason})`);
    }
  }
  if (plan.ignoredCandidates.length > 0) {
    console.log("ignored candidates left visible:");
    for (const candidate of plan.ignoredCandidates) {
      console.log(`  ${candidate.hostRelativePath} (${candidate.reason})`);
    }
  }
  if ((plan.warnings ?? []).length > 0) {
    console.log("warnings:");
    for (const warning of plan.warnings ?? []) {
      console.log(`  ${warning.hostRelativePath} (${warning.reason})`);
    }
  }
  console.log(`runtime recreate required: ${changed ? "yes" : "no"}`);
}

export const PYPI_PREFLIGHT_REMEDIATION = "Run: runfree service enable python";

function dependencyOverlayVolumesFromPlan(context: RuntimeContext, plan: DependencyOverlayPlan): string[] {
  const prefix = `runfree-deps-${projectHash(fs.realpathSync(context.projectRoot))}-`;
  const volumes = [
    ...plan.overlays.map((overlay) => overlay.volume),
    ...plan.storeVolumes.map((store) => store.volume),
  ];
  for (const volume of volumes) {
    if (!volume.startsWith(prefix)) warn(`ignoring non-Runfree dependency volume in persisted plan: ${volume}`);
  }
  return Array.from(new Set(volumes.filter((volume) => volume.startsWith(prefix)))).sort();
}

function readPersistedDependencyOverlayPlanObject(context: RuntimeContext): DependencyOverlayPlan | undefined {
  const source = readPersistedDependencyOverlayPlan(context);
  if (!source) return undefined;
  try {
    return JSON.parse(source) as DependencyOverlayPlan;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    die(`could not parse dependency overlay plan: ${detail}`);
  }
}

type DependencyRuntimeAdapters = {
  docker: RuntimeDocker;
};

export type DependencyRuntimeStarter = (
  context: RuntimeContext,
  io: RuntimeIO,
) => Promise<{ context?: RuntimeContext; status: number }>;

// Typed deps intent built by the yargs deps command module.
export type DepsInput =
  | { kind: "plan" }
  | { kind: "install" }
  | { kind: "doctor" }
  | { kind: "reset"; force: boolean };

// Typed core for `runfree deps`. Receives a validated intent and performs no
// argument parsing.
export async function depsRuntime(
  input: DepsInput,
  context: RuntimeContext,
  io: RuntimeIO,
  adapters: DependencyRuntimeAdapters,
  startRuntime: DependencyRuntimeStarter,
): Promise<number> {
  switch (input.kind) {
    case "plan": {
      const { changed, plan } = prepareDependencyOverlayPlanResult(context, io);
      printDependencyOverlayPlan(plan, changed);
      return 0;
    }
    case "install": {
      // The per-session runtime has no shared agent to exec the package manager
      // in. Deliberately refuse with a supported workaround rather than fail
      // deep in resolveAgentExecTarget with a confusing "agent container is not
      // running". A per-session `deps install` (ephemeral helper / session
      // container) is tracked follow-up work.
      return die("`runfree deps install` is not yet available in the per-session runtime; run the package manager inside a `runfree shell` session for now");
    }
    case "doctor": {
      const prepared = prepareDependencyOverlayPlanResult(context, io);
      const liveMountDrift = dependencyOverlayMissingEmptySignatureRuntimeDrift(prepared, context, io, adapters.docker);
      const mountDrift = prepared.changed || liveMountDrift;
      printDependencyOverlayPlan(prepared.plan, mountDrift);
      if (prepared.previousStateIssue) console.log(`dependency overlay state issue: ${prepared.previousStateIssue}`);
      if (mountDrift) {
        console.log(`dependency overlay mount drift detected; recreate the runtime before relying on these mounts: ${remedy.rebuild()}`);
        return 1;
      }
      if (prepared.diagnosticChanged) {
        console.log("dependency overlay diagnostic drift detected; runtime recreate is not required");
        return 0;
      }
      console.log("dependency overlays: no drift detected");
      return 0;
    }
    case "reset": {
      const plan = readPersistedDependencyOverlayPlanObject(context);
      const volumes = plan ? dependencyOverlayVolumesFromPlan(context, plan) : [];
      if (volumes.length === 0) {
        console.log("no Runfree dependency volumes recorded for this project");
        return 0;
      }
      if (!input.force) {
        flushWarnings();
        if (!io.confirm(`Remove ${volumes.length} Runfree dependency volume(s)? [y/N] `)) return 1;
      }
      adapters.docker.assertAvailable();
      return io.run("docker", ["volume", "rm", ...volumes], dockerClientEnvOptions(context));
    }
  }
}
