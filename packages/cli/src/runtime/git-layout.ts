import { type SpawnSyncOptions, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { die } from "../errors.ts";
import type { RuntimeComposeMount } from "./compose.ts";
import { envOptions } from "./docker.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";
import { failClosedSpawnStatus } from "./spawn-status.ts";
import { sha256Hex } from "../strict-primitives.ts";

const WORKSPACE_ROOT = "/workspace";
const GIT_LAYOUT_ROOT = "/runfree/git-layout";

export type RelativeLinkedWorktree = {
  projectRoot: string;
  gitFile: string;
  gitDir: string;
  gitCommonDir: string;
  relativeGitDir: string;
  hostBase: string;
  projectRel: string;
  commonRel: string;
  containerBase: string;
  containerProjectRoot: string;
  containerCompatRoot: string;
  containerGitCommonDir: string;
  containerGitDir: string;
};

export type GitRepositoryShape =
  | { kind: "none" }
  | { kind: "normal"; gitDir: string }
  | { kind: "relative-linked"; details: RelativeLinkedWorktree }
  | { kind: "fatal"; reason: string; remediation?: string };

export type RuntimeGitLayoutPlan =
  | {
    version: 1;
    kind: "workspace";
    hostProjectRoot: string;
    containerProjectRoot: string;
    containerCompatRoot: string;
  }
  | {
    version: 1;
    kind: "relative-linked";
    hostProjectRoot: string;
    hostGitDir: string;
    hostGitCommonDir: string;
    hostBase: string;
    projectRel: string;
    commonRel: string;
    relativeGitDir: string;
    containerBase: string;
    containerProjectRoot: string;
    containerCompatRoot: string;
    containerGitCommonDir: string;
    containerGitDir: string;
  };

function remediation(projectRoot: string): string {
  return [
    `git -C ${projectRoot} worktree repair --relative-paths`,
    `git -C ${projectRoot} config --local worktree.useRelativePaths true`,
  ].join("\n  ");
}

function fatal(projectRoot: string, reason: string): GitRepositoryShape {
  return { kind: "fatal", reason, remediation: remediation(projectRoot) };
}

function firstNonEmptyLine(source: string): string | undefined {
  return source.split(/\r?\n/).find((line) => line.trim() !== "");
}

function realpathExisting(value: string): string | undefined {
  try {
    return fs.realpathSync(value);
  } catch {
    return undefined;
  }
}

function lstatExisting(value: string): fs.Stats | undefined {
  try {
    return fs.lstatSync(value);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
}

function isInsideOrSame(parent: string, child: string): boolean {
  const relative = path.relative(parent, child);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function isAbsoluteTopologyPath(value: string): boolean {
  const trimmed = value.trim();
  return path.isAbsolute(trimmed) || path.win32.isAbsolute(trimmed) || /^\\\\/.test(trimmed);
}

function readFirstLine(filePath: string): { line?: string; error?: string } {
  try {
    return { line: firstNonEmptyLine(fs.readFileSync(filePath, "utf8"))?.trim() };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

function resolveRelativeExistingDir(base: string, raw: string): string | undefined {
  if (isAbsoluteTopologyPath(raw)) return undefined;
  const resolved = realpathExisting(path.resolve(base, raw));
  if (!resolved) return undefined;
  return fs.statSync(resolved).isDirectory() ? resolved : undefined;
}

function resolveRelativeExistingPath(base: string, raw: string): string | undefined {
  if (isAbsoluteTopologyPath(raw)) return undefined;
  return realpathExisting(path.resolve(base, raw));
}

// Parse only this file, even when repository discovery is broken. Git owns
// config syntax and boolean conversion; includes remain outside this check.
function readGitConfigValue(filePath: string, key: string, boolean = false): string | undefined {
  if (!fs.existsSync(filePath)) return undefined;
  const result = spawnSync("git", [
    "config", "--file", "-", "--no-includes", "--null",
    ...(boolean ? ["--type=bool"] : []), "--get", key,
  ], {
    cwd: path.parse(path.resolve(filePath)).root,
    input: fs.readFileSync(filePath),
    encoding: "utf8",
    timeout: 5_000,
  });
  // A timeout, kill or spawn error never maps to 1 here, so 1 is Git's own "not set".
  const { status } = failClosedSpawnStatus(result);
  if (status === 1) return undefined;
  if (status !== 0) {
    throw new Error(`${filePath}: Git could not read ${key}: ${result.error?.message ?? result.stderr.trim()}`);
  }
  return result.stdout.replace(/\0$/, "");
}

function validateRelativeConfigValue(filePath: string, key: string): string | undefined {
  const value = readGitConfigValue(filePath, key);
  if (value !== undefined && isAbsoluteTopologyPath(value)) {
    return `${filePath}: ${key} must be relative`;
  }
  return undefined;
}

function validateAlternates(gitCommonDir: string): string | undefined {
  const alternates = path.join(gitCommonDir, "objects", "info", "alternates");
  if (!fs.existsSync(alternates)) return undefined;
  const lines = fs.readFileSync(alternates, "utf8").split(/\r?\n/);
  const absolute = lines.map((line) => line.trim()).find((line) => line !== "" && isAbsoluteTopologyPath(line));
  return absolute ? `${alternates}: object alternate paths must be relative` : undefined;
}

function collectNestedGitfiles(projectRoot: string, topGitFile: string): string[] | { fatal: string } {
  const gitfiles: string[] = [];

  function visit(dir: string): string | undefined {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return undefined;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.name === ".git") {
        if (fullPath === topGitFile) continue;
        const stat = lstatExisting(fullPath);
        if (!stat) continue;
        if (stat.isSymbolicLink()) return `${fullPath}: submodule .git must not be a symlink`;
        if (stat.isFile()) gitfiles.push(fullPath);
        continue;
      }
      if (!entry.isDirectory()) continue;
      if (entry.name === ".runfree" || entry.name === "node_modules") continue;
      const nested = visit(fullPath);
      if (nested) return nested;
    }
    return undefined;
  }

  const issue = visit(projectRoot);
  return issue ? { fatal: issue } : gitfiles;
}

function validateSubmoduleGitfile(gitfile: string): string | undefined {
  const line = readFirstLine(gitfile);
  if (line.error) return `${gitfile}: could not read submodule gitfile: ${line.error}`;
  if (!line.line?.startsWith("gitdir:")) return `${gitfile}: submodule .git file must start with gitdir:`;
  const rawGitDir = line.line.slice("gitdir:".length).trim();
  if (rawGitDir === "") return `${gitfile}: submodule gitdir is empty`;
  if (isAbsoluteTopologyPath(rawGitDir)) return `${gitfile}: submodule gitdir must be relative`;
  const gitDir = resolveRelativeExistingDir(path.dirname(gitfile), rawGitDir);
  if (!gitDir) return `${gitfile}: submodule gitdir does not resolve to an existing directory`;
  return validateRelativeConfigValue(path.join(gitDir, "config"), "core.worktree")
    ?? validateRelativeConfigValue(path.join(gitDir, "config.worktree"), "core.worktree");
}

function commonAncestor(paths: string[]): string {
  if (paths.length === 0) return path.parse(process.cwd()).root;
  const resolved = paths.map((entry) => path.resolve(entry));
  const [first, ...rest] = resolved.map((entry) => entry.split(path.sep).filter(Boolean));
  const root = path.parse(resolved[0]).root;
  const common: string[] = [];
  for (let index = 0; index < first.length; index += 1) {
    const part = first[index];
    if (rest.every((entry) => entry[index] === part)) common.push(part);
    else break;
  }
  return path.join(root, ...common);
}

function posixRelative(from: string, to: string): string {
  const relative = path.relative(from, to).split(path.sep).join(path.posix.sep);
  return relative === "" ? "." : relative;
}

function containerJoin(base: string, relative: string): string {
  return relative === "." ? base : path.posix.join(base, relative);
}

function projectLayoutId(projectRoot: string): string {
  return sha256Hex(projectRoot).slice(0, 12);
}

function assertNoOverlappingGitLayout(details: RelativeLinkedWorktree): string | undefined {
  const project = details.containerProjectRoot;
  const common = details.containerGitCommonDir;
  if (project === common || project.startsWith(`${common}/`) || common.startsWith(`${project}/`)) {
    return `computed Git layout mount targets overlap: ${project} and ${common}`;
  }
  return undefined;
}

function relativeLinkedDetails(projectRoot: string, gitFile: string, gitDir: string, gitCommonDir: string): RelativeLinkedWorktree {
  const hostBase = commonAncestor([projectRoot, gitCommonDir]);
  const projectRel = posixRelative(hostBase, projectRoot);
  const commonRel = posixRelative(hostBase, gitCommonDir);
  const relativeGitDir = posixRelative(gitCommonDir, gitDir);
  const containerBase = path.posix.join(GIT_LAYOUT_ROOT, projectLayoutId(projectRoot));
  const containerProjectRoot = containerJoin(containerBase, projectRel);
  const containerGitCommonDir = containerJoin(containerBase, commonRel);
  return {
    projectRoot,
    gitFile,
    gitDir,
    gitCommonDir,
    relativeGitDir,
    hostBase,
    projectRel,
    commonRel,
    containerBase,
    containerProjectRoot,
    containerCompatRoot: containerProjectRoot,
    containerGitCommonDir,
    containerGitDir: containerJoin(containerGitCommonDir, relativeGitDir),
  };
}

// Only inspect registered worktrees inside the main checkout's bind mount.
// A stale /workspace backlink is translated only to locate that same nested
// worktree on the host; it is never accepted as a portable link or a mount.
function nestedWorktrees(projectRoot: string, gitCommonDir: string): { projectRoot: string; gitDir: string }[] {
  const registry = path.join(gitCommonDir, "worktrees");
  const registryStat = lstatExisting(registry);
  if (!registryStat) return [];
  if (!registryStat.isDirectory()) throw new Error(`${registry}: worktree registry must be a directory, not a link`);
  const result: { projectRoot: string; gitDir: string }[] = [];
  for (const entry of fs.readdirSync(registry, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const gitDir = path.join(registry, entry.name);
    const backlinkFile = path.join(gitDir, "gitdir");
    const backlinkStat = lstatExisting(backlinkFile);
    if (!backlinkStat) continue;
    if (!backlinkStat.isFile() || backlinkStat.nlink > 1 || backlinkStat.size > 4096) {
      throw new Error(`${backlinkFile}: worktree backlink must be a small regular single-link file`);
    }
    const backlink = readFirstLine(backlinkFile);
    if (backlink.error) throw new Error(`${backlinkFile}: ${backlink.error}`);
    if (!backlink.line) continue;
    const hostGitfile = backlink.line.startsWith(`${WORKSPACE_ROOT}/`)
      ? path.resolve(projectRoot, backlink.line.slice(WORKSPACE_ROOT.length + 1))
      : path.resolve(gitDir, backlink.line);
    if (!isInsideOrSame(projectRoot, hostGitfile) || path.basename(hostGitfile) !== ".git") continue;
    const nestedRoot = path.dirname(hostGitfile);
    if (nestedRoot === projectRoot || !lstatExisting(nestedRoot)) continue;
    if (fs.realpathSync(nestedRoot) !== nestedRoot) {
      throw new Error(`${nestedRoot}: nested worktree path must not contain symlinks`);
    }
    result.push({ projectRoot: nestedRoot, gitDir });
  }
  return result.sort((a, b) => a.projectRoot.localeCompare(b.projectRoot));
}

function classifyMainRepository(projectRoot: string, gitDir: string): GitRepositoryShape {
  const refuse = (reason: string): GitRepositoryShape => ({
    kind: "fatal",
    reason,
    remediation: [
      `cd '${projectRoot.replaceAll("'", "'\\''")}'`,
      "runfree git repair-worktree-links",
    ].join("\n  "),
  });
  try {
    const relativeDefault = readGitConfigValue(path.join(gitDir, "config"), "worktree.useRelativePaths", true);
    if (relativeDefault !== undefined && relativeDefault !== "true") {
      return refuse(`${gitDir}/config: worktree.useRelativePaths must not disable relative links`);
    }
    for (const nested of nestedWorktrees(projectRoot, gitDir)) {
      if (!lstatExisting(path.join(nested.projectRoot, ".git"))?.isFile()) {
        return refuse(`${nested.projectRoot}: registered nested worktree must have a regular .git file`);
      }
      const shape = classifyGitRepositoryAtRoot(nested.projectRoot, false);
      if (shape.kind === "fatal") return refuse(shape.reason);
      if (shape.kind !== "relative-linked" || shape.details.gitDir !== nested.gitDir || shape.details.gitCommonDir !== gitDir) {
        return refuse(`${nested.projectRoot}: registered nested worktree must link back to ${nested.gitDir}`);
      }
    }
    return { kind: "normal", gitDir };
  } catch (error) {
    return refuse(error instanceof Error ? error.message : String(error));
  }
}

export function classifyGitRepository(projectRootInput: string): GitRepositoryShape {
  try {
    return classifyGitRepositoryAtRoot(projectRootInput, true);
  } catch (error) {
    return fatal(projectRootInput, error instanceof Error ? error.message : String(error));
  }
}

function classifyGitRepositoryAtRoot(projectRootInput: string, requireLocalRelativeDefault: boolean): GitRepositoryShape {
  const projectRoot = fs.existsSync(projectRootInput)
    ? fs.realpathSync(projectRootInput)
    : path.resolve(projectRootInput);
  const gitFile = path.join(projectRoot, ".git");
  const stat = lstatExisting(gitFile);
  if (!stat) return { kind: "none" };
  if (stat.isDirectory()) return classifyMainRepository(projectRoot, fs.realpathSync(gitFile));
  if (stat.isSymbolicLink()) return fatal(projectRoot, `${gitFile}: .git must not be a symlink`);
  if (!stat.isFile()) return fatal(projectRoot, `${gitFile}: .git must be a directory or regular gitfile`);
  if (stat.nlink > 1) return fatal(projectRoot, `${gitFile}: .git gitfile must not be hard-linked`);

  const gitLine = readFirstLine(gitFile);
  if (gitLine.error) return fatal(projectRoot, `${gitFile}: could not read .git file: ${gitLine.error}`);
  if (!gitLine.line?.startsWith("gitdir:")) return fatal(projectRoot, `${gitFile}: .git file must start with gitdir:`);
  const rawGitDir = gitLine.line.slice("gitdir:".length).trim();
  if (rawGitDir === "") return fatal(projectRoot, `${gitFile}: gitdir is empty`);
  if (isAbsoluteTopologyPath(rawGitDir)) return fatal(projectRoot, `${gitFile}: gitdir must be relative`);
  const gitDir = resolveRelativeExistingDir(projectRoot, rawGitDir);
  if (!gitDir) return fatal(projectRoot, `${gitFile}: relative gitdir does not resolve to an existing directory`);

  const commonDirFile = path.join(gitDir, "commondir");
  const commonDirLine = readFirstLine(commonDirFile);
  if (commonDirLine.error) return fatal(projectRoot, `${commonDirFile}: commondir is required and must be readable`);
  const rawCommonDir = commonDirLine.line?.trim() ?? "";
  if (rawCommonDir === "") return fatal(projectRoot, `${commonDirFile}: commondir is empty`);
  if (isAbsoluteTopologyPath(rawCommonDir)) return fatal(projectRoot, `${commonDirFile}: commondir must be relative`);
  const gitCommonDir = resolveRelativeExistingDir(gitDir, rawCommonDir);
  if (!gitCommonDir) return fatal(projectRoot, `${commonDirFile}: relative commondir does not resolve to an existing directory`);
  if (!isInsideOrSame(gitCommonDir, gitDir)) {
    return fatal(projectRoot, `${gitDir}: linked worktree git directory must be inside common Git directory ${gitCommonDir}`);
  }

  const backlinkFile = path.join(gitDir, "gitdir");
  const backlinkLine = readFirstLine(backlinkFile);
  if (backlinkLine.error) return fatal(projectRoot, `${backlinkFile}: backlink gitdir is required and must be readable`);
  const rawBacklink = backlinkLine.line?.trim() ?? "";
  if (rawBacklink === "") return fatal(projectRoot, `${backlinkFile}: backlink gitdir is empty`);
  if (isAbsoluteTopologyPath(rawBacklink)) return fatal(projectRoot, `${backlinkFile}: backlink gitdir must be relative`);
  const backlink = resolveRelativeExistingPath(gitDir, rawBacklink);
  const gitFileRealpath = fs.realpathSync(gitFile);
  if (backlink !== gitFileRealpath) {
    return fatal(projectRoot, `${backlinkFile}: backlink gitdir must resolve back to ${gitFile}`);
  }

  const commonConfig = path.join(gitCommonDir, "config");
  if (readGitConfigValue(commonConfig, "extensions.relativeWorktrees", true) !== "true") {
    return fatal(projectRoot, `${commonConfig}: extensions.relativeWorktrees must be true`);
  }
  if (requireLocalRelativeDefault && readGitConfigValue(commonConfig, "worktree.useRelativePaths", true) !== "true") {
    return fatal(projectRoot, `${commonConfig}: worktree.useRelativePaths must be true`);
  }

  const configWorktreeIssue = validateRelativeConfigValue(path.join(gitDir, "config.worktree"), "core.worktree");
  if (configWorktreeIssue) return fatal(projectRoot, configWorktreeIssue);
  const alternatesIssue = validateAlternates(gitCommonDir);
  if (alternatesIssue) return fatal(projectRoot, alternatesIssue);
  const submoduleGitfiles = collectNestedGitfiles(projectRoot, gitFile);
  if (!Array.isArray(submoduleGitfiles)) return fatal(projectRoot, submoduleGitfiles.fatal);
  for (const submoduleGitfile of submoduleGitfiles) {
    const issue = validateSubmoduleGitfile(submoduleGitfile);
    if (issue) return fatal(projectRoot, issue);
  }

  const details = relativeLinkedDetails(projectRoot, gitFile, gitDir, gitCommonDir);
  const layoutIssue = assertNoOverlappingGitLayout(details);
  if (layoutIssue) return fatal(projectRoot, layoutIssue);
  return { kind: "relative-linked", details };
}

/**
 * The host project root as the filesystem itself names it.
 *
 * A Git layout records mount sources, so it has to resolve symlinks: on macOS
 * `os.tmpdir()` and `/tmp` are `/var/...` spellings of `/private/var/...`, and
 * a project reached through any symlinked parent has the same two names. Every
 * consumer that compares a path against a planned layout must canonicalize it
 * the same way, or the two spellings of one directory read as two directories.
 *
 * Deliberately not applied to project identity: `projectHash` and
 * `composeProjectName` derive from the root as configured, so canonicalizing
 * there would rename an existing project's Compose stack and state directory.
 */
export function canonicalHostProjectRoot(projectRootInput: string): string {
  return fs.existsSync(projectRootInput)
    ? fs.realpathSync(projectRootInput)
    : path.resolve(projectRootInput);
}

export function gitLayoutPlanForShape(projectRootInput: string, shape: GitRepositoryShape): RuntimeGitLayoutPlan {
  const projectRoot = canonicalHostProjectRoot(projectRootInput);
  if (shape.kind !== "relative-linked") {
    return {
      version: 1,
      kind: "workspace",
      hostProjectRoot: projectRoot,
      containerProjectRoot: WORKSPACE_ROOT,
      containerCompatRoot: WORKSPACE_ROOT,
    };
  }
  const details = shape.details;
  return {
    version: 1,
    kind: "relative-linked",
    hostProjectRoot: details.projectRoot,
    hostGitDir: details.gitDir,
    hostGitCommonDir: details.gitCommonDir,
    hostBase: details.hostBase,
    projectRel: details.projectRel,
    commonRel: details.commonRel,
    relativeGitDir: details.relativeGitDir,
    containerBase: details.containerBase,
    containerProjectRoot: details.containerProjectRoot,
    containerCompatRoot: details.containerCompatRoot,
    containerGitCommonDir: details.containerGitCommonDir,
    containerGitDir: details.containerGitDir,
  };
}

export function serializeGitLayoutPlan(plan: RuntimeGitLayoutPlan): string {
  return `${JSON.stringify(plan, null, 2)}\n`;
}

export function formatGitRepositoryShapeError(shape: Extract<GitRepositoryShape, { kind: "fatal" }>): string {
  return [
    "Runfree only supports Git linked worktrees that use relative links.",
    "",
    "This worktree uses unsupported or unsafe Git metadata:",
    `  ${shape.reason}`,
    "",
    "Repair it on the host with:",
    `  ${shape.remediation ?? ""}`,
    "",
    "Then rerun runfree.",
  ].join("\n");
}

function gitLayoutPlanPath(context: RuntimeContext): string {
  return path.join(context.project.paths.stateDir, "git-layout-plan.json");
}

export function readPersistedGitLayoutPlan(context: RuntimeContext): RuntimeGitLayoutPlan | undefined {
  try {
    return JSON.parse(fs.readFileSync(gitLayoutPlanPath(context), "utf8")) as RuntimeGitLayoutPlan;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    const detail = error instanceof Error ? error.message : String(error);
    die(`could not parse Git layout plan: ${detail}`);
  }
}

function writeGitLayoutPlan(context: RuntimeContext, plan: RuntimeGitLayoutPlan): void {
  fs.mkdirSync(path.dirname(gitLayoutPlanPath(context)), { recursive: true, mode: 0o700 });
  fs.writeFileSync(gitLayoutPlanPath(context), serializeGitLayoutPlan(plan), { mode: 0o600 });
}

export type PreparedGitRepositoryLayout = {
  changed: boolean;
  plan: RuntimeGitLayoutPlan;
  shape: GitRepositoryShape;
};

export function prepareGitRepositoryLayoutResult(context: RuntimeContext): PreparedGitRepositoryLayout {
  const shape = classifyGitRepository(context.projectRoot);
  if (shape.kind === "fatal") die(formatGitRepositoryShapeError(shape));
  const plan = gitLayoutPlanForShape(context.projectRoot, shape);
  const serialized = serializeGitLayoutPlan(plan);
  const previous = readPersistedGitLayoutPlan(context);
  const changed = previous === undefined
    ? plan.kind === "relative-linked"
    : serializeGitLayoutPlan(previous) !== serialized;
  return { changed, plan, shape };
}

export function prepareGitRepositoryLayout(context: RuntimeContext): RuntimeGitLayoutPlan {
  return prepareGitRepositoryLayoutResult(context).plan;
}

export function persistGitRepositoryLayout(context: RuntimeContext, plan: RuntimeGitLayoutPlan): void {
  writeGitLayoutPlan(context, plan);
}

export function projectMountsForGitLayout(plan: RuntimeGitLayoutPlan): RuntimeComposeMount[] {
  const mounts: RuntimeComposeMount[] = [
    {
      type: "bind",
      source: "${RUNFREE_PROJECT_ROOT:-..}",
      target: plan.containerProjectRoot,
    },
  ];
  if (plan.kind === "relative-linked") {
    mounts.push({
      type: "bind",
      source: "${RUNFREE_GIT_COMMON_DIR:?RUNFREE_GIT_COMMON_DIR is required}",
      target: plan.containerGitCommonDir,
    });
  }
  return mounts;
}

function gitHelpSupportsRelativeWorktree(io: RuntimeIO, options: SpawnSyncOptions, subcommand: "add" | "repair"): boolean {
  const result = io.capture("git", ["worktree", subcommand, "-h"], options);
  return `${result.stdout}\n${result.stderr}`.includes("--[no-]relative-paths")
    || `${result.stdout}\n${result.stderr}`.includes("--relative-paths");
}

export function assertHostGitSupportsRelativeWorktrees(context: RuntimeContext, io: RuntimeIO): void {
  // Subcommand help requires a repository. Use a disposable one so the probe
  // also works outside Git projects and while repairing broken project links.
  const probe = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-git-probe-"));
  const env = Object.fromEntries(Object.entries(context.env ?? process.env).filter(([key]) => !key.startsWith("GIT_")));
  const options: SpawnSyncOptions = {
    cwd: probe,
    env: { ...env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" },
    timeout: 5_000,
  };
  try {
    const initialized = io.capture("git", ["init", "--bare", "--quiet", "--template=", probe], options);
    if (initialized.status !== 0 || !gitHelpSupportsRelativeWorktree(io, options, "repair") || !gitHelpSupportsRelativeWorktree(io, options, "add")) {
      die("host Git does not support relative worktree links; install a Git version with git worktree --relative-paths support");
    }
  } finally {
    fs.rmSync(probe, { recursive: true, force: true });
  }
}

export function worktreeRepairCandidateFiles(projectRoot: string): string[] {
  const files = new Set<string>();
  const gitFile = path.join(projectRoot, ".git");
  if (lstatExisting(gitFile)?.isDirectory()) {
    files.add(path.join(gitFile, "config"));
    for (const nested of nestedWorktrees(fs.realpathSync(projectRoot), fs.realpathSync(gitFile))) {
      files.add(path.join(nested.projectRoot, ".git"));
      files.add(path.join(nested.gitDir, "gitdir"));
    }
    return [...files].sort();
  }
  files.add(gitFile);
  let rawGitDir: string | undefined;
  try {
    const line = fs.readFileSync(gitFile, "utf8").split(/\r?\n/).find((entry) => entry.trim() !== "")?.trim();
    if (line?.startsWith("gitdir:")) rawGitDir = line.slice("gitdir:".length).trim();
  } catch {
    return [...files];
  }
  if (!rawGitDir) return [...files];
  const gitDir = path.resolve(projectRoot, rawGitDir);
  for (const file of ["commondir", "gitdir", "config.worktree"]) {
    files.add(path.join(gitDir, file));
  }
  let commonDir: string | undefined;
  try {
    const rawCommonDir = fs.readFileSync(path.join(gitDir, "commondir"), "utf8").split(/\r?\n/).find((entry) => entry.trim() !== "")?.trim();
    if (rawCommonDir) commonDir = path.resolve(gitDir, rawCommonDir);
  } catch {
    commonDir = undefined;
  }
  if (commonDir) {
    files.add(path.join(commonDir, "config"));
    files.add(path.join(commonDir, "objects", "info", "alternates"));
  }
  return [...files].sort();
}

// Typed core for `runfree git repair-worktree-links`. The grammar (the single
// subcommand) is validated by the yargs command module, so this performs no
// argument parsing.
export async function repairWorktreeLinks(context: RuntimeContext, io: RuntimeIO): Promise<number> {
  assertHostGitSupportsRelativeWorktrees(context, io);

  console.log("Runfree will ask Git to repair relative worktree links for these metadata files when present:");
  for (const file of worktreeRepairCandidateFiles(context.projectRoot)) {
    console.log(`  ${file}`);
  }

  const mainGitDir = path.join(context.projectRoot, ".git");
  const repairTargets = lstatExisting(mainGitDir)?.isDirectory()
    ? nestedWorktrees(fs.realpathSync(context.projectRoot), fs.realpathSync(mainGitDir)).map((entry) => entry.projectRoot)
    : [];
  const repair = io.run("git", ["-C", context.projectRoot, "worktree", "repair", "--relative-paths", ...repairTargets], envOptions(context.env));
  if (repair !== 0) return repair;
  const config = io.run("git", ["-C", context.projectRoot, "config", "--local", "worktree.useRelativePaths", "true"], envOptions(context.env));
  if (config !== 0) return config;

  const shape = classifyGitRepository(context.projectRoot);
  if (shape.kind === "fatal") {
    console.error(formatGitRepositoryShapeError(shape));
    return 1;
  }
  console.log("Git worktree links passed Runfree relative-only validation.");
  return 0;
}
