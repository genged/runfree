
import fs from "node:fs";
import path from "node:path";

import {
  normalizedAgentBuildConfig,
  selectedProjectAgentImageInput,
  stageAgentBuildContext,
  stagedAgentBuildContextManifest,
  type BuildContextManifestEntry,
  type LegacyInjectedBuildArgument,
} from "../agent-image.ts";
import type { AgentBuildConfig, ProjectInfo } from "../config.ts";
import { copyRegularFileNoFollow } from "../safe-fs.ts";
import {
  approvedSubjectDirectory,
  readControlApprovalSelection,
  selectSubjectApproval,
  type ControlApprovalMechanism,
  type ControlApprovalSelection,
} from "./approvals.ts";
import { imageBuildControlSubject, type ControlSubject } from "./subjects.ts";
import { parseStrictJson } from "./strict-json.ts";
import { assertAllowedKeys as exactKeys, isDigest, isRecord } from "../strict-primitives.ts";

const IMAGE_CANDIDATE_ROOT = "image-build";
const CONTEXT_DIRECTORY = "context";
const SUBJECT_FILE = "subject.json";

export type NarrowImageBuildCandidate = {
  build: AgentBuildConfig;
  contextPath: string;
  directory: string;
  dockerfilePath: string;
  inputDigest: string;
  manifest: BuildContextManifestEntry[];
  referencedLegacyInjectedArguments: readonly LegacyInjectedBuildArgument[];
  subject: ControlSubject;
};

export type ApprovedNarrowImageBuild = NarrowImageBuildCandidate;





function immutableDirectoryName(digest: string): string {
  if (!isDigest(digest)) throw new Error("image-build subject digest is malformed");
  return digest.slice("sha256:".length);
}

function subjectContents(subject: ControlSubject): string {
  return `${JSON.stringify(subject.payload, null, 2)}\n`;
}

function writeDurableFile(filePath: string, contents: string): void {
  const descriptor = fs.openSync(filePath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o400);
  try {
    fs.writeFileSync(descriptor, contents);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function readRegularSingleLink(filePath: string, label: string): string {
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    throw new Error(`${label} is not a regular single-link file`);
  }
  return fs.readFileSync(filePath, "utf8");
}

function validateBuild(raw: unknown): AgentBuildConfig {
  if (!isRecord(raw)) throw new Error("image-build build config must be an object");
  exactKeys(raw, ["args", "context", "dockerfile", "target"], "image-build build config");
  if (typeof raw.context !== "string" || raw.context.length === 0
    || typeof raw.dockerfile !== "string" || raw.dockerfile.length === 0) {
    throw new Error("image-build build paths are malformed");
  }
  if (raw.target !== undefined && (typeof raw.target !== "string" || raw.target.length === 0)) {
    throw new Error("image-build target is malformed");
  }
  let args: Record<string, string> | undefined;
  if (raw.args !== undefined) {
    if (!isRecord(raw.args) || Object.entries(raw.args).some(([name, value]) => name.length === 0 || typeof value !== "string")) {
      throw new Error("image-build args are malformed");
    }
    args = Object.fromEntries(Object.entries(raw.args).map(([name, value]) => [name, value as string]));
  }
  return normalizedAgentBuildConfig({
    context: raw.context,
    dockerfile: raw.dockerfile,
    ...(raw.target === undefined ? {} : { target: raw.target }),
    ...(args === undefined ? {} : { args }),
  });
}

function validateManifest(raw: unknown): BuildContextManifestEntry[] {
  if (!Array.isArray(raw)) throw new Error("image-build context manifest must be an array");
  const entries: BuildContextManifestEntry[] = raw.map((value, index) => {
    if (!isRecord(value)) throw new Error(`image-build context manifest entry ${index} must be an object`);
    if (value.type !== "directory" && value.type !== "file") {
      throw new Error(`image-build context manifest entry ${index} has an unsupported type`);
    }
    exactKeys(
      value,
      value.type === "directory" ? ["mode", "path", "type"] : ["mode", "path", "sha256", "size", "type"],
      `image-build context manifest entry ${index}`,
    );
    if (typeof value.path !== "string" || value.path.length === 0 || path.isAbsolute(value.path)
      || value.path.split(/[\\/]/).some((part) => part.length === 0 || part === "." || part === "..")) {
      throw new Error(`image-build context manifest entry ${index} has an unsafe path`);
    }
    if (!Number.isSafeInteger(value.mode) || Number(value.mode) < 0 || Number(value.mode) > 0o777) {
      throw new Error(`image-build context manifest entry ${index} has an invalid mode`);
    }
    if (value.type === "directory") {
      return { mode: Number(value.mode), path: value.path, type: "directory" };
    }
    if (!isDigest(value.sha256) || !Number.isSafeInteger(value.size) || Number(value.size) < 0) {
      throw new Error(`image-build context manifest entry ${index} has invalid file identity`);
    }
    return {
      mode: Number(value.mode),
      path: value.path,
      sha256: value.sha256,
      size: Number(value.size),
      type: "file",
    };
  });
  const paths = entries.map((entry) => entry.path);
  if (new Set(paths).size !== paths.length
    || paths.some((entry, index) => index > 0 && (paths[index - 1]?.localeCompare(entry) ?? -1) >= 0)) {
    throw new Error("image-build context manifest paths must be unique and sorted");
  }
  return entries;
}

function parseSubject(source: string): {
  build: AgentBuildConfig;
  contextManifest: BuildContextManifestEntry[];
  subject: ControlSubject;
} {
  const raw = parseStrictJson(source);
  if (!isRecord(raw)) throw new Error("image-build subject must be an object");
  exactKeys(raw, ["build", "contextKind", "contextManifest", "schemaVersion", "subjectType"], "image-build subject");
  if (raw.schemaVersion !== 1 || raw.subjectType !== "image-build" || raw.contextKind !== "narrow") {
    throw new Error("image-build subject identity is malformed");
  }
  const build = validateBuild(raw.build);
  const contextManifest = validateManifest(raw.contextManifest);
  const subject = imageBuildControlSubject({ build, contextKind: "narrow", contextManifest });
  if (source !== subjectContents(subject)) throw new Error("image-build subject is not canonical");
  return { build, contextManifest, subject };
}

function verifySnapshotDirectory(directory: string, expectedDigest?: string): ApprovedNarrowImageBuild {
  const contextPath = path.join(directory, CONTEXT_DIRECTORY);
  const subjectSource = readRegularSingleLink(path.join(directory, SUBJECT_FILE), "image-build subject");
  const parsed = parseSubject(subjectSource);
  if (expectedDigest !== undefined && parsed.subject.digest !== expectedDigest) {
    throw new Error("image-build snapshot has the wrong subject digest");
  }
  // The subject payload is the store; its parsed digest plus the context
  // re-hash below are the proof. A manifest file written by an older release
  // is ignored rather than required.
  const actualContextManifest = stagedAgentBuildContextManifest(contextPath);
  if (JSON.stringify(actualContextManifest) !== JSON.stringify(parsed.contextManifest)) {
    throw new Error("image-build staged context does not match its approved manifest");
  }
  const dockerfileRelativePath = path.relative(parsed.build.context, parsed.build.dockerfile);
  if (dockerfileRelativePath.length === 0 || path.isAbsolute(dockerfileRelativePath) || dockerfileRelativePath.startsWith(`..${path.sep}`)) {
    throw new Error("approved image-build Dockerfile is outside its context");
  }
  const dockerfilePath = path.join(contextPath, dockerfileRelativePath);
  const dockerfile = Buffer.from(readRegularSingleLink(dockerfilePath, "approved image-build Dockerfile"));
  // The input digest is derived fresh from the verified bytes plus the current
  // embedded runtime identity; it names the image to build, so it must track
  // runfree upgrades while the approval subject above stays stable.
  const selected = selectedProjectAgentImageInput(parsed.build, "narrow", actualContextManifest, dockerfile);
  return {
    build: parsed.build,
    contextPath,
    directory,
    dockerfilePath,
    inputDigest: selected.digest,
    manifest: actualContextManifest,
    referencedLegacyInjectedArguments: selected.referencedLegacyInjectedArguments,
    subject: parsed.subject,
  };
}

function copyContext(source: string, destination: string, manifest: readonly BuildContextManifestEntry[]): void {
  fs.mkdirSync(destination, { mode: 0o700 });
  for (const entry of manifest) {
    const sourcePath = path.join(source, entry.path);
    const destinationPath = path.join(destination, entry.path);
    const sourceStat = fs.lstatSync(sourcePath);
    if (entry.type === "directory") {
      if (!sourceStat.isDirectory() || sourceStat.isSymbolicLink()) throw new Error("image-build candidate context changed before approval");
      fs.mkdirSync(destinationPath, { mode: entry.mode });
      fs.chmodSync(destinationPath, entry.mode);
      continue;
    }
    fs.mkdirSync(path.dirname(destinationPath), { recursive: true, mode: 0o700 });
    copyRegularFileNoFollow(sourcePath, destinationPath, sourceStat);
  }
}

export function captureNarrowImageBuildCandidate(
  projectRoot: string,
  build: AgentBuildConfig,
  candidateRoot: string,
): NarrowImageBuildCandidate {
  const root = path.join(candidateRoot, IMAGE_CANDIDATE_ROOT);
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const rootStat = fs.lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new Error("image-build candidate root must be a normal directory");
  fs.chmodSync(root, 0o700);
  const temporary = fs.mkdtempSync(path.join(root, ".candidate-"));
  try {
    fs.chmodSync(temporary, 0o700);
    const staged = stageAgentBuildContext(projectRoot, build, temporary);
    const subject = imageBuildControlSubject({
      build,
      contextKind: "narrow",
      contextManifest: staged.manifest,
    });
    fs.renameSync(staged.contextPath, path.join(temporary, CONTEXT_DIRECTORY));
    writeDurableFile(path.join(temporary, SUBJECT_FILE), subjectContents(subject));
    const directory = path.join(root, immutableDirectoryName(subject.digest));
    if (fs.existsSync(directory)) {
      fs.rmSync(temporary, { recursive: true, force: true });
      return verifySnapshotDirectory(directory, subject.digest);
    }
    fs.renameSync(temporary, directory);
    return verifySnapshotDirectory(directory, subject.digest);
  } catch (error) {
    fs.rmSync(temporary, { recursive: true, force: true });
    throw error;
  }
}

export function verifyNarrowImageBuildCandidate(candidate: NarrowImageBuildCandidate): void {
  const verified = verifySnapshotDirectory(candidate.directory, candidate.subject.digest);
  if (verified.inputDigest !== candidate.inputDigest
    || JSON.stringify(verified.manifest) !== JSON.stringify(candidate.manifest)
    || JSON.stringify(verified.build) !== JSON.stringify(candidate.build)) {
    throw new Error("image-build candidate does not match its immutable snapshot");
  }
}

function publishApprovedSnapshot(project: ProjectInfo, candidate: NarrowImageBuildCandidate): ApprovedNarrowImageBuild {
  verifyNarrowImageBuildCandidate(candidate);
  const target = approvedSubjectDirectory(project, "image-build", candidate.subject.digest);
  if (fs.existsSync(target)) {
    try {
      return verifySnapshotDirectory(target, candidate.subject.digest);
    } catch {
      // A same-digest snapshot that fails verification is corrupt host state.
      // The caller holds a freshly verified candidate under explicit approval,
      // so replacing the snapshot is the reclamation path for that wedge.
      // Publication takes no lock: concurrent same-digest publishers converge
      // on verified identical bytes or throw; none can land unverified state.
      fs.rmSync(target, { recursive: true, force: true });
    }
  }
  const parent = path.dirname(target);
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const temporary = fs.mkdtempSync(path.join(parent, ".approved-"));
  try {
    fs.chmodSync(temporary, 0o700);
    copyContext(candidate.contextPath, path.join(temporary, CONTEXT_DIRECTORY), candidate.manifest);
    writeDurableFile(path.join(temporary, SUBJECT_FILE), subjectContents(candidate.subject));
    fs.renameSync(temporary, target);
    return verifySnapshotDirectory(target, candidate.subject.digest);
  } catch (error) {
    fs.rmSync(temporary, { recursive: true, force: true });
    throw error;
  }
}

export function approveNarrowImageBuildCandidate(
  projectRoot: string,
  project: ProjectInfo,
  candidate: NarrowImageBuildCandidate,
  mechanism: ControlApprovalMechanism,
  now = new Date(),
): { approved: ApprovedNarrowImageBuild; selection: ControlApprovalSelection } {
  const approved = publishApprovedSnapshot(project, candidate);
  const selection = selectSubjectApproval(projectRoot, project, candidate.subject, mechanism, now);
  return { approved, selection };
}

export function readApprovedNarrowImageBuild(
  projectRoot: string,
  project: ProjectInfo,
): ApprovedNarrowImageBuild | undefined {
  const selection = readControlApprovalSelection(projectRoot, project);
  const record = selection?.subjects["image-build"];
  if (!record) return undefined;
  return verifySnapshotDirectory(approvedSubjectDirectory(project, "image-build", record.digest), record.digest);
}

/** Verify one approved image-build snapshot by digest. Used by migration. */
export function verifyApprovedImageSnapshot(project: ProjectInfo, digest: string): ApprovedNarrowImageBuild {
  return verifySnapshotDirectory(approvedSubjectDirectory(project, "image-build", digest), digest);
}

/**
 * Thrown only when a same-digest approved snapshot fails verification. Callers
 * may recover from this by re-prompting over a freshly staged candidate;
 * selection-level failures (checkout binding, malformed record) propagate as
 * plain errors and must abort instead.
 */
export class ApprovedImageBuildSnapshotError extends Error {}

/**
 * Resolve the approved snapshot from the context manifest already computed this
 * launch, without staging a candidate.
 *
 * Staging copies every file in the narrow context and deletes the copy again
 * when the digest already matches, so checking the approval from a staged
 * candidate would add a copy-and-discard to every cached launch. The subject
 * digest needs only the manifest, and `stageAgentBuildContext` derives its
 * manifest from the same `validateBuildContextTree` call, so skipping the copy
 * changes no digest. Staging stays required to build, and to show the user the
 * files being approved — neither of which is needed when the approval matches.
 */
export function approvedNarrowImageBuildForManifest(
  projectRoot: string,
  project: ProjectInfo,
  input: { build: AgentBuildConfig; contextManifest: readonly BuildContextManifestEntry[] },
): ApprovedNarrowImageBuild | undefined {
  const subject = imageBuildControlSubject({ ...input, contextKind: "narrow" });
  const selection = readControlApprovalSelection(projectRoot, project);
  const record = selection?.subjects["image-build"];
  // Compare digests before touching the stored snapshot: a stale record means
  // "not approved for this input", not corruption, and must fall through to a
  // fresh approval prompt rather than fail verification of a snapshot that
  // cannot match.
  if (record?.digest !== subject.digest) return undefined;
  try {
    return verifySnapshotDirectory(approvedSubjectDirectory(project, "image-build", record.digest), record.digest);
  } catch (error) {
    throw new ApprovedImageBuildSnapshotError(error instanceof Error ? error.message : String(error), { cause: error });
  }
}

export function narrowImageBuildApprovalPrompt(
  candidate: NarrowImageBuildCandidate,
  previous: ApprovedNarrowImageBuild | undefined = undefined,
  options: { cached?: boolean; projectRoot?: string } = {},
): string {
  return narrowImageBuildApprovalPromptWithContent(candidate, previous, options);
}

// ---------------------------------------------------------------------------
// Show-the-content approval prompt (output contract D6).
//
// A human cannot audit a digest by eye. The prompt shows what the decision is
// about: the staged file list with sizes, the Dockerfile text, and — when a
// previous approval exists — what changed since it. The digest prints once,
// small, as the record id. The risk line is verbatim from the original prompt.
// ---------------------------------------------------------------------------

export const IMAGE_BUILD_RISK_LINE = "Docker build runs before the Runfree sandbox and can execute files or send them over the network.";
const DOCKERFILE_DISPLAY_LINE_LIMIT = 40;

export type NarrowImageBuildChangeSummary = {
  added: string[];
  removed: string[];
  changed: string[];
  dockerfileChanged: boolean;
};

function manifestFingerprint(entry: BuildContextManifestEntry): string {
  return entry.type === "file" ? `file:${entry.mode}:${entry.size}:${entry.sha256}` : `dir:${entry.mode}`;
}

export function summarizeNarrowImageBuildChanges(
  candidate: NarrowImageBuildCandidate,
  previous: ApprovedNarrowImageBuild,
): NarrowImageBuildChangeSummary {
  const before = new Map(previous.manifest.map((entry) => [entry.path, manifestFingerprint(entry)]));
  const after = new Map(candidate.manifest.map((entry) => [entry.path, manifestFingerprint(entry)]));
  const added = [...after.keys()].filter((entry) => !before.has(entry)).sort();
  const removed = [...before.keys()].filter((entry) => !after.has(entry)).sort();
  const changed = [...after.keys()].filter((entry) => before.has(entry) && before.get(entry) !== after.get(entry)).sort();
  const dockerfileRelative = path.relative(candidate.contextPath, candidate.dockerfilePath);
  return { added, removed, changed, dockerfileChanged: changed.includes(dockerfileRelative) };
}

function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

// Minimal line diff (LCS) for two small Dockerfiles; the display is bounded
// by the same line limit as the full-text view.
function lineDiff(before: string[], after: string[]): string[] {
  const rows = before.length;
  const cols = after.length;
  const lcs: number[][] = Array.from({ length: rows + 1 }, () => new Array<number>(cols + 1).fill(0));
  for (let i = rows - 1; i >= 0; i -= 1) {
    for (let j = cols - 1; j >= 0; j -= 1) {
      lcs[i][j] = before[i] === after[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const out: string[] = [];
  let i = 0;
  let j = 0;
  while (i < rows && j < cols) {
    if (before[i] === after[j]) {
      i += 1;
      j += 1;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      out.push(`- ${before[i]}`);
      i += 1;
    } else {
      out.push(`+ ${after[j]}`);
      j += 1;
    }
  }
  while (i < rows) out.push(`- ${before[i++]}`);
  while (j < cols) out.push(`+ ${after[j++]}`);
  return out;
}

function boundedLines(lines: string[], fullFilePath: string): string[] {
  if (lines.length <= DOCKERFILE_DISPLAY_LINE_LIMIT) return lines;
  return [
    ...lines.slice(0, DOCKERFILE_DISPLAY_LINE_LIMIT),
    `… truncated (${lines.length - DOCKERFILE_DISPLAY_LINE_LIMIT} more lines) — full file: ${fullFilePath}`,
  ];
}

function readStagedText(filePath: string): string {
  return Buffer.from(readRegularSingleLink(filePath, "staged image-build Dockerfile")).toString("utf8").replace(/\n$/, "");
}

/**
 * The content of an image-build approval decision, as lines. `previous` is the
 * currently approved snapshot when one exists (a changed-content approval);
 * absent for the first approval in this project.
 */
export function describeNarrowImageBuildCandidate(
  candidate: NarrowImageBuildCandidate,
  previous: ApprovedNarrowImageBuild | undefined,
  options: { projectRoot?: string } = {},
): string[] {
  const relativeDockerfile = path.relative(candidate.contextPath, candidate.dockerfilePath);
  const displayPath = options.projectRoot
    ? path.join(candidate.build.context, relativeDockerfile)
    : candidate.dockerfilePath;
  const lines: string[] = [];
  if (previous) {
    const changes = summarizeNarrowImageBuildChanges(candidate, previous);
    lines.push(`Changed since the approved build (${previous.subject.digest.slice(0, 19)}…):`);
    if (changes.added.length + changes.removed.length + changes.changed.length === 0) {
      lines.push("  no staged file changed (the build config or base inputs changed)");
    }
    for (const entry of changes.added) lines.push(`  + ${entry}`);
    for (const entry of changes.removed) lines.push(`  - ${entry}`);
    for (const entry of changes.changed) lines.push(`  ~ ${entry}`);
    if (changes.dockerfileChanged) {
      lines.push("", `Dockerfile diff (${displayPath}):`);
      const before = readStagedText(previous.dockerfilePath).split("\n");
      const after = readStagedText(candidate.dockerfilePath).split("\n");
      lines.push(...boundedLines(lineDiff(before, after).map((line) => `  ${line}`), displayPath));
    }
  } else {
    lines.push("First image-build approval for this project.");
  }
  const files = candidate.manifest.filter((entry) => entry.type === "file");
  const directories = candidate.manifest.length - files.length;
  lines.push("", `Staged files (${files.length}${directories > 0 ? `, ${directories} directories` : ""}):`);
  for (const entry of candidate.manifest) {
    if (entry.type === "file") lines.push(`  ${entry.path}  ${humanSize(entry.size)}  ${entry.sha256.slice(0, "sha256:".length + 12)}`);
    else lines.push(`  ${entry.path}/`);
  }
  if (!previous || !summarizeNarrowImageBuildChanges(candidate, previous).dockerfileChanged) {
    lines.push("", `Dockerfile (${displayPath}):`);
    lines.push(...boundedLines(readStagedText(candidate.dockerfilePath).split("\n").map((line) => `  ${line}`), displayPath));
  }
  lines.push("", `approval record id: ${candidate.subject.digest}`);
  return lines;
}

/**
 * The interactive prompt: content first, the verbatim risk line, then the
 * question. `previous` is the approved snapshot the candidate would replace.
 */
export function narrowImageBuildApprovalPromptWithContent(
  candidate: NarrowImageBuildCandidate,
  previous: ApprovedNarrowImageBuild | undefined,
  options: { cached?: boolean; projectRoot?: string } = {},
): string {
  // The prompt distinguishes reuse from build. Approval is now prepared whether
  // or not Docker needs to build, so telling the user that no rebuild is coming
  // is the difference between "this is about to run" and "this already ran".
  return [
    options.cached
      ? "This checkout's custom agent image needs approval."
      : "This project wants to build a Runfree agent image from the staged input below.",
    ...(options.cached ? ["The image is already cached; no rebuild is needed."] : []),
    IMAGE_BUILD_RISK_LINE,
    "",
    ...describeNarrowImageBuildCandidate(candidate, previous, options),
    "",
    options.cached
      ? "Approve this image configuration? [y/N] "
      : previous
        ? "Approve this changed build input for this checkout? [y/N] "
        : "Approve this build input for this checkout? [y/N] ",
  ].join("\n");
}
