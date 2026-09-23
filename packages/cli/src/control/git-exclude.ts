import fs from "node:fs";
import path from "node:path";

import { classifyGitRepository, formatGitRepositoryShapeError } from "../runtime/git-layout.ts";
import type { RuntimeIO } from "../runtime/types.ts";

export const LOCAL_POLICY_EXCLUDE_PATTERN = "/.runfree/network-policy.local.json";
const LOCAL_POLICY_REPOSITORY_PATH = ".runfree/network-policy.local.json";
const MAX_GIT_EXCLUDE_BYTES = 1024 * 1024;

function gitCapture(projectRoot: string, io: RuntimeIO, args: string[]) {
  return io.capture("git", ["-C", projectRoot, ...args], { encoding: "utf8" });
}

function oneAbsoluteLine(source: string, label: string): string {
  const lines = source.split(/\r?\n/).filter((line) => line !== "");
  if (lines.length !== 1 || !path.isAbsolute(lines[0] ?? "")) throw new Error(`git returned an invalid ${label}`);
  return path.resolve(lines[0] as string);
}

type ExcludeFile = {
  contents: string;
  identity?: { dev: number; ino: number };
  mode: number;
};

function readExclude(filePath: string): ExcludeFile {
  let before: fs.Stats;
  try {
    before = fs.lstatSync(filePath);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return { contents: "", mode: 0o600 };
    }
    throw error;
  }
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) {
    throw new Error("Git exclude must be a regular single-link file");
  }
  if (before.size > MAX_GIT_EXCLUDE_BYTES) throw new Error("Git exclude exceeds the 1 MiB safety limit");
  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino) {
      throw new Error("Git exclude changed during validation");
    }
    const contents = fs.readFileSync(descriptor, "utf8");
    if (Buffer.byteLength(contents) > MAX_GIT_EXCLUDE_BYTES) throw new Error("Git exclude exceeds the 1 MiB safety limit");
    return { contents, identity: { dev: opened.dev, ino: opened.ino }, mode: opened.mode & 0o777 };
  } finally {
    fs.closeSync(descriptor);
  }
}

function assertExcludeUnchanged(filePath: string, expected: ExcludeFile): void {
  let current: fs.Stats;
  try {
    current = fs.lstatSync(filePath);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT" && !expected.identity) return;
    throw new Error("Git exclude changed during atomic replacement", { cause: error });
  }
  if (!expected.identity
    || !current.isFile()
    || current.isSymbolicLink()
    || current.nlink !== 1
    || current.dev !== expected.identity.dev
    || current.ino !== expected.identity.ino) {
    throw new Error("Git exclude changed during atomic replacement");
  }
}

function writeExclude(filePath: string, contents: string, expected: ExcludeFile): void {
  const parent = path.dirname(filePath);
  const temporary = path.join(parent, `.exclude.${process.pid}.${Date.now().toString(36)}.tmp`);
  try {
    const descriptor = fs.openSync(
      temporary,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0),
      expected.mode,
    );
    try {
      fs.writeFileSync(descriptor, contents);
      fs.fchmodSync(descriptor, expected.mode);
      fs.fsyncSync(descriptor);
    } finally {
      fs.closeSync(descriptor);
    }
    assertExcludeUnchanged(filePath, expected);
    fs.renameSync(temporary, filePath);
    const parentDescriptor = fs.openSync(parent, fs.constants.O_RDONLY);
    try {
      fs.fsyncSync(parentDescriptor);
    } finally {
      fs.closeSync(parentDescriptor);
    }
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}

export function ensureCheckoutLocalPolicyExcluded(projectRoot: string, io: RuntimeIO): "absent-git" | "present" | "written" {
  const shape = classifyGitRepository(projectRoot);
  if (shape.kind === "none") return "absent-git";
  if (shape.kind === "fatal") throw new Error(formatGitRepositoryShapeError(shape));

  const tracked = gitCapture(projectRoot, io, ["ls-files", "--error-unmatch", "--", LOCAL_POLICY_REPOSITORY_PATH]);
  if (tracked.status === 0) {
    throw new Error([
      ".runfree/network-policy.local.json is tracked by Git; checkout-local policy must remain untracked",
      "untrack it with: git rm --cached -- .runfree/network-policy.local.json",
    ].join("\n"));
  }
  if (tracked.status !== 1) throw new Error("could not determine whether checkout-local policy is tracked");

  const resolved = gitCapture(projectRoot, io, ["rev-parse", "--path-format=absolute", "--git-path", "info/exclude"]);
  if (resolved.status !== 0) throw new Error("could not resolve the checkout Git exclude path");
  const excludePath = oneAbsoluteLine(resolved.stdout, "Git exclude path");
  const commonRoot = shape.kind === "normal" ? shape.gitDir : shape.details.gitCommonDir;
  const expectedPath = path.join(commonRoot, "info", "exclude");
  if (excludePath !== expectedPath) throw new Error("Git exclude path does not match the validated Git common directory");

  const commonStat = fs.lstatSync(commonRoot);
  const infoRoot = path.join(commonRoot, "info");
  const infoStat = fs.lstatSync(infoRoot);
  if (!commonStat.isDirectory() || commonStat.isSymbolicLink()
    || !infoStat.isDirectory() || infoStat.isSymbolicLink()
    || fs.realpathSync.native(infoRoot) !== infoRoot) {
    throw new Error("Git common/info directory must be a normal resolved directory");
  }

  const current = readExclude(excludePath);
  if (current.contents.split(/\r?\n/).includes(LOCAL_POLICY_EXCLUDE_PATTERN)) return "present";
  const prefix = current.contents === "" || current.contents.endsWith("\n") ? current.contents : `${current.contents}\n`;
  writeExclude(excludePath, `${prefix}${LOCAL_POLICY_EXCLUDE_PATTERN}\n`, current);
  return "written";
}
