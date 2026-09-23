import fs from "node:fs";
import path from "node:path";

export function isPathInside(rootPath: string, targetPath: string): boolean {
  const root = path.resolve(rootPath);
  const target = path.resolve(targetPath);
  return target === root || target.startsWith(`${root}${path.sep}`);
}

export function isPathInsideByRealpath(rootPath: string, targetPath: string): boolean {
  const root = fs.existsSync(rootPath) ? fs.realpathSync(rootPath) : path.resolve(rootPath);
  const target = path.resolve(targetPath);
  if (isPathInside(root, target)) return true;

  let current = target;
  while (true) {
    if (fs.existsSync(current)) {
      const realCurrent = fs.realpathSync(current);
      if (isPathInside(root, realCurrent)) return true;
      const remainder = path.relative(current, target);
      if (remainder === "") return false;
      return isPathInside(root, path.resolve(realCurrent, remainder));
    }
    const parent = path.dirname(current);
    if (parent === current) return false;
    current = parent;
  }
}

export function relativeProjectPath(projectRoot: string, targetPath: string): string {
  const relative = path.relative(path.resolve(projectRoot), path.resolve(targetPath));
  return relative === "" ? "." : relative;
}

export const relativeDisplay = relativeProjectPath;

function unsafePathMessage(projectRoot: string, targetPath: string): string {
  return `refusing to write unsafe project-controlled path: ${relativeProjectPath(projectRoot, targetPath)}
replace symlinks, hard links, or special files with normal directories/files and retry`;
}

export function assertPathInside(rootPath: string, targetPath: string, label: string): void {
  if (!isPathInside(rootPath, targetPath)) {
    throw new Error(`${label} must resolve inside the project root`);
  }
}

export function statKind(stat: fs.Stats): string {
  if (stat.isDirectory()) return "directory";
  if (stat.isFile()) return "regular file";
  if (stat.isSymbolicLink()) return "symlink";
  if (stat.isFIFO()) return "fifo";
  if (stat.isSocket()) return "socket";
  if (stat.isBlockDevice()) return "block device";
  if (stat.isCharacterDevice()) return "character device";
  return "special file";
}

function assertExistingDirectory(projectRoot: string, dirPath: string): void {
  const stat = fs.lstatSync(dirPath);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`${unsafePathMessage(projectRoot, dirPath)} (${statKind(stat)})`);
  }
}

function pathComponentsFromRoot(projectRoot: string, targetPath: string): string[] {
  const relative = path.relative(path.resolve(projectRoot), path.resolve(targetPath));
  if (relative === "") return [];
  return relative.split(path.sep).filter(Boolean);
}

export function assertNoSymlinkPath(
  projectRoot: string,
  targetPath: string,
  options: { allowMissingFinal?: boolean; allowMissingPath?: boolean } = {},
): void {
  assertPathInside(projectRoot, targetPath, "path");
  const root = path.resolve(projectRoot);
  let current = root;
  const components = pathComponentsFromRoot(root, targetPath);

  for (const [index, component] of components.entries()) {
    current = path.join(current, component);
    const isFinal = index === components.length - 1;
    try {
      const stat = fs.lstatSync(current);
      if (stat.isSymbolicLink()) {
        throw new Error(`${unsafePathMessage(projectRoot, current)} (symlink)`);
      }
      if (!isFinal && !stat.isDirectory()) {
        throw new Error(`${unsafePathMessage(projectRoot, current)} (${statKind(stat)})`);
      }
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
        if (options.allowMissingPath) return;
        if (isFinal && options.allowMissingFinal) return;
        if (isFinal) throw error;
        throw new Error(`${unsafePathMessage(projectRoot, current)} (missing parent path)`);
      }
      throw error;
    }
  }
}

export function ensureSafeProjectDir(projectRoot: string, dirPath: string, mode = 0o700): void {
  assertPathInside(projectRoot, dirPath, "path");
  const root = path.resolve(projectRoot);
  let current = root;
  assertExistingDirectory(projectRoot, current);

  for (const component of pathComponentsFromRoot(root, dirPath)) {
    current = path.join(current, component);
    try {
      assertExistingDirectory(projectRoot, current);
    } catch (error) {
      if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) {
        if (fs.existsSync(current)) throw error;
      }
      if (!fs.existsSync(current)) {
        fs.mkdirSync(current, { mode });
        assertExistingDirectory(projectRoot, current);
      }
    }
  }
}

export function safeRemoveEmptyProjectDir(projectRoot: string, dirPath: string): "removed" | "kept" {
  try {
    assertPathInside(projectRoot, dirPath, "path");
    const root = path.resolve(projectRoot);
    const target = path.resolve(dirPath);
    if (path.dirname(target) !== root) return "kept";

    const rootStat = fs.lstatSync(root);
    if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) return "kept";
    const targetStat = fs.lstatSync(target);
    if (targetStat.isSymbolicLink() || !targetStat.isDirectory()) return "kept";
    assertNoSymlinkPath(root, target);
    if (fs.readdirSync(target).length !== 0) return "kept";
    fs.rmdirSync(target);
    return "removed";
  } catch {
    return "kept";
  }
}

export function assertNormalDirectory(projectRoot: string, dirPath: string, label: string): fs.Stats {
  if (!fs.existsSync(dirPath)) {
    throw new Error(`${label} not found: ${relativeDisplay(projectRoot, dirPath)}`);
  }
  const stat = fs.lstatSync(dirPath);
  if (stat.isSymbolicLink()) {
    throw new Error(`${label} is not a normal directory: ${relativeDisplay(projectRoot, dirPath)} (symlink)`);
  }
  if (!stat.isDirectory()) {
    throw new Error(`${label} is not a directory: ${relativeDisplay(projectRoot, dirPath)} (${statKind(stat)})`);
  }
  return stat;
}

export function assertOptionalNormalProjectDirectory(projectRoot: string, dirPath: string, label: string): fs.Stats | undefined {
  assertPathInside(projectRoot, dirPath, label);
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(dirPath);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
  if (stat.isSymbolicLink()) {
    throw new Error(`${label} is not a normal directory: ${relativeDisplay(projectRoot, dirPath)} (symlink)`);
  }
  if (!stat.isDirectory()) {
    throw new Error(`${label} is not a directory: ${relativeDisplay(projectRoot, dirPath)} (${statKind(stat)})`);
  }
  return stat;
}

export function assertNormalFile(projectRoot: string, filePath: string, label: string): fs.Stats {
  if (!fs.existsSync(filePath)) {
    throw new Error(`${label} not found: ${relativeDisplay(projectRoot, filePath)}`);
  }
  const stat = fs.lstatSync(filePath);
  if (stat.isSymbolicLink()) {
    throw new Error(`${label} is not a regular file: ${relativeDisplay(projectRoot, filePath)} (symlink)`);
  }
  if (!stat.isFile()) {
    throw new Error(`${label} is not a file: ${relativeDisplay(projectRoot, filePath)} (${statKind(stat)})`);
  }
  if (stat.nlink !== 1) {
    throw new Error(`${label} is a hard link: ${relativeDisplay(projectRoot, filePath)} (links=${stat.nlink})`);
  }
  return stat;
}

export function assertRegularNonHardLinkedFile(projectRoot: string, filePath: string, options: { allowMissing?: boolean } = {}): void {
  assertNoSymlinkPath(projectRoot, filePath, {
    allowMissingFinal: options.allowMissing,
    allowMissingPath: options.allowMissing,
  });
  try {
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.nlink !== 1) {
      throw new Error(`${unsafePathMessage(projectRoot, filePath)} (${statKind(stat)}, links=${stat.nlink})`);
    }
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT" && options.allowMissing) return;
    throw error;
  }
}

function openTempNoFollow(tmpPath: string, mode: number): number {
  const flags = fs.constants.O_WRONLY
    | fs.constants.O_CREAT
    | fs.constants.O_EXCL
    | (fs.constants.O_NOFOLLOW ?? 0);
  return fs.openSync(tmpPath, flags, mode);
}

export function fsyncDirectory(directory: string): void {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

export function atomicReplaceFile(filePath: string, contents: string | Buffer, mode = 0o600): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const tmpPath = `${filePath}.${process.pid}.${Date.now().toString(36)}.tmp`;
  let fd: number | undefined;
  try {
    fd = openTempNoFollow(tmpPath, mode);
    fs.writeFileSync(fd, contents);
    fs.fchmodSync(fd, mode);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmpPath, filePath);
    fs.chmodSync(filePath, mode);
    fsyncDirectory(path.dirname(filePath));
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try {
      fs.rmSync(tmpPath, { force: true });
    } catch {
      // Best-effort cleanup for failed writes.
    }
  }
}

export function copyRegularFileNoFollow(sourcePath: string, destinationPath: string, sourceStat: fs.Stats): void {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  const fd = fs.openSync(sourcePath, flags);
  try {
    const openStat = fs.fstatSync(fd);
    if (!openStat.isFile() || openStat.nlink !== 1 || openStat.dev !== sourceStat.dev || openStat.ino !== sourceStat.ino) {
      throw new Error(`agent build context changed during staging: ${sourcePath}`);
    }
    const contents = fs.readFileSync(fd);
    fs.writeFileSync(destinationPath, contents, {
      flag: "wx",
      mode: sourceStat.mode & 0o777,
    });
    fs.chmodSync(destinationPath, sourceStat.mode & 0o777);
    const stagedStat = fs.lstatSync(destinationPath);
    if (!stagedStat.isFile() || stagedStat.isSymbolicLink() || stagedStat.nlink !== 1) {
      throw new Error(`staged agent build context file is unsafe: ${destinationPath}`);
    }
  } finally {
    fs.closeSync(fd);
  }
}

export function safeReplaceProjectFile(projectRoot: string, filePath: string, contents: string | Buffer, mode = 0o600): void {
  const parent = path.dirname(filePath);
  ensureSafeProjectDir(projectRoot, parent, 0o700);
  assertRegularNonHardLinkedFile(projectRoot, filePath, { allowMissing: true });

  const basename = path.basename(filePath);
  const tmpPath = path.join(parent, `.${basename}.${process.pid}.${Date.now().toString(36)}.tmp`);
  let fd: number | undefined;
  try {
    fd = openTempNoFollow(tmpPath, mode);
    fs.writeFileSync(fd, contents);
    fs.fchmodSync(fd, mode);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;

    const tmpStat = fs.lstatSync(tmpPath);
    if (!tmpStat.isFile() || tmpStat.isSymbolicLink() || tmpStat.nlink !== 1) {
      throw new Error(`${unsafePathMessage(projectRoot, tmpPath)} (${statKind(tmpStat)}, links=${tmpStat.nlink})`);
    }

    fs.renameSync(tmpPath, filePath);
    assertRegularNonHardLinkedFile(projectRoot, filePath);
    fsyncDirectory(parent);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try {
      fs.rmSync(tmpPath, { force: true });
    } catch {
      // Best-effort cleanup for failed writes.
    }
  }
}

export function safeReadProjectFile(projectRoot: string, filePath: string): string | undefined {
  try {
    assertRegularNonHardLinkedFile(projectRoot, filePath, { allowMissing: true });
    return fs.readFileSync(filePath, "utf8");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
}

export function safeCopyProjectFile(projectRoot: string, sourcePath: string, destinationPath: string, mode = 0o600): void {
  assertRegularNonHardLinkedFile(projectRoot, sourcePath);
  safeReplaceProjectFile(projectRoot, destinationPath, fs.readFileSync(sourcePath), mode);
}
