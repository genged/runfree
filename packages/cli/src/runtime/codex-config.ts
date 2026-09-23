import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { warn } from "../warnings.ts";

const CONFIG_NAME = "config.toml";
const MAX_CONFIG_BYTES = 1024 * 1024;
const CONFIG_MODE = 0o600;
const DIRECTORY_MODE = 0o700;

type FileIdentity = Readonly<{
  ctimeNs: bigint;
  device: bigint;
  inode: bigint;
  links: bigint;
  mode: bigint;
  mtimeNs: bigint;
  size: bigint;
}>;

export type CodexConfigUpdateResult = "unchanged" | "updated" | "unsafe";

class UnsafeCodexConfigError extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = "UnsafeCodexConfigError";
  }
}

function errorCode(error: unknown): string | undefined {
  return error && typeof error === "object" && "code" in error && typeof error.code === "string"
    ? error.code
    : undefined;
}

function attackerPathError(error: unknown): boolean {
  return ["EACCES", "EEXIST", "EISDIR", "ELOOP", "ENOENT", "ENOTDIR", "ENOTEMPTY", "EPERM"].includes(errorCode(error) ?? "");
}

function fileIdentity(stat: fs.BigIntStats): FileIdentity {
  return {
    ctimeNs: stat.ctimeNs,
    device: stat.dev,
    inode: stat.ino,
    links: stat.nlink,
    mode: stat.mode,
    mtimeNs: stat.mtimeNs,
    size: stat.size,
  };
}

function sameFile(left: fs.BigIntStats, right: fs.BigIntStats): boolean {
  const a = fileIdentity(left);
  const b = fileIdentity(right);
  return a.ctimeNs === b.ctimeNs
    && a.device === b.device
    && a.inode === b.inode
    && a.links === b.links
    && a.mode === b.mode
    && a.mtimeNs === b.mtimeNs
    && a.size === b.size;
}

function sameFileAcrossRename(left: fs.BigIntStats, right: fs.BigIntStats): boolean {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.nlink === right.nlink
    && left.mode === right.mode
    && left.mtimeNs === right.mtimeNs
    && left.size === right.size;
}

function requiredFlags(): { directory: number; noFollow: number } {
  const noFollow = fs.constants.O_NOFOLLOW;
  const directory = fs.constants.O_DIRECTORY;
  if (!Number.isInteger(noFollow) || noFollow === 0 || !Number.isInteger(directory) || directory === 0) {
    throw new UnsafeCodexConfigError("safe no-follow filesystem operations are unavailable");
  }
  return { directory, noFollow };
}

function openCodexDirectory(codexDir: string, flags: { directory: number; noFollow: number }): number {
  try {
    fs.mkdirSync(codexDir, { recursive: true, mode: DIRECTORY_MODE });
  } catch (error) {
    if (attackerPathError(error)) {
      throw new UnsafeCodexConfigError("the Codex state root cannot be created safely");
    }
    throw error;
  }
  let before: fs.BigIntStats;
  try {
    before = fs.lstatSync(codexDir, { bigint: true });
  } catch (error) {
    if (attackerPathError(error)) {
      throw new UnsafeCodexConfigError("the Codex state root changed or is inaccessible");
    }
    throw error;
  }
  if (!before.isDirectory() || before.isSymbolicLink()) {
    throw new UnsafeCodexConfigError("the Codex state root is not a normal directory");
  }

  let descriptor: number;
  try {
    descriptor = fs.openSync(codexDir, fs.constants.O_RDONLY | flags.directory | flags.noFollow);
  } catch (error) {
    if (attackerPathError(error)) {
      throw new UnsafeCodexConfigError("the Codex state root changed or is inaccessible");
    }
    throw error;
  }
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isDirectory() || opened.dev !== before.dev || opened.ino !== before.ino) {
      throw new UnsafeCodexConfigError("the Codex state root changed while it was opened");
    }
    fs.fchmodSync(descriptor, DIRECTORY_MODE);
    return descriptor;
  } catch (error) {
    fs.closeSync(descriptor);
    throw error;
  }
}

function readCurrentConfig(configPath: string, noFollow: number): string | undefined {
  let before: fs.BigIntStats;
  try {
    before = fs.lstatSync(configPath, { bigint: true });
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    if (attackerPathError(error)) {
      throw new UnsafeCodexConfigError("config.toml changed or is inaccessible");
    }
    throw error;
  }
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
    throw new UnsafeCodexConfigError("config.toml is a link or is not a single-link regular file");
  }
  if (before.size > BigInt(MAX_CONFIG_BYTES)) {
    throw new UnsafeCodexConfigError("config.toml is larger than 1 MiB");
  }

  let descriptor: number;
  try {
    descriptor = fs.openSync(configPath, fs.constants.O_RDONLY | noFollow);
  } catch (error) {
    if (attackerPathError(error)) {
      throw new UnsafeCodexConfigError("config.toml changed before it could be opened safely");
    }
    throw error;
  }
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile()
      || opened.nlink !== 1n
      || opened.size > BigInt(MAX_CONFIG_BYTES)
      || !sameFile(before, opened)) {
      throw new UnsafeCodexConfigError("config.toml changed before it could be read safely");
    }
    const buffer = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < buffer.length) {
      const bytesRead = fs.readSync(descriptor, buffer, offset, buffer.length - offset, offset);
      if (bytesRead === 0) throw new UnsafeCodexConfigError("config.toml changed while it was being read");
      offset += bytesRead;
    }
    if (!sameFile(opened, fs.fstatSync(descriptor, { bigint: true }))) {
      throw new UnsafeCodexConfigError("config.toml changed while it was being read");
    }
    return buffer.toString("utf8");
  } finally {
    fs.closeSync(descriptor);
  }
}

function createTemporaryConfig(codexDir: string, noFollow: number): { descriptor: number; temporaryPath: string } {
  const flags = fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollow;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const temporaryPath = path.join(
      codexDir,
      `.${CONFIG_NAME}.runfree-${process.pid}-${crypto.randomBytes(16).toString("hex")}.tmp`,
    );
    try {
      return { descriptor: fs.openSync(temporaryPath, flags, CONFIG_MODE), temporaryPath };
    } catch (error) {
      if (errorCode(error) === "EEXIST") continue;
      if (attackerPathError(error)) {
        throw new UnsafeCodexConfigError("the Codex state root changed or refused a safe temporary file");
      }
      throw error;
    }
  }
  throw new UnsafeCodexConfigError("a unique temporary config.toml file could not be created");
}

function writeReplacement(codexDir: string, directoryDescriptor: number, configPath: string, contents: string, noFollow: number): void {
  const temporary = createTemporaryConfig(codexDir, noFollow);
  let renamed = false;
  try {
    const expectedSize = BigInt(Buffer.byteLength(contents));
    fs.writeFileSync(temporary.descriptor, contents);
    fs.fchmodSync(temporary.descriptor, CONFIG_MODE);
    fs.fsyncSync(temporary.descriptor);
    const written = fs.fstatSync(temporary.descriptor, { bigint: true });
    const named = fs.lstatSync(temporary.temporaryPath, { bigint: true });
    if (!written.isFile() || written.nlink !== 1n || written.size !== expectedSize || !sameFile(written, named)) {
      throw new UnsafeCodexConfigError("the temporary config.toml file changed during the update");
    }
    try {
      fs.renameSync(temporary.temporaryPath, configPath);
      renamed = true;
    } catch (error) {
      if (attackerPathError(error)) {
        throw new UnsafeCodexConfigError("config.toml changed before it could be replaced safely");
      }
      throw error;
    }
    const finalEntry = fs.lstatSync(configPath, { bigint: true });
    const committed = fs.fstatSync(temporary.descriptor, { bigint: true });
    if (!committed.isFile()
      || committed.nlink !== 1n
      || committed.size !== expectedSize
      || !sameFileAcrossRename(written, committed)
      || !sameFile(committed, finalEntry)) {
      throw new UnsafeCodexConfigError("config.toml changed while the replacement was committed");
    }
    const expected = Buffer.from(contents);
    const observed = Buffer.alloc(expected.length);
    let offset = 0;
    while (offset < observed.length) {
      const bytesRead = fs.readSync(temporary.descriptor, observed, offset, observed.length - offset, offset);
      if (bytesRead === 0) {
        throw new UnsafeCodexConfigError("config.toml changed while the replacement was verified");
      }
      offset += bytesRead;
    }
    if (!observed.equals(expected) || !sameFile(committed, fs.fstatSync(temporary.descriptor, { bigint: true }))) {
      throw new UnsafeCodexConfigError("config.toml changed while the replacement was verified");
    }
    fs.fsyncSync(directoryDescriptor);
  } catch (error) {
    if (error instanceof UnsafeCodexConfigError) throw error;
    if (attackerPathError(error)) {
      throw new UnsafeCodexConfigError("Codex state changed during the config.toml update");
    }
    throw error;
  } finally {
    fs.closeSync(temporary.descriptor);
    if (!renamed) {
      try {
        fs.unlinkSync(temporary.temporaryPath);
      } catch {
        // The entry is attacker-controlled. Never recurse through it.
      }
    }
  }
}

/**
 * Safely updates the fixed `config.toml` child of the per-project Codex state
 * mount. The container can change children, but it cannot replace the bind
 * mount itself. This function is not safe for arbitrary roots or nested paths.
 */
export function updateCodexConfig(
  codexDir: string,
  update: (current: string | undefined) => string | undefined,
): CodexConfigUpdateResult {
  const configPath = path.join(codexDir, CONFIG_NAME);
  try {
    const flags = requiredFlags();
    const directoryDescriptor = openCodexDirectory(codexDir, flags);
    try {
      const current = readCurrentConfig(configPath, flags.noFollow);
      const next = update(current);
      if (next === undefined || next === current) return "unchanged";
      writeReplacement(codexDir, directoryDescriptor, configPath, next, flags.noFollow);
      return "updated";
    } finally {
      fs.closeSync(directoryDescriptor);
    }
  } catch (error) {
    if (!(error instanceof UnsafeCodexConfigError)) throw error;
    warn(`Codex config update skipped: ${error.reason}: ${configPath}\nrecovery: stop Runfree sessions, remove only this config.toml entry, then retry`);
    return "unsafe";
  }
}
