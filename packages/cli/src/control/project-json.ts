import fs from "node:fs";
import path from "node:path";

import { PROJECT_RUNFREE_PATHS } from "../runfree-consumer-registry.ts";
import { parseStrictJson } from "./strict-json.ts";

export const DESIRED_POLICY_MAX_BYTES = 1024 * 1024;

export type BoundedProjectJson = {
  bytes: Buffer;
  parsed: unknown;
};

function assertDirectRunfreeChild(relativePath: string): void {
  const normalized = relativePath.split(path.sep).join("/");
  if (normalized !== PROJECT_RUNFREE_PATHS.networkPolicy && normalized !== PROJECT_RUNFREE_PATHS.networkPolicyLocal) {
    throw new Error(`refusing unrecognized project JSON path ${relativePath}`);
  }
}

export function readBoundedProjectJson(
  projectRoot: string,
  relativePath: string,
  options: { allowMissing?: boolean; maxBytes?: number } = {},
): BoundedProjectJson | undefined {
  assertDirectRunfreeChild(relativePath);
  const maxBytes = options.maxBytes ?? DESIRED_POLICY_MAX_BYTES;
  const realProjectRoot = fs.realpathSync.native(projectRoot);
  const runfreeDir = path.join(realProjectRoot, ".runfree");
  const rootStat = fs.lstatSync(runfreeDir);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error(".runfree must be a normal directory");
  }

  const filePath = path.join(realProjectRoot, relativePath);
  let pathStat: fs.Stats;
  try {
    pathStat = fs.lstatSync(filePath);
  } catch (error) {
    if (options.allowMissing && error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
  if (!pathStat.isFile() || pathStat.isSymbolicLink() || pathStat.nlink !== 1) {
    throw new Error(`${relativePath} must be a regular, non-hard-linked file`);
  }
  if (pathStat.size > maxBytes) throw new Error(`${relativePath} exceeds the ${maxBytes}-byte limit`);

  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== pathStat.dev || opened.ino !== pathStat.ino) {
      throw new Error(`${relativePath} changed while it was being opened`);
    }
    if (opened.size > maxBytes) throw new Error(`${relativePath} exceeds the ${maxBytes}-byte limit`);
    const bytes = Buffer.alloc(opened.size);
    let consumed = 0;
    while (consumed < bytes.length) {
      const count = fs.readSync(descriptor, bytes, consumed, bytes.length - consumed, consumed);
      if (count === 0) throw new Error(`${relativePath} changed while it was being read`);
      consumed += count;
    }
    const after = fs.fstatSync(descriptor);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.nlink !== 1 || after.size !== opened.size) {
      throw new Error(`${relativePath} changed while it was being read`);
    }
    return { bytes, parsed: parseStrictJson(bytes.toString("utf8")) };
  } finally {
    fs.closeSync(descriptor);
  }
}
