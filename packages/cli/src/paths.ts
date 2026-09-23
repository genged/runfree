import os from "node:os";
import path from "node:path";

import { die } from "./errors.ts";

export function dataRoot(env: NodeJS.ProcessEnv = process.env): string {
  const xdgDataHome = env.XDG_DATA_HOME;
  return path.resolve(xdgDataHome && xdgDataHome.trim() !== ""
    ? xdgDataHome
    : path.join(os.homedir(), ".local", "share"));
}

export function runfreeDataRoot(env: NodeJS.ProcessEnv = process.env): string {
  return path.join(dataRoot(env), "runfree");
}

export function stateRoot(env: NodeJS.ProcessEnv = process.env): string {
  const xdgStateHome = env.XDG_STATE_HOME;
  return path.resolve(xdgStateHome && xdgStateHome.trim() !== ""
    ? xdgStateHome
    : path.join(os.homedir(), ".local", "state"));
}

export function runfreeStateRoot(env: NodeJS.ProcessEnv = process.env): string {
  return path.join(stateRoot(env), "runfree");
}

export function configRoot(env: NodeJS.ProcessEnv = process.env): string {
  const xdgConfigHome = env.XDG_CONFIG_HOME;
  return path.resolve(xdgConfigHome && xdgConfigHome.trim() !== ""
    ? xdgConfigHome
    : path.join(os.homedir(), ".config"));
}

export function runfreeConfigRoot(env: NodeJS.ProcessEnv = process.env): string {
  return path.join(configRoot(env), "runfree");
}

export function resolveProjectPath(projectRoot: string, relativePath: string): string {
  const resolved = path.resolve(projectRoot, relativePath);
  if (resolved !== projectRoot && !resolved.startsWith(`${projectRoot}${path.sep}`)) {
    die(`path escapes project root: ${relativePath}`);
  }
  return resolved;
}
