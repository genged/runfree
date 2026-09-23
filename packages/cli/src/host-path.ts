// host-path.ts — sanitized host PATH resolution shared by command sources and
// init-wizard helper detection.
//
// The project checkout is untrusted: nothing here may resolve, expose, or
// execute project-controlled paths. PATH entries inside the project (or any
// node_modules/.bin) are dropped, candidate executables are resolved to real
// paths and rejected when they live inside the project, and the execution
// environment is reduced to a small allowlist of identity/XDG variables whose
// path values must also be outside the project.

import fs from "node:fs";
import path from "node:path";

import { isPathInsideByRealpath } from "./safe-fs.ts";

function isUnsafeProjectPath(projectRoot: string, filePath: string): boolean {
  return isPathInsideByRealpath(projectRoot, filePath);
}

export function regularExecutableRealpath(projectRoot: string, candidatePath: string): string | undefined {
  const resolved = path.resolve(candidatePath);
  if (isUnsafeProjectPath(projectRoot, resolved)) return undefined;
  let realPath: string;
  try {
    realPath = fs.realpathSync(resolved);
  } catch {
    return undefined;
  }
  if (isUnsafeProjectPath(projectRoot, realPath)) return undefined;
  try {
    const stat = fs.statSync(realPath);
    if (!stat.isFile()) return undefined;
    fs.accessSync(realPath, fs.constants.X_OK);
  } catch {
    return undefined;
  }
  return realPath;
}

export function sanitizedPathEntries(projectRoot: string, env: NodeJS.ProcessEnv): string[] {
  const entries = (env.PATH ?? "").split(path.delimiter);
  const clean: string[] = [];
  for (const entry of entries) {
    if (entry.trim() === "" || !path.isAbsolute(entry)) continue;
    const resolved = path.resolve(entry);
    if (isUnsafeProjectPath(projectRoot, resolved)) continue;
    if (resolved.split(path.sep).includes("node_modules") && path.basename(resolved) === ".bin") continue;
    let realPath: string;
    try {
      realPath = fs.realpathSync(resolved);
    } catch {
      continue;
    }
    if (isUnsafeProjectPath(projectRoot, realPath)) continue;
    if (realPath.split(path.sep).includes("node_modules") && path.basename(realPath) === ".bin") continue;
    clean.push(realPath);
  }
  return Array.from(new Set(clean));
}

export function resolveHostExecutable(projectRoot: string, env: NodeJS.ProcessEnv, command: string): string | undefined {
  if (command.trim() === "") return undefined;
  if (command.includes("/") || path.isAbsolute(command)) return regularExecutableRealpath(projectRoot, command);
  for (const entry of sanitizedPathEntries(projectRoot, env)) {
    const realPath = regularExecutableRealpath(projectRoot, path.join(entry, command));
    if (realPath) return realPath;
  }
  return undefined;
}

export function pathEnvOutsideProject(projectRoot: string, value: string | undefined): string | undefined {
  if (!value || value.trim() === "") return undefined;
  const resolved = path.resolve(value);
  if (isUnsafeProjectPath(projectRoot, resolved)) return undefined;
  try {
    if (isUnsafeProjectPath(projectRoot, fs.realpathSync(resolved))) return undefined;
  } catch {
    return undefined;
  }
  return resolved;
}

export function sanitizedHostExecutionEnv(projectRoot: string, env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const clean: NodeJS.ProcessEnv = {};
  for (const key of ["HOME", "USER", "LOGNAME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME"] as const) {
    const value = env[key];
    if (!value) continue;
    if (key === "HOME" || key.startsWith("XDG_")) {
      const cleanPath = pathEnvOutsideProject(projectRoot, value);
      if (cleanPath) clean[key] = cleanPath;
      continue;
    }
    clean[key] = value;
  }
  const cleanPath = sanitizedPathEntries(projectRoot, env).join(path.delimiter);
  if (cleanPath) clean.PATH = cleanPath;
  return clean;
}

export type HostHelperProbe = {
  command: string;
  realPath: string;
};

// Detects a host credential helper (for example `gh` or `op`) by resolving it
// through the sanitized host PATH. Project content is never executed, and
// neither is the helper.
//
// This used to run `<helper> --version` to prove the binary works. Proving it
// also runs whatever that vendor's CLI decides to run: observed on macOS,
// `op --version` spawns `ngrok --version`, which put a Gatekeeper first-run
// dialog for an unrelated tool in the middle of `runfree init`. Detection is
// not worth executing a chain of third-party binaries the user did not ask
// for. A helper that resolves but cannot run now fails where it is actually
// used, which is a more useful place to learn it than first-run detection.
export function resolveHostHelper(
  projectRoot: string,
  env: NodeJS.ProcessEnv,
  command: string,
): HostHelperProbe | undefined {
  if (command.includes("/") || path.isAbsolute(command)) return undefined;
  const realPath = resolveHostExecutable(projectRoot, env, command);
  if (!realPath) return undefined;
  return { command, realPath };
}
