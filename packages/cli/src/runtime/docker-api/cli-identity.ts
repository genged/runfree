import fs from "node:fs";
import path from "node:path";

/**
 * The identity of the `docker` the CLI path would execute, when it is a
 * native executable.
 *
 * The transport stands in for the Docker CLI, so it only does so when the
 * command the CLI path would run is plausibly that CLI: an ELF or Mach-O
 * binary found first on the same PATH `spawnSync` would search. A script
 * (a `podman-docker` shim, a wrapper, a test's fake `docker`) keeps every
 * call on the CLI path, because the transport cannot know what it does.
 *
 * The answer is re-derived on every call (a few `stat`s) and names the
 * binary by real path, device, inode, size, and mtime, so a binary replaced
 * or shadowed mid-process yields a new identity and a new daemon binding.
 * Only the magic-byte read is cached, per identity.
 */
export type DockerCliProbe = (env: NodeJS.ProcessEnv, envGiven: boolean) => string | undefined;

const NATIVE_MAGIC = new Set([
  "7f454c46", // ELF
  "feedface", "feedfacf", "cefaedfe", "cffaedfe", // Mach-O 32/64, both byte orders
  "cafebabe", "bebafeca", // Mach-O universal
]);

// Node searches options.env.PATH when env is given, and falls back to
// /usr/bin:/bin when that env has no PATH; otherwise it searches process.env.PATH.
export function spawnSearchPath(env: NodeJS.ProcessEnv, envGiven: boolean): string {
  if (env.PATH !== undefined) return env.PATH;
  return envGiven ? "/usr/bin:/bin" : "";
}

/** The first executable `docker` on the search path, or undefined on doubt or absence. */
export function firstDockerOnPath(searchPath: string): { realPath: string; identity: string } | undefined {
  for (const dir of searchPath.split(":")) {
    // A relative or empty entry resolves against the working directory; that
    // is doubt, and doubt stays on the CLI.
    if (!path.isAbsolute(dir)) return undefined;
    const candidate = path.join(dir, "docker");
    let stat: fs.Stats;
    try {
      stat = fs.statSync(candidate);
    } catch {
      continue;
    }
    if (!stat.isFile()) continue;
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
    } catch {
      continue;
    }
    let realPath: string;
    try {
      realPath = fs.realpathSync(candidate);
    } catch {
      return undefined;
    }
    return { realPath, identity: `${realPath}\u0000${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeMs}` };
  }
  return undefined;
}

export function isNativeExecutable(filePath: string): boolean {
  let fd: number | undefined;
  try {
    fd = fs.openSync(filePath, "r");
    const magic = Buffer.alloc(4);
    if (fs.readSync(fd, magic, 0, 4, 0) !== 4) return false;
    return NATIVE_MAGIC.has(magic.toString("hex"));
  } catch {
    return false;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

export function createNativeDockerCliProbe(): DockerCliProbe {
  const native = new Map<string, boolean>();
  return (env, envGiven) => {
    const found = firstDockerOnPath(spawnSearchPath(env, envGiven));
    if (!found) return undefined;
    let answer = native.get(found.identity);
    if (answer === undefined) {
      answer = isNativeExecutable(found.realPath);
      native.set(found.identity, answer);
    }
    return answer ? found.identity : undefined;
  };
}
