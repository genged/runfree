import fs from "node:fs";
import path from "node:path";

/**
 * Whether the `docker` the CLI path would execute is a native executable.
 *
 * The transport stands in for the Docker CLI, so it only does so when the
 * command the CLI path would run is plausibly that CLI: an ELF or Mach-O
 * binary found first on the same PATH `spawnSync` would search. A script
 * (a `podman-docker` shim, a wrapper, a test's fake `docker`) keeps every
 * call on the CLI path, because the transport cannot know what it does.
 */
export type DockerCliProbe = (env: NodeJS.ProcessEnv, envGiven: boolean) => boolean;

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

export function nativeDockerCliOnPath(searchPath: string): boolean {
  for (const dir of searchPath.split(":")) {
    // A relative or empty entry resolves against the working directory; that
    // is doubt, and doubt stays on the CLI.
    if (!path.isAbsolute(dir)) return false;
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
    let fd: number | undefined;
    try {
      fd = fs.openSync(candidate, "r");
      const magic = Buffer.alloc(4);
      if (fs.readSync(fd, magic, 0, 4, 0) !== 4) return false;
      return NATIVE_MAGIC.has(magic.toString("hex"));
    } catch {
      return false;
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
    }
  }
  return false;
}

export function createNativeDockerCliProbe(): DockerCliProbe {
  const cache = new Map<string, boolean>();
  return (env, envGiven) => {
    const searchPath = spawnSearchPath(env, envGiven);
    const cached = cache.get(searchPath);
    if (cached !== undefined) return cached;
    const answer = nativeDockerCliOnPath(searchPath);
    cache.set(searchPath, answer);
    return answer;
  };
}
