import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * Which Docker daemon the Docker CLI would contact, when that is a local Unix
 * socket the Engine API transport may use instead.
 *
 * The answer must name the same daemon the CLI names for the same
 * environment, or say `cli`. It is computed from the caller's environment and
 * the host user's Docker config files only — never from argv or project
 * files — and re-computed on every call, because the CLI re-reads its config
 * on every invocation too. Every input the CLI could read differently, or
 * that selects a transport other than a plain Unix socket, answers `cli`:
 *
 * - `DOCKER_HOST` and `DOCKER_CONTEXT` both set: CLI versions disagree on
 *   which one wins.
 * - `DOCKER_TLS_VERIFY` / `DOCKER_CERT_PATH` / `DOCKER_API_VERSION` set, a
 *   non-`unix://` host (`tcp`, `ssh`, `fd`, `npipe`), a relative or
 *   non-canonical socket path.
 * - A config file or context record that is missing, unreadable, malformed,
 *   carries TLS material or `SkipTLSVerify`, or sets `HttpHeaders` (custom
 *   headers the CLI would send and the transport would not).
 * - The default context when `/var/run/docker.sock` does not exist.
 */
export type DockerEndpoint =
  | { kind: "unix"; socketPath: string; context: string }
  | { kind: "cli"; reason: string };

export type DockerEndpointFs = {
  /** File contents, or undefined when the file does not exist. Throws on other read errors. */
  readFile(filePath: string): string | undefined;
  /** Whether a path exists (following symlinks). */
  exists(filePath: string): boolean;
  /** The passwd home directory, used when HOME is unset (Go's user.Current()). */
  passwdHome(): string | undefined;
};

export const DEFAULT_DOCKER_SOCKET = "/var/run/docker.sock";
const DEFAULT_CONTEXT = "default";
// The Docker CLI's own context-name rule (cli/context/store).
const CONTEXT_NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.+-]+$/;
const MAX_CONFIG_BYTES = 1024 * 1024;

export const nodeDockerEndpointFs: DockerEndpointFs = {
  readFile(filePath) {
    try {
      const stat = fs.statSync(filePath);
      if (!stat.isFile() || stat.size > MAX_CONFIG_BYTES) throw new Error(`${filePath} is not a readable config file`);
      return fs.readFileSync(filePath, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw error;
    }
  },
  exists(filePath) {
    return fs.existsSync(filePath);
  },
  passwdHome() {
    try {
      return os.userInfo().homedir || undefined;
    } catch {
      return undefined;
    }
  },
};

function cli(reason: string): DockerEndpoint {
  return { kind: "cli", reason };
}

function set(value: string | undefined): value is string {
  return value !== undefined && value !== "";
}

/** Parses `unix:///abs/path`; anything else (other schemes, relative, non-canonical) is undefined. */
export function parseUnixDockerHost(host: string): string | undefined {
  if (!host.startsWith("unix://")) return undefined;
  const socketPath = host.slice("unix://".length);
  if (!socketPath.startsWith("/") || socketPath.length > 1024) return undefined;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\s?#]/u.test(socketPath)) return undefined;
  if (path.posix.normalize(socketPath) !== socketPath || socketPath.endsWith("/")) return undefined;
  return socketPath;
}

function readJsonObject(fsx: DockerEndpointFs, filePath: string): { value?: Record<string, unknown>; missing?: true; error?: string } {
  let text: string | undefined;
  try {
    text = fsx.readFile(filePath);
  } catch (error) {
    return { error: `${filePath} is unreadable: ${(error as Error).message}` };
  }
  if (text === undefined) return { missing: true };
  try {
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return { error: `${filePath} is not a JSON object` };
    return { value: parsed as Record<string, unknown> };
  } catch {
    return { error: `${filePath} is malformed` };
  }
}

function dockerConfigDir(env: NodeJS.ProcessEnv, fsx: DockerEndpointFs): string | undefined {
  if (set(env.DOCKER_CONFIG)) return path.isAbsolute(env.DOCKER_CONFIG) ? env.DOCKER_CONFIG : undefined;
  const home = set(env.HOME) ? env.HOME : fsx.passwdHome();
  if (!home || !path.isAbsolute(home)) return undefined;
  return path.join(home, ".docker");
}

export function dockerContextMetaPath(configDir: string, contextName: string): string {
  const digest = crypto.createHash("sha256").update(contextName).digest("hex");
  return path.join(configDir, "contexts", "meta", digest, "meta.json");
}

function dockerContextTlsDir(configDir: string, contextName: string): string {
  const digest = crypto.createHash("sha256").update(contextName).digest("hex");
  return path.join(configDir, "contexts", "tls", digest);
}

/**
 * Resolves the endpoint with no network I/O. `env` is the environment the
 * Docker CLI child would receive (the call's `env` option, or the process
 * environment when the call passes none).
 */
export function resolveDockerEndpoint(env: NodeJS.ProcessEnv, fsx: DockerEndpointFs = nodeDockerEndpointFs): DockerEndpoint {
  for (const name of ["DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION"] as const) {
    if (set(env[name])) return cli(`${name} is set`);
  }
  const host = env.DOCKER_HOST;
  const contextOverride = env.DOCKER_CONTEXT;
  if (set(host) && set(contextOverride)) return cli("DOCKER_HOST and DOCKER_CONTEXT are both set");

  const configDir = dockerConfigDir(env, fsx);
  if (!configDir) return cli("the Docker config directory cannot be resolved");
  const config = readJsonObject(fsx, path.join(configDir, "config.json"));
  if (config.error) return cli(config.error);
  const headers = config.value?.HttpHeaders;
  if (headers !== undefined && headers !== null && !(typeof headers === "object" && Object.keys(headers).length === 0)) {
    return cli("config.json sets HttpHeaders");
  }

  if (set(host)) {
    const socketPath = parseUnixDockerHost(host);
    return socketPath ? { kind: "unix", socketPath, context: DEFAULT_CONTEXT } : cli("DOCKER_HOST is not a unix socket");
  }

  let contextName = DEFAULT_CONTEXT;
  if (set(contextOverride)) {
    contextName = contextOverride;
  } else if (config.value && config.value.currentContext !== undefined) {
    const current = config.value.currentContext;
    if (typeof current !== "string") return cli("config.json currentContext is not a string");
    if (current !== "") contextName = current;
  }

  if (contextName === DEFAULT_CONTEXT) {
    return fsx.exists(DEFAULT_DOCKER_SOCKET)
      ? { kind: "unix", socketPath: DEFAULT_DOCKER_SOCKET, context: DEFAULT_CONTEXT }
      : cli(`${DEFAULT_DOCKER_SOCKET} does not exist`);
  }
  if (!CONTEXT_NAME_PATTERN.test(contextName)) return cli("the Docker context name is invalid");

  const meta = readJsonObject(fsx, dockerContextMetaPath(configDir, contextName));
  if (meta.error) return cli(meta.error);
  if (meta.missing || !meta.value) return cli(`Docker context ${contextName} has no metadata`);
  if (meta.value.Name !== contextName) return cli(`Docker context ${contextName} metadata names another context`);
  const endpoints = meta.value.Endpoints;
  if (typeof endpoints !== "object" || endpoints === null || Array.isArray(endpoints)) return cli("Docker context has no endpoints");
  const docker = (endpoints as Record<string, unknown>).docker;
  if (typeof docker !== "object" || docker === null || Array.isArray(docker)) return cli("Docker context has no docker endpoint");
  const endpoint = docker as Record<string, unknown>;
  if (endpoint.SkipTLSVerify !== undefined && endpoint.SkipTLSVerify !== false) return cli("Docker context sets SkipTLSVerify");
  if (fsx.exists(dockerContextTlsDir(configDir, contextName))) return cli("Docker context has TLS material");
  if (typeof endpoint.Host !== "string") return cli("Docker context endpoint has no host");
  const socketPath = parseUnixDockerHost(endpoint.Host);
  return socketPath ? { kind: "unix", socketPath, context: contextName } : cli("Docker context endpoint is not a unix socket");
}
