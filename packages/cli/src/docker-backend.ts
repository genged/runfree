// Which Docker backend the CLI is talking to, for host services (Linux host
// services, Option A).
//
// Host services work on two backends, and the difference between them is one
// adapter: on Docker Desktop the daemon's host gateway already forwards to the
// host's loopback; on a local Docker Engine on Linux a `host_relay` Compose
// service on the host network makes host 127.0.0.1:P answer at <gateway>:P.
// Everything else (the proxy path, admission, the registry) is shared. This is
// the one function that decides which adapter applies, and it never guesses:
//   - `docker-desktop`: `docker info` names Docker Desktop and the daemon
//     endpoint is a local socket (a remote Desktop's gateway reaches another
//     machine's loopback);
//   - `docker-engine`: not Desktop, the CLI runs on Linux, the daemon endpoint
//     is a local unix socket, the daemon is not rootless, and the daemon's
//     host name and kernel are this machine's (a daemon inside a VM, such as
//     Colima, answers on a local socket too, but its host network is not this
//     host's);
//   - anything else (OrbStack, Colima, a remote or rootless daemon, an
//     unreadable answer) is `unsupported`, and `host-service add` refuses.

import os from "node:os";

import { createDockerClient } from "./runtime/docker-client.ts";
import { dockerClientEnvironment } from "./runtime/env.ts";
import type { RuntimeIO } from "./runtime/types.ts";

export const HOST_SERVICE_BACKEND_REFUSAL = "host services need Docker Desktop or a local Docker Engine on Linux";
export const HOST_RELAY_COMPOSE_PROFILE = "host-relay";
export const HOST_RELAY_COMPOSE_SERVICE = "host_relay";

/** The relay's fixed `container_name` (compose.yaml): `<compose project>-host-relay`. */
export function hostRelayContainerName(composeProject: string): string {
  return `${composeProject}-host-relay`;
}

export type DockerBackend =
  | Readonly<{ kind: "docker-desktop" }>
  | Readonly<{ kind: "docker-engine" }>
  | Readonly<{ kind: "unsupported"; reason: string }>;

/** Whether the runtime runs the Engine host-service relay. */
export type HostServiceRelayMode = "engine-relay" | "none";

/** The `docker info` fields the classification reads. */
export type DockerBackendInfo = Readonly<{
  operatingSystem: string;
  name: string;
  kernelVersion: string;
  rootless: boolean;
}>;

export type DockerBackendHost = Readonly<{
  platform: NodeJS.Platform;
  hostname: string;
  kernelRelease: string;
}>;

const TEXT_MAX = 256;

/** The classification fields of a `docker info --format '{{json .}}'` answer, or undefined. */
export function parseDockerBackendInfo(stdout: string): DockerBackendInfo | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const value = parsed as Record<string, unknown>;
  const text = (key: string): string | undefined => {
    const field = value[key];
    return typeof field === "string" && field.length > 0 && field.length <= TEXT_MAX ? field : undefined;
  };
  const operatingSystem = text("OperatingSystem");
  const name = text("Name");
  const kernelVersion = text("KernelVersion");
  const securityOptions = value.SecurityOptions;
  if (!operatingSystem || !name || !kernelVersion) return undefined;
  if (securityOptions !== undefined && securityOptions !== null
    && (!Array.isArray(securityOptions) || securityOptions.some((entry) => typeof entry !== "string"))) return undefined;
  const rootless = ((securityOptions ?? []) as string[])
    .some((entry) => entry.split(",").some((part) => part.trim() === "name=rootless"));
  return Object.freeze({ operatingSystem, name, kernelVersion, rootless });
}

export function isDockerDesktopInfo(info: DockerBackendInfo): boolean {
  return /docker desktop/iu.test(info.operatingSystem) || info.name === "docker-desktop";
}

/** A local daemon socket: a unix socket, or a named pipe on this machine (`npipe:////./pipe/...`). */
export function isLocalDockerEndpoint(endpoint: string): boolean {
  return endpoint.startsWith("unix://") || endpoint.startsWith("npipe:////./pipe/");
}

/**
 * The pure classification. `endpoint` is the daemon endpoint the client uses
 * (`DOCKER_HOST`, else the current context's), or undefined when it could
 * not be read. Desktop and Engine both require a local endpoint.
 */
export function classifyDockerBackend(
  info: DockerBackendInfo | undefined,
  endpoint: string | undefined,
  host: DockerBackendHost,
): DockerBackend {
  if (!info) return { kind: "unsupported", reason: `${HOST_SERVICE_BACKEND_REFUSAL}; docker info did not identify the daemon` };
  const refuse = (detail: string): DockerBackend => ({ kind: "unsupported", reason: `${HOST_SERVICE_BACKEND_REFUSAL}; ${detail}` });
  if (isDockerDesktopInfo(info)) {
    // Desktop's gateway forwards to the loopback of the machine Desktop runs
    // on, so a Desktop reached over TCP or SSH would serve another host's
    // 127.0.0.1:P. Only a local socket endpoint is this host's Desktop.
    if (endpoint === undefined) return refuse("the Docker endpoint could not be read");
    if (!isLocalDockerEndpoint(endpoint)) return refuse(`the Docker endpoint ${endpoint} is not a local socket`);
    return { kind: "docker-desktop" };
  }
  if (host.platform !== "linux") return refuse(`this daemon (${info.operatingSystem}) is not Docker Desktop`);
  if (endpoint === undefined) return refuse("the Docker endpoint could not be read");
  if (!endpoint.startsWith("unix://")) return refuse(`the Docker endpoint ${endpoint} is not a local unix socket`);
  if (info.rootless) return refuse("rootless Docker is not supported");
  if (info.name !== host.hostname || info.kernelVersion !== host.kernelRelease) {
    return refuse(`the daemon runs on ${info.name} (kernel ${info.kernelVersion}), not this host`);
  }
  return { kind: "docker-engine" };
}

export function hostServiceRelayModeFor(backend: DockerBackend): HostServiceRelayMode {
  return backend.kind === "docker-engine" ? "engine-relay" : "none";
}

/** `COMPOSE_PROFILES` for a Compose `up`: the relay profile only on Engine. */
export function composeProfilesFor(mode: HostServiceRelayMode): string {
  return mode === "engine-relay" ? HOST_RELAY_COMPOSE_PROFILE : "";
}

type BackendContext = Readonly<{ env?: NodeJS.ProcessEnv }>;

function localHost(platform: NodeJS.Platform): DockerBackendHost {
  return { platform, hostname: os.hostname(), kernelRelease: os.release() };
}

function dockerEndpoint(context: BackendContext, io: Pick<RuntimeIO, "capture">): string | undefined {
  const env = context.env ?? process.env;
  const dockerHost = env.DOCKER_HOST;
  if (typeof dockerHost === "string" && dockerHost.trim() !== "") return dockerHost.trim();
  const result = createDockerClient(io, { env: dockerClientEnvironment(env) })
    .inspectContext("{{json .Endpoints.docker.Host}}", { timeout: 10_000 });
  if (result.status !== 0) return undefined;
  try {
    const parsed: unknown = JSON.parse(result.stdout.trim());
    return typeof parsed === "string" && parsed.length > 0 && parsed.length <= 4096 ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Classifies the daemon the CLI talks to. `infoStdout` is a `docker info
 * --format '{{json .}}'` answer the caller already has (startup's
 * availability check); without it this runs one. Desktop on any platform
 * and a non-Desktop daemon on Linux cost the extra endpoint read.
 */
export function detectDockerBackend(
  context: BackendContext,
  io: Pick<RuntimeIO, "capture">,
  options: Readonly<{ platform?: NodeJS.Platform; infoStdout?: string; host?: DockerBackendHost }> = {},
): DockerBackend {
  const platform = options.platform ?? process.platform;
  const env = context.env ?? process.env;
  let infoStdout = options.infoStdout;
  if (infoStdout === undefined) {
    const result = createDockerClient(io, { env: dockerClientEnvironment(env) }).info("{{json .}}", { timeout: 30_000 });
    infoStdout = result.status === 0 ? result.stdout : "";
  }
  const info = parseDockerBackendInfo(infoStdout);
  const needsEndpoint = info !== undefined && (isDockerDesktopInfo(info) || platform === "linux");
  const endpoint = needsEndpoint ? dockerEndpoint(context, io) : undefined;
  return classifyDockerBackend(info, endpoint, options.host ?? localHost(platform));
}
