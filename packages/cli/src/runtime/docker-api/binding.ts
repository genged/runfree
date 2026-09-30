import fs from "node:fs";

import type { BridgeReply } from "./sync-bridge.ts";

/**
 * Proves, once per (Docker CLI binary, socket file, context), that the socket
 * the transport would use is the daemon the Docker CLI actually talks to, and
 * learns the API version the CLI negotiated with it.
 *
 * Endpoint resolution alone only shows which socket Docker's config names. A
 * native non-Docker `docker` (nerdctl, a renamed podman), or a socket symlink
 * re-pointed to another engine, would make that a different daemon. So the
 * binding asks the CLI itself — one `docker version --format '{{json .}}'`
 * with the call's environment — and requires:
 *
 * - the CLI reports its resolved context, and it equals the endpoint's;
 * - the daemon's `/_ping` says Docker (no libpod header) and its `/version`
 *   over the socket reports the same server version, API range, commit,
 *   OS/arch, kernel, and build time the CLI reported;
 * - the CLI's negotiated client API version is at least 1.41 and not above
 *   the daemon's. The transport then speaks exactly that version, so the
 *   daemon shapes every body as it would for the CLI.
 *
 * Any mismatch or unreadable answer binds to `cli` for the rest of the
 * process. The key includes the socket's real path, device, and inode, so a
 * re-pointed or re-created socket is bound again, and the transport drops a
 * binding as soon as a reply names another engine (`Server`, `Api-Version`).
 */
export type DaemonBinding = {
  /** The API version the CLI negotiated; every routed path uses it. */
  apiVersion: string;
  swarmInactive: boolean;
  /** The bound engine's `Server` and `Api-Version` reply headers. */
  server: string;
  daemonApiVersion: string;
};

export type BindingOutcome =
  | { kind: "bound"; binding: DaemonBinding }
  /** Stay on the CLI; `cache` says whether the answer holds for the rest of the process. */
  | { kind: "cli"; cache: boolean; reason: string }
  /** The binding step itself failed in a way the call must report (timeout, socket error). */
  | { kind: "reply"; reply: BridgeReply };

export type CliRunResult = { status: number; stdout: string };
export type CliRunner = (args: readonly string[], env: NodeJS.ProcessEnv, timeoutMs: number) => CliRunResult;

export type BindingExchange = (req: { method: "GET"; path: string; maxBytes: number }, deadline: number) => BridgeReply;

export const MIN_API_MINOR = 41;
const CLI_VERSION_TIMEOUT_MS = 15_000;
const API_VERSION_PATTERN = /^1\.([0-9]{1,3})$/;
const REQUIRED_SERVER_FIELDS = ["Version", "ApiVersion", "GitCommit", "Os", "Arch"] as const;
const OPTIONAL_SERVER_FIELDS = ["MinAPIVersion", "KernelVersion", "BuildTime"] as const;

/** Real path, device, and inode of the socket, or undefined when it is not a socket. */
export function socketIdentity(socketPath: string): string | undefined {
  try {
    const stat = fs.statSync(socketPath);
    if (!stat.isSocket()) return undefined;
    return `${fs.realpathSync(socketPath)}\u0000${stat.dev}:${stat.ino}`;
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJsonRecord(text: string): Record<string, unknown> | undefined {
  try {
    const parsed: unknown = JSON.parse(text);
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function minor(version: unknown): number | undefined {
  if (typeof version !== "string") return undefined;
  const match = API_VERSION_PATTERN.exec(version);
  return match ? Number(match[1]) : undefined;
}

function cli(reason: string): BindingOutcome {
  return { kind: "cli", cache: true, reason };
}

export function bindDaemon(input: {
  exchange: BindingExchange;
  runCli: CliRunner;
  env: NodeJS.ProcessEnv;
  context: string;
  deadline: number;
  now: () => number;
}): BindingOutcome {
  const ping = input.exchange({ method: "GET", path: "/_ping", maxBytes: 4096 }, input.deadline);
  if (ping.kind === "error" && ping.phase === "connect") return { kind: "cli", cache: false, reason: `connect failed (${ping.code})` };
  if (ping.kind !== "response") return { kind: "reply", reply: ping };
  if (ping.status !== 200) return cli(`/_ping answered ${ping.status}`);
  const server = ping.headers.server ?? "";
  if (!server.startsWith("Docker/") || ping.headers["libpod-api-version"] !== undefined) return cli("the daemon is not Docker");
  const daemonMinor = minor(ping.headers["api-version"]);
  if (daemonMinor === undefined || daemonMinor < MIN_API_MINOR) return cli("the daemon API version is unsupported");

  const budget = Math.floor(input.deadline - input.now());
  if (budget <= 0) return { kind: "reply", reply: { kind: "timeout" } };
  const version = input.runCli(["version", "--format", "{{json .}}"], input.env, Math.min(budget, CLI_VERSION_TIMEOUT_MS));
  if (version.status === 124 && input.deadline - input.now() <= 0) return { kind: "reply", reply: { kind: "timeout" } };
  if (version.status !== 0) return cli("docker version failed");
  const reported = parseJsonRecord(version.stdout.trim());
  const client = reported && isRecord(reported.Client) ? reported.Client : undefined;
  const cliServer = reported && isRecord(reported.Server) ? reported.Server : undefined;
  if (!client || !cliServer) return cli("docker version did not report a client and a server");
  if (typeof client.Context !== "string" || client.Context !== input.context) return cli("the Docker CLI resolved another context");
  const clientMinor = minor(client.ApiVersion);
  if (clientMinor === undefined || clientMinor < MIN_API_MINOR || clientMinor > daemonMinor) return cli("the Docker CLI API version is unsupported");
  const apiVersion = client.ApiVersion as string;

  const daemonVersion = input.exchange({ method: "GET", path: `/v${apiVersion}/version`, maxBytes: 256 * 1024 }, input.deadline);
  if (daemonVersion.kind === "timeout" || daemonVersion.kind === "dead") return { kind: "reply", reply: daemonVersion };
  if (daemonVersion.kind !== "response" || daemonVersion.status !== 200) return cli("the daemon /version is unreadable");
  const daemon = parseJsonRecord(daemonVersion.body.toString("utf8"));
  if (!daemon) return cli("the daemon /version is not a JSON object");
  for (const field of REQUIRED_SERVER_FIELDS) {
    if (typeof cliServer[field] !== "string" || cliServer[field] !== daemon[field]) return cli(`the socket's daemon differs from the CLI's (${field})`);
  }
  for (const field of OPTIONAL_SERVER_FIELDS) {
    if (cliServer[field] !== daemon[field]) return cli(`the socket's daemon differs from the CLI's (${field})`);
  }
  if (daemon.ApiVersion !== ping.headers["api-version"]) return cli("the daemon API version changed during binding");
  return {
    kind: "bound",
    binding: { apiVersion, swarmInactive: ping.headers.swarm === "inactive", server, daemonApiVersion: ping.headers["api-version"] as string },
  };
}
