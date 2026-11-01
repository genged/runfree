// Host-service port admission (design "Policy shape", SR5/SR13).
//
// Before a `runfree host-service add` writes policy, the host checks the port:
//   1. the static refusals shared with policy validation (Docker Engine TCP,
//      runfree's own VNC default and MCP callback block);
//   2. the Docker backend (`docker-backend.ts`): host services need Docker
//      Desktop or a local Docker Engine on Linux; anything else refuses;
//   3. on Docker Engine only, the two refusals its relay adapter needs: a
//      port below `net.ipv4.ip_unprivileged_port_start` (the relay binds
//      without root or added capabilities), and a port Docker publishes on
//      the host (a `docker ps` binding on 127.0.0.1, 0.0.0.0, or ::);
//   4. the live owner, from the host listener check (`host-listener-probe.ts`:
//      lsof on macOS, /proc on Linux): a visible process must listen on the
//      host's TCP port at 127.0.0.1:<port> or *:<port>, the addresses the
//      host gateway (Desktop) or the Engine relay reaches (R22). No visible
//      listener refuses: Docker Desktop answers some ports from its VM, and a
//      listener owned by root or another user is invisible to the operator's
//      probe, so it refuses as "no visible listener" too (Linux names the
//      socket's uid). A listener only on [::1] or a LAN address is refused
//      with its address. A `com.docker.*` listener on any address refuses
//      (another container's published port, or Docker Engine TCP), and so
//      does a visible `docker-proxy` (a container-published port on Engine).
// The admitted owner (command and pid) is what the operator reviews and what
// the port registry records. Every probe only reads: none connects to the port.

import fs from "node:fs";

import { refusedHostServicePortReason, type HostServicesJson } from "@runfree/runtime-contracts/host-services";

import { detectDockerBackend, type DockerBackend } from "./docker-backend.ts";
import { hostListenerProbe, type HostListenerProbe } from "./host-listener-probe.ts";
import { createDockerClient } from "./runtime/docker-client.ts";
import { dockerClientEnvironment } from "./runtime/env.ts";
import type { RuntimeContext, RuntimeIO } from "./runtime/types.ts";

export {
  LSOF_PATH,
  LSOF_TIMEOUT_MS,
  parseLsofProcessRecords,
  printableCommand,
  type LsofProcessRecord,
} from "./host-listener-lsof.ts";

export type HostPortListener = { command: string; pid: number; addresses: string[] };

/** A listening socket no visible process holds (Linux): its owner uid and address. */
export type HiddenHostListener = { uid: number; address: string };

export type HostPortOwner =
  // `command`/`pid` name the first listener; `commands` lists every listening
  // process, so admission can refuse when any of them is Docker Desktop;
  // `listeners` carries each process's listen addresses (`-Fn`, R22).
  | { kind: "listener"; command: string; pid: number; count: number; commands: string[]; listeners: HostPortListener[] }
  // `hidden` (Linux only): sockets that listen, but whose process this user
  // cannot see. Still no visible listener.
  | { kind: "none"; hidden?: HiddenHostListener[] }
  | { kind: "unavailable"; reason: string };

export type HostServicePortAdmission =
  | { ok: true; owner: { command: string; pid: number } }
  | { ok: false; reason: string };

/**
 * What admission knows about the Docker backend. Production detects it;
 * tests supply it. The Engine facts are read only when the backend is Engine.
 */
export type HostServiceAdmissionEnvironment = Readonly<{
  backend(): DockerBackend;
  /** `net.ipv4.ip_unprivileged_port_start`, or why it could not be read. */
  unprivilegedPortStart(): number | { error: string };
  /** Host TCP ports `docker ps` shows published on 127.0.0.1, 0.0.0.0, or ::. */
  dockerPublishedPorts(): ReadonlySet<number> | { error: string };
  /** The listener check; defaults to the platform's (`host-listener-probe.ts`). */
  listenerProbe?: HostListenerProbe;
}>;

const DOCKER_DESKTOP_COMMAND_PREFIX = "com.docker";
const DOCKER_PROXY_COMMAND = "docker-proxy";
export const UNPRIVILEGED_PORT_START_PATH = "/proc/sys/net/ipv4/ip_unprivileged_port_start";

type ProbeContext = Pick<RuntimeContext, "env" | "projectRoot">;

/**
 * The first listener bound where the host-service path reaches it:
 * `127.0.0.1:<port>` or the wildcard `*:<port>` (R22). `[::1]` and LAN
 * addresses alone do not count.
 */
export function gatewayReachableListener(
  owner: Extract<HostPortOwner, { kind: "listener" }>,
  port: number,
): HostPortListener | undefined {
  const reachable = new Set([`127.0.0.1:${port}`, `*:${port}`]);
  return owner.listeners.find((listener) => listener.addresses.some((address) => reachable.has(address)));
}

function listenAddressSummary(owner: Extract<HostPortOwner, { kind: "listener" }>): string {
  const addresses = [...new Set(owner.listeners.flatMap((listener) => listener.addresses))];
  return addresses.length > 0 ? addresses.join(", ") : "no address reported";
}

function hiddenSummary(hidden: readonly HiddenHostListener[]): string {
  return hidden.map((entry) => `uid ${entry.uid} on ${entry.address}`).join(", ");
}

function publishedByContainer(owner: Extract<HostPortOwner, { kind: "listener" }>): boolean {
  return owner.commands.some((command) => command === DOCKER_PROXY_COMMAND);
}

/** Who listens on the host's TCP `port` (read-only, bounded; macOS or Linux). */
export function probeHostPortOwner(
  context: ProbeContext,
  io: RuntimeIO,
  port: number,
  platform: NodeJS.Platform = process.platform,
): HostPortOwner {
  return hostListenerProbe(context, io, platform).portOwner(port);
}

const PUBLISHED_HOST_IPS = new Set(["127.0.0.1", "0.0.0.0", "::", "[::]", ""]);
const PORT_ENTRY_RE = /^(?:(.*):)?([0-9]{1,5})(?:-([0-9]{1,5}))?->[0-9]{1,5}(?:-[0-9]{1,5})?\/(tcp|udp|sctp)$/u;
const EXPOSED_ONLY_RE = /^[0-9]{1,5}(?:-[0-9]{1,5})?\/(tcp|udp|sctp)$/u;
const MAX_PUBLISHED_RANGE = 65_536;

/**
 * Host TCP ports in `docker ps --format '{{.Ports}}'` output published on
 * 127.0.0.1, 0.0.0.0, or ::. An entry that is not Docker's shape fails the
 * whole read, so admission refuses rather than missing a published port.
 */
export function parseDockerPublishedPorts(stdout: string): Set<number> | { error: string } {
  const ports = new Set<number>();
  for (const line of stdout.split("\n")) {
    for (const raw of line.split(",")) {
      const entry = raw.trim();
      if (entry === "" || EXPOSED_ONLY_RE.test(entry)) continue;
      const match = PORT_ENTRY_RE.exec(entry);
      if (!match) return { error: `docker ps reported an unreadable port binding: ${entry.slice(0, 128)}` };
      const [, hostIp = "", first, last, protocol] = match;
      if (protocol !== "tcp" || !PUBLISHED_HOST_IPS.has(hostIp)) continue;
      const start = Number(first);
      const end = last === undefined ? start : Number(last);
      if (start < 1 || end > 65535 || end < start || end - start >= MAX_PUBLISHED_RANGE) {
        return { error: `docker ps reported an invalid port range: ${entry.slice(0, 128)}` };
      }
      for (let port = start; port <= end; port += 1) ports.add(port);
    }
  }
  return ports;
}

export function parseUnprivilegedPortStart(text: string): number | { error: string } {
  const trimmed = text.trim();
  if (!/^(0|[1-9][0-9]{0,4})$/u.test(trimmed) || Number(trimmed) > 65536) {
    return { error: `${UNPRIVILEGED_PORT_START_PATH} is not a port number` };
  }
  return Number(trimmed);
}

/** The production admission environment: detected backend, host sysctl, `docker ps`. */
export function hostServiceAdmissionEnvironment(
  context: ProbeContext,
  io: RuntimeIO,
  platform: NodeJS.Platform = process.platform,
): HostServiceAdmissionEnvironment {
  return Object.freeze({
    backend: () => detectDockerBackend(context, io, { platform }),
    unprivilegedPortStart: () => {
      try {
        return parseUnprivilegedPortStart(fs.readFileSync(UNPRIVILEGED_PORT_START_PATH, "utf8").slice(0, 64));
      } catch (error) {
        return { error: `could not read ${UNPRIVILEGED_PORT_START_PATH}: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
    dockerPublishedPorts: () => {
      const result = createDockerClient(io, { env: dockerClientEnvironment(context.env ?? process.env) })
        .listContainers({ noTrunc: true, format: "{{.Ports}}" }, { timeout: 30_000, maxBuffer: 4 * 1024 * 1024 });
      if (result.status !== 0) return { error: `docker ps exited with status ${result.status}` };
      return parseDockerPublishedPorts(result.stdout);
    },
  });
}

/** Static refusal first (no probe), then the backend, then the live owner check. */
export function admitHostServicePort(
  context: ProbeContext,
  io: RuntimeIO,
  port: number,
  platform: NodeJS.Platform = process.platform,
  environment: HostServiceAdmissionEnvironment = hostServiceAdmissionEnvironment(context, io, platform),
): HostServicePortAdmission {
  const staticReason = refusedHostServicePortReason(port);
  if (staticReason !== undefined) return { ok: false, reason: `port ${port} is refused: ${staticReason}` };
  const backend = environment.backend();
  if (backend.kind === "unsupported") return { ok: false, reason: backend.reason };
  const engine = backend.kind === "docker-engine";
  if (engine) {
    const start = environment.unprivilegedPortStart();
    if (typeof start !== "number") return { ok: false, reason: start.error };
    if (port < start) {
      return {
        ok: false,
        reason: `port ${port} is below net.ipv4.ip_unprivileged_port_start (${start}); on Docker Engine the host-service `
          + "relay binds it without root or added capabilities, so use a port at or above that value "
          + "(or lower the sysctl on the host)",
      };
    }
    const published = environment.dockerPublishedPorts();
    if ("error" in published) return { ok: false, reason: published.error };
    if (published.has(port)) return { ok: false, reason: `127.0.0.1:${port} is published by a container (docker ps)` };
  }
  const owner = environment.listenerProbe?.portOwner(port) ?? probeHostPortOwner(context, io, port, platform);
  if (owner.kind === "none") {
    if (owner.hidden && owner.hidden.length > 0) {
      return {
        ok: false,
        reason: `no visible listener on 127.0.0.1:${port}: a socket listens (${hiddenSummary(owner.hidden)}) `
          + "but its process is not visible to this user",
      };
    }
    return { ok: false, reason: `no process listens on 127.0.0.1:${port}` };
  }
  if (owner.kind === "unavailable") return { ok: false, reason: owner.reason };
  // Every listener counts: two sockets can share a port on macOS (a user
  // process on [::1] or *, Docker Desktop on 127.0.0.1, which the gateway
  // reaches), so a non-Docker first listener proves nothing alone.
  if (owner.commands.some((command) => command.startsWith(DOCKER_DESKTOP_COMMAND_PREFIX))) {
    return { ok: false, reason: `127.0.0.1:${port} is owned by Docker Desktop (a published container port)` };
  }
  if (publishedByContainer(owner)) {
    return { ok: false, reason: `127.0.0.1:${port} is published by a container (${DOCKER_PROXY_COMMAND})` };
  }
  const reachable = gatewayReachableListener(owner, port);
  if (!reachable) {
    return {
      ok: false,
      reason: `no visible listener on 127.0.0.1:${port} or *:${port} (found: ${listenAddressSummary(owner)}); `
        + (engine
          ? "the Docker Engine host-service relay reaches only IPv4 loopback, so bind the service to 127.0.0.1"
          : "the Docker Desktop gateway reaches only IPv4 loopback, so bind the service to 127.0.0.1"),
    };
  }
  return { ok: true, owner: { command: reachable.command, pid: reachable.pid } };
}

/**
 * The owner-check warning core, shared by the per-port probe below
 * (`hostServiceOwnerWarnings`, used by `runtime status` and unchanged by
 * F29) and the batched-snapshot path (`hostServiceOwnerWarningsFromSnapshot`
 * in host-listener-snapshot.ts, the launch-time warning loop): both drive
 * the identical label/classification/comparison logic through an
 * owner-lookup callback, so the two call shapes can never diverge in the
 * warning text they produce for the same observed owners.
 */
export function hostServiceWarningLines(
  services: HostServicesJson,
  recorded: ReadonlyMap<number, string>,
  ownerFor: (port: number) => HostPortOwner,
): string[] {
  const lines: string[] = [];
  for (const [name, entry] of Object.entries(services).sort(([left], [right]) => left.localeCompare(right))) {
    const label = `host service ${name} (127.0.0.1:${entry.port})`;
    const owner = ownerFor(entry.port);
    if (owner.kind === "none") {
      // A hidden socket is named: on Engine it can be the relay itself holding
      // <gateway>:P, which also blocks a new wildcard bind of P on the host.
      lines.push(owner.hidden && owner.hidden.length > 0
        ? `${label}: no visible listener (a socket owned by ${hiddenSummary(owner.hidden)})`
        : `${label}: no listener`);
    } else if (owner.kind === "unavailable") {
      lines.push(`${label}: ${owner.reason}`);
    } else if (owner.commands.some((command) => command.startsWith(DOCKER_DESKTOP_COMMAND_PREFIX))) {
      lines.push(`${label}: owned by Docker Desktop`);
    } else if (publishedByContainer(owner)) {
      lines.push(`${label}: published by a container`);
    } else {
      const reachable = gatewayReachableListener(owner, entry.port);
      if (!reachable) {
        lines.push(`${label}: no visible listener on 127.0.0.1 or * (found: ${listenAddressSummary(owner)})`);
        continue;
      }
      const previous = recorded.get(entry.port);
      if (previous !== undefined && previous !== reachable.command) {
        lines.push(`${label}: listener changed to ${reachable.command}`);
      }
    }
  }
  return lines;
}

/**
 * Live re-check (design "Policy shape", Re-check, SR13): `runfree status`
 * repeats the owner check for each approved host service with one query per
 * service, so drift since `add` time (a stopped service, a different
 * process, a port a container now publishes) is never silent. `recorded` is
 * the owner command the port registry has on file for this port, if any; a
 * warning fires only when there is a problem, never on a clean match, and
 * the function never throws — an unavailable probe reports its own reason as
 * the problem.
 *
 * The launch-time warning loop uses the batched snapshot instead
 * (`hostServiceOwnerWarningsFromSnapshot`, host-listener-snapshot.ts, F29):
 * this per-port probe is kept only for `status`, unchanged by that work.
 */
export function hostServiceOwnerWarnings(
  context: ProbeContext,
  io: RuntimeIO,
  services: HostServicesJson,
  recorded: ReadonlyMap<number, string>,
): string[] {
  return hostServiceWarningLines(services, recorded, (port) => probeHostPortOwner(context, io, port));
}
