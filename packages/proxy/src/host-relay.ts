// The Docker Engine host-service relay (Linux host services, Option A).
//
// On Docker Desktop the daemon's host gateway already forwards to the host's
// loopback, so this module never runs there. On a local Docker Engine the
// gateway is a bridge address (docker0) and a service on the host's
// 127.0.0.1:P is unreachable through it. This relay is the one backend
// adapter: a Compose service on the host network namespace, run from the
// proxy image, that makes host 127.0.0.1:P answer at <gateway>:P and nothing
// else. The proxy's own path is unchanged on every backend: it dials the
// pinned gateway, only its uid 1001 may (`@host_service`), and its two cuts
// (the request-proxy cut and the firewall cut) are the whole revocation, as on
// Desktop. The relay adds no third cut: it never closes an established
// connection itself.
//
// What it enforces:
//   - the gateway is read the way the proxy's root supervisor reads it (the
//     daemon's `host-gateway` entry in a root-owned /etc/hosts) and refused by
//     the same `validateHostServiceGateway` checks; a refused gateway leaves
//     the relay idle, with no listener;
//   - it listens on exactly <gateway>:P, for each P in the effective policy
//     generation the proxy serves, and never on a wildcard, loopback, or any
//     other address;
//   - it accepts a connection only from the proxy's egress IP; any other peer
//     is destroyed before a byte is read and before any upstream dial;
//   - it splices opaque bytes to 127.0.0.1:P and parses nothing;
//   - a port that leaves the effective set stops listening (no new
//     connections); its established connections end when the proxy's cuts
//     close them, exactly as on Desktop.
// The effective selection is watched (`fs.watch` on the effective root) with
// a short poll as the fallback, so a port added to the live generation is
// listening within about one poll interval.
// A port whose <gateway>:P bind fails with EADDRINUSE because a wildcard
// listener (0.0.0.0:P or [::]:P) already owns it is "served directly": the
// kernel delivers <gateway>:P to that service, so the proxy reaches it with
// the same proxy-side guarantees. The bind is retried on every poll, so a
// later 127.0.0.1-only service is relayed once the wildcard listener is gone.

import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import { pathToFileURL } from "node:url";

import { loadEffectiveProxyControl } from "@runfree/runtime-contracts/effective-control";
import {
  isWildcardListenAddress,
  parseProcNetTcp,
  PROC_NET_TCP_LISTEN_STATE,
  type ProcNetTcpFamily,
} from "@runfree/runtime-contracts/proc-net-tcp";

import {
  checkEtcHostsFile,
  parseHostServiceGatewayFromEtcHosts,
  validateHostServiceGateway,
  type HostServiceGatewayPlan,
} from "./firewall/host-service-gateway.js";

/** Fallback poll of the effective selection; `fs.watch` normally reacts first. */
export const HOST_RELAY_POLL_MS = 250;
export const HOST_RELAY_MAX_CONNECTIONS_PER_PORT = 256;
export const HOST_RELAY_UPSTREAM_HOST = "127.0.0.1";
const PROC_NET_TCP_MAX_BYTES = 16 * 1024 * 1024;
const ETC_HOSTS_MAX_BYTES = 64 * 1024;

const IPV4_OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
const CANONICAL_IPV4_RE = new RegExp(`^${IPV4_OCTET}(?:\\.${IPV4_OCTET}){3}$`);
const IPV4_CIDR_RE = new RegExp(`^${IPV4_OCTET}(?:\\.${IPV4_OCTET}){3}/(?:[0-9]|[12][0-9]|3[0-2])$`);

export type HostRelayPortState = "listening" | "served-directly" | "bind-failed";

export type HostRelayConfig = Readonly<{
  /** The pinned host-service gateway: the only address any listener binds. */
  gateway: string;
  /** The proxy's egress IP: the only peer a connection is accepted from. */
  allowedSource: string;
}>;

export type HostRelayDeps = Readonly<{
  /** Listen on exactly `host:port`; resolves with the server or rejects with the bind error. */
  listen(host: string, port: number, onConnection: (socket: net.Socket) => void): Promise<net.Server>;
  /** Dial the host service behind `port` (127.0.0.1:port in production). */
  connectUpstream(port: number): net.Socket;
  /** Whether a wildcard listener (0.0.0.0:P or [::]:P) owns `port` on this host. */
  wildcardListener(port: number): boolean;
  log(line: string): void;
}>;

export type HostRelay = Readonly<{
  /** Converge the listeners to exactly `ports`; retries every port not yet listening. */
  reconcile(ports: readonly number[]): Promise<void>;
  /** The current state of each relayed port. */
  state(): ReadonlyMap<number, HostRelayPortState>;
  /** Open relayed connections on `port` (diagnostics and tests). */
  connections(port: number): number;
  close(): Promise<void>;
}>;

/** `::ffff:a.b.c.d` (a dual-stack accept) is the IPv4 peer it carries. */
export function normalizePeerAddress(address: string | undefined): string | undefined {
  if (address === undefined) return undefined;
  return address.startsWith("::ffff:") ? address.slice("::ffff:".length) : address;
}

function errorCode(error: unknown): string {
  return error && typeof error === "object" && typeof (error as { code?: unknown }).code === "string"
    ? (error as { code: string }).code
    : "unknown";
}

type PortEntry = {
  // "new" only until the first bind attempt settles, so that outcome is logged.
  state: HostRelayPortState | "new";
  server?: net.Server;
  pairs: Set<{ client: net.Socket; upstream?: net.Socket }>;
};

export function createHostRelay(config: HostRelayConfig, deps: HostRelayDeps): HostRelay {
  const ports = new Map<number, PortEntry>();
  let closed = false;

  const transition = (port: number, entry: PortEntry, next: HostRelayPortState, detail: string): void => {
    if (entry.state === next) return;
    entry.state = next;
    deps.log(`host-relay: ${config.gateway}:${port} ${detail}`);
  };

  const accept = (port: number, entry: PortEntry, client: net.Socket): void => {
    const peer = normalizePeerAddress(client.remoteAddress);
    // Refused before a byte is read (the server pauses on connect) and before
    // any upstream dial.
    if (peer !== config.allowedSource) {
      client.destroy();
      deps.log(`host-relay: ${config.gateway}:${port} refused a connection from ${peer ?? "an unknown peer"}`);
      return;
    }
    if (entry.pairs.size >= HOST_RELAY_MAX_CONNECTIONS_PER_PORT || ports.get(port) !== entry || entry.server === undefined) {
      client.destroy();
      return;
    }
    const pair: { client: net.Socket; upstream?: net.Socket } = { client };
    entry.pairs.add(pair);
    const upstream = deps.connectUpstream(port);
    pair.upstream = upstream;
    const teardown = (): void => {
      entry.pairs.delete(pair);
      client.destroy();
      upstream.destroy();
    };
    client.on("error", teardown);
    client.on("close", teardown);
    upstream.on("error", teardown);
    upstream.on("close", teardown);
    client.pipe(upstream);
    upstream.pipe(client);
    client.resume();
  };

  // Stops accepting on `port`. Established pairs are left to their own ends:
  // revocation is the proxy's two cuts, never the relay (`destroyPairs` is
  // only the relay's own shutdown).
  const closeEntry = async (port: number, entry: PortEntry, destroyPairs = false): Promise<void> => {
    if (destroyPairs) {
      for (const pair of entry.pairs) {
        pair.client.destroy();
        pair.upstream?.destroy();
      }
      entry.pairs.clear();
    }
    const server = entry.server;
    entry.server = undefined;
    // `close()` stops accepting at once (the listening fd closes now); its
    // callback would wait for every established connection, which this does
    // not, so a later re-add binds the port again without waiting.
    if (server) {
      server.close();
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    deps.log(`host-relay: ${config.gateway}:${port} closed`);
    ports.delete(port);
  };

  const tryListen = async (port: number, entry: PortEntry): Promise<void> => {
    try {
      const server = await deps.listen(config.gateway, port, (socket) => accept(port, entry, socket));
      if (closed || ports.get(port) !== entry) {
        await new Promise<void>((resolve) => server.close(() => resolve()));
        return;
      }
      entry.server = server;
      server.on("error", (error) => deps.log(`host-relay: ${config.gateway}:${port} listener error ${errorCode(error)}`));
      transition(port, entry, "listening", "listening");
    } catch (error) {
      const code = errorCode(error);
      if (code === "EADDRINUSE" && deps.wildcardListener(port)) {
        transition(port, entry, "served-directly", "is served directly by a wildcard listener on the host; not relayed");
      } else {
        transition(port, entry, "bind-failed", `could not listen (${code}); retrying`);
      }
    }
  };

  return Object.freeze({
    async reconcile(next) {
      if (closed) return;
      const wanted = new Set(next.filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535));
      for (const [port, entry] of [...ports]) {
        if (!wanted.has(port)) await closeEntry(port, entry);
      }
      for (const port of [...wanted].sort((left, right) => left - right)) {
        let entry = ports.get(port);
        if (!entry) {
          entry = { state: "new", pairs: new Set() };
          ports.set(port, entry);
        }
        if (entry.server === undefined) await tryListen(port, entry);
      }
    },
    state() {
      return new Map([...ports].flatMap(([port, entry]): Array<[number, HostRelayPortState]> =>
        entry.state === "new" ? [] : [[port, entry.state]]));
    },
    connections(port) {
      return ports.get(port)?.pairs.size ?? 0;
    },
    async close() {
      closed = true;
      for (const [port, entry] of [...ports]) await closeEntry(port, entry, true);
    },
  });
}

/** `net` listening on exactly `host:port`, paused on connect, IPv4 only. */
export function listenExactly(host: string, port: number, onConnection: (socket: net.Socket) => void): Promise<net.Server> {
  return new Promise((resolve, reject) => {
    const server = net.createServer({ pauseOnConnect: true }, onConnection);
    const onError = (error: Error): void => reject(error);
    server.once("error", onError);
    server.listen({ host, port, exclusive: true }, () => {
      server.off("error", onError);
      resolve(server);
    });
  });
}

type ProcReader = (path: string) => string;

function readBounded(path: string, maxBytes: number): string {
  const descriptor = fs.openSync(path, "r");
  try {
    const chunks: Buffer[] = [];
    let total = 0;
    for (;;) {
      const chunk = Buffer.alloc(64 * 1024);
      const read = fs.readSync(descriptor, chunk, 0, chunk.length, null);
      if (read === 0) break;
      total += read;
      if (total > maxBytes) throw new Error(`${path} exceeds ${maxBytes} bytes`);
      chunks.push(chunk.subarray(0, read));
    }
    return Buffer.concat(chunks).toString("utf8");
  } finally {
    fs.closeSync(descriptor);
  }
}

/**
 * Whether `/proc/net/tcp{,6}` (this relay shares the host network namespace)
 * shows a LISTEN socket on 0.0.0.0:P or [::]:P. An unreadable or malformed
 * table answers false: the port then reads as a bind failure, never as served.
 */
export function procWildcardListener(port: number, read: ProcReader = (path) => readBounded(path, PROC_NET_TCP_MAX_BYTES)): boolean {
  for (const [path, family] of [["/proc/net/tcp", 4], ["/proc/net/tcp6", 6]] as const satisfies readonly (readonly [string, ProcNetTcpFamily])[]) {
    let parsed: ReturnType<typeof parseProcNetTcp>;
    try {
      parsed = parseProcNetTcp(read(path), family);
    } catch {
      return false;
    }
    if (!Array.isArray(parsed)) return false;
    if (parsed.some((socket) => socket.state === PROC_NET_TCP_LISTEN_STATE && socket.port === port
      && isWildcardListenAddress(socket.address))) return true;
  }
  return false;
}

export type HostRelayConfigInput = Readonly<{
  etcHosts: string;
  etcHostsStat: Readonly<{ uid: number; mode: number; isFile: boolean }>;
  env: NodeJS.ProcessEnv;
}>;

function envIpv4(env: NodeJS.ProcessEnv, name: string): string | { error: string } {
  const value = env[name];
  if (typeof value !== "string" || !CANONICAL_IPV4_RE.test(value)) return { error: `${name} is not a canonical IPv4 address` };
  return value;
}

/**
 * The relay's gateway and allowed source, read and refused exactly as the
 * proxy's root supervisor reads and refuses the gateway: a root-owned,
 * non-writable /etc/hosts entry for the daemon's `host-gateway`, then
 * `validateHostServiceGateway` against the same runtime addresses.
 */
export function resolveHostRelayConfig(input: HostRelayConfigInput): HostRelayConfig | { error: string } {
  const statIssue = checkEtcHostsFile(input.etcHostsStat);
  if (statIssue !== undefined) return { error: statIssue };
  const parsed = parseHostServiceGatewayFromEtcHosts(input.etcHosts);
  if ("error" in parsed) return { error: parsed.error };
  const sourceIp = envIpv4(input.env, "RUNFREE_PROXY_EGRESS_IP");
  if (typeof sourceIp !== "string") return sourceIp;
  const gatewayIp = envIpv4(input.env, "RUNFREE_PROXY_EGRESS_GATEWAY");
  if (typeof gatewayIp !== "string") return gatewayIp;
  const proxyIp = envIpv4(input.env, "RUNFREE_PROXY_IP");
  if (typeof proxyIp !== "string") return proxyIp;
  const runtimeSubnets: string[] = [];
  for (const name of ["RUNFREE_SUBNET", "RUNFREE_PROXY_EGRESS_SUBNET"]) {
    const value = input.env[name];
    if (typeof value !== "string" || !IPV4_CIDR_RE.test(value)) return { error: `${name} is not an IPv4 CIDR` };
    runtimeSubnets.push(value);
  }
  const plan: HostServiceGatewayPlan = { internal: { proxyIp }, egress: { sourceIp, gatewayIp }, runtimeSubnets };
  const refusal = validateHostServiceGateway(parsed.ip, plan);
  if (refusal !== undefined) return { error: refusal };
  return Object.freeze({ gateway: parsed.ip, allowedSource: sourceIp });
}

/** The ports of the effective policy generation's host services. */
export function effectiveHostServicePorts(root: string): number[] {
  const control = loadEffectiveProxyControl(root);
  return Object.values(control.networkPolicy.hostServices).map((entry) => entry.port).sort((left, right) => left - right);
}

function readEtcHosts(): Pick<HostRelayConfigInput, "etcHosts" | "etcHostsStat"> {
  const stat = fs.statSync("/etc/hosts");
  return {
    etcHostsStat: { uid: stat.uid, mode: stat.mode, isFile: stat.isFile() },
    etcHosts: readBounded("/etc/hosts", ETC_HOSTS_MAX_BYTES),
  };
}

async function main(): Promise<void> {
  const log = (line: string): void => console.log(line);
  const root = process.env.RUNFREE_EFFECTIVE_PROXY_ROOT;
  let config: HostRelayConfig | { error: string };
  try {
    config = typeof root === "string" && root !== ""
      ? resolveHostRelayConfig({ ...readEtcHosts(), env: process.env })
      : { error: "RUNFREE_EFFECTIVE_PROXY_ROOT is not set" };
  } catch (error) {
    config = { error: `could not read /etc/hosts: ${error instanceof Error ? error.message : String(error)}` };
  }
  if ("error" in config) {
    // Idle, not exited: the relay holds no listener and the proxy refuses the
    // same gateway on its side, so host services stay cut while the rest of
    // the runtime keeps working. The gateway is pinned for this relay's life,
    // as the supervisor pins it; recreating the runtime re-reads it.
    log(`host-relay: refusing to relay host services: ${config.error}`);
    setInterval(() => {}, 1 << 30);
    return;
  }
  log(`host-relay: gateway ${config.gateway}, accepting only ${config.allowedSource}`);
  const relay = createHostRelay(config, {
    listen: listenExactly,
    connectUpstream: (port) => net.connect({ host: HOST_RELAY_UPSTREAM_HOST, port }),
    wildcardListener: (port) => procWildcardListener(port),
    log,
  });
  let previousError: string | undefined;
  let current: number[] = [];
  let running = false;
  let pending = false;
  // The selection file's identity at the last successful reload: the control
  // plane is re-read only when `active.json` was replaced (rename gives it a
  // new inode), not on every 250 ms poll.
  let loadedSelection: string | undefined;
  const selectionRevision = (): string => {
    try {
      const stat = fs.statSync(path.join(root as string, "active.json"));
      return `${stat.ino}:${stat.mtimeMs}:${stat.size}`;
    } catch {
      return "missing";
    }
  };
  const tick = async (): Promise<void> => {
    // A watch event during a running reconcile is not dropped: it runs once more.
    if (running) {
      pending = true;
      return;
    }
    running = true;
    try {
      do {
        pending = false;
        const revision = selectionRevision();
        if (revision !== loadedSelection || previousError !== undefined) {
          try {
            current = effectiveHostServicePorts(root as string);
            loadedSelection = revision;
            previousError = undefined;
          } catch (error) {
            // Same rule as the proxy: an unreadable generation keeps the previous
            // valid one; the proxy's own cuts are the revocation.
            const message = error instanceof Error ? error.message : String(error);
            if (message !== previousError) log(`host-relay: effective policy reload failed, keeping the previous ports: ${message}`);
            previousError = message;
          }
        }
        await relay.reconcile(current);
      } while (pending);
    } finally {
      running = false;
    }
  };
  await tick();
  // The selection (`active.json`) is replaced by rename in the effective
  // root, which a directory watch sees. The poll stays the fallback for a
  // missed or unsupported watch, so a watch failure only costs latency.
  let watcher: fs.FSWatcher | undefined;
  try {
    watcher = fs.watch(root as string, { persistent: false }, () => void tick());
    watcher.on("error", (error) => {
      log(`host-relay: effective policy watch failed, polling only: ${errorCode(error)}`);
      watcher?.close();
    });
  } catch (error) {
    log(`host-relay: effective policy watch unavailable, polling only: ${errorCode(error)}`);
  }
  const timer = setInterval(() => void tick(), HOST_RELAY_POLL_MS);
  const stop = (): void => {
    clearInterval(timer);
    watcher?.close();
    void relay.close().finally(() => process.exit(0));
  };
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
}

function isMainModule(): boolean {
  if (!process.argv[1]) return false;
  return import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMainModule()) {
  main().catch((error) => {
    console.error(`host-relay: startup failed: ${error instanceof Error ? error.stack ?? error.message : String(error)}`);
    process.exitCode = 1;
  });
}
