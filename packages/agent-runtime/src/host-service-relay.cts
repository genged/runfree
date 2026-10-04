#!/usr/bin/env node
// Runfree agent-side host-service relay, started once by `session-entry`
// (`packages/agent-runtime/agent/session-entry.sh`) in the background, before
// the readiness loop, and never awaited.
//
// Compiled by `pnpm build:runtime` (`tsc -b packages/agent-runtime`) into
// `dist/runtime/agent/host-service-relay.cjs`, which the agent Dockerfile
// installs as `/usr/local/libexec/runfree/host-service-relay`. The source is
// written in the repo's ESM syntax; the `.cts` extension makes `tsc` emit
// CommonJS, which is what the agent image's apt-pinned Node runs for an
// extensionless file. The entrypoint test at the bottom uses
// `require.main === module` because `import.meta` is not available in a file
// that compiles to CommonJS (see `session-ready-probe.cts`, which this file
// is modeled on).
//
// See local/specs/2026-10-03-host-services-design.md, "The agent-side relay"
// (OQ1, HS6, SR12). `fb-idb` and similar clients ignore proxy environment
// variables, so the sandbox needs an approved host service to look local: one
// `net.Server` per service, bound to `127.0.0.1:<port>` only, on the same
// port number the host uses (never `0.0.0.0` or `::` — SR20; binding wider
// would serve peer sessions reachable on `agent_internal`, and each session
// is its own container with its own network namespace, so loopback is
// per-session). Each inbound connection opens
// `CONNECT <name>.runfree.internal:<port> HTTP/1.1` to the request proxy at
// `PROXY_IP:PROXY_PORT` (the fixed proxy port, like `session-ready-probe`'s)
// and, once the proxy answers `200`, pipes bytes in both directions. Any
// other status, or a response that never completes, closes both sockets
// before any byte crosses. The relay carries no credential or authority of
// its own (SR12): clients inside the sandbox point at `127.0.0.1:<port>`,
// never at the `.runfree.internal` name, and the proxy alone decides whether
// the pair is approved.
//
// `RUNFREE_HOST_SERVICES` is the host-owned env list the session template
// renders (`name:port` pairs, sorted by name — `formatHostServicesEnv`). This
// module cannot import `@runfree/runtime-contracts`: it is a separate CJS
// build and the agent image carries no contracts package. `parseRelayServices`
// below re-implements the same parse; a unit test pins it against
// `parseHostServicesEnv` on shared vectors so the two cannot drift silently.
//
// Exit codes are not read by the entry, and nothing here may change them: a
// missing binary, a crash, or a bind failure must never change the entry's
// exit code or delay the final `exec` (`session-entry.sh`). This process
// itself never exits with anything but 0: `main()` calls `process.exit(0)`
// directly on every "nothing to do" or bad-input path, before anything has
// bound, and otherwise never calls `process.exit` at all — once a service is
// bound its `net.Server` is an active handle, and this process must keep
// running for as long as that handle does (that is the relay's entire job),
// so nothing here may tear the process down out from under it. Warnings
// about services that failed to bind go to stderr only while the servers are
// binding; once every bind has settled, every further log line goes to
// `/tmp/runfree-host-service-relay.log` only, so nothing the relay does
// writes into the agent's TUI.

import fs from "node:fs";
import net from "node:net";

export const PROXY_PORT = 8080;
export const RELAY_LOG_PATH = "/tmp/runfree-host-service-relay.log";
const RESERVED_SUFFIX = "runfree.internal";
const PROXY_HEAD_LIMIT_BYTES = 8_192;

const IPV4_OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
const IPV4_LITERAL = new RegExp(`^${IPV4_OCTET}(?:\\.${IPV4_OCTET}){3}$`);

// Mirrors `parseHostServicesEnv` in `packages/runtime-contracts/src/host-services.ts`
// (`HOST_SERVICES_ENV_PAIR_RE`) exactly: this file cannot import that module
// (see header), so the parse is duplicated rather than shared. A pinned test
// proves the two stay in lockstep.
const HOST_SERVICES_ENV_PAIR_RE = /^([a-z][a-z0-9-]{0,62}):([1-9][0-9]{0,4})$/;

export function parseRelayServices(value: string): Array<{ name: string; port: number }> {
  const seenNames = new Set<string>();
  const seenPorts = new Set<number>();
  const result: Array<{ name: string; port: number }> = [];

  for (const pair of value.split(",")) {
    const match = HOST_SERVICES_ENV_PAIR_RE.exec(pair);
    if (!match) throw new Error(`invalid RUNFREE_HOST_SERVICES entry: ${JSON.stringify(pair)}`);
    const name = match[1];
    const port = Number(match[2]);
    if (port > 65_535) throw new Error(`invalid RUNFREE_HOST_SERVICES port: ${pair}`);
    if (seenNames.has(name)) throw new Error(`invalid RUNFREE_HOST_SERVICES duplicate name: ${name}`);
    if (seenPorts.has(port)) throw new Error(`invalid RUNFREE_HOST_SERVICES duplicate port: ${port}`);
    seenNames.add(name);
    seenPorts.add(port);
    result.push({ name, port });
  }

  return result;
}

/** Opens one connection, like `net.connect`; a test seam for a fake proxy. */
export type RelayConnect = (options: Readonly<{ host: string; port: number; family: 4 }>) => net.Socket;

const STATUS_LINE_RE = /^HTTP\/1\.[01] (\d{3})(?: |$)/;

/**
 * One accepted client: opens its own `CONNECT` to the proxy, forwards the
 * client's bytes only after the proxy answers `200`, and tears both sockets
 * down together on any refusal, error, or close.
 */
function relayConnection(
  clientSocket: net.Socket,
  service: Readonly<{ name: string; port: number }>,
  proxyHost: string,
  proxyPort: number,
  connect: RelayConnect,
  log: (line: string) => void,
): void {
  const authority = `${service.name}.${RESERVED_SUFFIX}:${service.port}`;
  const head = [`CONNECT ${authority} HTTP/1.1`, `Host: ${authority}`, "", ""].join("\r\n");

  const upstream = connect({ host: proxyHost, port: proxyPort, family: 4 });
  let buffered = Buffer.alloc(0);
  let established = false;
  let torn = false;

  const teardown = (reason?: string): void => {
    if (torn) return;
    torn = true;
    if (reason !== undefined) log(`${service.name}: ${reason}`);
    clientSocket.destroy();
    upstream.destroy();
  };

  // Held until the proxy answers 200: nothing the client sends before then is
  // lost, only delayed (mirrors `host-service-tunnel.ts`'s own `admit()`).
  clientSocket.pause();
  clientSocket.on("error", () => teardown(established ? undefined : "client error before the proxy answered"));
  clientSocket.once("close", () => teardown());

  upstream.once("connect", () => {
    upstream.write(head, "latin1");
  });
  upstream.on("data", (chunk: Buffer) => {
    if (established) return;
    buffered = Buffer.concat([buffered, chunk]);
    const headEnd = buffered.indexOf("\r\n\r\n");
    if (headEnd === -1) {
      if (buffered.length > PROXY_HEAD_LIMIT_BYTES) teardown("the proxy's response head exceeded 8 KiB");
      return;
    }
    const headText = buffered.slice(0, headEnd).toString("latin1");
    const remainder = buffered.slice(headEnd + 4);
    const statusLine = headText.split("\r\n", 1)[0];
    const status = STATUS_LINE_RE.exec(statusLine);
    if (!status || status[1] !== "200") {
      teardown(`the proxy refused the connection (${status ? status[1] : "no status line"})`);
      return;
    }
    established = true;
    upstream.removeAllListeners("data");
    if (remainder.length > 0) clientSocket.write(remainder);
    clientSocket.pipe(upstream);
    upstream.pipe(clientSocket);
    clientSocket.resume();
    log(`${service.name}: connected`);
  });
  upstream.on("error", () => teardown(established ? undefined : "upstream connect error"));
  upstream.once("close", () => teardown());
}

export type StartRelayOptions = Readonly<{
  services: ReadonlyArray<{ name: string; port: number }>;
  proxyHost: string;
  proxyPort: number;
  log?: (line: string) => void;
  connect?: RelayConnect;
}>;

export type StartRelayResult = Readonly<{
  bound: ReadonlyArray<{ name: string; port: number }>;
  skipped: ReadonlyArray<{ name: string; port: number; reason: string }>;
  close(): Promise<void>;
}>;

/**
 * Binds one loopback-only `net.Server` per service. A service whose port is
 * already taken (including `EACCES` on a privileged port) is reported in
 * `skipped` rather than failing the whole call; every other service still
 * binds and the promise still resolves.
 */
export async function startRelay(options: StartRelayOptions): Promise<StartRelayResult> {
  const connect = options.connect ?? ((connectOptions) => net.connect(connectOptions));
  const log = options.log ?? (() => {});
  const bound: Array<{ name: string; port: number }> = [];
  const skipped: Array<{ name: string; port: number; reason: string }> = [];
  const servers: net.Server[] = [];
  const activeSockets = new Set<net.Socket>();

  await Promise.all(options.services.map((service) => new Promise<void>((resolve) => {
    let settled = false;
    const server = net.createServer((clientSocket) => {
      activeSockets.add(clientSocket);
      clientSocket.once("close", () => activeSockets.delete(clientSocket));
      relayConnection(clientSocket, service, options.proxyHost, options.proxyPort, connect, log);
    });
    server.once("error", (error: NodeJS.ErrnoException) => {
      if (settled) return;
      settled = true;
      skipped.push({ name: service.name, port: service.port, reason: error.code ?? String(error) });
      resolve();
    });
    server.listen(service.port, "127.0.0.1", () => {
      if (settled) return;
      settled = true;
      servers.push(server);
      bound.push({ name: service.name, port: service.port });
      log(`${service.name}: listening on 127.0.0.1:${service.port}`);
      resolve();
    });
  })));

  return Object.freeze({
    bound,
    skipped,
    close: async (): Promise<void> => {
      for (const socket of activeSockets) socket.destroy();
      await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
    },
  });
}

function appendLogLine(line: string): void {
  try {
    fs.appendFileSync(RELAY_LOG_PATH, `${line}\n`);
  } catch {
    // Best effort only: a log write must never throw into the relay's own
    // control flow, and nothing here may fall back to stderr post-bind.
  }
}

/**
 * Never exits on the success path: once a service is bound, its `net.Server`
 * is an active handle that must keep the process alive indefinitely (that is
 * the relay's whole job). Only the "nothing to do" and "bad input" paths call
 * `process.exit` themselves, before anything has bound; a path that reaches
 * `startRelay` lets the event loop's own liveness decide when the process
 * ends, so a successful bind is never torn down by this function returning.
 */
async function main(): Promise<void> {
  const proxyHost = process.env.PROXY_IP;
  if (typeof proxyHost !== "string" || !IPV4_LITERAL.test(proxyHost)) {
    process.stderr.write(`host-service-relay: PROXY_IP must be an IPv4 literal, got: ${proxyHost === undefined ? "<unset>" : proxyHost}\n`);
    process.exit(0);
  }

  const raw = process.env.RUNFREE_HOST_SERVICES;
  if (typeof raw !== "string" || raw === "") {
    // The entry only starts this binary when `RUNFREE_HOST_SERVICES` is set
    // (`session-entry.sh`), but main() stays defensive: nothing to relay is
    // not a warning.
    process.exit(0);
  }

  let services: Array<{ name: string; port: number }>;
  try {
    services = parseRelayServices(raw);
  } catch (error) {
    process.stderr.write(`host-service-relay: invalid RUNFREE_HOST_SERVICES: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(0);
  }

  const result = await startRelay({
    services,
    proxyHost,
    proxyPort: PROXY_PORT,
    log: appendLogLine,
  });

  for (const skip of result.skipped) {
    process.stderr.write(`host-service-relay: ${skip.name}:${skip.port} not bound: ${skip.reason}\n`);
  }
  // No explicit exit here, win or lose: zero bound services means nothing is
  // pending and the process ends on its own; one or more means the bound
  // servers must keep it running.
}

if (require.main === module) {
  main().catch((error: unknown) => {
    process.stderr.write(`host-service-relay: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(0);
  });
}
