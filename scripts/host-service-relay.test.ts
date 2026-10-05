// Unit proof for the agent image's host-service relay (host services plan
// Task 6; see local/specs/2026-10-03-host-services-design.md, "The
// agent-side relay").
//
// The relay is compiled here the same way `scripts/build-runtime.ts` and
// `scripts/session-entry.test.ts` do: `tsc -b packages/agent-runtime`, so the
// bytes under test are the shipped ones, not a test-only bundle. Two kinds of
// proxy stand-in are used: a scripted fake that answers one canned response
// and then optionally echoes (for the forwarding/refusal/parity cases below),
// and the real session entry's own fake-proxy pattern is intentionally not
// duplicated here — `scripts/session-entry.test.ts` covers the relay's
// process lifecycle (start order, survival across exec, signal teardown).

import childProcess from "node:child_process";
import { createRequire } from "node:module";
import net from "node:net";
import path from "node:path";

import { afterEach, beforeAll, describe, expect, test } from "vitest";

import { BASE_AGENT_ENVIRONMENT } from "../packages/cli/src/runtime/agent-env.ts";
import { parseHostServicesEnv } from "../packages/runtime-contracts/src/host-services.ts";

const AGENT_PACKAGE = path.resolve("packages/agent-runtime");
const RELAY_SOURCE = path.join(AGENT_PACKAGE, "dist", "host-service-relay.cjs");

type RelayModule = Readonly<{
  PROXY_PORT: number;
  RELAY_LOG_PATH: string;
  DEFAULT_HANDSHAKE_TIMEOUT_MS: number;
  parseRelayServices: (value: string) => Array<{ name: string; port: number }>;
  startRelay: (options: {
    services: ReadonlyArray<{ name: string; port: number }>;
    proxyHost: string;
    proxyPort: number;
    log?: (line: string) => void;
    connect?: (options: Readonly<{ host: string; port: number; family: 4 }>) => net.Socket;
    handshakeTimeoutMs?: number;
  }) => Promise<{
    bound: ReadonlyArray<{ name: string; port: number }>;
    skipped: ReadonlyArray<{ name: string; port: number; reason: string }>;
    close(): Promise<void>;
  }>;
}>;

let relayModule: RelayModule;

beforeAll(() => {
  // Same compiler and project the runtime build runs; incremental, so a warm
  // tree costs well under a second. The repo-serial build test cleans these
  // outputs, but it runs after the parallel group this file belongs to.
  const build = childProcess.spawnSync("pnpm", ["exec", "tsc", "-b", "packages/agent-runtime"], {
    cwd: path.resolve("."),
    encoding: "utf8",
  });
  if (build.error) throw build.error;
  if (build.status !== 0) throw new Error(`agent-runtime build failed: ${build.stdout}${build.stderr}`);
  relayModule = createRequire(import.meta.url)(RELAY_SOURCE) as RelayModule;
}, 60_000);

async function unusedPort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("could not reserve a port");
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return address.port;
}

/** One attempt: whether a loopback TCP connection to `port` succeeds right now. */
async function isListening(port: number): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("error", () => resolve(false));
  });
}

async function waitFor(port: number, expected: boolean, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if ((await isListening(port)) === expected) return true;
    if (Date.now() >= deadline) return false;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

type FakeProxy = Readonly<{
  port: number;
  requests: readonly string[];
  /** Bytes the proxy received from the client after the head. */
  bytesAfterHead: () => Buffer;
  /**
   * Whether the proxy's *listening server* is still open — not the one
   * accepted connection, which this helper also never closes itself (see
   * `startFakeProxy`) but whose own closed-vs-open timing races the client's
   * (both are reactions, on a loopback connection shared by one process, to
   * the same `destroy()` pair in the relay's `teardown()`, measured to
   * resolve within the same event-loop tick either way). The server staying
   * open is the reliable half of "the proxy side is still open": nothing
   * here ever calls `server.close()` except this helper's own `close()`, so
   * while this reads `true` the proxy was never the active party that ended
   * anything — only the relay's status-line check could have.
   */
  listening: () => boolean;
  close: () => Promise<void>;
}>;

/**
 * A loopback stand-in for the request proxy: reads one `CONNECT` head,
 * records it verbatim, then answers with `statusCode`. On 200 it echoes
 * every later byte, like the real proxy's own pipe. On anything else, it
 * deliberately never ends or destroys its own socket — only the relay's own
 * status-line check may close the connection, so a relay that ignored the
 * status line and only reacted to "the proxy hung up" could not pass a test
 * built on this helper (nothing would ever hang up, and the test would time
 * out instead of passing).
 */
function startFakeProxy(statusCode: 200 | 403 | 204): Promise<FakeProxy> {
  const requests: string[] = [];
  let afterHead = Buffer.alloc(0);
  let lastSocket: net.Socket | undefined;
  const reasonPhrase = statusCode === 200 ? "Connection Established" : statusCode === 403 ? "Forbidden" : "No Content";
  const responseHead = statusCode === 200
    ? "HTTP/1.1 200 Connection Established\r\n\r\n"
    : `HTTP/1.1 ${statusCode} ${reasonPhrase}\r\nConnection: close\r\n\r\n`;
  const server = net.createServer((socket) => {
    lastSocket = socket;
    let buffered = Buffer.alloc(0);
    let headSeen = false;
    socket.on("data", (chunk: Buffer) => {
      if (headSeen) {
        afterHead = Buffer.concat([afterHead, chunk]);
        if (statusCode === 200) socket.write(chunk);
        return;
      }
      buffered = Buffer.concat([buffered, chunk]);
      const headEnd = buffered.indexOf("\r\n\r\n");
      if (headEnd === -1) return;
      headSeen = true;
      requests.push(buffered.slice(0, headEnd + 4).toString("latin1"));
      const remainder = buffered.slice(headEnd + 4);
      if (remainder.length > 0) {
        afterHead = Buffer.concat([afterHead, remainder]);
        if (statusCode === 200) socket.write(remainder);
      }
      socket.write(responseHead, "latin1");
    });
    socket.on("error", () => {});
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("fake proxy did not bind a TCP port");
      resolve(Object.freeze({
        port: address.port,
        requests,
        bytesAfterHead: () => afterHead,
        listening: () => server.listening,
        close: async () => {
          lastSocket?.destroy();
          await new Promise<void>((done) => server.close(() => done()));
        },
      }));
    });
  });
}

async function connectOnce(port: number): Promise<net.Socket> {
  const socket = net.connect({ host: "127.0.0.1", port });
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
  return socket;
}

const proxies: FakeProxy[] = [];
async function fakeProxy(statusCode: 200 | 403 | 204): Promise<FakeProxy> {
  const proxy = await startFakeProxy(statusCode);
  proxies.push(proxy);
  return proxy;
}

afterEach(async () => {
  for (const proxy of proxies.splice(0)) await proxy.close();
});

describe("parseRelayServices parity with parseHostServicesEnv", () => {
  // Every vector exercised against the runtime-contracts parser in
  // `packages/runtime-contracts/src/host-services.test.ts`, duplicated here so
  // the two parsers are proven identical rather than merely both "tested".
  const VALID = ["aa:1,zz:2", "a:1", "a:1,b:2", "idb:10882"];
  const INVALID = ["", "a", "a:", "a:0", "A:1", "a:1,", "a:1,a:2", "a:1,b:1", "a:65536", "a:01", "9x:1"];

  test.each(VALID)("agrees on the valid vector %j", (value) => {
    expect(relayModule.parseRelayServices(value)).toEqual(parseHostServicesEnv(value));
  });

  test.each(INVALID)("throws on the same bad input %j as parseHostServicesEnv", (value) => {
    expect(() => parseHostServicesEnv(value)).toThrow();
    expect(() => relayModule.parseRelayServices(value)).toThrow();
  });
});

test("relays through the proxy port the session environment routes the agent's own traffic to", () => {
  const match = /:(\d+)$/.exec(BASE_AGENT_ENVIRONMENT.HTTPS_PROXY);
  expect(match).not.toBeNull();
  expect(relayModule.PROXY_PORT).toBe(Number(match?.[1]));
});

test("defaults the handshake deadline somewhat above the proxy's own host-service dial timeout (5000 ms)", () => {
  expect(relayModule.DEFAULT_HANDSHAKE_TIMEOUT_MS).toBe(10_000);
});

describe("startRelay", () => {
  test("forwards client bytes once the proxy answers 200, sending the exact CONNECT head", async () => {
    const proxy = await fakeProxy(200);
    const port = await unusedPort();
    const relay = await relayModule.startRelay({ services: [{ name: "echo", port }], proxyHost: "127.0.0.1", proxyPort: proxy.port });
    try {
      expect(relay.bound).toEqual([{ name: "echo", port }]);
      const client = await connectOnce(port);
      const echoedPromise = new Promise<Buffer>((resolve) => {
        client.once("data", (chunk: Buffer) => resolve(chunk));
      });
      client.write("hello from idb");
      const reply = await echoedPromise;
      expect(reply.toString("latin1")).toBe("hello from idb");
      expect(proxy.requests).toEqual([`CONNECT echo.runfree.internal:${port} HTTP/1.1\r\nHost: echo.runfree.internal:${port}\r\n\r\n`]);
      client.destroy();
    } finally {
      await relay.close();
    }
  });

  test.each([403, 204] as const)(
    "closes the client without forwarding any byte, driven only by the status line (%i)",
    async (statusCode) => {
      const proxy = await fakeProxy(statusCode);
      const port = await unusedPort();
      const relay = await relayModule.startRelay({ services: [{ name: "echo", port }], proxyHost: "127.0.0.1", proxyPort: proxy.port });
      try {
        const client = await connectOnce(port);
        const received: Buffer[] = [];
        client.on("data", (chunk: Buffer) => received.push(chunk));
        const closed = new Promise<void>((resolve) => client.once("close", resolve));
        client.write("should never be forwarded");
        await closed;
        // The proxy's listening server is still open: it was never the
        // active party that closed anything (it never calls `end()` or
        // `destroy()` itself — see `startFakeProxy`). So the client's close
        // can only be the relay's own status-line check tearing both
        // sockets down.
        expect(proxy.listening(), "the proxy's own server should still be open").toBe(true);
        expect(Buffer.concat(received).length).toBe(0);
        expect(proxy.bytesAfterHead().length).toBe(0);
      } finally {
        await relay.close();
      }
    },
  );

  test("destroys both sockets after the handshake deadline when the proxy accepts but never answers", async () => {
    const stalledSockets = new Set<net.Socket>();
    const stallServer = net.createServer((socket) => {
      stalledSockets.add(socket);
      socket.on("data", () => {});
      socket.on("error", () => {});
    });
    await new Promise<void>((resolve) => stallServer.listen(0, "127.0.0.1", resolve));
    const stallAddress = stallServer.address() as net.AddressInfo;
    const port = await unusedPort();
    const relay = await relayModule.startRelay({
      services: [{ name: "echo", port }],
      proxyHost: "127.0.0.1",
      proxyPort: stallAddress.port,
      handshakeTimeoutMs: 200,
    });
    try {
      const client = await connectOnce(port);
      const received: Buffer[] = [];
      client.on("data", (chunk: Buffer) => received.push(chunk));
      const closed = new Promise<void>((resolve) => client.once("close", resolve));
      const startedAt = Date.now();
      await closed;
      const elapsed = Date.now() - startedAt;
      expect(elapsed).toBeGreaterThanOrEqual(190);
      expect(elapsed).toBeLessThan(2_000);
      expect(Buffer.concat(received).length).toBe(0);
    } finally {
      await relay.close();
      for (const socket of stalledSockets) socket.destroy();
      await new Promise<void>((resolve) => stallServer.close(() => resolve()));
    }
  });

  test("binds every server to 127.0.0.1 only, never 0.0.0.0 or ::", async () => {
    const proxy = await fakeProxy(200);
    const ports = [await unusedPort(), await unusedPort()];
    const services = ports.map((port, index) => ({ name: `svc${index}`, port }));
    const relay = await relayModule.startRelay({ services, proxyHost: "127.0.0.1", proxyPort: proxy.port });
    try {
      expect(relay.bound).toHaveLength(2);
      const fs = await import("node:fs");
      for (const { port } of relay.bound) {
        const hexPort = port.toString(16).toUpperCase().padStart(4, "0");
        const tcp4Listeners = fs.readFileSync("/proc/net/tcp", "utf8").split("\n").slice(1)
          .map((line) => line.trim().split(/\s+/))
          .filter((cols) => cols[1]?.endsWith(`:${hexPort}`) && cols[3] === "0A");
        expect(tcp4Listeners.length).toBeGreaterThan(0);
        for (const cols of tcp4Listeners) expect(cols[1]).toBe(`0100007F:${hexPort}`);

        const tcp6Listeners = fs.readFileSync("/proc/net/tcp6", "utf8").split("\n").slice(1)
          .map((line) => line.trim().split(/\s+/))
          .filter((cols) => cols[1]?.endsWith(`:${hexPort}`) && cols[3] === "0A");
        expect(tcp6Listeners).toHaveLength(0);
      }
    } finally {
      await relay.close();
    }
  });

  test("skips a port already bound and still binds the others, resolving the call", async () => {
    const blocker = net.createServer();
    await new Promise<void>((resolve) => blocker.listen(0, "127.0.0.1", resolve));
    const blockedPort = (blocker.address() as net.AddressInfo).port;
    const openPort = await unusedPort();
    const relay = await relayModule.startRelay({
      services: [{ name: "blocked", port: blockedPort }, { name: "open", port: openPort }],
      proxyHost: "127.0.0.1",
      proxyPort: 9,
    });
    try {
      expect(relay.skipped).toHaveLength(1);
      expect(relay.skipped[0].name).toBe("blocked");
      expect(relay.skipped[0].port).toBe(blockedPort);
      expect(relay.skipped[0].reason).toMatch(/EADDRINUSE/);
      expect(relay.bound).toEqual([{ name: "open", port: openPort }]);
    } finally {
      await relay.close();
      await new Promise<void>((resolve) => blocker.close(() => resolve()));
    }
  });
});

describe("terminal signals (as a real process)", () => {
  test("SIGINT, SIGQUIT and SIGHUP are ignored; SIGTERM still ends it", async () => {
    const port = await unusedPort();
    const child = childProcess.spawn("node", [RELAY_SOURCE], {
      env: { PATH: process.env.PATH ?? "", PROXY_IP: "127.0.0.1", RUNFREE_HOST_SERVICES: `svc:${port}` },
      stdio: ["ignore", "ignore", "ignore"],
    });
    try {
      expect(await waitFor(port, true, 2_000), "the relay never started listening").toBe(true);

      for (const signal of ["SIGINT", "SIGQUIT", "SIGHUP"] as const) {
        child.kill(signal);
        // No handler-driven state change to poll for a no-op: give the signal
        // a moment to have been delivered and (not) acted on, then confirm
        // the port is still answered.
        await new Promise((resolve) => setTimeout(resolve, 150));
        expect(await isListening(port), `relay did not survive ${signal}`).toBe(true);
      }

      child.kill("SIGTERM");
      expect(await waitFor(port, false, 2_000), "relay did not exit on SIGTERM").toBe(true);
    } finally {
      child.kill("SIGKILL");
    }
  });
});

describe("main() as a child process (bad environment)", () => {
  function runRelayBinary(env: NodeJS.ProcessEnv): childProcess.SpawnSyncReturns<string> {
    return childProcess.spawnSync("node", [RELAY_SOURCE], {
      encoding: "utf8",
      env: { PATH: process.env.PATH ?? "", ...env },
      timeout: 5_000,
    });
  }

  test("exits 0 with a stderr warning and binds nothing when PROXY_IP is missing", async () => {
    const port = await unusedPort();
    const result = runRelayBinary({ RUNFREE_HOST_SERVICES: `svc:${port}` });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toContain("PROXY_IP must be an IPv4 literal");
    // The process has already exited (spawnSync) and this path never reaches
    // startRelay, so the port must still refuse connections.
    expect(await isListening(port)).toBe(false);
  });

  test("exits 0 with a stderr warning and binds nothing when RUNFREE_HOST_SERVICES is malformed", async () => {
    const port = await unusedPort();
    const result = runRelayBinary({ PROXY_IP: "127.0.0.1", RUNFREE_HOST_SERVICES: "not a valid list" });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toContain("invalid RUNFREE_HOST_SERVICES");
    expect(await isListening(port)).toBe(false);
  });

  test("exits 0 and does nothing when RUNFREE_HOST_SERVICES is unset", () => {
    const result = runRelayBinary({ PROXY_IP: "127.0.0.1" });
    expect(result.status, result.stderr).toBe(0);
  });
});
