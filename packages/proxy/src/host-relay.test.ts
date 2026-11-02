import net from "node:net";

import { afterEach, describe, expect, test, vi } from "vitest";

import {
  createHostRelay,
  listenExactly,
  normalizePeerAddress,
  procWildcardListener,
  resolveHostRelayConfig,
  type HostRelay,
  type HostRelayDeps,
} from "./host-relay.ts";

const cleanups: Array<() => Promise<void> | void> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

/**
 * `count` distinct free ports: every probe listener is held until all are
 * bound, so two ports can never be the same one handed out twice.
 */
async function freePorts(count: number, host = "127.0.0.1"): Promise<number[]> {
  const servers: net.Server[] = [];
  try {
    for (let index = 0; index < count; index += 1) {
      const server = net.createServer();
      await new Promise<void>((resolve) => server.listen({ host, port: 0 }, resolve));
      servers.push(server);
    }
    return servers.map((server) => (server.address() as net.AddressInfo).port);
  } finally {
    await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  }
}

async function freePort(host = "127.0.0.1"): Promise<number> {
  return (await freePorts(1, host))[0] as number;
}

/**
 * Reconciles the relay onto `count` fresh ports and returns them once every
 * one is listening. A released probe port can be taken by another process
 * before the relay binds it, so a lost race retries on new ports (bounded)
 * instead of failing the test on someone else's socket.
 */
async function reconcileOnFreshPorts(h: Harness, count: number): Promise<number[]> {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const ports = await freePorts(count);
    h.listens.length = 0;
    await h.relay.reconcile(ports);
    if (ports.every((port) => h.relay.state().get(port) === "listening")) return ports;
    await h.relay.reconcile([]);
  }
  throw new Error("no free ports could be bound after 5 attempts");
}

/**
 * A client whose connection the relay must reject: it resolves as closed on
 * a clean close or on a reset (both are a rejection), and reports what it
 * read. Any other error fails the test.
 */
function rejectedRoundTrip(port: number, payload: string): Promise<{ data: string; closed: boolean }> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    let data = "";
    socket.on("data", (chunk) => {
      data += chunk.toString("utf8");
    });
    socket.on("close", () => resolve({ data, closed: true }));
    socket.on("error", (error: NodeJS.ErrnoException) => {
      if (error.code === "ECONNRESET" || error.code === "EPIPE") return;
      reject(error);
    });
    socket.on("connect", () => socket.write(payload));
  });
}

/** An echo server standing in for the host service behind the relay. */
async function echoServer(): Promise<{ port: number; accepted: () => number }> {
  let accepted = 0;
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    accepted += 1;
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.pipe(socket);
  });
  await new Promise<void>((resolve) => server.listen({ host: "127.0.0.1", port: 0 }, resolve));
  cleanups.push(() => new Promise<void>((resolve) => {
    for (const socket of sockets) socket.destroy();
    server.close(() => resolve());
  }));
  return { port: (server.address() as net.AddressInfo).port, accepted: () => accepted };
}

type Harness = { relay: HostRelay; deps: HostRelayDeps; listens: Array<{ host: string; port: number }>; dials: number[]; logs: string[] };

function harness(
  config: { gateway: string; allowedSource: string },
  upstreamPort: number,
  overrides: Partial<HostRelayDeps> = {},
): Harness {
  const listens: Array<{ host: string; port: number }> = [];
  const dials: number[] = [];
  const logs: string[] = [];
  const deps: HostRelayDeps = {
    listen: (host, port, onConnection) => {
      listens.push({ host, port });
      return listenExactly(host, port, onConnection);
    },
    connectUpstream: (port) => {
      dials.push(port);
      return net.connect({ host: "127.0.0.1", port: upstreamPort });
    },
    wildcardListener: () => false,
    log: (line) => logs.push(line),
    ...overrides,
  };
  const relay = createHostRelay(config, deps);
  cleanups.push(() => relay.close());
  return { relay, deps, listens, dials, logs };
}

function roundTrip(port: number, payload: string): Promise<{ data: string; closed: boolean }> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    let data = "";
    socket.on("data", (chunk) => {
      data += chunk.toString("utf8");
      if (data.length >= payload.length) {
        socket.destroy();
        resolve({ data, closed: false });
      }
    });
    socket.on("close", () => resolve({ data, closed: true }));
    socket.on("error", reject);
    socket.on("connect", () => socket.write(payload));
  });
}

function waitForClose(socket: net.Socket): Promise<void> {
  return new Promise((resolve) => {
    if (socket.destroyed) resolve();
    else socket.once("close", () => resolve());
  });
}

describe("host relay source check (C3)", () => {
  test("a connection from the proxy egress IP is spliced to the host service", async () => {
    const upstream = await echoServer();
    const h = harness({ gateway: "127.0.0.1", allowedSource: "127.0.0.1" }, upstream.port);
    const { relay, dials } = h;
    const [port] = await reconcileOnFreshPorts(h, 1) as [number];
    expect(relay.state().get(port)).toBe("listening");

    await expect(roundTrip(port, "ping-through-relay")).resolves.toEqual({ data: "ping-through-relay", closed: false });
    expect(dials).toEqual([port]);
    expect(upstream.accepted()).toBe(1);
  });

  test("any other source is closed before a byte is read and with no upstream dial", async () => {
    const upstream = await echoServer();
    // The test client connects from 127.0.0.1; the relay admits only 127.0.0.9.
    const h = harness({ gateway: "127.0.0.1", allowedSource: "127.0.0.9" }, upstream.port);
    const { relay, dials, logs } = h;
    const [port] = await reconcileOnFreshPorts(h, 1) as [number];

    // A clean close and a reset are both a rejection; what matters is that
    // nothing came back and nothing was dialed upstream.
    await expect(rejectedRoundTrip(port, "must-not-arrive")).resolves.toEqual({ data: "", closed: true });
    expect(dials).toEqual([]);
    expect(upstream.accepted()).toBe(0);
    expect(relay.connections(port)).toBe(0);
    expect(logs.some((line) => line.includes("refused a connection from 127.0.0.1"))).toBe(true);
  });

  test("an IPv4-mapped peer is compared as the IPv4 address it carries", () => {
    expect(normalizePeerAddress("::ffff:172.30.1.10")).toBe("172.30.1.10");
    expect(normalizePeerAddress("172.30.1.10")).toBe("172.30.1.10");
    expect(normalizePeerAddress("::1")).toBe("::1");
    expect(normalizePeerAddress(undefined)).toBeUndefined();
  });
});

describe("host relay listeners (C4)", () => {
  test("binds exactly <gateway>:P for each effective port and nothing else", async () => {
    const upstream = await echoServer();
    const h = harness({ gateway: "127.0.0.1", allowedSource: "127.0.0.1" }, upstream.port);
    const { relay, listens } = h;
    const [first, second] = await reconcileOnFreshPorts(h, 2) as [number, number];
    expect(listens.filter((entry) => entry.port === first || entry.port === second).map((entry) => entry.host))
      .toEqual(["127.0.0.1", "127.0.0.1"]);
    // Out-of-range entries are never listened on, whatever else is in the set.
    // The ports stay held throughout, so no released port can be lost to a race.
    listens.length = 0;
    await relay.reconcile([second, first, 0, 70000]);

    expect(listens).toEqual([]);
    expect([...relay.state().keys()].sort()).toEqual([first, second].sort());
  });

  test("the real listener's bound address is the gateway, never a wildcard", async () => {
    // Port 0: the kernel picks a free port, so no released probe port can be lost.
    const server = await listenExactly("127.0.0.1", 0, (socket) => socket.destroy());
    cleanups.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
    expect(server.address()).toMatchObject({ address: "127.0.0.1", family: "IPv4" });
    expect((server.address() as net.AddressInfo).port).toBeGreaterThan(0);
  });

  test("removing a service closes its listener but leaves established connections to the proxy's cuts", async () => {
    const upstream = await echoServer();
    const h = harness({ gateway: "127.0.0.1", allowedSource: "127.0.0.1" }, upstream.port);
    const { relay, logs } = h;
    const [port] = await reconcileOnFreshPorts(h, 1) as [number];

    const client = net.connect({ host: "127.0.0.1", port });
    cleanups.push(() => {
      client.destroy();
    });
    await new Promise<void>((resolve) => client.once("data", () => resolve()).on("connect", () => client.write("x")));
    expect(relay.connections(port)).toBe(1);

    await relay.reconcile([]);
    expect(relay.state().has(port)).toBe(false);
    // No third cut: the established splice still carries bytes both ways.
    // Revocation is the request-proxy cut and the firewall cut, as on Desktop.
    const echoed = await new Promise<string>((resolve, reject) => {
      client.once("data", (chunk) => resolve(chunk.toString("utf8")));
      client.once("close", () => reject(new Error("the relay closed an established connection")));
      client.write("after-removal");
    });
    expect(echoed).toBe("after-removal");
    expect(upstream.accepted()).toBe(1);
    // A re-add binds again at once, without waiting for that connection to end.
    await relay.reconcile([port]);
    expect(relay.state().get(port)).toBe("listening");
    await expect(roundTrip(port, "re-added")).resolves.toEqual({ data: "re-added", closed: false });
    await relay.reconcile([]);
    // Its end is still the peers' to decide, and closes the upstream leg too.
    client.destroy();
    await waitForClose(client);
    expect(logs).toContain(`host-relay: 127.0.0.1:${port} closed`);
    await expect(new Promise((resolve, reject) => {
      const probe = net.connect({ host: "127.0.0.1", port });
      probe.on("connect", () => {
        probe.destroy();
        resolve("connected");
      });
      probe.on("error", (error: NodeJS.ErrnoException) => reject(error));
    })).rejects.toMatchObject({ code: "ECONNREFUSED" });
  });

  test("EADDRINUSE against a wildcard listener is served directly, then relayed once the wildcard is gone", async () => {
    let wildcard = true;
    const inUse = Object.assign(new Error("listen EADDRINUSE"), { code: "EADDRINUSE" });
    const listen = vi.fn<HostRelayDeps["listen"]>(async (host, port, onConnection) => {
      if (wildcard) throw inUse;
      return listenExactly(host, port, onConnection);
    });
    const upstream = await echoServer();
    // The released probe port can be taken before the relay binds it once the
    // wildcard is gone, so a lost race retries on a new port (bounded).
    for (let attempt = 0; attempt < 5; attempt += 1) {
      wildcard = true;
      const port = await freePort();
      const { relay, logs } = harness({ gateway: "127.0.0.1", allowedSource: "127.0.0.1" }, upstream.port, {
        listen,
        wildcardListener: () => wildcard,
      });

      await expect(relay.reconcile([port])).resolves.toBeUndefined();
      expect(relay.state().get(port)).toBe("served-directly");
      expect(logs.filter((line) => line.includes("served directly"))).toHaveLength(1);
      await relay.reconcile([port]);
      expect(logs.filter((line) => line.includes("served directly"))).toHaveLength(1);

      wildcard = false;
      await relay.reconcile([port]);
      if (relay.state().get(port) !== "listening") {
        await relay.close();
        continue;
      }
      await expect(roundTrip(port, "after-wildcard")).resolves.toMatchObject({ data: "after-wildcard" });
      return;
    }
    throw new Error("no free port could be bound after 5 attempts");
  });

  test("EADDRINUSE with no wildcard owner is a bind failure that keeps retrying", async () => {
    const inUse = Object.assign(new Error("listen EADDRINUSE"), { code: "EADDRINUSE" });
    const listen = vi.fn<HostRelayDeps["listen"]>(async () => {
      throw inUse;
    });
    const { relay, logs } = harness({ gateway: "127.0.0.1", allowedSource: "127.0.0.1" }, 1, { listen });
    await relay.reconcile([4242]);
    await relay.reconcile([4242]);
    expect(relay.state().get(4242)).toBe("bind-failed");
    expect(listen).toHaveBeenCalledTimes(2);
    expect(logs.filter((line) => line.includes("could not listen (EADDRINUSE)"))).toHaveLength(1);
  });

  test.skipIf(process.platform !== "linux")("on Linux a real 0.0.0.0:P listener makes <gateway>:P served directly", async () => {
    const wildcardServer = net.createServer((socket) => socket.end("direct"));
    await new Promise<void>((resolve) => wildcardServer.listen({ host: "0.0.0.0", port: 0 }, resolve));
    cleanups.push(() => new Promise<void>((resolve) => wildcardServer.close(() => resolve())));
    const port = (wildcardServer.address() as net.AddressInfo).port;
    const { relay } = harness({ gateway: "127.0.0.1", allowedSource: "127.0.0.1" }, 1, {
      wildcardListener: (candidate) => procWildcardListener(candidate),
    });
    await relay.reconcile([port]);
    expect(relay.state().get(port)).toBe("served-directly");
  });
});

const TCP_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
const TCP6_HEADER = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
const tcpRow = (local: string, state = "0A"): string =>
  `   0: ${local} 00000000:0000 ${state} 00000000:00000000 00:00000000 00000000 1000 0 99 1 0000000000000000 100 0 0 10 0`;
// An IPv6 row: its remote address is IPv6-width too, as the kernel prints it.
const tcp6Row = (local: string, state = "0A"): string =>
  `   0: ${local} 00000000000000000000000000000000:0000 ${state} 00000000:00000000 00:00000000 00000000 1000 0 99 1 0000000000000000 100 0 0 10 0`;

describe("procWildcardListener", () => {
  const reader = (tables: Record<string, string>) => (path: string): string => {
    const table = tables[path];
    if (table === undefined) throw new Error(`ENOENT ${path}`);
    return table;
  };

  test("an IPv4 or IPv6 wildcard LISTEN socket on the port counts", () => {
    expect(procWildcardListener(0x2a82, reader({
      "/proc/net/tcp": `${TCP_HEADER}\n${tcpRow("00000000:2A82")}\n`,
      "/proc/net/tcp6": `${TCP6_HEADER}\n`,
    }))).toBe(true);
    expect(procWildcardListener(0x2a82, reader({
      "/proc/net/tcp": `${TCP_HEADER}\n`,
      "/proc/net/tcp6": `${TCP6_HEADER}\n${tcp6Row("00000000000000000000000000000000:2A82")}\n`,
    }))).toBe(true);
  });

  test("a loopback listener, another port, or a non-LISTEN row does not count", () => {
    expect(procWildcardListener(0x2a82, reader({
      "/proc/net/tcp": `${TCP_HEADER}\n${tcpRow("0100007F:2A82")}\n${tcpRow("00000000:2A83")}\n${tcpRow("00000000:2A82", "01")}\n`,
      "/proc/net/tcp6": `${TCP6_HEADER}\n`,
    }))).toBe(false);
  });

  test("an unreadable or malformed table answers false, never served", () => {
    expect(procWildcardListener(0x2a82, reader({}))).toBe(false);
    expect(procWildcardListener(0x2a82, reader({ "/proc/net/tcp": "garbage", "/proc/net/tcp6": `${TCP6_HEADER}\n` }))).toBe(false);
  });
});

describe("resolveHostRelayConfig (C4 gateway checks)", () => {
  const env = {
    RUNFREE_PROXY_EGRESS_IP: "172.30.1.10",
    RUNFREE_PROXY_EGRESS_GATEWAY: "172.30.1.1",
    RUNFREE_PROXY_IP: "172.30.0.10",
    RUNFREE_SUBNET: "172.30.0.0/24",
    RUNFREE_PROXY_EGRESS_SUBNET: "172.30.1.0/24",
  };
  const rootFile = { uid: 0, mode: 0o100644, isFile: true };
  const hosts = (ip: string): string => `127.0.0.1\tlocalhost\n${ip}\tgateway.runfree.internal\n`;

  test("the daemon's docker0 gateway is accepted with the proxy egress IP as the only source", () => {
    expect(resolveHostRelayConfig({ etcHosts: hosts("172.17.0.1"), etcHostsStat: rootFile, env })).toEqual({
      gateway: "172.17.0.1",
      allowedSource: "172.30.1.10",
    });
  });

  test.each([
    ["127.0.0.1", "loopback"],
    ["169.254.1.1", "link-local"],
    ["8.8.8.8", "RFC 1918"],
    ["172.30.1.1", "proxy egress gateway"],
    ["172.30.1.10", "proxy address"],
    ["172.30.0.10", "proxy address"],
    ["172.30.0.99", "runtime subnet"],
    ["172.017.0.1", "malformed"],
  ])("a gateway %s is refused (%s), as validateHostServiceGateway refuses it", (ip, reason) => {
    const resolved = resolveHostRelayConfig({ etcHosts: hosts(ip), etcHostsStat: rootFile, env });
    expect(resolved).toMatchObject({ error: expect.stringContaining(reason) });
  });

  test("an /etc/hosts the supervisor would not trust is refused", () => {
    expect(resolveHostRelayConfig({ etcHosts: hosts("172.17.0.1"), etcHostsStat: { ...rootFile, uid: 1000 }, env }))
      .toMatchObject({ error: expect.stringContaining("uid 0") });
    expect(resolveHostRelayConfig({ etcHosts: hosts("172.17.0.1"), etcHostsStat: { ...rootFile, mode: 0o100666 }, env }))
      .toMatchObject({ error: expect.stringContaining("writable") });
    expect(resolveHostRelayConfig({ etcHosts: "127.0.0.1 localhost\n", etcHostsStat: rootFile, env }))
      .toMatchObject({ error: expect.stringContaining("missing") });
    expect(resolveHostRelayConfig({
      etcHosts: `${hosts("172.17.0.1")}172.18.0.1 gateway.runfree.internal\n`,
      etcHostsStat: rootFile,
      env,
    })).toMatchObject({ error: expect.stringContaining("more than one") });
  });

  test("a missing or malformed runtime address refuses rather than guessing", () => {
    for (const [name, value] of [
      ["RUNFREE_PROXY_EGRESS_IP", undefined],
      ["RUNFREE_PROXY_EGRESS_IP", "172.30.1"],
      ["RUNFREE_SUBNET", "172.30.0.0"],
      ["RUNFREE_PROXY_IP", "not-an-ip"],
    ] as const) {
      expect(resolveHostRelayConfig({ etcHosts: hosts("172.17.0.1"), etcHostsStat: rootFile, env: { ...env, [name]: value } }))
        .toMatchObject({ error: expect.stringContaining(name) });
    }
  });
});
