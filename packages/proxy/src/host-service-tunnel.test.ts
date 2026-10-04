import net from "node:net";
import { afterEach, describe, expect, test, vi } from "vitest";

import type { HostServiceGatewayStatus } from "@runfree/runtime-contracts/proxy-status";
import { createHostServiceTunnels, type HostServiceAdmitInput } from "./host-service-tunnel.ts";

const GENERATION = "sha256:gen";
const gateway: HostServiceGatewayStatus = {
  schemaVersion: 1,
  policyGeneration: GENERATION,
  gatewayIp: "127.0.0.1",
  writtenAt: "2026-10-04T00:00:00.000Z",
};

const cleanups: Array<() => void> = [];
afterEach(() => {
  for (const cleanup of cleanups.splice(0)) cleanup();
});

// A connected loopback pair: `server` plays the agent's client socket as the
// proxy sees it; `peer` is the agent end.
async function socketPair(): Promise<{ server: net.Socket; peer: net.Socket; received: () => string }> {
  const listener = net.createServer();
  await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", () => resolve()));
  const { port } = listener.address() as net.AddressInfo;
  const accepted = new Promise<net.Socket>((resolve) => listener.once("connection", resolve));
  const peer = net.connect({ host: "127.0.0.1", port });
  peer.on("error", () => {});
  let received = "";
  peer.on("data", (chunk: Buffer) => {
    received += chunk.toString("latin1");
  });
  const server = await accepted;
  server.on("error", () => {});
  cleanups.push(() => {
    peer.destroy();
    server.destroy();
    listener.close();
  });
  return { server, peer, received: () => received };
}

function admitInput(client: net.Socket, overrides: Partial<HostServiceAdmitInput> = {}): HostServiceAdmitInput & {
  rejections: Array<{ reason: string; denial: string }>;
} {
  const rejections: Array<{ reason: string; denial: string }> = [];
  return {
    clientSocket: client,
    sessionKey: "session-a",
    name: "echo",
    port: 9,
    policyGeneration: GENERATION,
    remainder: Buffer.alloc(0),
    reject: (reason, denial) => {
      rejections.push({ reason, denial });
    },
    rejections,
    ...overrides,
  };
}

// An upstream socket that never connects, standing in for a gateway port
// that silently drops SYNs.
function neverConnecting(): typeof net.connect & { calls: () => number } {
  let calls = 0;
  const connect = (() => {
    calls += 1;
    const socket = new net.Socket();
    cleanups.push(() => socket.destroy());
    return socket;
  }) as unknown as typeof net.connect & { calls: () => number };
  connect.calls = () => calls;
  return connect;
}

describe("host-service tunnels", () => {
  test("a dial timeout refuses unavailable and never writes a 200", async () => {
    const tunnels = createHostServiceTunnels({
      readGateway: () => gateway,
      maxPerSession: 4,
      maxGlobal: 4,
      maxPendingDials: 4,
      dialTimeoutMs: 50,
      connect: neverConnecting(),
    });
    const pair = await socketPair();
    const input = admitInput(pair.server);
    tunnels.admit(input);
    expect(tunnels.spliceCounts()).toEqual({ echo: 1 });
    await vi.waitFor(() => expect(input.rejections).toHaveLength(1), { timeout: 2_000 });
    expect(input.rejections[0].denial).toBe("host-service-unavailable");
    expect(pair.received()).not.toContain("200");
    // The refused dial frees its pending and per-session slots.
    expect(tunnels.spliceCounts()).toEqual({});
  });

  test("the pending-dial cap refuses before dialling and frees when the dial ends", async () => {
    const connect = neverConnecting();
    const tunnels = createHostServiceTunnels({
      readGateway: () => gateway,
      maxPerSession: 4,
      maxGlobal: 4,
      maxPendingDials: 1,
      dialTimeoutMs: 60_000,
      connect,
    });
    const first = await socketPair();
    tunnels.admit(admitInput(first.server));
    const second = await socketPair();
    const secondInput = admitInput(second.server);
    tunnels.admit(secondInput);
    expect(secondInput.rejections).toEqual([{
      reason: expect.stringContaining("pending") as string,
      denial: "host-service-capacity",
    }]);
    expect(connect.calls()).toBe(1);

    // Reclaim: the agent abandons the first dial.
    first.server.destroy();
    await vi.waitFor(() => expect(tunnels.spliceCounts()).toEqual({}));
    const third = await socketPair();
    const thirdInput = admitInput(third.server);
    tunnels.admit(thirdInput);
    expect(thirdInput.rejections).toEqual([]);
    expect(connect.calls()).toBe(2);
  });

  test("the global cap refuses across sessions", async () => {
    const tunnels = createHostServiceTunnels({
      readGateway: () => gateway,
      maxPerSession: 4,
      maxGlobal: 1,
      maxPendingDials: 4,
      dialTimeoutMs: 60_000,
      connect: neverConnecting(),
    });
    tunnels.admit(admitInput((await socketPair()).server, { sessionKey: "session-a" }));
    const other = admitInput((await socketPair()).server, { sessionKey: "session-b" });
    tunnels.admit(other);
    expect(other.rejections.map((entry) => entry.denial)).toEqual(["host-service-capacity"]);
  });

  test.each([
    ["no gateway status", undefined],
    ["another policy generation", { ...gateway, policyGeneration: "sha256:other" }],
    ["an unavailable gateway", { schemaVersion: 1 as const, policyGeneration: GENERATION, unavailableReason: "suspect", writtenAt: gateway.writtenAt }],
  ])("refuses unavailable with %s and never dials", async (_label, status) => {
    const connect = neverConnecting();
    const tunnels = createHostServiceTunnels({
      readGateway: () => status,
      maxPerSession: 4,
      maxGlobal: 4,
      maxPendingDials: 4,
      dialTimeoutMs: 60_000,
      connect,
    });
    const input = admitInput((await socketPair()).server);
    tunnels.admit(input);
    expect(input.rejections.map((entry) => entry.denial)).toEqual(["host-service-unavailable"]);
    expect(connect.calls()).toBe(0);
  });

  test("cutRemoved cuts removed names and changed ports, keeps unchanged pairs, and cutAll cuts the rest", async () => {
    const tunnels = createHostServiceTunnels({
      readGateway: () => gateway,
      maxPerSession: 8,
      maxGlobal: 8,
      maxPendingDials: 8,
      dialTimeoutMs: 60_000,
      connect: neverConnecting(),
    });
    const removed = await socketPair();
    const moved = await socketPair();
    const kept = await socketPair();
    tunnels.admit(admitInput(removed.server, { name: "gone", port: 1001 }));
    tunnels.admit(admitInput(moved.server, { name: "moved", port: 1002 }));
    tunnels.admit(admitInput(kept.server, { name: "kept", port: 1003 }));

    const cut = tunnels.cutRemoved({
      moved: { target: "host-loopback", port: 2002 },
      kept: { target: "host-loopback", port: 1003 },
    });
    expect(cut).toBe(2);
    expect(removed.server.destroyed).toBe(true);
    expect(moved.server.destroyed).toBe(true);
    expect(kept.server.destroyed).toBe(false);
    expect(tunnels.spliceCounts()).toEqual({ kept: 1 });

    expect(tunnels.cutAll()).toBe(1);
    expect(kept.server.destroyed).toBe(true);
    expect(tunnels.spliceCounts()).toEqual({});
  });
});
