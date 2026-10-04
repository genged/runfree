import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { describe, expect, test } from "vitest";

import { refusedHostServicePortReason } from "@runfree/runtime-contracts/host-services";
import { validateNetworkPolicy } from "@runfree/runtime-contracts/network-policy";
import {
  harnessSessionFile,
  openConnectTunnel,
  parseHttpResponse,
  rawConnectViaProxy,
  readUntil,
  replaceJson,
  startProxy,
  tmp,
  waitUntil,
  writeHarnessSessionFiles,
  type RunningProxy,
} from "./server.test-harness.ts";

type EchoServer = {
  port: number;
  connections: () => number;
  received: () => string;
  openSockets: () => net.Socket[];
  stop: () => Promise<void>;
};

async function listenOnce(): Promise<net.Server> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  return server;
}

// A local TCP echo server standing in for the host service behind the
// gateway. The kernel may hand out a port the policy refuses (the MCP
// callback block sits inside the Linux ephemeral range), so re-listen until
// the port is one the policy accepts.
async function startEchoServer(): Promise<EchoServer> {
  let server = await listenOnce();
  for (;;) {
    const address = server.address();
    if (address && typeof address !== "string" && refusedHostServicePortReason(address.port) === undefined) break;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    server = await listenOnce();
  }
  const address = server.address() as net.AddressInfo;
  let connections = 0;
  let received = "";
  const sockets = new Set<net.Socket>();
  server.on("connection", (socket) => {
    connections += 1;
    sockets.add(socket);
    socket.on("data", (chunk: Buffer) => {
      received += chunk.toString("latin1");
      socket.write(chunk);
    });
    socket.on("error", () => {});
    socket.once("close", () => sockets.delete(socket));
  });
  return {
    port: address.port,
    connections: () => connections,
    received: () => received,
    openSockets: () => Array.from(sockets),
    stop: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

function hostServicePolicy(services: Record<string, number>): Record<string, unknown> {
  return {
    hosts: [],
    tokens: {},
    hostServices: Object.fromEntries(Object.entries(services).map(([name, port]) => [name, { target: "host-loopback", port }])),
  };
}

function policyGenerationOf(policy: unknown): string {
  return validateNetworkPolicy(policy).generation;
}

type GatewayFile = { dir: string; path: string };

function gatewayFile(): GatewayFile {
  const dir = fs.mkdtempSync(path.join(tmp, "host-service-gateway-"));
  return { dir, path: path.join(dir, "host-service-gateway.json") };
}

function writeGateway(file: GatewayFile, contents: Record<string, unknown>): void {
  const tmpPath = `${file.path}.tmp`;
  fs.writeFileSync(tmpPath, `${JSON.stringify(contents)}\n`, { mode: 0o644 });
  fs.renameSync(tmpPath, file.path);
}

function availableGateway(policyGeneration: string): Record<string, unknown> {
  return {
    schemaVersion: 1,
    policyGeneration,
    gatewayIp: "127.0.0.1",
    writtenAt: new Date().toISOString(),
  };
}

async function startHostServiceProxy(options: {
  policy: Record<string, unknown>;
  gateway?: Record<string, unknown> | "missing";
  extraEnv?: NodeJS.ProcessEnv;
}): Promise<{ proxy: RunningProxy; gateway: GatewayFile }> {
  const gateway = gatewayFile();
  const contents = options.gateway ?? availableGateway(policyGenerationOf(options.policy));
  if (contents !== "missing") writeGateway(gateway, contents);
  const proxy = await startProxy({
    extraEnv: {
      PROXY_HOST_SERVICE_GATEWAY_PATH: gateway.path,
      PROXY_STATUS_DEBUG: "1",
      ...options.extraEnv,
    },
    policy: options.policy,
  });
  return { proxy, gateway };
}

// CONNECT head plus `early` payload in one write; resolves with the full bytes
// read until `until` appears (the response head, plus any echoed bytes).
async function connectWithEarlyBytes(proxyPort: number, authority: string, early: string, until: string): Promise<{
  socket: net.Socket;
  raw: string;
}> {
  const socket = net.connect({ host: "127.0.0.1", port: proxyPort });
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", () => resolve());
    socket.once("error", reject);
  });
  socket.on("error", () => {});
  socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n${early}`);
  const raw = await readUntil(socket, until);
  return { socket, raw: raw.toString("latin1") };
}

function statusDebugLines(output: string): Array<{ index: number; status: Record<string, unknown> }> {
  const prefix = "proxy-debug: request-proxy status ";
  const lines: Array<{ index: number; status: Record<string, unknown> }> = [];
  let offset = 0;
  for (const line of output.split("\n")) {
    if (line.startsWith(prefix)) {
      lines.push({ index: offset, status: JSON.parse(line.slice(prefix.length)) as Record<string, unknown> });
    }
    offset += line.length + 1;
  }
  return lines;
}

async function expectNoDialFor(echo: EchoServer, settleMs = 150): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, settleMs));
  expect(echo.connections()).toBe(0);
}

describe("proxy server: host-service CONNECT splice", () => {
  test("an approved pair splices to the gateway, forwards early bytes, and echoes", async () => {
    const echo = await startEchoServer();
    const { proxy } = await startHostServiceProxy({ policy: hostServicePolicy({ echo: echo.port }) });

    const { socket, raw } = await connectWithEarlyBytes(proxy.port, `echo.runfree.internal:${echo.port}`, "early-bytes", "early-bytes");
    expect(raw.startsWith("HTTP/1.1 200 Connection Established\r\n\r\n")).toBe(true);
    expect(echo.received()).toBe("early-bytes");

    socket.write("ping-after-200");
    await readUntil(socket, "ping-after-200");
    expect(echo.connections()).toBe(1);
    socket.destroy();
    await echo.stop();
  }, 20_000);

  test.each([
    ["a wrong port for a known name", (port: number) => `echo.runfree.internal:${port === 65535 ? port - 1 : port + 1}`],
    ["an unknown name", (port: number) => `other.runfree.internal:${port}`],
  ])("%s gets a raw not-configured 403 with an agent-labelled remedy and no dial", async (_label, authorityFor) => {
    const echo = await startEchoServer();
    const { proxy } = await startHostServiceProxy({ policy: hostServicePolicy({ echo: echo.port }) });
    const authority = authorityFor(echo.port);
    const [name, port] = authority.replace(".runfree.internal", "").split(":");

    const response = await rawConnectViaProxy({ proxyPort: proxy.port, authority });
    expect(response.statusCode).toBe(403);
    expect(response.body).toContain("host-service-not-configured");
    expect(response.body).toContain("this host service is not approved for the project");
    expect(response.body).toContain(`requested by the agent; to approve: runfree host-service add ${name} --port ${port}`);
    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"host-service-not-configured"/);
    await expectNoDialFor(echo);
    await echo.stop();
  }, 20_000);

  test.each([
    ["the bare suffix", () => "runfree.internal:1"],
    ["a trailing dot", (port: number) => `echo.runfree.internal.:${port}`],
    ["an upper-case name", (port: number) => `ECHO.runfree.internal:${port}`],
    ["no port", () => "echo.runfree.internal"],
    ["a bracketed approved pair", (port: number) => `[echo.runfree.internal]:${port}`],
    ["a trailing colon", () => "x.runfree.internal:443:"],
    ["a reserved name inside another authority", () => "x.runfree.internal.example.com:443"],
  ])("a malformed reserved authority (%s) gets a raw 403 without a remedy and no dial", async (_label, authorityFor) => {
    const echo = await startEchoServer();
    const { proxy } = await startHostServiceProxy({ policy: hostServicePolicy({ echo: echo.port }) });

    const response = await rawConnectViaProxy({ proxyPort: proxy.port, authority: authorityFor(echo.port) });
    expect(response.statusCode).toBe(403);
    expect(response.body).toContain("host-service-not-configured");
    expect(response.body).not.toContain("runfree host-service add");
    expect(response.body).not.toContain("requested by the agent");
    await expectNoDialFor(echo);
    await echo.stop();
  }, 20_000);

  test.each([
    ["x.runfree.internal:443", "without", false],
    ["x.runfree.internal:443", "with", true],
    ["[x.runfree.internal]:443", "without", false],
    ["[x.runfree.internal]:443", "with", true],
  ])("%s %s an active audit marker gets a raw 403, no spool write, and no audit pass", async (authority, _label, auditActive) => {
    const auditDir = fs.mkdtempSync(path.join(tmp, "audit-state-"));
    const markerPath = path.join(auditDir, "active.json");
    const spoolPath = path.join(auditDir, "spool.txt");
    if (auditActive) {
      const now = new Date();
      fs.writeFileSync(markerPath, `${JSON.stringify({
        v: 1,
        enabledAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + 600_000).toISOString(),
        sessionHint: "server-test",
      })}\n`);
    }
    const echo = await startEchoServer();
    const { proxy } = await startHostServiceProxy({
      policy: hostServicePolicy({ echo: echo.port }),
      extraEnv: {
        PROXY_AUDIT_MARKER_PATH: markerPath,
        PROXY_AUDIT_SPOOL_PATH: spoolPath,
        PROXY_AUDIT_RESOLVED_HOSTS_PATH: path.join(auditDir, "audit-resolved-hosts.json"),
        PROXY_AUDIT_WATCH_MS: "100",
      },
    });
    if (auditActive) await proxy.waitForOutput("proxy-audit: network audit mode ACTIVE");

    const response = await rawConnectViaProxy({ proxyPort: proxy.port, authority });
    expect(response.statusCode).toBe(403);
    expect(response.raw).not.toContain("200 Connection Established");
    expect(response.body).toContain("host-service-not-configured");
    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"host-service-not-configured"/);
    await new Promise((resolve) => setTimeout(resolve, 150));
    const spool = fs.existsSync(spoolPath) ? fs.readFileSync(spoolPath, "utf8") : "";
    expect(spool).not.toContain("runfree.internal");
    expect(proxy.output()).not.toMatch(/proxy-audit: \{[^\n]*runfree\.internal/);
    await echo.stop();
  }, 20_000);

  test.each([
    ["the gateway file is missing", (_generation: string) => "missing" as const],
    ["the gateway file names another policy generation", (_generation: string) => availableGateway(`sha256:${"9".repeat(64)}`)],
    ["the gateway file reports unavailable", (generation: string) => ({
      schemaVersion: 1,
      policyGeneration: generation,
      unavailableReason: "gateway address changed",
      writtenAt: new Date().toISOString(),
    })],
    ["the gateway file is malformed", (generation: string) => ({ ...availableGateway(generation), extra: true })],
  ])("refuses unavailable when %s, then recovers on a valid file", async (_label, gatewayFor) => {
    const echo = await startEchoServer();
    const policy = hostServicePolicy({ echo: echo.port });
    const generation = policyGenerationOf(policy);
    const { proxy, gateway } = await startHostServiceProxy({ policy, gateway: gatewayFor(generation) });

    const refused = await rawConnectViaProxy({ proxyPort: proxy.port, authority: `echo.runfree.internal:${echo.port}` });
    expect(refused.statusCode).toBe(403);
    expect(refused.body).toContain("host-service-unavailable");
    expect(refused.body).not.toContain("runfree host-service add");
    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"host-service-unavailable"/);
    await expectNoDialFor(echo);

    // Reclaim: the gateway is re-read on every admit, so the next valid file
    // written by the supervisor restores service with no proxy restart.
    writeGateway(gateway, availableGateway(generation));
    const recovered = await openConnectTunnel({ proxyPort: proxy.port, authority: `echo.runfree.internal:${echo.port}` });
    expect(recovered.head.statusCode).toBe(200);
    recovered.socket.destroy();
    await echo.stop();
  }, 20_000);

  test.each([
    ["a symlink to a valid file", (file: GatewayFile, contents: Record<string, unknown>) => {
      const target = path.join(file.dir, "target.json");
      fs.writeFileSync(target, `${JSON.stringify(contents)}\n`, { mode: 0o644 });
      fs.symlinkSync(target, file.path);
    }],
    ["group- and other-writable", (file: GatewayFile, contents: Record<string, unknown>) => {
      writeGateway(file, contents);
      fs.chmodSync(file.path, 0o666);
    }],
  ])("a gateway file that is %s is refused as unavailable", async (_label, plant) => {
    const echo = await startEchoServer();
    const policy = hostServicePolicy({ echo: echo.port });
    const { proxy, gateway } = await startHostServiceProxy({ policy, gateway: "missing" });
    plant(gateway, availableGateway(policyGenerationOf(policy)));

    const refused = await rawConnectViaProxy({ proxyPort: proxy.port, authority: `echo.runfree.internal:${echo.port}` });
    expect(refused.statusCode).toBe(403);
    expect(refused.body).toContain("host-service-unavailable");
    await expectNoDialFor(echo);
    await echo.stop();
  }, 20_000);

  test("no listener at the target gets a raw refusal, never a 200", async () => {
    const echo = await startEchoServer();
    const port = echo.port;
    await echo.stop();
    const { proxy } = await startHostServiceProxy({ policy: hostServicePolicy({ echo: port }) });

    const response = await rawConnectViaProxy({ proxyPort: proxy.port, authority: `echo.runfree.internal:${port}` });
    expect(response.statusCode).toBe(403);
    expect(response.raw).not.toContain("200 Connection Established");
    expect(response.body).toContain("host-service-unavailable");
    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"host-service-unavailable"/);
  }, 20_000);

  test("the per-session cap refuses a second concurrent splice and reclaims when the first closes", async () => {
    const echo = await startEchoServer();
    const { proxy } = await startHostServiceProxy({
      policy: hostServicePolicy({ echo: echo.port }),
      extraEnv: { PROXY_HOST_SERVICE_MAX_PER_SESSION: "1" },
    });
    const authority = `echo.runfree.internal:${echo.port}`;

    const first = await openConnectTunnel({ proxyPort: proxy.port, authority });
    expect(first.head.statusCode).toBe(200);
    await waitUntil(() => echo.connections() === 1, "first splice dialled");

    const overCap = await rawConnectViaProxy({ proxyPort: proxy.port, authority });
    expect(overCap.statusCode).toBe(403);
    expect(overCap.body).toContain("host-service-capacity");
    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"host-service-capacity"/);
    expect(echo.connections()).toBe(1);

    first.socket.destroy();
    await waitUntil(() => echo.openSockets().length === 0, "first splice upstream closed");
    // Reclaim: once the first splice is gone, a new one is admitted.
    // The proxy sees the client close asynchronously, so retry briefly.
    let reclaimed: Awaited<ReturnType<typeof openConnectTunnel>> | undefined;
    for (let attempt = 0; attempt < 40 && reclaimed === undefined; attempt += 1) {
      const next = await openConnectTunnel({ proxyPort: proxy.port, authority });
      if (next.head.statusCode === 200) reclaimed = next;
      else {
        next.socket.destroy();
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
    }
    expect(reclaimed?.head.statusCode).toBe(200);
    reclaimed?.socket.destroy();
    await echo.stop();
  }, 20_000);

  test("removing the entry cuts an open splice on both legs before the status drops the name", async () => {
    const echo = await startEchoServer();
    const keep = await startEchoServer();
    const policy = hostServicePolicy({ echo: echo.port, keep: keep.port });
    const { proxy, gateway } = await startHostServiceProxy({ policy });

    const tunnel = await openConnectTunnel({ proxyPort: proxy.port, authority: `echo.runfree.internal:${echo.port}` });
    expect(tunnel.head.statusCode).toBe(200);
    const kept = await openConnectTunnel({ proxyPort: proxy.port, authority: `keep.runfree.internal:${keep.port}` });
    expect(kept.head.statusCode).toBe(200);
    await waitUntil(() => echo.openSockets().length === 1 && keep.openSockets().length === 1, "both splices dialled");
    const upstreamLeg = echo.openSockets()[0];

    const nextPolicy = hostServicePolicy({ keep: keep.port });
    // The supervisor follows the new effective policy generation; the cut must
    // not depend on it.
    writeGateway(gateway, availableGateway(policyGenerationOf(nextPolicy)));
    replaceJson(proxy.policyPath, nextPolicy);

    await waitUntil(() => tunnel.socket.destroyed || tunnel.socket.readableEnded, "client leg closed");
    await waitUntil(() => upstreamLeg.destroyed, "upstream leg closed");
    await proxy.waitForOutput("proxy: host-service splices cut: 1");
    await proxy.waitForOutput(`proxy: policy reloaded, generation=${policyGenerationOf(nextPolicy)}`);

    // The unchanged entry's splice survives.
    expect(kept.socket.destroyed).toBe(false);
    kept.socket.write("still-here");
    await readUntil(kept.socket, "still-here");

    const output = proxy.output();
    const cutIndex = output.indexOf("proxy: host-service splices cut: 1");
    const statuses = statusDebugLines(output);
    // The status is level-triggered (startup and each reload). The first
    // status naming the new generation comes after the cut, no longer names
    // echo, and still counts the surviving splice.
    expect(cutIndex).toBeGreaterThan(-1);
    const after = statuses.find((line) => line.status.generation === policyGenerationOf(nextPolicy));
    expect(after?.index).toBeGreaterThan(cutIndex);
    expect(after?.status.hostServiceSplices).toEqual({ keep: 1 });

    // New CONNECTs for the removed entry are refused.
    const refused = await rawConnectViaProxy({ proxyPort: proxy.port, authority: `echo.runfree.internal:${echo.port}` });
    expect(refused.statusCode).toBe(403);
    expect(refused.body).toContain("host-service-not-configured");
    kept.socket.destroy();
    await echo.stop();
    await keep.stop();
  }, 20_000);

  test("revoking the session closes an open splice on both legs", async () => {
    const echo = await startEchoServer();
    const { proxy } = await startHostServiceProxy({ policy: hostServicePolicy({ echo: echo.port }) });

    const tunnel = await openConnectTunnel({ proxyPort: proxy.port, authority: `echo.runfree.internal:${echo.port}` });
    expect(tunnel.head.statusCode).toBe(200);
    await waitUntil(() => echo.openSockets().length === 1, "splice dialled");
    const upstreamLeg = echo.openSockets()[0];

    const registryDir = proxy.sessionRegistryDir;
    if (registryDir === undefined) throw new Error("the harness did not provision a session registry");
    writeHarnessSessionFiles(registryDir, [harnessSessionFile({
      selectedAgentImageId: `sha256:${"9".repeat(64)}`,
    })]);

    await waitUntil(() => tunnel.socket.destroyed || tunnel.socket.readableEnded, "client leg closed");
    await waitUntil(() => upstreamLeg.destroyed, "upstream leg closed");
    await echo.stop();
  }, 20_000);
});

describe("proxy server: host-service response framing", () => {
  test("a refused host-service CONNECT is a well-formed raw 403", async () => {
    const echo = await startEchoServer();
    const { proxy } = await startHostServiceProxy({ policy: hostServicePolicy({ echo: echo.port }) });
    const socket = net.connect({ host: "127.0.0.1", port: proxy.port });
    await new Promise<void>((resolve) => socket.once("connect", () => resolve()));
    socket.write("CONNECT nope.runfree.internal:80 HTTP/1.1\r\nHost: nope.runfree.internal:80\r\n\r\n");
    const chunks: Buffer[] = [];
    await new Promise<void>((resolve) => {
      socket.on("data", (chunk: Buffer) => chunks.push(chunk));
      socket.once("end", () => resolve());
      socket.once("close", () => resolve());
    });
    const response = parseHttpResponse(Buffer.concat(chunks));
    expect(response.statusCode).toBe(403);
    expect(Number(response.headers["content-length"])).toBe(Buffer.byteLength(response.body));
    socket.destroy();
    await echo.stop();
  }, 20_000);
});
