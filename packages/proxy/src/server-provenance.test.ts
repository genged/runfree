import fs from "node:fs";
import path from "node:path";
import type net from "node:net";
import tls from "node:tls";
import { describe, expect, test } from "vitest";

import { writeResolvedHostsFile } from "./resolved-hosts.ts";
import {
  openConnectTunnel,
  parseHttpResponse,
  startHttpsUpstream,
  startProxy,
  tlsHandshakeOverTunnel,
  tmp,
  type ProxyResponse,
} from "./server.test-harness.ts";

async function absoluteRequest(tlsSocket: tls.TLSSocket, input: {
  host: string;
  path: string;
  port: number;
}): Promise<ProxyResponse> {
  tlsSocket.write([
    `GET https://${input.host}:${input.port}${input.path} HTTP/1.1`,
    `Host: ${input.host}:${input.port}`,
    "Connection: close",
    "",
    "",
  ].join("\r\n"));
  const chunks: Buffer[] = [];
  await new Promise<void>((resolve, reject) => {
    tlsSocket.on("data", (chunk: Buffer) => chunks.push(chunk));
    tlsSocket.once("end", resolve);
    tlsSocket.once("close", resolve);
    tlsSocket.once("error", reject);
  });
  return parseHttpResponse(Buffer.concat(chunks));
}

async function tlsHandshakeOutcome(socket: net.Socket, servername?: string): Promise<
  | { kind: "connected"; socket: tls.TLSSocket }
  | { kind: "rejected"; message: string }
> {
  const tlsSocket = tls.connect({ socket, servername, rejectUnauthorized: false });
  tlsSocket.on("error", () => {});
  return await new Promise((resolve) => {
    let settled = false;
    const finish = (outcome:
      | { kind: "connected"; socket: tls.TLSSocket }
      | { kind: "rejected"; message: string }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(outcome);
    };
    const timer = setTimeout(() => {
      tlsSocket.destroy();
      finish({ kind: "rejected", message: "TLS handshake timed out" });
    }, 5_000);
    tlsSocket.once("secureConnect", () => finish({ kind: "connected", socket: tlsSocket }));
    tlsSocket.once("error", (error: Error) => finish({ kind: "rejected", message: error.message }));
    tlsSocket.once("close", () => finish({ kind: "rejected", message: "connection closed before TLS handshake" }));
  });
}

async function absoluteWebSocketRequest(tlsSocket: tls.TLSSocket, input: {
  host: string;
  path: string;
  port: number;
}): Promise<ProxyResponse> {
  tlsSocket.write([
    `GET ${input.path} HTTP/1.1`,
    `Host: ${input.host}:${input.port}`,
    "Upgrade: websocket",
    "Connection: Upgrade",
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
    "Sec-WebSocket-Version: 13",
    "",
    "",
  ].join("\r\n"));
  const chunks: Buffer[] = [];
  return await new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(parseHttpResponse(Buffer.concat(chunks)));
    };
    const timer = setTimeout(() => {
      tlsSocket.destroy();
      finish();
    }, 5_000);
    tlsSocket.on("data", (chunk: Buffer) => chunks.push(chunk));
    tlsSocket.once("end", finish);
    tlsSocket.once("close", finish);
    tlsSocket.once("error", finish);
  });
}

describe("proxy server entrypoint: authorization provenance", () => {
  test("inner-host disagreement fails before upstream TCP, with 421 only for another allowed host", async () => {
    const admittedHost = "first.example.test";
    const otherAllowedHost = "second.example.test";
    const deniedHost = "denied.example.test";
    const upstream = await startHttpsUpstream({
      commonName: otherAllowedHost,
      subjectAltName: `DNS:${otherAllowedHost}`,
    });
    const resolvedHostsPath = path.join(tmp, "resolved-hosts.json");
    writeResolvedHostsFile(resolvedHostsPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: {
        [admittedHost]: ["127.0.0.1"],
        [otherAllowedHost]: ["127.0.0.1"],
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: upstream.certPath,
        PROXY_RESOLVED_HOSTS_PATH: resolvedHostsPath,
      },
      policy: { hosts: [admittedHost, otherAllowedHost], tokens: {}, writeApproval: "allow" },
    });

    const allowedMismatchTunnel = await openConnectTunnel({
      authority: `${admittedHost}:443`,
      proxyPort: proxy.port,
    });
    const allowedMismatchTls = await tlsHandshakeOverTunnel(allowedMismatchTunnel.socket, admittedHost);
    const allowedMismatch = await absoluteRequest(allowedMismatchTls, {
      host: otherAllowedHost,
      path: "/must-not-dial",
      port: upstream.port,
    });
    expect(allowedMismatch.statusCode).toBe(421);
    expect(allowedMismatch.headers["x-runfree-blocked"]).toBe("connect-host-mismatch");
    expect(upstream.acceptedConnections()).toBe(0);

    const deniedMismatchTunnel = await openConnectTunnel({
      authority: `${admittedHost}:443`,
      proxyPort: proxy.port,
    });
    const deniedMismatchTls = await tlsHandshakeOverTunnel(deniedMismatchTunnel.socket, admittedHost);
    const deniedMismatch = await absoluteRequest(deniedMismatchTls, {
      host: deniedHost,
      path: "/must-not-dial",
      port: upstream.port,
    });
    expect(deniedMismatch.statusCode).toBe(403);
    expect(deniedMismatch.headers["x-runfree-blocked"]).toBe("connect-host-mismatch");
    expect(upstream.acceptedConnections()).toBe(0);

    const matchingTunnel = await openConnectTunnel({
      authority: `${otherAllowedHost}:443`,
      proxyPort: proxy.port,
    });
    const matchingTls = await tlsHandshakeOverTunnel(matchingTunnel.socket, otherAllowedHost);
    const matching = await absoluteRequest(matchingTls, {
      host: otherAllowedHost,
      path: "/matching",
      port: upstream.port,
    });
    expect(matching.statusCode).toBe(200);
    expect(upstream.requests.map((request) => request.url)).toEqual(["/matching"]);
  }, 30_000);

  test("CONNECT and TLS SNI must agree before upstream TCP; equal and absent SNI remain admitted", async () => {
    const admittedHost = "sni-admitted.example.test";
    const mismatchedHost = "sni-other.example.test";
    const upstream = await startHttpsUpstream({
      commonName: admittedHost,
      subjectAltName: `DNS:${admittedHost}`,
    });
    const resolvedHostsPath = path.join(tmp, "resolved-hosts.json");
    writeResolvedHostsFile(resolvedHostsPath, {
      generation: `sha256:${"b".repeat(64)}`,
      hosts: {
        [admittedHost]: ["127.0.0.1"],
        [mismatchedHost]: ["127.0.0.1"],
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: upstream.certPath,
        PROXY_RESOLVED_HOSTS_PATH: resolvedHostsPath,
      },
      policy: { hosts: [admittedHost, mismatchedHost], tokens: {}, writeApproval: "allow" },
    });

    const equalTunnel = await openConnectTunnel({ authority: `${admittedHost}:443`, proxyPort: proxy.port });
    expect(equalTunnel.head.statusCode).toBe(200);
    const equalTls = await tlsHandshakeOverTunnel(equalTunnel.socket, admittedHost);
    expect((await absoluteRequest(equalTls, {
      host: admittedHost,
      path: "/equal-sni",
      port: upstream.port,
    })).statusCode).toBe(200);

    const absentTunnel = await openConnectTunnel({ authority: `${admittedHost}:443`, proxyPort: proxy.port });
    expect(absentTunnel.head.statusCode).toBe(200);
    const absentTls = await tlsHandshakeOverTunnel(absentTunnel.socket);
    expect((await absoluteRequest(absentTls, {
      host: admittedHost,
      path: "/absent-sni",
      port: upstream.port,
    })).statusCode).toBe(200);
    expect(upstream.requests.map((request) => request.url)).toEqual(["/equal-sni", "/absent-sni"]);

    const acceptedBeforeMismatch = upstream.acceptedConnections();
    const mismatchTunnel = await openConnectTunnel({ authority: `${admittedHost}:443`, proxyPort: proxy.port });
    expect(mismatchTunnel.head.statusCode).toBe(200);
    const mismatch = await tlsHandshakeOutcome(mismatchTunnel.socket, mismatchedHost);
    // Turn an incorrectly accepted handshake into an observable upstream side
    // effect. The correct path terminates before any HTTP context exists.
    if (mismatch.kind === "connected") {
      await absoluteRequest(mismatch.socket, {
        host: admittedHost,
        path: "/must-not-dial-after-sni-mismatch",
        port: upstream.port,
      });
    }

    expect(upstream.acceptedConnections()).toBe(acceptedBeforeMismatch);
    expect(mismatch.kind).toBe("rejected");
    await proxy.waitForOutput(
      /proxy-denial: [^\n]*"reason":"connect-sni-mismatch","host":"sni-admitted\.example\.test"/,
    );
  }, 40_000);

  test("WSS inner-host disagreement returns 421 before websocket passthrough TCP", async () => {
    const admittedHost = "wss-admitted.example.test";
    const otherAllowedHost = "wss-other.example.test";
    const upstream = await startHttpsUpstream({
      commonName: admittedHost,
      subjectAltName: `DNS:${admittedHost},DNS:${otherAllowedHost}`,
    });
    const resolvedHostsPath = path.join(tmp, "resolved-hosts.json");
    writeResolvedHostsFile(resolvedHostsPath, {
      generation: `sha256:${"c".repeat(64)}`,
      hosts: {
        [admittedHost]: ["127.0.0.1"],
        [otherAllowedHost]: ["127.0.0.1"],
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: upstream.certPath,
        PROXY_RESOLVED_HOSTS_PATH: resolvedHostsPath,
      },
      policy: { hosts: [admittedHost, otherAllowedHost], tokens: {}, writeApproval: "allow" },
    });

    // Positive control: the matching WSS authority reaches the adapter's
    // allowed matcher. A CONNECT tunnel fixes upstream port 443, so this
    // unprivileged fixture cannot receive the eventual passthrough dial.
    fs.writeFileSync(path.join(proxy.verboseDir, "enabled"), "");
    const matchingTunnel = await openConnectTunnel({ authority: `${admittedHost}:443`, proxyPort: proxy.port });
    const matchingTls = await tlsHandshakeOverTunnel(matchingTunnel.socket, admittedHost);
    const matchingResponse = absoluteWebSocketRequest(matchingTls, {
      host: admittedHost,
      path: "/matching",
      port: upstream.port,
    });
    await proxy.waitForOutput(/proxy: allowed method=GET scheme=wss host=wss-admitted\.example\.test path=\/matching/);
    matchingTls.destroy();
    await matchingResponse;
    expect(upstream.acceptedConnections()).toBe(0);

    const acceptedBeforeMismatch = upstream.acceptedConnections();
    const mismatchTunnel = await openConnectTunnel({ authority: `${admittedHost}:443`, proxyPort: proxy.port });
    const mismatchTls = await tlsHandshakeOverTunnel(mismatchTunnel.socket, admittedHost);
    const mismatch = await absoluteWebSocketRequest(mismatchTls, {
      host: otherAllowedHost,
      path: "/must-not-dial",
      port: upstream.port,
    });

    expect(mismatch.statusCode).toBe(421);
    expect(mismatch.headers["x-runfree-blocked"]).toBe("connect-host-mismatch");
    expect(upstream.acceptedConnections()).toBe(acceptedBeforeMismatch);
    await proxy.waitForOutput(
      /proxy-denial: [^\n]*"reason":"connect-host-mismatch","host":"wss-other\.example\.test"/,
    );
  }, 40_000);
});
