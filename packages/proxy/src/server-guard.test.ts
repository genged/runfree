// The CONNECT guard is the sole interpreter of agent-controlled proxy bytes.
// These tests pin that property at the seam: a refused connection must obtain
// no tunnel and cause no upstream connection, and mockttp must never be handed
// a client-authored `Proxy-Authorization` header (mockttp 4.4.2 parses
// `Basic metadata:<base64url-json>` into socket/request metadata, surfaced as
// `socket-metadata:<tag>` request tags).
import http2 from "node:http2";
import net from "node:net";
import path from "node:path";
import tls from "node:tls";
import { describe, expect, test } from "vitest";
import { writeResolvedHostsFile } from "./resolved-hosts.ts";
import {
  httpViaProxyPlain,
  openConnectTunnel,
  parseHttpResponse,
  replaceJson,
  startHttpsUpstream,
  startProxy,
  tlsHandshakeOverTunnel,
  tmp,
  type ProxyResponse,
  type RunningProxy,
} from "./server.test-harness.ts";

// `Basic metadata:<base64url({"tags":[...]})>` — the exact shape mockttp
// ingests into request metadata.
function metadataCredential(tag: string): string {
  const payload = Buffer.from(JSON.stringify({ tags: [tag] })).toString("base64url");
  return `Basic ${Buffer.from(`metadata:${payload}`).toString("base64")}`;
}

// Write raw bytes to the proxy port and collect everything sent back until the
// proxy closes the connection or `idleMs` passes with nothing further.
async function rawExchange(options: {
  bytes: string | Buffer;
  followUp?: { afterMs: number; bytes: string | Buffer };
  idleMs?: number;
  proxyPort: number;
}): Promise<{ closed: boolean; raw: string }> {
  const idleMs = options.idleMs ?? 1_500;
  return await new Promise((resolve) => {
    let received = "";
    let settled = false;
    const followUp = options.followUp;
    const socket = net.connect({ host: "127.0.0.1", port: options.proxyPort }, () => {
      socket.write(options.bytes);
      if (followUp) {
        setTimeout(() => socket.write(followUp.bytes), followUp.afterMs);
      }
    });
    const finish = (closed: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve({ closed, raw: received });
    };
    const timer = setTimeout(() => finish(false), idleMs + (options.followUp?.afterMs ?? 0));
    socket.on("data", (chunk: Buffer) => {
      received += chunk.toString("latin1");
    });
    socket.on("error", () => finish(true));
    socket.on("close", () => finish(true));
  });
}

// Attempt an HTTP/2 prior-knowledge (h2c) CONNECT through the proxy port.
// Resolves with the CONNECT `:status` if a tunnel was granted, or undefined.
async function h2cConnect(options: {
  authority: string;
  headers?: Record<string, string>;
  proxyPort: number;
}): Promise<number | undefined> {
  return await new Promise((resolve) => {
    let settled = false;
    const client = http2.connect(`http://127.0.0.1:${options.proxyPort}`);
    const finish = (status: number | undefined) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      client.destroy();
      resolve(status);
    };
    const timer = setTimeout(() => finish(undefined), 4_000);
    client.on("error", () => finish(undefined));
    client.on("connect", () => {
      const request = client.request({
        ":method": "CONNECT",
        ":authority": options.authority,
        ...options.headers,
      });
      request.on("response", (headers) => finish(Number(headers[":status"])));
      request.on("error", () => finish(undefined));
    });
  });
}

async function connectWithHeaders(options: {
  authority: string;
  headerLines: string[];
  proxyPort: number;
}): Promise<ProxyResponse> {
  const { raw } = await rawExchange({
    proxyPort: options.proxyPort,
    bytes: [
      `CONNECT ${options.authority} HTTP/1.1`,
      `Host: ${options.authority}`,
      ...options.headerLines,
      "",
      "",
    ].join("\r\n"),
  });
  return parseHttpResponse(Buffer.from(raw, "latin1"));
}

async function allowlistedProxy(): Promise<{
  proxy: RunningProxy;
  upstream: Awaited<ReturnType<typeof startHttpsUpstream>>;
}> {
  const upstream = await startHttpsUpstream();
  const proxy = await startProxy({
    extraEnv: { NODE_EXTRA_CA_CERTS: upstream.certPath },
    policy: { hosts: ["127.0.0.1"], tokens: {} },
  });
  return { proxy, upstream };
}

describe("proxy server entrypoint: CONNECT guard is the only interpreter", () => {
  test("an HTTP/2 prior-knowledge CONNECT obtains no tunnel and never reaches mockttp's TLS layer", async () => {
    const { proxy, upstream } = await allowlistedProxy();

    // Denied host, denied port, allowed host, and a metadata-bearing CONNECT:
    // none of them may be tunnelled. Before this guard, every one of these was
    // answered `:status 200` by mockttp's `handleH2Connect` with no host
    // classification, no non-443 port check, no denied-tunnel path and no
    // audit-tunnel registration.
    expect(await h2cConnect({ proxyPort: proxy.port, authority: "denied.example.test:443" })).toBeUndefined();
    expect(await h2cConnect({ proxyPort: proxy.port, authority: "deny-all.runfree.invalid:22" })).toBeUndefined();
    expect(await h2cConnect({ proxyPort: proxy.port, authority: "127.0.0.1:443" })).toBeUndefined();
    expect(await h2cConnect({
      proxyPort: proxy.port,
      authority: "127.0.0.1:443",
      headers: { "proxy-authorization": metadataCredential("h2-injected") },
    })).toBeUndefined();

    // No tunnel means no upstream connection, and mockttp never minted a leaf
    // for an unclassified hostname.
    expect(upstream.requests).toHaveLength(0);
    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"unsupported-client-protocol"/);
  }, 30_000);

  test("a TLS ClientHello sent straight to the proxy port is refused before any handshake", async () => {
    const proxy = await startProxy({ policy: { hosts: ["api.github.com"], tokens: {} } });

    // httpolyglot hands a 0x16 first byte to mockttp's TLS server, which mints
    // a CA-signed leaf per SNI and then serves HTTP/1 or HTTP/2 CONNECT inside
    // the TLS session — a complete guard bypass plus unbounded certificate
    // minting. The guard must refuse before the handshake starts.
    const handshake = await new Promise<{ error?: string; peerCommonName?: string }>((resolve) => {
      const socket = tls.connect({
        host: "127.0.0.1",
        port: proxy.port,
        servername: "tls-to-proxy-port.example.test",
        rejectUnauthorized: false,
      });
      const timer = setTimeout(() => resolve({ error: "timeout" }), 5_000);
      socket.once("secureConnect", () => {
        clearTimeout(timer);
        const commonName = socket.getPeerCertificate().subject?.CN;
        socket.destroy();
        resolve({ peerCommonName: Array.isArray(commonName) ? commonName.join(",") : commonName });
      });
      socket.once("error", (error: Error) => {
        clearTimeout(timer);
        socket.destroy();
        resolve({ error: error.message });
      });
    });

    expect(handshake.peerCommonName).toBeUndefined();
    expect(handshake.error).toBeDefined();
    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"unsupported-client-protocol"/);
  }, 30_000);

  test("a CONNECT hidden behind leading CRLFs is refused instead of tunnelled by mockttp", async () => {
    const proxy = await startProxy({ policy: { hosts: [], tokens: {} } });

    // Node's HTTP parser skips leading CR/LF before a request line; the guard's
    // prefix test does not. mockttp therefore used to answer "HTTP/1.1 200 OK"
    // to a CONNECT the guard never classified — here, a non-443 port on a
    // non-allowlisted host, which the guard always rejects. Only CR/LF prefixes
    // were ever a bypass: Node rejects a leading space, so that variant was
    // already answered 400, and it is kept here to pin the whole class.
    for (const prefix of ["\r\n", "\n", "\r\n\r\n", " "]) {
      const { raw } = await rawExchange({
        proxyPort: proxy.port,
        bytes: `${prefix}CONNECT deny-all.runfree.invalid:22 HTTP/1.1\r\nHost: x\r\n\r\n`,
      });
      expect(raw, `prefix ${JSON.stringify(prefix)}`).not.toContain("200");
      expect(raw, `prefix ${JSON.stringify(prefix)}`).toContain("403 Forbidden");
      expect(raw).toContain("blocked non-HTTP/1.1 client protocol");
    }
  }, 30_000);

  test("CONNECT body-framing headers are rejected before a tunnel or upstream socket exists", async () => {
    const { proxy, upstream } = await allowlistedProxy();

    for (const header of [
      "Content-Length: 0",
      "content-length: 4",
      "Transfer-Encoding: chunked",
      "tRaNsFeR-EnCoDiNg: identity",
    ]) {
      const response = await rawExchange({
        proxyPort: proxy.port,
        bytes: [
          "CONNECT 127.0.0.1:443 HTTP/1.1",
          "Host: 127.0.0.1:443",
          header,
          "",
          "",
        ].join("\r\n"),
      });
      expect(response.raw, header).toContain("403 Forbidden");
      expect(response.raw, header).toContain("blocked CONNECT request carrying body-framing headers");
      expect(response.raw, header).not.toContain("200 Connection Established");
    }

    expect(upstream.acceptedConnections()).toBe(0);
    expect(upstream.requests).toHaveLength(0);
  }, 30_000);

  test("no keep-alive on the pass-through path: a CONNECT pipelined behind a Content-Length body gets no tunnel", async () => {
    const { proxy, upstream } = await allowlistedProxy();

    // The pass-through path must not keep connections alive. Scanning the
    // payload for a later CONNECT request line is NOT sufficient, and this is
    // the exact shape that defeats such a scan: after a Content-Length body the
    // next request line begins at the last body byte, with no line terminator
    // in front of it. A chunked prelude WOULD be caught by a line-anchored
    // scan because its terminator ends with CRLF, so the prelude here must use
    // Content-Length.
    for (const target of [
      "deny-all.runfree.invalid:22",
      "attacker-picked.example.test:443",
      `127.0.0.1:${upstream.port}`,
    ]) {
      const attempt = await rawExchange({
        proxyPort: proxy.port,
        idleMs: 2_000,
        bytes: [
          `GET https://127.0.0.1:${upstream.port}/prelude HTTP/1.1`,
          `Host: 127.0.0.1:${upstream.port}`,
          "Connection: keep-alive",
          "Content-Length: 2",
          "",
          "xx",
        ].join("\r\n"),
        // Sent only after the prelude response has drained — the strongest form
        // of the attack, where the connection is demonstrably idle and reusable.
        followUp: {
          afterMs: 900,
          bytes: `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`,
        },
      });
      // Exactly one status line: the contextless prelude's. mockttp never saw the CONNECT,
      // so it never answered "200 Connection Established" for an unclassified
      // host, port or SNI.
      expect(attempt.raw.match(/HTTP\/1\.1 \d\d\d/g) ?? [], target).toHaveLength(1);
      expect(attempt.raw, target).toContain("x-runfree-blocked: missing-admission-record");
      expect(attempt.raw, target).not.toContain("200 Connection Established");
      expect(attempt.raw.toLowerCase(), target).toContain("connection: close");
      expect(attempt.closed, target).toBe(true);
    }

    // No contextless prelude or pipelined CONNECT reached upstream.
    expect(upstream.requests).toHaveLength(0);

    // Fresh connection, non-token first byte: refused outright rather than
    // handed to mockttp.
    const garbage = await rawExchange({ proxyPort: proxy.port, bytes: "\u0000\u0001\u0002GARBAGE\r\n\r\n" });
    expect(garbage.raw).toContain("403 Forbidden");
    expect(garbage.raw).not.toContain("200");

    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"unsupported-client-protocol"/);
  }, 60_000);

  test("an HTTP/1.0 keep-alive prelude cannot pipeline a CONNECT past the forced close", async () => {
    const { proxy, upstream } = await allowlistedProxy();

    // The forced `Connection: close` is version-specific: Node computes
    // HTTP/1.0 keep-alive from the `F_CONNECTION_KEEP_ALIVE` flag and never
    // consults the close token for it, so an HTTP/1.0 prelude with an explicit
    // `Connection: keep-alive` ignores the appended header entirely and the
    // socket keeps parsing. No body trick is needed — explicit keep-alive on an
    // HTTP/1.0 request is the whole precondition, which is why the HTTP/1.1
    // pipelining test above does not cover this.
    const preludes: Array<{ label: string; lines: string[] }> = [
      {
        label: "HTTP/1.0 keep-alive with a body",
        lines: [
          `GET https://127.0.0.1:${upstream.port}/prelude HTTP/1.0`,
          `Host: 127.0.0.1:${upstream.port}`,
          "Connection: keep-alive",
          "Content-Length: 2",
          "",
          "xx",
        ],
      },
      {
        label: "HTTP/1.0 keep-alive with no body",
        lines: [
          `GET https://127.0.0.1:${upstream.port}/prelude HTTP/1.0`,
          `Host: 127.0.0.1:${upstream.port}`,
          "Connection: keep-alive",
          "",
          "",
        ],
      },
      {
        label: "HTTP/1.0 without keep-alive",
        lines: [
          `GET https://127.0.0.1:${upstream.port}/prelude HTTP/1.0`,
          `Host: 127.0.0.1:${upstream.port}`,
          "",
          "",
        ],
      },
    ];

    for (const prelude of preludes) {
      const attempt = await rawExchange({
        proxyPort: proxy.port,
        idleMs: 2_000,
        bytes: prelude.lines.join("\r\n"),
        followUp: {
          afterMs: 700,
          bytes: "CONNECT deny-all.runfree.invalid:22 HTTP/1.1\r\nHost: deny-all.runfree.invalid:22\r\n\r\n",
        },
      });
      // Refused at the guard with a readable 403 and a denial event, rather
      // than reaching mockttp and being answered with a bare, unlogged
      // "HTTP/1.1 200 OK\r\n\r\n" for an unclassified host and port.
      expect(attempt.raw, prelude.label).toContain("403 Forbidden");
      expect(attempt.raw, prelude.label).toContain("blocked non-HTTP/1.1 request on the proxy port");
      expect(attempt.raw, prelude.label).not.toContain("HTTP/1.1 200 OK\r\n\r\n");
    }

    // The prelude itself never reached upstream either: a non-HTTP/1.1 request
    // on the pass-through path is refused outright, not forwarded.
    expect(upstream.requests).toHaveLength(0);
    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"unsupported-client-protocol"/);
  }, 40_000);

  test("plaintext inside an admitted CONNECT tunnel is severed instead of becoming a fresh mockttp request", async () => {
    const { proxy, upstream } = await allowlistedProxy();

    // Every admitted CONNECT is a 443 CONNECT that Runfree TLS-intercepts, so
    // the first tunnel byte must open a TLS record. Plaintext here is the last
    // way to hand mockttp an unclassified request head — and a fresh
    // `Proxy-Authorization` — behind the guard's back.
    const tunnel = await openConnectTunnel({ proxyPort: proxy.port, authority: "127.0.0.1:443" });
    expect(tunnel.head.statusCode).toBe(200);

    const smuggled = await new Promise<string>((resolve) => {
      let received = "";
      tunnel.socket.on("data", (chunk: Buffer) => {
        received += chunk.toString("latin1");
      });
      tunnel.socket.on("close", () => resolve(received));
      tunnel.socket.write([
        `GET https://127.0.0.1:${upstream.port}/smuggled HTTP/1.1`,
        `Host: 127.0.0.1:${upstream.port}`,
        `Proxy-Authorization: ${metadataCredential("in-tunnel")}`,
        "",
        "",
      ].join("\r\n"));
      setTimeout(() => resolve(received), 2_000);
    });
    tunnel.socket.destroy();

    // Refused before mockttp saw it, and answered with a readable 403 rather
    // than a bare reset: the payload was cleartext by definition, so an
    // over-rejected client can diagnose what happened.
    expect(smuggled).toContain("403 Forbidden");
    expect(smuggled).toContain("blocked non-TLS payload in a CONNECT tunnel");
    expect(smuggled).not.toContain(`"url":"/smuggled"`);
    expect(upstream.requests).toHaveLength(0);
    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"unsupported-client-protocol"/);
  }, 30_000);
});

describe("proxy server entrypoint: client Proxy-Authorization never reaches mockttp", () => {
  test("a CONNECT carrying Proxy-Authorization is refused: no tunnel, no upstream connection", async () => {
    const { proxy, upstream } = await allowlistedProxy();

    const refused = await connectWithHeaders({
      proxyPort: proxy.port,
      authority: "127.0.0.1:443",
      headerLines: [`Proxy-Authorization: ${metadataCredential("h1-injected")}`],
    });

    // The seam: no "200 Connection Established", so mockttp's `handleH1Connect`
    // never ran and never stored socket metadata for this connection.
    expect(refused.statusCode).toBe(403);
    expect(refused.raw).not.toContain("200");
    expect(refused.body).toContain("blocked client-supplied Proxy-Authorization");
    expect(upstream.requests).toHaveLength(0);

    // The identical CONNECT without the header is admitted, proving the
    // rejection is caused by the header and not by the target.
    const admitted = await openConnectTunnel({ proxyPort: proxy.port, authority: "127.0.0.1:443" });
    expect(admitted.head.statusCode).toBe(200);
    // The handshake completing at all proves the tunnel reached mockttp's TLS
    // layer, which the refused CONNECT above never did.
    const tlsSocket = await tlsHandshakeOverTunnel(admitted.socket);
    expect(typeof tlsSocket.getPeerCertificate().subject?.CN).toBe("string");
    admitted.socket.destroy();
  }, 30_000);

  test("mixed-case, duplicated, obs-folded, oversized and malformed Proxy-Authorization are refused identically", async () => {
    const { proxy, upstream } = await allowlistedProxy();

    const credential = metadataCredential("variant");
    const variants: Array<{ headerLines: string[]; label: string }> = [
      { label: "canonical", headerLines: [`Proxy-Authorization: ${credential}`] },
      { label: "mixed-case", headerLines: [`pRoXy-AuThOrIzAtIoN: ${credential}`] },
      { label: "lower-case", headerLines: [`proxy-authorization: ${credential}`] },
      {
        label: "duplicated",
        headerLines: [
          `Proxy-Authorization: ${credential}`,
          `Proxy-Authorization: ${metadataCredential("second")}`,
        ],
      },
      { label: "obs-folded", headerLines: ["Proxy-Authorization: Basic", ` ${credential.slice("Basic ".length)}`] },
      { label: "oversized", headerLines: [`Proxy-Authorization: Basic ${"A".repeat(12_000)}`] },
      { label: "malformed-value", headerLines: ["Proxy-Authorization: not-a-scheme"] },
      { label: "empty-value", headerLines: ["Proxy-Authorization:"] },
      { label: "padded-name", headerLines: [`Proxy-Authorization : ${credential}`] },
    ];

    for (const variant of variants) {
      const response = await connectWithHeaders({
        proxyPort: proxy.port,
        authority: "127.0.0.1:443",
        headerLines: variant.headerLines,
      });
      // Identical outcome for every framing: a raw pre-tunnel 403 naming the
      // same reason, and no tunnel. A byte-level refusal cannot disagree with
      // Node's header parser about which of these is "really" a header.
      expect(response.statusCode, variant.label).toBe(403);
      expect(response.raw, variant.label).not.toContain("200");
      expect(response.body, variant.label).toContain("blocked client-supplied Proxy-Authorization");
    }

    expect(upstream.requests).toHaveLength(0);
  }, 40_000);

  test("Proxy-Authorization on the absolute-form path is refused before the request reaches upstream", async () => {
    const { proxy, upstream } = await allowlistedProxy();

    // First request on the connection.
    const first = await rawExchange({
      proxyPort: proxy.port,
      bytes: [
        `GET https://127.0.0.1:${upstream.port}/first HTTP/1.1`,
        `Host: 127.0.0.1:${upstream.port}`,
        `Proxy-Authorization: ${metadataCredential("absolute-form")}`,
        "Connection: close",
        "",
        "",
      ].join("\r\n"),
    });
    expect(first.raw).toContain("403 Forbidden");
    expect(first.raw).toContain("blocked client-supplied Proxy-Authorization");
    expect(upstream.requests).toHaveLength(0);

    // Pipelined behind an allowed request on a reused connection: mockttp
    // parses per-request proxy-auth metadata for absolute-form requests. The
    // guard classifies only the first head, so this is closed by the
    // pass-through path refusing keep-alive, not by watching the payload.
    const pipelined = await rawExchange({
      proxyPort: proxy.port,
      bytes: [
        `GET https://127.0.0.1:${upstream.port}/one HTTP/1.1`,
        `Host: 127.0.0.1:${upstream.port}`,
        "Connection: keep-alive",
        "",
        "",
      ].join("\r\n"),
      followUp: {
        afterMs: 700,
        bytes: [
          `GET https://127.0.0.1:${upstream.port}/two HTTP/1.1`,
          `Host: 127.0.0.1:${upstream.port}`,
          `Proxy-Authorization: ${metadataCredential("pipelined")}`,
          "Connection: close",
          "",
          "",
        ].join("\r\n"),
      },
    });
    expect(pipelined.raw).toContain("x-runfree-blocked: missing-admission-record");
    expect(upstream.requests).toHaveLength(0);
    expect(proxy.output()).not.toContain("refused proxy-authorization metadata");
  }, 30_000);

  test("a request inside an admitted TLS tunnel cannot reach mockttp's proxy-auth metadata parse", async () => {
    const { proxy, upstream } = await allowlistedProxy();

    // The residual the guard structurally cannot cover: inside an ordinary,
    // correctly admitted 443 tunnel the client speaks TLS, the tunnel payload
    // check is satisfied by the first byte and disarms, and an absolute-form
    // request within that TLS session reaches mockttp's proxy-auth metadata
    // branch. The guard must not decrypt the tunnel to find it, so the channel
    // is shut at mockttp instead.
    const tunnel = await openConnectTunnel({ proxyPort: proxy.port, authority: "127.0.0.1:443" });
    expect(tunnel.head.statusCode).toBe(200);
    const tlsSocket = await tlsHandshakeOverTunnel(tunnel.socket);
    tlsSocket.write([
      `GET https://127.0.0.1:${upstream.port}/in-tls HTTP/1.1`,
      `Host: 127.0.0.1:${upstream.port}`,
      `Proxy-Authorization: ${metadataCredential("in-tls")}`,
      "Connection: close",
      "",
      "",
    ].join("\r\n"));
    // The seal reporting a refusal is the proof that this path really does
    // reach mockttp's ingestion point, and that ingestion did not happen.
    await proxy.waitForOutput("proxy: refused proxy-authorization metadata");
    tunnel.socket.destroy();
  }, 30_000);
});

describe("proxy server entrypoint: denied tunnels never acquire admission by policy reload", () => {
  test("a client Proxy-Authorization header stays on the local denial path after widening", async () => {
    const host = "upgrade-proxyauth.example.test";
    const upstream = await startHttpsUpstream({ commonName: host, subjectAltName: `DNS:${host}` });
    const resolvedHostsPath = path.join(tmp, "resolved-hosts.json");
    writeResolvedHostsFile(resolvedHostsPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: { [host]: ["127.0.0.1"] },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: upstream.certPath,
        PROXY_RESOLVED_HOSTS_PATH: resolvedHostsPath,
      },
      policy: { hosts: [], tokens: {} },
    });

    const tunnel = await openConnectTunnel({ proxyPort: proxy.port, authority: `${host}:443` });
    expect(tunnel.head.statusCode).toBe(200);
    const tlsSocket = await tlsHandshakeOverTunnel(tunnel.socket, host);
    expect(tlsSocket.getPeerCertificate().subject?.CN).toBe("blocked.invalid");

    replaceJson(proxy.policyPath, { hosts: [host], tokens: {} });
    await proxy.waitForOutput("proxy: policy reloaded, generation=");

    tlsSocket.write([
      "GET /upgraded HTTP/1.1",
      `Host: ${host}`,
      `Proxy-Authorization: ${metadataCredential("upgraded")}`,
      "Proxy-Connection: keep-alive",
      "Connection: close",
      "",
      "",
    ].join("\r\n"));
    const chunks: Buffer[] = [];
    await new Promise<void>((resolve) => {
      tlsSocket.on("data", (chunk: Buffer) => chunks.push(chunk));
      tlsSocket.once("close", () => resolve());
      tlsSocket.once("error", () => resolve());
      setTimeout(resolve, 5_000);
    });
    tunnel.socket.destroy();

    const response = parseHttpResponse(Buffer.concat(chunks));
    expect(response.statusCode).toBe(403);
    expect(response.headers["x-runfree-blocked"]).toBe("missing-admission-record");
    expect(upstream.requests).toHaveLength(0);

    // The denied endpoint owns this connection, so mockttp never sees the
    // header and cannot parse it into trusted-looking metadata.
    expect(proxy.output()).not.toContain("refused proxy-authorization metadata");
  }, 30_000);
});

describe("proxy server entrypoint: guard preserves provenance denial feedback", () => {
  test("origin-form and absolute-form requests without CONNECT report missing admission first", async () => {
    const proxy = await startProxy({ policy: { hosts: ["api.github.com"], tokens: {} } });

    // A non-CONNECT request has no admission context, regardless of scheme or
    // hostname policy. Provenance denial precedes policy evaluation.
    const plain = await httpViaProxyPlain({
      proxyPort: proxy.port,
      targetHost: "api.github.com",
      targetPort: 80,
      path: "/x",
    });
    expect(plain.statusCode).toBe(403);
    expect(plain.headers["x-runfree-blocked"]).toBe("missing-admission-record");

    // The same ordering applies to a non-allowlisted claim.
    const denied = await rawExchange({
      proxyPort: proxy.port,
      bytes: [
        "GET https://denied.example.test/x HTTP/1.1",
        "Host: denied.example.test",
        "Connection: close",
        "",
        "",
      ].join("\r\n"),
    });
    expect(denied.raw).toContain("x-runfree-blocked: missing-admission-record");

    // Origin-form request (a client that ignored the proxy contract).
    const originForm = await rawExchange({
      proxyPort: proxy.port,
      bytes: "GET / HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n",
    });
    expect(originForm.raw).toContain("403 Forbidden");
    expect(originForm.raw).toContain("x-runfree-blocked: missing-admission-record");
  }, 30_000);
});

