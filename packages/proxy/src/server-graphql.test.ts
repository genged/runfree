// Live-proxy GraphQL classification tests (MED-5): proven against the real
// mockttp request-body buffering in the spawned server subprocess, not a unit
// mock. A declared GraphQL endpoint under a deny posture forwards provably
// pure queries (with credential injection) and blocks everything unproven
// before any token read or upstream contact.
import path from "node:path";
import { describe, expect, test } from "vitest";

import { GRAPHQL_BODY_CAP_BYTES } from "./graphql-classify.ts";
import {
  httpsViaProxy,
  openConnectTunnel,
  parseHttpResponse,
  startHttpsUpstream,
  startProxy,
  tlsHandshakeOverTunnel,
  tmp,
  type ProxyResponse,
} from "./server.test-harness.ts";

// Like httpsViaProxy, but resolves as soon as a complete HTTP response
// (headers plus content-length bytes) has arrived instead of waiting for the
// server to close the socket: after an over-cap request body mockttp delivers
// the synthetic 403 but can leave the connection lingering.
async function postUntilResponse(options: {
  body: string;
  headers?: Record<string, string>;
  path: string;
  proxyPort: number;
  targetPort: number;
}): Promise<ProxyResponse> {
  const tunnel = await openConnectTunnel({
    authority: "127.0.0.1:443",
    proxyPort: options.proxyPort,
  });
  if (tunnel.head.statusCode !== 200) return tunnel.head;
  const socket = await tlsHandshakeOverTunnel(tunnel.socket);
  socket.write([
    `POST https://127.0.0.1:${options.targetPort}${options.path} HTTP/1.1`,
    `Host: 127.0.0.1:${options.targetPort}`,
    ...Object.entries(options.headers ?? {}).map(([name, value]) => `${name}: ${value}`),
    `Content-Length: ${Buffer.byteLength(options.body)}`,
    "Connection: close",
    "",
    options.body,
  ].join("\r\n"));
  const chunks: Buffer[] = [];
  const raw = await new Promise<Buffer>((resolve, reject) => {
    const check = () => {
      const buffered = Buffer.concat(chunks);
      const headerEnd = buffered.indexOf("\r\n\r\n");
      if (headerEnd === -1) return;
      const contentLength = /content-length:\s*(\d+)/i.exec(buffered.subarray(0, headerEnd).toString("latin1"));
      if (!contentLength) return;
      if (buffered.length >= headerEnd + 4 + Number(contentLength[1])) resolve(buffered);
    };
    socket.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
      check();
    });
    socket.once("end", () => resolve(Buffer.concat(chunks)));
    socket.once("error", reject);
  });
  socket.destroy();
  return parseHttpResponse(raw);
}

function graphqlPolicy(writeAction: "deny" | "ask"): unknown {
  return {
    hosts: ["127.0.0.1"],
    tokens: {
      example: {
        description: "Example token",
        credentials: [
          { host: "127.0.0.1", header: "Authorization", scheme: "bearer" },
        ],
      },
    },
    requests: {
      "127.0.0.1": {
        writeAction,
        graphql: { endpoints: ["/graphql"], writeOps: "mutation" },
      },
    },
  };
}

async function startGraphqlProxy(writeAction: "deny" | "ask" = "deny") {
  const upstream = await startHttpsUpstream();
  const proxy = await startProxy({
    extraEnv: { NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt") },
    policy: graphqlPolicy(writeAction),
    secretFiles: { example: "real-proxy-token\n" },
  });
  return { proxy, upstream };
}

describe("proxy server GraphQL endpoint classification", () => {
  test("a pure query POST is a read: forwarded with the injected credential", async () => {
    const { proxy, upstream } = await startGraphqlProxy();
    const body = JSON.stringify({ query: "query Viewer { viewer { login } }" });
    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/graphql",
      headers: { "content-type": "application/json", Authorization: "Bearer agent-forged" },
      body,
    });
    expect(response.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].headers.authorization).toBe("Bearer real-proxy-token");
  }, 20_000);

  test("mutations, batches, persisted-query, oversize, and compressed bodies classify write and never reach upstream", async () => {
    const { proxy, upstream } = await startGraphqlProxy();
    const cases: Array<{ label: string; body: string; headers?: Record<string, string> }> = [
      {
        label: "mutation",
        body: JSON.stringify({ query: "mutation { createIssue { id } }" }),
      },
      {
        label: "batch",
        body: JSON.stringify([{ query: "query { a }" }]),
      },
      {
        label: "persisted-query",
        body: JSON.stringify({ query: "query { a }", extensions: { persistedQuery: { sha256Hash: "x" } } }),
      },
      {
        label: "unparseable",
        body: "not-json",
      },
      {
        label: "oversize",
        body: JSON.stringify({ query: `query { ${"a ".repeat(GRAPHQL_BODY_CAP_BYTES / 2)} }` }),
      },
      {
        // The content-encoding header alone classifies write (the proxy never
        // decompresses); a plain body keeps the raw-socket harness framing
        // valid, which real gzip bytes would break.
        label: "compressed",
        body: JSON.stringify({ query: "query { a }" }),
        headers: { "content-encoding": "gzip" },
      },
    ];
    for (const testCase of cases) {
      const response = await postUntilResponse({
        proxyPort: proxy.port,
        targetPort: upstream.port,
        path: "/graphql",
        headers: { "content-type": "application/json", ...(testCase.headers ?? {}) },
        body: testCase.body,
      });
      expect(response.statusCode, testCase.label).toBe(403);
      expect(response.raw, testCase.label).toContain("x-runfree-blocked: write-denied");
      expect(response.raw, testCase.label).not.toContain("real-proxy-token");
    }
    expect(upstream.requests).toHaveLength(0);
  }, 30_000);

  test("GET-based GraphQL is a read by construction and needs no parsing", async () => {
    const { proxy, upstream } = await startGraphqlProxy();
    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/graphql?query=%7Bviewer%7Blogin%7D%7D",
    });
    expect(response.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
  }, 20_000);

  test("non-declared endpoints keep the plain conservative classification", async () => {
    const { proxy, upstream } = await startGraphqlProxy();
    // POST off the declared endpoint: plain method write, denied — even with
    // a query-shaped body.
    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/api/other",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ query: "query { viewer { login } }" }),
    });
    expect(response.statusCode).toBe(403);
    expect(upstream.requests).toHaveLength(0);
  }, 20_000);
});
