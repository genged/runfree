// Live-proxy proofs for the request-side refusal of unmediated OAuth grants
// (cross-host token endpoint design P1-a, R14, R15, X3), against the real
// server subprocess. The hosts are exact hostnames resolved through the
// resolved-hosts snapshot to one local HTTPS upstream. Every refusal is
// proven to stop before an upstream connection, before an approval hold or
// pending record (the host's write posture is `ask` with an approver
// attached), and before any OAuth state write.
import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import zlib from "node:zlib";
import { describe, expect, test } from "vitest";

import {
  APPROVALS_PROCESS_EPOCH_FILE,
  APPROVALS_WATCHER_HEARTBEAT_FILE,
  parsePendingApprovalRecord,
} from "@runfree/runtime-contracts/write-approvals";
import { writeResolvedHostsFile } from "./resolved-hosts.ts";
import {
  createUpstreamCertificate,
  httpsViaProxy,
  openConnectTunnel,
  type ProxyResponse,
  parseHttpResponse,
  type RunningProxy,
  servers,
  startProxy,
  tlsHandshakeOverTunnel,
  tmp,
  waitUntil,
  writeJson,
} from "./server.test-harness.ts";

const OWN_UID = String(process.getuid?.() ?? 0);
const RECORD_ONLY = "ahrefs.com";
const ENDPOINT_HOST = "api.ahrefs.com";
const BROAD = "broad.example.com";
const HOSTS = [RECORD_ONLY, ENDPOINT_HOST, BROAD];
const GRANT = "grant_type=authorization_code&code=secret-code&code_verifier=v";
const FORM = { "Content-Type": "application/x-www-form-urlencoded" };

type Upstream = {
  acceptedConnections: () => number;
  certPath: string;
  port: number;
  requests: Array<{ body: string; method?: string; url?: string }>;
};

// Every path answers with a real token body, so any request that reaches the
// upstream on an unmediated path would hand the agent a real token.
async function startUpstream(): Promise<Upstream> {
  const { certPath, keyPath } = createUpstreamCertificate(tmp, {
    commonName: RECORD_ONLY,
    subjectAltName: HOSTS.map((host) => `DNS:${host}`).join(","),
  });
  const requests: Upstream["requests"] = [];
  let acceptedConnections = 0;
  const server = https.createServer({ cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) }, (request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      requests.push({ body: Buffer.concat(chunks).toString("utf8"), method: request.method, url: request.url });
      response.setHeader("content-type", "application/json");
      if (request.url === "/mcp") {
        response.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }));
        return;
      }
      if (request.url?.endsWith("-400")) response.statusCode = 400;
      response.end(JSON.stringify({ access_token: "real-access-token", refresh_token: "real-refresh-token", token_type: "Bearer" }));
    });
  });
  servers.add(server);
  server.on("connection", () => {
    acceptedConnections += 1;
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("upstream server did not report a TCP port");
  return { acceptedConnections: () => acceptedConnections, certPath, port: address.port, requests };
}

type Started = {
  decisionsDir: string;
  oauthPolicyPath: string;
  oauthStateDir: string;
  pendingDir: string;
  // The OAuth state file as seeded before the proxy started.
  seededState: string;
  proxy: RunningProxy;
  upstream: Upstream;
};

async function startOAuthProxy(options: {
  oauthPolicy: unknown;
  writeApproval: "allow" | "ask";
}): Promise<Started> {
  const upstream = await startUpstream();
  const resolvedHostsPath = path.join(tmp, "resolved-hosts.json");
  writeResolvedHostsFile(resolvedHostsPath, {
    generation: `sha256:${"a".repeat(64)}`,
    hosts: Object.fromEntries(HOSTS.map((host) => [host, ["127.0.0.1"]])),
  });
  const oauthPolicyPath = path.join(tmp, "oauth-mediation-policy.json");
  const oauthStateDir = path.join(tmp, "oauth-state");
  writeJson(oauthPolicyPath, options.oauthPolicy);
  // An existing state file, so a refusal is proven to leave it byte-identical
  // rather than only to create nothing.
  const seededState = `${JSON.stringify({ discovered: {}, handles: {} }, null, 2)}\n`;
  fs.mkdirSync(oauthStateDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(oauthStateDir, "handles.json"), seededState, { mode: 0o600 });
  const pendingDir = fs.mkdtempSync(path.join(tmp, "approvals-pending-"));
  const decisionsDir = fs.mkdtempSync(path.join(tmp, "approvals-decisions-"));
  fs.writeFileSync(path.join(decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE), "watch-requested");
  const proxy = await startProxy({
    extraEnv: {
      NODE_EXTRA_CA_CERTS: upstream.certPath,
      PROXY_RESOLVED_HOSTS_PATH: resolvedHostsPath,
      RUNFREE_OAUTH_POLICY: oauthPolicyPath,
      RUNFREE_OAUTH_STATE_DIR: oauthStateDir,
      RUNFREE_APPROVALS_PENDING_DIR: pendingDir,
      RUNFREE_APPROVALS_DECISIONS_DIR: decisionsDir,
      RUNFREE_APPROVALS_DECISION_OWNER_UID: OWN_UID,
      RUNFREE_WRITE_APPROVAL_HOLD_SECONDS: "5",
    },
    policy: { hosts: HOSTS, tokens: {}, writeApproval: options.writeApproval },
  });
  // Attach an approver for the running proxy's process epoch, so a write
  // that reaches classification is held (and leaves a pending record).
  fs.writeFileSync(
    path.join(decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE),
    fs.readFileSync(path.join(pendingDir, APPROVALS_PROCESS_EPOCH_FILE), "utf8"),
  );
  return { decisionsDir, oauthPolicyPath, oauthStateDir, pendingDir, proxy, seededState, upstream };
}

function send(started: Started, host: string, request: { body?: string; headers?: Record<string, string>; method?: string; path: string }): Promise<ProxyResponse> {
  return httpsViaProxy({
    proxyPort: started.proxy.port,
    targetHost: host,
    targetPort: started.upstream.port,
    path: request.path,
    ...(request.method !== undefined ? { method: request.method } : {}),
    ...(request.headers !== undefined ? { headers: request.headers } : {}),
    ...(request.body !== undefined ? { body: request.body } : {}),
  });
}

// A raw request whose body bytes and framing the test controls (gzip bytes,
// chunked framing with no Content-Length).
async function sendRaw(started: Started, host: string, head: string[], body: Buffer): Promise<ProxyResponse> {
  const tunnel = await openConnectTunnel({ authority: `${host}:443`, proxyPort: started.proxy.port });
  if (tunnel.head.statusCode !== 200) return tunnel.head;
  const socket = await tlsHandshakeOverTunnel(tunnel.socket, host);
  socket.write(Buffer.concat([
    Buffer.from([...head, `Host: ${host}:${started.upstream.port}`, "Connection: close", "", ""].join("\r\n")),
    body,
  ]));
  const chunks: Buffer[] = [];
  await new Promise<void>((resolve, reject) => {
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.once("end", () => resolve());
    socket.once("close", () => resolve());
    socket.once("error", reject);
  });
  return parseHttpResponse(Buffer.concat(chunks));
}

function pendingRecords(started: Started): string[] {
  return fs.readdirSync(started.pendingDir).filter((entry) => entry.endsWith(".json"));
}

function stateFile(started: Started): string {
  return path.join(started.oauthStateDir, "handles.json");
}

function expectRefusedBeforeUpstream(started: Started, response: ProxyResponse, connectionsBefore: number, label: string): void {
  expect(response.statusCode, label).toBe(403);
  expect(response.raw, label).toContain("x-runfree-blocked: oauth-endpoint-not-mediated");
  expect(response.body, label).not.toContain("real-access-token");
  expect(started.upstream.acceptedConnections(), `${label}: upstream connection`).toBe(connectionsBefore);
  expect(started.upstream.requests, `${label}: upstream request`).toHaveLength(0);
  expect(pendingRecords(started), `${label}: pending approval record`).toEqual([]);
  expect(fs.readFileSync(stateFile(started), "utf8"), `${label}: OAuth state write`).toBe(started.seededState);
}

function approve(started: Started, id: string, scope: "request" | "session"): void {
  fs.writeFileSync(path.join(started.decisionsDir, `${id}.json`), `${JSON.stringify({
    v: 1,
    processEpoch: fs.readFileSync(path.join(started.pendingDir, APPROVALS_PROCESS_EPOCH_FILE), "utf8"),
    id,
    decidedAt: new Date().toISOString(),
    decision: "approve",
    scope,
  })}\n`);
}

function touchPolicy(filePath: string, value: unknown): void {
  writeJson(filePath, value);
  const future = new Date(Date.now() + 2_000);
  fs.utimesSync(filePath, future, future);
}

// A WebSocket upgrade over a fresh tunnel; resolves with whatever came back.
async function webSocketUpgrade(started: Started, host: string, pathName: string): Promise<ProxyResponse> {
  const tunnel = await openConnectTunnel({ authority: `${host}:443`, proxyPort: started.proxy.port });
  if (tunnel.head.statusCode !== 200) return tunnel.head;
  const socket = await tlsHandshakeOverTunnel(tunnel.socket, host);
  socket.on("error", () => {});
  socket.write([
    `GET ${pathName} HTTP/1.1`,
    `Host: ${host}:${started.upstream.port}`,
    "Upgrade: websocket",
    "Connection: Upgrade",
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
    "Sec-WebSocket-Version: 13",
    "",
    "",
  ].join("\r\n"));
  const chunks: Buffer[] = [];
  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      socket.destroy();
      resolve();
    }, 5_000);
    const done = () => {
      clearTimeout(timer);
      resolve();
    };
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.once("end", done);
    socket.once("close", done);
  });
  return parseHttpResponse(Buffer.concat(chunks));
}

describe("proxy server: unmediated OAuth grants are refused before upstream", () => {
  test("every grant shape to a record-only host is refused with no connect, no hold, and no state write", async () => {
    const started = await startOAuthProxy({
      oauthPolicy: { recordOnlyHosts: [RECORD_ONLY], providers: { "mcp:claude-ahrefs": { kind: "mcp", resourceHost: ENDPOINT_HOST, bindingHosts: [RECORD_ONLY] } } },
      writeApproval: "ask",
    });
    const cases: Array<[string, () => Promise<ProxyResponse>]> = [
      ["form POST", () => send(started, RECORD_ONLY, { method: "POST", path: "/oauth/token", headers: FORM, body: GRANT })],
      ["JSON POST", () => send(started, RECORD_ONLY, { method: "POST", path: "/oauth/token", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ grant_type: "authorization_code", code: "c" }) })],
      ["JSON array", () => send(started, RECORD_ONLY, { method: "POST", path: "/oauth/token", headers: { "Content-Type": "application/json" }, body: JSON.stringify([{ refresh_token: "r" }]) })],
      ["text/plain", () => send(started, RECORD_ONLY, { method: "POST", path: "/oauth/token", headers: { "Content-Type": "text/plain" }, body: GRANT })],
      ["query GET", () => send(started, RECORD_ONLY, { path: "/oauth/token?grant_type=authorization_code&code=c" })],
      ["PUT", () => send(started, RECORD_ONLY, { method: "PUT", path: "/oauth/token", headers: FORM, body: GRANT })],
      ["registration", () => send(started, RECORD_ONLY, { method: "POST", path: "/oauth/register", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ redirect_uris: ["http://127.0.0.1/cb"] }) })],
      ["gzip", async () => {
        const body = zlib.gzipSync(GRANT);
        return await sendRaw(started, RECORD_ONLY, [
          `POST https://${RECORD_ONLY}:${started.upstream.port}/oauth/token HTTP/1.1`,
          "Content-Type: application/x-www-form-urlencoded",
          "Content-Encoding: gzip",
          `Content-Length: ${body.length}`,
        ], body);
      }],
      ["multipart", () => send(started, RECORD_ONLY, { method: "POST", path: "/upload", headers: { "Content-Type": "multipart/form-data; boundary=b" }, body: "--b\r\n\r\nx\r\n--b--" })],
      ["oversize", () => send(started, RECORD_ONLY, { method: "POST", path: "/upload", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ blob: "x".repeat(17 * 1024) }) })],
      ["missing Content-Length", () => sendRaw(started, RECORD_ONLY, [
        `POST https://${RECORD_ONLY}:${started.upstream.port}/upload HTTP/1.1`,
        "Content-Type: application/json",
        "Transfer-Encoding: chunked",
      ], Buffer.from("2\r\n{}\r\n0\r\n\r\n"))],
    ];
    for (const [label, run] of cases) {
      const connectionsBefore = started.upstream.acceptedConnections();
      expectRefusedBeforeUpstream(started, await run(), connectionsBefore, label);
    }
    expect(started.proxy.output()).toContain('"reason":"oauth-endpoint-not-mediated"');
    expect(started.proxy.output()).not.toContain("secret-code");

    // Positive control: a write that is not grant-shaped reaches write
    // classification and is held for approval on the same host.
    const held = send(started, RECORD_ONLY, { method: "POST", path: "/api", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ q: 1 }) });
    await waitUntil(() => pendingRecords(started).length > 0, "pending approval record for the non-grant write");
    expect((await held).raw).toContain("x-runfree-blocked: write-approval-timeout");
    // A read passes and reaches the upstream.
    const read = await send(started, RECORD_ONLY, { path: "/.well-known/oauth-authorization-server" });
    expect(read.statusCode).toBe(200);
    expect(started.upstream.requests.map((request) => request.url)).toEqual(["/.well-known/oauth-authorization-server"]);
  }, 60_000);

  test("the denial names the host, the path, and the MCP remedies; an unreadable upload names host add", async () => {
    const started = await startOAuthProxy({
      oauthPolicy: { recordOnlyHosts: [RECORD_ONLY], providers: { "mcp:claude-ahrefs": { kind: "mcp", resourceHost: ENDPOINT_HOST, bindingHosts: [RECORD_ONLY] } } },
      writeApproval: "allow",
    });
    const grant = await send(started, RECORD_ONLY, { method: "POST", path: "/oauth/token?state=x", headers: FORM, body: GRANT });
    expect(grant.body).toContain(`host:   ${RECORD_ONLY}`);
    expect(grant.body).toContain("path:   /oauth/token");
    expect(grant.body).not.toContain("state=x");
    expect(grant.body).toContain("grant_type (a token exchange)");
    expect(grant.body).toContain("runfree mcp enable <agent> <server>");
    expect(grant.body).toContain("runfree mcp revoke <agent> <server>");
    expect(grant.body).toContain("OAuth providers involved: mcp:claude-ahrefs");
    expect(grant.body).not.toContain(`runfree host add ${RECORD_ONLY}`);

    const upload = await send(started, RECORD_ONLY, { method: "POST", path: "/upload", headers: { "Content-Type": "text/plain" }, body: "x".repeat(17 * 1024) });
    expect(upload.body).toContain("larger than 16 KiB");
    expect(upload.body).toContain(`runfree host add ${RECORD_ONLY}`);
    expect(started.upstream.requests).toHaveLength(0);
    expect(fs.readFileSync(stateFile(started), "utf8")).toBe(started.seededState);
  }, 30_000);

  test("on a host a record names that serves an MCP endpoint, a top-level grant is refused and JSON-RPC passes", async () => {
    const started = await startOAuthProxy({
      oauthPolicy: { recordEndpointHosts: [ENDPOINT_HOST], providers: { "mcp:claude-ahrefs": { kind: "mcp", resourceHost: ENDPOINT_HOST, resourcePathPrefix: "/mcp" } } },
      writeApproval: "allow",
    });
    const connectionsBefore = started.upstream.acceptedConnections();
    expectRefusedBeforeUpstream(started, await send(started, ENDPOINT_HOST, { method: "POST", path: "/oauth/token", headers: FORM, body: GRANT }), connectionsBefore, "top-level grant");
    const rpc = await send(started, ENDPOINT_HOST, {
      method: "POST",
      path: "/mcp",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { arguments: { grant_type: "x", code: "c", code_verifier: "v" } } }),
    });
    expect(rpc.statusCode).toBe(200);
    expect(started.upstream.requests.map((request) => request.url)).toEqual(["/mcp"]);
  }, 30_000);

  test("a static endpoint on a record-only host is mediated: the agent gets handles, not tokens", async () => {
    const started = await startOAuthProxy({
      oauthPolicy: {
        recordOnlyHosts: [RECORD_ONLY],
        providers: { "mcp:claude-ahrefs": { kind: "mcp", resourceHost: ENDPOINT_HOST, tokenEndpoints: [{ host: RECORD_ONLY, path: "/oauth/token" }] } },
      },
      writeApproval: "allow",
    });
    const response = await send(started, RECORD_ONLY, { method: "POST", path: "/oauth/token", headers: FORM, body: GRANT });
    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body).access_token).toMatch(/^runfree_oauth_access_/);
    expect(response.body).not.toContain("real-access-token");
  }, 30_000);

  test("a blocked endpoint refuses a grant, blocks a token reply at any status, and clears when the policy drops it", async () => {
    const blocked = {
      blockedEndpoints: [{ host: BROAD, path: "/oauth/token" }, { host: BROAD, path: "/oauth/token-400" }],
      providers: { "mcp:claude-ahrefs": { kind: "mcp", resourceHost: ENDPOINT_HOST } },
    };
    const started = await startOAuthProxy({ oauthPolicy: blocked, writeApproval: "allow" });
    const connectionsBefore = started.upstream.acceptedConnections();
    expectRefusedBeforeUpstream(started, await send(started, BROAD, { method: "POST", path: "/oauth/token", headers: FORM, body: GRANT }), connectionsBefore, "blocked grant");

    // Not grant-shaped: it goes upstream, and the token reply is blocked.
    for (const pathName of ["/oauth/token", "/oauth/token-400"]) {
      const reply = await send(started, BROAD, { path: pathName });
      expect(reply.body, pathName).toContain("blocked by OAuth proxy policy");
      expect(reply.body, pathName).not.toContain("real-access-token");
    }
    // Plain traffic on the same broadly allowed host is unaffected (G4).
    expect((await send(started, BROAD, { path: "/blog" })).body).toContain("real-access-token");

    // A path variant the exact match misses is caught by the host-wide scan.
    for (const variant of ["/oauth/token/", "/OAuth/token", "/oauth/%74oken"]) {
      const before = started.upstream.acceptedConnections();
      const requestsBefore = started.upstream.requests.length;
      const refused = await send(started, BROAD, { method: "POST", path: variant, headers: FORM, body: GRANT });
      expect(refused.raw, variant).toContain("x-runfree-blocked: oauth-endpoint-not-mediated");
      expect(started.upstream.acceptedConnections(), variant).toBe(before);
      expect(started.upstream.requests, variant).toHaveLength(requestsBefore);
    }
    expect(fs.readFileSync(stateFile(started), "utf8")).toBe(started.seededState);

    // Reclaim: the projection drops the blocked endpoint (conflict removed
    // or the server revoked); the next request is plain again.
    touchPolicy(started.oauthPolicyPath, { providers: blocked.providers });
    expect((await send(started, BROAD, { path: "/oauth/token" })).body).toContain("real-access-token");
  }, 30_000);

  test("while the OAuth policy is invalid a grant to any allowlisted host is refused before upstream", async () => {
    const started = await startOAuthProxy({ oauthPolicy: { providers: { "mcp:claude-ahrefs": { kind: "mcp", resourceHost: ENDPOINT_HOST } } }, writeApproval: "allow" });
    expect((await send(started, BROAD, { path: "/warm" })).statusCode).toBe(200);
    fs.writeFileSync(started.oauthPolicyPath, "{ malformed\n");
    const future = new Date(Date.now() + 2_000);
    fs.utimesSync(started.oauthPolicyPath, future, future);
    const requestsBefore = started.upstream.requests.length;
    const refused = await send(started, BROAD, { method: "POST", path: "/token", headers: FORM, body: GRANT });
    expect(refused.raw).toContain("x-runfree-blocked: oauth-endpoint-not-mediated");
    expect(refused.body).toContain("runfree doctor");
    expect(started.upstream.requests).toHaveLength(requestsBefore);
  }, 30_000);
});

describe("proxy server: WebSocket upgrades where the proxy guards OAuth", () => {
  test("an upgrade to a record-only host, a claimed endpoint, or with a grant query is refused before upstream and notes no retry approval", async () => {
    const started = await startOAuthProxy({
      oauthPolicy: {
        recordOnlyHosts: [RECORD_ONLY],
        recordEndpointHosts: [ENDPOINT_HOST],
        providers: { "mcp:claude-ahrefs": { kind: "mcp", resourceHost: ENDPOINT_HOST, tokenEndpoints: [{ host: BROAD, path: "/oauth/token" }] } },
      },
      writeApproval: "ask",
    });
    for (const [host, pathName] of [
      [RECORD_ONLY, "/oauth/token?grant_type=refresh_token&refresh_token=R"],
      [RECORD_ONLY, "/socket"],
      [BROAD, "/oauth/token"],
      [ENDPOINT_HOST, "/socket?grant_type=refresh_token&refresh_token=R"],
    ] as const) {
      const label = `${host}${pathName}`;
      const before = started.upstream.acceptedConnections();
      const response = await webSocketUpgrade(started, host, pathName);
      expect(response.statusCode, label).toBe(403);
      expect(response.raw, label).toContain("x-runfree-blocked: oauth-endpoint-not-mediated");
      expect(response.raw, label).not.toContain("real-access-token");
      expect(response.body, label).toContain("Runfree blocked this WebSocket upgrade.");
      expect(response.body, label).toContain("Current rules: runfree host explain <host>");
      expect(started.upstream.acceptedConnections(), `${label}: upstream connection`).toBe(before);
      // No deny-then-approve retry approval is noted for a refused upgrade.
      expect(pendingRecords(started), label).toEqual([]);
    }
    expect(started.upstream.requests).toHaveLength(0);
    expect(fs.readFileSync(stateFile(started), "utf8")).toBe(started.seededState);
    expect(started.proxy.output()).toContain('"reason":"oauth-endpoint-not-mediated"');

    // Each refusal carries its own remedy.
    const mediated = await webSocketUpgrade(started, BROAD, "/oauth/token");
    expect(mediated.body).toContain("Send this request over HTTPS instead.");
    const recordOnly = await webSocketUpgrade(started, RECORD_ONLY, "/socket");
    expect(recordOnly.body).toContain("  runfree mcp revoke <agent> <server>");
    expect(recordOnly.body).toContain("  runfree host add <host>");
    const query = await webSocketUpgrade(started, ENDPOINT_HOST, "/socket?grant_type=refresh_token");
    expect(query.body).toContain("The request carries an OAuth grant field.");

  }, 60_000);

  test("positive control: an unguarded upgrade is admitted and handed to mockttp's passthrough", async () => {
    // mockttp's WebSocket passthrough dials port 443 whatever the Host port,
    // so this harness cannot serve the upstream 200 token reply (the live
    // suite can). The proof here is that the same upgrade is admitted to
    // the passthrough once the host is not guarded, and refused before it
    // while guarded.
    const started = await startOAuthProxy({ oauthPolicy: { recordOnlyHosts: [RECORD_ONLY], providers: {} }, writeApproval: "allow" });
    fs.writeFileSync(path.join(started.proxy.verboseDir, "enabled"), "");
    const target = "/oauth/token?grant_type=refresh_token&refresh_token=R";
    const admitted = /proxy: allowed method=GET scheme=wss host=ahrefs\.com/;
    const refused = await webSocketUpgrade(started, RECORD_ONLY, target);
    expect(refused.raw).toContain("x-runfree-blocked: oauth-endpoint-not-mediated");
    expect(started.proxy.output()).not.toMatch(admitted);

    touchPolicy(started.oauthPolicyPath, { providers: {} });
    const passed = await webSocketUpgrade(started, RECORD_ONLY, target);
    expect(passed.raw).not.toContain("oauth-endpoint-not-mediated");
    await started.proxy.waitForOutput(admitted);
  }, 60_000);
});

describe("proxy server: a held write is re-checked when it is released", () => {
  test("a grant held for approval is refused on release when the host became record-only meanwhile", async () => {
    const started = await startOAuthProxy({
      oauthPolicy: { providers: { "mcp:claude-ahrefs": { kind: "mcp", resourceHost: ENDPOINT_HOST } } },
      writeApproval: "ask",
    });
    // Not guarded yet: the grant reaches write classification and is held.
    const responsePromise = send(started, RECORD_ONLY, { method: "POST", path: "/oauth/token", headers: FORM, body: GRANT });
    await waitUntil(() => pendingRecords(started).length > 0, "pending approval record");
    const record = parsePendingApprovalRecord(fs.readFileSync(path.join(started.pendingDir, pendingRecords(started)[0]), "utf8"));
    if (!record) throw new Error("pending approval record did not parse");

    // The projection makes the host record-only while the request is held.
    touchPolicy(started.oauthPolicyPath, { recordOnlyHosts: [RECORD_ONLY], providers: { "mcp:claude-ahrefs": { kind: "mcp", resourceHost: ENDPOINT_HOST } } });
    approve(started, record.id, "request");

    const response = await responsePromise;
    expect(response.statusCode).toBe(403);
    expect(response.raw).toContain("x-runfree-blocked: oauth-endpoint-not-mediated");
    expect(response.body).not.toContain("real-access-token");
    expect(started.upstream.acceptedConnections()).toBe(0);
    expect(started.upstream.requests).toHaveLength(0);
    expect(fs.readFileSync(stateFile(started), "utf8")).toBe(started.seededState);
  }, 30_000);
});
