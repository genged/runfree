import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "vitest";
import { writeResolvedHostsFile } from "./resolved-hosts.ts";
import { tmp, replaceJson, waitUntil, startProxy, createUpstreamCertificate, startHttpsUpstream, readUntil, parseHttpResponse, httpsViaProxy, httpViaProxyPlain, rawConnectViaProxy, openConnectTunnel, tlsHandshakeOverTunnel, httpsRequestOverTunnel, type ProxyResponse } from "./server.test-harness.ts";

describe("proxy server entrypoint: denied tunnels", () => {
  test("serves an in-tunnel synthetic 403 from the static blocked.invalid certificate with no upstream side effects", async () => {
    const deniedHost = "denied.example.test";
    const otherDeniedHost = "other-denied.example.test";
    // Configure the DNS guard to resolve the denied host and run a live
    // upstream there: this proves the denial short-circuit fired on its own,
    // rather than the resolved-hosts defense-in-depth masking a regression.
    const upstream = await startHttpsUpstream({
      commonName: deniedHost,
      subjectAltName: `DNS:${deniedHost}`,
    });
    const resolvedHostsPath = path.join(tmp, "resolved-hosts.json");
    writeResolvedHostsFile(resolvedHostsPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: {
        [deniedHost]: ["127.0.0.1"],
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: upstream.certPath,
        PROXY_RESOLVED_HOSTS_PATH: resolvedHostsPath,
      },
      policy: { hosts: ["api.github.com"], tokens: {} },
    });

    const tunnel = await openConnectTunnel({
      proxyPort: proxy.port,
      authority: `${deniedHost}:443`,
    });
    expect(tunnel.head.statusCode).toBe(200);
    const tlsSocket = await tlsHandshakeOverTunnel(tunnel.socket, deniedHost);
    const peerCertificate = tlsSocket.getPeerCertificate();
    expect(peerCertificate.subject?.CN).toBe("blocked.invalid");

    const response = await httpsRequestOverTunnel(tlsSocket, {
      host: deniedHost,
      path: "/v1/data?api_key=secret-query-value",
    });
    expect(response.statusCode).toBe(403);
    expect(response.raw).toContain("x-runfree-blocked: host-not-allowlisted");
    expect(response.raw).toContain("content-type: text/plain; charset=utf-8");
    expect(response.body).toContain("Runfree blocked this request.");
    expect(response.body).toContain(`host:   ${deniedHost}`);
    expect(response.body).toContain(`runfree host add ${deniedHost}`);
    tunnel.socket.destroy();

    // No DNS-driven upstream connection happened even though the DNS guard
    // could resolve the host.
    expect(upstream.requests).toHaveLength(0);

    // The denial path reuses one static pre-generated leaf for every denied
    // hostname: a different SNI sees the identical certificate.
    const secondTunnel = await openConnectTunnel({
      proxyPort: proxy.port,
      authority: `${otherDeniedHost}:443`,
    });
    expect(secondTunnel.head.statusCode).toBe(200);
    const secondTlsSocket = await tlsHandshakeOverTunnel(secondTunnel.socket, otherDeniedHost);
    const secondCertificate = secondTlsSocket.getPeerCertificate();
    expect(secondCertificate.subject?.CN).toBe("blocked.invalid");
    expect(secondCertificate.serialNumber).toBe(peerCertificate.serialNumber);
    secondTunnel.socket.destroy();

    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"host-not-allowlisted"[^\n]*"method":"GET","path":"\/v1\/data"/);
    expect(proxy.output()).not.toContain("api_key");
    expect(proxy.output()).not.toContain("secret-query-value");
  }, 20_000);

  test("falls back to the raw pre-TLS 403 past the denied-tunnel concurrency cap", async () => {
    const proxy = await startProxy({
      extraEnv: { PROXY_DENIED_TUNNEL_MAX: "1" },
      policy: { hosts: [], tokens: {} },
    });

    const heldTunnel = await openConnectTunnel({
      proxyPort: proxy.port,
      authority: "denied-one.example.test:443",
    });
    expect(heldTunnel.head.statusCode).toBe(200);

    const overCap = await rawConnectViaProxy({
      proxyPort: proxy.port,
      authority: "denied-two.example.test:443",
    });
    expect(overCap.statusCode).toBe(403);
    expect(overCap.body).toContain("blocked outbound host: denied-two.example.test");

    heldTunnel.socket.destroy();
  }, 20_000);

  // Guards the runtime topology probe target (NON_RESOLVING_CONNECT_PROBE_HOST
  // in packages/cli/src/runtime/probes.ts). The probe claims that a non-443
  // CONNECT is rejected before DNS and before any upstream connection; this
  // pins the ordering that claim depends on.
  test("the runtime topology probe target is rejected on the port, before the host check and before DNS", async () => {
    // A deny-all policy makes the ordering observable: if the CONNECT
    // classifier consulted the host allowlist first, this non-allowlisted host
    // would be adopted into a denied tunnel and answered "200 Connection
    // established". A raw pre-TLS 403 naming the port therefore proves the
    // port check runs first, and the reserved RFC 2606 `.invalid` target
    // proves the verdict needs no DNS lookup and no upstream connection.
    const proxy = await startProxy({ policy: { hosts: [], tokens: {} } });

    const rejected = await rawConnectViaProxy({
      proxyPort: proxy.port,
      authority: "deny-all.runfree.invalid:22",
    });

    expect(rejected.statusCode).toBe(403);
    expect(rejected.body).toContain("blocked non-HTTPS CONNECT port: 22");
    expect(rejected.body).not.toContain("blocked outbound host");
    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"non-https-port","host":"deny-all\.runfree\.invalid"/);
  }, 20_000);

  test("destroys idle denied tunnels at the timeout and still records the denial", async () => {
    const proxy = await startProxy({
      extraEnv: { PROXY_DENIED_TUNNEL_IDLE_MS: "150" },
      policy: { hosts: [], tokens: {} },
    });

    const tunnel = await openConnectTunnel({
      proxyPort: proxy.port,
      authority: "idle-denied.example.test:443",
    });
    expect(tunnel.head.statusCode).toBe(200);

    const closed = await Promise.race([
      new Promise<boolean>((resolve) => tunnel.socket.once("close", () => resolve(true))),
      new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 5_000)),
    ]);
    expect(closed, "idle denied tunnel should be destroyed by the proxy").toBe(true);

    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"host-not-allowlisted","host":"idle-denied\.example\.test","generation"/);
  }, 20_000);

  test("re-evaluates policy per in-tunnel request: hosts removed mid-tunnel are denied locally", async () => {
    const upstream = await startHttpsUpstream();
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
      },
      policy: { hosts: ["127.0.0.1"], tokens: {} },
    });

    // Allowed at CONNECT time: the tunnel reaches mockttp.
    const tunnel = await openConnectTunnel({
      proxyPort: proxy.port,
      authority: "127.0.0.1:443",
    });
    expect(tunnel.head.statusCode).toBe(200);
    const tlsSocket = await tlsHandshakeOverTunnel(tunnel.socket);

    replaceJson(proxy.policyPath, { hosts: [], tokens: {} });
    await proxy.waitForOutput("proxy: policy reloaded, generation=");

    const response = await httpsRequestOverTunnel(tlsSocket, {
      host: "127.0.0.1",
      path: "/removed-mid-tunnel",
    });
    expect(response.statusCode).toBe(403);
    expect(response.raw).toContain("x-runfree-blocked: host-not-allowlisted");
    expect(response.body).toContain("runfree host add 127.0.0.1");
    expect(upstream.requests).toHaveLength(0);
    tunnel.socket.destroy();
  }, 20_000);

  test("a tunnel denied at CONNECT cannot be upgraded by policy widening; a fresh CONNECT proceeds", async () => {
    const allowedLaterHost = "allowed-later.example.test";
    const upstream = await startHttpsUpstream({
      commonName: allowedLaterHost,
      subjectAltName: `DNS:${allowedLaterHost}`,
    });
    const resolvedHostsPath = path.join(tmp, "resolved-hosts.json");
    writeResolvedHostsFile(resolvedHostsPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: {
        [allowedLaterHost]: ["127.0.0.1"],
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: upstream.certPath,
        PROXY_RESOLVED_HOSTS_PATH: resolvedHostsPath,
      },
      policy: { hosts: [], tokens: {} },
    });

    // Denied at CONNECT time: the tunnel terminates at the denial endpoint.
    const tunnel = await openConnectTunnel({
      proxyPort: proxy.port,
      authority: `${allowedLaterHost}:443`,
    });
    expect(tunnel.head.statusCode).toBe(200);
    const tlsSocket = await tlsHandshakeOverTunnel(tunnel.socket, allowedLaterHost);
    expect(tlsSocket.getPeerCertificate().subject?.CN).toBe("blocked.invalid");

    replaceJson(proxy.policyPath, { hosts: [allowedLaterHost], tokens: {} });
    await proxy.waitForOutput("proxy: policy reloaded, generation=");

    const response = await httpsRequestOverTunnel(tlsSocket, {
      host: allowedLaterHost,
      path: "/allowed-mid-tunnel",
    });
    expect(response.statusCode).toBe(403);
    expect(response.raw).toContain("x-runfree-blocked: missing-admission-record");
    expect(upstream.requests).toHaveLength(0);
    tunnel.socket.destroy();

    const fresh = await httpsViaProxy({
      proxyPort: proxy.port,
      targetHost: allowedLaterHost,
      targetPort: upstream.port,
      path: "/allowed-mid-tunnel",
    });
    expect(fresh.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].url).toBe("/allowed-mid-tunnel");
  }, 20_000);

  test("served denied-tunnel request leaves no stale port-state entry after the client closes", async () => {
    const deniedHost = "served-cleanup.example.test";
    const proxy = await startProxy({
      extraEnv: { PROXY_DENIED_TUNNEL_DEBUG: "1" },
      policy: { hosts: ["api.github.com"], tokens: {} },
    });

    const tunnel = await openConnectTunnel({
      proxyPort: proxy.port,
      authority: `${deniedHost}:443`,
    });
    expect(tunnel.head.statusCode).toBe(200);
    const tlsSocket = await tlsHandshakeOverTunnel(tunnel.socket, deniedHost);

    // An in-tunnel request is served a synthetic 403 (state.served = true);
    // the internal socket closes first on this path, so the cleanup must rely
    // on the port captured at connect time, not internalSocket.localPort.
    const response = await httpsRequestOverTunnel(tlsSocket, {
      host: deniedHost,
      path: "/denied",
    });
    expect(response.statusCode).toBe(403);
    tunnel.socket.destroy();

    // The client-close debug line proves the map entry was deleted: the served
    // flag is true and the remaining state-map size is zero.
    await proxy.waitForOutput(
      new RegExp(`proxy-debug: denied-tunnel states=0 served=true host=${deniedHost.replaceAll(".", "\\.")}`),
    );
  }, 20_000);

  test("a widened policy does not disarm the idle bound on a tunnel that was denied at CONNECT", async () => {
    const allowedLaterHost = "upgrade-keepalive.example.test";
    const upstream = await startHttpsUpstream({
      commonName: allowedLaterHost,
      subjectAltName: `DNS:${allowedLaterHost}`,
    });
    const resolvedHostsPath = path.join(tmp, "resolved-hosts.json");
    writeResolvedHostsFile(resolvedHostsPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: { [allowedLaterHost]: ["127.0.0.1"] },
    });
    const idleMs = 150;
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: upstream.certPath,
        PROXY_RESOLVED_HOSTS_PATH: resolvedHostsPath,
        PROXY_DENIED_TUNNEL_IDLE_MS: String(idleMs),
      },
      policy: { hosts: [], tokens: {} },
    });

    // Denied at CONNECT time, then allowlisted mid-tunnel.
    const tunnel = await openConnectTunnel({
      proxyPort: proxy.port,
      authority: `${allowedLaterHost}:443`,
    });
    expect(tunnel.head.statusCode).toBe(200);
    const tlsSocket = await tlsHandshakeOverTunnel(tunnel.socket, allowedLaterHost);
    expect(tlsSocket.getPeerCertificate().subject?.CN).toBe("blocked.invalid");

    replaceJson(proxy.policyPath, { hosts: [allowedLaterHost], tokens: {} });
    await proxy.waitForOutput("proxy: policy reloaded, generation=");

    // The old tunnel remains contextless and receives a local denial.
    tlsSocket.write([
      "GET /upgrade HTTP/1.1",
      `Host: ${allowedLaterHost}`,
      "Connection: keep-alive",
      "",
      "",
    ].join("\r\n"));
    const firstResponse = await readUntil(tlsSocket, "\r\n\r\n");
    const denied = parseHttpResponse(firstResponse);
    expect(denied.statusCode).toBe(403);
    expect(denied.headers["x-runfree-blocked"]).toBe("missing-admission-record");

    // The denied-tunnel bound remains active; widening never turns this into a
    // long-lived authorized connection.
    const severed = await Promise.race([
      new Promise<boolean>((resolve) => tunnel.socket.once("close", () => resolve(true))),
      new Promise<boolean>((resolve) => setTimeout(() => resolve(false), idleMs * 4)),
    ]);
    expect(severed, "contextless denied tunnel should still be severed by its idle bound").toBe(true);
    tunnel.socket.destroy();
  }, 20_000);

  test("missing-admission and missing-token denials emit rate-bounded structured events", async () => {
    const upstream = await startHttpsUpstream();
    const proxy = await startProxy({
      extraEnv: { NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt") },
      policy: {
        hosts: ["127.0.0.1"],
        tokens: {
          firecrawl: {
            description: "Firecrawl token",
            credentials: [
              { host: "127.0.0.1", header: "Authorization", scheme: "bearer" },
            ],
          },
        },
      },
    });

    // Missing required token: the synthetic body keeps the remediation steps
    // AND a structured event is emitted for doctor/summary visibility.
    const missingToken = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/v1/scrape",
      headers: { Authorization: "Bearer agent-placeholder" },
    });
    expect(missingToken.statusCode).toBe(403);
    expect(missingToken.body).toContain("missing required proxy token: firecrawl");
    expect(missingToken.body).toContain("runfree credential set-source firecrawl --from-env FIRECRAWL_TOKEN");
    expect(upstream.requests).toHaveLength(0);
    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"missing-required-token","host":"127\.0\.0\.1"/);

    // Plain HTTP never traverses CONNECT, so provenance rejects it before
    // policy. A hostile loop must still be rate-bounded.
    const httpDenials: Promise<ProxyResponse>[] = [];
    for (let index = 0; index < 14; index += 1) {
      httpDenials.push(httpViaProxyPlain({
        proxyPort: proxy.port,
        targetPort: upstream.port,
        path: `/loop-${index}?secret=should-not-be-logged`,
      }));
    }
    const httpResponses = await Promise.all(httpDenials);
    for (const response of httpResponses) {
      expect(response.statusCode).toBe(403);
    }
    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"missing-admission-record","host":"127\.0\.0\.1"/);
    // Rate bound: the structured missing-admission events are capped per window.
    await waitUntil(() => {
      const events = proxy.output().split("\n").filter((line) => (
        line.includes('"reason":"missing-admission-record"') && !line.includes("suppressed")
      ));
      return events.length <= 10 && events.length >= 1;
    }, "rate-bounded missing-admission events");
    const nonHttpsEmitted = proxy.output().split("\n").filter((line) => (
      line.includes('"reason":"missing-admission-record"') && !line.includes("suppressed")
    ));
    expect(nonHttpsEmitted.length).toBeLessThanOrEqual(10);
    // The query string never reaches the logs.
    expect(proxy.output()).not.toContain("should-not-be-logged");
  }, 20_000);
});

describe("proxy server audit mode", () => {
  type AuditPaths = {
    markerPath: string;
    spoolPath: string;
    auditResolvedHostsPath: string;
    env: NodeJS.ProcessEnv;
  };

  function auditPaths(extra: NodeJS.ProcessEnv = {}): AuditPaths {
    const dir = fs.mkdtempSync(path.join(tmp, "audit-state-"));
    const markerPath = path.join(dir, "active.json");
    const spoolPath = path.join(dir, "spool.txt");
    const auditResolvedHostsPath = path.join(dir, "audit-resolved-hosts.json");
    return {
      markerPath,
      spoolPath,
      auditResolvedHostsPath,
      env: {
        PROXY_AUDIT_MARKER_PATH: markerPath,
        PROXY_AUDIT_SPOOL_PATH: spoolPath,
        PROXY_AUDIT_RESOLVED_HOSTS_PATH: auditResolvedHostsPath,
        PROXY_AUDIT_WATCH_MS: "100",
        ...extra,
      },
    };
  }

  function writeMarker(markerPath: string, options: { expiresInMs?: number; enabledAt?: string; expiresAt?: string } = {}): void {
    const now = new Date();
    fs.writeFileSync(markerPath, `${JSON.stringify({
      v: 1,
      enabledAt: options.enabledAt ?? now.toISOString(),
      expiresAt: options.expiresAt ?? new Date(now.getTime() + (options.expiresInMs ?? 600_000)).toISOString(),
      sessionHint: "server-test",
    })}\n`);
  }

  test("audited request path: forwards without token reads, strips the union of configured credential headers, and observes", async () => {
    const auditedHost = "audited.example.test";
    const upstream = await startHttpsUpstream({
      commonName: auditedHost,
      subjectAltName: `DNS:${auditedHost}`,
    });
    const enforceResolvedHostsPath = path.join(tmp, "resolved-hosts.json");
    writeResolvedHostsFile(enforceResolvedHostsPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: {},
    });
    const paths = auditPaths({
      NODE_EXTRA_CA_CERTS: upstream.certPath,
      PROXY_RESOLVED_HOSTS_PATH: enforceResolvedHostsPath,
    });
    // The supervisor publishes audited hosts into the dedicated audit
    // snapshot; the test plays that role.
    writeResolvedHostsFile(paths.auditResolvedHostsPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: { [auditedHost]: ["127.0.0.1"] },
    });
    writeMarker(paths.markerPath);
    const proxy = await startProxy({
      extraEnv: paths.env,
      // Tokens are configured for a different (allowlisted) host with two
      // distinct header names, and no secret files exist: the audited path
      // must never read token files, and must strip the union of configured
      // header names rather than the (empty) per-host mapping.
      policy: {
        hosts: ["allowed.example"],
        tokens: {
          github: {
            description: "GitHub token",
            credentials: [
              { host: "allowed.example", header: "Authorization", scheme: "bearer" },
              { host: "allowed.example", header: "X-Api-Key", scheme: "raw" },
            ],
          },
        },
      },
    });

    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      targetHost: auditedHost,
      targetPort: upstream.port,
      path: "/v1/data?secret_param=should-not-be-logged",
      headers: {
        Authorization: "Bearer agent-forged-credential",
        "Accept-Encoding": "gzip, deflate, br",
        "X-Api-Key": "agent-forged-key",
        "X-Keep": "still-forwarded",
      },
    });

    expect(response.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].headers.authorization).toBeUndefined();
    expect(upstream.requests[0].headers["accept-encoding"]).toBe("gzip, deflate, br");
    expect(upstream.requests[0].headers["x-api-key"]).toBeUndefined();
    expect(upstream.requests[0].headers["x-keep"]).toBe("still-forwarded");
    // Never a "missing required proxy token" denial on the audited path: the
    // request succeeded with no token files present.
    expect(proxy.output()).not.toContain("missing required proxy token");

    await proxy.waitForOutput(/proxy-audit: \{"v":1,[^\n]*"host":"audited\.example\.test","method":"GET","path":"\/v1\/data","generation":"sha256:[a-f0-9]{64}"\}/);
    expect(proxy.output()).not.toContain("secret_param");
    await waitUntil(() => {
      try {
        return fs.readFileSync(paths.spoolPath, "utf8").includes(`${auditedHost}\n`);
      } catch {
        return false;
      }
    }, "audited host spooled");
  }, 20_000);

  test("CONNECT guard audit branch: a valid marker passes a non-allowlisted 443 CONNECT to mockttp; no marker keeps the denied tunnel", async () => {
    const auditedHost = "tunnel-audited.example.test";
    const paths = auditPaths();
    const proxy = await startProxy({
      extraEnv: paths.env,
      policy: { hosts: ["api.github.com"], tokens: {} },
    });

    // No marker: the denied-tunnel TLS endpoint answers with the static
    // blocked.invalid leaf.
    const deniedTunnel = await openConnectTunnel({
      proxyPort: proxy.port,
      authority: `${auditedHost}:443`,
    });
    expect(deniedTunnel.head.statusCode).toBe(200);
    const deniedTls = await tlsHandshakeOverTunnel(deniedTunnel.socket, auditedHost);
    expect(deniedTls.getPeerCertificate().subject?.CN).toBe("blocked.invalid");
    deniedTunnel.socket.destroy();

    // Expired marker: still enforce mode.
    writeMarker(paths.markerPath, { expiresInMs: -60_000 });
    const expiredTunnel = await openConnectTunnel({
      proxyPort: proxy.port,
      authority: `${auditedHost}:443`,
    });
    const expiredTls = await tlsHandshakeOverTunnel(expiredTunnel.socket, auditedHost);
    expect(expiredTls.getPeerCertificate().subject?.CN).toBe("blocked.invalid");
    expiredTunnel.socket.destroy();

    // Valid marker: the CONNECT passes through to mockttp, which mints a
    // CA-signed leaf for the requested hostname instead of the denial leaf.
    writeMarker(paths.markerPath);
    const auditedTunnel = await openConnectTunnel({
      proxyPort: proxy.port,
      authority: `${auditedHost}:443`,
    });
    expect(auditedTunnel.head.statusCode).toBe(200);
    const auditedTls = await tlsHandshakeOverTunnel(auditedTunnel.socket, auditedHost);
    expect(auditedTls.getPeerCertificate().subject?.CN).toBe(auditedHost);
    auditedTunnel.socket.destroy();

    await proxy.waitForOutput(new RegExp(`proxy-audit: \\{"v":1,[^\\n]*"host":"${auditedHost.replaceAll(".", "\\.")}"`));
    await waitUntil(() => {
      try {
        return fs.readFileSync(paths.spoolPath, "utf8").includes(`${auditedHost}\n`);
      } catch {
        return false;
      }
    }, "audited CONNECT host spooled");

    // Non-443 and malformed CONNECTs keep the raw pre-TLS rejection in audit
    // mode too.
    const port = await rawConnectViaProxy({
      proxyPort: proxy.port,
      authority: `${auditedHost}:8443`,
    });
    expect(port.statusCode).toBe(403);
    expect(port.body).toContain("blocked non-HTTPS CONNECT port: 8443");
    const malformed = await rawConnectViaProxy({
      proxyPort: proxy.port,
      authority: "bad authority",
    });
    expect(malformed.statusCode).toBe(403);
    expect(malformed.body).toContain("blocked malformed CONNECT request");
  }, 20_000);

  test("destroys registered audited tunnel sockets on the marker inactive transition without a new request", async () => {
    const auditedHost = "expiring-audited.example.test";
    const paths = auditPaths();
    writeMarker(paths.markerPath);
    const proxy = await startProxy({
      extraEnv: paths.env,
      policy: { hosts: [], tokens: {} },
    });
    await proxy.waitForOutput("proxy-audit: network audit mode ACTIVE");

    const tunnel = await openConnectTunnel({
      proxyPort: proxy.port,
      authority: `${auditedHost}:443`,
    });
    expect(tunnel.head.statusCode).toBe(200);

    fs.rmSync(paths.markerPath);
    const closed = await Promise.race([
      new Promise<boolean>((resolve) => tunnel.socket.once("close", () => resolve(true))),
      new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 5_000)),
    ]);
    expect(closed, "audited tunnel socket should be destroyed when the marker goes inactive").toBe(true);
    await proxy.waitForOutput("proxy-audit: network audit mode ended");
  }, 20_000);

  test("allowlisted hosts keep enforce-path token injection during audit; OAuth handle mediation is unchanged", async () => {
    const auditedHost = "audited-mcp.example.test";
    const upstream = await startHttpsUpstream();
    const enforceResolvedHostsPath = path.join(tmp, "resolved-hosts.json");
    writeResolvedHostsFile(enforceResolvedHostsPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: { [auditedHost]: ["127.0.0.1"] },
    });
    const paths = auditPaths({
      NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
      PROXY_RESOLVED_HOSTS_PATH: enforceResolvedHostsPath,
    });
    writeMarker(paths.markerPath);
    const proxy = await startProxy({
      extraEnv: paths.env,
      policy: {
        hosts: ["127.0.0.1"],
        tokens: {
          github: {
            description: "GitHub token",
            credentials: [
              { host: "127.0.0.1", header: "Authorization", scheme: "bearer" },
            ],
          },
        },
      },
      secretFiles: { github: "real-proxy-token\n" },
    });

    // The allowlisted host behaves identically in both modes, including
    // injection.
    const allowed = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/v1/data",
      headers: { Authorization: "Bearer agent-placeholder" },
    });
    expect(allowed.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].headers.authorization).toBe("Bearer real-proxy-token");

    // An OAuth bearer handle toward an audited host fails exactly as in
    // enforce mode, before any upstream contact.
    const handleResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetHost: auditedHost,
      targetPort: upstream.port,
      path: "/mcp",
      headers: { Authorization: "Bearer runfree_oauth_access_unknown-audit-handle" },
    });
    expect(handleResponse.statusCode).toBe(403);
    expect(handleResponse.body).toContain("unknown OAuth token handle");
    expect(upstream.requests).toHaveLength(1);
    expect(proxy.output()).not.toContain("runfree_oauth_access_unknown-audit-handle");
  }, 20_000);

  // KNOWN LIMITATION (finding 6): mockttp 4.4.2's WebSocket passthrough mirrors
  // the client's raw upgrade headers exactly and exposes no header transform or
  // per-request callback, so the union credential-header strip the HTTP audit
  // path applies cannot be applied to an audited WSS upgrade. The audited WSS
  // path is still reached and observed (proven below); the residual gap is that
  // a configured credential header on the upgrade is forwarded rather than
  // stripped. This test pins the path being exercised and that the proxy never
  // logs the credential value; tighten it to assert stripping once mockttp can
  // transform WS upgrade headers. (A full upstream round-trip cannot be tested
  // here because a CONNECT tunnel forces mockttp to dial the audited host on the
  // privileged port 443, unreachable in the unprivileged test harness.)
  test("audited WSS upgrade is observed; configured credential header is forwarded (mockttp WS limitation) and never logged", async () => {
    const auditedHost = "audited-ws.example.test";
    const enforceResolvedHostsPath = path.join(tmp, "resolved-hosts.json");
    writeResolvedHostsFile(enforceResolvedHostsPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: {},
    });
    const { certPath } = createUpstreamCertificate(tmp, {
      commonName: auditedHost,
      subjectAltName: `DNS:${auditedHost}`,
    });
    const paths = auditPaths({
      NODE_EXTRA_CA_CERTS: certPath,
      PROXY_RESOLVED_HOSTS_PATH: enforceResolvedHostsPath,
    });
    writeResolvedHostsFile(paths.auditResolvedHostsPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: { [auditedHost]: ["127.0.0.1"] },
    });
    writeMarker(paths.markerPath);
    const proxy = await startProxy({
      extraEnv: paths.env,
      // Authorization is a configured credential header for a different
      // (allowlisted) host; the audited WSS path cannot strip the union today.
      policy: {
        hosts: ["allowed.example"],
        tokens: {
          github: {
            description: "GitHub token",
            credentials: [
              { host: "allowed.example", header: "Authorization", scheme: "bearer" },
            ],
          },
        },
      },
    });

    // CONNECT to the audited host on 443, then send a raw WSS upgrade carrying
    // a configured credential header. mockttp routes it through the audited WS
    // passthrough rule, which observes the host; the upstream dial to 443 then
    // fails, but observation has already fired.
    const tunnel = await openConnectTunnel({
      proxyPort: proxy.port,
      authority: `${auditedHost}:443`,
    });
    expect(tunnel.head.statusCode).toBe(200);
    const tlsSocket = await tlsHandshakeOverTunnel(tunnel.socket, auditedHost);
    tlsSocket.on("error", () => {});
    tlsSocket.on("data", () => {});
    tlsSocket.write([
      `GET /socket HTTP/1.1`,
      `Host: ${auditedHost}`,
      "Upgrade: websocket",
      "Connection: Upgrade",
      "Sec-WebSocket-Version: 13",
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
      "Authorization: Bearer agent-forged-ws-credential",
      "",
      "",
    ].join("\r\n"));

    // The audited WSS upgrade reaches the audit observation path.
    await proxy.waitForOutput(
      new RegExp(`proxy-audit: \\{"v":1,[^\\n]*"host":"${auditedHost.replaceAll(".", "\\.")}"`),
    );
    tunnel.socket.destroy();
    // The configured credential value never appears in proxy logs regardless of
    // the header-forwarding limitation.
    expect(proxy.output()).not.toContain("agent-forged-ws-credential");
  }, 20_000);
});
