import fs from "node:fs";
import path from "node:path";
import { validateNetworkPolicy } from "@runfree/runtime-contracts/network-policy";
import { describe, expect, test } from "vitest";
import { writeResolvedHostsFile } from "./resolved-hosts.ts";
import { tmp, readJson, replaceJson, unusedTcpPort, startProxy, startHttpsUpstream, startSseUpstream, readUntilWithTimeout, proxyRequestEvents, httpsViaProxy, openConnectTunnel, rawConnectViaProxy, tlsHandshakeOverTunnel } from "./server.test-harness.ts";

describe("proxy server entrypoint: core", () => {
  test("accepts denied 443 CONNECTs for in-tunnel denial; rejects non-HTTPS ports and malformed CONNECTs before TLS", async () => {
    const proxy = await startProxy({
      policy: { hosts: ["api.github.com"], tokens: {} },
    });

    // A denied host on 443 now passes the guard so the agent can read an
    // in-tunnel synthetic 403 after TLS.
    const disallowedHost = await rawConnectViaProxy({
      proxyPort: proxy.port,
      authority: "disallowed.example:443",
    });
    expect(disallowedHost.statusCode).toBe(200);
    // Closing the tunnel without a request still records exactly one denial:
    // a structured event without method/path (the only denial log format).
    await proxy.waitForOutput(/proxy-denial: \{"v":1,[^\n]*"reason":"host-not-allowlisted","host":"disallowed\.example","generation":"sha256:[a-f0-9]{64}"\}/);

    const disallowedPort = await rawConnectViaProxy({
      proxyPort: proxy.port,
      authority: "api.github.com:22",
    });
    expect(disallowedPort.statusCode).toBe(403);
    expect(disallowedPort.body).toContain("blocked non-HTTPS CONNECT port: 22");
    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"non-https-port","host":"api\.github\.com"/);

    const deniedHostAndPort = await rawConnectViaProxy({
      proxyPort: proxy.port,
      authority: "disallowed.example:8443",
    });
    expect(deniedHostAndPort.statusCode).toBe(403);
    expect(deniedHostAndPort.body).toContain("blocked non-HTTPS CONNECT port: 8443");

    const malformed = await rawConnectViaProxy({
      proxyPort: proxy.port,
      authority: "bad authority",
    });
    expect(malformed.statusCode).toBe(403);
    expect(malformed.body).toContain("blocked malformed CONNECT request");
    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"malformed-connect","host":"<unparseable>"/);
  }, 20_000);

  test("persists proxy CA material and reuses it across restarts without logging secret values", async () => {
    const stateDir = path.join(tmp, "proxy");
    const policy = {
      hosts: ["127.0.0.1"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "127.0.0.1", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    };

    const first = await startProxy({
      policy,
      secretFiles: { github: "super-secret-token\n" },
      stateDir,
      umask: 0o077,
    });
    const firstCert = fs.readFileSync(first.caCertPath, "utf8");
    const firstKey = fs.readFileSync(first.caKeyPath, "utf8");
    expect(firstCert).toContain("BEGIN CERTIFICATE");
    expect(firstKey).toContain("BEGIN");
    expect(fs.statSync(first.caCertPath).mode & 0o777).toBe(0o644);
    expect(fs.statSync(first.caKeyPath).mode & 0o777).toBe(0o600);
    expect(first.output()).toContain("tokens=[github]");
    expect(first.output()).not.toContain("super-secret-token");
    await first.stop();
    fs.chmodSync(first.caCertPath, 0o600);

    const second = await startProxy({
      policy,
      secretFiles: { github: "super-secret-token\n" },
      stateDir,
      umask: 0o077,
    });
    expect(fs.readFileSync(second.caCertPath, "utf8")).toBe(firstCert);
    expect(fs.readFileSync(second.caKeyPath, "utf8")).toBe(firstKey);
    expect(fs.statSync(second.caCertPath).mode & 0o777).toBe(0o644);
    expect(fs.statSync(second.caKeyPath).mode & 0o777).toBe(0o600);
    expect(second.output()).not.toContain("super-secret-token");
  }, 20_000);

  test("returns a policy denial instead of a server error when a required token is missing", async () => {
    const upstream = await startHttpsUpstream();
    const proxy = await startProxy({
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

    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/v1/scrape",
      headers: {
        Authorization: "Bearer agent-placeholder",
      },
    });

    expect(response.statusCode).toBe(403);
    expect(response.body).toContain("missing required proxy token: firecrawl");
    expect(response.body).toContain("runfree credential set-source firecrawl --from-env FIRECRAWL_TOKEN");
    expect(upstream.requests).toHaveLength(0);
  }, 20_000);

  test("streams an allowlisted response incrementally instead of buffering until the upstream ends", async () => {
    // Regression: a single forAnyRequest() pass-through carrying beforeResponse
    // made mockttp buffer the entire upstream response, so streaming endpoints
    // (api.anthropic.com/v1/messages) stalled until the upstream finished. The
    // upstream here flushes one SSE chunk and holds the connection open; a
    // streaming proxy delivers that chunk immediately, a buffering one never
    // does.
    const upstream = await startSseUpstream();
    const proxy = await startProxy({
      extraEnv: { NODE_EXTRA_CA_CERTS: upstream.certPath },
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });

    // Use the same admitted CONNECT+TLS path as production clients, while
    // reading the response incrementally instead of buffering to end.
    const tunnel = await openConnectTunnel({ authority: "127.0.0.1:443", proxyPort: proxy.port });
    expect(tunnel.head.statusCode).toBe(200);
    const socket = await tlsHandshakeOverTunnel(tunnel.socket);
    socket.write([
      `POST https://127.0.0.1:${upstream.port}/v1/messages HTTP/1.1`,
      `Host: 127.0.0.1:${upstream.port}`,
      "Accept: text/event-stream",
      "Connection: close",
      "",
      "",
    ].join("\r\n"));

    // Reaches the client well before finishAll(): proves the body streams. On
    // the buffering bug this rejects via the timeout instead of hanging the run.
    const firstChunk = await readUntilWithTimeout(socket, "data: first", 8_000);
    expect(firstChunk.toString("utf8")).toContain("data: first");
    expect(firstChunk.toString("utf8")).not.toContain("data: last");

    upstream.finishAll();
    const full = await readUntilWithTimeout(socket, "data: last", 8_000);
    expect(full.toString("utf8")).toContain("data: last");

    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0]?.url).toBe("/v1/messages");

    socket.destroy();
    await upstream.stop();
    await proxy.stop();
  }, 30_000);

  test("forces identity upstream response encoding for Claude streaming requests to avoid zlib failures", async () => {
    const targetHost = "api.anthropic.com";
    const upstream = await startHttpsUpstream({
      commonName: targetHost,
      subjectAltName: `DNS:${targetHost}`,
    });
    const resolvedHostsPath = path.join(tmp, "resolved-hosts.json");
    writeResolvedHostsFile(resolvedHostsPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: {
        [targetHost]: ["127.0.0.1"],
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: upstream.certPath,
        PROXY_RESOLVED_HOSTS_PATH: resolvedHostsPath,
      },
      policy: { hosts: [targetHost], tokens: {}, writeApproval: "allow" },
    });

    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      targetHost,
      targetPort: upstream.port,
      path: "/v1/messages",
      headers: {
        Accept: "text/event-stream",
        "Accept-Encoding": "gzip, deflate, br",
      },
    });

    expect(response.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].headers["accept-encoding"]).toBe("identity");

    await upstream.stop();
    await proxy.stop();
  }, 20_000);

  test("preserves upstream response compression negotiation for non-streaming Claude requests", async () => {
    const targetHost = "api.anthropic.com";
    const upstream = await startHttpsUpstream({
      commonName: targetHost,
      subjectAltName: `DNS:${targetHost}`,
    });
    const resolvedHostsPath = path.join(tmp, "resolved-hosts.json");
    writeResolvedHostsFile(resolvedHostsPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: {
        [targetHost]: ["127.0.0.1"],
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: upstream.certPath,
        PROXY_RESOLVED_HOSTS_PATH: resolvedHostsPath,
      },
      policy: { hosts: [targetHost], tokens: {}, writeApproval: "allow" },
    });

    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      targetHost,
      targetPort: upstream.port,
      path: "/v1/organizations",
      headers: {
        "Accept-Encoding": "gzip, deflate, br",
      },
    });

    expect(response.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].headers["accept-encoding"]).toBe("gzip, deflate, br");

    await upstream.stop();
    await proxy.stop();
  }, 20_000);

  test("preserves upstream response compression negotiation for non-Claude hosts", async () => {
    const upstream = await startHttpsUpstream();
    const proxy = await startProxy({
      extraEnv: { NODE_EXTRA_CA_CERTS: upstream.certPath },
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });

    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/v1/messages",
      headers: {
        "Accept-Encoding": "gzip, deflate, br",
      },
    });

    expect(response.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].headers["accept-encoding"]).toBe("gzip, deflate, br");

    await upstream.stop();
    await proxy.stop();
  }, 20_000);

  test("uses firewall-published resolved hosts instead of unprivileged proxy-server DNS", async () => {
    const targetHost = "blocked-dns.test";
    const upstream = await startHttpsUpstream({
      commonName: targetHost,
      subjectAltName: `DNS:${targetHost}`,
    });
    const resolvedHostsPath = path.join(tmp, "resolved-hosts.json");
    writeResolvedHostsFile(resolvedHostsPath, {
      generation: `sha256:${"a".repeat(64)}`,
      hosts: {
        [targetHost]: ["127.0.0.1"],
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: upstream.certPath,
        PROXY_RESOLVED_HOSTS_PATH: resolvedHostsPath,
      },
      policy: { hosts: [targetHost], tokens: {}, writeApproval: "allow" },
    });

    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      targetHost,
      targetPort: upstream.port,
      path: "/rate_limit",
    });

    expect(response.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].headers.host).toBe(`${targetHost}:${upstream.port}`);
  }, 20_000);

  test("logs upstream passthrough failures with redacted request metadata", async () => {
    const targetPort = await unusedTcpPort();
    const proxy = await startProxy({
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });
    fs.writeFileSync(path.join(proxy.verboseDir, "enabled"), "");

    const response = await httpsViaProxy({
      body: "{}",
      headers: {
        Authorization: "Bearer agent-placeholder",
      },
      method: "POST",
      proxyPort: proxy.port,
      targetPort,
      path: "/v1/messages?api_key=agent-query-token",
    });

    expect(response.statusCode).toBe(502);
    await proxy.waitForOutput(/proxy-request: [^\n]*"event":"passthrough_abort"[^\n]*"path":"\/v1\/messages"/);
    const events = proxyRequestEvents(proxy.output())
      .filter((event) => event.host === "127.0.0.1" && event.path === "/v1/messages");
    expect(events.find((event) => event.event === "passthrough_abort")).toMatchObject({
      method: "POST",
      scheme: "https",
      host: "127.0.0.1",
      path: "/v1/messages",
      side: "upstream",
      error_code: "ECONNREFUSED",
    });
    expect(proxy.output()).not.toContain("api_key=agent-query-token");
    expect(proxy.output()).not.toContain("agent-placeholder");
    expect(proxy.output()).not.toContain("Bearer");
  }, 20_000);

  test("reloads policy atomically, injects credentials only after allowlisting, and keeps the last valid policy after invalid edits", async () => {
    const upstream = await startHttpsUpstream();
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
      },
      policy: { hosts: [], tokens: {} },
    });

    const blocked = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/v1/models?api_key=agent-query-token",
      headers: {
        Authorization: "Bearer agent-placeholder",
        "X-Keep": "still-forwarded-after-allow",
      },
    });
    expect(blocked.statusCode).toBe(403);
    expect(blocked.raw).toContain("x-runfree-blocked: host-not-allowlisted");
    expect(blocked.body).toContain("Runfree blocked this request.");
    expect(blocked.body).toContain("host:   127.0.0.1");
    expect(blocked.body).toContain("runfree host add 127.0.0.1");
    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"host-not-allowlisted","host":"127\.0\.0\.1"/);
    expect(upstream.requests).toHaveLength(0);

    fs.writeFileSync(path.join(proxy.secretDir, "github"), "real-proxy-token\n");
    fs.writeFileSync(path.join(proxy.verboseDir, "enabled"), "");
    replaceJson(proxy.policyPath, {
      hosts: ["127.0.0.1"],
      tokens: {
        github: {
          description: "GitHub token",
          credentials: [
            { host: "127.0.0.1", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });
    await proxy.waitForOutput("proxy: policy reloaded");

    const allowed = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/v1/models?api_key=agent-query-token",
      headers: {
        Authorization: "Bearer agent-placeholder",
        "X-Keep": "still-forwarded-after-allow",
      },
    });
    expect(allowed.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].url).toBe("/v1/models?api_key=agent-query-token");
    expect(upstream.requests[0].headers.authorization).toBe("Bearer real-proxy-token");
    expect(upstream.requests[0].headers["x-keep"]).toBe("still-forwarded-after-allow");

    await proxy.waitForOutput("proxy: allowed method=GET scheme=https host=127.0.0.1 path=/v1/models");
    expect(proxy.output()).not.toContain("agent-query-token");
    expect(proxy.output()).not.toContain("agent-placeholder");
    expect(proxy.output()).not.toContain("real-proxy-token");

    await proxy.waitForOutput(/proxy-request: [^\n]*"event":"response_head"[^\n]*"path":"\/v1\/models"/);
    const requestEvents = proxyRequestEvents(proxy.output())
      .filter((event) => event.host === "127.0.0.1" && event.path === "/v1/models");
    const eventNames = requestEvents.map((event) => event.event);
    expect(eventNames).toContain("admitted");
    expect(eventNames).toContain("upstream_request");
    expect(eventNames).toContain("response_head");

    const requestIds = new Set(requestEvents.map((event) => event.id));
    expect(requestIds.size).toBe(1);
    expect(requestEvents.find((event) => event.event === "admitted")).toMatchObject({
      method: "GET",
      scheme: "https",
      host: "127.0.0.1",
      path: "/v1/models",
      policy_generation: validateNetworkPolicy(
        readJson<Parameters<typeof validateNetworkPolicy>[0]>(proxy.policyPath),
      ).generation,
      credential_action: "injected",
      credential_headers: ["Authorization"],
      token_names: ["github"],
    });
    expect(requestEvents.find((event) => event.event === "response_head")).toMatchObject({
      status: 200,
    });
    expect(proxy.output()).not.toContain("api_key=agent-query-token");
    expect(proxy.output()).not.toContain("Bearer");

    replaceJson(proxy.policyPath, { hosts: ["UPPER.EXAMPLE"], tokens: {} });
    await proxy.waitForOutput("proxy: policy reload failed; keeping last valid policy");
    expect(proxy.output()).toMatch(/previous_generation=sha256:[a-f0-9]{64}/);

    const afterInvalidReload = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/v1/after-invalid-policy",
      headers: { Authorization: "Bearer agent-placeholder" },
    });
    expect(afterInvalidReload.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(2);
    expect(upstream.requests[1].headers.authorization).toBe("Bearer real-proxy-token");
  }, 20_000);

  test("denies request-shape mismatches in-tunnel before credential injection and OAuth mediation", async () => {
    const upstream = await startHttpsUpstream();
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
      },
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
        requests: {
          "127.0.0.1": { methods: ["GET"], writeAction: "allow" },
        },
        writeApproval: "allow",
      },
      secretFiles: { github: "real-proxy-token\n" },
    });
    expect(proxy.output()).toContain("request_rule_hosts=[127.0.0.1]");

    // Allowed verb: passes shape, credential injection still applies, and the
    // method-override header is stripped on the method-ruled host.
    const allowed = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/v1/data",
      headers: {
        Authorization: "Bearer agent-placeholder",
        "X-HTTP-Method-Override": "DELETE",
        "X-Keep": "still-forwarded",
      },
    });
    expect(allowed.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].headers.authorization).toBe("Bearer real-proxy-token");
    expect(upstream.requests[0].headers["x-http-method-override"]).toBeUndefined();
    expect(upstream.requests[0].headers["x-keep"]).toBe("still-forwarded");

    // Disallowed verb: synthetic in-tunnel 403 carrying the shape reason and
    // the exact widening command; the upstream never sees the request and the
    // injected credential is never attached to the denial response.
    const denied = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/v1/data?api_key=agent-query-secret",
      body: "exfil-payload",
      headers: {
        Authorization: "Bearer agent-placeholder",
        "content-type": "text/plain",
      },
    });
    expect(denied.statusCode).toBe(403);
    expect(denied.raw).toContain("x-runfree-blocked: method-not-allowed");
    expect(denied.body).toContain("Runfree blocked this request.");
    expect(denied.body).toContain("method: POST");
    expect(denied.body).toContain("reason: method is not permitted for this host (allowed: GET)");
    expect(denied.body).toContain("runfree host rules 127.0.0.1 --method GET --method POST");
    expect(denied.raw).not.toContain("real-proxy-token");
    expect(upstream.requests).toHaveLength(1);
    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"method-not-allowed","host":"127\.0\.0\.1","method":"POST","path":"\/v1\/data"/);
    expect(proxy.output()).not.toContain("agent-query-secret");

    // A request carrying an OAuth bearer handle is shape-denied before
    // OAuth mediation runs: the denial names the shape reason, not the
    // unknown-handle mediation error, and the upstream is never contacted.
    const deniedMcp = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/mcp",
      headers: {
        Authorization: "Bearer runfree_oauth_access_test-handle-value",
      },
    });
    expect(deniedMcp.statusCode).toBe(403);
    expect(deniedMcp.raw).toContain("x-runfree-blocked: method-not-allowed");
    expect(deniedMcp.body).not.toContain("MCP");
    expect(upstream.requests).toHaveLength(1);
  }, 20_000);

  test("reloads request rules live: tighten denies, loosen permits, invalid edits keep the last valid rules", async () => {
    const upstream = await startHttpsUpstream();
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
      },
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });
    const post = async () => await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/v1/data",
      headers: {},
    });

    // No rules: all methods pass (today's behavior).
    expect((await post()).statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(1);

    // Tighten: a requests-only edit converges to the generation computed by
    // the shared validateNetworkPolicy and the next POST is denied without
    // restart.
    const tightenedPolicy = {
      hosts: ["127.0.0.1"],
      tokens: {},
      requests: { "127.0.0.1": { methods: ["GET"], writeAction: "allow" } },
      writeApproval: "allow",
    };
    replaceJson(proxy.policyPath, tightenedPolicy);
    await proxy.waitForOutput(`proxy: policy reloaded, generation=${validateNetworkPolicy(tightenedPolicy).generation}`);
    const denied = await post();
    expect(denied.statusCode).toBe(403);
    expect(denied.raw).toContain("x-runfree-blocked: method-not-allowed");
    expect(upstream.requests).toHaveLength(1);

    // Invalid edit: the previous valid rules stay enforced.
    replaceJson(proxy.policyPath, {
      hosts: ["127.0.0.1"],
      tokens: {},
      requests: { "127.0.0.1": { methods: ["FETCH"] } },
    });
    await proxy.waitForOutput("proxy: policy reload failed; keeping last valid policy");
    const deniedAfterInvalid = await post();
    expect(deniedAfterInvalid.statusCode).toBe(403);
    expect(deniedAfterInvalid.raw).toContain("x-runfree-blocked: method-not-allowed");
    expect(upstream.requests).toHaveLength(1);

    // Loosen: the next POST passes.
    const loosenedPolicy = {
      hosts: ["127.0.0.1"],
      tokens: {},
      requests: { "127.0.0.1": { methods: ["GET", "POST"], writeAction: "allow" } },
      writeApproval: "allow",
    };
    replaceJson(proxy.policyPath, loosenedPolicy);
    await proxy.waitForOutput(`proxy: policy reloaded, generation=${validateNetworkPolicy(loosenedPolicy).generation}`);
    const loosened = await post();
    expect(loosened.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(2);
  }, 20_000);

});
