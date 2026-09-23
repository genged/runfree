import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "vitest";
import { tmp, writeJson, replaceJson, waitUntil, startProxy, startMcpOAuthUpstream, httpsViaProxy } from "./server.test-harness.ts";

describe("proxy server entrypoint: OAuth mediation", () => {
  test("substitutes OAuth token handles while keeping real tokens proxy-side", async () => {
    const upstream = await startMcpOAuthUpstream();
    const mcpOAuthPolicyPath = path.join(tmp, "oauth-mediation-policy.json");
    const mcpOAuthStateDir = path.join(tmp, "mcp-oauth-state");
    writeJson(mcpOAuthPolicyPath, {
      servers: {
        sentry: {
          resourceHost: "127.0.0.1",
          resourcePathPrefix: "/mcp",
          tokenHost: "127.0.0.1",
          tokenPath: "/oauth/token",
        },
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
        RUNFREE_OAUTH_POLICY: mcpOAuthPolicyPath,
        RUNFREE_OAUTH_STATE_DIR: mcpOAuthStateDir,
      },
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });

    const tokenResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/token",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "grant_type=authorization_code&code=secret-authorization-code",
    });
    expect(tokenResponse.statusCode).toBe(200);
    const tokenBody = JSON.parse(tokenResponse.body) as {
      access_token: string;
      client_secret: string;
      refresh_token: string;
    };
    expect(tokenBody.access_token).toMatch(/^runfree_oauth_access_/);
    expect(tokenBody.refresh_token).toMatch(/^runfree_oauth_refresh_/);
    expect(tokenBody.client_secret).toMatch(/^runfree_oauth_secret_/);
    expect(tokenResponse.body).toMatch(/runfree_oauth_secret_/);
    expect(tokenResponse.body).not.toContain("real-access-token-1");
    expect(tokenResponse.body).not.toContain("real-refresh-token-1");
    expect(tokenResponse.body).not.toContain("real-id-token-1");
    expect(tokenResponse.body).not.toContain("real-client-secret-1");
    expect(tokenResponse.body).not.toContain("real-registration-token-1");

    const resourceResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/mcp",
      headers: { Authorization: `Bearer ${tokenBody.access_token}` },
    });
    expect(resourceResponse.statusCode).toBe(200);
    expect(upstream.requests.find((request) => request.url === "/mcp")?.headers.authorization)
      .toBe("Bearer real-access-token-1");

    const outsideResourceResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/mcp-evil",
      headers: { Authorization: `Bearer ${tokenBody.access_token}` },
    });
    expect(outsideResourceResponse.statusCode).toBe(403);
    expect(outsideResourceResponse.body).toContain("wrong resource");
    expect(upstream.requests.some((request) => request.url === "/mcp-evil")).toBe(false);

    const refreshResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/token",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: [
        "grant_type=refresh_token",
        `refresh_token=${encodeURIComponent(tokenBody.refresh_token)}`,
        `client_secret=${encodeURIComponent(tokenBody.client_secret)}`,
      ].join("&"),
    });
    expect(refreshResponse.statusCode).toBe(200);
    const refreshBody = JSON.parse(refreshResponse.body) as { access_token: string; refresh_token: string };
    expect(refreshBody.access_token).toMatch(/^runfree_oauth_access_/);
    expect(refreshBody.refresh_token).toMatch(/^runfree_oauth_refresh_/);
    expect(refreshResponse.body).not.toContain("real-access-token-2");
    expect(refreshResponse.body).not.toContain("real-refresh-token-2");
    const upstreamRefreshBody = upstream.requests.find((request) => request.body.includes("grant_type=refresh_token"))?.body ?? "";
    expect(upstreamRefreshBody).toContain("refresh_token=real-refresh-token-1");
    expect(upstreamRefreshBody).toContain("client_secret=real-client-secret-1");
    expect(upstreamRefreshBody).not.toContain(tokenBody.client_secret);

    const stored = fs.readFileSync(path.join(mcpOAuthStateDir, "handles.json"), "utf8");
    expect(stored).toContain("real-access-token-1");
    expect(stored).toContain("real-refresh-token-1");
    expect(stored).toContain("real-id-token-1");
    expect(stored).toContain("real-client-secret-1");
    expect(stored).toContain("real-registration-token-1");
    expect(fs.statSync(path.join(mcpOAuthStateDir, "handles.json")).mode & 0o777).toBe(0o600);
    expect(proxy.output()).not.toContain("real-access-token");
    expect(proxy.output()).not.toContain("real-refresh-token");
    expect(proxy.output()).not.toContain("real-id-token");
    expect(proxy.output()).not.toContain("real-client-secret");
    expect(proxy.output()).not.toContain("real-registration-token");
    expect(proxy.output()).not.toContain("secret-authorization-code");
    expect(proxy.output()).not.toContain(tokenBody.access_token);
    expect(proxy.output()).not.toContain(tokenBody.refresh_token);
  }, 20_000);

  test("composes OAuth mediation with static header injection on the same resource request", async () => {
    const upstream = await startMcpOAuthUpstream({
      tokenResponseBody: JSON.stringify({
        access_token: "real-service-access-token",
        expires_in: 3600,
        token_type: "Bearer",
      }),
    });
    const oauthPolicyPath = path.join(tmp, "oauth-policy.json");
    const oauthStateDir = path.join(tmp, "oauth-state");
    const refreshHandle = "runfree_oauth_refresh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const secretHandle = "runfree_oauth_secret_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    writeJson(oauthPolicyPath, {
      providers: {
        "service:google-ads": {
          kind: "service",
          resourceHost: "127.0.0.1",
          resourcePathPrefix: "/",
          tokenEndpoints: ["https://127.0.0.1/oauth/token"],
          seeds: [
            { field: "refresh_token", handle: refreshHandle, secretRef: "oauth-google-ads-refresh-token" },
            { field: "client_secret", handle: secretHandle, secretRef: "oauth-google-ads-client-secret" },
          ],
        },
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
        RUNFREE_OAUTH_POLICY: oauthPolicyPath,
        RUNFREE_OAUTH_STATE_DIR: oauthStateDir,
      },
      policy: {
        hosts: ["127.0.0.1"],
        writeApproval: "allow",
        tokens: {
          "google-ads-developer-token": {
            description: "Google Ads developer token",
            credentials: [
              { host: "127.0.0.1", header: "developer-token", scheme: "raw" },
            ],
          },
        },
      },
      secretFiles: {
        "google-ads-developer-token": "real-developer-token\n",
        "oauth-google-ads-client-secret": "real-client-secret\n",
        "oauth-google-ads-refresh-token": "real-refresh-token\n",
      },
    });

    const tokenResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/token",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: [
        "grant_type=refresh_token",
        `refresh_token=${encodeURIComponent(refreshHandle)}`,
        `client_secret=${encodeURIComponent(secretHandle)}`,
      ].join("&"),
    });
    const tokenBody = JSON.parse(tokenResponse.body) as { access_token: string };
    expect(tokenBody.access_token).toMatch(/^runfree_oauth_access_/);
    const upstreamTokenBody = upstream.requests.find((request) => request.url === "/oauth/token")?.body ?? "";
    expect(upstreamTokenBody).toContain("refresh_token=real-refresh-token");
    expect(upstreamTokenBody).toContain("client_secret=real-client-secret");

    const resourceResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/mcp",
      headers: {
        Authorization: `Bearer ${tokenBody.access_token}`,
        "developer-token": "runfree-placeholder-overwritten-by-proxy",
      },
    });

    expect(resourceResponse.statusCode).toBe(200);
    const resourceRequest = upstream.requests.find((request) => request.url === "/mcp");
    expect(resourceRequest?.headers.authorization).toBe("Bearer real-service-access-token");
    expect(resourceRequest?.headers["developer-token"]).toBe("real-developer-token");
    expect(proxy.output()).not.toContain("real-service-access-token");
    expect(proxy.output()).not.toContain("real-refresh-token");
    expect(proxy.output()).not.toContain("real-client-secret");
    expect(proxy.output()).not.toContain(tokenBody.access_token);
  }, 20_000);

  test("mediates in-flight OAuth token responses after policy changes", async () => {
    const upstream = await startMcpOAuthUpstream({ tokenResponseDelayMs: 100 });
    const mcpOAuthPolicyPath = path.join(tmp, "oauth-mediation-policy.json");
    const mcpOAuthStateDir = path.join(tmp, "mcp-oauth-state");
    writeJson(mcpOAuthPolicyPath, {
      servers: {
        sentry: {
          resourceHost: "127.0.0.1",
          resourcePathPrefix: "/mcp",
          tokenHost: "127.0.0.1",
          tokenPath: "/oauth/token",
        },
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
        RUNFREE_OAUTH_POLICY: mcpOAuthPolicyPath,
        RUNFREE_OAUTH_STATE_DIR: mcpOAuthStateDir,
      },
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });

    const tokenResponse = httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/token",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "grant_type=authorization_code&code=secret-authorization-code",
    });
    await waitUntil(() => upstream.requests.some((request) => request.url === "/oauth/token"), "upstream token request");
    replaceJson(mcpOAuthPolicyPath, { servers: {} });

    const response = await tokenResponse;

    expect(response.statusCode).toBe(200);
    expect(response.body).not.toContain("real-access-token-1");
    expect(response.body).not.toContain("real-refresh-token-1");
    expect(response.body).not.toContain("real-client-secret-1");
    const body = JSON.parse(response.body) as { access_token: string; refresh_token: string };
    expect(body.access_token).toMatch(/^runfree_oauth_access_/);
    expect(body.refresh_token).toMatch(/^runfree_oauth_refresh_/);
  }, 20_000);

  test("mediates OAuth token responses regardless of response content type", async () => {
    const upstream = await startMcpOAuthUpstream({ tokenContentType: "text/plain" });
    const mcpOAuthPolicyPath = path.join(tmp, "oauth-mediation-policy.json");
    const mcpOAuthStateDir = path.join(tmp, "mcp-oauth-state");
    writeJson(mcpOAuthPolicyPath, {
      servers: {
        sentry: {
          resourceHost: "127.0.0.1",
          resourcePathPrefix: "/mcp",
          tokenHost: "127.0.0.1",
          tokenPath: "/oauth/token",
        },
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
        RUNFREE_OAUTH_POLICY: mcpOAuthPolicyPath,
        RUNFREE_OAUTH_STATE_DIR: mcpOAuthStateDir,
      },
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });

    const tokenResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/token",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "grant_type=authorization_code&code=secret-authorization-code",
    });

    expect(tokenResponse.statusCode).toBe(200);
    const tokenBody = JSON.parse(tokenResponse.body) as { access_token: string; refresh_token: string };
    expect(tokenBody.access_token).toMatch(/^runfree_oauth_access_/);
    expect(tokenBody.refresh_token).toMatch(/^runfree_oauth_refresh_/);
    expect(tokenResponse.body).not.toContain("real-access-token-1");
    expect(tokenResponse.body).not.toContain("real-refresh-token-1");
    expect(tokenResponse.body).not.toContain("real-client-secret-1");
  }, 20_000);

  test("blocks malformed OAuth token responses from known token endpoints", async () => {
    const upstream = await startMcpOAuthUpstream({
      tokenContentType: null,
      tokenResponseBody: "access_token=real-access-token-1&client_secret=real-client-secret-1",
    });
    const mcpOAuthPolicyPath = path.join(tmp, "oauth-mediation-policy.json");
    writeJson(mcpOAuthPolicyPath, {
      servers: {
        sentry: {
          resourceHost: "127.0.0.1",
          resourcePathPrefix: "/mcp",
          tokenHost: "127.0.0.1",
          tokenPath: "/oauth/token",
        },
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
        RUNFREE_OAUTH_POLICY: mcpOAuthPolicyPath,
      },
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });

    const tokenResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/token",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "grant_type=authorization_code&code=secret-authorization-code",
    });

    expect(tokenResponse.statusCode).toBe(200);
    expect(tokenResponse.body).toContain("malformed OAuth token response");
    expect(tokenResponse.body).not.toContain("real-access-token-1");
    expect(tokenResponse.body).not.toContain("real-client-secret-1");
  }, 20_000);

  test("rejects OAuth handles replayed to a different token endpoint", async () => {
    const upstream = await startMcpOAuthUpstream({ tokenPaths: ["/oauth/token", "/oauth/secondary"] });
    const mcpOAuthPolicyPath = path.join(tmp, "oauth-mediation-policy.json");
    const mcpOAuthStateDir = path.join(tmp, "mcp-oauth-state");
    writeJson(mcpOAuthPolicyPath, {
      servers: {
        sentry: {
          resourceHost: "127.0.0.1",
          resourcePathPrefix: "/mcp",
          tokenEndpoints: [
            { host: "127.0.0.1", path: "/oauth/token" },
            { host: "127.0.0.1", path: "/oauth/secondary" },
          ],
        },
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
        RUNFREE_OAUTH_POLICY: mcpOAuthPolicyPath,
        RUNFREE_OAUTH_STATE_DIR: mcpOAuthStateDir,
      },
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });

    const tokenResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/token",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "grant_type=authorization_code&code=secret-authorization-code",
    });
    const tokenBody = JSON.parse(tokenResponse.body) as {
      client_secret: string;
      refresh_token: string;
    };

    const replayResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/secondary",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: [
        "grant_type=refresh_token",
        `refresh_token=${encodeURIComponent(tokenBody.refresh_token)}`,
        `client_secret=${encodeURIComponent(tokenBody.client_secret)}`,
      ].join("&"),
    });

    expect(replayResponse.statusCode).toBe(403);
    expect(replayResponse.body).toContain("wrong token endpoint");
    expect(upstream.requests.some((request) => request.url === "/oauth/secondary")).toBe(false);
    expect(proxy.output()).not.toContain("real-refresh-token-1");
    expect(proxy.output()).not.toContain("real-client-secret-1");
  }, 20_000);

  test("does not consume unrelated response bodies when OAuth policy is configured", async () => {
    const upstream = await startMcpOAuthUpstream({
      tokenResponseBody: JSON.stringify({
        access_token: "real-access-token-1",
        token_type: "Bearer",
      }),
    });
    const mcpOAuthPolicyPath = path.join(tmp, "oauth-mediation-policy.json");
    writeJson(mcpOAuthPolicyPath, {
      servers: {
        sentry: {
          resourceHost: "127.0.0.1",
          resourcePathPrefix: "/mcp",
          tokenHost: "127.0.0.1",
          tokenPath: "/oauth/token",
        },
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
        RUNFREE_OAUTH_POLICY: mcpOAuthPolicyPath,
      },
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });

    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/not-oauth-token",
    });

    expect(response.statusCode).toBe(404);
    expect(response.body).toContain("not found");
  }, 20_000);

  test("discovers OAuth token endpoints from authorization metadata before rewriting tokens", async () => {
    const upstream = await startMcpOAuthUpstream();
    const mcpOAuthPolicyPath = path.join(tmp, "oauth-mediation-policy.json");
    const mcpOAuthStateDir = path.join(tmp, "mcp-oauth-state");
    writeJson(mcpOAuthPolicyPath, {
      servers: {
        sentry: {
          resourceHost: "127.0.0.1",
          resourcePathPrefix: "/mcp",
          oauth: {
            authServerMetadataUrl: "https://127.0.0.1/.well-known/oauth-authorization-server",
          },
        },
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
        RUNFREE_OAUTH_POLICY: mcpOAuthPolicyPath,
        RUNFREE_OAUTH_STATE_DIR: mcpOAuthStateDir,
      },
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });

    const metadataResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/.well-known/oauth-authorization-server",
    });
    expect(metadataResponse.statusCode).toBe(200);
    expect(metadataResponse.body).toContain("/oauth/token");
    await proxy.waitForOutput("proxy: mcp oauth discovery ok name=sentry token_host=127.0.0.1");

    const tokenResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/token",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "grant_type=authorization_code&code=secret-authorization-code",
    });

    expect(tokenResponse.statusCode).toBe(200);
    const tokenBody = JSON.parse(tokenResponse.body) as { access_token: string; refresh_token: string };
    expect(tokenBody.access_token).toMatch(/^runfree_oauth_access_/);
    expect(tokenBody.refresh_token).toMatch(/^runfree_oauth_refresh_/);
    expect(tokenResponse.body).not.toContain("real-access-token-1");
    expect(tokenResponse.body).not.toContain("real-refresh-token-1");
    const stored = JSON.parse(fs.readFileSync(path.join(mcpOAuthStateDir, "handles.json"), "utf8")) as {
      discovered?: Record<string, { tokenEndpoints?: Array<{ host: string; path: string }> }>;
    };
    expect(stored.discovered?.sentry?.tokenEndpoints).toContainEqual({ host: "127.0.0.1", path: "/oauth/token" });
  }, 20_000);

  test("mediates OAuth dynamic registration secrets and registration access handles", async () => {
    const upstream = await startMcpOAuthUpstream();
    const mcpOAuthPolicyPath = path.join(tmp, "oauth-mediation-policy.json");
    const mcpOAuthStateDir = path.join(tmp, "mcp-oauth-state");
    writeJson(mcpOAuthPolicyPath, {
      servers: {
        sentry: {
          resourceHost: "127.0.0.1",
          resourcePathPrefix: "/mcp",
          oauth: {
            authServerMetadataUrl: "https://127.0.0.1/.well-known/oauth-authorization-server",
          },
        },
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
        RUNFREE_OAUTH_POLICY: mcpOAuthPolicyPath,
        RUNFREE_OAUTH_STATE_DIR: mcpOAuthStateDir,
      },
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });

    const metadataResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/.well-known/oauth-authorization-server",
    });
    expect(metadataResponse.statusCode).toBe(200);

    const registrationResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/register",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_name: "Runfree test client" }),
    });

    expect(registrationResponse.statusCode).toBe(200);
    const registrationBody = JSON.parse(registrationResponse.body) as {
      client_secret: string;
      registration_access_token: string;
    };
    expect(registrationBody.client_secret).toMatch(/^runfree_oauth_secret_/);
    expect(registrationBody.registration_access_token).toMatch(/^runfree_oauth_secret_/);
    expect(registrationResponse.body).not.toContain("real-registered-client-secret-1");
    expect(registrationResponse.body).not.toContain("real-registration-access-token-1");

    const tokenResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/token",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: [
        "grant_type=authorization_code",
        "code=secret-authorization-code",
        `client_secret=${encodeURIComponent(registrationBody.client_secret)}`,
      ].join("&"),
    });
    expect(tokenResponse.statusCode).toBe(200);
    const upstreamTokenBody = upstream.requests.find((request) => request.url === "/oauth/token")?.body ?? "";
    expect(upstreamTokenBody).toContain("client_secret=real-registered-client-secret-1");
    expect(upstreamTokenBody).not.toContain(registrationBody.client_secret);

    const registrationReadResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/oauth/register/registered-client-id",
      headers: { Authorization: `Bearer ${registrationBody.registration_access_token}` },
    });
    expect(registrationReadResponse.statusCode).toBe(200);
    expect(upstream.requests.find((request) => request.url === "/oauth/register/registered-client-id")?.headers.authorization)
      .toBe("Bearer real-registration-access-token-1");

    const beforeInvalidRegistrationReads = upstream.requests.length;
    const registrationChildResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/oauth/register/registered-client-id/extra",
      headers: { Authorization: `Bearer ${registrationBody.registration_access_token}` },
    });
    expect(registrationChildResponse.statusCode).toBe(403);
    expect(registrationChildResponse.body).toContain("wrong registration endpoint");

    const registrationSiblingResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/oauth/register/other-client-id",
      headers: { Authorization: `Bearer ${registrationBody.registration_access_token}` },
    });
    expect(registrationSiblingResponse.statusCode).toBe(403);
    expect(registrationSiblingResponse.body).toContain("wrong registration endpoint");
    expect(upstream.requests).toHaveLength(beforeInvalidRegistrationReads);

    const stored = fs.readFileSync(path.join(mcpOAuthStateDir, "handles.json"), "utf8");
    expect(stored).toContain("real-registered-client-secret-1");
    expect(stored).toContain("real-registration-access-token-1");
    expect(proxy.output()).not.toContain("real-registered-client-secret-1");
    expect(proxy.output()).not.toContain("real-registration-access-token-1");
  }, 20_000);

  test("swaps a client_secret_basic handle in the Authorization header for the real secret", async () => {
    const upstream = await startMcpOAuthUpstream();
    const mcpOAuthPolicyPath = path.join(tmp, "oauth-mediation-policy.json");
    const mcpOAuthStateDir = path.join(tmp, "mcp-oauth-state");
    writeJson(mcpOAuthPolicyPath, {
      servers: {
        sentry: {
          resourceHost: "127.0.0.1",
          resourcePathPrefix: "/mcp",
          oauth: {
            authServerMetadataUrl: "https://127.0.0.1/.well-known/oauth-authorization-server",
          },
        },
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
        RUNFREE_OAUTH_POLICY: mcpOAuthPolicyPath,
        RUNFREE_OAUTH_STATE_DIR: mcpOAuthStateDir,
      },
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });

    const metadataResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/.well-known/oauth-authorization-server",
    });
    expect(metadataResponse.statusCode).toBe(200);

    const registrationResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/register",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_name: "Runfree test client" }),
    });
    expect(registrationResponse.statusCode).toBe(200);
    const registrationBody = JSON.parse(registrationResponse.body) as { client_id: string; client_secret: string };
    expect(registrationBody.client_id).toBe("registered-client-id");
    expect(registrationBody.client_secret).toMatch(/^runfree_oauth_secret_/);

    // The confidential client sends client_secret_basic: base64(client_id:secret)
    // in the Authorization header, with no client_secret in the body.
    const presentedAuthorization = `Basic ${Buffer.from(`${registrationBody.client_id}:${registrationBody.client_secret}`, "utf8").toString("base64")}`;
    const tokenResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/token",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: presentedAuthorization,
      },
      body: "grant_type=authorization_code&code=secret-authorization-code",
    });
    expect(tokenResponse.statusCode).toBe(200);

    const upstreamTokenRequest = upstream.requests.find((request) => request.url === "/oauth/token");
    const expectedAuthorization = `Basic ${Buffer.from("registered-client-id:real-registered-client-secret-1", "utf8").toString("base64")}`;
    expect(upstreamTokenRequest?.headers.authorization).toBe(expectedAuthorization);
    expect(upstreamTokenRequest?.headers.authorization).not.toBe(presentedAuthorization);
    expect(JSON.stringify(upstreamTokenRequest?.headers)).not.toContain(registrationBody.client_secret);
    expect(proxy.output()).not.toContain("real-registered-client-secret-1");
  }, 20_000);

  test("rejects an unknown secret handle in the Authorization: Basic header before reaching upstream", async () => {
    const upstream = await startMcpOAuthUpstream();
    const mcpOAuthPolicyPath = path.join(tmp, "oauth-mediation-policy.json");
    const mcpOAuthStateDir = path.join(tmp, "mcp-oauth-state");
    writeJson(mcpOAuthPolicyPath, {
      servers: {
        sentry: {
          resourceHost: "127.0.0.1",
          resourcePathPrefix: "/mcp",
          tokenHost: "127.0.0.1",
          tokenPath: "/oauth/token",
        },
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
        RUNFREE_OAUTH_POLICY: mcpOAuthPolicyPath,
        RUNFREE_OAUTH_STATE_DIR: mcpOAuthStateDir,
      },
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });

    const forgedHandle = `runfree_oauth_secret_${"a".repeat(40)}`;
    const forgedAuthorization = `Basic ${Buffer.from(`registered-client-id:${forgedHandle}`, "utf8").toString("base64")}`;
    const tokenResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/token",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: forgedAuthorization,
      },
      body: "grant_type=authorization_code&code=secret-authorization-code",
    });
    expect(tokenResponse.statusCode).toBe(403);
    expect(tokenResponse.body).toContain("unknown OAuth secret handle");
    expect(upstream.requests.some((request) => request.url === "/oauth/token")).toBe(false);
  }, 20_000);

  test("passes a non-handle Authorization: Basic header through untouched", async () => {
    const upstream = await startMcpOAuthUpstream();
    const mcpOAuthPolicyPath = path.join(tmp, "oauth-mediation-policy.json");
    const mcpOAuthStateDir = path.join(tmp, "mcp-oauth-state");
    writeJson(mcpOAuthPolicyPath, {
      servers: {
        sentry: {
          resourceHost: "127.0.0.1",
          resourcePathPrefix: "/mcp",
          tokenHost: "127.0.0.1",
          tokenPath: "/oauth/token",
        },
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
        RUNFREE_OAUTH_POLICY: mcpOAuthPolicyPath,
        RUNFREE_OAUTH_STATE_DIR: mcpOAuthStateDir,
      },
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });

    const passthroughAuthorization = `Basic ${Buffer.from("registered-client-id:not-a-runfree-handle", "utf8").toString("base64")}`;
    const tokenResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/token",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: passthroughAuthorization,
      },
      body: "grant_type=authorization_code&code=secret-authorization-code",
    });
    expect(tokenResponse.statusCode).toBe(200);
    const upstreamTokenRequest = upstream.requests.find((request) => request.url === "/oauth/token");
    expect(upstreamTokenRequest?.headers.authorization).toBe(passthroughAuthorization);
  }, 20_000);

  test("preserves a client_secret_basic handle over configured Authorization credential injection", async () => {
    const upstream = await startMcpOAuthUpstream();
    const mcpOAuthPolicyPath = path.join(tmp, "oauth-mediation-policy.json");
    const mcpOAuthStateDir = path.join(tmp, "mcp-oauth-state");
    writeJson(mcpOAuthPolicyPath, {
      servers: {
        sentry: {
          resourceHost: "127.0.0.1",
          resourcePathPrefix: "/mcp",
          oauth: {
            authServerMetadataUrl: "https://127.0.0.1/.well-known/oauth-authorization-server",
          },
        },
      },
    });
    // The MCP token host also carries a static Authorization credential mapping;
    // the Basic handle must survive credential stripping/injection so the
    // mediator swaps in the real client_secret instead of the static token.
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
        RUNFREE_OAUTH_POLICY: mcpOAuthPolicyPath,
        RUNFREE_OAUTH_STATE_DIR: mcpOAuthStateDir,
      },
      policy: {
        hosts: ["127.0.0.1"],
        writeApproval: "allow",
        tokens: {
          github: {
            description: "GitHub token",
            credentials: [{ host: "127.0.0.1", header: "Authorization", scheme: "bearer" }],
          },
        },
      },
      secretFiles: { github: "generic-proxy-token\n" },
    });

    const metadataResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/.well-known/oauth-authorization-server",
    });
    expect(metadataResponse.statusCode).toBe(200);

    const registrationResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/register",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_name: "Runfree test client" }),
    });
    expect(registrationResponse.statusCode).toBe(200);
    const registrationBody = JSON.parse(registrationResponse.body) as { client_id: string; client_secret: string };
    expect(registrationBody.client_secret).toMatch(/^runfree_oauth_secret_/);

    const presentedAuthorization = `Basic ${Buffer.from(`${registrationBody.client_id}:${registrationBody.client_secret}`, "utf8").toString("base64")}`;
    const tokenResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/token",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: presentedAuthorization,
      },
      body: "grant_type=authorization_code&code=secret-authorization-code",
    });
    expect(tokenResponse.statusCode).toBe(200);

    const upstreamTokenRequest = upstream.requests.find((request) => request.url === "/oauth/token");
    const expectedAuthorization = `Basic ${Buffer.from("registered-client-id:real-registered-client-secret-1", "utf8").toString("base64")}`;
    expect(upstreamTokenRequest?.headers.authorization).toBe(expectedAuthorization);
    expect(upstreamTokenRequest?.headers.authorization).not.toBe("Bearer generic-proxy-token");
    expect(JSON.stringify(upstreamTokenRequest?.headers)).not.toContain(registrationBody.client_secret);
  }, 20_000);

  test("mediates OAuth bearer handles while keeping generic proxy credential injection", async () => {
    const upstream = await startMcpOAuthUpstream();
    const mcpOAuthPolicyPath = path.join(tmp, "oauth-mediation-policy.json");
    const mcpOAuthStateDir = path.join(tmp, "mcp-oauth-state");
    writeJson(mcpOAuthPolicyPath, {
      servers: {
        sentry: {
          resourceHost: "127.0.0.1",
          resourcePathPrefix: "/mcp",
          tokenHost: "127.0.0.1",
          tokenPath: "/oauth/token",
        },
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
        RUNFREE_OAUTH_POLICY: mcpOAuthPolicyPath,
        RUNFREE_OAUTH_STATE_DIR: mcpOAuthStateDir,
      },
      policy: {
        hosts: ["127.0.0.1"],
        writeApproval: "allow",
        tokens: {
          github: {
            description: "GitHub token",
            credentials: [
              { host: "127.0.0.1", header: "Authorization", scheme: "bearer" },
              { host: "127.0.0.1", header: "X-Api-Key", scheme: "raw" },
            ],
          },
        },
      },
      secretFiles: { github: "generic-proxy-token\n" },
    });

    const tokenResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/token",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "grant_type=authorization_code&code=secret-authorization-code",
    });
    const tokenBody = JSON.parse(tokenResponse.body) as { access_token: string };

    const resourceResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/mcp",
      headers: {
        Authorization: `Bearer ${tokenBody.access_token}`,
        "X-Api-Key": "agent-supplied-secret",
      },
    });

    expect(resourceResponse.statusCode).toBe(200);
    const resourceRequest = upstream.requests.find((request) => request.url === "/mcp");
    expect(resourceRequest?.headers.authorization)
      .toBe("Bearer real-access-token-1");
    expect(resourceRequest?.headers["x-api-key"]).toBe("generic-proxy-token");
    expect(proxy.output()).not.toContain("generic-proxy-token");
    expect(proxy.output()).not.toContain(tokenBody.access_token);
  }, 20_000);

  test("rejects OAuth handles after an MCP server name is repointed", async () => {
    const upstream = await startMcpOAuthUpstream();
    const mcpOAuthPolicyPath = path.join(tmp, "oauth-mediation-policy.json");
    const mcpOAuthStateDir = path.join(tmp, "mcp-oauth-state");
    writeJson(mcpOAuthPolicyPath, {
      servers: {
        sentry: {
          resourceHost: "127.0.0.1",
          resourcePathPrefix: "/mcp",
          tokenHost: "127.0.0.1",
          tokenPath: "/oauth/token",
        },
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
        RUNFREE_OAUTH_POLICY: mcpOAuthPolicyPath,
        RUNFREE_OAUTH_STATE_DIR: mcpOAuthStateDir,
      },
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });

    const tokenResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/oauth/token",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "grant_type=authorization_code&code=secret-authorization-code",
    });
    const tokenBody = JSON.parse(tokenResponse.body) as { access_token: string };
    replaceJson(mcpOAuthPolicyPath, {
      servers: {
        sentry: {
          resourceHost: "127.0.0.1",
          resourcePathPrefix: "/other",
          tokenHost: "127.0.0.1",
          tokenPath: "/oauth/token",
        },
      },
    });

    const replayResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/other",
      headers: { Authorization: `Bearer ${tokenBody.access_token}` },
    });

    expect(replayResponse.statusCode).toBe(403);
    expect(replayResponse.body).toContain("unknown OAuth token handle");
    expect(upstream.requests.some((request) => request.url === "/other")).toBe(false);
  }, 20_000);

  test("rejects unknown OAuth handles before contacting the upstream host", async () => {
    const upstream = await startMcpOAuthUpstream();
    const mcpOAuthPolicyPath = path.join(tmp, "oauth-mediation-policy.json");
    writeJson(mcpOAuthPolicyPath, {
      servers: {
        sentry: {
          resourceHost: "127.0.0.1",
          resourcePathPrefix: "/mcp",
          tokenHost: "127.0.0.1",
          tokenPath: "/oauth/token",
        },
      },
    });
    const proxy = await startProxy({
      extraEnv: {
        NODE_EXTRA_CA_CERTS: path.join(tmp, "upstream.crt"),
        RUNFREE_OAUTH_POLICY: mcpOAuthPolicyPath,
        RUNFREE_OAUTH_STATE_DIR: path.join(tmp, "mcp-oauth-state"),
      },
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });

    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      path: "/mcp",
      headers: { Authorization: "Bearer runfree_oauth_access_unknown" },
    });

    expect(response.statusCode).toBe(403);
    expect(response.body).toContain("unknown OAuth token handle");
    expect(upstream.requests).toHaveLength(0);
    expect(proxy.output()).not.toContain("runfree_oauth_access_unknown");
  }, 20_000);

});
