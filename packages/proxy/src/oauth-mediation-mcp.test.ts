import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { OAuthMediator } from "./oauth-mediation.ts";

let tmp: string;

function writeJson(filePath: string, value: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const policy = value !== null && typeof value === "object" && !Array.isArray(value) && "servers" in value
    ? {
      providers: Object.fromEntries(Object.entries((value as { servers: Record<string, unknown> }).servers)
        .map(([name, provider]) => [name, { kind: "mcp", ...(provider as Record<string, unknown>) }])),
    }
    : value;
  fs.writeFileSync(filePath, `${JSON.stringify(policy, null, 2)}\n`);
}

function writeMalformedPolicy(filePath: string): void {
  fs.writeFileSync(filePath, "{ malformed\n");
  const future = new Date(Date.now() + 2_000);
  fs.utimesSync(filePath, future, future);
}

function responseBody(value: unknown, delayMs: number): { getText(): Promise<string> } {
  return {
    getText: async () => {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      return JSON.stringify(value);
    },
  };
}

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-oauth-tests-")));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("MCP OAuth mediator", () => {
  test("preserves concurrent token exchange handles in proxy-side state", async () => {
    const policyPath = path.join(tmp, "oauth-mediation-policy.json");
    const stateDir = path.join(tmp, "state");
    writeJson(policyPath, {
      servers: {
        sentry: {
          resourceHost: "mcp.example.test",
          resourcePathPrefix: "/mcp",
          tokenHost: "auth.example.test",
          tokenPath: "/oauth/token",
        },
      },
    });
    const mediator = new OAuthMediator({
      log: () => {},
      policyPath,
      projectId: "project-under-test",
      stateDir,
    });
    const req = {
      method: "POST",
      url: "https://auth.example.test/oauth/token",
    };

    const [first, second] = await Promise.all([
      mediator.beforeResponse({
        body: responseBody({ access_token: "real-access-token-a", token_type: "Bearer" }, 40),
        statusCode: 200,
      }, req),
      mediator.beforeResponse({
        body: responseBody({ access_token: "real-access-token-b", token_type: "Bearer" }, 0),
        statusCode: 200,
      }, req),
    ]);

    const firstHandle = (JSON.parse(first?.body ?? "{}") as { access_token?: string }).access_token;
    const secondHandle = (JSON.parse(second?.body ?? "{}") as { access_token?: string }).access_token;
    expect(firstHandle).toMatch(/^runfree_oauth_access_/);
    expect(secondHandle).toMatch(/^runfree_oauth_access_/);

    const firstReplay = await mediator.beforeRequest({
      headers: { authorization: `Bearer ${firstHandle}` },
      method: "GET",
      url: "https://mcp.example.test/mcp",
    });
    const secondReplay = await mediator.beforeRequest({
      headers: { authorization: `Bearer ${secondHandle}` },
      method: "GET",
      url: "https://mcp.example.test/mcp",
    });
    expect(firstReplay?.headers?.authorization).toBe("Bearer real-access-token-a");
    expect(secondReplay?.headers?.authorization).toBe("Bearer real-access-token-b");
  });

  test("fails closed for new MCP OAuth requests after policy reload becomes malformed", async () => {
    const policyPath = path.join(tmp, "oauth-mediation-policy.json");
    const stateDir = path.join(tmp, "state");
    const logs: string[] = [];
    writeJson(policyPath, {
      servers: {
        sentry: {
          resourceHost: "mcp.example.test",
          resourcePathPrefix: "/mcp",
          tokenHost: "auth.example.test",
          tokenPath: "/oauth/token",
        },
      },
    });
    const mediator = new OAuthMediator({
      log: (line) => logs.push(line),
      policyPath,
      projectId: "project-under-test",
      stateDir,
    });
    const tokenReq = {
      id: "initial-token",
      method: "POST",
      url: "https://auth.example.test/oauth/token",
    };
    const tokenRewrite = await mediator.beforeResponse({
      body: responseBody({ access_token: "real-access-token", token_type: "Bearer" }, 0),
      statusCode: 200,
    }, tokenReq);
    const handle = JSON.parse(tokenRewrite?.body ?? "{}") as { access_token: string };
    expect(handle.access_token).toMatch(/^runfree_oauth_access_/);

    writeMalformedPolicy(policyPath);

    const replay = await mediator.beforeRequest({
      headers: { authorization: `Bearer ${handle.access_token}` },
      url: "https://mcp.example.test/mcp",
    });
    expect(replay?.response?.statusCode).toBe(403);
    expect(replay?.response?.body).toContain("OAuth policy unavailable");
    expect(replay).not.toHaveProperty("headers");

    const newTokenRequest = await mediator.beforeRequest({
      body: { getText: async () => "grant_type=authorization_code&code=secret-code" },
      headers: { "content-type": "application/x-www-form-urlencoded" },
      id: "new-token",
      method: "POST",
      url: "https://auth.example.test/oauth/token",
    });
    expect(newTokenRequest?.response?.statusCode).toBe(403);
    expect(newTokenRequest?.response?.body).toContain("OAuth policy unavailable");

    const untrackedResponse = await mediator.beforeResponse({
      body: responseBody({ access_token: "real-untracked-token", token_type: "Bearer" }, 0),
      statusCode: 200,
    }, {
      id: "untracked-token-response",
      method: "POST",
      url: "https://auth.example.test/oauth/token",
    });
    expect(untrackedResponse).toBeUndefined();
    expect(fs.readFileSync(path.join(stateDir, "handles.json"), "utf8")).not.toContain("real-untracked-token");
    expect(logs.some((line) => line.includes("oauth policy reload failed"))).toBe(true);
  });

  test("ignores a discovered OAuth endpoint on a host not bound to the server", async () => {
    const policyPath = path.join(tmp, "oauth-mediation-policy.json");
    const stateDir = path.join(tmp, "state");
    const logs: string[] = [];
    writeJson(policyPath, {
      servers: {
        example: {
          resourceHost: "mcp.example.test",
          resourcePathPrefix: "/mcp",
          oauth: { authServerMetadataUrl: "https://mcp.example.test/.well-known/oauth-authorization-server" },
        },
      },
    });
    const mediator = new OAuthMediator({
      log: (line) => logs.push(line),
      policyPath,
      projectId: "project-under-test",
      stateDir,
    });

    // Authorization-server metadata served from the resource host names a token
    // endpoint on an unrelated host (the token-relay attack) and a registration
    // endpoint on the bound resource host.
    const result = await mediator.beforeResponse({
      body: responseBody({
        issuer: "https://mcp.example.test",
        token_endpoint: "https://evil.example.test/oauth/token",
        registration_endpoint: "https://mcp.example.test/oauth/register",
      }, 0),
      statusCode: 200,
    }, {
      method: "GET",
      url: "https://mcp.example.test/.well-known/oauth-authorization-server",
    });

    // Metadata responses themselves are never rewritten.
    expect(result).toBeUndefined();
    const discovered = (JSON.parse(fs.readFileSync(path.join(stateDir, "handles.json"), "utf8")) as {
      discovered: Record<string, { tokenEndpoints?: unknown[]; registrationEndpoints?: unknown[] }>;
    }).discovered.example;
    // The unbound token endpoint host is dropped; the bound registration endpoint is kept.
    expect(JSON.stringify(discovered.tokenEndpoints ?? [])).not.toContain("evil.example.test");
    expect(JSON.stringify(discovered.registrationEndpoints ?? [])).toContain("mcp.example.test");
    expect(logs.some((line) =>
      line.includes("discovery rejected")
      && line.includes("evil.example.test")
      && line.includes("unbound-host"))).toBe(true);
  });

  test("mediates a cross-host issuer's tokens after the resource's own PRM binds it", async () => {
    const policyPath = path.join(tmp, "oauth-mediation-policy.json");
    const stateDir = path.join(tmp, "state");
    writeJson(policyPath, {
      servers: { example: { resourceHost: "mcp.example.test", resourcePathPrefix: "/mcp" } },
    });
    const mediator = new OAuthMediator({ log: () => {}, policyPath, projectId: "p", stateDir });
    const readDiscovered = () =>
      (JSON.parse(fs.readFileSync(path.join(stateDir, "handles.json"), "utf8")) as {
        discovered: Record<string, { issuerHosts?: string[]; tokenEndpoints?: unknown[] }>;
      }).discovered.example;

    // 1. RFC 9728 protected-resource metadata from the resource host names the issuer.
    await mediator.beforeResponse({
      body: responseBody({ resource: "https://mcp.example.test", authorization_servers: ["https://auth.example.test"] }, 0),
      statusCode: 200,
    }, { method: "GET", url: "https://mcp.example.test/.well-known/oauth-protected-resource" });
    expect(readDiscovered().issuerHosts).toContain("auth.example.test");

    // 2. RFC 8414 metadata from the (self-consistent) issuer advertises its token endpoint.
    await mediator.beforeResponse({
      body: responseBody({ issuer: "https://auth.example.test", token_endpoint: "https://auth.example.test/token" }, 0),
      statusCode: 200,
    }, { method: "GET", url: "https://auth.example.test/.well-known/oauth-authorization-server" });
    expect(JSON.stringify(readDiscovered().tokenEndpoints)).toContain("auth.example.test");

    // 3. The token exchange at the cross-host issuer is sanitized into handles.
    const tokenRewrite = await mediator.beforeResponse({
      body: responseBody({ access_token: "real-xhost-token", refresh_token: "real-xhost-refresh", token_type: "Bearer" }, 0),
      statusCode: 200,
    }, { id: "tok", method: "POST", url: "https://auth.example.test/token" });
    expect(tokenRewrite?.body).toContain("runfree_oauth_access_");
    expect(tokenRewrite?.body).not.toContain("real-xhost-token");
    expect(fs.readFileSync(path.join(stateDir, "handles.json"), "utf8")).toContain("real-xhost-token");
  });

  test("reports MCP context for a denied issuer host discovered from resource metadata", async () => {
    const policyPath = path.join(tmp, "oauth-mediation-policy.json");
    const stateDir = path.join(tmp, "state");
    writeJson(policyPath, {
      servers: { posthog: { resourceHost: "mcp.posthog.com", resourcePathPrefix: "/mcp" } },
    });
    const mediator = new OAuthMediator({ log: () => {}, policyPath, projectId: "p", stateDir });

    await mediator.beforeResponse({
      body: responseBody({ resource: "https://mcp.posthog.com", authorization_servers: ["https://oauth.posthog.com"] }, 0),
      statusCode: 200,
    }, { method: "GET", url: "https://mcp.posthog.com/.well-known/oauth-protected-resource" });

    expect(mediator.issuerDenialContext("oauth.posthog.com")).toEqual({
      providerId: "posthog",
      resourceHost: "mcp.posthog.com",
    });
    expect(mediator.issuerDenialContext("api.example.com")).toBeUndefined();
  });

  test("ignores authorization-server metadata from a host the resource never declared as its issuer", async () => {
    const policyPath = path.join(tmp, "oauth-mediation-policy.json");
    const stateDir = path.join(tmp, "state");
    writeJson(policyPath, {
      servers: { example: { resourceHost: "mcp.example.test", resourcePathPrefix: "/mcp" } },
    });
    const mediator = new OAuthMediator({ log: () => {}, policyPath, projectId: "p", stateDir });

    // No PRM bound this host, so its AS metadata must not register a token endpoint.
    await mediator.beforeResponse({
      body: responseBody({ issuer: "https://evil.example.test", token_endpoint: "https://evil.example.test/token" }, 0),
      statusCode: 200,
    }, { method: "GET", url: "https://evil.example.test/.well-known/oauth-authorization-server" });

    // And a token exchange there is not mediated (real token passes through untouched).
    const tokenRewrite = await mediator.beforeResponse({
      body: responseBody({ access_token: "real-evil-token", token_type: "Bearer" }, 0),
      statusCode: 200,
    }, { id: "tok", method: "POST", url: "https://evil.example.test/token" });
    expect(tokenRewrite).toBeUndefined();
    const stateFile = path.join(stateDir, "handles.json");
    if (fs.existsSync(stateFile)) {
      const contents = fs.readFileSync(stateFile, "utf8");
      expect(contents).not.toContain("real-evil-token");
      expect(contents).not.toContain("evil.example.test");
    }
  });

  test("rejects cross-host issuer metadata whose issuer field does not match the serving host", async () => {
    const policyPath = path.join(tmp, "oauth-mediation-policy.json");
    const stateDir = path.join(tmp, "state");
    const logs: string[] = [];
    writeJson(policyPath, {
      servers: { example: { resourceHost: "mcp.example.test", resourcePathPrefix: "/mcp" } },
    });
    const mediator = new OAuthMediator({ log: (line) => logs.push(line), policyPath, projectId: "p", stateDir });

    await mediator.beforeResponse({
      body: responseBody({ authorization_servers: ["https://auth.example.test"] }, 0),
      statusCode: 200,
    }, { method: "GET", url: "https://mcp.example.test/.well-known/oauth-protected-resource" });

    // Issuer field claims a different host than the one serving the metadata.
    await mediator.beforeResponse({
      body: responseBody({ issuer: "https://other.example.test", token_endpoint: "https://auth.example.test/token" }, 0),
      statusCode: 200,
    }, { method: "GET", url: "https://auth.example.test/.well-known/oauth-authorization-server" });

    const discovered = (JSON.parse(fs.readFileSync(path.join(stateDir, "handles.json"), "utf8")) as {
      discovered: Record<string, { tokenEndpoints?: unknown[] }>;
    }).discovered.example;
    expect(discovered.tokenEndpoints ?? []).toEqual([]);
    expect(logs.some((line) => line.includes("issuer-mismatch") && line.includes("auth.example.test"))).toBe(true);

    const tokenRewrite = await mediator.beforeResponse({
      body: responseBody({ access_token: "real-mismatch-token", token_type: "Bearer" }, 0),
      statusCode: 200,
    }, { id: "tok", method: "POST", url: "https://auth.example.test/token" });
    expect(tokenRewrite).toBeUndefined();
  });

  test("fails closed when the configured MCP OAuth policy is unavailable before first load", async () => {
    const policyPath = path.join(tmp, "missing-oauth-mediation-policy.json");
    const logs: string[] = [];
    const mediator = new OAuthMediator({
      log: (line) => logs.push(line),
      policyPath,
      projectId: "project-under-test",
      stateDir: path.join(tmp, "state"),
    });

    const request = await mediator.beforeRequest({
      url: "https://mcp.example.test/mcp",
    });

    expect(request?.response?.statusCode).toBe(403);
    expect(request?.response?.body).toContain("OAuth policy unavailable");
    expect(logs.some((line) => line.includes("oauth policy reload failed"))).toBe(true);
  });

  test("still mediates an in-flight MCP OAuth token response after policy reload becomes malformed", async () => {
    const policyPath = path.join(tmp, "oauth-mediation-policy.json");
    const stateDir = path.join(tmp, "state");
    writeJson(policyPath, {
      servers: {
        sentry: {
          resourceHost: "mcp.example.test",
          resourcePathPrefix: "/mcp",
          tokenHost: "auth.example.test",
          tokenPath: "/oauth/token",
        },
      },
    });
    const mediator = new OAuthMediator({
      log: () => {},
      policyPath,
      projectId: "project-under-test",
      stateDir,
    });
    const req = {
      id: "in-flight-token",
      method: "POST",
      url: "https://auth.example.test/oauth/token",
    };
    await mediator.beforeRequest(req);
    writeMalformedPolicy(policyPath);

    const tokenRewrite = await mediator.beforeResponse({
      body: responseBody({
        access_token: "real-in-flight-access-token",
        refresh_token: "real-in-flight-refresh-token",
        token_type: "Bearer",
      }, 0),
      statusCode: 200,
    }, req);

    expect(tokenRewrite?.body).toContain("runfree_oauth_access_");
    expect(tokenRewrite?.body).toContain("runfree_oauth_refresh_");
    expect(tokenRewrite?.body).not.toContain("real-in-flight-access-token");
    expect(tokenRewrite?.body).not.toContain("real-in-flight-refresh-token");
    const stored = fs.readFileSync(path.join(stateDir, "handles.json"), "utf8");
    expect(stored).toContain("real-in-flight-access-token");
    expect(stored).toContain("real-in-flight-refresh-token");
  });
});
