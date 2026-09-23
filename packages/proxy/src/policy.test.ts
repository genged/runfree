import { afterEach, describe, expect, test, vi } from "vitest";

import {
  ProxyAdmissionHostMismatchError,
  ProxyPolicyDenialError,
  assertAllowedWebSocketRequest as authorizeWebSocketRequest,
  type CredentialPolicy,
  beforeAllowedRequest as authorizeRequest,
  configuredCredentialHeaderNames,
  hostFromUrl,
  loadProxyPolicy,
  tokenPath,
  validateProxyPolicy,
  type PolicyOptions,
  type ProxyRequest,
} from "./policy.ts";
import type { AdmissionRecord } from "./admission.ts";

let admissionSerial = 0;

function testAdmission(req: ProxyRequest, options: Pick<PolicyOptions, "allowedHosts"> = {}): AdmissionRecord {
  admissionSerial += 1;
  return {
    v: 1,
    host: hostFromUrl(req.url) || options.allowedHosts?.[0] || "invalid.example",
    port: 443,
    policyGeneration: "sha256:test-policy",
    admittedAtMs: Date.now(),
    connectionSerial: admissionSerial,
    stage: "request",
  };
}

function testBeforeAllowedRequest(req: ProxyRequest, options: PolicyOptions = {}) {
  return authorizeRequest(testAdmission(req, options), req, options);
}

function testAssertAllowedWebSocketRequest(req: ProxyRequest, options: PolicyOptions = {}): void {
  authorizeWebSocketRequest(testAdmission(req, options), req, options);
}

function shapeDenial(run: () => unknown): ProxyPolicyDenialError {
  try {
    run();
  } catch (error) {
    if (error instanceof ProxyPolicyDenialError) return error;
    throw error;
  }
  throw new Error("expected a ProxyPolicyDenialError");
}

describe("proxy policy", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  test("hostFromUrl normalizes hostnames and rejects malformed URLs", () => {
    expect(hostFromUrl("https://API.GITHUB.COM/rate_limit")).toBe("api.github.com");
    expect(hostFromUrl("not a url")).toBe("");
  });

  test("loads policy JSON and keeps credential hosts inside allowed hosts", () => {
    const policy = loadProxyPolicy(new URL("../../cli/templates/network-policy.json", import.meta.url).pathname);

    for (const mapping of policy.credentialMappings) {
      expect(policy.allowedHosts, `${mapping.host} is credentialed but not allowlisted`).toContain(mapping.host);
    }
  });

  test("default desired policy grants no network or credential authority", () => {
    const policy = loadProxyPolicy(new URL("../../cli/templates/network-policy.json", import.meta.url).pathname);

    expect(policy.allowedHosts).toEqual([]);
    expect(policy.credentialMappings).toEqual([]);
    expect(policy.tokens).toEqual({});
    expect(policy.requests).toEqual({});
  });

  test("migrates legacy generated GitHub token policy to anonymous fallback", () => {
    const policy = validateProxyPolicy({
      hosts: ["api.github.com", "raw.githubusercontent.com"],
      tokens: {
        github: {
          description: "Read-only GitHub API token for rate limit and public metadata",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
            { host: "raw.githubusercontent.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });

    expect(policy.raw.tokens?.github.allowAnonymous).toBe(true);
    expect(policy.credentials["api.github.com"][0].allowAnonymous).toBe(true);
    expect(policy.credentials["raw.githubusercontent.com"][0].allowAnonymous).toBe(true);
  });

  test("allows WebSocket requests to explicitly allowlisted WSS hosts", () => {
    // Under the ask default an upgrade is a classified write, so today's
    // pass-through behavior requires an allow posture for the host.
    expect(() => testAssertAllowedWebSocketRequest({
      url: "wss://chatgpt.com/backend-api/codex/responses",
    }, {
      allowedHosts: ["chatgpt.com"],
      writeApproval: "allow",
    })).not.toThrow();
  });

  test("rejects WebSocket requests outside the allowlist", () => {
    expect(() => testAssertAllowedWebSocketRequest({
      url: "wss://example.com/socket",
    }, {
      allowedHosts: ["chatgpt.com"],
    })).toThrow(/blocked outbound host: example\.com/);
  });

  test("rejects cleartext WebSocket requests", () => {
    expect(() => testAssertAllowedWebSocketRequest({
      url: "ws://chatgpt.com/socket",
    }, {
      allowedHosts: ["chatgpt.com"],
    })).toThrow(/blocked non-WSS outbound URL/);
  });

  test("requires an explicit runtime policy path", () => {
    vi.stubEnv("PROXY_POLICY_PATH", "");

    expect(() => loadProxyPolicy()).toThrow(/PROXY_POLICY_PATH is required/);
  });

  test("validates proxy token filenames with the shared runtime contract", () => {
    expect(tokenPath("github", "/run/secrets")).toBe("/run/secrets/github");
    expect(() => tokenPath("../github", "/run/secrets")).toThrow("invalid token name: ../github");
  });

  test("validates stored hostname shape, credential host membership, and conflicts", () => {
    const badPolicy = {
      domains: {
        A: ["api.example.com", "https://bad.example.com/path", "API.EXAMPLE.COM"],
        B: ["api.example.com"],
      },
      tokens: {
        github: {
          description: "token",
          credentials: [
            { host: "missing.example.com", header: "Authorization", scheme: "bearer" },
            { host: "api.example.com", header: "Authorization", scheme: "bearer" },
          ],
        },
        other: {
          description: "token",
          credentials: [
            { host: "api.example.com", header: "authorization", scheme: "raw" },
          ],
        },
      },
    };

    expect(() => validateProxyPolicy(badPolicy)).toThrow(/expected hostname, got URL/);
    expect(() => validateProxyPolicy(badPolicy)).toThrow(/must be stored lowercase/);
    expect(() => validateProxyPolicy(badPolicy)).toThrow(/appears in both/);
    expect(() => validateProxyPolicy(badPolicy)).toThrow(/credentialed but not allowlisted/);
    expect(() => validateProxyPolicy(badPolicy)).toThrow(/conflicts with/);
  });

  test("normalizes legacy category and host-map policies into the plain allowlist", () => {
    const loaded = validateProxyPolicy({
      domains: {
        GitHub: ["api.github.com", "raw.githubusercontent.com"],
        "registry.npmjs.org": { note: "old note shape" },
      },
      tokens: {},
    });

    expect(loaded.raw.hosts).toEqual(["api.github.com", "raw.githubusercontent.com", "registry.npmjs.org"]);
    expect(loaded.allowedHosts).toEqual(["api.github.com", "raw.githubusercontent.com", "registry.npmjs.org"]);
  });

  test("derives policy generation from normalized hosts and token policy", () => {
    const plain = validateProxyPolicy({
      hosts: ["api.github.com", "raw.githubusercontent.com"],
      tokens: {},
    });
    const legacy = validateProxyPolicy({
      domains: {
        GitHub: ["api.github.com", "raw.githubusercontent.com"],
      },
      tokens: {},
    });
    const changedHosts = validateProxyPolicy({
      hosts: ["api.github.com"],
      tokens: {},
    });
    const changedToken = validateProxyPolicy({
      hosts: ["api.github.com", "raw.githubusercontent.com"],
      tokens: {
        github: {
          description: "Read-only GitHub API token for rate limit and public metadata",
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" },
            { host: "raw.githubusercontent.com", header: "Authorization", scheme: "bearer" },
          ],
        },
      },
    });

    expect(plain.generation).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(legacy.generation).toBe(plain.generation);
    expect(changedHosts.generation).not.toBe(plain.generation);
    expect(changedToken.generation).not.toBe(plain.generation);
  });

  test("validates plain hostname allowlist entries", () => {
    const badPolicy = {
      hosts: ["api.example.com", "https://bad.example.com/path", "API.EXAMPLE.COM", "api.example.com"],
      tokens: {},
    };

    expect(() => validateProxyPolicy(badPolicy)).toThrow(/expected hostname, got URL/);
    expect(() => validateProxyPolicy(badPolicy)).toThrow(/must be stored lowercase/);
    expect(() => validateProxyPolicy(badPolicy)).toThrow(/appears more than once/);
  });

  test("unknown hosts fail closed", () => {
    expect(() => testBeforeAllowedRequest({
      url: "https://example.com",
      headers: {},
    }, {
      allowedHosts: ["api.github.com"],
      credentials: {},
    })).toThrow(/blocked outbound host: example\.com/);
  });

  test("denies non-allowlisted hosts before any token read", () => {
    const tokenReader = vi.fn(() => "real-proxy-token");
    const credentials: CredentialPolicy = {
      "denied.example.com": [{
        host: "denied.example.com",
        header: "Authorization",
        scheme: "bearer",
        tokenName: "github",
        tokenDescription: "GitHub token",
      }],
    };

    expect(() => testBeforeAllowedRequest({
      url: "https://denied.example.com/v1/data",
      headers: { Authorization: "Bearer agent-placeholder" },
    }, {
      allowedHosts: ["api.github.com"],
      credentials,
      tokenReader,
    })).toThrow(/blocked outbound host: denied\.example\.com/);

    // The denial fires before the credential lookup side effect.
    expect(tokenReader).not.toHaveBeenCalled();
  });

  test("rejects an inner host that differs from the admitted CONNECT before token read", () => {
    const admission: AdmissionRecord = {
      v: 1,
      host: "first.example.com",
      port: 443,
      policyGeneration: "sha256:policy-a",
      admittedAtMs: Date.now(),
      connectionSerial: 1,
      stage: "request",
    };
    const tokenReader = vi.fn(() => "real-token");
    const request = {
      url: "https://second.example.com/write",
      headers: { host: "second.example.com" },
    };

    let mismatch: ProxyAdmissionHostMismatchError | undefined;
    try {
      authorizeRequest(admission, request, {
        allowedHosts: ["first.example.com", "second.example.com"],
        credentials: {
          "second.example.com": [{
            host: "second.example.com",
            tokenName: "second",
            tokenDescription: "Second token",
            header: "Authorization",
            scheme: "bearer",
          }],
        },
        tokenReader,
      });
    } catch (error) {
      if (error instanceof ProxyAdmissionHostMismatchError) mismatch = error;
      else throw error;
    }
    expect(mismatch).toMatchObject({
      admittedHost: "first.example.com",
      claimedHost: "second.example.com",
      statusCode: 421,
    });
    expect(tokenReader).not.toHaveBeenCalled();

    expect(() => authorizeRequest(admission, {
      url: "https://denied.example.com/write",
      headers: { host: "denied.example.com" },
    }, {
      allowedHosts: ["first.example.com"],
      credentials: {},
      tokenReader,
    })).toThrow(expect.objectContaining({ statusCode: 403 }));
    expect(tokenReader).not.toHaveBeenCalled();
  });

  test("malformed request URLs fail closed", () => {
    expect(() => testBeforeAllowedRequest({
      url: "not a url",
      headers: {},
    }, {
      allowedHosts: ["api.github.com"],
      credentials: {},
    })).toThrow(/request host <unparseable> does not match admitted CONNECT host api\.github\.com/);
  });

  test("plain HTTP requests fail closed before reaching the firewall", () => {
    expect(() => testBeforeAllowedRequest({
      url: "http://example.com/?token=agent-query-secret",
      headers: {},
    }, {
      allowedHosts: ["example.com"],
      credentials: {},
    })).toThrow(/blocked non-HTTPS outbound URL: http:\/\/example\.com\//);
    expect(() => testBeforeAllowedRequest({
      url: "http://example.com/?token=agent-query-secret",
      headers: {},
    }, {
      allowedHosts: ["example.com"],
      credentials: {},
    })).not.toThrow(/agent-query-secret/);
  });

  test("uncredentialed allowed hosts pass through unchanged", () => {
    const result = testBeforeAllowedRequest({
      url: "https://registry.npmjs.org/lodash",
      headers: { accept: "application/json" },
    }, {
      allowedHosts: ["registry.npmjs.org"],
      credentials: {},
      log: () => {},
    });

    expect(result).toEqual({});
  });

  test("missing required token strips agent-provided auth and rejects the request", () => {
    const credentials: CredentialPolicy = {
      "api.github.com": [{
        tokenName: "github",
        tokenDescription: "token",
        host: "api.github.com",
        header: "Authorization",
        scheme: "bearer",
      }],
    };

    expect(() => testBeforeAllowedRequest({
      url: "https://api.github.com/rate_limit",
      headers: {
        Authorization: "Bearer agent-placeholder",
        accept: "application/json",
      },
    }, {
      allowedHosts: ["api.github.com"],
      credentials,
      tokenReader: () => null,
      log: () => {},
    })).toThrow("missing required proxy token: github");
  });

  test("missing optional token strips agent-provided auth and preserves anonymous access", () => {
    const credentials: CredentialPolicy = {
      "api.github.com": [{
        tokenName: "github",
        tokenDescription: "token",
        allowAnonymous: true,
        host: "api.github.com",
        header: "Authorization",
        scheme: "bearer",
      }],
    };

    const result = testBeforeAllowedRequest({
      url: "https://api.github.com/rate_limit",
      headers: {
        Authorization: "Bearer agent-placeholder",
        accept: "application/json",
      },
    }, {
      allowedHosts: ["api.github.com"],
      credentials,
      tokenReader: () => null,
      log: () => {},
    });

    expect(result).toEqual({
      headers: { accept: "application/json" },
    });
  });

  test("present token overwrites every case variant of the target header", () => {
    const logs: string[] = [];
    const credentials: CredentialPolicy = {
      "api.github.com": [{
        tokenName: "github",
        tokenDescription: "token",
        host: "api.github.com",
        header: "Authorization",
        scheme: "bearer",
      }],
    };

    const result = testBeforeAllowedRequest({
      url: "https://api.github.com/rate_limit",
      headers: {
        Authorization: "Bearer old",
        authorization: "Bearer older",
        accept: "application/json",
      },
    }, {
      allowedHosts: ["api.github.com"],
      credentials,
      tokenReader: () => "real",
      log: (line) => logs.push(line),
    });

    expect(result).toEqual({
      headers: {
        accept: "application/json",
        authorization: "Bearer real",
      },
    });
    expect(logs).toEqual(["proxy: injected Authorization for api.github.com using github"]);
  });

  test("raw token scheme injects the token value without a bearer prefix", () => {
    const credentials: CredentialPolicy = {
      "api.example.com": [{
        tokenName: "example",
        tokenDescription: "token",
        host: "api.example.com",
        header: "X-Api-Key",
        scheme: "raw",
      }],
    };

    const result = testBeforeAllowedRequest({
      url: "https://api.example.com/v1",
      headers: {},
    }, {
      allowedHosts: ["api.example.com"],
      credentials,
      tokenReader: () => "secret",
      log: () => {},
    });

    expect(result).toEqual({
      headers: {
        "x-api-key": "secret",
      },
    });
  });

  test("path-scoped credentials override unscoped host credentials", () => {
    const logs: string[] = [];
    const credentials: CredentialPolicy = {
      "generativelanguage.googleapis.com": [
        {
          tokenName: "gemini",
          tokenDescription: "Gemini API token",
          host: "generativelanguage.googleapis.com",
          header: "x-goog-api-key",
          scheme: "raw",
        },
        {
          tokenName: "gemini",
          tokenDescription: "Gemini API token",
          host: "generativelanguage.googleapis.com",
          header: "Authorization",
          scheme: "bearer",
          pathPrefix: "/v1beta/openai/",
        },
      ],
    };

    const result = testBeforeAllowedRequest({
      url: "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
      headers: {
        "x-goog-api-key": "agent-placeholder",
        Authorization: "Bearer agent-placeholder",
        "content-type": "application/json",
      },
    }, {
      allowedHosts: ["generativelanguage.googleapis.com"],
      credentials,
      tokenReader: () => "real-gemini-key",
      log: (line) => logs.push(line),
    });

    expect(result).toEqual({
      headers: {
        "content-type": "application/json",
        authorization: "Bearer real-gemini-key",
      },
    });
    expect(logs).toEqual([
      "proxy: injected Authorization for generativelanguage.googleapis.com using gemini",
    ]);
  });

  test("unscoped credentials handle non-matching paths after stripping scoped headers", () => {
    const credentials: CredentialPolicy = {
      "generativelanguage.googleapis.com": [
        {
          tokenName: "gemini",
          tokenDescription: "Gemini API token",
          host: "generativelanguage.googleapis.com",
          header: "x-goog-api-key",
          scheme: "raw",
        },
        {
          tokenName: "gemini",
          tokenDescription: "Gemini API token",
          host: "generativelanguage.googleapis.com",
          header: "Authorization",
          scheme: "bearer",
          pathPrefix: "/v1beta/openai/",
        },
      ],
    };

    const result = testBeforeAllowedRequest({
      url: "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent",
      headers: {
        "x-goog-api-key": "agent-placeholder",
        Authorization: "Bearer agent-placeholder",
      },
    }, {
      allowedHosts: ["generativelanguage.googleapis.com"],
      credentials,
      tokenReader: () => "real-gemini-key",
      log: () => {},
    });

    expect(result).toEqual({
      headers: {
        "x-goog-api-key": "real-gemini-key",
      },
    });
  });

  test("path-scoped credentials match exact paths and child paths, not sibling prefixes", () => {
    const credentials: CredentialPolicy = {
      "api.example.com": [
        {
          tokenName: "root",
          tokenDescription: "Root token",
          host: "api.example.com",
          header: "X-Root",
          scheme: "raw",
        },
        {
          tokenName: "mcp",
          tokenDescription: "MCP token",
          host: "api.example.com",
          header: "Authorization",
          scheme: "bearer",
          pathPrefix: "/mcp",
        },
      ],
    };
    const options = {
      allowedHosts: ["api.example.com"],
      credentials,
      tokenReader: (name: string) => `token-${name}`,
      log: () => {},
    };

    expect(testBeforeAllowedRequest({ url: "https://api.example.com/mcp", headers: {} }, options)).toEqual({
      headers: { authorization: "Bearer token-mcp" },
    });
    expect(testBeforeAllowedRequest({ url: "https://api.example.com/mcp/tools", headers: {} }, options)).toEqual({
      headers: { authorization: "Bearer token-mcp" },
    });
    expect(testBeforeAllowedRequest({ url: "https://api.example.com/mcp2", headers: {} }, options)).toEqual({
      headers: { "x-root": "token-root" },
    });
  });

  test("missing optional token strips every configured credential header for the host", () => {
    const credentials: CredentialPolicy = {
      "generativelanguage.googleapis.com": [
        {
          tokenName: "gemini",
          tokenDescription: "Gemini API token",
          allowAnonymous: true,
          host: "generativelanguage.googleapis.com",
          header: "x-goog-api-key",
          scheme: "raw",
        },
        {
          tokenName: "gemini",
          tokenDescription: "Gemini API token",
          allowAnonymous: true,
          host: "generativelanguage.googleapis.com",
          header: "Authorization",
          scheme: "bearer",
          pathPrefix: "/v1beta/openai/",
        },
      ],
    };

    const result = testBeforeAllowedRequest({
      url: "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
      headers: {
        "x-goog-api-key": "agent-placeholder",
        Authorization: "Bearer agent-placeholder",
        accept: "application/json",
      },
    }, {
      allowedHosts: ["generativelanguage.googleapis.com"],
      credentials,
      tokenReader: () => null,
      log: () => {},
    });

    expect(result).toEqual({
      headers: {
        accept: "application/json",
      },
    });
  });

  test("method rules admit listed verbs and deny others before any credential work", () => {
    const tokenReader = vi.fn(() => "real-proxy-token");
    const credentials: CredentialPolicy = {
      "api.example.com": [{
        tokenName: "example",
        tokenDescription: "token",
        host: "api.example.com",
        header: "Authorization",
        scheme: "bearer",
      }],
    };
    const options = {
      allowedHosts: ["api.example.com"],
      credentials,
      requests: { "api.example.com": { methods: ["GET", "HEAD"] as Array<"GET" | "HEAD"> } },
      tokenReader,
      log: () => {},
    };
    const request = (method: string) => testBeforeAllowedRequest({
      url: "https://api.example.com/v1/data",
      method,
      headers: { Authorization: "Bearer agent-placeholder" },
    }, options);

    expect(request("GET")).toEqual({ headers: { authorization: "Bearer real-proxy-token" } });
    expect(tokenReader).toHaveBeenCalledTimes(1);

    tokenReader.mockClear();
    for (const method of ["POST", "DELETE", "get", "Get", "FETCH", "CONNECT", "TRACE"]) {
      const denial = shapeDenial(() => request(method));
      expect(denial.shape).toMatchObject({
        reason: "method-not-allowed",
        host: "api.example.com",
        method,
        allowedMethods: ["GET", "HEAD"],
      });
    }
    // Shape denial fires before the credential lookup side effect.
    expect(tokenReader).not.toHaveBeenCalled();
  });

  test("rule-less hosts keep the pre-tri-state behavior for every verb under an allow posture", () => {
    for (const method of ["GET", "POST", "DELETE", "FETCH", "get"]) {
      expect(testBeforeAllowedRequest({
        url: "https://api.example.com/v1/data",
        method,
        headers: { "X-HTTP-Method-Override": "DELETE" },
      }, {
        allowedHosts: ["api.example.com"],
        credentials: {},
        requests: {},
        writeApproval: "allow",
      })).toEqual({});
    }
  });

  test("strips method-override headers on method-ruled hosts only under an allow posture", () => {
    const headers = {
      "X-HTTP-Method-Override": "DELETE",
      "x-http-method": "DELETE",
      "X-Method-Override": "DELETE",
      accept: "application/json",
    };

    expect(testBeforeAllowedRequest({
      url: "https://ruled.example.com/v1",
      method: "POST",
      headers,
    }, {
      allowedHosts: ["ruled.example.com"],
      credentials: {},
      requests: { "ruled.example.com": { methods: ["POST"] } },
      writeApproval: "allow",
    })).toEqual({ headers: { accept: "application/json" } });

    expect(testBeforeAllowedRequest({
      url: "https://pathonly.example.com/v1",
      method: "POST",
      headers,
    }, {
      allowedHosts: ["pathonly.example.com"],
      credentials: {},
      requests: { "pathonly.example.com": { pathPrefixes: ["/v1"] } },
      writeApproval: "allow",
    })).toEqual({});
  });

  test("path rules follow pathMatchesPrefix and ignore query strings and fragments", () => {
    const options = {
      allowedHosts: ["api.example.com"],
      credentials: {},
      requests: { "api.example.com": { pathPrefixes: ["/api/v2/"] } },
    };
    const request = (path: string) => testBeforeAllowedRequest({
      url: `https://api.example.com${path}`,
      method: "GET",
      headers: {},
    }, options);

    expect(request("/api/v2/")).toEqual({});
    expect(request("/api/v2/items")).toEqual({});
    // Exact prefix without the trailing slash matches per pathMatchesPrefix.
    expect(request("/api/v2/?supplier=/etc/passwd#frag")).toEqual({});
    expect(shapeDenial(() => request("/api/v3/items")).shape).toMatchObject({
      reason: "path-not-allowed",
      host: "api.example.com",
      path: "/api/v3/items",
      allowedPathPrefixes: ["/api/v2/"],
    });
    expect(shapeDenial(() => request("/api/v22/items")).shape?.reason).toBe("path-not-allowed");

    // A root prefix admits every traversal-free path.
    const rootOptions = {
      ...options,
      requests: { "api.example.com": { pathPrefixes: ["/"] } },
    };
    expect(testBeforeAllowedRequest({
      url: "https://api.example.com/anything/at/all",
      method: "GET",
      headers: {},
    }, rootOptions)).toEqual({});
  });

  test("encoded traversal pathnames are denied on path-ruled hosts", () => {
    const options = {
      allowedHosts: ["api.example.com"],
      credentials: {},
      requests: { "api.example.com": { pathPrefixes: ["/api/v2/"] } },
    };
    for (const path of [
      "/api/v2/%2e%2e/secret",
      "/api/v2/%2E%2E/secret",
      "/api/v2/a%2fb",
      "/api/v2/a%5cb",
      "/api/v2/%252e%252e/secret",
      "/api/v2/%zz",
      // Matrix `;param` traversal: servlet origins strip `;params` and reach
      // `../secret`, escaping the prefix.
      "/api/v2/..;/secret",
      // Triple-encoded `..`: only a decode-to-fixed-point guard reduces this
      // to the literal traversal a doubly-decoding origin reaches.
      "/api/v2/%25252e%25252e/secret",
    ]) {
      const denial = shapeDenial(() => testBeforeAllowedRequest({
        url: `https://api.example.com${path}`,
        method: "GET",
        headers: {},
      }, options));
      expect(denial.shape?.reason, path).toBe("path-not-allowed");
    }
    // The same pathnames pass untouched on rule-less hosts.
    expect(testBeforeAllowedRequest({
      url: "https://api.example.com/api/v2/%2e%2e/secret",
      method: "GET",
      headers: {},
    }, { allowedHosts: ["api.example.com"], credentials: {}, requests: {} })).toEqual({});
  });

  test("gitPush deny blocks the push RPC and its capability probe only", () => {
    const options = {
      allowedHosts: ["github.com"],
      credentials: {},
      requests: { "github.com": { gitPush: "deny" as const } },
    };
    const request = (method: string, path: string) => testBeforeAllowedRequest({
      url: `https://github.com${path}`,
      method,
      headers: {},
    }, options);

    expect(shapeDenial(() => request("POST", "/owner/repo.git/git-receive-pack")).shape).toMatchObject({
      reason: "git-push-denied",
      host: "github.com",
      path: "/owner/repo.git/git-receive-pack",
    });
    expect(shapeDenial(() => request("GET", "/owner/repo.git/info/refs?service=git-receive-pack")).shape?.reason)
      .toBe("git-push-denied");

    // Clone and fetch endpoints are unaffected.
    expect(request("POST", "/owner/repo.git/git-upload-pack")).toEqual({});
    expect(request("GET", "/owner/repo.git/info/refs?service=git-upload-pack")).toEqual({});
    expect(request("GET", "/owner/repo.git/info/refs")).toEqual({});
    expect(request("GET", "/owner/repo.git/git-receive-pack-other")).toEqual({});
  });

  test("gitPush deny resists percent-encoded and mixed-case push bypasses", () => {
    const options = {
      allowedHosts: ["github.com"],
      credentials: {},
      // A gitPush-only host runs neither the method nor the pathPrefixes guard,
      // so the git-push decision must normalize encoding on its own.
      requests: { "github.com": { gitPush: "deny" as const } },
    };
    const request = (method: string, path: string) => testBeforeAllowedRequest({
      url: `https://github.com${path}`,
      method,
      headers: {},
    }, options);

    // Percent-encoded final byte of `git-receive-pack` that a decoding origin
    // routes to the push RPC.
    expect(shapeDenial(() => request("POST", "/owner/repo.git/git-receive-pac%6b")).shape?.reason)
      .toBe("git-push-denied");
    // Mixed-case suffix variations.
    expect(shapeDenial(() => request("POST", "/owner/repo.git/Git-Receive-Pack")).shape?.reason)
      .toBe("git-push-denied");
    expect(shapeDenial(() => request("POST", "/owner/repo.git/GIT-RECEIVE-PACK")).shape?.reason)
      .toBe("git-push-denied");
    // Encoded capability-probe path with the push service.
    expect(shapeDenial(() => request("GET", "/owner/repo.git/info/ref%73?service=git-receive-pack")).shape?.reason)
      .toBe("git-push-denied");
    // Doubly-encoded final byte still reduces to the push RPC.
    expect(shapeDenial(() => request("POST", "/owner/repo.git/git-receive-pac%256b")).shape?.reason)
      .toBe("git-push-denied");

    // The fetch RPC and a plain info/refs probe remain allowed even with the
    // same normalization in place.
    expect(request("POST", "/owner/repo.git/git-upload-pack")).toEqual({});
    expect(request("GET", "/owner/repo.git/info/refs")).toEqual({});
    expect(request("GET", "/owner/repo.git/info/refs?service=git-upload-pack")).toEqual({});
  });

  test("WebSocket upgrades evaluate as GET against method and path rules", () => {
    expect(() => testAssertAllowedWebSocketRequest({
      url: "wss://api.example.com/socket",
    }, {
      allowedHosts: ["api.example.com"],
      requests: { "api.example.com": { methods: ["POST"] } },
    })).toThrow(/method is not permitted/);

    expect(() => testAssertAllowedWebSocketRequest({
      url: "wss://api.example.com/socket",
    }, {
      allowedHosts: ["api.example.com"],
      requests: { "api.example.com": { methods: ["GET"], writeAction: "allow" } },
    })).not.toThrow();

    expect(() => testAssertAllowedWebSocketRequest({
      url: "wss://api.example.com/elsewhere",
    }, {
      allowedHosts: ["api.example.com"],
      requests: { "api.example.com": { pathPrefixes: ["/socket/"] } },
    })).toThrow(/blocked request path/);

    expect(() => testAssertAllowedWebSocketRequest({
      url: "wss://api.example.com/socket/v1",
    }, {
      allowedHosts: ["api.example.com"],
      requests: { "api.example.com": { pathPrefixes: ["/socket/"], writeAction: "allow" } },
    })).not.toThrow();
  });

  test("shape denial messages carry the pathname only, never the query string", () => {
    const denial = shapeDenial(() => testBeforeAllowedRequest({
      url: "https://api.example.com/denied/path?api_key=query-secret",
      method: "GET",
      headers: {},
    }, {
      allowedHosts: ["api.example.com"],
      credentials: {},
      requests: { "api.example.com": { pathPrefixes: ["/allowed/"] } },
    }));
    expect(denial.message).toContain("/denied/path");
    expect(denial.message).not.toContain("query-secret");
    expect(denial.shape?.path).toBe("/denied/path");
  });

  test("validates credential path prefixes", () => {
    expect(() => validateProxyPolicy({
      hosts: ["api.example.com"],
      tokens: {
        example: {
          description: "Example token",
          credentials: [
            {
              host: "api.example.com",
              header: "Authorization",
              scheme: "bearer",
              pathPrefix: "v1/openai/",
            },
          ],
        },
      },
    })).toThrow(/pathPrefix must start with \//);

    expect(() => validateProxyPolicy({
      hosts: ["api.example.com"],
      tokens: {
        example: {
          description: "Example token",
          credentials: [
            {
              host: "api.example.com",
              header: "Authorization",
              scheme: "bearer",
              pathPrefix: "/v1/openai/?key=value",
            },
          ],
        },
      },
    })).toThrow(/pathPrefix must not contain query or fragment/);
  });
});

describe("configured credential header union", () => {
  test("collects every configured header name across every token policy, lowercased", () => {
    const credentials: CredentialPolicy = {
      "api.example.com": [
        { host: "api.example.com", header: "Authorization", scheme: "bearer", tokenName: "example", tokenDescription: "Example" },
      ],
      "registry.example.com": [
        { host: "registry.example.com", header: "X-Api-Key", scheme: "raw", tokenName: "registry", tokenDescription: "Registry" },
        { host: "registry.example.com", header: "AUTHORIZATION", scheme: "bearer", tokenName: "registry", tokenDescription: "Registry" },
      ],
    };

    // Audit mode strips this union for non-allowlisted hosts: the per-host
    // credentials entry is empty there, so only the union catches a
    // configured header sent toward an audited host.
    expect(Array.from(configuredCredentialHeaderNames(credentials)).sort())
      .toEqual(["authorization", "x-api-key"]);
    expect(configuredCredentialHeaderNames({}).size).toBe(0);
  });
});

describe("write classification (operation-aware read-only / approve-on-write)", () => {
  const CREDENTIALS: CredentialPolicy = {
    "api.example.com": [
      { host: "api.example.com", header: "Authorization", scheme: "bearer", tokenName: "example", tokenDescription: "Example" },
    ],
  };

  function requestOptions(overrides: Record<string, unknown> = {}) {
    return {
      allowedHosts: ["api.example.com", "git.example.com"],
      credentials: CREDENTIALS,
      requests: {},
      log: () => {},
      ...overrides,
    };
  }

  test("a classified write under writeAction deny is 403'd before any token read", () => {
    const tokenReader = vi.fn(() => "real-proxy-token");
    const denial = shapeDenial(() => testBeforeAllowedRequest({
      method: "POST",
      url: "https://api.example.com/v1/things",
      headers: {},
    }, requestOptions({
      requests: { "api.example.com": { writeAction: "deny" } },
      tokenReader,
    })));

    expect(denial.shape?.reason).toBe("write-denied");
    expect(denial.shape?.writeCategory).toBe("method");
    expect(tokenReader).not.toHaveBeenCalled();
  });

  test("writeAction ask with no grant denies fail-closed with the approval reason and no token read", () => {
    const tokenReader = vi.fn(() => "real-proxy-token");
    const denial = shapeDenial(() => testBeforeAllowedRequest({
      method: "DELETE",
      url: "https://api.example.com/v1/things/1",
      headers: {},
    }, requestOptions({
      requests: { "api.example.com": { writeAction: "ask" } },
      tokenReader,
    })));

    expect(denial.shape?.reason).toBe("write-approval-required");
    expect(tokenReader).not.toHaveBeenCalled();
  });

  test("GET with a method-override header classifies as a write on a host without a methods rule (HIGH-1)", () => {
    const denial = shapeDenial(() => testBeforeAllowedRequest({
      method: "GET",
      url: "https://api.example.com/v1/things",
      headers: { "X-HTTP-Method-Override": "DELETE" },
    }, requestOptions({
      requests: { "api.example.com": { writeAction: "ask" } },
      tokenReader: () => null,
    })));

    expect(denial.shape?.reason).toBe("write-approval-required");
    expect(denial.shape?.writeCategory).toBe("method-override");
  });

  test("reads flow on deny hosts; non-uppercase and extension verbs classify as writes", () => {
    const options = requestOptions({
      requests: { "api.example.com": { writeAction: "deny" } },
      tokenReader: () => "token",
    });
    for (const method of ["GET", "HEAD", "OPTIONS"]) {
      expect(() => testBeforeAllowedRequest({
        method,
        url: "https://api.example.com/v1/things",
        headers: {},
      }, options)).not.toThrow();
    }
    for (const method of ["get", "FETCH", "TRACE"]) {
      const denial = shapeDenial(() => testBeforeAllowedRequest({
        method,
        url: "https://api.example.com/v1/things",
        headers: {},
      }, options));
      expect(denial.shape?.reason).toBe("write-denied");
    }
  });

  test("the compiled policy-level writeApproval default applies to hosts without a per-host writeAction", () => {
    const denial = shapeDenial(() => testBeforeAllowedRequest({
      method: "POST",
      url: "https://api.example.com/v1/things",
      headers: {},
    }, requestOptions({ writeApproval: "deny", tokenReader: () => "token" })));
    expect(denial.shape?.reason).toBe("write-denied");

    // A per-host allow overrides the ask/deny default (opt-out granularity).
    expect(() => testBeforeAllowedRequest({
      method: "POST",
      url: "https://api.example.com/v1/things",
      headers: {},
    }, requestOptions({
      writeApproval: "deny",
      requests: { "api.example.com": { writeAction: "allow" } },
      tokenReader: () => "token",
    }))).not.toThrow();
  });

  test("git push classifies as a write; upload-pack fetch reads pass on declared git hosts", () => {
    const options = requestOptions({
      requests: { "git.example.com": { gitPush: "write", writeAction: "deny" } },
      tokenReader: () => null,
    });

    const push = shapeDenial(() => testBeforeAllowedRequest({
      method: "POST",
      url: "https://git.example.com/org/repo.git/git-receive-pack",
      headers: {},
    }, options));
    expect(push.shape?.reason).toBe("write-denied");
    expect(push.shape?.writeCategory).toBe("git-push");

    const probe = shapeDenial(() => testBeforeAllowedRequest({
      method: "GET",
      url: "https://git.example.com/org/repo.git/info/refs?service=git-receive-pack",
      headers: {},
    }, options));
    expect(probe.shape?.writeCategory).toBe("git-push");

    // git fetch negotiation is a read on a declared git host.
    expect(() => testBeforeAllowedRequest({
      method: "POST",
      url: "https://git.example.com/org/repo.git/git-upload-pack",
      headers: {},
    }, options)).not.toThrow();
    expect(() => testBeforeAllowedRequest({
      method: "GET",
      url: "https://git.example.com/org/repo.git/info/refs?service=git-upload-pack",
      headers: {},
    }, options)).not.toThrow();

    // Without the git declaration the same fetch POST stays a conservative write.
    const undeclared = shapeDenial(() => testBeforeAllowedRequest({
      method: "POST",
      url: "https://api.example.com/org/repo.git/git-upload-pack",
      headers: {},
    }, requestOptions({
      requests: { "api.example.com": { writeAction: "deny" } },
      tokenReader: () => null,
    })));
    expect(undeclared.shape?.reason).toBe("write-denied");
  });

  test("readPathPrefixes classify POST reads; path confusion disqualifies the exemption", () => {
    const options = requestOptions({
      requests: {
        "api.example.com": { writeAction: "deny", readPathPrefixes: ["/search/"] },
      },
      tokenReader: () => "token",
    });

    expect(() => testBeforeAllowedRequest({
      method: "POST",
      url: "https://api.example.com/search/items",
      headers: {},
    }, options)).not.toThrow();

    const outside = shapeDenial(() => testBeforeAllowedRequest({
      method: "POST",
      url: "https://api.example.com/items",
      headers: {},
    }, options));
    expect(outside.shape?.reason).toBe("write-denied");

    const confused = shapeDenial(() => testBeforeAllowedRequest({
      method: "POST",
      url: "https://api.example.com/search/%2e%2e/admin",
      headers: {},
    }, options));
    expect(confused.shape?.reason).toBe("write-denied");

    for (const url of [
      "https://api.example.com/search//items",
      "https://api.example.com/search/%2fitems",
    ]) {
      const duplicateSlash = shapeDenial(() => testBeforeAllowedRequest({
        method: "POST",
        url,
        headers: {},
      }, options));
      expect(duplicateSlash.shape?.reason).toBe("write-denied");
    }
  });

  test("writePathPrefixes classify writes regardless of method", () => {
    const denial = shapeDenial(() => testBeforeAllowedRequest({
      method: "POST",
      url: "https://api.example.com/search/reindex",
      headers: {},
    }, requestOptions({
      requests: {
        "api.example.com": {
          writeAction: "deny",
          readPathPrefixes: ["/search/"],
          writePathPrefixes: ["/search/reindex"],
        },
      },
      tokenReader: () => null,
    })));
    expect(denial.shape?.writeCategory).toBe("write-path");
  });

  test("a POST to a declared GraphQL endpoint classifies as a write even under a covering read prefix", () => {
    const denial = shapeDenial(() => testBeforeAllowedRequest({
      method: "POST",
      url: "https://api.example.com/graphql",
      headers: {},
    }, requestOptions({
      requests: {
        "api.example.com": {
          writeAction: "deny",
          readPathPrefixes: ["/"],
          graphql: { endpoints: ["/graphql"], writeOps: "mutation" },
        },
      },
      tokenReader: () => null,
    })));
    expect(denial.shape?.reason).toBe("write-denied");
    expect(denial.shape?.writeCategory).toBe("graphql");

    // GET-based GraphQL is a read by construction.
    expect(() => testBeforeAllowedRequest({
      method: "GET",
      url: "https://api.example.com/graphql?query=%7B__typename%7D",
      headers: {},
    }, requestOptions({
      requests: {
        "api.example.com": {
          writeAction: "deny",
          graphql: { endpoints: ["/graphql"], writeOps: "mutation" },
        },
      },
      tokenReader: () => "token",
    }))).not.toThrow();
  });

  test("a wss upgrade to an ask or deny host is classified as a write before any upstream connection (HIGH-2)", () => {
    for (const writeAction of ["ask", "deny"] as const) {
      const denial = shapeDenial(() => testAssertAllowedWebSocketRequest({
        method: "GET",
        url: "wss://api.example.com/live",
        headers: {},
      }, {
        allowedHosts: ["api.example.com"],
        requests: { "api.example.com": { writeAction } },
      }));
      expect(denial.shape?.reason).toBe(writeAction === "deny" ? "write-denied" : "write-approval-required");
      expect(denial.shape?.writeCategory).toBe("websocket");
    }

    expect(() => testAssertAllowedWebSocketRequest({
      method: "GET",
      url: "wss://api.example.com/live",
      headers: {},
    }, {
      allowedHosts: ["api.example.com"],
      requests: { "api.example.com": { writeAction: "allow" } },
      writeApproval: "deny",
    })).not.toThrow();
  });

  test("a covering grant lets an ask write proceed with credential injection and agent headers stripped first", () => {
    const tokenReader = vi.fn(() => "real-proxy-token");
    const hasWriteGrant = vi.fn(() => true);
    const mutation = testBeforeAllowedRequest({
      method: "POST",
      url: "https://api.example.com/v1/things",
      headers: { Authorization: "Bearer agent-forged", "X-HTTP-Method": "PUT" },
    }, requestOptions({
      requests: { "api.example.com": { writeAction: "ask" } },
      tokenReader,
      hasWriteGrant,
    }));

    expect(hasWriteGrant).toHaveBeenCalledWith(expect.objectContaining({
      host: "api.example.com",
      method: "POST",
      writeAction: "ask",
      category: "method-override",
    }));
    expect(tokenReader).toHaveBeenCalledWith("example");
    expect(mutation.headers?.authorization).toBe("Bearer real-proxy-token");
    expect(mutation.headers?.Authorization).toBeUndefined();
    // Method-override headers are stripped whenever classification is active.
    expect(mutation.headers?.["X-HTTP-Method"]).toBeUndefined();
  });
});
