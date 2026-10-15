import fs from "node:fs";

import { afterEach, describe, expect, test, vi } from "vitest";
import {
  desiredPolicyDirectProjection,
  type DesiredNetworkPolicyJson,
} from "@runfree/runtime-contracts/desired-network-policy";

import {
  ProxyAdmissionHostMismatchError,
  ProxyPolicyDenialError,
  assertAllowedWebSocketRequest as authorizeWebSocketRequest,
  type CredentialPolicy,
  beforeAllowedRequest as authorizeRequest,
  configuredCredentialHeaderNames,
  gitHttpRequestKind,
  hostFromUrl,
  loadProxyPolicy,
  tokenPath,
  validateProxyPolicy,
  type PolicyOptions,
  type ProxyRequest,
} from "./policy.ts";
import type { AdmissionRecord } from "./admission.ts";

let admissionSerial = 0;

// The template is a desired policy (it carries `version`); the proxy reads its
// direct projection, the same shape the CLI compiles for it.
function templateEffectivePolicy() {
  const templatePath = new URL("../../cli/templates/network-policy.json", import.meta.url).pathname;
  const desired = JSON.parse(fs.readFileSync(templatePath, "utf8")) as DesiredNetworkPolicyJson;
  return validateProxyPolicy(desiredPolicyDirectProjection(desired), templatePath);
}

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
    const policy = templateEffectivePolicy();

    for (const mapping of policy.credentialMappings) {
      expect(policy.allowedHosts, `${mapping.host} is credentialed but not allowlisted`).toContain(mapping.host);
    }
  });

  test("default desired policy grants no network or credential authority", () => {
    const policy = templateEffectivePolicy();

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

  test("basic formats Basic base64(username:token) exactly (T1 golden)", () => {
    const logs: string[] = [];
    const tokenReader = vi.fn(() => "abc");
    const result = testBeforeAllowedRequest({
      url: "https://github.com/owner/repo.git/info/refs?service=git-upload-pack",
      headers: { Authorization: "Basic YWdlbnQ6cGxhY2Vob2xkZXI=" },
    }, {
      allowedHosts: ["github.com"],
      credentials: {
        "github.com": [{
          tokenName: "github",
          tokenDescription: "GitHub token",
          host: "github.com",
          header: "Authorization",
          scheme: "basic",
          username: "x-access-token",
        }],
      },
      tokenReader,
      log: (line) => logs.push(line),
    });

    expect(result).toEqual({ headers: { authorization: "Basic eC1hY2Nlc3MtdG9rZW46YWJj" } });
    expect(tokenReader).toHaveBeenCalledWith("github");
    // The log names the header, host and token, never the encoded value.
    expect(logs).toEqual(["proxy: injected Authorization for github.com using github"]);
  });

  describe("git-http protocol-scoped credentials (T4, T5, T12)", () => {
    const GITHUB_BASIC = {
      tokenName: "github",
      tokenDescription: "GitHub token",
      host: "github.com",
      header: "Authorization",
      scheme: "basic",
      username: "x-access-token",
      protocol: "git-http",
    } as const;
    const GITHUB_BASIC_VALUE = `Basic ${Buffer.from("x-access-token:real-token").toString("base64")}`;

    function githubRequest(method: string, url: string) {
      const tokenReader = vi.fn(() => "real-token");
      const result = testBeforeAllowedRequest({
        method,
        url,
        headers: { Authorization: "Basic YWdlbnQ6cGxhY2Vob2xkZXI=", accept: "*/*" },
      }, {
        allowedHosts: ["github.com", "gist.github.com"],
        credentials: { "github.com": [GITHUB_BASIC] },
        writeApproval: "allow",
        tokenReader,
        log: () => {},
      });
      return { result, tokenReader };
    }

    // Every §4.2 row, with and without `.git`, and with a nested group.
    const ELIGIBLE: ReadonlyArray<{ method: string; tail: string; kind: string }> = [
      { method: "GET", tail: "info/refs?service=git-upload-pack", kind: "refs" },
      { method: "GET", tail: "info/refs?service=git-receive-pack", kind: "refs" },
      { method: "POST", tail: "git-upload-pack", kind: "upload-pack" },
      { method: "POST", tail: "git-receive-pack", kind: "receive-pack" },
      { method: "POST", tail: "info/lfs/objects/batch", kind: "lfs-batch" },
      { method: "GET", tail: "info/lfs/locks", kind: "lfs-locks" },
      { method: "GET", tail: "info/lfs/locks?path=a.bin&limit=10", kind: "lfs-locks" },
      { method: "POST", tail: "info/lfs/locks", kind: "lfs-locks" },
      { method: "POST", tail: "info/lfs/locks/verify", kind: "lfs-locks" },
      { method: "POST", tail: "info/lfs/locks/123_abc-x.y/unlock", kind: "lfs-locks" },
    ];
    const REPOS = ["/owner/repo.git", "/owner/repo", "/group/sub/repo.git"];

    test("T4: the git-http credential is attached for every §4.2 row in .git and non-.git forms", () => {
      for (const repo of REPOS) {
        for (const row of ELIGIBLE) {
          const url = `https://github.com${repo}/${row.tail}`;
          expect(gitHttpRequestKind(row.method, new URL(url)), `${row.method} ${url}`).toBe(row.kind);
          const { result, tokenReader } = githubRequest(row.method, url);
          expect(result, `${row.method} ${url}`).toEqual({ headers: { accept: "*/*", authorization: GITHUB_BASIC_VALUE } });
          expect(tokenReader).toHaveBeenCalledWith("github");
        }
      }
    });

    test("T4: web paths, look-alikes, decorated or encoded spellings, wrong methods, and HEAD get no credential", () => {
      const ineligible: ReadonlyArray<[string, string]> = [
        ["GET", "https://github.com/owner/repo"],
        ["GET", "https://github.com/owner/repo/pulls"],
        ["GET", "https://github.com/owner/repo.git"],
        ["POST", "https://github.com/x/git-upload-pack-not"],
        ["POST", "https://github.com/owner/repo/git-upload-pack%2Fx"],
        ["POST", "https://github.com/owner%2Frepo/git-upload-pack"],
        ["POST", "https://github.com/owner/repo/%67it-upload-pack"],
        ["POST", "https://github.com/owner/repo/git-upload-pack;x"],
        ["POST", "https://github.com/owner/repo/git-upload-pack/"],
        ["POST", "https://github.com/owner/repo/git-upload-pack."],
        ["POST", "https://github.com/owner/repo/git-upload-pack%20"],
        ["POST", "https://github.com/owner/repo/git-upload-pack%00"],
        ["POST", "https://github.com/owner/repo/git-upload-pack%00/rename"],
        ["POST", "https://github.com/owner/repo/git-receive-pack%2500"],
        ["POST", "https://github.com/owner/repo/info/lfs/objects/batch/"],
        ["POST", "https://github.com/owner/repo/info/lfs/objects%2Fbatch"],
        ["POST", "https://github.com/owner/repo/info/lfs/locks/a%20b/unlock"],
        ["POST", "https://github.com/owner/repo/info/lfs/locks/a.../unlock"],
        ["POST", "https://github.com/owner/repo/info/lfs/locks/a/unlock/"],
        ["POST", "https://github.com/owner//repo/git-upload-pack"],
        // Wrong methods for each row, and HEAD (never eligible).
        ["GET", "https://github.com/owner/repo/git-upload-pack"],
        ["PUT", "https://github.com/owner/repo/git-receive-pack"],
        ["DELETE", "https://github.com/owner/repo/git-upload-pack"],
        ["post", "https://github.com/owner/repo/git-upload-pack"],
        ["POST", "https://github.com/owner/repo/info/refs?service=git-upload-pack"],
        ["HEAD", "https://github.com/owner/repo/info/refs?service=git-upload-pack"],
        ["HEAD", "https://github.com/owner/repo/info/lfs/locks"],
        ["GET", "https://github.com/owner/repo/info/lfs/objects/batch"],
        ["GET", "https://github.com/owner/repo/info/lfs/locks/verify"],
        ["DELETE", "https://github.com/owner/repo/info/lfs/locks"],
        // info/refs needs exactly one literal service of a known value.
        ["GET", "https://github.com/owner/repo/info/refs"],
        ["GET", "https://github.com/owner/repo/info/refs?service=git-upload-pack&service=git-receive-pack"],
        ["GET", "https://github.com/owner/repo/info/refs?service=git-upload-pack&%73ervice=git-receive-pack"],
        ["GET", "https://github.com/owner/repo/info/refs?service=git-upload-pack&Service=x"],
        ["GET", "https://github.com/owner/repo/info/refs?service=%67it-upload-pack"],
        ["GET", "https://github.com/owner/repo/info/refs?service=GIT-UPLOAD-PACK"],
        ["GET", "https://github.com/owner/repo/info/refs?service=git-annex"],
        ["GET", "https://github.com/owner/repo/info/refs?service"],
        // No repository segment before the endpoint.
        ["GET", "https://github.com/info/refs?service=git-upload-pack"],
        ["POST", "https://github.com/git-upload-pack"],
        ["POST", "https://github.com/info/lfs/objects/batch"],
        ["POST", "https://github.com/%20/git-upload-pack"],
      ];
      for (const [method, url] of ineligible) {
        expect(gitHttpRequestKind(method, new URL(url)), `${method} ${url}`).toBeUndefined();
        const { result, tokenReader } = githubRequest(method, url);
        // Stripped (the host maps Authorization), never injected.
        expect(result, `${method} ${url}`).toEqual({ headers: { accept: "*/*" } });
        expect(tokenReader, `${method} ${url}`).not.toHaveBeenCalled();
      }
    });

    // git's remote-curl posts to `<remote>/git-upload-pack|git-receive-pack`
    // with no query, and git-lfs posts batch and lock requests to
    // `<lfs endpoint>/objects/batch|locks|locks/verify|locks/<id>/unlock`
    // with the parameters in the JSON body; only the GET lock listing takes a
    // query. An origin that merges query parameters over body parameters
    // (Rails, GitLab) would act on a query the proxy never inspected, so a
    // POST git endpoint with any query is not a git request.
    test("F3: a POST git endpoint with a query string gets no credential; the GET lock listing keeps its query", () => {
      for (const repo of REPOS) {
        for (const tail of [
          "git-upload-pack?x=1",
          "git-receive-pack?service=git-upload-pack",
          "info/lfs/objects/batch?operation=upload",
          "info/lfs/locks?path=a.bin",
          "info/lfs/locks/verify?x",
          "info/lfs/locks/1/unlock?force=true",
        ]) {
          const url = `https://github.com${repo}/${tail}`;
          expect(gitHttpRequestKind("POST", new URL(url)), url).toBeUndefined();
          const { result, tokenReader } = githubRequest("POST", url);
          expect(result, url).toEqual({ headers: { accept: "*/*" } });
          expect(tokenReader, url).not.toHaveBeenCalled();
        }
        // An empty query (a bare `?`) carries no parameter.
        expect(gitHttpRequestKind("POST", new URL(`https://github.com${repo}/git-upload-pack?`))).toBe("upload-pack");
        expect(gitHttpRequestKind("GET", new URL(`https://github.com${repo}/info/lfs/locks?path=a.bin&cursor=c&limit=10&refspec=refs%2Fheads%2Fmain`)))
          .toBe("lfs-locks");
      }
    });

    // Some origins (Python's parse_qs before 3.10, Perl CGI) also split a
    // query on `;`, so `x=1;service=git-receive-pack&service=git-upload-pack`
    // may name a second service the `&`-split count never saw.
    test("F4: an info/refs query with any `;` gets no credential", () => {
      for (const query of [
        "service=git-upload-pack;x=1",
        "x=1;service=git-receive-pack&service=git-upload-pack",
        "service=git-upload-pack&x=1;y",
        ";service=git-upload-pack",
      ]) {
        const url = `https://github.com/owner/repo.git/info/refs?${query}`;
        expect(gitHttpRequestKind("GET", new URL(url)), url).toBeUndefined();
        const { result, tokenReader } = githubRequest("GET", url);
        expect(result, url).toEqual({ headers: { accept: "*/*" } });
        expect(tokenReader, url).not.toHaveBeenCalled();
      }
    });

    // F6: GitLab serves its REST API under `/api/...` and non-git routes
    // behind a `-` segment, where a last segment may be any user-chosen name
    // (`…/repository/files/git-upload-pack` is a file read/write API). Neither
    // is a git request. A github.com owner named `api` is intentionally
    // excluded with them: fail closed over guessing per provider.
    test("F6: an `api` first segment or a `-` route segment is not a git request", () => {
      for (const [method, url] of [
        ["POST", "https://github.com/api/v4/projects/123/repository/files/git-upload-pack"],
        ["POST", "https://github.com/API/v4/projects/123/repository/files/git-upload-pack"],
        ["POST", "https://github.com/%61pi/v4/projects/123/repository/files/git-upload-pack"],
        ["POST", "https://github.com/api/v4/projects/123/repository/files/git-receive-pack"],
        ["POST", "https://github.com/api/repo.git/info/lfs/objects/batch"],
        ["GET", "https://github.com/api/repo.git/info/refs?service=git-upload-pack"],
        ["POST", "https://github.com/group/project/-/git-upload-pack"],
        ["POST", "https://github.com/group/project/-/info/lfs/objects/batch"],
        ["GET", "https://github.com/group/-/project/info/lfs/locks"],
        ["POST", "https://github.com/group/project/-./git-upload-pack"],
      ] as const) {
        expect(gitHttpRequestKind(method, new URL(url)), `${method} ${url}`).toBeUndefined();
        const { result, tokenReader } = githubRequest(method, url);
        expect(result, `${method} ${url}`).toEqual({ headers: { accept: "*/*" } });
        expect(tokenReader, `${method} ${url}`).not.toHaveBeenCalled();
      }
      // `api` only as the first segment; a `-` only as a whole segment.
      expect(gitHttpRequestKind("POST", new URL("https://github.com/owner/api/git-upload-pack"))).toBe("upload-pack");
      expect(gitHttpRequestKind("POST", new URL("https://github.com/my-org/re-po/git-upload-pack"))).toBe("upload-pack");
    });

    test("T4: gist.github.com carries no github.com mapping, so a git request there passes untouched", () => {
      const { result, tokenReader } = githubRequest("GET", "https://gist.github.com/owner/abc.git/info/refs?service=git-upload-pack");
      expect(result).toEqual({});
      expect(tokenReader).not.toHaveBeenCalled();
    });

    const GITLAB: CredentialPolicy = {
      "gitlab.com": [
        {
          tokenName: "gitlab",
          tokenDescription: "GitLab token",
          host: "gitlab.com",
          header: "Authorization",
          scheme: "bearer",
          pathPrefix: "/api/",
        },
        {
          tokenName: "gitlab",
          tokenDescription: "GitLab token",
          host: "gitlab.com",
          header: "Authorization",
          scheme: "basic",
          username: "oauth2",
          protocol: "git-http",
        },
      ],
    };

    test("T5: gitlab /api/v4 gets Bearer, git requests get Basic oauth2:, and /api, /-/ and repo web paths get nothing", () => {
      const tokenReader = vi.fn(() => "real-token");
      const request = (method: string, url: string) => testBeforeAllowedRequest({
        method,
        url,
        headers: { Authorization: "Bearer agent-placeholder", accept: "*/*" },
      }, { allowedHosts: ["gitlab.com"], credentials: GITLAB, writeApproval: "allow", tokenReader, log: () => {} });
      const basic = `Basic ${Buffer.from("oauth2:real-token").toString("base64")}`;
      expect(basic).toBe("Basic b2F1dGgyOnJlYWwtdG9rZW4=");

      expect(request("GET", "https://gitlab.com/api/v4/projects")).toEqual({
        headers: { accept: "*/*", authorization: "Bearer real-token" },
      });
      for (const [method, url] of [
        ["GET", "https://gitlab.com/group/repo.git/info/refs?service=git-upload-pack"],
        ["GET", "https://gitlab.com/group/sub/repo/info/refs?service=git-receive-pack"],
        ["POST", "https://gitlab.com/group/repo.git/git-upload-pack"],
        ["POST", "https://gitlab.com/group/repo.git/git-receive-pack"],
        ["POST", "https://gitlab.com/group/repo.git/info/lfs/objects/batch"],
        ["POST", "https://gitlab.com/group/repo.git/info/lfs/locks/verify"],
      ] as const) {
        expect(request(method, url), `${method} ${url}`).toEqual({ headers: { accept: "*/*", authorization: basic } });
      }
      tokenReader.mockClear();
      for (const url of [
        "https://gitlab.com/api",
        "https://gitlab.com/-/profile",
        "https://gitlab.com/-/user_settings/personal_access_tokens",
        "https://gitlab.com/group/repo",
        "https://gitlab.com/group/repo/-/merge_requests",
      ]) {
        expect(request("GET", url), url).toEqual({ headers: { accept: "*/*" } });
      }
      expect(tokenReader).not.toHaveBeenCalled();
    });

    // F6 (supersedes the earlier "an /api/ git path is still git" case): a
    // path under `/api/` is never a git request (GitLab reserves the `api`
    // namespace for its REST API, where `…/files/git-upload-pack` is a file
    // endpoint), so the git-http mapping is not eligible and the `/api/`
    // Bearer applies as for any API path. Protocol-tier precedence over a
    // pathPrefix is covered by T12.
    test("T5: a git-shaped /api/ path is an API request: it gets the /api/ Bearer, never the git-http Basic", () => {
      for (const url of [
        "https://gitlab.com/api/repo.git/git-upload-pack",
        "https://gitlab.com/api/v4/projects/123/repository/files/git-upload-pack",
      ]) {
        const result = testBeforeAllowedRequest({
          method: "POST",
          url,
          headers: {},
        }, { allowedHosts: ["gitlab.com"], credentials: GITLAB, writeApproval: "allow", tokenReader: () => "t", log: () => {} });
        expect(result, url).toEqual({ headers: { authorization: "Bearer t" } });
      }
    });

    test("T12: an unscoped Bearer and a git-http Basic on one header give Basic on git requests and Bearer elsewhere", () => {
      const credentials: CredentialPolicy = {
        "huggingface.co": [
          {
            tokenName: "hf",
            tokenDescription: "Hugging Face token",
            host: "huggingface.co",
            header: "Authorization",
            scheme: "bearer",
          },
          {
            tokenName: "hf",
            tokenDescription: "Hugging Face token",
            host: "huggingface.co",
            header: "Authorization",
            scheme: "basic",
            username: "hf_user",
            protocol: "git-http",
          },
        ],
      };
      const logs: string[] = [];
      const request = (method: string, url: string) => testBeforeAllowedRequest({
        method,
        url,
        headers: { Authorization: "Bearer agent-placeholder" },
      }, { allowedHosts: ["huggingface.co"], credentials, writeApproval: "allow", tokenReader: () => "hf-token", log: (line) => logs.push(line) });

      expect(request("POST", "https://huggingface.co/org/model/git-upload-pack")).toEqual({
        headers: { authorization: `Basic ${Buffer.from("hf_user:hf-token").toString("base64")}` },
      });
      expect(request("GET", "https://huggingface.co/org/model.git/info/refs?service=git-upload-pack")).toEqual({
        headers: { authorization: `Basic ${Buffer.from("hf_user:hf-token").toString("base64")}` },
      });
      expect(request("GET", "https://huggingface.co/api/models/org/model")).toEqual({
        headers: { authorization: "Bearer hf-token" },
      });
      expect(request("GET", "https://huggingface.co/org/model/resolve/main/config.json")).toEqual({
        headers: { authorization: "Bearer hf-token" },
      });
      // One injection per request: exactly one mapping survived selection.
      expect(logs).toHaveLength(4);
    });

    test("T12: a protocol mapping with a pathPrefix is eligible only on matching git requests", () => {
      const credentials: CredentialPolicy = {
        "git.example.com": [
          {
            tokenName: "scoped",
            tokenDescription: "Scoped token",
            host: "git.example.com",
            header: "Authorization",
            scheme: "basic",
            username: "u",
            protocol: "git-http",
            pathPrefix: "/team/",
          },
        ],
      };
      const tokenReader = vi.fn(() => "t");
      const request = (url: string) => testBeforeAllowedRequest({ method: "POST", url, headers: {} }, {
        allowedHosts: ["git.example.com"], credentials, writeApproval: "allow", tokenReader, log: () => {},
      });
      expect(request("https://git.example.com/team/repo.git/git-upload-pack")).toEqual({
        headers: { authorization: `Basic ${Buffer.from("u:t").toString("base64")}` },
      });
      expect(request("https://git.example.com/other/repo.git/git-upload-pack")).toEqual({});
      expect(request("https://git.example.com/team/repo")).toEqual({});
      expect(tokenReader).toHaveBeenCalledTimes(1);
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

  // Under `writeApproval: allow` the git-push rule is the only check a push
  // meets, so it must match every spelling a routing origin may reduce to the
  // push RPC: by its last path segment, not by a raw suffix.
  test("gitPush deny matches the push RPC by its last path segment under an allow posture", () => {
    const options = {
      allowedHosts: ["github.com"],
      credentials: {},
      writeApproval: "allow" as const,
      requests: { "github.com": { gitPush: "deny" as const } },
    };
    const request = (method: string, path: string) => testBeforeAllowedRequest({
      url: `https://github.com${path}`,
      method,
      headers: {},
    }, options);

    for (const path of [
      "/owner/repo.git/git-receive-pack/",
      "/owner/repo.git/git-receive-pack;x",
      "/owner/repo.git/git-receive-pack%00",
      "/owner/repo.git/git-receive-pack%00.txt",
      "/owner/repo.git/git-receive-pack.",
      "/owner/repo.git/git-receive-pack%2f",
      "/owner/repo.git/git-receive-pack%5c",
      "/owner/repo.git/git-receive-pack%20",
      // Six encoding levels: past the decode bound, so it fails closed.
      "/owner/repo.git/git-receive-pac%2525252525256b",
    ]) {
      expect(shapeDenial(() => request("POST", path)).shape?.reason, path).toBe("git-push-denied");
    }
    for (const path of [
      "/owner/repo.git/info/refs/?service=git-receive-pack",
      "/owner/repo.git/info/refs;x?service=git-receive-pack",
      "/owner/repo.git/info/refs?service=git-upload-pack&service=git-receive-pack",
      "/owner/repo.git/info/refs?service=GIT-RECEIVE-PACK",
      "/owner/repo.git/info/refs?service=git-receive-pac%256b",
    ]) {
      expect(shapeDenial(() => request("GET", path)).shape?.reason, path).toBe("git-push-denied");
    }

    // Look-alike names and the fetch RPC stay allowed.
    expect(request("POST", "/owner/repo.git/git-upload-pack")).toEqual({});
    expect(request("POST", "/owner/repo.git/git-receive-pack-other")).toEqual({});
    expect(request("GET", "/owner/repo/blob/main/git-receive-pack.txt")).toEqual({});
    expect(request("GET", "/owner/repo.git/info/refs?service=git-upload-pack")).toEqual({});
  });

  // Known defects found by policy.property.test.ts (P1.1, P1.3), todo 100.
  // Each pins a path the guard admits today; flip to a plain `test` when the
  // guard denies it.
  describe("known defect: path-confusion guard gaps", () => {
    const options = {
      allowedHosts: ["api.example.com"],
      credentials: {},
      writeApproval: "allow" as const,
      requests: { "api.example.com": { pathPrefixes: ["/api/v2/"] } },
    };
    const request = (path: string) => testBeforeAllowedRequest({
      url: `https://api.example.com${path}`,
      method: "GET",
      headers: {},
    }, options);

    // A NUL-truncating origin reaches `/api/v2/..`, which resolves to `/api`.
    test.fails("P1.1 counterexample: `..%00` escapes the prefix", () => {
      expect(shapeDenial(() => request("/api/v2/..%00")).shape?.reason).toBe("path-not-allowed");
    });
    // `%2e` under seven encoding levels: past the 5-level decode bound, so
    // the guard never sees it, but a decode-to-fixed-point origin reaches `..`.
    test.fails("P1.1 counterexample: an encoded dot past the decode bound escapes the prefix", () => {
      expect(shapeDenial(() => request("/api/v2/.%2525252525252e")).shape?.reason).toBe("path-not-allowed");
    });
    // The proxy judges the parsed path, where `..` removes `..;x` and leaves
    // `/api/v2/`; the raw target is forwarded unchanged, and an origin that
    // strips `;params` first (Tomcat order) resolves `/api/v2/../..` to `/`.
    test.fails("P1.1 counterexample: a `..;x` segment removed by the parser escapes the prefix upstream", () => {
      expect(shapeDenial(() => request("/api/v2/..;x/..")).shape?.reason).toBe("path-not-allowed");
    });
    // `%2f` is denied, but `%252f` is not: only the raw and fully decoded
    // forms are checked, never the intermediate ones.
    test.fails("P1.3 counterexample: a doubly encoded slash is admitted while a singly encoded one is denied", () => {
      expect(shapeDenial(() => request("/api/v2/a%2fb")).shape?.reason).toBe("path-not-allowed");
      expect(shapeDenial(() => request("/api/v2/a%252fb")).shape?.reason).toBe("path-not-allowed");
    });
  });

  // Known defects found by policy.property.test.ts (P1.2), todo 101. The push
  // check canonicalizes in one decoder order; an origin with a different order
  // reaches the push RPC.
  describe("known defect: git-push decoder order", () => {
    const options = {
      allowedHosts: ["github.com"],
      credentials: {},
      writeApproval: "allow" as const,
      requests: { "github.com": { gitPush: "deny" as const } },
    };
    const push = (path: string) => testBeforeAllowedRequest({
      url: `https://github.com${path}`,
      method: "POST",
      headers: {},
    }, options);

    // The proxy cuts at the NUL and sees `repo.git`; an origin that decodes
    // without truncating routes `.../\0/git-receive-pack`.
    test.fails("P1.2 counterexample: a NUL segment before the push RPC hides it", () => {
      expect(shapeDenial(() => push("/owner/repo.git/%00/git-receive-pack")).shape?.reason).toBe("git-push-denied");
    });
    // The proxy decodes first and sees last segment `a`; an origin that strips
    // `;params` before decoding (Tomcat order) routes `git-receive-pack`.
    test.fails("P1.2 counterexample: a param holding an encoded slash hides the push RPC", () => {
      expect(shapeDenial(() => push("/owner/repo.git/git-receive-pack;x%2Fa")).shape?.reason).toBe("git-push-denied");
    });
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

  // F4: an origin that splits the query on `;` may read a service the
  // `&`-split URLSearchParams never shows, and a git client never sends `;`,
  // so any `;` in an info/refs query is a push (fail closed). A `service`
  // spelled with a different case or encoding is also read as a service.
  test("an info/refs query with a `;` or a case/encoding-variant receive-pack service classifies as a push", () => {
    const options = requestOptions({
      requests: { "git.example.com": { gitPush: "deny", writeAction: "allow" } },
      tokenReader: () => null,
    });
    for (const query of [
      "x=1;service=git-receive-pack&service=git-upload-pack",
      "service=git-upload-pack;service=git-receive-pack",
      "service=git-upload-pack;x",
      "Service=git-receive-pack",
      "%73ervice=git-receive-pack",
      "service=git-upload-pack&SERVICE=git-%72eceive-pack",
    ]) {
      const url = `https://git.example.com/org/repo.git/info/refs?${query}`;
      const denial = shapeDenial(() => testBeforeAllowedRequest({ method: "GET", url, headers: {} }, options));
      expect(denial.shape?.reason, url).toBe("git-push-denied");
    }
    // The plain fetch probe is still not a push.
    expect(() => testBeforeAllowedRequest({
      method: "GET",
      url: "https://git.example.com/org/repo.git/info/refs?service=git-upload-pack",
      headers: {},
    }, options)).not.toThrow();
  });

  // F6: the upload-pack and LFS read exemptions use the shared git matcher,
  // so a GitLab API or `-` route ending in an endpoint name is not a read,
  // while push detection keeps matching any receive-pack last segment.
  test("API and `-` routes ending in a git endpoint name get no read exemption and still count as pushes", () => {
    const decide = (method: string, path: string, gitPush: "write" | "deny", extra: Partial<PolicyOptions> = {}) => {
      try {
        testBeforeAllowedRequest({ method, url: `https://gitlab.com${path}`, headers: {} }, {
          ...requestOptions({
            allowedHosts: ["gitlab.com"],
            credentials: {},
            requests: { "gitlab.com": { gitPush, writeAction: "deny" } },
            tokenReader: () => null,
          }),
          ...extra,
        });
        return "read";
      } catch (error) {
        if (error instanceof ProxyPolicyDenialError) return error.shape?.writeCategory ?? error.shape?.reason;
        throw error;
      }
    };
    expect(decide("POST", "/api/v4/projects/123/repository/files/git-upload-pack", "write")).toBe("method");
    expect(decide("POST", "/API/v4/projects/123/repository/files/git-upload-pack", "write")).toBe("method");
    expect(decide("POST", "/group/project/-/git-upload-pack", "write")).toBe("method");
    expect(decide("POST", "/api/v4/x/info/lfs/objects/batch", "write", { lfsBodyClass: "download" })).toBe("method");
    expect(decide("POST", "/group/project/-/info/lfs/objects/batch", "write", { lfsBodyClass: "download" })).toBe("method");
    // Push detection is unchanged: any receive-pack last segment is a push.
    expect(decide("POST", "/api/v4/projects/123/repository/files/git-receive-pack", "write")).toBe("git-push");
    expect(decide("POST", "/group/project/-/git-receive-pack", "deny")).toBe("git-push-denied");
    // The real repository paths are still reads.
    expect(decide("POST", "/group/project.git/git-upload-pack", "write")).toBe("read");
    expect(decide("POST", "/group/project.git/info/lfs/objects/batch", "write", { lfsBodyClass: "download" })).toBe("read");
  });

  test("an LFS batch POST is a read only with a proven download body, on the exact batch endpoint of a git-declared host", () => {
    const options = (rule: Record<string, unknown>) => requestOptions({
      allowedHosts: ["git.example.com"],
      credentials: {},
      requests: { "git.example.com": { writeAction: "deny", ...rule } },
      tokenReader: () => null,
    });
    const batch = "https://git.example.com/org/repo.git/info/lfs/objects/batch";
    const decide = (url: string, rule: Record<string, unknown>, extra: Partial<PolicyOptions> = {}, method = "POST") => {
      try {
        testBeforeAllowedRequest({ method, url, headers: {} }, { ...options(rule), ...extra });
        return "read";
      } catch (error) {
        if (error instanceof ProxyPolicyDenialError) return error.shape?.writeCategory ?? error.message;
        throw error;
      }
    };

    expect(decide(batch, { gitPush: "write" }, { lfsBodyClass: "download" })).toBe("read");
    expect(decide(batch, { gitPush: "deny" }, { lfsBodyClass: "download" })).toBe("read");
    expect(decide("https://git.example.com/org/repo/info/lfs/objects/batch", { gitPush: "write" }, { lfsBodyClass: "download" })).toBe("read");
    // Unproven body (upload, malformed, ...) => the verdict is absent => write.
    expect(decide(batch, { gitPush: "write" })).toBe("method");
    // D-4: no git declaration on the host => no exemption.
    expect(decide(batch, {}, { lfsBodyClass: "download" })).toBe("method");
    // An explicit write rule keeps precedence.
    expect(decide(batch, { gitPush: "write", writePathPrefixes: ["/org/"] }, { lfsBodyClass: "download" })).toBe("write-path");
    // Lock requests and decorated batch spellings stay writes even with a
    // (misapplied) download verdict.
    for (const url of [
      "https://git.example.com/org/repo.git/info/lfs/locks",
      "https://git.example.com/org/repo.git/info/lfs/locks/verify",
      "https://git.example.com/org/repo.git/info/lfs/locks/1/unlock",
      `${batch}/`,
      `${batch};x`,
      "https://git.example.com/org/repo.git/info/lfs/objects/%62atch",
      "https://git.example.com/org/repo.git/info/lfs/objects%2Fbatch",
      `${batch}%00`,
    ]) {
      expect(decide(url, { gitPush: "write" }, { lfsBodyClass: "download" }), url).toBe("method");
    }
    // Only POST: other non-safe methods stay writes.
    expect(decide(batch, { gitPush: "write" }, { lfsBodyClass: "download" }, "PUT")).toBe("method");
    // F3: GitLab (Rails) merges query parameters over the JSON body, so
    // `?operation=upload` on a download body is an upload upstream. Any query
    // disqualifies the read exemption.
    for (const query of ["?operation=upload", "?x=1", "?"]) {
      const expected = query === "?" ? "read" : "method";
      expect(decide(`${batch}${query}`, { gitPush: "write" }, { lfsBodyClass: "download" }), query).toBe(expected);
    }
  });

  // todo 118: the upload-pack read exemption ignored the HTTP method, so a
  // non-POST verb (or a POST to the info/refs capability probe, which has no
  // POST form of its own) on an upload-pack path wrongly read through a
  // `gitPush`-ruled host instead of hitting write approval/deny.
  test("non-POST methods and POST info/refs on an upload-pack path classify as writes (todo 118)", () => {
    const options = requestOptions({
      requests: { "git.example.com": { gitPush: "write", writeAction: "deny" } },
      tokenReader: () => null,
    });
    const request = (method: string, path: string) => shapeDenial(() => testBeforeAllowedRequest({
      method,
      url: `https://git.example.com${path}`,
      headers: {},
    }, options));

    for (const [method, path] of [
      ["DELETE", "/owner/repo.git/git-upload-pack"],
      ["PUT", "/owner/repo.git/git-upload-pack"],
      ["PATCH", "/owner/repo.git/git-upload-pack"],
      ["POST", "/owner/repo.git/info/refs?service=git-upload-pack"],
    ] as const) {
      const denial = request(method, path);
      expect(denial.shape?.reason, `${method} ${path}`).toBe("write-denied");
      expect(denial.shape?.writeCategory, `${method} ${path}`).toBe("method");
    }

    // The canonical fetch RPC stays a read by POST, with or without `.git`,
    // and the GET capability probe stays a read because GET is already safe.
    expect(() => testBeforeAllowedRequest({
      method: "POST",
      url: "https://git.example.com/owner/repo.git/git-upload-pack",
      headers: {},
    }, options)).not.toThrow();
    expect(() => testBeforeAllowedRequest({
      method: "POST",
      url: "https://git.example.com/owner/repo/git-upload-pack",
      headers: {},
    }, options)).not.toThrow();
    expect(() => testBeforeAllowedRequest({
      method: "GET",
      url: "https://git.example.com/owner/repo.git/info/refs?service=git-upload-pack",
      headers: {},
    }, options)).not.toThrow();
  });

  // Look-alike last segments must not match the canonical name: a dash/suffix
  // extension or an extra path segment after `git-upload-pack` is a write.
  test("look-alike git-upload-pack segments stay writes (todo 118)", () => {
    const options = requestOptions({
      requests: { "git.example.com": { gitPush: "write", writeAction: "deny" } },
      tokenReader: () => null,
    });
    const request = (method: string, path: string) => shapeDenial(() => testBeforeAllowedRequest({
      method,
      url: `https://git.example.com${path}`,
      headers: {},
    }, options));

    for (const [method, path] of [
      ["POST", "/x/git-upload-pack-not"],
      ["POST", "/x/git-upload-pack/extra"],
    ] as const) {
      const denial = request(method, path);
      expect(denial.shape?.reason, `${method} ${path}`).toBe("write-denied");
      expect(denial.shape?.writeCategory, `${method} ${path}`).toBe("method");
    }
  });

  // Fix round 1 (todo 118 review): canonicalPathSegments truncates at the
  // first NUL, so a NUL placed after the tail hid a real trailing segment —
  // the request canonicalized to a last segment of "git-upload-pack" even
  // though the raw request kept going past the NUL. The parser also
  // normalizes away a trailing `/`, `;param`, `.`, or encoded space, so a
  // decorated spelling canonicalized to the same name too. The exemption now
  // also requires the raw path to literally end with "/git-upload-pack"
  // (case-insensitively), so none of these read through.
  test("a NUL after the tail, or a decorated spelling, stays a write (todo 118 review)", () => {
    const options = requestOptions({
      requests: { "git.example.com": { gitPush: "write", writeAction: "deny" } },
      tokenReader: () => null,
    });
    const request = (method: string, path: string) => shapeDenial(() => testBeforeAllowedRequest({
      method,
      url: `https://git.example.com${path}`,
      headers: {},
    }, options));

    for (const [method, path] of [
      ["POST", "/o/r/branches/git-upload-pack%00/rename"],
      ["POST", "/o/r/git-upload-pack%00/x"],
      // Double-encoded NUL: one decode exposes %00, the next decodes to NUL.
      ["POST", "/o/r/git-upload-pack%2500/rename"],
      ["POST", "/owner/repo.git/git-upload-pack/"],
      ["POST", "/owner/repo.git/git-upload-pack;x"],
      ["POST", "/owner/repo.git/git-upload-pack."],
      ["POST", "/owner/repo.git/git-upload-pack%20"],
      // A decoy "git-upload-pack" before the NUL makes the truncated
      // canonical segment and the raw suffix agree with each other, so this
      // one depends on the decoded-NUL check specifically, not on either of
      // the other two conditions disagreeing.
      ["POST", "/o/git-upload-pack%00/git-upload-pack"],
    ] as const) {
      const denial = request(method, path);
      expect(denial.shape?.reason, `${method} ${path}`).toBe("write-denied");
      expect(denial.shape?.writeCategory, `${method} ${path}`).toBe("method");
    }

    // The exact canonical RPC, with or without `.git`, keeps reading.
    expect(() => testBeforeAllowedRequest({
      method: "POST",
      url: "https://git.example.com/owner/repo.git/git-upload-pack",
      headers: {},
    }, options)).not.toThrow();
    expect(() => testBeforeAllowedRequest({
      method: "POST",
      url: "https://git.example.com/owner/repo/git-upload-pack",
      headers: {},
    }, options)).not.toThrow();
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

describe("OAuth protocol-read classification", () => {
  const url = "https://auth.example.com/oauth/token";
  const base: PolicyOptions = {
    allowedHosts: ["auth.example.com"],
    requests: { "auth.example.com": { methods: ["GET", "HEAD", "OPTIONS", "POST"], pathPrefixes: ["/.well-known", "/oauth/token"] } },
  };

  test("a POST the mediator proved protocol-shaped passes an ask host without a grant", () => {
    const hasWriteGrant = vi.fn(() => false);
    expect(() => testBeforeAllowedRequest({ method: "POST", url }, { ...base, oauthProtocolRead: true, hasWriteGrant })).not.toThrow();
    expect(hasWriteGrant).not.toHaveBeenCalled();
  });

  test("without the proof the same POST is a write that needs approval", () => {
    const denial = shapeDenial(() => testBeforeAllowedRequest({ method: "POST", url }, base));
    expect(denial.shape?.reason).toBe("write-approval-required");
  });

  test("an explicit deny stays denied: the read class applies only to ask", () => {
    const denial = shapeDenial(() => testBeforeAllowedRequest({ method: "POST", url }, { ...base, writeApproval: "deny", oauthProtocolRead: true }));
    expect(denial.shape?.reason).toBe("write-denied");
  });

  test.each([
    ["another method", { method: "PUT", url }, "method-not-allowed"],
    ["a method-override header", { method: "POST", url, headers: { "x-http-method-override": "DELETE" } }, "write-approval-required"],
  ] as const)("never makes %s a read", (_label, req, reason) => {
    const denial = shapeDenial(() => testBeforeAllowedRequest(req, { ...base, oauthProtocolRead: true }));
    expect(denial.shape?.reason).toBe(reason);
  });

  test("a PUT on a host without method rules stays a write even with the flag", () => {
    const denial = shapeDenial(() => testBeforeAllowedRequest({ method: "PUT", url }, { allowedHosts: ["auth.example.com"], oauthProtocolRead: true }));
    expect(denial.shape?.reason).toBe("write-approval-required");
  });

  test("an explicit write path rule wins over the protocol read", () => {
    const denial = shapeDenial(() => testBeforeAllowedRequest({ method: "POST", url }, {
      allowedHosts: ["auth.example.com"],
      requests: { "auth.example.com": { writePathPrefixes: ["/oauth"] } },
      oauthProtocolRead: true,
    }));
    expect(denial.shape?.writeCategory).toBe("write-path");
  });

  test("an MCP operation classification takes precedence over the protocol read", () => {
    const denial = shapeDenial(() => testBeforeAllowedRequest({ method: "POST", url }, {
      ...base,
      oauthProtocolRead: true,
      mcpClassification: { kind: "unclassifiable", category: "mcp-unknown", reason: "non-json", writeAction: "ask" },
    }));
    expect(denial.shape?.reason).toBe("write-approval-required");
  });
});
