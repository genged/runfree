import { describe, expect, test } from "vitest";

import {
  oauthProviderPolicyJson,
  validateOAuthMediationPolicy,
  type OAuthMediationPolicyJson,
} from "./oauth-mediation-policy.ts";

describe("OAuth mediation policy", () => {
  test("normalizes curated service providers with token-name-compatible seed refs", () => {
    const policy: OAuthMediationPolicyJson = {
      providers: {
        "service:google-ads": {
          kind: "service",
          resourceHost: "googleads.googleapis.com",
          tokenEndpoints: ["https://oauth2.googleapis.com/token"],
          seeds: [
            {
              field: "refresh_token",
              handle: "runfree_oauth_refresh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              secretRef: "oauth-google-ads-refresh-token",
            },
            {
              field: "client_secret",
              handle: "runfree_oauth_secret_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              secretRef: "oauth-google-ads-client-secret",
            },
          ],
        },
      },
    };

    const loaded = validateOAuthMediationPolicy(policy, "oauth-policy.json");

    expect(loaded.providers.map((provider) => provider.providerId)).toEqual(["service:google-ads"]);
    expect(loaded.providers[0]).toMatchObject({
      kind: "service",
      providerId: "service:google-ads",
      resourceHost: "googleads.googleapis.com",
      resourcePathPrefix: "/",
      tokenEndpoints: [{ host: "oauth2.googleapis.com", path: "/token" }],
      seeds: [
        {
          field: "refresh_token",
          handle: "runfree_oauth_refresh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          secretRef: "oauth-google-ads-refresh-token",
        },
        {
          field: "client_secret",
          handle: "runfree_oauth_secret_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          secretRef: "oauth-google-ads-client-secret",
        },
      ],
    });
  });

  test("rejects path-like seed refs and non-service seeds before proxy startup", () => {
    expect(() => validateOAuthMediationPolicy({
      providers: {
        "service:bad": {
          kind: "service",
          resourceHost: "api.example.com",
          tokenEndpoints: ["https://auth.example.com/token"],
          seeds: [
            {
              field: "refresh_token",
              handle: "runfree_oauth_refresh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              secretRef: "../refresh-token",
            },
          ],
        },
        "mcp:bad": {
          kind: "mcp",
          resourceHost: "mcp.example.com",
          tokenEndpoints: ["https://mcp.example.com/token"],
          seeds: [
            {
              field: "client_secret",
              handle: "runfree_oauth_secret_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              secretRef: "oauth-bad-client-secret",
            },
          ],
        },
      },
    }, "oauth-policy.json")).toThrow(/secretRef|mcp:bad/);
  });

  const EPOCH = "0123456789abcdef0123456789abcdef";

  test("keeps an MCP provider's state epoch and protocol-read endpoints that are static mediated endpoints", () => {
    const loaded = validateOAuthMediationPolicy({
      providers: {
        "mcp:claude-linear": {
          kind: "mcp",
          resourceHost: "mcp.example.com",
          stateEpoch: EPOCH,
          tokenEndpoints: [{ host: "auth.example.com", path: "/oauth/token" }],
          registrationEndpoints: [{ host: "auth.example.com", path: "/oauth/register" }],
          protocolReadEndpoints: [
            { host: "auth.example.com", path: "/oauth/token" },
            { host: "auth.example.com", path: "/oauth/register" },
          ],
        },
      },
    });
    expect(loaded.providers[0]).toMatchObject({
      stateEpoch: EPOCH,
      protocolReadEndpoints: [
        { host: "auth.example.com", path: "/oauth/token" },
        { host: "auth.example.com", path: "/oauth/register" },
      ],
    });
  });

  test("omits the state epoch and protocol-read endpoints when a provider declares none", () => {
    const loaded = validateOAuthMediationPolicy({
      providers: { "mcp:claude-a": { resourceHost: "mcp.example.com", tokenEndpoints: ["https://auth.example.com/token"] } },
    });
    expect(loaded.providers[0].stateEpoch).toBeUndefined();
    expect(loaded.providers[0].protocolReadEndpoints).toEqual([]);
  });

  test.each([
    ["a short epoch", { stateEpoch: "abc" }, /stateEpoch/],
    ["an epoch with other characters", { stateEpoch: "0123456789abcdef/0123456789abcdef" }, /stateEpoch/],
    ["a non-string epoch", { stateEpoch: 12 }, /stateEpoch/],
    ["a protocol-read endpoint that is not mediated statically", {
      protocolReadEndpoints: [{ host: "auth.example.com", path: "/other" }],
    }, /protocolReadEndpoints/],
    ["a protocol-read endpoint on another host", {
      protocolReadEndpoints: [{ host: "evil.example.com", path: "/token" }],
    }, /protocolReadEndpoints/],
    ["a root protocol-read endpoint", {
      tokenEndpoints: [{ host: "auth.example.com", path: "/" }],
      protocolReadEndpoints: [{ host: "auth.example.com", path: "/" }],
    }, /protocolReadEndpoints/],
    ["protocol-read endpoints that are not an array", { protocolReadEndpoints: "https://auth.example.com/token" }, /protocolReadEndpoints/],
  ])("refuses %s", (_label, extra, message) => {
    expect(() => validateOAuthMediationPolicy({
      providers: {
        "mcp:claude-a": {
          kind: "mcp",
          resourceHost: "mcp.example.com",
          tokenEndpoints: [{ host: "auth.example.com", path: "/token" }],
          ...extra,
        },
      },
    })).toThrow(message);
  });

  // One field per case: with both on one provider, either refusal alone
  // would satisfy the assertion.
  test.each([
    ["a state epoch", { stateEpoch: EPOCH }, /stateEpoch is only supported for mcp providers/],
    ["protocol-read endpoints", {
      protocolReadEndpoints: [{ host: "auth.example.com", path: "/token" }],
    }, /protocolReadEndpoints are only supported for mcp providers/],
  ])("refuses %s on a service provider", (_label, extra, message) => {
    expect(() => validateOAuthMediationPolicy({
      providers: {
        "service:x": {
          kind: "service",
          resourceHost: "api.example.com",
          tokenEndpoints: [{ host: "auth.example.com", path: "/token" }],
          ...extra,
        },
      },
    })).toThrow(message);
  });
});

describe("OAuth provider serialization", () => {
  test("round-trips every validated provider field, including the state epoch and protocol-read endpoints", () => {
    const loaded = validateOAuthMediationPolicy({
      providers: {
        "mcp:claude-linear": {
          kind: "mcp",
          resourceHost: "mcp.example.com",
          resourcePathPrefix: "/mcp",
          stateEpoch: "0123456789abcdef0123456789abcdef",
          oauth: { authServerMetadataUrl: "https://auth.example.com/.well-known/oauth-authorization-server" },
          tokenEndpoints: [{ host: "auth.example.com", path: "/oauth/token" }],
          registrationEndpoints: [{ host: "auth.example.com", path: "/oauth/register" }],
          protocolReadEndpoints: [{ host: "auth.example.com", path: "/oauth/token" }],
        },
      },
    });
    const json = { providers: Object.fromEntries(loaded.providers.map((provider) => [provider.providerId, oauthProviderPolicyJson(provider)])) };
    expect(validateOAuthMediationPolicy(json)).toEqual(loaded);
  });

  test("serializes a provider without the new fields exactly as before", () => {
    const [provider] = validateOAuthMediationPolicy({
      providers: { "mcp:claude-a": { resourceHost: "mcp.example.com", tokenEndpoints: ["https://auth.example.com/token"] } },
    }).providers;
    expect(oauthProviderPolicyJson(provider)).toEqual({
      kind: "mcp",
      resourceHost: "mcp.example.com",
      resourcePathPrefix: "/",
      tokenEndpoints: [{ host: "auth.example.com", path: "/token" }],
      registrationEndpoints: [],
      metadataEndpoints: [],
      seeds: [],
    });
  });
});
