import { describe, expect, test } from "vitest";

import {
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
});
