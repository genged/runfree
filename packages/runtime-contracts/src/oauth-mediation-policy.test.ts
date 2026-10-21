import { describe, expect, test } from "vitest";

import {
  oauthHostRefusedForProvider,
  oauthMediationPolicyJson,
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

describe("cross-host token endpoint contract fields", () => {
  const MCP = { kind: "mcp" as const, resourceHost: "api.ahrefs.com", tokenEndpoints: [{ host: "ahrefs.com", path: "/oauth/token" }] };

  const validate = (top: Record<string, unknown>, provider: Record<string, unknown> = {}) =>
    validateOAuthMediationPolicy({ ...top, providers: { "mcp:claude-ahrefs": { ...MCP, ...provider } } });

  test("absent fields load as empty and leave the provider unchanged", () => {
    const loaded = validate({});
    expect(loaded.recordOnlyHosts).toEqual([]);
    expect(loaded.refusedHosts).toEqual([]);
    expect(loaded.blockedEndpoints).toEqual([]);
    expect(loaded.providers[0].bindingHosts).toEqual([]);
    expect(loaded.providers[0].captureOwner).toBeUndefined();
    expect(oauthMediationPolicyJson(loaded)).toEqual({
      providers: { "mcp:claude-ahrefs": oauthProviderPolicyJson(loaded.providers[0]) },
    });
    expect(Object.keys(oauthMediationPolicyJson(loaded))).toEqual(["providers"]);
  });

  test("loads valid fields with host lists and blocked endpoints sorted", () => {
    const loaded = validate({
      recordOnlyHosts: ["zeta.example.com", "ahrefs.com"],
      refusedHosts: ["github.com", "api.anthropic.com"],
      blockedEndpoints: [
        { host: "b.example.com", path: "/token" },
        { host: "a.example.com", path: "/z" },
        { host: "a.example.com", path: "/a" },
      ],
    }, {
      bindingHosts: ["user.example.com", "ahrefs.com"],
      captureOwner: false,
      registrationEndpoints: [{ host: "ahrefs.com", path: "/oauth/register", exact: true }],
    });
    expect(loaded.recordOnlyHosts).toEqual(["ahrefs.com", "zeta.example.com"]);
    expect(loaded.refusedHosts).toEqual(["api.anthropic.com", "github.com"]);
    expect(loaded.blockedEndpoints).toEqual([
      { host: "a.example.com", path: "/a" },
      { host: "a.example.com", path: "/z" },
      { host: "b.example.com", path: "/token" },
    ]);
    expect(loaded.providers[0]).toMatchObject({
      bindingHosts: ["ahrefs.com", "user.example.com"],
      captureOwner: false,
      registrationEndpoints: [{ host: "ahrefs.com", path: "/oauth/register", exact: true }],
    });
  });

  test("round-trips every new field through the JSON form", () => {
    const loaded = validate({
      recordOnlyHosts: ["ahrefs.com"],
      refusedHosts: ["github.com"],
      blockedEndpoints: [{ host: "blocked.example.com", path: "/oauth/token" }],
    }, {
      bindingHosts: ["ahrefs.com"],
      captureOwner: false,
      registrationEndpoints: [
        { host: "ahrefs.com", path: "/oauth/register", exact: true },
        { host: "api.ahrefs.com", path: "/mcp/register" },
      ],
    });
    const json = oauthMediationPolicyJson(loaded);
    expect(json.providers["mcp:claude-ahrefs"].registrationEndpoints).toEqual([
      { exact: true, host: "ahrefs.com", path: "/oauth/register" },
      { host: "api.ahrefs.com", path: "/mcp/register" },
    ]);
    expect(validateOAuthMediationPolicy(JSON.parse(JSON.stringify(json)))).toEqual(loaded);
  });

  test("a URL-string registration endpoint stays prefix-matched", () => {
    const loaded = validate({}, { registrationEndpoints: ["https://api.ahrefs.com/mcp/register"] });
    expect(loaded.providers[0].registrationEndpoints).toEqual([{ host: "api.ahrefs.com", path: "/mcp/register" }]);
  });

  const hostCases: Array<[string, unknown, RegExp]> = [
    ["an uppercase host", "Ahrefs.com", /exact normalized hostname ahrefs\.com/],
    ["a host with surrounding whitespace", " ahrefs.com", /exact normalized hostname/],
    ["a trailing-dot host", "ahrefs.com.", /must not end with a dot/],
    ["an IPv4 literal", "192.0.2.1", /not an IP address/],
    ["a numeric last label", "foo.0x7f", /not an IP address/],
    ["an IPv6 literal", "::1", /without port|hostname/],
    ["a localhost name", "app.localhost", /localhost/],
    ["a reserved runfree.internal name", "gateway.runfree.internal", /runfree\.internal/],
    ["a single-label host", "intranet", /fully-qualified/],
    ["a URL", "https://ahrefs.com", /got URL/],
    ["a wildcard", "*.ahrefs.com", /wildcard/],
    ["a non-string", 7, /must be a hostname string/],
  ];

  test.each(hostCases)("recordOnlyHosts refuses %s", (_label, host, message) => {
    expect(() => validate({ recordOnlyHosts: [host] })).toThrow(message);
  });

  test.each(hostCases)("refusedHosts refuses %s", (_label, host, message) => {
    expect(() => validate({ refusedHosts: [host] })).toThrow(message);
  });

  test.each(hostCases)("bindingHosts refuses %s", (_label, host, message) => {
    expect(() => validate({}, { bindingHosts: [host] })).toThrow(message);
  });

  test.each(hostCases)("blockedEndpoints refuses a host that is %s", (_label, host, message) => {
    expect(() => validate({ blockedEndpoints: [{ host, path: "/token" }] })).toThrow(message);
  });

  test.each([
    ["recordOnlyHosts", { recordOnlyHosts: ["a.example.com", "a.example.com"] }, {}, /recordOnlyHosts\[1\] duplicates a\.example\.com/],
    ["refusedHosts", { refusedHosts: ["a.example.com", "a.example.com"] }, {}, /refusedHosts\[1\] duplicates/],
    ["bindingHosts", {}, { bindingHosts: ["a.example.com", "a.example.com"] }, /bindingHosts\[1\] duplicates/],
    ["blockedEndpoints", {
      blockedEndpoints: [{ host: "a.example.com", path: "/t" }, { host: "a.example.com", path: "/t" }],
    }, {}, /blockedEndpoints\[1\] duplicates a\.example\.com\/t/],
  ])("refuses duplicates in %s", (_label, top, provider, message) => {
    expect(() => validate(top, provider)).toThrow(message);
  });

  test.each([
    ["recordOnlyHosts that is not an array", { recordOnlyHosts: "ahrefs.com" }, {}, /recordOnlyHosts must be an array/],
    ["refusedHosts that is not an array", { refusedHosts: { host: "github.com" } }, {}, /refusedHosts must be an array/],
    ["bindingHosts that is not an array", {}, { bindingHosts: "ahrefs.com" }, /bindingHosts must be an array/],
    ["blockedEndpoints that is not an array", { blockedEndpoints: "https://a.example.com/t" }, {}, /blockedEndpoints must be an array/],
    ["a blocked endpoint as a URL string", { blockedEndpoints: ["https://a.example.com/t"] }, {}, /blockedEndpoints\[0\] must be a \{host,path\} object/],
    ["a blocked endpoint with a non-string path", { blockedEndpoints: [{ host: "a.example.com", path: 1 }] }, {}, /blockedEndpoints\[0\]\.path must be a string/],
    ["a blocked endpoint path with a query", { blockedEndpoints: [{ host: "a.example.com", path: "/t?x=1" }] }, {}, /query or fragment/],
    ["a relative blocked endpoint path", { blockedEndpoints: [{ host: "a.example.com", path: "t" }] }, {}, /must start with \//],
    ["a blocked endpoint path with whitespace", { blockedEndpoints: [{ host: "a.example.com", path: "/t " }] }, {}, /without surrounding whitespace/],
    ["a blocked endpoint with an exact flag", { blockedEndpoints: [{ host: "a.example.com", path: "/t", exact: true }] }, {}, /unsupported fields: exact/],
    ["captureOwner true", {}, { captureOwner: true }, /captureOwner must be false/],
    ["captureOwner as a string", {}, { captureOwner: "false" }, /captureOwner must be false/],
  ])("refuses %s", (_label, top, provider, message) => {
    expect(() => validate(top, provider)).toThrow(message);
  });

  test.each([
    ["bindingHosts", { bindingHosts: ["ahrefs.com"] }, /bindingHosts are only supported for mcp providers/],
    ["captureOwner", { captureOwner: false }, /captureOwner is only supported for mcp providers/],
  ])("refuses %s on a service provider", (_label, extra, message) => {
    expect(() => validateOAuthMediationPolicy({
      providers: { "service:x": { kind: "service", resourceHost: "api.example.com", tokenEndpoints: ["https://auth.example.com/t"], ...extra } },
    })).toThrow(message);
  });

  test.each([
    ["a token endpoint", { tokenEndpoints: [{ host: "ahrefs.com", path: "/oauth/token", exact: true }] }, /tokenEndpoints\[0\]\.exact is only supported on registration endpoints/],
    ["a metadata endpoint", { metadataEndpoints: [{ host: "ahrefs.com", path: "/.well-known/x", exact: true }] }, /metadataEndpoints\[0\]\.exact is only supported/],
    ["a protocol-read endpoint", {
      protocolReadEndpoints: [{ host: "ahrefs.com", path: "/oauth/token", exact: true }],
    }, /protocolReadEndpoints\[0\]\.exact is only supported/],
  ])("refuses the exact flag on %s", (_label, extra, message) => {
    expect(() => validate({}, extra)).toThrow(message);
  });

  test.each([
    ["false", false],
    ["a string", "true"],
  ])("refuses a registration exact flag that is %s", (_label, exact) => {
    expect(() => validate({}, { registrationEndpoints: [{ host: "ahrefs.com", path: "/r", exact }] })).toThrow(/exact must be true/);
  });

  test("refuses one registration endpoint listed both exact and by prefix", () => {
    expect(() => validate({}, {
      registrationEndpoints: [
        { host: "ahrefs.com", path: "/r", exact: true },
        "https://ahrefs.com/r",
      ],
    })).toThrow(/ahrefs\.com\/r both exact and by prefix/);
  });

  test("an exact registration endpoint can be a protocol-read endpoint", () => {
    const loaded = validate({}, {
      registrationEndpoints: [{ host: "ahrefs.com", path: "/r", exact: true }],
      protocolReadEndpoints: [{ host: "ahrefs.com", path: "/r" }],
    });
    expect(loaded.providers[0].protocolReadEndpoints).toEqual([{ host: "ahrefs.com", path: "/r" }]);
  });

  test("refusedHosts exempt only the provider's own resource host", () => {
    const loaded = validate({ refusedHosts: ["api.ahrefs.com", "github.com"] }, { bindingHosts: ["github.com"] });
    const [provider] = loaded.providers;
    expect(oauthHostRefusedForProvider(loaded, provider, "api.ahrefs.com")).toBe(false);
    // A binding (user) host is not exempt.
    expect(oauthHostRefusedForProvider(loaded, provider, "github.com")).toBe(true);
    expect(oauthHostRefusedForProvider(loaded, provider, "ahrefs.com")).toBe(false);
    expect(oauthHostRefusedForProvider(loaded, { resourceHost: "github.com" }, "github.com")).toBe(false);
    expect(oauthHostRefusedForProvider(loaded, { resourceHost: "github.com" }, "api.ahrefs.com")).toBe(true);
  });
});
