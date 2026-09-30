import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { validateOAuthMediationPolicy } from "@runfree/runtime-contracts/oauth-mediation-policy";
import { OAuthMediator } from "./oauth-mediation.ts";
import {
  plainRequestPath,
  protocolReadBodyAllowed,
  ProtocolReadRateLimiter,
} from "./oauth-protocol-read.ts";

const FORM = "application/x-www-form-urlencoded";
const TOKEN_URL = "https://auth.example.test/oauth/token";
const REGISTER_URL = "https://auth.example.test/oauth/register";

function formHeaders(body: string, extra: Record<string, string | string[]> = {}) {
  return { "content-type": FORM, "content-length": String(Buffer.byteLength(body)), ...extra };
}

function jsonHeaders(body: string, extra: Record<string, string | string[]> = {}) {
  return { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)), ...extra };
}

describe("plainRequestPath", () => {
  test("returns the exact path as sent", () => {
    expect(plainRequestPath(TOKEN_URL)).toBe("/oauth/token");
    expect(plainRequestPath("https://auth.example.test")).toBe("/");
  });

  test.each([
    ["a dot-dot segment", "https://auth.example.test/api/x/../../oauth/token"],
    ["a dot segment", "https://auth.example.test/./oauth/token"],
    ["percent-encoding", "https://auth.example.test/oauth%2ftoken"],
    ["an encoded dot", "https://auth.example.test/%2e%2e/oauth/token"],
    ["a matrix parameter", "https://auth.example.test/oauth/token;x=1"],
    ["a double slash", "https://auth.example.test//oauth/token"],
    ["a backslash", "https://auth.example.test/oauth\\token"],
    ["a query", `${TOKEN_URL}?x=1`],
    ["an empty query", `${TOKEN_URL}?`],
    ["a fragment", `${TOKEN_URL}#x`],
    ["non-ASCII", "https://auth.example.test/oauth/tökén"],
    ["plain http", "http://auth.example.test/oauth/token"],
  ])("refuses %s", (_label, url) => {
    expect(plainRequestPath(url)).toBeUndefined();
  });
});

describe("protocolReadBodyAllowed", () => {
  const code = "grant_type=authorization_code&code=abc&redirect_uri=http%3A%2F%2Flocalhost%3A33418%2Fcallback&code_verifier=v&client_id=c";
  const refresh = "grant_type=refresh_token&refresh_token=runfree_oauth_refresh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&client_id=c";
  const registration = JSON.stringify({
    client_name: "Claude Code (linear)",
    redirect_uris: ["http://localhost:33418/callback"],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  });

  test.each([
    ["an authorization-code grant", code],
    ["a refresh grant", refresh],
  ])("allows %s", (_label, body) => {
    expect(protocolReadBodyAllowed({ kind: "token", bodyText: body, headers: formHeaders(body) })).toBe(true);
  });

  test("allows a media-type parameter", () => {
    expect(protocolReadBodyAllowed({ kind: "token", bodyText: code, headers: formHeaders(code, { "content-type": `${FORM}; charset=UTF-8` }) })).toBe(true);
  });

  test("allows a loopback-only dynamic client registration", () => {
    expect(protocolReadBodyAllowed({ kind: "registration", bodyText: registration, headers: jsonHeaders(registration) })).toBe(true);
  });

  test.each([
    ["a client-credentials grant", "grant_type=client_credentials&client_id=c"],
    ["a token-exchange grant", "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=x"],
    ["a client assertion", `${code}&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=eyJ`],
    ["an unknown field", `${code}&data=exfil`],
    ["a duplicate field", `${code}&code=second`],
    ["a non-loopback redirect", "grant_type=authorization_code&code=abc&redirect_uri=https%3A%2F%2Fevil.example%2Fcb"],
    ["no grant type", "code=abc"],
  ])("refuses a token body with %s", (_label, body) => {
    expect(protocolReadBodyAllowed({ kind: "token", bodyText: body, headers: formHeaders(body) })).toBe(false);
  });

  test.each([
    ["JSON instead of a form", { "content-type": "application/json" }],
    ["two content types", { "content-type": [FORM, "application/json"] }],
    ["a compressed body", { "content-encoding": "gzip" }],
    ["a chunked body", { "transfer-encoding": "chunked" }],
    ["no content length", { "content-length": "" }],
    ["a wrong content length", { "content-length": "3" }],
    ["an oversize body", { "content-length": "20000" }],
  ])("refuses a token request with %s", (_label, extra) => {
    const headers = { ...formHeaders(code), ...extra } as Record<string, string | string[]>;
    if (headers["content-length"] === "") delete headers["content-length"];
    expect(protocolReadBodyAllowed({ kind: "token", bodyText: code, headers })).toBe(false);
  });

  test.each([
    ["a jwks_uri", { jwks_uri: "https://evil.example/jwks" }],
    ["a sector_identifier_uri", { sector_identifier_uri: "https://evil.example/s" }],
    ["a logo_uri", { logo_uri: "https://evil.example/l.png" }],
    ["request_uris", { request_uris: ["https://evil.example/r"] }],
    ["a software statement", { software_statement: "eyJ" }],
    ["a non-loopback redirect", { redirect_uris: ["https://evil.example/cb"] }],
    ["an https loopback redirect", { redirect_uris: ["https://localhost/cb"] }],
    ["a redirect with userinfo", { redirect_uris: ["http://user@localhost/cb"] }],
    ["an implicit response type", { response_types: ["token"] }],
    ["a client-credentials grant", { grant_types: ["client_credentials"] }],
    ["an unknown auth method", { token_endpoint_auth_method: "private_key_jwt" }],
  ])("refuses a registration with %s", (_label, extra) => {
    const body = JSON.stringify({ ...JSON.parse(registration) as object, ...extra });
    expect(protocolReadBodyAllowed({ kind: "registration", bodyText: body, headers: jsonHeaders(body) })).toBe(false);
  });

  test("refuses a registration with a duplicate JSON key", () => {
    const body = `{"redirect_uris":["http://localhost/cb"],"redirect_uris":["https://evil.example/cb"]}`;
    expect(protocolReadBodyAllowed({ kind: "registration", bodyText: body, headers: jsonHeaders(body) })).toBe(false);
  });

  test("refuses a registration sent as a form", () => {
    expect(protocolReadBodyAllowed({ kind: "registration", bodyText: registration, headers: formHeaders(registration) })).toBe(false);
  });
});

describe("ProtocolReadRateLimiter", () => {
  test("allows a budget per provider per window, then falls back", () => {
    let now = 0;
    const limiter = new ProtocolReadRateLimiter({ maxPerWindow: 2, windowMs: 1000, now: () => now });
    expect([limiter.take("a"), limiter.take("a"), limiter.take("a"), limiter.take("b")]).toEqual([true, true, false, true]);
    now = 1001;
    expect(limiter.take("a")).toBe(true);
  });
});

describe("OAuthMediator.protocolReadEndpoint", () => {
  let tmp: string;
  let stateDir: string;
  beforeEach(() => {
    tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-protocol-read-")));
    stateDir = path.join(tmp, "state");
  });
  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function linear(extra: Record<string, unknown> = {}) {
    return {
      kind: "mcp",
      resourceHost: "mcp.example.test",
      resourcePathPrefix: "/mcp",
      stateEpoch: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      tokenEndpoints: [{ host: "auth.example.test", path: "/oauth/token" }, { host: "auth.example.test", path: "/declared/token" }],
      registrationEndpoints: [{ host: "auth.example.test", path: "/oauth/register" }],
      protocolReadEndpoints: [{ host: "auth.example.test", path: "/oauth/token" }, { host: "auth.example.test", path: "/oauth/register" }],
      ...extra,
    };
  }

  function mediator(providers: Record<string, unknown> = { "mcp:claude-linear": linear() }): OAuthMediator {
    return new OAuthMediator({
      log: () => {},
      pairedPolicy: validateOAuthMediationPolicy({ providers }),
      projectId: "project-under-test",
      stateDir,
    });
  }

  test("matches a POST to an exact recorded token or registration endpoint", () => {
    const target = mediator();
    expect(target.protocolReadEndpoint({ method: "POST", url: TOKEN_URL })).toEqual({ provider: "mcp:claude-linear", kind: "token" });
    expect(target.protocolReadEndpoint({ method: "POST", url: REGISTER_URL })).toEqual({ provider: "mcp:claude-linear", kind: "registration" });
  });

  test.each([
    ["a GET", { method: "GET", url: TOKEN_URL }],
    ["a lowercase post", { method: "post", url: TOKEN_URL }],
    ["a sub-path", { method: "POST", url: `${TOKEN_URL}/` }],
    ["a deeper sub-path", { method: "POST", url: `${REGISTER_URL}/client-1` }],
    ["a query", { method: "POST", url: `${TOKEN_URL}?x=1` }],
    ["a dot-segment path that normalizes to the endpoint", { method: "POST", url: "https://auth.example.test/other/../oauth/token" }],
    ["a static endpoint that no enable record lists", { method: "POST", url: "https://auth.example.test/declared/token" }],
    ["another host", { method: "POST", url: "https://other.example.test/oauth/token" }],
  ])("does not match %s", (_label, req) => {
    expect(mediator().protocolReadEndpoint(req)).toBeUndefined();
  });

  test("does not match an endpoint another provider also mediates statically (a service provider too)", () => {
    const target = mediator({
      "mcp:claude-linear": linear(),
      "service:shared": { kind: "service", resourceHost: "api.example.test", tokenEndpoints: [{ host: "auth.example.test", path: "/oauth/token" }] },
    });
    expect(target.protocolReadEndpoint({ method: "POST", url: TOKEN_URL })).toBeUndefined();
    expect(target.protocolReadEndpoint({ method: "POST", url: REGISTER_URL })).toEqual({ provider: "mcp:claude-linear", kind: "registration" });
  });

  test("does not match an endpoint another server discovered at run time", async () => {
    const target = mediator({
      "mcp:claude-linear": linear(),
      "mcp:claude-other": { kind: "mcp", resourceHost: "other.example.test" },
    });
    // The other server's resource names the shared issuer, which advertises
    // the same token endpoint.
    await target.beforeResponse({
      body: { getText: async () => JSON.stringify({ authorization_servers: ["https://auth.example.test"] }) },
      statusCode: 200,
    }, { method: "GET", url: "https://other.example.test/.well-known/oauth-protected-resource" });
    await target.beforeResponse({
      body: { getText: async () => JSON.stringify({ issuer: "https://auth.example.test", token_endpoint: TOKEN_URL }) },
      statusCode: 200,
    }, { method: "GET", url: "https://auth.example.test/.well-known/oauth-authorization-server" });
    expect(target.protocolReadEndpoint({ method: "POST", url: TOKEN_URL })).toBeUndefined();
  });

  test("does not match an endpoint only discovered at run time for the same server", async () => {
    const target = mediator({ "mcp:claude-linear": linear({ protocolReadEndpoints: [] }) });
    await target.beforeResponse({
      body: { getText: async () => JSON.stringify({ token_endpoint: "https://mcp.example.test/token" }) },
      statusCode: 200,
    }, { method: "GET", url: "https://mcp.example.test/.well-known/oauth-authorization-server" });
    expect(target.requestNeedsResponseMediation({ url: "https://mcp.example.test/token" })).toBe(true);
    expect(target.protocolReadEndpoint({ method: "POST", url: "https://mcp.example.test/token" })).toBeUndefined();
  });

  test("stops matching as soon as a new policy no longer mediates the endpoint", () => {
    const target = mediator();
    target.activatePairedPolicy(validateOAuthMediationPolicy({ providers: {} }));
    expect(target.protocolReadEndpoint({ method: "POST", url: TOKEN_URL })).toBeUndefined();
  });

  test("does not match while the OAuth policy is unavailable", () => {
    const policyPath = path.join(tmp, "oauth-policy.json");
    fs.writeFileSync(policyPath, "{ malformed");
    const target = new OAuthMediator({ log: () => {}, policyPath, projectId: "p", stateDir });
    expect(target.protocolReadEndpoint({ method: "POST", url: TOKEN_URL })).toBeUndefined();
  });

  test("a token request that selected the unmediated rule is refused if the endpoint became mediated", async () => {
    const target = mediator();
    const result = await target.beforeRequest({
      body: { getText: async () => "grant_type=refresh_token&refresh_token=x" },
      headers: { "content-type": FORM },
      method: "POST",
      url: TOKEN_URL,
    }, { responseMediated: false });
    expect(result?.response?.statusCode).toBe(403);
    expect(result?.response?.body).toContain("retry");
  });

  test("a protocol read whose endpoint stopped being mediated before forwarding is refused", async () => {
    const target = mediator();
    const match = target.protocolReadEndpoint({ method: "POST", url: TOKEN_URL });
    target.activatePairedPolicy(validateOAuthMediationPolicy({ providers: { "mcp:claude-linear": linear({ protocolReadEndpoints: [] }) } }));
    const result = await target.beforeRequest({ method: "POST", url: TOKEN_URL }, { responseMediated: true, protocolRead: match });
    expect(result?.response?.statusCode).toBe(403);
  });
});
