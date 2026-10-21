// Mediator-level proofs for the cross-host token endpoint design: the
// request-side refusal of unmediated OAuth grants (P1-a, P1-c), blocked and
// colliding endpoints (X3, X4, R2), user binding hosts (P1-b), capture
// refusals (R1, R9, R2), share-group capture owners (R16), exact registration
// matching (Q8), and no protocol reads on credential hosts (X5). Every
// refusal asserts the OAuth state file is untouched, and every new refusal
// has its reclaim path.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { validateOAuthMediationPolicy } from "@runfree/runtime-contracts/oauth-mediation-policy";
import { OAuthMediator, type OAuthProxyRequest, type UnmediatedOAuthRequestRefusal } from "./oauth-mediation.ts";

const RESOURCE = "api.ahrefs.com";
const TOKEN_HOST = "ahrefs.com";
const TOKEN_URL = `https://${TOKEN_HOST}/oauth/token`;
const EPOCH = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

let tmp: string;
let stateDir: string;
let stateFile: string;
let logs: string[];

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-oauth-cross-host-")));
  stateDir = path.join(tmp, "state");
  stateFile = path.join(stateDir, "handles.json");
  logs = [];
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

type PolicyInput = Record<string, unknown> & { providers: Record<string, unknown> };

function ahrefs(extra: Record<string, unknown> = {}) {
  return { kind: "mcp", resourceHost: RESOURCE, resourcePathPrefix: "/mcp", stateEpoch: EPOCH, ...extra };
}

function mediator(policy: PolicyInput, extra: Partial<ConstructorParameters<typeof OAuthMediator>[0]> = {}): OAuthMediator {
  return new OAuthMediator({
    log: (line) => logs.push(line),
    pairedPolicy: validateOAuthMediationPolicy(policy),
    projectId: "project-under-test",
    stateDir,
    ...extra,
  });
}

function activate(target: OAuthMediator, policy: PolicyInput): void {
  target.activatePairedPolicy(validateOAuthMediationPolicy(policy));
}

let requestCounter = 0;
function request(method: string, url: string, body?: string, headers: Record<string, string> = {}): OAuthProxyRequest {
  const buffer = body === undefined ? undefined : Buffer.from(body, "utf8");
  requestCounter += 1;
  return {
    id: `req-${requestCounter}`,
    method,
    url,
    headers: { ...headers, ...(buffer !== undefined ? { "content-length": String(buffer.length) } : {}) },
    ...(buffer !== undefined ? { body: { buffer, getText: async () => body } } : {}),
  };
}

const FORM = { "content-type": "application/x-www-form-urlencoded" };
const JSON_TYPE = { "content-type": "application/json" };
const GRANT = "grant_type=authorization_code&code=c&code_verifier=v";

function stateSnapshot(): string | null {
  return fs.existsSync(stateFile) ? fs.readFileSync(stateFile, "utf8") : null;
}

function jsonResponse(value: unknown, statusCode = 200) {
  const text = JSON.stringify(value);
  return { body: { buffer: Buffer.from(text), getText: async () => text }, statusCode };
}

async function capture(target: OAuthMediator, url: string, value: unknown): Promise<void> {
  await target.beforeResponse(jsonResponse(value), { method: "GET", url });
}

describe("P1-a: unmediated grant requests to record-only hosts", () => {
  test.each([
    ["a form POST", request("POST", TOKEN_URL, GRANT, FORM)],
    ["a JSON POST", request("POST", TOKEN_URL, JSON.stringify({ grant_type: "authorization_code" }), JSON_TYPE)],
    ["a JSON array", request("POST", TOKEN_URL, JSON.stringify([{ refresh_token: "r" }]), JSON_TYPE)],
    ["a text/plain grant", request("POST", TOKEN_URL, GRANT, { "content-type": "text/plain" })],
    ["a query GET", request("GET", `${TOKEN_URL}?grant_type=authorization_code`)],
    ["a PUT", request("PUT", TOKEN_URL, GRANT, FORM)],
    ["a method-override header", request("POST", TOKEN_URL, GRANT, { ...FORM, "x-http-method-override": "GET" })],
    ["a registration", request("POST", `https://${TOKEN_HOST}/oauth/register`, JSON.stringify({ redirect_uris: ["http://127.0.0.1/cb"] }), JSON_TYPE)],
  ])("refuses %s and writes no state", async (_label, req) => {
    const target = mediator({ recordOnlyHosts: [TOKEN_HOST], providers: { "mcp:claude-ahrefs": ahrefs({ bindingHosts: [TOKEN_HOST] }) } });
    const refusal = await target.unmediatedRequestRefusal(req, { allowlisted: true });
    expect(refusal).toMatchObject({
      finding: { kind: "grant-shaped" },
      host: TOKEN_HOST,
      providers: ["mcp:claude-ahrefs"],
      target: "record-only-host",
    });
    expect(stateSnapshot()).toBeNull();
  });

  test.each([
    ["multipart", request("POST", TOKEN_URL, "--b--", { "content-type": "multipart/form-data; boundary=b" }), "multipart"],
    ["an oversize body", request("POST", TOKEN_URL, `a=${"x".repeat(17 * 1024)}`, FORM), "oversize"],
  ])("fails closed on %s", async (_label, req, kind) => {
    const target = mediator({ recordOnlyHosts: [TOKEN_HOST], providers: {} });
    expect((await target.unmediatedRequestRefusal(req, { allowlisted: true }))?.finding.kind).toBe(kind);
  });

  test("passes a request that is not grant-shaped, and any request to an unguarded host", async () => {
    const target = mediator({ recordOnlyHosts: [TOKEN_HOST], providers: {} });
    expect(await target.unmediatedRequestRefusal(request("GET", `https://${TOKEN_HOST}/.well-known/oauth-authorization-server`), { allowlisted: true })).toBeUndefined();
    expect(await target.unmediatedRequestRefusal(request("POST", `https://${TOKEN_HOST}/api`, JSON.stringify({ q: 1 }), JSON_TYPE), { allowlisted: true })).toBeUndefined();
    expect(await target.unmediatedRequestRefusal(request("POST", "https://other.example.com/oauth/token", GRANT, FORM), { allowlisted: true })).toBeUndefined();
  });

  test("a static endpoint on a record-only host is mediated, not blocked; its siblings are", async () => {
    const target = mediator({
      recordOnlyHosts: [TOKEN_HOST],
      providers: { "mcp:claude-ahrefs": ahrefs({ tokenEndpoints: [{ host: TOKEN_HOST, path: "/oauth/token" }] }) },
    });
    expect(await target.unmediatedRequestRefusal(request("POST", TOKEN_URL, GRANT, FORM), { allowlisted: true })).toBeUndefined();
    expect(await target.unmediatedRequestRefusal(request("POST", `${TOKEN_URL}/other`, GRANT, FORM), { allowlisted: true }))
      .toMatchObject({ target: "record-only-host" });
  });

  test("an endpoint host a record names refuses only a top-level grant; JSON-RPC passes", async () => {
    const target = mediator({ recordEndpointHosts: [RESOURCE], providers: { "mcp:claude-ahrefs": ahrefs() } });
    const rpc = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { arguments: { grant_type: "x", code: "c", code_verifier: "v" } } });
    expect(await target.unmediatedRequestRefusal(request("POST", `https://${RESOURCE}/mcp`, rpc, JSON_TYPE), { allowlisted: true })).toBeUndefined();
    // No fail-closed rule: a large or unreadable body passes.
    expect(await target.unmediatedRequestRefusal(request("POST", `https://${RESOURCE}/upload`, "--b--", { "content-type": "multipart/form-data; boundary=b" }), { allowlisted: true })).toBeUndefined();
    expect(await target.unmediatedRequestRefusal(request("POST", `https://${RESOURCE}/oauth/token`, GRANT, FORM), { allowlisted: true }))
      .toMatchObject({ target: "record-endpoint-host", finding: { kind: "grant-shaped", field: "grant_type" } });
  });

  test("reclaim: a user binding host binds the endpoint the server's metadata names, and the grant is then mediated", async () => {
    const policy = { recordOnlyHosts: [TOKEN_HOST], providers: { "mcp:claude-ahrefs": ahrefs({ bindingHosts: [TOKEN_HOST] }) } };
    const target = mediator(policy);
    const grant = () => request("POST", TOKEN_URL, GRANT, FORM);
    expect(await target.unmediatedRequestRefusal(grant(), { allowlisted: true })).toMatchObject({ target: "record-only-host" });

    // P1-b: the issuer's metadata on the resource host names a token
    // endpoint on the user host, which the binding set now includes.
    await capture(target, `https://${RESOURCE}/.well-known/oauth-authorization-server`, { issuer: `https://${RESOURCE}`, token_endpoint: TOKEN_URL });
    expect(logs.join("\n")).toContain("discovery ok name=mcp:claude-ahrefs token_host=ahrefs.com");
    expect(await target.unmediatedRequestRefusal(grant(), { allowlisted: true })).toBeUndefined();
    expect(target.requestNeedsResponseMediation({ url: TOKEN_URL })).toBe(true);

    const minted = await target.beforeResponse(jsonResponse({ access_token: "real-access", token_type: "Bearer" }), grant());
    expect(JSON.parse(minted?.body ?? "{}").access_token).toMatch(/^runfree_oauth_access_/);
  });

  test("without a binding host the same capture is refused as unbound, and the grant stays refused", async () => {
    const target = mediator({ recordOnlyHosts: [TOKEN_HOST], providers: { "mcp:claude-ahrefs": ahrefs() } });
    await capture(target, `https://${RESOURCE}/.well-known/oauth-authorization-server`, { issuer: `https://${RESOURCE}`, token_endpoint: TOKEN_URL });
    expect(logs.join("\n")).toContain("token_endpoint_host=ahrefs.com reason=unbound-host");
    expect(stateSnapshot()).toBeNull();
    expect(await target.unmediatedRequestRefusal(request("POST", TOKEN_URL, GRANT, FORM), { allowlisted: true })).toMatchObject({ target: "record-only-host" });
  });

  test("reclaim: a policy that stops listing the host clears the refusal", async () => {
    const target = mediator({ recordOnlyHosts: [TOKEN_HOST], providers: {} });
    expect(await target.unmediatedRequestRefusal(request("POST", TOKEN_URL, GRANT, FORM), { allowlisted: true })).toBeDefined();
    activate(target, { providers: {} });
    expect(await target.unmediatedRequestRefusal(request("POST", TOKEN_URL, GRANT, FORM), { allowlisted: true })).toBeUndefined();
  });
});

describe("P1-a while the OAuth policy is invalid", () => {
  function malformedMediator(): OAuthMediator {
    const policyPath = path.join(tmp, "oauth-policy.json");
    fs.writeFileSync(policyPath, "{ malformed\n");
    return new OAuthMediator({ log: (line) => logs.push(line), policyPath, projectId: "p", stateDir });
  }

  test("refuses a readable grant to any allowlisted host, and nothing else", async () => {
    const target = malformedMediator();
    expect(await target.unmediatedRequestRefusal(request("POST", "https://anything.example.com/token", GRANT, FORM), { allowlisted: true }))
      .toMatchObject({ target: "policy-unavailable", finding: { kind: "grant-shaped" } });
    // Audited hosts are outside the allowlist and outside this rule.
    expect(await target.unmediatedRequestRefusal(request("POST", "https://anything.example.com/token", GRANT, FORM), { allowlisted: false })).toBeUndefined();
    expect(await target.unmediatedRequestRefusal(request("POST", "https://anything.example.com/upload", JSON.stringify({ q: 1 }), JSON_TYPE), { allowlisted: true })).toBeUndefined();
    expect(await target.unmediatedRequestRefusal(request("POST", "https://anything.example.com/upload", "--b--", { "content-type": "multipart/form-data; boundary=b" }), { allowlisted: true })).toBeUndefined();
  });

  test("beforeRequest refuses the same grant at the last check, after a valid policy was loaded", async () => {
    const policyPath = path.join(tmp, "oauth-policy.json");
    fs.writeFileSync(policyPath, JSON.stringify({ providers: { "mcp:claude-ahrefs": ahrefs() } }));
    const target = new OAuthMediator({ log: (line) => logs.push(line), policyPath, projectId: "p", stateDir });
    expect(target.requestNeedsResponseMediation({ url: "https://anything.example.com/token" })).toBe(false);
    fs.writeFileSync(policyPath, "{ malformed\n");
    const future = new Date(Date.now() + 2_000);
    fs.utimesSync(policyPath, future, future);
    const result = await target.beforeRequest(request("POST", "https://anything.example.com/token", GRANT, FORM));
    expect(result?.response?.body).toContain("grant-shaped");
    expect(await target.beforeRequest(request("POST", "https://anything.example.com/token", GRANT, FORM), { allowlisted: false })).toBeUndefined();
    expect(await target.beforeRequest(request("POST", "https://anything.example.com/upload", "{}", JSON_TYPE))).toBeUndefined();
  });
});

describe("P1-c: the last check in beforeRequest", () => {
  test("a host that became record-only after rule selection refuses a grant, through the server's renderer", async () => {
    const seen: UnmediatedOAuthRequestRefusal[] = [];
    const target = mediator({ providers: {} }, {
      unmediatedRequestResponse: (_req, refusal) => {
        seen.push(refusal);
        return { response: { statusCode: 403, headers: { "x-runfree-blocked": "oauth-endpoint-not-mediated" }, body: "denied\n" } };
      },
    });
    const req = request("POST", TOKEN_URL, GRANT, FORM);
    // Selected the plain rule under the old policy; the host then became
    // record-only.
    expect(target.requestNeedsResponseMediation(req)).toBe(false);
    activate(target, { recordOnlyHosts: [TOKEN_HOST], providers: {} });
    const result = await target.beforeRequest(req, { responseMediated: false });
    expect(result?.response?.headers["x-runfree-blocked"]).toBe("oauth-endpoint-not-mediated");
    expect(seen).toEqual([expect.objectContaining({ host: TOKEN_HOST, target: "record-only-host" })]);
    expect(stateSnapshot()).toBeNull();
    // A request that is not grant-shaped is not refused.
    expect(await target.beforeRequest(request("POST", `https://${TOKEN_HOST}/api`, "{}", JSON_TYPE), { responseMediated: false })).toBeUndefined();
  });

  test("an endpoint that became blocked after rule selection is refused for a retry on the plain rule", async () => {
    const target = mediator({ providers: {} });
    activate(target, { blockedEndpoints: [{ host: TOKEN_HOST, path: "/oauth/token" }], providers: {} });
    const result = await target.beforeRequest(request("GET", TOKEN_URL), { responseMediated: false });
    expect(result?.response?.body).toContain("became blocked");
  });
});

describe("X3: blocked endpoints", () => {
  const blocked = { blockedEndpoints: [{ host: TOKEN_HOST, path: "/oauth/token" }], providers: { "mcp:claude-ahrefs": ahrefs() } };

  test("a grant to a blocked endpoint is refused before upstream, fail-closed; its reply is read", async () => {
    const target = mediator(blocked);
    expect(target.requestNeedsResponseMediation({ url: TOKEN_URL })).toBe(true);
    expect(target.requestNeedsResponseMediation({ url: `${TOKEN_URL}/x` })).toBe(false);
    expect(await target.unmediatedRequestRefusal(request("POST", TOKEN_URL, GRANT, FORM), { allowlisted: true }))
      .toMatchObject({ target: "blocked-endpoint", finding: { kind: "grant-shaped" } });
    const chunked: OAuthProxyRequest = {
      method: "POST",
      url: TOKEN_URL,
      headers: { "transfer-encoding": "chunked" },
      body: { buffer: Buffer.from("x"), getText: async () => "x" },
    };
    expect(await target.unmediatedRequestRefusal(chunked, { allowlisted: true }))
      .toMatchObject({ target: "blocked-endpoint", finding: { kind: "missing-length" } });
    // A non-grant request passes upstream, and a token reply is blocked.
    const plain = request("GET", TOKEN_URL);
    expect(await target.unmediatedRequestRefusal(plain, { allowlisted: true })).toBeUndefined();
    const reply = await target.beforeResponse(jsonResponse({ result: { access_token: "real" } }), plain);
    expect(reply?.body).toContain("blocked by OAuth proxy policy");
    expect(reply?.body).not.toContain("real");
    expect(stateSnapshot()).toBeNull();
  });

  test("a sensitive reply is blocked at a non-success status, in an array, and when it does not decode", async () => {
    const target = mediator(blocked);
    const plain = request("GET", TOKEN_URL);
    expect((await target.beforeResponse(jsonResponse({ access_token: "real" }, 400), plain))?.body).toContain("blocked");
    expect((await target.beforeResponse(jsonResponse([{ refresh_token: "real" }]), plain))?.body).toContain("blocked");
    const undecodable = { body: { buffer: Buffer.from([1, 2, 3]), getText: async () => undefined }, statusCode: 200 };
    expect((await target.beforeResponse(undecodable, plain))?.body).toContain("undecodable");
    expect(await target.beforeResponse(jsonResponse({ error: "invalid_grant" }, 400), plain)).toBeUndefined();
  });

  test("reclaim: a static endpoint for the same path is mediated before the block", async () => {
    const target = mediator({
      ...blocked,
      providers: { "mcp:claude-ahrefs": ahrefs({ tokenEndpoints: [{ host: TOKEN_HOST, path: "/oauth/token" }] }) },
    });
    const grant = request("POST", TOKEN_URL, GRANT, FORM);
    expect(await target.unmediatedRequestRefusal(grant, { allowlisted: true })).toBeUndefined();
    await target.beforeRequest(grant, { responseMediated: true });
    const minted = await target.beforeResponse(jsonResponse({ access_token: "real-access" }), grant);
    expect(JSON.parse(minted?.body ?? "{}").access_token).toMatch(/^runfree_oauth_access_/);
  });

  test("reclaim: a policy without the blocked endpoint (revoke, or the conflict removed) clears it", async () => {
    const target = mediator(blocked);
    activate(target, { providers: { "mcp:claude-ahrefs": ahrefs() } });
    expect(target.requestNeedsResponseMediation({ url: TOKEN_URL })).toBe(false);
    expect(await target.unmediatedRequestRefusal(request("POST", TOKEN_URL, GRANT, FORM), { allowlisted: true })).toBeUndefined();
  });

  test("blocked endpoints apply with no provider at all", async () => {
    const target = mediator({ ...blocked, providers: {} });
    expect(target.requestNeedsResponseMediation({ url: TOKEN_URL })).toBe(true);
  });
});

describe("R1, R9, R2: capture refusals write no state", () => {
  test("a refused host is never bound as an issuer", async () => {
    const target = mediator({ refusedHosts: ["github.com"], providers: { "mcp:claude-ahrefs": ahrefs() } });
    await capture(target, `https://${RESOURCE}/.well-known/oauth-protected-resource/mcp`, { authorization_servers: ["https://github.com/login/oauth"] });
    expect(logs.join("\n")).toContain("issuer_host=github.com reason=refused-host");
    expect(stateSnapshot()).toBeNull();
    expect(target.requestNeedsResponseMediation({ url: "https://github.com/.well-known/oauth-authorization-server" })).toBe(false);
  });

  test("a refused host is never bound as an endpoint, even when it is a user binding host (R9)", async () => {
    const target = mediator({
      refusedHosts: ["github.com"],
      providers: { "mcp:claude-ahrefs": ahrefs({ bindingHosts: ["github.com"] }) },
    });
    await capture(target, `https://${RESOURCE}/.well-known/oauth-authorization-server`, {
      issuer: `https://${RESOURCE}`,
      token_endpoint: "https://github.com/login/oauth/access_token",
      registration_endpoint: "https://github.com/register",
    });
    expect(logs.join("\n")).toContain("token_endpoint_host=github.com reason=refused-host");
    expect(logs.join("\n")).toContain("registration_endpoint_host=github.com reason=refused-host");
    expect(stateSnapshot()).toBeNull();
  });

  test("the server's own resource host is exempt from refusedHosts", async () => {
    const target = mediator({ refusedHosts: [RESOURCE], providers: { "mcp:claude-ahrefs": ahrefs() } });
    await capture(target, `https://${RESOURCE}/.well-known/oauth-authorization-server`, { issuer: `https://${RESOURCE}`, token_endpoint: `https://${RESOURCE}/token` });
    expect(target.requestNeedsResponseMediation({ url: `https://${RESOURCE}/token` })).toBe(true);
  });

  test("another provider's host is refused as an issuer host", async () => {
    const target = mediator({
      providers: {
        "mcp:claude-ahrefs": ahrefs(),
        "service:google": { kind: "service", resourceHost: "googleads.googleapis.com", tokenEndpoints: ["https://oauth2.googleapis.com/token"] },
      },
    });
    await capture(target, `https://${RESOURCE}/.well-known/oauth-protected-resource/mcp`, { authorization_servers: ["https://oauth2.googleapis.com"] });
    expect(logs.join("\n")).toContain("issuer_host=oauth2.googleapis.com reason=other-provider-host providers=service:google");
    expect(stateSnapshot()).toBeNull();
  });

  test("an issuer host that later becomes another provider's host binds no new endpoint there", async () => {
    const own = { "mcp:claude-ahrefs": ahrefs() };
    const target = mediator({ providers: own });
    await capture(target, `https://${RESOURCE}/.well-known/oauth-protected-resource/mcp`, { authorization_servers: ["https://auth.shared.example.com"] });
    const before = stateSnapshot();
    expect(before).toContain("auth.shared.example.com");
    activate(target, { providers: { ...own, "mcp:claude-other": ahrefs({ resourceHost: "auth.shared.example.com" }) } });
    await capture(target, "https://auth.shared.example.com/.well-known/oauth-authorization-server", {
      issuer: "https://auth.shared.example.com",
      token_endpoint: "https://auth.shared.example.com/token",
    });
    expect(logs.join("\n")).toContain("token_endpoint_host=auth.shared.example.com reason=other-provider-host providers=mcp:claude-other");
    expect(stateSnapshot()).toBe(before);
  });
});

describe("R2/X4: a discovered endpoint that collides with another provider's blocks both", () => {
  const SHARED = "auth.example.com";
  const policy = {
    providers: {
      "mcp:claude-first": ahrefs({ resourceHost: "first.example.com", tokenEndpoints: [{ host: SHARED, path: "/token" }] }),
      "mcp:claude-second": ahrefs({ resourceHost: "second.example.com", bindingHosts: [SHARED] }),
    },
  };

  test("both providers lose mediation, the grant is refused, the reply is blocked, and revoke reclaims it", async () => {
    const target = mediator(policy);
    const url = `https://${SHARED}/token`;
    expect(await target.unmediatedRequestRefusal(request("POST", url, GRANT, FORM), { allowlisted: true })).toBeUndefined();

    await capture(target, "https://second.example.com/.well-known/oauth-authorization-server", { issuer: "https://second.example.com", token_endpoint: url });
    expect(logs.join("\n")).toContain("endpoint-collision name=mcp:claude-second token_endpoint_host=auth.example.com providers=mcp:claude-first");
    const before = stateSnapshot();

    expect(target.requestNeedsResponseMediation({ url })).toBe(true);
    expect(await target.unmediatedRequestRefusal(request("POST", url, GRANT, FORM), { allowlisted: true })).toMatchObject({
      target: "endpoint-collision",
      providers: ["mcp:claude-first", "mcp:claude-second"],
    });
    const plain = request("GET", url);
    const reply = await target.beforeResponse(jsonResponse({ access_token: "real" }), plain);
    expect(reply?.body).toContain("blocked");
    expect(stateSnapshot()).toBe(before);

    // Reclaim: revoking the second server leaves the first sole claimant.
    activate(target, { providers: { "mcp:claude-first": policy.providers["mcp:claude-first"] } });
    const grant = request("POST", url, GRANT, FORM);
    expect(await target.unmediatedRequestRefusal(grant, { allowlisted: true })).toBeUndefined();
    await target.beforeRequest(grant, { responseMediated: true });
    const minted = await target.beforeResponse(jsonResponse({ access_token: "real-access" }), grant);
    expect(JSON.parse(minted?.body ?? "{}").access_token).toMatch(/^runfree_oauth_access_/);
  });
});

describe("R16: only the share-group owner captures metadata", () => {
  test("a non-owner listed first is skipped; the owner records the discovery", async () => {
    const target = mediator({
      providers: {
        "mcp:claude-ahrefs": ahrefs({ captureOwner: false }),
        "mcp:codex-ahrefs": ahrefs(),
      },
    });
    await capture(target, `https://${RESOURCE}/.well-known/oauth-authorization-server`, { issuer: `https://${RESOURCE}`, token_endpoint: `https://${RESOURCE}/token` });
    const state = JSON.parse(stateSnapshot() ?? "{}") as { discovered?: Record<string, unknown> };
    expect(Object.keys(state.discovered ?? {})).toEqual(["mcp:codex-ahrefs"]);
  });

  test("a group whose only member is a non-owner captures nothing", async () => {
    const target = mediator({ providers: { "mcp:claude-ahrefs": ahrefs({ captureOwner: false }) } });
    expect(target.requestNeedsResponseMediation({ url: `https://${RESOURCE}/.well-known/oauth-authorization-server` })).toBe(false);
    await capture(target, `https://${RESOURCE}/.well-known/oauth-authorization-server`, { issuer: `https://${RESOURCE}`, token_endpoint: `https://${RESOURCE}/token` });
    expect(stateSnapshot()).toBeNull();
  });
});

describe("Q8: exact registration endpoints", () => {
  test("an exact registration endpoint matches only its path; a prefix one matches below it", () => {
    const target = mediator({
      providers: {
        "mcp:claude-vercel": ahrefs({
          resourceHost: "mcp.vercel.com",
          registrationEndpoints: [
            { host: "api.vercel.com", path: "/login/oauth/register", exact: true },
            { host: "mcp.vercel.com", path: "/register" },
          ],
        }),
      },
    });
    expect(target.requestNeedsResponseMediation({ url: "https://api.vercel.com/login/oauth/register" })).toBe(true);
    expect(target.requestNeedsResponseMediation({ url: "https://api.vercel.com/login/oauth/register/client-1" })).toBe(false);
    expect(target.requestNeedsResponseMediation({ url: "https://mcp.vercel.com/register/client-1" })).toBe(true);
  });
});

describe("X5: no protocol reads on credential destination hosts", () => {
  const policy = {
    providers: {
      "mcp:claude-ahrefs": ahrefs({
        tokenEndpoints: [{ host: TOKEN_HOST, path: "/oauth/token" }],
        protocolReadEndpoints: [{ host: TOKEN_HOST, path: "/oauth/token" }],
      }),
    },
  };

  test("a credential host is never a protocol read; the same endpoint elsewhere is", () => {
    let hosts = new Set<string>([TOKEN_HOST]);
    const target = mediator(policy, { credentialHosts: () => hosts });
    expect(target.protocolReadEndpoint({ method: "POST", url: TOKEN_URL })).toBeUndefined();
    hosts = new Set(["other.example.com"]);
    expect(target.protocolReadEndpoint({ method: "POST", url: TOKEN_URL })).toEqual({ kind: "token", provider: "mcp:claude-ahrefs", resourceHost: RESOURCE });
  });

  test("beforeRequest re-checks the protocol read against the current credential hosts", async () => {
    let hosts = new Set<string>();
    const target = mediator(policy, { credentialHosts: () => hosts });
    const match = target.protocolReadEndpoint({ method: "POST", url: TOKEN_URL });
    expect(match).toBeDefined();
    hosts = new Set([TOKEN_HOST]);
    const result = await target.beforeRequest(request("POST", TOKEN_URL, GRANT, FORM), { responseMediated: true, ...(match ? { protocolRead: match } : {}) });
    expect(result?.response?.body).toContain("no longer mediated");
  });
});

describe("unmediated token replies on the response-mediating rule", () => {
  test("a nested token from an endpoint that is no longer mediated is blocked", async () => {
    const target = mediator({ providers: { "mcp:claude-ahrefs": ahrefs({ tokenEndpoints: [{ host: TOKEN_HOST, path: "/oauth/token" }] }) } });
    activate(target, { providers: {} });
    const reply = await target.beforeResponse(jsonResponse({ data: [{ access_token: "real" }] }), request("POST", TOKEN_URL));
    expect(reply?.body).toContain("no longer mediated");
  });

  test("a mediated endpoint's non-success reply with a token is blocked, and an ordinary error passes", async () => {
    const target = mediator({ providers: { "mcp:claude-ahrefs": ahrefs({ tokenEndpoints: [{ host: TOKEN_HOST, path: "/oauth/token" }] }) } });
    expect((await target.beforeResponse(jsonResponse({ access_token: "real" }, 401), request("POST", TOKEN_URL)))?.body).toContain("blocked");
    expect(await target.beforeResponse(jsonResponse({ error: "invalid_client" }, 401), request("POST", TOKEN_URL))).toBeUndefined();
    expect(stateSnapshot()).toBeNull();
  });
});

describe("path variants of blocked and colliding endpoints", () => {
  const variants = ["/oauth/token/", "/OAuth/token", "/oauth/%74oken", "/oauth//token", "/other"];

  test.each(variants)("a grant to %s on a host with a blocked endpoint is refused by the host-wide scan", async (variant) => {
    const target = mediator({ blockedEndpoints: [{ host: TOKEN_HOST, path: "/oauth/token" }], providers: {} });
    expect(await target.unmediatedRequestRefusal(request("POST", `https://${TOKEN_HOST}${variant}`, GRANT, FORM), { allowlisted: true }))
      .toMatchObject({ target: "blocked-endpoint", finding: { kind: "grant-shaped" } });
    // A nested grant field counts too (deep scan).
    expect(await target.unmediatedRequestRefusal(request("POST", `https://${TOKEN_HOST}${variant}`, JSON.stringify({ a: { refresh_token: "r" } }), JSON_TYPE), { allowlisted: true }))
      .toMatchObject({ target: "blocked-endpoint" });
  });

  test("the host-wide scan has no fail-closed rules: ordinary traffic passes whatever its size or encoding", async () => {
    const target = mediator({ blockedEndpoints: [{ host: TOKEN_HOST, path: "/oauth/token" }], providers: {} });
    for (const req of [
      request("POST", `https://${TOKEN_HOST}/upload`, "x".repeat(64 * 1024), { "content-type": "text/plain" }),
      request("POST", `https://${TOKEN_HOST}/upload`, "--b--", { "content-type": "multipart/form-data; boundary=b" }),
      request("POST", `https://${TOKEN_HOST}/upload`, "abc", { "content-encoding": "x-custom" }),
    ]) {
      expect(await target.unmediatedRequestRefusal(req, { allowlisted: true })).toBeUndefined();
    }
    // The exact blocked endpoint keeps its fail-closed rules.
    expect(await target.unmediatedRequestRefusal(request("POST", TOKEN_URL, "--b--", { "content-type": "multipart/form-data; boundary=b" }), { allowlisted: true }))
      .toMatchObject({ finding: { kind: "multipart" } });
  });

  test("a JSON body quoting an OAuth URL passes elsewhere on the host, but is refused at the exact blocked endpoint", async () => {
    const target = mediator({ blockedEndpoints: [{ host: TOKEN_HOST, path: "/oauth/token" }], providers: {} });
    const quoting = JSON.stringify({ body: "see https://x.example/cb?state=1&refresh_token=abc" });
    expect(await target.unmediatedRequestRefusal(request("POST", `https://${TOKEN_HOST}/issues/1/comments`, quoting, JSON_TYPE), { allowlisted: true })).toBeUndefined();
    expect(await target.unmediatedRequestRefusal(request("POST", TOKEN_URL, quoting, JSON_TYPE), { allowlisted: true }))
      .toMatchObject({ target: "blocked-endpoint", finding: { kind: "grant-shaped", field: "refresh_token" } });
    // Not declared as JSON, the same text is still read as a form host-wide.
    expect(await target.unmediatedRequestRefusal(request("POST", `https://${TOKEN_HOST}/issues/1/comments`, quoting, { "content-type": "text/plain" }), { allowlisted: true }))
      .toMatchObject({ target: "blocked-endpoint" });
  });

  test("on a record-only host a JSON body quoting an OAuth URL is still refused", async () => {
    const target = mediator({ recordOnlyHosts: [TOKEN_HOST], providers: {} });
    const quoting = JSON.stringify({ body: "see https://x.example/cb?state=1&refresh_token=abc" });
    expect(await target.unmediatedRequestRefusal(request("POST", `https://${TOKEN_HOST}/api`, quoting, JSON_TYPE), { allowlisted: true }))
      .toMatchObject({ target: "record-only-host" });
  });

  test("a host with a colliding endpoint gets the same host-wide scan, naming both providers", async () => {
    const SHARED = "auth.example.com";
    const target = mediator({
      providers: {
        "mcp:claude-first": ahrefs({ resourceHost: "first.example.com", tokenEndpoints: [{ host: SHARED, path: "/token" }] }),
        "mcp:claude-second": ahrefs({ resourceHost: "second.example.com", tokenEndpoints: [{ host: SHARED, path: "/token" }] }),
      },
    });
    expect(await target.unmediatedRequestRefusal(request("POST", `https://${SHARED}/Token`, GRANT, FORM), { allowlisted: true }))
      .toMatchObject({ target: "endpoint-collision", providers: ["mcp:claude-first", "mcp:claude-second"] });
    expect(await target.unmediatedRequestRefusal(request("GET", `https://${SHARED}/page`), { allowlisted: true })).toBeUndefined();
  });

  test("reclaim: without the blocked endpoint the host is unguarded again", async () => {
    const target = mediator({ blockedEndpoints: [{ host: TOKEN_HOST, path: "/oauth/token" }], providers: {} });
    activate(target, { providers: {} });
    expect(await target.unmediatedRequestRefusal(request("POST", `https://${TOKEN_HOST}/oauth/token/`, GRANT, FORM), { allowlisted: true })).toBeUndefined();
  });
});

describe("WebSocket upgrades where the proxy guards OAuth", () => {
  const ws = (url: string) => ({ url, headers: { upgrade: "websocket" } });

  test("an upgrade to a record-only host is refused, whatever its query", () => {
    const target = mediator({ recordOnlyHosts: [TOKEN_HOST], providers: {} });
    expect(target.webSocketUpgradeRefusal(ws(`wss://${TOKEN_HOST}/oauth/token?grant_type=refresh_token&refresh_token=R`)))
      .toMatchObject({ target: "record-only-host", finding: { kind: "websocket" } });
    expect(target.webSocketUpgradeRefusal(ws(`wss://${TOKEN_HOST}/socket`))).toMatchObject({ target: "record-only-host" });
  });

  test("an upgrade to any claimed URL is refused: mediated, blocked, or colliding", () => {
    const target = mediator({
      blockedEndpoints: [{ host: "blocked.example.com", path: "/token" }],
      providers: {
        "mcp:claude-ahrefs": ahrefs({ tokenEndpoints: [{ host: TOKEN_HOST, path: "/oauth/token" }] }),
        "mcp:claude-a": ahrefs({ resourceHost: "a.example.com", tokenEndpoints: [{ host: "shared.example.com", path: "/t" }] }),
        "mcp:claude-b": ahrefs({ resourceHost: "b.example.com", tokenEndpoints: [{ host: "shared.example.com", path: "/t" }] }),
      },
    });
    expect(target.webSocketUpgradeRefusal(ws(`wss://${TOKEN_HOST}/oauth/token`))).toMatchObject({ target: "mediated-endpoint", providers: ["mcp:claude-ahrefs"] });
    expect(target.webSocketUpgradeRefusal(ws("wss://blocked.example.com/token"))).toMatchObject({ target: "blocked-endpoint" });
    expect(target.webSocketUpgradeRefusal(ws("wss://shared.example.com/t"))).toMatchObject({ target: "endpoint-collision" });
    // Elsewhere on a blocked host only a grant-shaped query is refused.
    expect(target.webSocketUpgradeRefusal(ws("wss://blocked.example.com/Token?refresh_token=R"))).toMatchObject({ target: "blocked-endpoint", finding: { kind: "grant-shaped" } });
    expect(target.webSocketUpgradeRefusal(ws("wss://blocked.example.com/socket"))).toBeUndefined();
  });

  test("on a host a record names, only an upgrade with a grant-shaped query is refused", () => {
    const target = mediator({ recordEndpointHosts: [RESOURCE], providers: { "mcp:claude-ahrefs": ahrefs() } });
    expect(target.webSocketUpgradeRefusal(ws(`wss://${RESOURCE}/socket?grant_type=refresh_token`)))
      .toMatchObject({ target: "record-endpoint-host", finding: { kind: "grant-shaped", field: "grant_type" } });
    expect(target.webSocketUpgradeRefusal(ws(`wss://${RESOURCE}/mcp/socket?session=1`))).toBeUndefined();
    expect(target.webSocketUpgradeRefusal(ws("wss://unrelated.example.com/socket?grant_type=x"))).toBeUndefined();
  });

  test("reclaim: a policy that stops guarding the host lets the upgrade through", () => {
    const target = mediator({ recordOnlyHosts: [TOKEN_HOST], providers: {} });
    activate(target, { providers: {} });
    expect(target.webSocketUpgradeRefusal(ws(`wss://${TOKEN_HOST}/socket`))).toBeUndefined();
  });
});
